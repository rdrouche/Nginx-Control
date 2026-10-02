// Package tail porte lib/tail.js: un tailer par polling generique, injectable avec n importe
// quel parseur ligne par ligne (access, waf, blocklist), avec la meme gestion de rotation,
// troncature, offset et ligne partielle.
package tail

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	maxPartialBytes = 64 * 1024
	headSigBytes    = 64
)

// OffsetStore persiste les offsets par fichier, comme le fait store.js cote Node
// (getOffset/setOffset). Une implementation en memoire suffit pour les tests.
type OffsetStore interface {
	GetOffset(file string) (inode uint64, offset int64, format string, ok bool)
	SetOffset(file string, inode uint64, offset int64, format string)
}

// MemoryOffsetStore est une implementation en memoire, pour les tests ou un usage sans SQLite.
type MemoryOffsetStore struct {
	mu Mutex
	m  map[string]offsetRow
}

type offsetRow struct {
	inode  uint64
	offset int64
	format string
}

// Mutex evite d importer sync directement dans la signature publique tout en restant sync.Mutex.
type Mutex = sync.Mutex

func NewMemoryOffsetStore() *MemoryOffsetStore {
	return &MemoryOffsetStore{m: make(map[string]offsetRow)}
}

func (s *MemoryOffsetStore) GetOffset(file string) (uint64, int64, string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.m[file]
	if !ok {
		return 0, 0, "", false
	}
	return r.inode, r.offset, r.format, true
}

func (s *MemoryOffsetStore) SetOffset(file string, inode uint64, offset int64, format string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[file] = offsetRow{inode: inode, offset: offset, format: format}
}

// DetectFormatFunc / ParseLineFunc / VhostFromFilenameFunc reproduisent les fonctions
// injectables du constructeur JS (detectFormat/parseLine/vhostFromFilename).
type DetectFormatFunc func(sampleLines []string) string
type ParseLineFunc func(line, format, defaultVhost string) (entry any, ok bool)
type VhostFromFilenameFunc func(filename string) string

// Stats reproduit this.stats du Tailer JS.
type Stats struct {
	Lines     int
	Parsed    int
	Dropped   int
	Rotations int
	Files     int
}

// FollowingStatus reproduit un element de status().following.
type FollowingStatus struct {
	File          string
	Vhost         string
	Format        string
	Offset        int64
	Lines         int
	Parsed        int
	Dropped       int
	SuspectFormat bool
}

type fileState struct {
	inode      uint64
	offset     int64
	format     string // "" == null/pending
	formatSet  bool
	vhost      string
	partialBuf []byte
	headSig    []byte
	headSigSet bool
	lines      int
	parsed     int
	dropped    int
}

// Options reproduit les options du constructeur Tailer.
type Options struct {
	Dir               string
	Pattern           *regexp.Regexp
	Store             OffsetStore
	OnEntry           func(entry any)
	PollMs            int
	MaxChunk          int64
	DetectFormat      DetectFormatFunc
	ParseLine         ParseLineFunc
	VhostFromFilename VhostFromFilenameFunc
}

// Tailer porte la classe Tailer de lib/tail.js.
type Tailer struct {
	dir               string
	pattern           *regexp.Regexp
	store             OffsetStore
	onEntry           func(entry any)
	pollMs            time.Duration
	maxChunk          int64
	detectFormat      DetectFormatFunc
	parseLine         ParseLineFunc
	vhostFromFilename VhostFromFilenameFunc

	mu    sync.Mutex
	files map[string]*fileState
	stats Stats

	ctlMu  sync.Mutex // protege stopCh (Start/Stop)
	stopCh chan struct{}
}

var defaultPattern = regexp.MustCompile(`\.access\.log$`)

// New construit un Tailer, avec les memes valeurs par defaut que le constructeur JS.
func New(opts Options) *Tailer {
	if opts.Pattern == nil {
		opts.Pattern = defaultPattern
	}
	if opts.PollMs == 0 {
		opts.PollMs = 1000
	}
	if opts.MaxChunk == 0 {
		opts.MaxChunk = 4 * 1024 * 1024
	}
	if opts.OnEntry == nil {
		opts.OnEntry = func(entry any) {}
	}
	return &Tailer{
		dir:               opts.Dir,
		pattern:           opts.Pattern,
		store:             opts.Store,
		onEntry:           opts.OnEntry,
		pollMs:            time.Duration(opts.PollMs) * time.Millisecond,
		maxChunk:          opts.MaxChunk,
		detectFormat:      opts.DetectFormat,
		parseLine:         opts.ParseLine,
		vhostFromFilename: opts.VhostFromFilename,
		files:             make(map[string]*fileState),
	}
}

// ListFiles reproduit listFiles().
func (t *Tailer) ListFiles() []string {
	entries, err := os.ReadDir(t.dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if t.pattern.MatchString(e.Name()) {
			out = append(out, filepath.Join(t.dir, e.Name()))
		}
	}
	return out
}

// detectFormatOf reproduit _detectFormat(file).
func (t *Tailer) detectFormatOf(file string) string {
	f, err := os.Open(file)
	if err != nil {
		return "combined"
	}
	defer f.Close()
	buf := make([]byte, 8192)
	n, _ := f.ReadAt(buf, 0)
	if n < 0 {
		n = 0
	}
	text := string(buf[:n])
	lines := strings.Split(text, "\n")
	if len(lines) > 20 {
		lines = lines[:20]
	}
	if t.detectFormat == nil {
		return "combined"
	}
	return t.detectFormat(lines)
}

// headSignature reproduit _headSignature(file).
func (t *Tailer) headSignature(file string) ([]byte, bool) {
	f, err := os.Open(file)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	buf := make([]byte, headSigBytes)
	n, err := f.ReadAt(buf, 0)
	if n <= 0 && err != nil {
		// ReadAt renvoie une erreur EOF meme si n>0 possible; on ne garde que n>=0.
	}
	if n < 0 {
		n = 0
	}
	return buf[:n], true
}

// vhostFromFN applique vhostFromFilename ou "" si non fourni.
func (t *Tailer) vhostFromFN(name string) string {
	if t.vhostFromFilename == nil {
		return ""
	}
	return t.vhostFromFilename(name)
}

// open reproduit _open(file).
func (t *Tailer) open(file string) *fileState {
	st, err := os.Stat(file)
	if err != nil {
		return nil
	}
	inode := inodeOf(st)

	var offset int64
	var format string
	formatKnown := false

	if t.store != nil {
		if savedInode, savedOffset, savedFormat, ok := t.store.GetOffset(file); ok {
			if savedInode == inode && savedOffset <= st.Size() {
				offset = savedOffset
				format = savedFormat
				formatKnown = savedFormat != ""
			} else {
				offset = 0
			}
		} else {
			// Jamais vu : on part de la fin (pas de re-ingestion de l historique).
			offset = st.Size()
		}
	} else {
		offset = st.Size()
	}

	if !formatKnown {
		format = t.detectFormatOf(file)
		formatKnown = true
	}

	headSig, _ := t.headSignature(file)

	fs := &fileState{
		inode:      inode,
		offset:     offset,
		format:     format,
		formatSet:  formatKnown,
		vhost:      t.vhostFromFN(filepath.Base(file)),
		partialBuf: nil,
		headSig:    headSig,
		headSigSet: true,
	}
	t.files[file] = fs
	if t.store != nil {
		t.store.SetOffset(file, fs.inode, fs.offset, fs.format)
	}
	return fs
}

func stripCR(s string) string {
	if strings.HasSuffix(s, "\r") {
		return s[:len(s)-1]
	}
	return s
}

// flushPartial reproduit _flushPartial(f).
func (t *Tailer) flushPartial(file string, f *fileState) {
	if len(f.partialBuf) == 0 {
		return
	}
	line := stripCR(string(f.partialBuf))
	f.partialBuf = nil
	if line == "" {
		return
	}
	t.stats.Lines++
	f.lines++
	if t.parseLine == nil {
		t.stats.Dropped++
		f.dropped++
		return
	}
	entry, ok := t.parseLine(line, f.format, f.vhost)
	if !ok {
		t.stats.Dropped++
		f.dropped++
		return
	}
	t.stats.Parsed++
	f.parsed++
	t.safeOnEntry(entry)
}

func (t *Tailer) safeOnEntry(entry any) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[tail] onEntry: %v", r)
		}
	}()
	t.onEntry(entry)
}

// read reproduit _read(file).
func (t *Tailer) read(file string) {
	st, err := os.Stat(file)
	if err != nil {
		t.mu.Lock()
		delete(t.files, file)
		t.mu.Unlock()
		return
	}

	f, ok := t.files[file]
	if !ok {
		f = t.open(file)
		if f == nil {
			return
		}
	}

	inode := inodeOf(st)

	headChanged := false
	if inode == f.inode && f.headSigSet && st.Size() > 0 {
		nowSig, ok := t.headSignature(file)
		if ok && !bytes.Equal(nowSig, f.headSig) {
			headChanged = true
		}
	}

	if inode != f.inode {
		t.flushPartial(file, f)
		t.stats.Rotations++
		f.inode = inode
		f.offset = 0
		f.format = ""
		f.formatSet = false
		f.headSig, f.headSigSet = t.headSignature(file)
	} else if st.Size() < f.offset || headChanged {
		t.flushPartial(file, f)
		t.stats.Rotations++
		f.offset = 0
		f.headSig, f.headSigSet = t.headSignature(file)
	}

	if st.Size() == f.offset {
		return
	}

	length := st.Size() - f.offset
	if length > t.maxChunk {
		length = t.maxChunk
	}
	buf := make([]byte, length)
	fh, err := os.Open(file)
	if err != nil {
		return
	}
	n, _ := fh.ReadAt(buf, f.offset)
	fh.Close()
	if n <= 0 {
		return
	}
	buf = buf[:n]

	var combined []byte
	if len(f.partialBuf) > 0 {
		combined = append(append([]byte{}, f.partialBuf...), buf...)
	} else {
		combined = buf
	}
	f.offset += int64(n)

	lastNL := bytes.LastIndexByte(combined, '\n')
	if lastNL == -1 {
		f.partialBuf = combined
	} else {
		f.partialBuf = append([]byte{}, combined[lastNL+1:]...)
	}
	if len(f.partialBuf) > maxPartialBytes {
		log.Printf("[tail] %s : ligne incomplete de plus de %d octets, abandonnee", filepath.Base(file), maxPartialBytes)
		t.stats.Dropped++
		f.dropped++
		f.partialBuf = nil
	}
	if lastNL == -1 {
		if t.store != nil {
			t.store.SetOffset(file, f.inode, f.offset, f.format)
		}
		return
	}

	text := string(combined[:lastNL])
	lines := strings.Split(text, "\n")

	if f.format == "" {
		var sample []string
		for _, l := range lines {
			if strings.TrimSpace(l) != "" {
				sample = append(sample, l)
			}
		}
		if len(sample) > 0 && t.detectFormat != nil {
			f.format = t.detectFormat(sample)
		}
	}

	for _, raw := range lines {
		if f.format == "" {
			break
		}
		line := stripCR(raw)
		if line == "" {
			continue
		}
		t.stats.Lines++
		f.lines++
		if t.parseLine == nil {
			t.stats.Dropped++
			f.dropped++
			continue
		}
		entry, ok := t.parseLine(line, f.format, f.vhost)
		if !ok {
			t.stats.Dropped++
			f.dropped++
			continue
		}
		t.stats.Parsed++
		f.parsed++
		t.safeOnEntry(entry)
	}

	if t.store != nil {
		t.store.SetOffset(file, f.inode, f.offset, f.format)
	}
}

// Poll reproduit poll(): une passe sur tous les fichiers correspondants.
func (t *Tailer) Poll() {
	t.mu.Lock()
	defer t.mu.Unlock()

	files := t.ListFiles()
	t.stats.Files = len(files)
	for _, file := range files {
		t.read(file)
	}
	present := make(map[string]bool, len(files))
	for _, f := range files {
		present[f] = true
	}
	for known := range t.files {
		if !present[known] {
			delete(t.files, known)
		}
	}
}

// Start reproduit start(): un poll immediat puis un ticker (jamais bloquant pour le process,
// arrete via Stop()).
func (t *Tailer) Start() {
	t.ctlMu.Lock()
	defer t.ctlMu.Unlock()
	if t.stopCh != nil {
		return
	}
	t.Poll()
	t.stopCh = make(chan struct{})
	go func(stop chan struct{}) {
		ticker := time.NewTicker(t.pollMs)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				t.Poll()
			}
		}
	}(t.stopCh)
	t.mu.Lock()
	files := t.stats.Files
	t.mu.Unlock()
	log.Printf("[tail] Following %d file(s) in %s", files, t.dir)
}

// Stop reproduit stop().
func (t *Tailer) Stop() {
	t.ctlMu.Lock()
	defer t.ctlMu.Unlock()
	if t.stopCh != nil {
		close(t.stopCh)
		t.stopCh = nil
	}
}

// Status reproduit status().
func (t *Tailer) Status() (Stats, []FollowingStatus) {
	t.mu.Lock()
	defer t.mu.Unlock()
	// Ordre deterministe (par nom de fichier) : une map Go itere dans un ordre
	// aleatoire, ce qui ferait sauter les lignes de l'ecran d'un refresh a l'autre.
	names := make([]string, 0, len(t.files))
	for file := range t.files {
		names = append(names, file)
	}
	sort.Strings(names)
	out := make([]FollowingStatus, 0, len(t.files))
	for _, file := range names {
		f := t.files[file]
		ratio := 0.0
		if f.lines > 0 {
			ratio = float64(f.dropped) / float64(f.lines)
		}
		out = append(out, FollowingStatus{
			File: filepath.Base(file), Vhost: f.vhost, Format: f.format, Offset: f.offset,
			Lines: f.lines, Parsed: f.parsed, Dropped: f.dropped,
			SuspectFormat: f.lines >= 5 && ratio > 0.8,
		})
	}
	return t.stats, out
}
