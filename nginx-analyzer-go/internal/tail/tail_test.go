package tail

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"nginx-analyzer-go/internal/parse"
)

// accessLine reproduit le helper line() du test Node.
func accessLine(p string) string {
	if p == "" {
		p = "/"
	}
	return `203.0.113.5 - - [09/Sep/2026:10:00:00 +0200] "GET ` + p + ` HTTP/1.1" 200 100 "-" "curl/8"` + "\n"
}

func accessParseLine(line, format, defaultVhost string) (any, bool) {
	return parse.ParseLine(line, format, defaultVhost)
}

func mkTailer(dir string, store OffsetStore, onEntry func(any)) *Tailer {
	return New(Options{
		Dir: dir, Store: store, OnEntry: onEntry,
		DetectFormat:      parse.DetectFormat,
		ParseLine:         accessParseLine,
		VhostFromFilename: parse.VhostFromFilename,
	})
}

func entryPath(e any) string {
	ae, ok := e.(parse.AccessEntry)
	if !ok || ae.Path == nil {
		return ""
	}
	return *ae.Path
}
func entryVhost(e any) string {
	ae, ok := e.(parse.AccessEntry)
	if !ok {
		return ""
	}
	return ae.Vhost
}

func TestNewFileStartsAtEnd(t *testing.T) {
	tmp := t.TempDir()
	log := filepath.Join(tmp, "site.fr.access.log")
	if err := os.WriteFile(log, []byte(repeatStr(accessLine("/ancien"), 50)), 0644); err != nil {
		t.Fatal(err)
	}
	var got []any
	tr := mkTailer(tmp, NewMemoryOffsetStore(), func(e any) { got = append(got, e) })
	tr.Poll()
	if len(got) != 0 {
		t.Errorf("l historique ne doit pas etre reingere, got %d", len(got))
	}
}

func repeatStr(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}

func TestNewLinesAreRead(t *testing.T) {
	tmp := t.TempDir()
	log := filepath.Join(tmp, "site.fr.access.log")
	os.WriteFile(log, nil, 0644)
	var got []any
	tr := mkTailer(tmp, NewMemoryOffsetStore(), func(e any) { got = append(got, e) })
	tr.Poll()
	appendFile(t, log, accessLine("/nouveau"))
	tr.Poll()
	if len(got) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(got))
	}
	if entryPath(got[0]) != "/nouveau" {
		t.Errorf("path = %q", entryPath(got[0]))
	}
}

func appendFile(t *testing.T, path, content string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
}

func TestNothingNewNothingReread(t *testing.T) {
	tmp := t.TempDir()
	log := filepath.Join(tmp, "site.fr.access.log")
	os.WriteFile(log, nil, 0644)
	var got []any
	tr := mkTailer(tmp, NewMemoryOffsetStore(), func(e any) { got = append(got, e) })
	tr.Poll()
	appendFile(t, log, accessLine(""))
	tr.Poll()
	n := len(got)
	tr.Poll()
	tr.Poll()
	if len(got) != n {
		t.Errorf("expected no new entries, got %d (was %d)", len(got), n)
	}
}

func TestRotationNewInodeRestartsFromZero(t *testing.T) {
	tmp := t.TempDir()
	log := filepath.Join(tmp, "site.fr.access.log")
	os.WriteFile(log, nil, 0644)
	store := NewMemoryOffsetStore()
	var got []any
	tr := mkTailer(tmp, store, func(e any) { got = append(got, e) })
	tr.Poll()
	appendFile(t, log, accessLine("/avant"))
	tr.Poll()

	if err := os.Rename(log, log+".1"); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(log, []byte(accessLine("/apres")), 0644)
	tr.Poll()

	found := false
	for _, e := range got {
		if entryPath(e) == "/apres" {
			found = true
		}
	}
	if !found {
		t.Error("le nouveau fichier doit etre lu")
	}
	stats, _ := tr.Status()
	if stats.Rotations == 0 {
		t.Error("la rotation doit etre comptee")
	}
	os.Remove(log + ".1")
}

func TestTruncationInPlaceDetected(t *testing.T) {
	tmp := t.TempDir()
	log := filepath.Join(tmp, "site.fr.access.log")
	os.WriteFile(log, []byte(repeatStr(accessLine(""), 10)), 0644)
	store := NewMemoryOffsetStore()
	var got []any
	tr := mkTailer(tmp, store, func(e any) { got = append(got, e) })
	tr.Poll()
	appendFile(t, log, accessLine("/a"))
	tr.Poll()
	statsBefore, _ := tr.Status()
	avant := statsBefore.Rotations

	os.WriteFile(log, []byte(accessLine("/apres-troncature")), 0644)
	tr.Poll()

	statsAfter, _ := tr.Status()
	if statsAfter.Rotations <= avant {
		t.Error("rotation attendue apres troncature")
	}
	found := false
	for _, e := range got {
		if entryPath(e) == "/apres-troncature" {
			found = true
		}
	}
	if !found {
		t.Error("la ligne post-troncature doit etre lue")
	}
}

func vhostLine(v, p string) string {
	if p == "" {
		p = "/"
	}
	return v + ` 203.0.113.9 - - [09/Sep/2026:10:00:00 +0200] "GET ` + p + ` HTTP/1.1" 200 100 "-" "curl/8"` + "\n"
}

func TestFormatRedetectedAfterRotation(t *testing.T) {
	tmp := t.TempDir()
	log := filepath.Join(tmp, "site.fr.access.log")
	os.WriteFile(log, []byte(repeatStr(vhostLine("avant.example.com", ""), 5)), 0644)
	store := NewMemoryOffsetStore()
	var got []any
	tr := mkTailer(tmp, store, func(e any) { got = append(got, e) })
	tr.Poll()
	appendFile(t, log, vhostLine("avant.example.com", "/deja-vu"))
	tr.Poll()

	sanity := false
	for _, e := range got {
		if entryPath(e) == "/deja-vu" && entryVhost(e) == "avant.example.com" {
			sanity = true
		}
	}
	if !sanity {
		t.Fatal("sanity check: format vhost doit etre actif avant rotation")
	}

	if err := os.Rename(log, log+".1"); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(log, nil, 0644)
	tr.Poll()

	appendFile(t, log, vhostLine("apres.example.com", "/apres-rotation"))
	tr.Poll()

	found := false
	for _, e := range got {
		if entryPath(e) == "/apres-rotation" && entryVhost(e) == "apres.example.com" {
			found = true
		}
	}
	if !found {
		t.Error("la ligne post-rotation (format vhost) doit etre parsee, pas figee sur combined")
	}
	os.Remove(log + ".1")
}

func TestResumeAvoidsRereadAfterRestart(t *testing.T) {
	tmp := t.TempDir()
	log := filepath.Join(tmp, "site.fr.access.log")
	os.WriteFile(log, []byte(repeatStr(accessLine(""), 5)), 0644)
	store := NewMemoryOffsetStore()
	t1 := mkTailer(tmp, store, func(e any) {})
	t1.Poll()
	appendFile(t, log, accessLine("/x"))
	var got1 []any
	t1.onEntry = func(e any) { got1 = append(got1, e) }
	t1.Poll()
	if len(got1) != 1 {
		t.Fatalf("expected 1, got %d", len(got1))
	}

	var got2 []any
	t2 := mkTailer(tmp, store, func(e any) { got2 = append(got2, e) })
	t2.Poll()
	if len(got2) != 0 {
		t.Error("la reprise ne doit pas dupliquer")
	}
}

func TestPartialLineWaitsForRest(t *testing.T) {
	tmp := t.TempDir()
	log := filepath.Join(tmp, "site.fr.access.log")
	os.WriteFile(log, nil, 0644)
	store := NewMemoryOffsetStore()
	var got []any
	tr := mkTailer(tmp, store, func(e any) { got = append(got, e) })
	tr.Poll()
	l := accessLine("/complet")
	appendFile(t, log, l[:30])
	tr.Poll()
	if len(got) != 0 {
		t.Error("une ligne incomplete ne doit pas etre parsee")
	}
	appendFile(t, log, l[30:])
	tr.Poll()
	if len(got) != 1 {
		t.Fatalf("expected 1, got %d", len(got))
	}
	if entryPath(got[0]) != "/complet" {
		t.Errorf("path = %q", entryPath(got[0]))
	}
}

func TestVhostFromFilenameInCombinedFormat(t *testing.T) {
	tmp := t.TempDir()
	log := filepath.Join(tmp, "site.fr.access.log")
	os.WriteFile(log, nil, 0644)
	store := NewMemoryOffsetStore()
	var got []any
	tr := mkTailer(tmp, store, func(e any) { got = append(got, e) })
	tr.Poll()
	appendFile(t, log, accessLine(""))
	tr.Poll()
	if len(got) == 0 || entryVhost(got[0]) != "site.fr" {
		t.Errorf("vhost attendu site.fr, got %v", got)
	}
}

func TestNonexistentDir(t *testing.T) {
	tr := mkTailer("/nexiste/pas", NewMemoryOffsetStore(), func(e any) {})
	tr.Poll() // ne doit pas paniquer
	if files := tr.ListFiles(); len(files) != 0 {
		t.Errorf("expected no files, got %v", files)
	}
}

func TestDeletedFileForgotten(t *testing.T) {
	tmp := t.TempDir()
	f := filepath.Join(tmp, "temporaire.access.log")
	os.WriteFile(f, nil, 0644)
	tr := mkTailer(tmp, NewMemoryOffsetStore(), func(e any) {})
	tr.Poll()
	os.Remove(f)
	tr.Poll() // ne doit pas paniquer
	_, following := tr.Status()
	for _, fs := range following {
		if fs.File == "temporaire.access.log" {
			t.Error("le fichier supprime doit etre oublie")
		}
	}
}

func TestUnreadableLineCountedNotBlocking(t *testing.T) {
	tmp := t.TempDir()
	log := filepath.Join(tmp, "site.fr.access.log")
	os.WriteFile(log, nil, 0644)
	store := NewMemoryOffsetStore()
	var got []any
	tr := mkTailer(tmp, store, func(e any) { got = append(got, e) })
	tr.Poll()
	appendFile(t, log, "n importe quoi\n"+accessLine("/ok"))
	tr.Poll()
	if len(got) != 1 {
		t.Fatalf("expected 1, got %d", len(got))
	}
	stats, _ := tr.Status()
	if stats.Dropped == 0 {
		t.Error("expected dropped > 0")
	}
}

func TestSuspectFormatFlaggedForBadFormat(t *testing.T) {
	tmp := t.TempDir()
	log := filepath.Join(tmp, "site.fr.access.log")
	os.WriteFile(log, nil, 0644)
	store := NewMemoryOffsetStore()
	tr := mkTailer(tmp, store, func(e any) {})
	tr.Poll()
	native := "--a1b2-A--\n[27/Sep/2026:10:00:00] abc 1.2.3.4\n--a1b2-B--\nGET /x HTTP/1.1\n--a1b2-Z--\n"
	appendFile(t, log, native)
	tr.Poll()
	_, following := tr.Status()
	var f *FollowingStatus
	for i := range following {
		if following[i].File == filepath.Base(log) {
			f = &following[i]
		}
	}
	if f == nil {
		t.Fatal("file status not found")
	}
	if f.Lines < 5 {
		t.Errorf("les lignes doivent etre comptees malgre l echec de parsing, got %d", f.Lines)
	}
	if f.Parsed != 0 {
		t.Errorf("parsed should be 0, got %d", f.Parsed)
	}
	if !f.SuspectFormat {
		t.Error("un journal qui n analyse jamais rien doit etre signale suspect")
	}
}

func TestValidFileNeverSuspect(t *testing.T) {
	tmp := t.TempDir()
	log := filepath.Join(tmp, "site.fr.access.log")
	os.WriteFile(log, nil, 0644)
	store := NewMemoryOffsetStore()
	tr := mkTailer(tmp, store, func(e any) {})
	tr.Poll()
	appendFile(t, log, repeatStr(accessLine("/ok"), 10))
	tr.Poll()
	_, following := tr.Status()
	var f *FollowingStatus
	for i := range following {
		if following[i].File == filepath.Base(log) {
			f = &following[i]
		}
	}
	if f == nil || f.SuspectFormat {
		t.Errorf("fichier valide ne doit jamais etre suspect: %+v", f)
	}
}

func TestSmallSampleNotFlagged(t *testing.T) {
	tmp := t.TempDir()
	log := filepath.Join(tmp, "site.fr.access.log")
	os.WriteFile(log, nil, 0644)
	store := NewMemoryOffsetStore()
	tr := mkTailer(tmp, store, func(e any) {})
	tr.Poll()
	appendFile(t, log, "ligne illisible\n"+accessLine("/ok"))
	tr.Poll()
	_, following := tr.Status()
	var f *FollowingStatus
	for i := range following {
		if following[i].File == filepath.Base(log) {
			f = &following[i]
		}
	}
	if f == nil || f.SuspectFormat {
		t.Errorf("echantillon trop petit pour signaler: %+v", f)
	}
}

func TestPatternFiltersFiles(t *testing.T) {
	tmp := t.TempDir()
	v := filepath.Join(tmp, "vhosts_access.log")
	os.WriteFile(v, nil, 0644)
	store := NewMemoryOffsetStore()
	tr := New(Options{
		Dir: tmp, Pattern: regexp.MustCompile(`vhosts_access\.log$`), Store: store,
		OnEntry: func(e any) {}, DetectFormat: parse.DetectFormat, ParseLine: accessParseLine,
		VhostFromFilename: parse.VhostFromFilename,
	})
	tr.Poll()
	appendFile(t, v, `autre.fr 1.2.3.4 - - [09/Sep/2026:10:00:00 +0200] "GET /v HTTP/1.1" 200 5 "-" "curl/8"`+"\n")
	tr.Poll()
	_, following := tr.Status()
	if len(following) == 0 {
		t.Error("expected at least one followed file")
	}
}

func TestStartStop(t *testing.T) {
	tmp := t.TempDir()
	log := filepath.Join(tmp, "site.fr.access.log")
	os.WriteFile(log, nil, 0644)
	tr := New(Options{
		Dir: tmp, Store: NewMemoryOffsetStore(), OnEntry: func(e any) {}, PollMs: 20,
		DetectFormat: parse.DetectFormat, ParseLine: accessParseLine, VhostFromFilename: parse.VhostFromFilename,
	})
	tr.Start()
	time.Sleep(60 * time.Millisecond)
	tr.Stop()
}
