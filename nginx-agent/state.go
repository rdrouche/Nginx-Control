package main

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// Local persisted state — only what survives a restart: the agentId handed
// back by enrollment (so the agent never re-enrolls on every restart while
// still pending) and, once an operator has pasted it in (see README.md —
// there is no channel for the dashboard to push a freshly-approved token to
// the agent itself, only to the operator's browser, by design: a bearer
// token is only ever shown once, see lib/agents-store.js#approve()), the
// bearer token itself.
type agentState struct {
	AgentID string `json:"agentId"`
	Token   string `json:"token,omitempty"`
}

func loadState(path string) agentState {
	var s agentState
	data, err := os.ReadFile(path)
	if err != nil {
		return s
	}
	_ = json.Unmarshal(data, &s)
	return s
}

// Fix (audit report, Basse/"Agent Go"): two independent issues in the
// previous write-tmp-then-rename sequence.
//
//  1. os.WriteFile(tmp, data, 0600) only applies that 0600 mode when the
//     file is CREATED — the permission bits of an ALREADY-EXISTING file
//     (a ".tmp" left over from a process that crashed between this write
//     and its own os.Rename, before this fix could ever run again) are left
//     untouched by WriteFile. This file holds a live bearer token
//     (agentState.Token) — a leftover .tmp that somehow ended up
//     world/group-readable (a looser umask at the time it was first
//     created, or the file copied/restored by some other tool) would stay
//     that way forever, never actually corrected on any subsequent write.
//     Fixed by opening the file explicitly with O_CREATE|O_TRUNC|O_WRONLY
//     and 0600, then calling Chmod on it unconditionally — a mode Open
//     silently ignores on populate is now applied for real, whether the
//     file pre-existed or not.
//  2. No fsync before the rename: on an unclean shutdown (power loss, a
//     killed container with no graceful stop), both the tmp file's own
//     content and the rename that publishes it as the real state file can
//     still be sitting in page cache, unwritten to disk — the classic
//     "torn write" window plain write+rename doesn't actually close by
//     itself. Fsync-ing the file before Close(), and the containing
//     directory after Rename(), makes the publish durable the way an
//     atomic-write pattern is normally expected to be.
func saveState(path string, s agentState) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if err := f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	if dir, err := os.Open(filepath.Dir(path)); err == nil {
		_ = dir.Sync() // best-effort — pas supporte partout (ex: certains systemes de fichiers reseau), jamais fatal
		dir.Close()
	}
	return nil
}
