package audit

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestChain(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.log")
	l, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	// Two writers (the agent and its command line) continue one chain.
	l2, _ := Open(p)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			w := l
			if i%2 == 1 {
				w = l2
			}
			if err := w.Append(Entry{Actor: "conductor:lab.admin", Op: "share.apply", Target: "eng", Result: ResultOK}); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	n, err := Verify(p)
	if err != nil || n != 20 {
		t.Fatalf("verify: %d %v", n, err)
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
	b, _ := os.ReadFile(p)
	lines := strings.SplitAfter(string(b), "\n")

	// An edited entry, a removed entry, a reordering: all detected.
	edited := strings.Replace(string(b), `"target":"eng"`, `"target":"hr"`, 1)
	removed := strings.Join(append(append([]string{}, lines[:3]...), lines[4:]...), "")
	swapped := strings.Join(append([]string{lines[1], lines[0]}, lines[2:]...), "")
	for name, content := range map[string]string{"edited": edited, "removed": removed, "swapped": swapped} {
		q := filepath.Join(t.TempDir(), name)
		_ = os.WriteFile(q, []byte(content), 0o600)
		if _, err := Verify(q); err == nil {
			t.Fatalf("%s: not detected", name)
		}
		if _, err := Open(q); err == nil {
			t.Fatalf("%s: Open must refuse a broken chain", name)
		}
	}
}
