package fsguard

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func setup(t *testing.T) (Guard, string) {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "shares")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(base, 0o755)
	return Guard{Roots: []string{root}, Owner: os.Getuid()}, root
}

func TestCheckAndCreate(t *testing.T) {
	g, root := setup(t)
	if err := g.CheckRoot(root); err != nil {
		t.Fatal(err)
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.Mkdir(filepath.Join(root, "eng"), 0o750))
	must(g.CheckDir(filepath.Join(root, "eng")))
	if err := g.CheckDir(root); !errors.Is(err, ErrOutside) {
		t.Fatalf("root itself: %v", err)
	}
	if err := g.CheckDir("/etc"); !errors.Is(err, ErrOutside) {
		t.Fatalf("outside: %v", err)
	}
	if err := g.CheckDir(root + "x/eng"); !errors.Is(err, ErrOutside) {
		t.Fatalf("prefix sibling: %v", err)
	}
	if err := g.CheckDir(filepath.Join(root, "missing")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	// Symbolic links are refused wherever they are.
	must(os.Symlink("/etc", filepath.Join(root, "link")))
	if err := g.CheckDir(filepath.Join(root, "link")); !errors.Is(err, ErrSymlink) {
		t.Fatalf("symlink: %v", err)
	}
	if err := g.CheckCreate(filepath.Join(root, "link", "x")); !errors.Is(err, ErrSymlink) {
		t.Fatalf("through a symlink: %v", err)
	}
	if err := g.CheckCreate(filepath.Join(root, "link")); !errors.Is(err, ErrExists) {
		t.Fatalf("create over a symlink: %v", err)
	}
	// A file is not a directory.
	must(os.WriteFile(filepath.Join(root, "file"), nil, 0o600))
	if err := g.CheckDir(filepath.Join(root, "file")); !errors.Is(err, ErrSymlink) {
		t.Fatalf("file: %v", err)
	}
	// A parent writable by others is unsafe.
	must(os.MkdirAll(filepath.Join(root, "open", "sub"), 0o755))
	must(os.Chmod(filepath.Join(root, "open"), 0o777))
	if err := g.CheckDir(filepath.Join(root, "open", "sub")); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("unsafe parent: %v", err)
	}
	if err := g.Create(filepath.Join(root, "open", "new")); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("create in unsafe parent: %v", err)
	}
	// Create.
	p := filepath.Join(root, "new")
	must(g.CheckCreate(p))
	must(g.Create(p))
	st, err := os.Lstat(p)
	if err != nil || !st.IsDir() || st.Mode().Perm() != 0o700 {
		t.Fatalf("created %v %v", st.Mode(), err)
	}
	if err := g.Create(p); !errors.Is(err, ErrExists) {
		t.Fatalf("create twice: %v", err)
	}
	// An unsafe root.
	must(os.Chmod(root, 0o777))
	if err := g.CheckRoot(root); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("unsafe root: %v", err)
	}
	if err := g.CheckDir(filepath.Join(root, "eng")); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("share below an unsafe root: %v", err)
	}
}

func TestList(t *testing.T) {
	g, root := setup(t)
	for _, d := range []string{"b", "a", ".hidden", "open/inner"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	_ = os.Chmod(filepath.Join(root, "open"), 0o777)
	_ = os.Symlink("/etc", filepath.Join(root, "link"))
	_ = os.WriteFile(filepath.Join(root, "file"), nil, 0o600)
	l, err := g.List("", nil)
	if err != nil || len(l.Roots) != 1 {
		t.Fatalf("roots: %+v %v", l, err)
	}
	l, err = g.List(root, map[string]string{filepath.Join(root, "a"): "share-a"})
	if err != nil {
		t.Fatal(err)
	}
	if !l.CanCreate || l.Parent != "" || len(l.Entries) != 3 || l.Entries[0].Name != "a" || l.Entries[0].Share != "share-a" || !l.Entries[1].Usable {
		t.Fatalf("list %+v", l)
	}
	l, err = g.List(filepath.Join(root, "open"), nil)
	if err != nil || l.CanCreate || len(l.Entries) != 1 || l.Entries[0].Usable || l.Entries[0].Reason != "parent" || l.Parent != root {
		t.Fatalf("unsafe list %+v %v", l, err)
	}
	if _, err := g.List(filepath.Join(root, "link"), nil); !errors.Is(err, ErrSymlink) {
		t.Fatalf("list through a symlink: %v", err)
	}
	if _, err := g.List("/etc", nil); !errors.Is(err, ErrOutside) {
		t.Fatalf("list outside: %v", err)
	}
}
