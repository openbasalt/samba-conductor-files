// Package fsguard resolves share paths below the configured roots without
// ever following a symbolic link, and checks that nobody but root can
// change which directory a path names.
//
// Rules (p2b-spec §2):
//   - a share directory is strictly below a root;
//   - every path component is opened relative to its parent with
//     O_NOFOLLOW (a symbolic link anywhere is refused, not resolved);
//   - the root and every parent of the share directory are owned by root
//     and not writable by group or others (mode bits, which also reflect a
//     POSIX ACL mask), so no other user can rename or replace a component
//     between this check and the ACL write that follows it;
//   - a new folder is created with mkdirat in such a parent, owned by
//     root:root, mode 0700, until its NT ACL is written.
package fsguard

import (
	"errors"
	"fmt"
	"os"
	"path"
	"slices"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/samba-conductor/conductor-files/filesapi"
)

// Guard knows the roots.
type Guard struct {
	Roots []string
	// Owner is the UID every root and parent must belong to (root, 0;
	// tests use their own UID).
	Owner int
}

// Errors (wrapped with details).
var (
	ErrOutside  = errors.New("the path is not below a configured root")
	ErrSymlink  = errors.New("a path component is a symbolic link or not a directory")
	ErrNotFound = errors.New("the directory does not exist")
	ErrExists   = errors.New("the directory already exists")
	ErrUnsafe   = errors.New("a parent directory is not owned by root or is writable by group or others")
)

// MaxEntries bounds a directory listing.
const MaxEntries = 1000

// split returns the root containing p and the components below it.
func (g Guard) split(p string) (string, []string, error) {
	if err := filesapi.ValidSharePath(p); err != nil {
		return "", nil, err
	}
	best := ""
	for _, r := range g.Roots {
		if (p == r || strings.HasPrefix(p, r+"/")) && len(r) > len(best) {
			best = r
		}
	}
	if best == "" {
		return "", nil, fmt.Errorf("%w: %s", ErrOutside, p)
	}
	rest := strings.TrimPrefix(strings.TrimPrefix(p, best), "/")
	if rest == "" {
		return best, nil, nil
	}
	return best, strings.Split(rest, "/"), nil
}

// RootOf returns the root containing p.
func (g Guard) RootOf(p string) (string, bool) {
	r, _, err := g.split(p)
	return r, err == nil
}

func safe(st *unix.Stat_t, owner int) bool { return int(st.Uid) == owner && st.Mode&0o022 == 0 }

const pathFlags = unix.O_PATH | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC

func openErr(err error, name string) error {
	switch {
	case errors.Is(err, unix.ELOOP), errors.Is(err, unix.ENOTDIR):
		return fmt.Errorf("%w: %s", ErrSymlink, name)
	case errors.Is(err, unix.ENOENT):
		return fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	return fmt.Errorf("%s: %w", name, err)
}

// CheckRoot verifies a root: an absolute real directory (no symbolic link
// in its path), owned by the guard's owner, not writable by group or others.
func (g Guard) CheckRoot(root string) error {
	fd, err := unix.Open("/", pathFlags, 0)
	if err != nil {
		return err
	}
	for _, c := range strings.Split(strings.TrimPrefix(root, "/"), "/") {
		next, err := unix.Openat(fd, c, pathFlags, 0)
		_ = unix.Close(fd)
		if err != nil {
			return openErr(err, root)
		}
		fd = next
	}
	defer func() { _ = unix.Close(fd) }()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if !safe(&st, g.Owner) {
		return fmt.Errorf("%w: %s", ErrUnsafe, root)
	}
	return nil
}

// walk opens the root and the given components, returning the fd of the
// last one and whether every directory opened (root included) is safe.
// With requireSafe, an unsafe directory is an error.
func walk(root string, comps []string, requireSafe bool, owner int) (int, bool, error) {
	fd, err := unix.Open(root, pathFlags, 0)
	if err != nil {
		return -1, false, openErr(err, root)
	}
	allSafe := true
	cur := root
	for i := 0; ; i++ {
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			_ = unix.Close(fd)
			return -1, false, err
		}
		if !safe(&st, owner) {
			allSafe = false
			if requireSafe {
				_ = unix.Close(fd)
				return -1, false, fmt.Errorf("%w: %s", ErrUnsafe, cur)
			}
		}
		if i == len(comps) {
			return fd, allSafe, nil
		}
		next, err := unix.Openat(fd, comps[i], pathFlags, 0)
		_ = unix.Close(fd)
		cur = path.Join(cur, comps[i])
		if err != nil {
			return -1, false, openErr(err, cur)
		}
		fd = next
	}
}

// CheckDir verifies an existing share directory: strictly below a root,
// no symbolic link, parents safe, a directory.
func (g Guard) CheckDir(p string) error {
	root, comps, err := g.split(p)
	if err != nil {
		return err
	}
	if len(comps) == 0 {
		return fmt.Errorf("%w: a root itself cannot be shared (%s)", ErrOutside, p)
	}
	parent, _, err := walk(root, comps[:len(comps)-1], true, g.Owner)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(parent) }()
	fd, err := unix.Openat(parent, comps[len(comps)-1], pathFlags, 0)
	if err != nil {
		return openErr(err, p)
	}
	return unix.Close(fd)
}

// CheckCreate verifies that p can be created: its parents exist and are
// safe, and p itself does not exist.
func (g Guard) CheckCreate(p string) error {
	root, comps, err := g.split(p)
	if err != nil {
		return err
	}
	if len(comps) == 0 {
		return fmt.Errorf("%w: %s", ErrOutside, p)
	}
	parent, _, err := walk(root, comps[:len(comps)-1], true, g.Owner)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(parent) }()
	var st unix.Stat_t
	err = unix.Fstatat(parent, comps[len(comps)-1], &st, unix.AT_SYMLINK_NOFOLLOW)
	switch {
	case err == nil:
		return fmt.Errorf("%w: %s", ErrExists, p)
	case errors.Is(err, unix.ENOENT):
		return nil
	}
	return err
}

// Create makes the directory p (owner:owner, i.e. root:root, 0700) after CheckCreate's
// checks, with mkdirat in the verified parent.
func (g Guard) Create(p string) error {
	root, comps, err := g.split(p)
	if err != nil {
		return err
	}
	if len(comps) == 0 {
		return fmt.Errorf("%w: %s", ErrOutside, p)
	}
	parent, _, err := walk(root, comps[:len(comps)-1], true, g.Owner)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(parent) }()
	name := comps[len(comps)-1]
	if err := unix.Mkdirat(parent, name, 0o700); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("%w: %s", ErrExists, p)
		}
		return err
	}
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return openErr(err, p)
	}
	defer func() { _ = unix.Close(fd) }()
	gid := -1 // tests: keep the creating user's group
	if g.Owner == 0 {
		gid = 0
	}
	if err := unix.Fchown(fd, g.Owner, gid); err != nil {
		return err
	}
	return unix.Fchmod(fd, 0o700)
}

// List returns the subdirectories of p (a root or a directory below one).
// shares maps share paths to share names (marks entries in use).
func (g Guard) List(p string, shares map[string]string) (filesapi.DirList, error) {
	out := filesapi.DirList{Path: p, Roots: slices.Clone(g.Roots)}
	if p == "" {
		return out, nil
	}
	root, comps, err := g.split(p)
	if err != nil {
		return out, err
	}
	out.Root = root
	if len(comps) > 0 {
		out.Parent = path.Dir(p)
	}
	fd, allSafe, err := walk(root, comps, false, g.Owner)
	if err != nil {
		return out, err
	}
	// Re-open for reading (an O_PATH descriptor cannot list).
	rfd, err := unix.Openat(fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	_ = unix.Close(fd)
	if err != nil {
		return out, err
	}
	f := os.NewFile(uintptr(rfd), p)
	defer func() { _ = f.Close() }()
	ents, err := f.ReadDir(-1)
	if err != nil {
		return out, err
	}
	slices.SortFunc(ents, func(a, b os.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })
	out.CanCreate = allSafe
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".") || !e.IsDir() || e.Type()&os.ModeSymlink != 0 {
			continue
		}
		if len(out.Entries) >= MaxEntries {
			out.Truncated = true
			break
		}
		full := path.Join(p, e.Name())
		de := filesapi.DirEntry{Name: e.Name(), Path: full, Share: shares[full], Usable: allSafe}
		switch {
		case filesapi.ValidSharePath(full) != nil:
			de.Usable, de.Reason = false, "name"
		case !allSafe:
			de.Reason = "parent"
		}
		out.Entries = append(out.Entries, de)
	}
	return out, nil
}
