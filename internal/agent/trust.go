package agent

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/openbasalt/samba-conductor-files/filesapi"
)

// Conductor is a pinned client key (a conductor instance).
type Conductor struct {
	Pin        string    `json:"pin"`
	Name       string    `json:"name"`
	EnrolledAt time.Time `json:"enrolled_at"`
	EnrolledBy string    `json:"enrolled_by"`
}

type trustFile struct {
	Conductors []Conductor `json:"conductors"`
}

// pending is the one enrollment code that may be outstanding.
type pending struct {
	TokenHash string    `json:"token_hash"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Failures  int       `json:"failures"`
}

// Trust keeps the pinned conductor keys and the outstanding enrollment
// code in the state directory (trust.json, enrollment.json, 0600). Both the
// agent and its command line use it, so every change takes an exclusive
// lock (trust.lock) and every read goes to the files.
type Trust struct {
	dir         string
	maxFailures int
	now         func() time.Time
	mu          sync.Mutex
}

// Enrollment errors.
var (
	ErrNoCode     = errors.New("no enrollment code is outstanding (run conductor-files enroll-code on the file server)")
	ErrExpired    = errors.New("the enrollment code has expired")
	ErrWrongToken = errors.New("the enrollment code does not match")
	ErrBurned     = errors.New("too many wrong enrollment codes: the code was cancelled")
)

// NewTrust opens the trust store in dir.
func NewTrust(dir string, maxFailures int) *Trust {
	return &Trust{dir: dir, maxFailures: maxFailures, now: time.Now}
}

func (t *Trust) path(name string) string { return filepath.Join(t.dir, name) }

// locked runs fn holding the process mutex and the file lock.
func (t *Trust) locked(fn func() error) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	f, err := os.OpenFile(t.path("trust.lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		return err
	}
	defer func() { _ = unix.Flock(int(f.Fd()), unix.LOCK_UN) }()
	return fn()
}

func readJSON(p string, v any) error {
	b, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// writeJSON replaces a file atomically (temporary file, fsync, rename).
func writeJSON(p string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := p + ".tmp"
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

func (t *Trust) load() (trustFile, error) {
	var tf trustFile
	if err := readJSON(t.path("trust.json"), &tf); err != nil && !errors.Is(err, os.ErrNotExist) {
		return tf, err
	}
	return tf, nil
}

func (t *Trust) loadPending() (*pending, error) {
	var p pending
	if err := readJSON(t.path("enrollment.json"), &p); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	return &p, nil
}

// List returns the pinned conductor keys.
func (t *Trust) List() ([]Conductor, error) {
	var out []Conductor
	err := t.locked(func() error {
		tf, err := t.load()
		out = tf.Conductors
		return err
	})
	return out, err
}

// Pinned reports whether pin is a trusted conductor key.
func (t *Trust) Pinned(pin string) bool {
	list, err := t.List()
	if err != nil {
		return false
	}
	return slices.ContainsFunc(list, func(c Conductor) bool { return filesapi.PinEqual(c.Pin, pin) })
}

// Pending reports whether an unexpired enrollment code is outstanding.
func (t *Trust) Pending() bool {
	ok := false
	_ = t.locked(func() error {
		p, err := t.loadPending()
		ok = err == nil && p != nil && t.now().Before(p.ExpiresAt) && p.Failures < t.maxFailures
		return nil
	})
	return ok
}

// NewCode replaces any outstanding code with a new one valid for ttl and
// returns its token (shown once; only its hash is stored).
func (t *Trust) NewCode(ttl time.Duration) (string, time.Time, error) {
	token, err := filesapi.NewToken()
	if err != nil {
		return "", time.Time{}, err
	}
	now := t.now().UTC()
	exp := now.Add(ttl)
	err = t.locked(func() error {
		return writeJSON(t.path("enrollment.json"), pending{TokenHash: filesapi.TokenHash(token), CreatedAt: now, ExpiresAt: exp})
	})
	return token, exp, err
}

// CancelCode removes any outstanding code.
func (t *Trust) CancelCode() error {
	return t.locked(func() error {
		err := os.Remove(t.path("enrollment.json"))
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	})
}

// Enroll consumes the outstanding code if token matches and pins the
// caller's key. A wrong token counts as a failure; the code is burned after
// maxFailures.
func (t *Trust) Enroll(token, pin, name, by string) error {
	return t.locked(func() error {
		p, err := t.loadPending()
		if err != nil {
			return err
		}
		if p == nil {
			return ErrNoCode
		}
		if !t.now().Before(p.ExpiresAt) {
			_ = os.Remove(t.path("enrollment.json"))
			return ErrExpired
		}
		if p.Failures >= t.maxFailures {
			_ = os.Remove(t.path("enrollment.json"))
			return ErrBurned
		}
		if subtle.ConstantTimeCompare([]byte(filesapi.TokenHash(token)), []byte(p.TokenHash)) != 1 {
			p.Failures++
			if p.Failures >= t.maxFailures {
				_ = os.Remove(t.path("enrollment.json"))
				return ErrBurned
			}
			if err := writeJSON(t.path("enrollment.json"), p); err != nil {
				return err
			}
			return ErrWrongToken
		}
		tf, err := t.load()
		if err != nil {
			return err
		}
		tf.Conductors = slices.DeleteFunc(tf.Conductors, func(c Conductor) bool { return c.Pin == pin })
		tf.Conductors = append(tf.Conductors, Conductor{Pin: pin, Name: name, EnrolledAt: t.now().UTC(), EnrolledBy: by})
		if err := writeJSON(t.path("trust.json"), tf); err != nil {
			return err
		}
		return os.Remove(t.path("enrollment.json"))
	})
}

// Remove unpins a key and reports whether it was pinned.
func (t *Trust) Remove(pin string) (bool, error) {
	removed := false
	err := t.locked(func() error {
		tf, err := t.load()
		if err != nil {
			return err
		}
		n := len(tf.Conductors)
		tf.Conductors = slices.DeleteFunc(tf.Conductors, func(c Conductor) bool { return c.Pin == pin })
		removed = len(tf.Conductors) != n
		if !removed {
			return nil
		}
		return writeJSON(t.path("trust.json"), tf)
	})
	return removed, err
}
