// Package audit is the agent's append-only, hash-chained audit log: one
// JSON object per line, each carrying the SHA-256 of the previous line's
// hash and its own content, so any edit, removal or reordering is detected
// by Verify (`conductor-files audit verify`).
package audit

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// Results.
const (
	ResultOK     = "ok"
	ResultFailed = "failed"
	ResultDenied = "denied"
)

// Entry is one audited event.
type Entry struct {
	Seq  int64     `json:"seq"`
	Time time.Time `json:"time"`
	// Actor is the AD user conductor acted for ("conductor:user@ip"), or
	// "local:root" for the command line.
	Actor    string `json:"actor"`
	ActorSID string `json:"actor_sid,omitempty"`
	Session  string `json:"session,omitempty"`
	// Peer is the pin of the TLS client key (conductor).
	Peer   string   `json:"peer,omitempty"`
	Op     string   `json:"op"`
	Target string   `json:"target,omitempty"`
	Result string   `json:"result"`
	Detail string   `json:"detail,omitempty"`
	Digest string   `json:"digest,omitempty"`
	Steps  []string `json:"steps,omitempty"`
	Prev   string   `json:"prev"`
	Hash   string   `json:"hash,omitempty"`
}

// genesis is the "previous hash" of the first entry.
const genesis = "0000000000000000000000000000000000000000000000000000000000000000"

func hashOf(e Entry) (string, error) {
	e.Hash = ""
	b, err := json.Marshal(e)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte(e.Prev+"\n"), b...))
	return hex.EncodeToString(sum[:]), nil
}

// Log appends to an audit file. Several processes (the agent and its
// command line) may append: each append takes an exclusive lock on the file
// and continues the chain from the last line actually in it.
type Log struct {
	mu   sync.Mutex
	path string
	now  func() time.Time
}

// Open opens (or creates, 0600) the log after verifying the whole chain.
func Open(path string) (*Log, error) {
	if _, _, err := verify(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return &Log{path: path, now: time.Now}, nil
}

// Append writes e (sequence, time and chain filled in) and syncs it.
func (l *Log) Append(e Entry) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	f, err := os.OpenFile(l.path, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		return err
	}
	defer func() { _ = unix.Flock(int(f.Fd()), unix.LOCK_UN) }()
	last, err := lastEntry(f)
	if err != nil {
		return err
	}
	e.Seq, e.Prev = 1, genesis
	if last != nil {
		e.Seq, e.Prev = last.Seq+1, last.Hash
	}
	e.Time = l.now().UTC()
	h, err := hashOf(e)
	if err != nil {
		return err
	}
	e.Hash = h
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		return err
	}
	return f.Sync()
}

// lastEntry reads the last line of the file (nil when empty).
func lastEntry(f *os.File) (*Entry, error) {
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := st.Size()
	if size == 0 {
		return nil, nil
	}
	const maxLine = 256 << 10 // entries are bounded by the agent (details clipped)
	n := min(size, int64(maxLine))
	buf := make([]byte, n)
	if _, err := f.ReadAt(buf, size-n); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	buf = bytes.TrimRight(buf, "\n")
	if i := bytes.LastIndexByte(buf, '\n'); i >= 0 {
		buf = buf[i+1:]
	} else if n < size {
		return nil, errors.New("audit: last line too long")
	}
	var e Entry
	if err := json.Unmarshal(buf, &e); err != nil {
		return nil, fmt.Errorf("audit: last line: %w", err)
	}
	return &e, nil
}

// Verify checks the whole file and returns the number of entries.
func Verify(path string) (int64, error) {
	n, _, err := verify(path)
	return n, err
}

func verify(path string) (int64, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = f.Close() }()
	return verifyReader(f)
}

func verifyReader(r io.Reader) (int64, string, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	prev := genesis
	var n int64
	for sc.Scan() {
		var e Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return n, "", fmt.Errorf("audit: line %d: %w", n+1, err)
		}
		if e.Seq != n+1 {
			return n, "", fmt.Errorf("audit: line %d has sequence %d", n+1, e.Seq)
		}
		if e.Prev != prev {
			return n, "", fmt.Errorf("audit: entry %d does not follow entry %d (chain broken)", e.Seq, n)
		}
		h, err := hashOf(e)
		if err != nil {
			return n, "", err
		}
		if h != e.Hash {
			return n, "", fmt.Errorf("audit: entry %d was modified (hash mismatch)", e.Seq)
		}
		prev = e.Hash
		n++
	}
	if err := sc.Err(); err != nil {
		return n, "", err
	}
	if n == 0 {
		return 0, "", nil
	}
	return n, prev, nil
}
