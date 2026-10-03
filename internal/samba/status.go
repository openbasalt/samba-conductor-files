package samba

// The smbstatus JSON reader is adapted from tui-tools' tui-samba
// (internal/samba/parse.go, MIT License, Copyright (c) 2026 Edimar
// Cardoso), the same way the ad library is shared with tui-dc.

import (
	"encoding/json"
	"errors"
	"path"
	"sort"
	"strings"

	"github.com/openbasalt/samba-conductor-files/filesapi"
)

// ParseStatusJSON reads `smbstatus --json` (Samba >= 4.17).
func ParseStatusJSON(out []byte) ([]filesapi.Session, []filesapi.TreeConnect, []filesapi.OpenFile, error) {
	// smbstatus prints its own warnings before the document on some
	// builds, so the parse starts at the first brace.
	s := string(out)
	start := strings.IndexByte(s, '{')
	if start < 0 {
		return nil, nil, nil, errors.New("samba: smbstatus printed no JSON document")
	}
	var report statusReport
	if err := json.Unmarshal([]byte(s[start:]), &report); err != nil {
		return nil, nil, nil, errors.New("samba: smbstatus JSON: " + err.Error())
	}
	sessions := make([]filesapi.Session, 0, len(report.Sessions))
	for _, x := range report.Sessions {
		sessions = append(sessions, filesapi.Session{SessionID: x.SessionID, PID: x.ServerID.PID, User: x.Username,
			Group: x.Groupname, Machine: x.RemoteMachine, Remote: x.Hostname, Protocol: x.SessionDialect,
			Encryption: x.Encryption.String(), Signing: x.Signing.String()})
	}
	tcons := make([]filesapi.TreeConnect, 0, len(report.Tcons))
	for _, x := range report.Tcons {
		tcons = append(tcons, filesapi.TreeConnect{Share: x.Service, PID: x.ServerID.PID, Machine: x.Machine,
			Since: x.ConnectedAt, Encryption: x.Encryption.String(), Signing: x.Signing.String()})
	}
	locked := map[string]bool{}
	for _, l := range report.ByteRangeLocks {
		locked[path.Join(l.SharePath, l.FileName)] = true
	}
	var files []filesapi.OpenFile
	for key, f := range report.OpenFiles {
		full := key
		if f.ServicePath != "" && f.Filename != "" {
			full = path.Join(f.ServicePath, f.Filename)
		}
		for _, o := range f.Opens {
			files = append(files, filesapi.OpenFile{PID: o.ServerID.PID, User: o.Username, Path: full,
				Access: o.AccessMask.Text, Oplock: o.Oplock.Text, Locked: locked[full]})
		}
	}
	sort.Slice(sessions, func(i, j int) bool {
		if sessions[i].User != sessions[j].User {
			return sessions[i].User < sessions[j].User
		}
		return sessions[i].SessionID < sessions[j].SessionID
	})
	sort.Slice(tcons, func(i, j int) bool {
		if tcons[i].Share != tcons[j].Share {
			return tcons[i].Share < tcons[j].Share
		}
		return tcons[i].PID < tcons[j].PID
	})
	sort.Slice(files, func(i, j int) bool {
		if files[i].Path != files[j].Path {
			return files[i].Path < files[j].Path
		}
		return files[i].PID < files[j].PID
	})
	return sessions, tcons, files, nil
}

// statusReport is the subset of `smbstatus --json` read here; key names
// are Samba's own (source3/utils/status_json.c).
type statusReport struct {
	Sessions       map[string]jsonSession    `json:"sessions"`
	Tcons          map[string]jsonTcon       `json:"tcons"`
	OpenFiles      map[string]jsonOpenFile   `json:"open_files"`
	ByteRangeLocks map[string]jsonRangeLocks `json:"byte_range_locks"`
}

type jsonServerID struct {
	PID string `json:"pid"`
}

type jsonCrypto struct {
	Cipher string `json:"cipher"`
	Degree string `json:"degree"`
}

func (c jsonCrypto) String() string {
	if c.Cipher != "" {
		return c.Cipher
	}
	if c.Degree != "" {
		return c.Degree
	}
	return "-"
}

type jsonSession struct {
	SessionID      string       `json:"session_id"`
	ServerID       jsonServerID `json:"server_id"`
	Username       string       `json:"username"`
	Groupname      string       `json:"groupname"`
	RemoteMachine  string       `json:"remote_machine"`
	Hostname       string       `json:"hostname"`
	SessionDialect string       `json:"session_dialect"`
	Encryption     jsonCrypto   `json:"encryption"`
	Signing        jsonCrypto   `json:"signing"`
}

type jsonTcon struct {
	Service     string       `json:"service"`
	ServerID    jsonServerID `json:"server_id"`
	Machine     string       `json:"machine"`
	ConnectedAt string       `json:"connected_at"`
	Encryption  jsonCrypto   `json:"encryption"`
	Signing     jsonCrypto   `json:"signing"`
}

type jsonOpenFile struct {
	ServicePath string              `json:"service_path"`
	Filename    string              `json:"filename"`
	Opens       map[string]jsonOpen `json:"opens"`
}

type jsonMask struct {
	Text string `json:"text"`
}

type jsonOpen struct {
	ServerID   jsonServerID `json:"server_id"`
	Username   string       `json:"username"`
	AccessMask jsonMask     `json:"access_mask"`
	Oplock     jsonMask     `json:"oplock"`
}

type jsonRangeLocks struct {
	FileName  string `json:"file_name"`
	SharePath string `json:"share_path"`
}
