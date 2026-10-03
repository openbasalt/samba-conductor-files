package samba

import (
	"strings"
	"testing"
)

func TestParseConf(t *testing.T) {
	out := `Load smb config files from /etc/samba/smb.conf
Loaded services file OK.
Server role: ROLE_DOMAIN_MEMBER

# Global parameters
[global]
	realm = LAB.CONDUCTOR.TEST
	vfs objects = acl_xattr
	include = registry

[eng]
	path = /srv/shares/eng
	comment = Engineering = files
	conductor-files:managed = yes
`
	secs := ParseConf(out)
	if len(secs) != 2 || secs[1].Name != "eng" {
		t.Fatalf("%+v", secs)
	}
	if v, ok := secs[1].Get("Comment"); !ok || v != "Engineering = files" {
		t.Fatalf("comment %q", v)
	}
	if v, _ := secs[1].Get("conductor-files:managed"); v != "yes" {
		t.Fatal("managed marker")
	}
	if NormKey("  Read   Only ") != "read only" {
		t.Fatal("normkey")
	}
	r := RenderSection(secs[1])
	if !strings.HasPrefix(r, "[eng]\n\tpath = /srv/shares/eng\n") {
		t.Fatalf("render %q", r)
	}
	if again := ParseConf(r); len(again) != 1 || len(again[0].Params) != 3 {
		t.Fatalf("round trip %+v", again)
	}
}

func TestParseLookup(t *testing.T) {
	n, k, err := ParseLookup("LAB\\Domain Admins 2\n")
	if err != nil || n != `LAB\Domain Admins` || k != SidGroup {
		t.Fatalf("%q %d %v", n, k, err)
	}
	if _, _, err := ParseLookup("garbage"); err == nil {
		t.Fatal("garbage parsed")
	}
}

// statusFixture is smbstatus --json from Samba 4.22 with one session, one
// tree connect and one open file (trimmed).
const statusFixture = `{"timestamp": "2026-10-03T08:00:00+0000", "version": "4.22.11", "smb_conf": "/etc/samba/smb.conf",
"sessions": {"3412": {"session_id": "3412", "server_id": {"pid": "2201", "task_id": "0", "vnn": "4294967295", "unique_id": "1"},
 "uid": 11105, "gid": 10513, "username": "LAB\\user0001", "groupname": "LAB\\domain users", "creation_time": "2026-10-03T08:00:00+0000",
 "expiration_time": "30828-09-14T02:48:05+0000", "auth_time": "2026-10-03T08:00:00+0000", "remote_machine": "10.93.0.11",
 "hostname": "ipv4:10.93.0.11:50110", "session_dialect": "SMB3_11", "client_guid": "x",
 "encryption": {"cipher": "", "degree": "none"}, "signing": {"cipher": "AES-128-GMAC", "degree": "partial"}, "channels": {}}},
"tcons": {"7": {"service": "eng", "server_id": {"pid": "2201"}, "tcon_id": "7", "session_id": "3412", "machine": "10.93.0.11",
 "connected_at": "2026-10-03T08:00:01+0000", "encryption": {"cipher": "", "degree": "none"}, "signing": {"cipher": "", "degree": "none"}}},
"open_files": {"/srv/shares/eng/a.txt": {"service_path": "/srv/shares/eng", "filename": "a.txt", "fileid": {}, "num_pending_deletes": 0,
 "opens": {"2201/1": {"server_id": {"pid": "2201"}, "uid": 11105, "username": "LAB\\user0001", "share_file_id": "1",
 "sharemode": {"text": "R"}, "access_mask": {"text": "R"}, "caching": {"text": ""}, "oplock": {"text": "LEASE(RWH)"}, "lease": {}, "opened_at": "x"}}}}}`

func TestParseStatusJSON(t *testing.T) {
	s, tc, f, err := ParseStatusJSON([]byte("warning: something\n" + statusFixture))
	if err != nil {
		t.Fatal(err)
	}
	if len(s) != 1 || s[0].User != `LAB\user0001` || s[0].Protocol != "SMB3_11" || s[0].Signing != "AES-128-GMAC" || s[0].Encryption != "none" {
		t.Fatalf("sessions %+v", s)
	}
	if len(tc) != 1 || tc[0].Share != "eng" || tc[0].PID != "2201" {
		t.Fatalf("tcons %+v", tc)
	}
	if len(f) != 1 || f[0].Path != "/srv/shares/eng/a.txt" || f[0].Oplock != "LEASE(RWH)" {
		t.Fatalf("files %+v", f)
	}
	if _, _, _, err := ParseStatusJSON([]byte("no json")); err == nil {
		t.Fatal("no json parsed")
	}
}
