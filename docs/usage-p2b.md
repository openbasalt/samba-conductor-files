# P2b in the lab: what was verified

Lab: [testing.md](https://github.com/openbasalt/samba-conductor-docs/blob/main/testing.md) (the lab host). fs1 = `conductor-lab-fs1`,
10.93.0.20, Debian 13, Samba 4.22.11 member of `LAB.CONDUCTOR.TEST`
(winbind, idmap rid), share root `/srv/shares`, conductor-files installed
with the unit of `deploy/systemd` (the real sandbox).

```sh
lab/fs-up.sh          # the VM, snapshot member-base (on the lab host)
lab/fs-join.sh        # join (from member-base)
make lab-test                  # from the laptop: build, install on fs1, run internal/labtest as root on fs1
```

## `conductor-files check` on fs1

```
fs1.lab.conductor.test: conductor-files <version>, Samba 4.22.11-Debian-4.22.11+dfsg-0+deb13u1, domain LAB (LAB.CONDUCTOR.TEST)
key sha256:<agent pin>
  ok   member_not_dc    member server
  ok   security_ads     ADS
  ok   domain_trust     LAB.CONDUCTOR.TEST
  ok   registry_shares
  ok   acl_xattr        acl_xattr
  ok   roots            /srv/shares
  ok   smbstatus_json
  ok   samba_tools
```

## Integration tests (`internal/labtest`, 2026-10-03: all passed, ~30 s)

The test plays conductor: its own key pair, the installed agent over TLS,
smbclient as lab users for the SMB side.

| Test | Proves |
|---|---|
| untrusted key refused at the handshake | with no enrollment code outstanding, an unknown client key gets `remote error: tls: bad certificate` |
| wrong agent key refused by the client | conductor's side refuses an agent whose key is not the pinned one (`PinMismatchError`) |
| enrollment | with a code outstanding the handshake passes but only `enroll` is served (`not_enrolled`); a wrong token is refused; the right one pins the key; the code is single use |
| directories | roots listed; a folder outside the roots refused |
| refusals | outside the roots, a root itself, `..`, a symbolic link, a path through a symbolic link, a parent writable by others, an unknown SID, a user SID, Domain Admins, a SID of another domain, a reserved name, `%` in the comment, shadow copies without a profile: all `invalid` with the reason |
| create, access, sessions, update, remove | plan (nothing written), stale digest refused (`conflict`), apply; `user0001` (Engineering, modify) uploads, `user0002` (Sales) gets `NT_STATUS_ACCESS_DENIED`; a held smbclient session appears in `sessions.list` with its connection; update to Engineering read + Sales modify: Sales writes, Engineering reads but cannot write; re-planning the same spec is a no-op; a change made by hand between plan and apply makes the apply conflict; removal: `NT_STATUS_BAD_NETWORK_NAME`, the folder and its files kept |
| shares not created by conductor-files are left alone | a share added with `net conf addshare` is listed (registry, not managed); plan and remove are `forbidden` |
| audit chain and revocation | `conductor-files audit verify` intact; `unenroll` then the key fails the handshake |

A plan as the agent shows it (create, a new folder):

```
[lt-eng]
	path = /srv/shares/lt-eng
	comment = Lab test
	read only = no
	guest ok = no
	browseable = yes
	conductor-files:managed = yes

# create the folder /srv/shares/lt-eng (owner root:root, mode 0700, no symbolic links followed)
/usr/bin/samba-tool ntacl set --use-s3fs -- 'O:S-1-5-32-544G:S-1-5-32-544D:PAI(A;OICI;0x001f01ff;;;S-1-5-18)(A;OICI;0x001f01ff;;;S-1-5-32-544)(A;OICI;0x001f01ff;;;<domain>-512)(A;OICI;0x001301bf;;;<domain>-4105)' /srv/shares/lt-eng
/usr/bin/net conf import /var/lib/conductor-files/import/lt-eng.conf lt-eng
/usr/bin/sharesec lt-eng --replace=S-1-5-32-544:ALLOWED/0/FULL,<domain>-512:ALLOWED/0/FULL,<domain>-4105:ALLOWED/0/CHANGE
/usr/bin/smbcontrol smbd reload-config
```

What Samba stores (read back with `samba-tool ntacl get --as-sddl`):
`O:BAG:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;DA)(A;OICI;0x1301bf;;;<Engineering SID>)`,
and the matching POSIX ACLs (`getfacl`: `group:LAB\engineering:rwx`,
`other::---`, default entries for new content).

The UI flows (conductor's File servers section driving this agent) are in
`../../conductor/docs/usage-p2b.md`.
