# conductor-files

File shares on Samba **domain-member file servers**, managed from Samba
Conductor's admin UI ("share a directory on the network from the admin
screen"). Part of Samba Conductor v2; design: `../planning/docs/architecture.md`
§6, phase spec: `../planning/docs/p2b-spec.md`.

`conductor-files` is a small agent installed on each file server. Conductor
(the web UI on the DC) drives it over mutually pinned TLS; administrators
pick a folder below the allowed roots, the AD groups that get read, modify or
full access, and a few options, review the exact change and confirm it with
their second factor.

## What it does

| | |
|---|---|
| Where | Samba member servers (`security = ADS`, winbind). It refuses to start on a domain controller: DCs should host only sysvol and netlogon |
| Shares | Samba's **registry configuration** (`net conf import`, one section replaced in a transaction); `smb.conf` is never edited; only shares it created (marked `conductor-files:managed = yes`) are changed or removed, others are listed read-only |
| Access | by **AD group SID** (resolved through winbind): an NT ACL on the share folder (`samba-tool ntacl set --use-s3fs`, so Samba writes security.NTACL and the matching POSIX ACLs) and the same groups as share permissions (`sharesec`). SYSTEM, Administrators and Domain Admins always have full control |
| Options | browseable, access-based enumeration, recycle bin (`vfs_recycle`), previous versions (`vfs_shadow_copy2`, only when the host has a snapshot profile) |
| Sessions | `smbstatus --json`: sessions, connections, open files |
| Removal | the share and its share permissions go; the folder and its files stay |

## Safety rules

| Rule | How |
|---|---|
| Typed operations only | an allowlist of operations with strictly decoded, validated parameters; no free-form command or argument; Samba programs with fixed paths, no shell, `--` before user values where the program supports it |
| Paths | only strictly below the configured roots; every component opened with `O_NOFOLLOW` (a symbolic link is refused); the root and every parent must be root-owned and not writable by group or others, so nobody else can swap a component between the check and the ACL write; new folders created with `mkdirat` (root:root, 0700) |
| Values | share names `[A-Za-z0-9][A-Za-z0-9._-]{0,62}$?`, reserved names refused; no `%` (Samba substitutions), backslash, quote or control character in any value |
| Plan, then apply | every change is planned first (the exact section, commands and ACL before/after); the apply re-plans and runs only if the digest of the reviewed plan still matches |
| Trust | TLS 1.3 with client certificates and no CA: the agent pins conductor's key (learned at enrollment with a one-time code), conductor pins the agent's key (carried in that code). Unknown keys fail the handshake |
| Audit | every change and refusal in a hash-chained JSON-lines log (`audit verify`), with the AD user conductor acted for, the client key, the plan digest and the commands run |
| Sandbox | root with a narrow capability set (CHOWN, DAC_OVERRIDE, DAC_READ_SEARCH, FOWNER, SYS_ADMIN for security.NTACL), read-only system except Samba's state, its own state and the roots |

## Commands

```
conductor-files serve                 # the agent (systemd unit)
conductor-files enroll-code [--ttl 1h] [--quiet]
conductor-files enroll-cancel
conductor-files trust list | trust remove sha256:<pin>
conductor-files check                 # prerequisites
conductor-files audit verify
conductor-files version
```

## Documentation

- `docs/install.md`: preparing a member server, installing, enrolling,
  revoking.
- `docs/usage-p2b.md`: what was verified in the lab.
- `../planning/docs/decisions.md` (P2b): design decisions.

## Development

`make check` (gofmt, vet, staticcheck, govulncheck, `go test -race`);
`make lab-test` runs the integration tests on fs1 in the server-home lab
(`../planning/docs/lab.md`).
