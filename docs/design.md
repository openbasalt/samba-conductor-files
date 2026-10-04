# conductor-files: design

`conductor-files` is an agent installed on Samba domain-member file
servers so that file shares can be managed from conductor's admin
interface. Administrators pick a folder below the roots the host allows,
the AD groups that get read, modify or full access, and a few options;
they review the exact change and confirm it with a second factor; the
agent applies it through Samba's registry configuration and NT ACLs.
conductor and the agent talk over TLS 1.3 with both keys pinned, and the
agent offers only typed operations. The cross-cutting design is in
[architecture.md](https://github.com/openbasalt/samba-conductor-docs/blob/main/architecture.md#integration-components),
packaging in
[packaging.md](https://github.com/openbasalt/samba-conductor-docs/blob/main/packaging.md),
and the conductor side in
[conductor's design](https://github.com/openbasalt/samba-conductor/blob/main/docs/design.md).

## Where it runs

- Only on domain-member servers (`security = ADS`, winbind). `serve`
  refuses to start when Samba reports an AD DC server role: DCs should host
  only `sysvol` and `netlogon`, so general file shares belong on member
  servers.
- `conductor-files check` lists every missing prerequisite: domain
  membership (`wbinfo -t`), `include = registry` in `[global]`,
  `acl_xattr` in `vfs objects`, `smbstatus --json` support, and the Samba
  programs it calls.
- Share roots are host configuration (`/etc/conductor-files/agent.toml`):
  absolute, root-owned, not writable by group or others. A request can
  never add a root, name a program, or carry free-form arguments.
- The agent listens on TCP 7443; the firewall should admit only the
  hosts running conductor.

## Enrollment with a one-time code

- Each side generates its own ECDSA P-256 key and self-signed certificate
  in its state directory; keys never travel.
- Root on the file server runs `conductor-files enroll-code`, which prints
  `cfe1.<token>.<agent key pin>`. The token is 32 random bytes, stored
  hashed, valid for one hour, single use; five wrong attempts burn it.
  `enroll-cancel` withdraws it.
- An administrator pastes the code and the server's address in conductor
  (preview and re-authentication). conductor connects pinning the agent's
  key from the code and sends the token; the agent checks it in constant
  time and pins conductor's key. Both sides audit the enrollment.
- The direction is deliberate: conductor needs no new unauthenticated
  endpoint, the code proves root access on the file server, and the pin
  inside the code defeats a man in the middle.

## Mutually pinned TLS

- TLS 1.3 with client certificates and no certificate authority. Each
  side pins the other's public key (SHA-256 of the SubjectPublicKeyInfo).
- Before enrollment the agent's handshake accepts an unknown client key
  only while a code is outstanding, and such a connection may only call
  `enroll`. Otherwise unknown keys fail the handshake (and are logged). An
  agent whose key changed is refused by conductor until enrolled again.
- Revocation: removing a server in conductor (re-authentication) calls
  `unenroll`, so the agent drops conductor's pin, then forgets the server
  even if the agent is unreachable (conductor then shows the command to
  run on the server). Locally, `conductor-files trust list` and
  `trust remove <pin>`.
- Key rotation without enrolling again is not implemented.

## Protocol and typed operations

One request and one response per connection, each one JSON line (at most
4 MiB), with a protocol version; parameters are decoded strictly and
validated on both sides. The public package `filesapi` holds the types,
validation, framing, TLS identities and the client that conductor imports.

| Operation | Does |
|---|---|
| `enroll`, `unenroll` | pin or drop the caller's key |
| `status` | versions, domain, roots, prerequisites, capabilities |
| `dirs.list` | subdirectories of a root, one level per call, links never followed, hidden entries omitted |
| `groups.resolve` | SID to name and type through winbind |
| `shares.list`, `share.get` | shares (managed or not), parameters, share ACL, NT ACL of the folder |
| `share.plan`, `share.apply` | plan a share spec; apply it bound to the plan's digest |
| `share.remove_plan`, `share.remove` | plan and apply a removal |
| `sessions.list` | sessions, tree connects and open files from `smbstatus --json` |

Samba programs run from fixed paths, without a shell, with `LANG=C` and
`--` before user values where the program supports it.

## Registry shares through net conf

- A share is written with `net conf import FILE SHARE`, which replaces
  that one section in a transaction, from a section the agent renders
  itself and marks `conductor-files:managed = yes`. `smb.conf` is never
  written.
- Shares without the marker (made by hand, or in `smb.conf`) are listed
  read-only and never changed or removed.
- Values are validated: share names match
  `[A-Za-z0-9][A-Za-z0-9._-]{0,62}$?`, reserved names (global, homes,
  printers, print$, ipc$, netlogon, sysvol) are refused, and no value may
  contain `%` (Samba substitutions), a backslash, a quote or a control
  character.
- Options: browseable (on by default), access-based enumeration, recycle
  bin (`vfs_recycle`), previous versions (`vfs_shadow_copy2`, offered only
  when the host configures a snapshot profile).
- A new share is created in this order: folder (root:root 0700), NT ACL,
  `net conf import`, `sharesec`, `smbcontrol smbd reload-config`, so the
  share is never visible with a folder carrying other permissions.
  Removal runs `sharesec --delete` first (a stale descriptor would apply to
  a future share of the same name), then `net conf delshare`; the folder
  and its files are kept.

## NT ACLs by AD group SID

- Access is granted to AD groups by SID. Each SID must resolve through
  winbind to a group or alias of the joined domain; users, other domains
  and Domain Admins are refused as grant targets. Existence and type are
  checked with `wbinfo -s`, because with idmap `rid` any RID maps to an ID
  whether it exists or not.
- Levels: read (read and execute, `0x1200a9`), modify (`0x1301bf`) and
  full (`FA`).
- The NT ACL on the share folder is protected (no inheritance from the
  root) and inheritable (`OI|CI`), owned by BUILTIN\Administrators, with
  SYSTEM, Administrators and Domain Admins full. It is written with
  `samba-tool ntacl set --use-s3fs`, through smbd's own VFS, so
  `security.NTACL` and the POSIX ACLs agree.
- Share permissions (`sharesec --replace`) mirror the groups (READ, CHANGE,
  FULL) plus Administrators and Domain Admins FULL, so a group that loses
  access is refused at the next tree connect even where older files carry
  inherited entries.
- Existing content is not re-permissioned; recursive propagation is not
  implemented.

## Paths

- Strictly below a configured root. Every component is opened with
  `openat` and `O_NOFOLLOW`; a symbolic link is refused.
- The root and every parent of a share folder must be root-owned and not
  writable by group or others (mode bits, which also reflect a POSIX ACL
  mask), so nobody else can swap a component between the check and the
  ACL write. New folders are created with `mkdirat` under such a parent.
  A consequence: a share folder cannot be created inside another share
  whose users can write to its parent.

## Plan, then apply bound to a digest

- `share.plan` returns the exact registry section (before and after), the
  share ACL and NT ACL (before and after, names resolved), the commands in
  order, warnings as codes, and a digest of the spec, the current state
  and the commands. It writes nothing.
- `share.apply` re-plans and runs only when the digest is the same; any
  change on the server between plan and apply is refused.
- conductor shows the plan as ACL differences above the audited text
  preview and requires a fresh second factor to confirm.

## Audit on the agent

- The agent keeps a hash-chained JSON-lines log
  (`/var/lib/conductor-files/audit.log`) of every change and refusal: the
  AD user conductor acted for (name, SID, session hash, source address),
  the client key, the operation, the plan digest, the commands run and the
  result. Both `serve` and the CLI append to it, under an exclusive file
  lock that re-reads the last line. `conductor-files audit verify` checks
  the chain.
- conductor records the same writes in its own audit log.

## Sessions

`sessions.list` reports SMB sessions, tree connects and open files parsed
from `smbstatus --json`. Closing sessions or open files is not
implemented.

## Trust model

- The agent cannot check AD roles itself (it holds no AD credentials
  beyond the machine account), so it trusts conductor's role decisions.
  conductor allows `files.read` to administrators and auditors and
  `files.write` to administrators, re-checks roles against AD, and
  requires a fresh second factor for every write.
- The agent's own guarantees do not depend on conductor: only typed
  operations, only below the roots, only managed shares, only domain
  group SIDs, never `smb.conf`, never on a DC. A compromised conductor can
  change share access within those bounds, and every change is recorded
  on the agent.
- Several conductor instances may each enroll their own key on one server;
  each is pinned separately.

## Sandbox

The agent runs as root (registry configuration and ACLs need it) in a
sandboxed unit with exactly CHOWN, DAC_OVERRIDE, DAC_READ_SEARCH, FOWNER
and SYS_ADMIN (for `security.NTACL`), `ProtectSystem=strict` with write
access only to Samba's state, its own state and the share roots,
`NoNewPrivileges`, a private `/tmp`, restricted address families and the
`@system-service` system call filter.

## Decisions

- A separate agent on member servers, never on a DC: Samba's guidance for
  DCs, and a narrower blast radius.
- No CA, pinned keys on both sides: nothing to issue, renew or revoke
  centrally; revocation is deleting a pin on either side.
- Enrollment started on the file server: proves root there and keeps
  conductor free of unauthenticated endpoints.
- `net conf import` rather than `addshare` plus `setparm`: one
  transaction, so a failure cannot leave a half-configured share.
- Only shares carrying the marker are managed: hand-made configuration is
  never overwritten.
- Groups by SID, never names: names can be renamed or collide; SIDs
  cannot.
- NT ACL plus mirrored share permissions: removing a group takes effect
  at once without walking existing content.
- Plan and apply bound to a digest: what the administrator reviewed is
  exactly what runs.
- No dependency on the `ad` library: the agent resolves SIDs through
  winbind on the member server.
