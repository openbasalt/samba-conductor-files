# Installing conductor-files on a file server

conductor-files runs on a **Samba domain-member file server**, never on a
domain controller. These steps were followed in the lab on Debian 13 with
Samba 4.22 (`planning/lab/fs-up.sh`, `fs-join.sh`, `files-install.sh`).

## 1. The member server

Packages (Debian 13 / Ubuntu 26.04): `samba winbind libnss-winbind
libpam-winbind krb5-user smbclient acl attr python3-samba
samba-ad-provision` (the last two provide `samba-tool`, used for NT ACLs).
Time must be within 5 minutes of the DCs (chrony against a DC is enough);
`/etc/resolv.conf` points at the DCs.

`/etc/krb5.conf`:

```
[libdefaults]
	default_realm = EXAMPLE.COM
	dns_lookup_realm = false
	dns_lookup_kdc = true
```

`/etc/samba/smb.conf`, everything in `[global]`; shares go to the registry:

```
[global]
	workgroup = EXAMPLE
	realm = EXAMPLE.COM
	security = ADS
	server role = member server
	disable netbios = yes
	idmap config * : backend = tdb
	idmap config * : range = 3000-7999
	idmap config EXAMPLE : backend = rid
	idmap config EXAMPLE : range = 10000-999999
	winbind refresh tickets = yes
	vfs objects = acl_xattr
	map acl inherit = yes
	store dos attributes = yes
	server min protocol = SMB2_10
	include = registry
```

- `vfs objects = acl_xattr` (with `map acl inherit`) stores Windows ACLs in
  `security.NTACL` next to the POSIX ACLs; conductor-files requires it.
- `include = registry` makes smbd read the shares conductor-files writes with
  `net conf`. Keep it the last line of `[global]`.
- `idmap rid` (or `ad`) must cover the domain, so every group SID has a GID.

Join and start:

```
net ads join -U Administrator         # the password is asked (or $PASSWD)
sed -i -E 's/^(passwd|group):.*/\1: files winbind/' /etc/nsswitch.conf
systemctl enable --now winbind smbd
wbinfo -t                             # "checking the trust secret ... succeeded"
getent group 'EXAMPLE\domain users'
```

## 2. Share roots

Shares can only be created strictly below the configured roots. A root must
be a real directory owned by root and not writable by group or others:

```
install -d -m 0755 -o root -g root /srv/shares
```

Use a file system with extended attributes and POSIX ACLs (ext4, xfs,
btrfs). Folders made from the UI are created root:root 0700 and then get
their NT ACL. An existing folder can also be shared if its parents up to the
root are root-owned and not writable by others (so a share folder cannot sit
inside another share whose users can write to its parent).

## 3. Install the agent

```
install -m 0755 conductor-files /usr/local/bin/conductor-files
install -m 0644 conductor-files.service /etc/systemd/system/
install -d -m 0755 /etc/conductor-files /etc/systemd/system/conductor-files.service.d
install -m 0644 agent.toml.example /etc/conductor-files/agent.toml   # then edit roots and name
printf '[Service]\nReadWritePaths=/srv/shares\n' > /etc/systemd/system/conductor-files.service.d/roots.conf
systemctl daemon-reload
systemctl enable --now conductor-files
conductor-files check
```

The drop-in lists every root (`ReadWritePaths=` may appear once per root):
the unit's file system is otherwise read-only. `check` must show every line
`ok`; the agent refuses changes until it does.

Firewall: allow TCP 7443 from the host(s) running conductor only. The agent
does not need outbound connections.

## 4. Enroll the file server in conductor

conductor needs `[files]` in `/etc/conductor/conductor.toml`:

```
[files]
enabled = true
```

On the file server, as root:

```
conductor-files enroll-code
```

It prints a one-time code (`cfe1.<token>.<key>`, valid 1 hour, single use;
five wrong attempts cancel it). In conductor: **File servers → Add a file
server**, the server's address (`fs1.example.com` or `fs1.example.com:7443`)
and the code; review and confirm with your second factor. conductor pins the
agent's key from the code; the agent pins conductor's key. On the file
server `conductor-files trust list` shows the enrolled conductor.

## 5. Revoking

- From conductor: the server page → **Remove** (second factor). conductor
  tells the agent to drop its key and forgets the server.
- On the file server: `conductor-files trust remove sha256:<pin>` (from
  `trust list`). conductor's calls then fail at the TLS handshake.
- A new agent key (the state directory was lost) needs a new enrollment:
  remove the server in conductor and add it again with a new code.

## 6. Files

| Path | What |
|---|---|
| `/etc/conductor-files/agent.toml` | configuration (root, 0644) |
| `/var/lib/conductor-files/tls-key.pem`, `tls-cert.pem` | the agent's key pair (0600) |
| `/var/lib/conductor-files/trust.json` | pinned conductor keys |
| `/var/lib/conductor-files/enrollment.json` | the outstanding code's hash (while one exists) |
| `/var/lib/conductor-files/audit.log` | hash-chained audit log (`conductor-files audit verify`) |
| `/var/lib/conductor-files/import/` | the share section handed to `net conf import`, removed after each run |
