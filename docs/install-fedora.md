# Installing conductor-files on Basalt OS / Fedora

The conductor-files agent on a Basalt OS (Fedora 44 based, SELinux
enforcing) or Fedora 44 domain-member file server, from the RPM
packages. The steps are those of `docs/install.md`; this page lists what
differs. The Basalt OS package lab (see
[testing.md](https://github.com/openbasalt/samba-conductor-docs/blob/main/testing.md)) runs them with SELinux enforcing, plus the agent's
lab test (enrollment, shares with NT ACLs by AD group, SMB access as domain
users, live sessions, adopting a share made by hand).

## 1. The member server

Fedora's packages: `samba samba-winbind samba-winbind-clients
samba-common-tools samba-tools samba-client python3-samba
krb5-workstation acl attr` (`samba-tools` brings `samba-tool`, used for NT
ACLs; the `conductor-files` package recommends it, so dnf installs it with
the agent unless weak dependencies are turned off). `smb.conf` and the join as in `docs/install.md`; the name
service switch through authselect:

```sh
sudo net ads join -U Administrator
sudo authselect select winbind --force
sudo systemctl enable --now winbind smb
sudo firewall-cmd --permanent --add-service=samba
sudo firewall-cmd --permanent --add-port=7443/tcp
sudo firewall-cmd --reload
```

## 2. Share roots

As in `docs/install.md`, and labeled for Samba so smbd may serve them:

```sh
sudo install -d -m 0755 -o root -g root /srv/shares
sudo semanage fcontext -a -t samba_share_t '/srv/shares(/.*)?'
sudo restorecon -R /srv/shares
```

## 3. The agent

```sh
sudo dnf install conductor-files          # Basalt OS: from basalt-tools
sudo dnf install ./conductor-files-<version>-1.x86_64.rpm ./conductor-files-selinux-<version>-1.noarch.rpm
                                          # Fedora, or a release's assets (check SHA256SUMS)
```

Then the roots in `agent.toml` and the `roots.conf` drop-in, `systemctl
enable --now conductor-files`, `conductor-files check`, an enrollment code,
exactly as in `docs/install.md`.

## SELinux

The agent runs in `conductor_files_t` (root with the unit's capability set)
and listens on `conductor_files_port_t` (TCP 7443, labeled by the
`conductor_files_port` module of `conductor-files-selinux`). It reads its
configuration (`conductor_files_conf_t`), manages its state
(`conductor_files_var_lib_t`), Samba's registry configuration and databases
(`samba_var_t`) and folders and ACLs under the share roots
(`samba_share_t`), and runs `net`, `sharesec`, `samba-tool`, `smbstatus`,
`smbcontrol`, `wbinfo` and `testparm` in its own domain.

- Another agent port: `sudo semanage port -a -t conductor_files_port_t -p tcp <port>`.
- A root that is not labeled `samba_share_t` is refused by the policy (and
  smbd could not serve it): label every root as in section 2.

## Upgrade and removal

`dnf upgrade` restarts the agent when it runs and keeps an edited
`agent.toml` (`.rpmnew` beside it), its key pair and the pinned conductor
keys (no new enrollment). `dnf remove` stops and disables it and removes
the packaged files and both policy modules; it keeps
`/var/lib/conductor-files`, the `roots.conf` drop-in, the shares in the
registry and their folders.
