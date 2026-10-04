# conductor-files: guidelines

Agent on Samba domain-member file servers (never a DC): registry shares
(`net conf`), NT ACLs by AD group SID, live sessions, managed by conductor's
admin UI over mutually pinned TLS. Spec: [design.md](docs/design.md).

- Read `../CLAUDE.md` (family rules) and [architecture.md](https://github.com/openbasalt/samba-conductor-docs/blob/main/architecture.md).
- Typed, allowlisted operations only: no free-form commands or arguments; the
  Samba programs run with fixed paths, no shell, values validated first.
- Paths only below the configured roots; symbolic links are never followed
  for writes; smb.conf is never edited (registry configuration only).
- Go: `make check` (gofmt, vet, staticcheck, govulncheck, `go test -race`).
  Code comments and docs in English. Commit with explicit paths (never
  `git add -A`).
- Lab: fs1 in the main lab (`lab/fs-up.sh`, `fs-join.sh`);
  `make lab-test` runs the integration tests there (the lab host).
