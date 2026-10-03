# conductor-files — Guidelines

Agent on Samba **domain-member file servers** (never a DC): registry shares
(`net conf`), NT ACLs by AD group SID, live sessions, managed by conductor's
admin UI over mutually pinned TLS. Spec: `../planning/docs/p2b-spec.md`.

- Read `../CLAUDE.md` (family rules) and `../planning/docs/architecture.md`.
- Typed, allowlisted operations only: no free-form commands or arguments; the
  Samba programs run with fixed paths, no shell, values validated first.
- Paths only below the configured roots; symbolic links are never followed
  for writes; smb.conf is never edited (registry configuration only).
- Go: `make check` (gofmt, vet, staticcheck, govulncheck, `go test -race`).
  Code comments and docs in English. Commit with explicit paths (never
  `git add -A`).
- Lab: fs1 in the main lab (`planning/lab/fs-up.sh`, `fs-join.sh`);
  `make lab-test` runs the integration tests there (server-home).
