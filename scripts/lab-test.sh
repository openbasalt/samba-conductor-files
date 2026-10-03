#!/usr/bin/env bash
# Integration tests on fs1, the main lab's domain-member file server
# (planning/docs/lab.md): build the agent and the test binary here, install
# the agent on fs1 (planning/lab/files-install.sh), run the tests there as
# root. The lab user password goes from server-home's secrets file to fs1
# on stdin (0600 file, deleted afterwards), never on a command line.
#
#   scripts/lab-test.sh [-run REGEX]
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
LAB_HOST="${LAB_HOST:-server-home}"
make build >/dev/null
GOWORK=off CGO_ENABLED=0 go test -c -tags lab -o bin/lab/labtest.test ./internal/labtest/
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
cp bin/conductor-files deploy/systemd/conductor-files.service bin/lab/labtest.test "$stage/"
ssh -o BatchMode=yes "$LAB_HOST" 'rm -rf ~/build-files && mkdir -p ~/build-files'
rsync -a "$stage/" "$LAB_HOST:build-files/"
rsync -a ../planning/lab/ "$LAB_HOST:samba-conductor/planning/lab/"
ssh -o BatchMode=yes "$LAB_HOST" bash -s -- "$*" <<'REMOTE'
set -euo pipefail
cd ~/samba-conductor/planning/lab
source ./common.sh
./files-install.sh ~/build-files </dev/null >/dev/null
opts=(); mapfile -t opts < <(ssh_opts)
scp -q "${opts[@]}" ~/build-files/labtest.test "debian@${DC_IP[fs1]}:/tmp/labtest.test" </dev/null
# shellcheck disable=SC1090
( set -a; . "$SECRETS"; set +a; printf 'LAB_USER_PASSWORD=%s\n' "$LAB_USER_PASSWORD" ) |
  ssh "${opts[@]}" "debian@${DC_IP[fs1]}" 'sudo sh -c "umask 077; cat > /root/labtest.env"'
rc=0
ssh -n "${opts[@]}" "debian@${DC_IP[fs1]}" "sudo sh -c 'set -a; . /root/labtest.env; set +a; rm -f /root/labtest.env; cd /tmp && /tmp/labtest.test -test.v -test.count=1 ${1:-}'" || rc=$?
ssh -n "${opts[@]}" "debian@${DC_IP[fs1]}" 'sudo rm -f /root/labtest.env /tmp/labtest.test /tmp/lt-upload.txt'
exit "$rc"
REMOTE
