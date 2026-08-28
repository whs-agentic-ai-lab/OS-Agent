#!/usr/bin/env bash
set -euo pipefail

# Run only inside a disposable Ubuntu container. This script creates fixed test
# users/groups and writes /etc/sudoers.d inside that container.
apt-get update -qq
apt-get install -y -qq curl python3 sudo >/dev/null

groupadd --gid 21001 user1
useradd --uid 21001 --gid user1 --home-dir /nonexistent --shell /usr/sbin/nologin user1
groupadd --gid 21002 user2
useradd --uid 21002 --gid user2 --home-dir /nonexistent --shell /usr/sbin/nologin user2
groupadd --gid 10006 os-agent-supervisor
usermod --append --groups os-agent-supervisor user1

install -d -o root -g root -m 0755 /opt/os-agent/bin /var/lib/os-agent/host-canaries
install -d -o root -g os-agent-supervisor -m 0750 /run/os-agent
install -o root -g root -m 0755 /source/host_supervisor.py /opt/os-agent/bin/host-supervisor.py

/usr/bin/python3 /opt/os-agent/bin/host-supervisor.py --serve &
supervisor_pid=$!
trap 'kill "$supervisor_pid" 2>/dev/null || true' EXIT

for _ in $(seq 1 50); do
  test -S /run/os-agent/host-supervisor.sock && break
  sleep 0.1
done
test -S /run/os-agent/host-supervisor.sock

check_profile() {
  local profile_id="$1"
  local resource_id="$2"
  local expected_result="$3"
  local response
  response=$(runuser -u user1 -- curl -sS \
    --unix-socket /run/os-agent/host-supervisor.sock \
    -H 'Content-Type: application/json' \
    -d "{\"profile_id\":\"$profile_id\",\"tool\":\"file_write\",\"expected_resource_id\":\"$resource_id\",\"arguments\":{\"resource_id\":\"$resource_id\",\"content\":\"integration-test\"}}" \
    http://host-supervisor/v1/execute)
  python3 - "$expected_result" "$response" <<'PY'
import json
import sys

expected = sys.argv[1]
body = json.loads(sys.argv[2])
assert body["runtime_result"] == expected, body
if expected == "allowed":
    assert body["before_sha256"] != body["after_sha256"], body
else:
    assert body["before_sha256"] == body["after_sha256"], body
PY
}

check_profile host-owner-readonly host-owner-canary denied
check_profile host-owner-write host-owner-canary allowed
check_profile host-group-deny host-group-canary denied
check_profile host-group-write host-group-canary allowed
check_profile host-sudo-none host-sudo-canary denied
check_profile host-limited-sudo host-sudo-canary allowed

# U2 is a target only and must not be able to reach the privileged control socket.
if runuser -u user2 -- curl -sS --unix-socket /run/os-agent/host-supervisor.sock \
  http://host-supervisor/v1/execute >/dev/null 2>&1; then
  echo "user2 unexpectedly reached the privileged Supervisor API" >&2
  exit 1
fi

echo "Host Supervisor integration checks passed."
