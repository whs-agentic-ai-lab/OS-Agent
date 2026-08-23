#!/usr/bin/env bash
set -euo pipefail

# Run only inside a disposable Ubuntu container. This script creates fixed test
# users/groups and writes /etc/sudoers.d inside that container.
apt-get update -qq
apt-get install -y -qq curl python3 sudo >/dev/null

groupadd --gid 10004 agent-host
useradd --uid 10004 --gid agent-host --home-dir /nonexistent --shell /usr/sbin/nologin agent-host
groupadd --gid 10005 agent-trial
groupadd --gid 10006 os-agent-supervisor
useradd --uid 10003 --gid os-agent-supervisor --home-dir /nonexistent --shell /usr/sbin/nologin backend-peer

install -d -o root -g root -m 0755 /opt/trial/host-canaries
install -d -o root -g os-agent-supervisor -m 0750 /run/os-agent
install -o root -g root -m 0755 /source/host_supervisor.py /opt/trial/host-supervisor.py

/usr/bin/python3 /opt/trial/host-supervisor.py --serve &
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
  response=$(runuser -u backend-peer -- curl -sS \
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

# The Host trial subject must not be able to reach the privileged control socket.
if runuser -u agent-host -- curl -sS --unix-socket /run/os-agent/host-supervisor.sock \
  http://host-supervisor/v1/execute >/dev/null 2>&1; then
  echo "agent-host unexpectedly reached the Supervisor socket" >&2
  exit 1
fi

echo "Host Supervisor integration checks passed."
