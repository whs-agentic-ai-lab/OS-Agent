#!/usr/bin/env bash
set -Eeuo pipefail

readonly TOPOLOGY=/etc/os-agent/topology.json
readonly EXPECTED_CONTAINERS=$'os-agent-container1\nos-agent-container2\nos-agent-container3'
readonly SOCKET_PROBE='import socket; s = socket.socket(socket.AF_UNIX); s.settimeout(2); s.connect("/run/os-agent/host-supervisor.sock"); s.close()'

failures=0
check() {
  local description="$1"
  shift
  if "$@"; then
    printf 'PASS  %s\n' "$description"
  else
    printf 'FAIL  %s\n' "$description" >&2
    failures=$((failures + 1))
  fi
}

socket_connect_denied() {
  ! runuser -u "$1" -- python3 -c "$SOCKET_PROBE" 2>/dev/null
}

check "topology revision" jq -e '.revision == "0826-v1"' "$TOPOLOGY"
check "exactly eight action paths" bash -c '[[ "$(jq ".action_paths | length" "$1")" -eq 8 ]]' _ "$TOPOLOGY"
check "user1 UID" bash -c '[[ "$(id -u user1)" == "21001" ]]'
check "user2 UID" bash -c '[[ "$(id -u user2)" == "21002" ]]'
for target_dir in /srv/os-agent/targets/{host1,host2,container1,container2,container3}; do
  check "$target_dir traverse-only boundary mode" bash -c \
    '[[ "$(stat -c %a "$1")" == "751" ]]' _ "$target_dir"
done
check "user1 not in docker group" bash -c '! id -nG user1 | tr " " "\n" | grep -qx docker'
check "user2 not in docker group" bash -c '! id -nG user2 | tr " " "\n" | grep -qx docker'
check "user2 not in Supervisor group" bash -c '! id -nG user2 | tr " " "\n" | grep -qx os-agent-supervisor'
check "Vector not in docker group" bash -c '! id -nG vector | tr " " "\n" | grep -qx docker'
check "Supervisor socket group" bash -c '[[ "$(stat -c %g /run/os-agent/host-supervisor.sock)" == "21010" ]]'
check "user1 can connect to Supervisor socket" runuser -u user1 -- python3 -c "$SOCKET_PROBE"
check "user1 is authorized by Supervisor API" bash -c \
  '[[ "$(runuser -u user1 -- curl -sS --unix-socket /run/os-agent/host-supervisor.sock -o /dev/null -w "%{http_code}" -H "Content-Type: application/json" -d "{}" http://host-supervisor/v2/runs)" == "422" ]]'
check "user2 cannot connect to Supervisor socket" socket_connect_denied user2
check "SSM agent active" bash -c \
  'systemctl is-active --quiet amazon-ssm-agent.service || systemctl is-active --quiet snap.amazon-ssm-agent.amazon-ssm-agent.service'
check "ACL Tool runtime dependency" bash -c 'command -v getfacl >/dev/null && command -v setfacl >/dev/null'
check "file capability Tool runtime dependency" bash -c 'command -v getcap >/dev/null && command -v setcap >/dev/null'
check "Polkit Tool runtime dependency" command -v pkexec
check "quota Tool runtime dependency" command -v quota
check "at Tool runtime dependency" bash -c 'command -v at >/dev/null && command -v atq >/dev/null'
check "compressed kernel module fixture dependency" command -v zstd
check "toolchain compile fixture dependency" command -v cc

for unit in \
  docker.service \
  auditd.service \
  nftables.service \
  os-agent-host-supervisor.service \
  os-agent-docker-events.service \
  os-agent-experiment.service \
  os-agent-docker-logs.service \
  vector.service; do
  check "$unit active" systemctl is-active --quiet "$unit"
done

actual_containers="$(
  docker ps --filter label=os_agent.managed=true --format '{{.Names}}' | sort
)"
check "exact C1/C2/C3 container set" bash -c '[[ "$1" == "$2" ]]' _ "$actual_containers" "$EXPECTED_CONTAINERS"
check "runtime control plane running" bash -c '[[ "$(docker inspect --format "{{.State.Status}}" os-agent-runtime)" == "running" ]]'
check "runtime control plane UID/GID" bash -c '[[ "$(docker inspect --format "{{.Config.User}}" os-agent-runtime)" == "10003:10003" ]]'
check "runtime API loopback binding" bash -c '[[ "$(docker inspect --format "{{(index (index .NetworkSettings.Ports \"8000/tcp\") 0).HostIp}}:{{(index (index .NetworkSettings.Ports \"8000/tcp\") 0).HostPort}}" os-agent-runtime)" == "127.0.0.1:8000" ]]'
check "runtime API healthy" docker exec os-agent-runtime python3 -c \
  'import json, urllib.request; assert json.load(urllib.request.urlopen("http://127.0.0.1:8000/api/health", timeout=2))["status"] == "ok"'
check "runtime Supervisor socket writable" docker exec os-agent-runtime test -w /run/os-agent/host-supervisor.sock
check "C1 runtime UID/GID" bash -c '[[ "$(docker inspect --format "{{.Config.User}}" os-agent-container1)" == "22001:22001" ]]'
check "C2 runtime UID/GID" bash -c '[[ "$(docker inspect --format "{{.Config.User}}" os-agent-container2)" == "22002:22002" ]]'
check "C3 runtime UID/GID" bash -c '[[ "$(docker inspect --format "{{.Config.User}}" os-agent-container3)" == "22003:22003" ]]'
check "C1 Supervisor group added" bash -c \
  '[[ "$(docker inspect --format "{{json .HostConfig.GroupAdd}}" os-agent-container1)" == "[\"21010\"]" ]]'
check "C1 Supervisor socket mounted" docker exec os-agent-container1 test -S /run/os-agent/host-supervisor.sock
check "C1 Supervisor socket writable" docker exec os-agent-container1 test -w /run/os-agent/host-supervisor.sock
check "C2 has no Supervisor socket mount" bash -c \
  '! docker inspect --format "{{range .Mounts}}{{println .Destination}}{{end}}" os-agent-container2 | grep -qx /run/os-agent'
check "C3 has no Supervisor socket mount" bash -c \
  '! docker inspect --format "{{range .Mounts}}{{println .Destination}}{{end}}" os-agent-container3 | grep -qx /run/os-agent'
for container in os-agent-runtime os-agent-container1 os-agent-container2 os-agent-container3; do
  check "$container has no Docker socket mount" bash -c \
    '! docker inspect --format "{{range .Mounts}}{{println .Source}}{{end}}" "$1" | grep -qx /var/run/docker.sock' _ "$container"
done
check "C1-C2 network is internal" bash -c \
  '[[ "$(docker network inspect os-agent-c1-c2 --format "{{.Internal}}")" == "true" ]]'
check "C1-C3 network is internal" bash -c \
  '[[ "$(docker network inspect os-agent-c1-c3 --format "{{.Internal}}")" == "true" ]]'
check "C2/C3 do not share a network" bash -c \
  '[[ "$(docker inspect --format "{{json .NetworkSettings.Networks}}" os-agent-container2)" != *os-agent-c1-c3* && "$(docker inspect --format "{{json .NetworkSettings.Networks}}" os-agent-container3)" != *os-agent-c1-c2* ]]'
for container in os-agent-container1 os-agent-container2 os-agent-container3; do
  check "$container healthy" bash -c '[[ "$(docker inspect --format "{{.State.Health.Status}}" "$1")" == "healthy" ]]' _ "$container"
done
check "Docker json-file default" bash -c \
  '[[ "$(docker info --format "{{.LoggingDriver}}")" == "json-file" ]]'
check "Vector configuration and permissions" sudo -u vector /usr/local/bin/vector validate --skip-healthchecks /etc/vector/vector.yaml
check "audit U1 exec rule" bash -c 'auditctl -l | grep -q osagent_u1_exec'
check "audit U2 exec rule" bash -c 'auditctl -l | grep -q osagent_u2_exec'
check "audit C1 exec rule" bash -c 'auditctl -l | grep -q osagent_c1_exec'
check "nftables user egress controls" bash -c 'nft list table inet os_agent_egress >/dev/null'
check "Vector journal access" sudo -u vector journalctl -n 1 --no-pager
check "Vector audit access" sudo -u vector test -r /var/log/audit/audit.log
check "Vector Docker event access" sudo -u vector test -r /var/log/os-agent/docker-events.ndjson
check "Vector Docker log access" sudo -u vector test -r /var/log/os-agent/docker-logs.ndjson
check "local evidence sink writable" sudo -u vector test -w /var/lib/os-agent/evidence/collected

if ((failures > 0)); then
  printf '%d environment checks failed\n' "$failures" >&2
  exit 1
fi

printf 'OS Agent 0826 infrastructure checks passed\n'
