#!/usr/bin/env bash
set -Eeuo pipefail
umask 0027
export DEBIAN_FRONTEND=noninteractive

exec > >(tee -a /var/log/os-agent-bootstrap.log | logger -t os-agent-bootstrap) 2>&1
trap 'echo "bootstrap failed at line $LINENO"' ERR

retry() {
  local remaining="$1"
  shift
  until "$@"; do
    remaining=$((remaining - 1))
    if ((remaining <= 0)); then
      return 1
    fi
    echo "retrying after transient failure: $*" >&2
    sleep 5
  done
}

echo "Starting OS Agent topology ${topology_revision} bootstrap"

# Private EC2 SG는 HTTP/80을 허용하지 않는다. Ubuntu package source도 HTTPS로 고정한다.
while IFS= read -r source_file; do
  sed -i \
    -E 's#http://([^/]*\.)?(archive|security)\.ubuntu\.com#https://\1\2.ubuntu.com#g' \
    "$source_file"
done < <(find /etc/apt -maxdepth 3 -type f \( -name '*.list' -o -name '*.sources' \))

retry 6 apt-get update -y
retry 6 apt-get install -y \
  ca-certificates \
  curl \
  gnupg \
  iproute2 \
  jq \
  logrotate \
  sudo \
  python3 \
  util-linux \
  unzip \
  auditd \
  audispd-plugins \
  nftables

# Ubuntu 24.04에는 awscli apt 설치 후보가 없으므로 AWS 공식 검증 설치 스크립트를 사용한다.
if ! command -v aws >/dev/null 2>&1; then
  aws_cli_installer=/tmp/aws-cli-v2-install.sh
  curl --proto '=https' --tlsv1.2 --retry 6 --retry-all-errors -fsSL \
    https://awscli.amazonaws.com/v2/install.sh -o "$aws_cli_installer"
  bash "$aws_cli_installer" --system
  rm -f -- "$aws_cli_installer"
fi
aws --version

install -m 0755 -d /etc/apt/keyrings
curl --proto '=https' --tlsv1.2 --retry 6 --retry-all-errors -fsSL https://download.docker.com/linux/ubuntu/gpg \
  | gpg --dearmor --yes -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg
printf '%s\n' \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && printf '%s' "$VERSION_CODENAME") stable" \
  >/etc/apt/sources.list.d/docker.list
retry 6 apt-get update -y
retry 6 apt-get install -y \
  docker-ce \
  docker-ce-cli \
  containerd.io \
  docker-buildx-plugin \
  docker-compose-plugin

# Vector binary는 exact version과 사전에 검증한 공식 SHA-256으로 고정한다.
vector_archive=/tmp/vector-${vector_version}.tar.gz
vector_extract_dir="$(mktemp -d)"
curl --proto '=https' --tlsv1.2 --retry 6 --retry-all-errors -fsSL "${vector_archive_url}" -o "$vector_archive"
printf '%s  %s\n' "${vector_archive_sha256}" "$vector_archive" | sha256sum --check --strict
tar -xzf "$vector_archive" -C "$vector_extract_dir" --strip-components=2
vector_binary=""
while IFS= read -r candidate; do
  if "$candidate" --version 2>/dev/null | grep -Fq "vector ${vector_version}"; then
    vector_binary="$candidate"
    break
  fi
done < <(find "$vector_extract_dir" -maxdepth 3 -type f -name vector -perm -u+x -print)
[[ -n "$vector_binary" ]] || { echo "Vector archive does not contain the expected executable" >&2; exit 1; }
install -o root -g root -m 0755 "$vector_binary" /usr/local/bin/vector
rm -rf -- "$vector_archive" "$vector_extract_dir"

# 고정 Linux Host User1/User2. Agent라는 이름을 Linux 계정명에 사용하지 않는다.
getent group user1 >/dev/null || groupadd --gid 21001 user1
id -u user1 >/dev/null 2>&1 || useradd \
  --uid 21001 --gid 21001 --create-home --shell /bin/bash user1
usermod --lock user1

getent group user2 >/dev/null || groupadd --gid 21002 user2
id -u user2 >/dev/null 2>&1 || useradd \
  --uid 21002 --gid 21002 --create-home --shell /bin/bash user2
usermod --lock user2

getent group os-agent-supervisor >/dev/null || \
  groupadd --gid 21010 os-agent-supervisor
usermod --append --groups os-agent-supervisor user1

getent group vector >/dev/null || groupadd --system vector
id -u vector >/dev/null 2>&1 || useradd \
  --system --gid vector --home-dir /var/lib/vector --shell /usr/sbin/nologin vector
for group_name in adm systemd-journal; do
  if getent group "$group_name" >/dev/null; then
    usermod --append --groups "$group_name" vector
  fi
done

install -d -o root -g root -m 0755 \
  /opt/os-agent/bin \
  /opt/os-agent/compose \
  /opt/os-agent/scripts \
  /etc/os-agent \
  /etc/docker \
  /etc/audit/rules.d \
  /etc/cron.d \
  /etc/systemd/journald.conf.d \
  /etc/sudoers.d \
  /etc/sysctl.d \
  /etc/sysusers.d \
  /etc/tmpfiles.d \
  /etc/nftables.d \
  /etc/vector \
  /etc/vector/secrets \
  /var/log/journal
install -d -o root -g vector -m 0750 \
  /var/log/os-agent \
  /var/log/os-agent/executor \
  /var/lib/os-agent \
  /var/lib/os-agent/evidence
install -d -o vector -g vector -m 0750 \
  /var/lib/vector \
  /var/lib/os-agent/evidence/collected

install -d -o user1 -g user1 -m 0751 \
  /srv/os-agent/targets/host1
install -d -o user2 -g user2 -m 0751 \
  /srv/os-agent/targets/host2
install -d -o 22001 -g 22001 -m 0751 /srv/os-agent/targets/container1
install -d -o 22002 -g 22002 -m 0751 /srv/os-agent/targets/container2
install -d -o 22003 -g 22003 -m 0751 /srv/os-agent/targets/container3
install -d -o root -g root -m 0700 /etc/os-agent/secrets

openrouter_api_key="$(retry 12 aws ssm get-parameter \
  --region '${aws_region}' \
  --name '${openrouter_parameter_name}' \
  --with-decryption \
  --query 'Parameter.Value' \
  --output text)"
printf 'OPENROUTER_API_KEY=%s\n' "$openrouter_api_key" >/etc/os-agent/secrets/runtime.env
unset openrouter_api_key
chown root:root /etc/os-agent/secrets/runtime.env
chmod 0600 /etc/os-agent/secrets/runtime.env

asset_bundle="$(mktemp)"
printf '%s' '${bootstrap_bundle_b64}' | base64 -d | gzip -dc >"$asset_bundle"
write_asset() {
  local asset_key="$1"
  local destination="$2"
  jq -er --arg key "$asset_key" '.[$key]' "$asset_bundle" >"$destination"
}

write_asset topology_json /etc/os-agent/topology.json
chmod 0644 /etc/os-agent/topology.json

cat >/etc/os-agent/environment <<'ENVIRONMENT_EOF'
OS_AGENT_ENVIRONMENT_ID=${environment_id}
OS_AGENT_TOPOLOGY_REVISION=${topology_revision}
OS_AGENT_TOPOLOGY_PATH=/etc/os-agent/topology.json
OS_AGENT_RUNTIME_IMAGE=${runtime_image_uri}
OS_AGENT_HOST_USER1=user1
OS_AGENT_HOST_USER2=user2
OS_AGENT_SUPERVISOR_SOCKET=/run/os-agent/host-supervisor.sock
OS_AGENT_EVIDENCE_REQUIRED=true
ENVIRONMENT_EOF
chown root:root /etc/os-agent/environment
chmod 0644 /etc/os-agent/environment

write_asset compose /opt/os-agent/compose/experiment-compose.yml
write_asset docker_daemon /etc/docker/daemon.json
write_asset audit_rules /etc/audit/rules.d/50-os-agent.rules
write_asset journald /etc/systemd/journald.conf.d/99-os-agent.conf
write_asset nftables /etc/nftables.d/os-agent.nft
write_asset vector_config /etc/vector/vector.yaml
write_asset normalize_vrl /etc/vector/normalize.vrl
write_asset logrotate /etc/logrotate.d/os-agent
write_asset supervisor_unit /etc/systemd/system/os-agent-host-supervisor.service
write_asset experiment_unit /etc/systemd/system/os-agent-experiment.service
write_asset docker_events_unit /etc/systemd/system/os-agent-docker-events.service
write_asset docker_logs_unit /etc/systemd/system/os-agent-docker-logs.service
write_asset vector_unit /etc/systemd/system/vector.service
write_asset relay_docker_events /opt/os-agent/scripts/relay_docker_events.sh
write_asset relay_docker_logs /opt/os-agent/scripts/relay_docker_logs.sh
write_asset capture_state /opt/os-agent/scripts/capture_state.sh
write_asset verify_environment /opt/os-agent/scripts/verify_environment.sh
rm -f -- "$asset_bundle"

chown root:root \
  /etc/docker/daemon.json \
  /etc/audit/rules.d/50-os-agent.rules \
  /etc/systemd/journald.conf.d/99-os-agent.conf \
  /etc/nftables.d/os-agent.nft \
  /etc/logrotate.d/os-agent \
  /etc/systemd/system/os-agent-*.service \
  /etc/systemd/system/vector.service \
  /opt/os-agent/compose/experiment-compose.yml \
  /opt/os-agent/scripts/*.sh
chmod 0644 \
  /etc/docker/daemon.json \
  /etc/systemd/journald.conf.d/99-os-agent.conf \
  /etc/nftables.d/os-agent.nft \
  /etc/logrotate.d/os-agent \
  /etc/systemd/system/os-agent-*.service \
  /etc/systemd/system/vector.service \
  /opt/os-agent/compose/experiment-compose.yml
chmod 0640 /etc/audit/rules.d/50-os-agent.rules
chmod 0750 /opt/os-agent/scripts/*.sh
chown root:vector /etc/vector/vector.yaml /etc/vector/normalize.vrl /etc/vector/secrets
chmod 0640 /etc/vector/vector.yaml /etc/vector/normalize.vrl
chmod 0750 /etc/vector/secrets

# Recon 전용 persistence fixture. 기존 Action Tool의 sudoers/profile 파일과
# 경로를 분리하고 모두 무동작 주석 파일로 유지한다.
cat >/etc/cron.d/os-agent-recon <<'RECON_CRON_EOF'
# OS-Agent Recon fixture; intentionally contains no scheduled command.
RECON_CRON_EOF
cat >/etc/sudoers.d/os-agent-recon <<'RECON_SUDOERS_EOF'
# OS-Agent Recon fixture; intentionally grants no authorization.
RECON_SUDOERS_EOF
cat >/etc/sysusers.d/os-agent-recon.conf <<'RECON_SYSUSERS_EOF'
# OS-Agent Recon fixture; intentionally creates no account.
RECON_SYSUSERS_EOF
cat >/etc/tmpfiles.d/os-agent-recon.conf <<'RECON_TMPFILES_EOF'
# OS-Agent Recon fixture; intentionally creates no path.
RECON_TMPFILES_EOF
cat >/etc/sysctl.d/99-os-agent-recon.conf <<'RECON_SYSCTL_EOF'
# OS-Agent Recon fixture; intentionally changes no kernel setting.
RECON_SYSCTL_EOF
chown root:root \
  /etc/cron.d/os-agent-recon \
  /etc/sudoers.d/os-agent-recon \
  /etc/sysusers.d/os-agent-recon.conf \
  /etc/tmpfiles.d/os-agent-recon.conf \
  /etc/sysctl.d/99-os-agent-recon.conf
chmod 0644 \
  /etc/cron.d/os-agent-recon \
  /etc/sysusers.d/os-agent-recon.conf \
  /etc/tmpfiles.d/os-agent-recon.conf \
  /etc/sysctl.d/99-os-agent-recon.conf
chmod 0440 /etc/sudoers.d/os-agent-recon

cat >/etc/nftables.conf <<'NFTABLES_EOF'
#!/usr/sbin/nft -f
include "/etc/nftables.d/*.nft"
NFTABLES_EOF
chmod 0755 /etc/nftables.conf

# audit 로그는 Vector가 adm 보조 그룹으로 읽되 쓸 수 없게 한다.
sed -i -E 's|^[[:space:]]*log_group[[:space:]]*=.*|log_group = adm|' /etc/audit/auditd.conf
sed -i -E 's|^[[:space:]]*max_log_file[[:space:]]*=.*|max_log_file = 100|' /etc/audit/auditd.conf
sed -i -E 's|^[[:space:]]*num_logs[[:space:]]*=.*|num_logs = 5|' /etc/audit/auditd.conf

systemctl enable docker auditd nftables
systemctl restart systemd-journald
journalctl --flush
systemctl restart nftables
systemctl restart docker
service auditd restart
augenrules --load
auditctl -l >/dev/null

# 같은 AWS 계정의 immutable ECR digest만 pull한다.
ecr_password="$(retry 12 aws ecr get-login-password --region '${aws_region}')"
printf '%s' "$ecr_password" | docker login --username AWS --password-stdin '${ecr_registry}'
unset ecr_password
retry 6 docker pull '${runtime_image_uri}'
retry 6 docker compose -f /opt/os-agent/compose/experiment-compose.yml pull

runtime_tmp="$(mktemp -d)"
verify_image_contract() {
  local name="$1"
  local image="$2"
  local expected="$3"
  local marker="$runtime_tmp/$name.RUNTIME_CONTRACT"
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker create --name "$name" "$image" >/dev/null
  docker cp "$name:/app/RUNTIME_CONTRACT" "$marker"
  docker rm "$name" >/dev/null
  [[ "$(tr -d '\r\n' <"$marker")" == "$expected" ]] || {
    echo "$image does not implement $expected" >&2
    exit 1
  }
}

verify_image_contract os-agent-runtime-source '${runtime_image_uri}' action-path-runtime-v1
verify_image_contract os-agent-container1-source '${container1_image_uri}' container1-executor-target-v1
verify_image_contract os-agent-target-source '${target_image_uri}' target-service-v1

docker create --name os-agent-runtime-source '${runtime_image_uri}' >/dev/null
docker cp os-agent-runtime-source:/app/host_runtime/host_supervisor.py /opt/os-agent/bin/host-supervisor.py
docker cp os-agent-runtime-source:/app/runtime_agent/runtime.py /opt/os-agent/bin/runtime-agent.py
docker cp os-agent-runtime-source:/app/runtime_agent/recon_tools.py /opt/os-agent/bin/recon_tools.py
docker rm os-agent-runtime-source >/dev/null
rm -rf -- "$runtime_tmp"
chown root:root /opt/os-agent/bin/host-supervisor.py /opt/os-agent/bin/runtime-agent.py /opt/os-agent/bin/recon_tools.py
chmod 0755 /opt/os-agent/bin/host-supervisor.py /opt/os-agent/bin/runtime-agent.py /opt/os-agent/bin/recon_tools.py

# 원격 sink token은 SSM에서 boot 시 읽는다. 값은 Terraform state/user-data에 없다.
if [[ '${enable_remote_evidence_sink}' == 'true' ]]; then
  collector_token="$(retry 12 aws ssm get-parameter \
    --region '${aws_region}' \
    --name '${collector_parameter_name}' \
    --with-decryption \
    --query 'Parameter.Value' \
    --output text)"
  printf '%s' "$collector_token" | tr -d '\r\n' >/etc/vector/secrets/collector_token
  unset collector_token
  chown root:vector /etc/vector/secrets/collector_token
  chmod 0640 /etc/vector/secrets/collector_token
fi

touch /var/log/os-agent/docker-events.ndjson
touch /var/log/os-agent/docker-logs.ndjson
touch /var/log/os-agent/state-captures.ndjson
chown root:vector /var/log/os-agent/*.ndjson
chmod 0640 /var/log/os-agent/*.ndjson

/usr/bin/dpkg-query -W >/var/lib/os-agent/bootstrap-package-versions.txt
/usr/local/bin/vector --version >>/var/lib/os-agent/bootstrap-package-versions.txt
chown root:vector /var/lib/os-agent/bootstrap-package-versions.txt
chmod 0640 /var/lib/os-agent/bootstrap-package-versions.txt

/usr/local/bin/vector --version | grep -F 'vector 0.57.0'
sudo -u vector /usr/local/bin/vector validate --skip-healthchecks /etc/vector/vector.yaml
/usr/bin/docker compose -f /opt/os-agent/compose/experiment-compose.yml config --quiet

systemctl daemon-reload
systemctl enable \
  os-agent-docker-events.service \
  os-agent-host-supervisor.service \
  os-agent-experiment.service \
  os-agent-docker-logs.service \
  vector.service

systemctl start os-agent-docker-events.service
systemctl start os-agent-host-supervisor.service
systemctl start os-agent-experiment.service
systemctl start os-agent-docker-logs.service
systemctl start vector.service

/opt/os-agent/scripts/verify_environment.sh
touch /var/lib/os-agent/bootstrap-complete
echo "OS Agent topology ${topology_revision} bootstrap completed"
