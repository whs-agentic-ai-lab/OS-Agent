#!/usr/bin/env bash
set -Eeuo pipefail
umask 0077

readonly RUN_ID="${1:-}"
readonly ACTION_ID="${2:-}"
readonly PATH_ID="${3:-}"
readonly PHASE="${4:-}"
readonly TARGET_ID="${5:-}"

safe_id='^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'
[[ "$RUN_ID" =~ $safe_id ]] || { echo "invalid run_id" >&2; exit 64; }
[[ "$ACTION_ID" =~ $safe_id ]] || { echo "invalid action_id" >&2; exit 64; }
[[ "$PHASE" == "before" || "$PHASE" == "after" ]] || { echo "phase must be before or after" >&2; exit 64; }

case "$PATH_ID:$TARGET_ID" in
  U1C1:C1|U1C2:C2|U1U2:U2|U1C3:C3|C1U1:U1|C1C2:C2|C1U2:U2|C1C3:C3) ;;
  *) echo "path_id and target_id do not match the fixed topology" >&2; exit 64 ;;
esac

case "$TARGET_ID" in
  U1) target_path=/srv/os-agent/targets/host1; target_user=user1; container_name="" ;;
  U2) target_path=/srv/os-agent/targets/host2; target_user=user2; container_name="" ;;
  C1) target_path=/srv/os-agent/targets/container1; target_user=""; container_name=os-agent-container1 ;;
  C2) target_path=/srv/os-agent/targets/container2; target_user=""; container_name=os-agent-container2 ;;
  C3) target_path=/srv/os-agent/targets/container3; target_user=""; container_name=os-agent-container3 ;;
  *) echo "unknown target_id" >&2; exit 64 ;;
esac

readonly ROOT=/var/lib/os-agent/evidence/runs
readonly ACTION_ROOT="$ROOT/$RUN_ID/actions/$ACTION_ID"
readonly FINAL_DIR="$ACTION_ROOT/$PHASE"
readonly LOCK_FILE="$ACTION_ROOT/.capture.lock"
readonly EVENT_FILE=/var/log/os-agent/state-captures.ndjson

install -d -o root -g vector -m 0750 "$ACTION_ROOT"
touch "$EVENT_FILE"
chown root:vector "$EVENT_FILE"
chmod 0640 "$EVENT_FILE"
exec 9>"$LOCK_FILE"
flock -x 9

mark_boundary() {
  local status="$1"
  local exit_code="${2:-0}"
  local message="os_agent_state run_id=$RUN_ID action_id=$ACTION_ID path_id=$PATH_ID phase=$PHASE target_id=$TARGET_ID status=$status exit_code=$exit_code"
  logger -t os-agent-state -- "$message" || true
  auditctl -m "$message" >/dev/null 2>&1 || true
}

publish_event() {
  local final_dir="$1"
  local manifest_sha
  local artifact_index_sha
  local occurred_at
  local event_id
  local event

  (
    cd "$final_dir"
    sha256sum --check --strict artifact-sha256.txt >/dev/null
  )
  manifest_sha="$(sha256sum "$final_dir/manifest.json" | awk '{print $1}')"
  artifact_index_sha="$(sha256sum "$final_dir/artifact-sha256.txt" | awk '{print $1}')"
  occurred_at="$(jq -r '.occurred_at' "$final_dir/manifest.json")"
  event_id="state-$artifact_index_sha"
  event="$(jq -cn \
    --arg event_id "$event_id" \
    --arg occurred_at "$occurred_at" \
    --arg run_id "$RUN_ID" \
    --arg action_id "$ACTION_ID" \
    --arg path_id "$PATH_ID" \
    --arg phase "$PHASE" \
    --arg target_id "$TARGET_ID" \
    --arg artifact_path "$final_dir" \
    --arg manifest_sha256 "$manifest_sha" \
    --arg artifact_index_sha256 "$artifact_index_sha" \
    '{
      event_id: $event_id,
      occurred_at: $occurred_at,
      source: "snapshot-runner",
      event_type: "STATE_CAPTURED",
      run_id: $run_id,
      action_id: $action_id,
      path_id: $path_id,
      phase: $phase,
      target_id: $target_id,
      artifact_path: $artifact_path,
      manifest_sha256: $manifest_sha256,
      artifact_index_sha256: $artifact_index_sha256
    }')"

  {
    flock -x 8
    if ! grep -Fq '"event_id":"'"$event_id"'"' "$EVENT_FILE"; then
      printf '%s\n' "$event" >>"$EVENT_FILE"
    fi
  } 8>/var/lib/os-agent/state-event.lock
}

if [[ -d "$FINAL_DIR" ]]; then
  jq -e \
    --arg run_id "$RUN_ID" \
    --arg action_id "$ACTION_ID" \
    --arg path_id "$PATH_ID" \
    --arg phase "$PHASE" \
    --arg target_id "$TARGET_ID" \
    '.status == "COMPLETE" and .run_id == $run_id and .action_id == $action_id and
     .path_id == $path_id and .phase == $phase and .target_id == $target_id' \
    "$FINAL_DIR/manifest.json" >/dev/null
  publish_event "$FINAL_DIR"
  mark_boundary REPUBLISHED
  printf '%s\n' "$FINAL_DIR"
  exit 0
fi

if [[ "$PHASE" == "after" ]]; then
  if [[ ! -d "$ACTION_ROOT/before" ]]; then
    echo "before capture must exist before after capture" >&2
    exit 65
  fi
  jq -e '.status == "COMPLETE" and .phase == "before"' \
    "$ACTION_ROOT/before/manifest.json" >/dev/null
  (
    cd "$ACTION_ROOT/before"
    sha256sum --check --strict artifact-sha256.txt >/dev/null
  )
fi

tmp_dir="$(mktemp -d "$ACTION_ROOT/.${PHASE}.tmp.XXXXXX")"
cleanup() {
  [[ -n "${tmp_dir:-}" && -d "$tmp_dir" ]] && rm -rf -- "$tmp_dir"
}
on_error() {
  local exit_code=$?
  set +e
  cleanup
  mark_boundary FAILED "$exit_code"
  trap - ERR EXIT
  exit "$exit_code"
}
trap on_error ERR
trap cleanup EXIT
mark_boundary STARTED

date -u +"%Y-%m-%dT%H:%M:%S.%NZ" >"$tmp_dir/timestamp_utc.txt"
cat /proc/sys/kernel/random/boot_id >"$tmp_dir/boot_id.txt"
journalctl --show-cursor -n 0 --no-pager >"$tmp_dir/journal_cursor.txt" 2>&1 || true
auditctl -s >"$tmp_dir/audit_status.txt" 2>&1 || true
ps -eo pid,ppid,uid,gid,lstart,args --sort=pid >"$tmp_dir/processes.txt"
ss -H -lntup >"$tmp_dir/listeners.txt" 2>&1 || true

if [[ -n "$target_user" ]]; then
  id "$target_user" >"$tmp_dir/identity.txt"
  ps -u "$target_user" -o pid,ppid,uid,gid,lstart,args >"$tmp_dir/target_processes.txt" 2>&1 || true
else
  docker inspect "$container_name" | jq 'walk(if type == "object" then del(.Env, .Config.Env) else . end)' \
    >"$tmp_dir/container_inspect.json"
  docker top "$container_name" -eo pid,ppid,uid,gid,lstart,args >"$tmp_dir/container_processes.txt" 2>&1 || true
  docker diff "$container_name" >"$tmp_dir/container_diff.txt" 2>&1 || true
fi

find "$target_path" -xdev -type f -print0 |
  sort -z |
  xargs -0 -r sha256sum >"$tmp_dir/files.sha256"
find "$target_path" -xdev -printf '%y %m %U %G %s %T@ %p\n' |
  sort >"$tmp_dir/files.metadata"

if [[ "$PHASE" == "after" ]]; then
  diff -u "$ACTION_ROOT/before/files.sha256" "$tmp_dir/files.sha256" \
    >"$tmp_dir/diff-from-before.txt" || true
fi

jq -n \
  --arg run_id "$RUN_ID" \
  --arg action_id "$ACTION_ID" \
  --arg path_id "$PATH_ID" \
  --arg phase "$PHASE" \
  --arg target_id "$TARGET_ID" \
  --arg target_path "$target_path" \
  --arg occurred_at "$(cat "$tmp_dir/timestamp_utc.txt")" \
  '{
    schema_version: "state-capture-v1",
    status: "COMPLETE",
    run_id: $run_id,
    action_id: $action_id,
    path_id: $path_id,
    phase: $phase,
    target_id: $target_id,
    target_path: $target_path,
    occurred_at: $occurred_at
  }' >"$tmp_dir/manifest.json"

(
  cd "$tmp_dir"
  find . -maxdepth 1 -type f ! -name artifact-sha256.txt -print0 |
    sort -z |
    xargs -0 sha256sum
) >"$tmp_dir/artifact-sha256.txt"
chown -R root:vector "$tmp_dir"
chmod -R u=rwX,g=rX,o= "$tmp_dir"
mv "$tmp_dir" "$FINAL_DIR"
tmp_dir=""

publish_event "$FINAL_DIR"
mark_boundary COMPLETE
trap - ERR EXIT
printf '%s\n' "$FINAL_DIR"
