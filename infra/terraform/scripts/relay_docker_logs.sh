#!/usr/bin/env bash
set -Eeuo pipefail
umask 0027

readonly OUTPUT=/var/log/os-agent/docker-logs.ndjson
readonly STATE_DIR=/var/lib/os-agent/docker-log-relay
readonly LOCK_FILE="$STATE_DIR/output.lock"
readonly CONTAINERS=(os-agent-runtime os-agent-container1 os-agent-container2 os-agent-container3)

install -d -o root -g vector -m 0750 "$(dirname "$OUTPUT")" "$STATE_DIR"
touch "$OUTPUT"
chown root:vector "$OUTPUT"
chmod 0640 "$OUTPUT"

emit_line() {
  local container="$1"
  local container_id="$2"
  local stream="$3"
  local cursor_file="$4"
  local line="$5"
  local occurred_at
  local message
  local event_hash
  local record

  if [[ ! "$line" =~ ^([^[:space:]]+)[[:space:]](.*)$ ]]; then
    logger -t os-agent-docker-logs -- "$container $stream relay: $line"
    return 0
  fi

  occurred_at="${BASH_REMATCH[1]}"
  message="${BASH_REMATCH[2]}"
  if [[ ! "$occurred_at" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T.*Z$ ]]; then
    logger -t os-agent-docker-logs -- "$container $stream relay: $line"
    return 0
  fi

  event_hash="$(
    printf '%s\0%s\0%s\0%s' "$container_id" "$stream" "$occurred_at" "$message" |
      sha256sum | awk '{print $1}'
  )"
  record="$(jq -cn \
    --arg event_id "docker-log-$event_hash" \
    --arg occurred_at "$occurred_at" \
    --arg container_id "$container_id" \
    --arg container_name "$container" \
    --arg stream "$stream" \
    --arg message "$message" \
    '{
      event_id: $event_id,
      occurred_at: $occurred_at,
      source: "docker-logs-relay",
      container_id: $container_id,
      container_name: $container_name,
      stream: $stream,
      message: $message
    }')"

  {
    flock -x 9
    printf '%s\n' "$record" >>"$OUTPUT"
  } 9>"$LOCK_FILE"

  printf '%s\n' "$occurred_at" >"$cursor_file.tmp"
  mv -f "$cursor_file.tmp" "$cursor_file"
}

relay_stream() {
  local container="$1"
  local container_id="$2"
  local stream="$3"
  local cursor_file="$4"
  local line

  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    emit_line "$container" "$container_id" "$stream" "$cursor_file" "$line"
  done
}

relay_one_stream() {
  local container="$1"
  local stream="$2"
  local cursor_file="$STATE_DIR/$container.$stream.since"

  while true; do
    until /usr/bin/docker inspect "$container" >/dev/null 2>&1; do
      sleep 1
    done

    local container_id
    local since
    container_id="$(/usr/bin/docker inspect --format '{{.Id}}' "$container")"
    since="$(
      cat "$cursor_file" 2>/dev/null ||
        /usr/bin/docker inspect --format '{{.Created}}' "$container"
    )"

    if [[ "$stream" == "stdout" ]]; then
      /usr/bin/docker logs --follow --timestamps --since "$since" "$container" 2>/dev/null |
        relay_stream "$container" "$container_id" stdout "$cursor_file" || true
    else
      /usr/bin/docker logs --follow --timestamps --since "$since" "$container" \
        >/dev/null \
        2> >(relay_stream "$container" "$container_id" stderr "$cursor_file") || true
    fi

    sleep 2
  done
}

pids=()
for container in "${CONTAINERS[@]}"; do
  for stream in stdout stderr; do
    relay_one_stream "$container" "$stream" &
    pids+=("$!")
  done
done

trap 'kill "${pids[@]}" 2>/dev/null || true' TERM INT EXIT
wait -n "${pids[@]}"
