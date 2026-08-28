#!/usr/bin/env bash
set -Eeuo pipefail
umask 0027

readonly OUTPUT=/var/log/os-agent/docker-events.ndjson
readonly STATE_DIR=/var/lib/os-agent/docker-event-relay
readonly CURSOR_FILE="$STATE_DIR/since"
readonly LOCK_FILE="$STATE_DIR/output.lock"

install -d -o root -g vector -m 0750 "$(dirname "$OUTPUT")" "$STATE_DIR"
touch "$OUTPUT"
chown root:vector "$OUTPUT"
chmod 0640 "$OUTPUT"

while true; do
  since="$(cat "$CURSOR_FILE" 2>/dev/null || date +%s)"

  /usr/bin/docker events \
    --since "$since" \
    --filter type=container \
    --filter container=os-agent-runtime \
    --filter container=os-agent-container1 \
    --filter container=os-agent-container2 \
    --filter container=os-agent-container3 \
    --format '{{json .}}' |
  while IFS= read -r raw; do
    [[ -n "$raw" ]] || continue
    event_hash="$(printf '%s' "$raw" | sha256sum | awk '{print $1}')"
    event_time="$(jq -r '.time // empty' <<<"$raw")"
    enriched="$(jq -c \
      --arg event_id "docker-event-$event_hash" \
      --arg source "docker-events-relay" \
      '. + {event_id: $event_id, source: $source}' <<<"$raw")"

    {
      flock -x 9
      printf '%s\n' "$enriched" >>"$OUTPUT"
    } 9>"$LOCK_FILE"

    if [[ "$event_time" =~ ^[0-9]+$ ]]; then
      printf '%s\n' "$event_time" >"$CURSOR_FILE.tmp"
      mv -f "$CURSOR_FILE.tmp" "$CURSOR_FILE"
    fi
  done

  sleep 2
done
