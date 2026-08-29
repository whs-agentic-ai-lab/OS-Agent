#!/usr/bin/env bash
set -Eeuo pipefail
umask 0027

readonly OUTPUT=/var/log/os-agent/docker-events.ndjson
readonly STATE_DIR=/var/lib/os-agent/docker-event-relay
readonly CURSOR_FILE="$STATE_DIR/since"
readonly LAST_EVENT_FILE="$STATE_DIR/last-event-id"
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
    event_id="docker-event-$event_hash"
    if [[ -f "$LAST_EVENT_FILE" && "$(cat "$LAST_EVENT_FILE")" == "$event_id" ]]; then
      continue
    fi

    event_time_nano=""
    if [[ "$raw" =~ \"timeNano\":([0-9]+) ]]; then
      event_time_nano="${BASH_REMATCH[1]}"
    fi
    if [[ ${#event_time_nano} -gt 9 ]]; then
      seconds="${event_time_nano:0:${#event_time_nano}-9}"
      nanoseconds="${event_time_nano: -9}"
      event_time="$seconds.$nanoseconds"
    else
      event_time="$(jq -r '.time // empty | tostring' <<<"$raw")"
    fi
    occurred_at="$(date -u --date="@$event_time" +'%Y-%m-%dT%H:%M:%S.%NZ')"
    enriched="$(jq -c \
      --arg event_id "$event_id" \
      --arg source "docker-events-relay" \
      --arg occurred_at "$occurred_at" \
      '. + {event_id: $event_id, source: $source, occurred_at: $occurred_at}' <<<"$raw")"

    {
      flock -x 9
      printf '%s\n' "$enriched" >>"$OUTPUT"
    } 9>"$LOCK_FILE"

    printf '%s\n' "$event_id" >"$LAST_EVENT_FILE.tmp"
    mv -f "$LAST_EVENT_FILE.tmp" "$LAST_EVENT_FILE"
    printf '%s\n' "$event_time" >"$CURSOR_FILE.tmp"
    mv -f "$CURSOR_FILE.tmp" "$CURSOR_FILE"
  done

  sleep 2
done
