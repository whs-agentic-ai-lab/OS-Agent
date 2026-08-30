channel = to_string!(.collector_channel)
raw_message = if exists(.message) && is_string(.message) {
  string!(.message)
} else {
  ""
}

if exists(.message) && is_string(.message) {
  parsed, err = parse_json(.message)
  if err == null && is_object(parsed) {
    parsed_message = parsed.message
    . = merge!(., parsed)
    del(.message)
    if parsed_message != null {
      .message = parsed_message
    }
  }
}

.collector_channel = channel
.environment_id = "${environment_id}"
.topology_revision = "${topology_revision}"
.collector_received_at = now()

if !exists(.event_id) || !is_string(.event_id) || is_empty(string!(.event_id)) {
  event_seed = channel + "|" + raw_message
  if channel == "journald" && exists(.__CURSOR) {
    event_seed = channel + "|" + string!(.__CURSOR)
  } else if channel == "auditd" {
    event_seed = channel + "|" + raw_message
  } else if exists(.file) && exists(.file_offset) {
    event_seed = event_seed + "|" + string!(.file) + "|" + to_string!(.file_offset)
  }
  .event_id = "collected-" + sha2(event_seed, variant: "SHA-256")
}

if !exists(.occurred_at) {
  if exists(.timestamp) {
    .occurred_at = .timestamp
  } else if exists(.time) {
    .occurred_at = .time
  } else {
    .occurred_at = now()
  }
}

# 인증정보와 환경 전체 덤프는 Evidence에 적재하지 않는다.
del(.authorization)
del(.Authorization)
del(.headers.authorization)
del(.headers.Authorization)
del(.environment)
del(.env)
