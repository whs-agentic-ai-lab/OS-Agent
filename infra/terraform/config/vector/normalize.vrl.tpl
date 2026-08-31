channel = string(.collector_channel) ?? "unknown"
original = .
collector_received_at = now()

raw_message = string(original.message) ?? ""

# Vector가 붙인 수집 메타데이터는 JSON payload를 파싱하기 전에 보존한다.
collector = {
  "channel": channel,
  "vector_source_type": original.source_type,
  "host": original.host,
  "file": original.file,
  "file_offset": original.file_offset,
  "journal_cursor": original.__CURSOR,
  "vector_timestamp": original.timestamp,
}

source_type = if channel == "journald" {
  "journald"
} else if channel == "auditd" {
  "auditd"
} else if channel == "docker_event" {
  "docker_event"
} else if channel == "docker_json" {
  "docker_log"
} else if channel == "executor" {
  "executor"
} else if channel == "state" {
  "snapshot"
} else {
  "unknown"
}

# file source의 NDJSON만 파싱한다. journald/auditd의 원문은 그대로 payload에 둔다.
payload = original
structured_file_event = channel == "docker_event" ||
  channel == "docker_json" ||
  channel == "executor" ||
  channel == "state"

if structured_file_event {
  parsed, parse_err = parse_json(raw_message)
  if parse_err == null && is_object(parsed) {
    payload = object!(parsed)
  } else if parse_err == null {
    payload = {"raw_value": parsed, "parse_error": true, "parse_error_code": "expected_object"}
  } else {
    payload = {
      "raw_message": raw_message,
      "parse_error": true,
    }
  }
}

# EXECVE aN/indexed aN[index]는 문자열/hex argv다. SYSCALL의 숫자 aN,
# argc 및 aN_len은 검증에 필요한 메타데이터이므로 그대로 남긴다.
if channel == "auditd" {
  audit_message = raw_message
  if match(raw_message, r'\btype=EXECVE\b') {
    audit_message = replace(audit_message, r'\ba[0-9]+(?:\[[0-9]+\])?=(?:"(?:\\[\s\S]|[^"\\])*(?:"|\\?\z)|\x27(?:\\[\s\S]|[^\x27\\])*(?:\x27|\\?\z)|[^\s"\x27]+)', "[REDACTED_AUDIT_ARGUMENT]")
  }
  audit_message = replace(audit_message, r'\bproctitle=(?:"(?:\\[\s\S]|[^"\\])*(?:"|\\?\z)|\x27(?:\\[\s\S]|[^\x27\\])*(?:\x27|\\?\z)|[^\s"\x27]+)', "[REDACTED_AUDIT_ARGUMENT]")
  if audit_message != raw_message {
    payload.message = audit_message
    payload.audit_arguments_omitted = true
  }
}

# 실제 backend의 구조화 stdout만 executor 증거로 승격한다.
# 일반 container 메시지/OS 로그에 들어 있는 run_id는 실행 컨텍스트로 추측하지 않는다.
if channel == "docker_json" && payload.container_name == "os-agent-runtime" && is_string(payload.message) {
  inner, inner_err = parse_json(string!(payload.message))
  if inner_err == null && is_object(inner) && inner.evidence_kind == "executor" {
    relay = payload
    payload = object!(inner)
    payload.docker = {
      "event_id": relay.event_id,
      "container_id": relay.container_id,
      "container_name": relay.container_name,
      "stream": relay.stream,
    }
    source_type = "executor"
  }
}

# 기존 최소 마스킹 계약을 payload에도 동일하게 유지한다.
del(payload.authorization)
del(payload.Authorization)
del(payload.headers.authorization)
del(payload.headers.Authorization)
del(payload.environment)
del(payload.env)
del(payload.collector_channel)

context = {"run_id": null, "action_id": null, "step_id": null, "tool_call_id": null}
if source_type == "executor" || source_type == "snapshot" {
  if is_string(payload.run_id) && !is_empty(string!(payload.run_id)) {
    context.run_id = payload.run_id
  }
  if is_string(payload.action_id) && !is_empty(string!(payload.action_id)) {
    context.action_id = payload.action_id
  }
  if is_string(payload.step_id) && !is_empty(string!(payload.step_id)) {
    context.step_id = payload.step_id
  }
  if is_string(payload.tool_call_id) && !is_empty(string!(payload.tool_call_id)) {
    context.tool_call_id = payload.tool_call_id
  }
}

status = "ok"
if payload.parse_error == true {
  status = "parse_error"
} else if payload.collection_error == true || is_object(payload.collection_error) ||
  payload.payload.collection_error == true || is_object(payload.payload.collection_error) {
  status = "collection_error"
}

source = string(payload.source) ?? ""
if is_empty(source) {
  source = if source_type == "journald" {
    string(payload._SYSTEMD_UNIT) ?? string(payload.SYSLOG_IDENTIFIER) ?? source_type
  } else {
    source_type
  }
}

message = ""
if exists(payload.message) && is_string(payload.message) {
  message = string!(payload.message)
} else if source_type == "docker_event" {
  docker_type = "container"
  docker_action = "event"
  if exists(payload.Type) && is_string(payload.Type) {
    docker_type = string!(payload.Type)
  }
  if exists(payload.Action) && is_string(payload.Action) {
    docker_action = string!(payload.Action)
  }
  message = docker_type + "." + docker_action
} else if source_type == "snapshot" {
  message = "state capture completed"
} else if !structured_file_event {
  message = raw_message
}

event_type = string(payload.event_type) ?? ""
if is_empty(event_type) {
  event_type = if source_type == "journald" { "journal_entry" } else if source_type == "auditd" { "audit_record" } else if source_type == "executor" { "executor_event" } else { source_type }
}

if source_type == "auditd" {
  audit_fields, audit_err = parse_regex(raw_message, r'^type=(?P<audit_type>[A-Z0-9_]+)')
  if audit_err == null && exists(audit_fields.audit_type) {
    event_type = "audit." + downcase(string!(audit_fields.audit_type))
  }
} else if source_type == "docker_event" && exists(payload.Action) && is_string(payload.Action) {
  # exec_create/exec_start Action에는 ': <command args>'가 붙는다. 분류에는 kind만 쓴다.
  action_parts = split(string!(payload.Action), ":", limit: 2)
  event_type = "docker_event." + downcase(string!(action_parts[0]))
}
if status == "parse_error" {
  event_type = "evidence.parse_error"
  message = "structured log parsing failed"
}

# 발생 시각 우선순위는 유지한다. 잘못 제시된 시각은 정상으로 숨기지 않는다.
occurred_at = collector_received_at
occurred_at_set = false
native_times = []
if source_type == "auditd" {
  audit_time, audit_err = parse_regex(raw_message, r'msg=audit\((?P<epoch>[0-9]+(?:\.[0-9]+)?):')
  if audit_err == null {
    parsed_time, time_err = parse_timestamp(string!(audit_time.epoch), format: "%s%.f")
    if time_err == null { native_times = push(native_times, parsed_time) } else { payload.timestamp_parse_error = true }
  } else {
    payload.timestamp_parse_error = true
  }
}
if source_type == "docker_event" {
  if is_integer(payload.timeNano) {
    parsed_time, time_err = from_unix_timestamp(int!(payload.timeNano), unit: "nanoseconds")
    if time_err == null { native_times = push(native_times, parsed_time) } else { payload.timestamp_parse_error = true }
  }
  if is_integer(payload.time) {
    parsed_time, time_err = from_unix_timestamp(int!(payload.time))
    if time_err == null { native_times = push(native_times, parsed_time) } else { payload.timestamp_parse_error = true }
  }
}
time_candidates = append([payload.occurred_at, payload.created_at], native_times)
time_candidates = append(time_candidates, [payload.timestamp, original.timestamp])
for_each(time_candidates) -> |_index, candidate| {
  if !occurred_at_set && candidate != null {
    if is_timestamp(candidate) {
      occurred_at = candidate
      occurred_at_set = true
    } else if is_string(candidate) {
      parsed_time, time_err = parse_timestamp(candidate, format: "%+")
      if time_err == null {
        occurred_at = parsed_time
        occurred_at_set = true
      } else {
        payload.timestamp_parse_error = true
      }
    } else {
      payload.timestamp_parse_error = true
    }
  }
}
if payload.timestamp_parse_error == true {
  status = "parse_error"
  event_type = "evidence.parse_error"
  message = "log timestamp parsing failed; fallback time used"
}

event_id = string(payload.event_id) ?? ""

if is_empty(event_id) {
  event_seed = channel + "|" + raw_message
  if is_empty(raw_message) {
    event_seed = channel + "|" + encode_json(payload)
  }
  if channel == "journald" && exists(original.__CURSOR) && is_string(original.__CURSOR) {
    event_seed = channel + "|" + string!(original.__CURSOR)
  } else if exists(original.file) || exists(original.file_offset) {
    event_seed = event_seed + "|" + encode_json(original.file) + "|" + encode_json(original.file_offset)
  }
  event_seed = "${environment_id}|" + encode_json(collector.host) + "|" + event_seed
  event_id = "collected-" + sha2(event_seed, variant: "SHA-256")
}

. = {
  "schema_version": "os-agent-evidence-v1",
  "event_id": event_id,
  "source_type": source_type,
  "source": source,
  "event_type": event_type,
  "occurred_at": occurred_at,
  "collector_received_at": collector_received_at,
  "environment_id": "${environment_id}",
  "topology_revision": "${topology_revision}",
  "message": message,
  "context": context,
  "status": status,
  "collector": collector,
  "payload": payload,
}

# 정규화 필드와 보존 원문을 함께 마스킹한다. 중첩 object/array도 같은 규칙이다.
# 원문 JSON 문자열은 재파싱하지 않아도 문자열 규칙으로 비밀값을 제거한다.
nul_escaped = false
safe_events = map_values([.], recursive: true) -> |value| {
  if is_object(value) {
    execve_object = value.type == "EXECVE" || value.record_type == "EXECVE" || value.audit_type == "EXECVE"
    has_nul_key = false
    for_each(object(value)) -> |key, _item| {
      # 이름을 복구하기 전에 검사한다. 실제 NUL/여러 번 escape된 NUL 모두
      # pa<NUL>ssword 같은 민감 키를 숨기는 수단으로 사용할 수 없다.
      checked_key = replace(key, r'(?i)\x00|\\+(?:u0000|x00)', "")
      if match(checked_key, r'(?i)^(?:[a-z0-9_-]*(?:api[_-]?key|password|passwd|token|secret(?:[_-]?key)?)|authorization|proxy[_-]?authorization|cookie|set-cookie|pwd|aws_access_key_id|aws_secret_access_key|env|environment)$') ||
        checked_key == "proctitle" ||
        (execve_object && match(checked_key, r'^a[0-9]+(?:\[[0-9]+\])?$')) {
        value = set!(value, [key], "[REDACTED]")
      }
      if match(key, r'\x00') {
        has_nul_key = true
        nul_escaped = true
      }
    }
    if has_nul_key {
      # 먼저 기존 backslash를 escape해야 bad<NUL>key와 bad\u0000key가
      # 같은 JSONB 키로 덮어써지지 않는다. 일반 키의 이름/값은 보존한다.
      repaired_object = {}
      for_each(object(value)) -> |key, item| {
        escaped_key = replace(key, "\\", "\\\\")
        repaired_key = replace(escaped_key, r'\x00', "\\u0000")
        repaired_object = set!(repaired_object, [repaired_key], item)
      }
      value = repaired_object
    }
  } else if is_array(value) {
    redact_next = false
    for_each(array!(value)) -> |index, item| {
      if redact_next {
        value = set!(value, [index], "[REDACTED]")
      }
      redact_next = false
      if is_string(item) {
        redact_next = match(string!(item), r'(?i)^--[a-z0-9_-]*(?:api[_-]?key|password|passwd|token|secret)$')
      }
    }
  } else if is_string(value) {
    text = string!(value)
    if match(text, r'\x00') {
      text = replace(text, r'\x00', "\\u0000")
      nul_escaped = true
    }
    text = replace(text, r'(?i)\b(?:Bearer|Basic)\s+[^\s"\x27<>;,]+', "[REDACTED]")
    text = replace(text, r'(?i)https?://[^\s/@:]+:[^\s/@]+@', "https://[REDACTED]@")
    text = replace(text, r'(?im)\b(?:set-cookie|cookie)\s*:\s*[^\r\n]+', "[REDACTED_COOKIE]")
    text = replace(text, r'(?i)--[a-z0-9_-]*(?:api[_-]?key|password|passwd|token|secret)(?:=|\s+)(?:"(?:\\.|[^"\\])*(?:"|$)|\x27[^\x27]*(?:\x27|$)|[^\s]+)', "[REDACTED]")
    text = replace(text, r'(?i)"--[a-z0-9_-]*(?:api[_-]?key|password|passwd|token|secret)"\s*,\s*"(?:\\.|[^"\\])*(?:"|$)', "[REDACTED]")
    text = replace(text, r'(?i)[a-z0-9_-]*(?:api[_-]?key|password|passwd|token|secret(?:[_-]?key)?|authorization|cookie)["\x27]?\s*(?:=|:)\s*(?:"(?:\\.|[^"\\])*(?:"|$)|\x27[^\x27]*(?:\x27|$)|[^\s,;&"\x27]+)', "[REDACTED]")
    text = replace(text, r'\b(?:sk-(?:proj-|or-v1-)?[A-Za-z0-9_-]{12,}|sb_secret_[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9_]{12,}|github_pat_[A-Za-z0-9_]{12,}|AKIA[A-Z0-9]{16}|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b', "[REDACTED]")
    value = text
  }
  value
}
. = safe_events[0]
if nul_escaped {
  .payload.nul_byte_escaped = true
  if .status == "ok" {
    .status = "collection_error"
  }
}
