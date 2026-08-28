data_dir: /var/lib/vector
timezone: UTC

%{ if remote_sink_enabled ~}
secret:
  collector:
    type: directory
    path: /etc/vector/secrets
    remove_trailing_whitespace: true
%{ endif ~}

sources:
  host_journal:
    type: journald
    since_now: false
    emit_cursor: true
    journalctl_path: /usr/bin/journalctl
    journal_directory: /var/log/journal
    include_units:
      - auditd.service
      - docker.service
      - os-agent-host-supervisor.service
      - os-agent-experiment.service
      - os-agent-docker-events.service
      - os-agent-docker-logs.service
      - init.scope

  auditd:
    type: file
    include:
      - /var/log/audit/audit.log
      - /var/log/audit/audit.log.*
    exclude:
      - /var/log/audit/*.gz
    read_from: beginning
    max_line_bytes: 262144
    offset_key: file_offset
    rotate_wait_secs: 30

  docker_events:
    type: file
    include:
      - /var/log/os-agent/docker-events.ndjson
    read_from: beginning
    max_line_bytes: 262144
    offset_key: file_offset
    rotate_wait_secs: 30

  docker_logs:
    type: file
    include:
      - /var/log/os-agent/docker-logs.ndjson
    read_from: beginning
    max_line_bytes: 262144
    offset_key: file_offset
    rotate_wait_secs: 30

  executor_events:
    type: file
    include:
      - /var/log/os-agent/executor/*.ndjson
    read_from: beginning
    max_line_bytes: 262144
    offset_key: file_offset
    rotate_wait_secs: 30

  state_events:
    type: file
    include:
      - /var/log/os-agent/state-captures.ndjson
    read_from: beginning
    max_line_bytes: 262144
    offset_key: file_offset
    rotate_wait_secs: 30

transforms:
  tag_journal:
    type: remap
    inputs: [host_journal]
    source: |
      .collector_channel = "journald"

  tag_audit:
    type: remap
    inputs: [auditd]
    source: |
      .collector_channel = "auditd"

  tag_docker_events:
    type: remap
    inputs: [docker_events]
    source: |
      .collector_channel = "docker_event"

  tag_docker_logs:
    type: remap
    inputs: [docker_logs]
    source: |
      .collector_channel = "docker_json"

  tag_executor:
    type: remap
    inputs: [executor_events]
    source: |
      .collector_channel = "executor"

  tag_state:
    type: remap
    inputs: [state_events]
    source: |
      .collector_channel = "state"

  normalize:
    type: remap
    inputs:
      - tag_journal
      - tag_audit
      - tag_docker_events
      - tag_docker_logs
      - tag_executor
      - tag_state
    file: /etc/vector/normalize.vrl
    drop_on_error: false

sinks:
  local_evidence:
    type: file
    inputs: [normalize]
    path: /var/lib/os-agent/evidence/collected/events.ndjson
    encoding:
      codec: json
    framing:
      method: newline_delimited
    healthcheck:
      enabled: true
    buffer:
      type: disk
      max_size: 268435488
      when_full: block

%{ if remote_sink_enabled ~}
  evidence_api:
    type: http
    inputs: [normalize]
    uri: ${evidence_api_uri}
    method: post
    compression: gzip
    encoding:
      codec: json
    framing:
      method: newline_delimited
    batch:
      max_events: 250
      timeout_secs: 2
    request:
      headers:
        Authorization: "Bearer SECRET[collector.collector_token]"
      timeout_secs: 30
      retry_initial_backoff_secs: 1
      retry_max_duration_secs: 300
      concurrency: 1
    buffer:
      type: disk
      max_size: 536870912
      when_full: block
    acknowledgements:
      enabled: true
    healthcheck:
      enabled: true
%{ endif ~}
