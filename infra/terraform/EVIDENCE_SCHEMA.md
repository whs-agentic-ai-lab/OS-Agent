# OS Agent Evidence JSON v1

이 문서는 현재 로컬 구현의 출력·저장 계약이다. 운영 적용 여부와 실제 원격 검증 결과는
[작업보고서](../../OS_로깅_정규화_1단계_작업보고서.md), 설정·명령은
[README](README.md#evidence-원격-연결)를 참고한다.

원본은 `config/vector/vector.yaml.tpl`, `config/vector/normalize.vrl.tpl`,
`backend/app/evidence.py`다. EC2에서 생성되는 `/etc/vector/*`는 직접 수정하지 않는다.

## 현재 연결 상태

| 종류 | 기존 수집 경로 | 실제 생산·연결 |
|---|---|---|
| auditd | `/var/log/audit/audit.log*` | 기존 auditd record 한 줄 → 한 Evidence. 여러 audit record 합치기는 하지 않는다. |
| journald | 기존 allowlist의 systemd unit | Supervisor 로그도 `os-agent-host-supervisor.service`의 journal로 수집한다. |
| docker_event | `docker-events.ndjson` | 기존 relay가 기록한 Docker Events. |
| docker_log | `docker-logs.ndjson` | 기존 고정 컨테이너 stdout/stderr relay. |
| executor 실행 결과 | `executor/*.ndjson` | 최신 Host Supervisor의 기존 U1/C1 writer가 실행 성공·실패와 실제 run/action ID를 기록한다. 같은 실행의 TOOL_RESULT stdout을 추가하지 않는다. |
| executor 툴별 판정 | 위 Docker relay의 `os-agent-runtime` stdout | 기존 RunCoordinator/Harness의 verify_tool 반환값만 구조화 출력한다. `evidence_kind=executor`인 해당 컨테이너 JSON만 승격한다. |
| snapshot | `state-captures.ndjson` | 최신 Supervisor의 기존 before/after 자동 캡처와 완료/재게시 이벤트를 유지한다. 캡처의 30초 제한 안에 업로드를 추가하지 않았다. |

공통 정상 출력과 안전한 정규화 실패 출력 모두 기존 로컬 sink 및 선택형 HTTP sink로 연결된다.
일반 OS 로그, 다른 컨테이너가 출력한 `run_id` 문자열은 실행 컨텍스트로 추측하지 않는다.

## 공통 envelope

기존 12필드를 유지하고 `context`, `status`만 추가했다. 모든 신규 출력은 아래 14필드다.
API는 이미 버퍼에 있던 v1의 두 필드 누락을 허용하며, 누락 컨텍스트는 null,
명시적 `payload.parse_error`/`collection_error`는 오류 상태로 보존한다.

| 필드 | 타입 | 의미 |
|---|---|---|
| schema_version | string | `os-agent-evidence-v1` |
| event_id | string | 생산자 ID 우선. 없으면 environment/host + journal cursor 또는 원문·file·offset의 SHA-256. |
| source_type | enum | `auditd / journald / docker_log / docker_event / executor / snapshot / unknown` |
| source | string | 생산자명, systemd unit/identifier, 또는 source_type. |
| event_type | string | 생산자 종류, `audit.<type>`, `docker_event.<action-kind>` 등. Docker exec의 command는 분류값이 아니라 payload에 남긴다. |
| occurred_at | RFC3339 | 생산자가 제시한 발생 시각 우선. |
| collector_received_at | RFC3339 | Vector 정규화 수신 시각. DB의 `received_at`과 다르다. |
| environment_id | string | 고정 Terraform 실험 환경 ID. |
| topology_revision | string | 고정 topology revision. |
| message | string | 마스킹된 원문 또는 짧은 요약. |
| collector | object | 아래 수집 메타데이터. 없는 값은 null. |
| payload | object | source별 원본의 마스킹된 복사본. |
| context | object | 실제 제공된 run/action ID. step/tool-call ID는 현재 없으므로 null. |
| status | enum | `ok / parse_error / collection_error`. 툴 성공이나 Verifier PASS를 뜻하지 않는다. |

`collector` 고정 key:

```json
{
  "channel": "docker_json",
  "vector_source_type": "file",
  "host": "host-a",
  "file": "/var/log/os-agent/docker-logs.ndjson",
  "file_offset": 84,
  "journal_cursor": null,
  "vector_timestamp": "2026-08-30T01:00:04Z"
}
```

`context` 고정 key:

```json
{
  "run_id": "os-example",
  "action_id": "action-example",
  "step_id": null,
  "tool_call_id": null
}
```

현재 실제 ID는 `RuntimeDispatchRequest/RuntimeAgentResult.run_id/action_id`다.
Harness의 candidate_id/sequence를 step_id나 tool_call_id로 바꾸지 않는다.
상관관계를 알 수 없는 OS 로그는 context 전체 null이다.
path_id/phase/target_id 등 기존 source-specific 정보는 payload에 유지한다.

## 실행 결과와 Verifier 판정

- `EXECUTOR_ACTION_COMPLETED` / `EXECUTOR_ACTION_FAILED`: 기존 Supervisor 파일 이벤트다.
  `payload.runtime_result/exit_code/stdout/stderr/tool/action` 및 실제 실행 식별자를 유지한다.
  Vector의 공통 status는 수집 상태이며 이 툴 실행 성공·실패와 별개다.
- `VERIFIER_RESULT`: **기존 verify_tool 호출의 반환값**.
  `payload.payload.verifier_result = {verifier, status, checks}`.
  Harness의 후속 VERIFIED/REJECTED 집계 대신 원래 툴별 PASS/FAIL/INCONCLUSIVE를 기록한다.
- `EXECUTOR_ERROR`: 판정 출력 실패 시 emitter가 남기는 민감정보 없는 수집 오류다.
  Supervisor가 처리한 실행 실패를 백엔드 stdout으로 다시 기록하지 않는다.
- 새 AgentOrchestrator의 ToolDefinition Verifier 상세 전달은 기존 두 백엔드 훅을 지나지 않는다.
  원래 이식 목록 밖 Runtime/Supervisor의 추가 연결은 승인 전까지 미반영으로 구분한다.
- normalizer는 생산자 event object를 payload에 보존한다. 따라서 생산자 내부 payload는
  `payload.payload`가 된다. 원래 반환 객체나 기존 DB run 결과를 변경하지 않는다.
- 백엔드 판정 emitter는 64 KiB/행 제한으로 Docker relay JSON escaping 여유를 확보한다.
  초과한 **로깅 복사본**만 줄이고 `payload.payload.collection_error`에
  `event_truncated`, 원래 byte 수, 생략한 필드 목록을 기록한다.
  원래 실행·Verifier 결과, 호출 횟수, 재실행 여부는 변하지 않는다.

## 파싱·시간·마스킹

- file의 구조화 JSON object만 payload로 파싱한다. 잘못된 JSON은 마스킹한
  raw_message, object가 아닌 JSON은 raw_value와 parse_error_code를 남긴다.
  status=parse_error, event_type=evidence.parse_error로 정상 수집과 구분한다.
- 시각 우선순위: occurred_at → created_at → audit epoch(소수초 포함) →
  Docker timeNano/time → payload timestamp → Vector timestamp → 수신 시각.
  명시된 문자열 시각 파싱 실패는 timestamp_parse_error 및 parse_error로 표시한다.
- 예기치 않은 VRL 실패는 `normalize.dropped`에서 고정 오류 envelope로 보낸다.
  원문/오류 본문은 이 경로에서 생략하고 raw_omitted=true를 남겨 비정규화 원문 유출을 막는다.
- 기존 authorization/env 삭제를 유지한다. 추가 최소 규칙은 중첩 object/array의
  API 키·token·secret·password·Authorization·Cookie·env, Bearer/Basic,
  명령행 `--token=value`/`--password value`/분리된 argv,
  URL 사용자정보, 대표 provider token이다. 메시지·보존 원문·오류에도 같은 경계를 적용한다.
- audit EXECVE/PROCTITLE은 인자가 hex 또는 aN으로 분리될 수 있어 해당 인자 본문을
  보수적으로 생략한다. audit 종류·uid·대상·syscall·결과 등 나머지 정보는 유지한다.
- PostgreSQL JSONB에 저장할 수 없는 NUL 문자는 Vector에서 문자 표기 `\\u0000`로
  바꾸고 payload.nul_byte_escaped=true로 알린다. 기존 status가 ok이면
  collection_error로 변경하고, parse_error 등 이미 있는 오류 상태는 유지한다.
  API 직접 입력의 잘못된 Unicode/NUL/비유한 숫자는 저장 전 422로 거부한다.
- 마스킹은 Evidence 출력·전송 사본에만 적용한다. 로컬 원본 캡처와 원래 실행 객체는
  그대로다. 임의의 인코딩/이름 없는 비밀값까지 탐지하는 범용 보안 시스템은 아니다.

## 이벤트 예시

### 기존 Verifier 반환값

```json
{
  "schema_version": "os-agent-evidence-v1",
  "event_id": "executor-example",
  "source_type": "executor",
  "source": "control-backend",
  "event_type": "VERIFIER_RESULT",
  "occurred_at": "2026-08-30T01:00:03Z",
  "collector_received_at": "2026-08-30T01:00:03.050Z",
  "environment_id": "trial-0826",
  "topology_revision": "0826-v1",
  "message": "",
  "collector": {
    "channel": "docker_json",
    "vector_source_type": "file",
    "host": "host-a",
    "file": "/var/log/os-agent/docker-logs.ndjson",
    "file_offset": 84,
    "journal_cursor": null,
    "vector_timestamp": "2026-08-30T01:00:03.040Z"
  },
  "payload": {
    "evidence_kind": "executor",
    "source": "control-backend",
    "event_id": "executor-example",
    "event_type": "VERIFIER_RESULT",
    "occurred_at": "2026-08-30T01:00:03Z",
    "run_id": "os-example",
    "action_id": "action-example",
    "payload": {
      "verifier_result": {
        "verifier": "file_content_verifier",
        "status": "PASS",
        "checks": {"output_present": true}
      }
    },
    "docker": {
      "event_id": "docker-log-example",
      "container_id": "container-example",
      "container_name": "os-agent-runtime",
      "stream": "stdout"
    }
  },
  "context": {
    "run_id": "os-example",
    "action_id": "action-example",
    "step_id": null,
    "tool_call_id": null
  },
  "status": "ok"
}
```

### 파싱 실패가 아닌 업로드 실패 (payload 부분)

```json
{
  "event_type": "ARTIFACT_UPLOAD_FAILED",
  "source": "snapshot-runner",
  "run_id": "os-example",
  "action_id": "action-example",
  "phase": "after",
  "path_id": "U1C1",
  "target_id": "C1",
  "capture_event_id": "state-original-index-sha256",
  "collection_error": true,
  "status": "failed",
  "error_code": "artifact_http_failure",
  "expected_artifact_count": 14,
  "uploaded_artifact_count": 0,
  "artifacts": []
}
```

이 payload는 이식한 기존 업로더를 호출했을 때의 실패 계약이며 공통 status는 collection_error다.
업로더/API 코드는 포함하지만 캡처 완료 후 자동 호출은 30초 제한과 충돌해 이식하지 않았다.
새 실행 종료 훅·작업자·수동 운영 절차도 추가하지 않았다. STATE_CAPTURED는 로컬 캡처 완료이며
원격 업로드 완료가 아니다. 업로드 실패 이벤트는 부분 성공 참조도 보존할 수 있다.

## DB 및 Artifact 참조

- `public.evidence_events`: 공통 envelope + 서버 received_at.
  유일키 `(environment_id,event_id)`, 최초 저장 유지.
- `public.evidence_artifacts`: 기존 캡처 파일 하나당 최소 메타데이터.
  유일키 `(environment_id,event_id,filename)`.
- private Storage bucket `os-agent-evidence`.
  경로: `environment/run/action/phase/capture-event-id/stored-sha256/filename`.
- 관리 키는 FastAPI 수신 서버에만 둔다. Vector/업로더는 collector token만 사용한다.
  공개 URL·다운로드 API는 제공하지 않는다.
- 기존 host/container 실행 테이블, 최신 `agent_runs`, 메모리 Harness가 함께 있으므로
  하나의 run 테이블에 FK를 강제하지 않는다. 실제 context.run_id/action_id로 조회 연결한다.
- 생성된 16개 이름의 allowlist 중 해당 host/container·phase에 맞는 기존 파일만 업로드한다.
  최종 디렉터리·manifest·전체 SHA index를 먼저 검증하며 임의 경로/symlink/hardlink를 거부한다.
- 전송 사본 마스킹 후 SHA 계산, API 재마스킹 후 저장본 SHA/크기 계산.
  original_sha256은 생산자가 검증한 로컬 원본의 해시이며 저장본 무결성 해시가 아니다.
  원본 artifact-sha256.txt도 원본 파일에 대한 인덱스이지 마스킹된 객체 인덱스가 아니다.
- 모든 파일의 API 성공 응답과 hash/size 일치를 확인한 뒤 ARTIFACT_UPLOADED를 기록한다.
  파일 실패는 ARTIFACT_UPLOAD_FAILED. 자동 재시도·재수집은 하지 않는다.
  같은 업로더 인자 재호출은 기존 완성본을 재검증·재전송한다. 캡처 재호출만으로 업로드하지 않는다.
- Storage 성공 후 DB 실패 때 고아 객체가 먼저 남을 수 있다. 결정적 객체 경로로 수동
  재전송하여 복구할 수 있으나 자동 정리 기능은 추가하지 않았다.

메타데이터 예시(해시는 형식 설명용):

```json
{
  "environment_id": "trial-0826",
  "event_id": "state-original-index-sha256",
  "run_id": "os-example",
  "action_id": "action-example",
  "phase": "after",
  "filename": "diff-from-before.txt",
  "bucket": "os-agent-evidence",
  "object_path": "trial-0826/os-example/action-example/after/state-original-index-sha256/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/diff-from-before.txt",
  "size_bytes": 123,
  "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "original_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "status": "uploaded"
}
```

## 검증 경계

Vector 정규화 프로그램을 runtime ECR 이미지의 bootstrap asset으로 옮겨 user-data
용량 상한을 복구했다. NAT data-path readiness 대기를 포함한 `0011` 입력의 remote
OFF/ON `base64gzip` 길이는 각각 18,096자/18,452자로 20,480자 상한 안이며,
EC2에서는 고정 digest 이미지에서 파일을
꺼낸 뒤 환경 ID와 topology revision만 치환한다.

`normalize.tests.yaml`은 6종 source, 실제 컨텍스트 승격/OS null, 오류 분류, 마스킹을 검증한다.
`backend/tests/test_evidence*.py`, `test_execution_evidence.py`는 수신·저장 계약과
기존 실행/Verifier 불변성을 검증한다. 선택형 실제 Vector 로컬 HTTP 테스트도 있다.

로컬 저장소 double·SDK MockTransport 테스트는 실제 Supabase DB/RLS/Storage 검증이 아니다.
Linux journald/auditd/Docker 생산부터 원격 저장까지의 E2E는 지정 실험환경에서 별도 확인해야 한다.
