# Tool 후속작업

검증된 OS Tool과 PM 공통·OS 하네스를 `main`에 병합한 뒤 실제 실험환경을 사용하기 전에 수행할 검증을 정리한다.

## 현재 Agent 연결 상태 (canonical provenance migration)

- 정적 Attack Inventory: **129 Tool family / 383 Action**
- 기존 라이브 PASS 재사용: **378 Action**
- Agent Attack 노출: **378 Action / 129 Tool family**
- Agent Recon 노출: **113 Tool**
- Non-PASS 제외: **5 Action**
- PM Common OS Harness allowlist: 동일 validated Registry 사용, 비어 있지 않음
- Source/manifest 불일치: Attack 노출 **0** (fail-closed)

기존 라이브 run `tool-validation-3bc32759b2a2`와 image digest
`sha256:de40c307b18defb084caa7baee3f34ca6c327adbcc8df7f229bab9369162d0c6`를
그대로 재사용한다. legacy source hash는 보존하고, CRLF/LF를 정규화한
canonical source hash
`sha256:70b4e9e62ce442f539e04675c02fc2c6bf5c9401eab478b4e510fa7ffd8f170f`를
Agent 연결 기준으로 추가했다. `origin/not-verified-tool`과 migration 기준
`origin/main`의 Tool 소스 diff가 없었고, `origin/recon-tools`
(`9a00cfc10b4faf0c637c54b8f9ac36d18fcae0b9`)와 main의 Recon 소스 diff도
없었다. 이 변경에서는 383 Action 라이브
검증, AWS/Terraform/ECR/Docker build, 전체 테스트 스위트를 실행하지 않았다.
관련 경로의 WSL targeted test 8개 파일은 **90 passed**였다.

Attack은 하나의 generic schema에서 자동 Registry가 최종 조합과 인수를
검증한 뒤 기존 `ToolDefinition` handler/verifier로 dispatch한다. Recon은 별도
generic schema에서 기존 `validate_recon_call` → `execute_recon` 경로를 사용한다.
Tool handler 파일은 변경하지 않았다.

## 1. Linux 전용 전체 테스트 실행

### 목적

Windows에서 수집할 수 없었던 Linux 전용 Runtime·Supervisor·Recon·Tool 테스트를 실제 Linux 환경에서 확인한다.

### 대상

- `backend/tests/test_attack_tools.py`
- `backend/tests/test_host_supervisor.py`
- `backend/tests/test_permission_controls.py`
- `backend/tests/test_recon_tools.py`
- `backend/tests/test_runtime_tool_definition_adapter_linux.py`
- 위 파일을 포함한 `backend/tests/` 전체

### 실행 조건

- Python 3.11 이상
- `backend/requirements.txt` 의존성 설치
- `libc.so.6`, `fcntl`, Unix Domain Socket 등 Linux 기능을 사용할 수 있는 환경
- 실제 외부 공격이나 Terraform 실행 없이 단위 테스트만 수행

### 권장 명령

```bash
cd backend
python -m pytest -q
```

### 완료 조건

- 전체 테스트 수집 성공
- Linux 전용 테스트 포함 전체 통과
- 실패가 있으면 플랫폼 차이가 아니라 실제 계약 또는 구현 문제인지 분류

## 2. Provisioning Baseline 통합 검증

### 목적

실제 Control/Provisioning Backend의 환경 초기화 응답이 `os-experiment-baseline-v1` 계약과 일치하는지 확인한다.

### 확인할 Baseline 항목

- `trial_group_member == false`
- `limited_sudo_rule == false`
- `docker_group_member == false`
- `container_run_root_empty == true`
- `target_canary_sha256`가 모든 고정 Target을 포함
- `running_containers`와 `healthy_containers`가 일치
- Action/Verifier Evidence가 초기화 후에도 보존
- OS Tool별 Resetter 호출 0회
- Scenario 종료 후 환경 전체 초기화 정확히 1회
- 실패 시 `CAMPAIGN_STOPPED_RESET_FAILED`로 종료되고 다음 Scenario가 실행되지 않음

### 검증 시나리오

1. 승인된 `source_id`와 Trust Boundary로 변경 가능한 OS Scenario를 시작한다.
2. Action Receipt와 독립 Verifier Evidence가 먼저 저장됐는지 확인한다.
3. 승인된 전체 환경 초기화 경로를 한 번 실행한다.
4. 초기화 응답과 독립 Baseline 관측 결과를 비교한다.
5. Evidence Bundle Hash와 Baseline Score를 검증한다.
6. 초기화 또는 Baseline 검증 실패 시 다음 Scenario가 실행되지 않는지 확인한다.

### 완료 조건

- 실제 Backend 응답이 `os-experiment-baseline-v1` 필수 필드를 모두 제공
- 모든 Baseline 독립 검사가 통과
- 환경 초기화가 정확히 한 번 실행
- Tool Resetter 호출이 0회
- 초기화 실패 시 fail-closed 및 다음 Scenario 중단 확인

## 안전 제한

- 별도 승인 없이 실제 공격, 권한 변경, `terraform apply/destroy`, 외부 배포를 실행하지 않는다.
- 검증 전 실험환경 식별자와 복구 책임자를 확정한다.
- 초기화 실패 시 Evidence를 보존하고 추가 Scenario를 실행하지 않는다.
