# PM 공통·OS 하네스 요구사항 커버리지

기준 브랜치: `feat/pm-common-os-harness`

이 표는 `PM_COMMON_OS_IMPLEMENTATION_PROMPT.md`의 공통 13개 영역과 OS 전용 4개 영역을 기준으로 한다. AWS 전용 Account/Region/Role/IAM/ECR/ECS/S3 계약은 구현 범위에서 제외했다.

| 요구사항 | 변경 전 | 변경 후 | 근거 |
|---|---|---|---|
| 공통 1. 실행 수명주기·Run 상태 | 부분 구현 — Run/Event는 있으나 현재 단계·구조화 오류·최종 결과 없음 | 구현됨 — stable `run_id`, 단계, 상태, 오류 코드, 최종 결과와 원자적 Evidence 파일 저장 | `backend/app/harness/models.py`, `coordinator.py`, `evidence.py`, `test_harness.py` |
| 공통 2. 입력 계약·실행 범위 | 부분 구현 — 상한은 있으나 Harness 추가 필드 허용, OS 신규 입력과 Provider 사전 오류 없음 | 구현됨 — extra-forbid, StrictBool, 상한, 승인 Source/TB/Provider 입구 검사 | `models.py`, `main.py`, 입력 계약 테스트 |
| 공통 3. 자격 증명·컨텍스트 분리 | 부분 구현 — ModelGateway가 Key를 소유하나 Harness 결과 Redaction과 다음 단계 컨텍스트 계약 부족 | 구현됨 — 자격 증명은 Gateway/환경에만 유지, 다음 단계에는 구조화 결과만 전달, 저장 전 Redaction | `coordinator.py`, `evidence.py`, Redaction 테스트 |
| 공통 4. Adapter·Tool 계약 | 부분 구현 — 포트는 있으나 메타데이터·엄격 스키마·OS 복구 구분 부족 | 구현됨 — domain/kind/risk/schema/target/condition/verifier/recovery/impact 계약과 fail-closed validator | `models.py`, `ports.py`, `os_adapters.py`, 계약 거부 테스트 |
| 공통 5. 정찰·Agent State·Asset Graph | 부분 구현 — 113개 OS Recon과 Agent Orchestrator가 있으나 Harness Snapshot 정규화 부족 | 구현됨 — 기존 Recon 보존, permission 상태·asset·subject·relationship·evidence 기반 Agent State 연결 | `runtime_agent/recon_tools.py`, `agent_orchestrator.py`, `os_adapters.py` |
| 공통 6. Capability·Action Frontier | 부분 구현 — Candidate는 있으나 상태·결정적 ID·별칭 제거 없음 | 구현됨 — capability 상태, ready/conditional/blocked, 결정적 ID, semantic 중복 제거 | `models.py`, `coordinator.py`, 결정성 테스트 |
| 공통 7. LLM·Scenario·Planner Grounding | 부분 구현 — Frontier 존재 검사만 구현 | 구현됨 — 공개 후보 제한, 재-Grounding, 인자 스키마, 대상 연결, Frozen Tool/Target 고정 | `coordinator.py`, `os_adapters.py`, Frontier/Frozen 테스트 |
| 공통 8. 실행 직전 Guardrail | 부분 구현 — 후보 존재만 검사 | 구현됨 — domain/risk/source/TB/asset/verifier/recovery/baseline/frontier 상태 검사, 불확실 시 차단 | `coordinator.py`, `models.py` |
| 공통 9. Action·Verifier·Reset·Receipt | 부분 구현 — Verifier는 있으나 Receipt와 Evidence 독립성 없음, OS가 Tool Reset 사용 | 구현됨 — Action Receipt, 독립 Evidence ID 검사, verified Impact Fact, 일반 Tool Reset/OS 환경 초기화 분리 | `models.py`, `coordinator.py`, `os_adapters.py`, 독립성·복구 테스트 |
| 공통 10. Idempotency·재시도·오류 | 미구현/부분 구현 — Budget만 존재 | 구현됨 — 결정적 Key, 중복 차단, TIMEOUT/THROTTLED 제한 재시도, 구조화 오류와 Harness 오류 분리 | `models.py`, `coordinator.py`, 결정성 테스트 |
| 공통 11. 다단계 Scenario·Reset | 부분 구현 — Action 직후 Reset | 구현됨 — 이전 Receipt 연결 검사, Frozen 순서 검사, 일반 역순 Reset, OS 종료 후 초기화 1회, 상태 유지 종료 | `coordinator.py`, Fixture/OS 복구 테스트 |
| 공통 12. 결과·Evidence Bundle·회귀 평가 | 미구현 | 구현됨 — manifest/events/evidence/scores, SHA-256, Redaction 수, 오프라인 scorer, 변조 검출 | `evidence.py`, Bundle 테스트 |
| 공통 13. 최소 권한 실험 | 구현됨 — 기존 Frozen Attack Contract와 OS Permission Atom/1-minimal 경로 존재 | 유지·회귀 확인 — AWS IAM Atom을 추가하지 않고 기존 OS Atom minimizer 보존 | `permission_minimizer.py`, `permission_controls.py`, `test_permission_minimizer.py` |
| OS 1. OS 실행 입력 | 부분 구현 — legacy 필드와 부분 profile만 지원 | 구현됨 — `environment/source_id/os_*` 엄격 계약과 legacy 매핑, 정확한 현재 Profile 키 검사 | `models.py`, `config.py`, `main.py`, strict input 테스트 |
| OS 2. Entrypoint·정찰 | 구현됨/부분 구현 — Host/Container Runtime 및 113 Recon Tool 존재 | 구현됨 — 기존 경로 보존, Harness Agent State/Asset Graph/TB Grounding 연결 | `runtime_agent/`, `host_runtime/`, `os_adapters.py` |
| OS 3. 검증·환경 전체 복구 | 미충족 — `OsRuntimeResetter`가 `/v2/harness/reset` Tool 단위 복구 호출 | 구현됨 — Tool Resetter 제거, Control Backend 전체 환경 초기화 1회, 버전 Baseline 독립 검사, 실패 시 Campaign 중단 | `ports.py`, `coordinator.py`, `os_adapters.py`, OS reset 테스트 |
| OS 4. OS 권한 최소화 | 구현됨 — Host/Container 통제와 Frozen Contract 기반 minimizer 존재 | 유지·회귀 확인 — 자격 증명/제어 채널은 Runtime·Gateway 밖 LLM Context에 노출하지 않음 | `permission_controls.py`, `permission_minimizer.py`, 관련 테스트 |

## 안전 범위

- 실제 Host/Container 공격, 실제 권한 변경, Terraform apply/destroy, 외부 배포는 실행하지 않았다.
- 기존 Vector 로그 수집 및 Terraform/AWS 구성은 수정하지 않았다.
- OS Action에는 Tool별 Resetter를 등록하거나 호출하지 않는다.
