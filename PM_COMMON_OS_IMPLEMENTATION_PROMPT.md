# PM 공통·OS 하네스 요구사항 적용 프롬프트

아래 프롬프트를 OS-Agent 저장소의 구현 작업에 그대로 사용한다.

---

당신은 `OS-Agent` 저장소의 공통 에이전트 하네스와 OS 실행 경로를 정비하는 구현 담당자다.

## 작업 기준

- 기준 브랜치: `feat/pm-common-os-harness`
- 기준 문서: PM이 전달한 「에이전트 작동 순서 및 하네스 설명」
- 원문 링크: https://app.notion.com/p/3cbb3271e3d2808c9f61cc81dafc9a95
- 구현 범위: 아래의 **공통 요구사항**과 **OS 전용 요구사항**만 적용한다.
- 제외 범위: AWS/ECS/EKS 전용 구현, AWS Account/Region/Role ARN 검사, IAM 정책 및 `iam:PassRole`, ECR/ECS/S3 전용 Tool·Verifier·Reset, AWS 전용 Permission Atom은 구현하지 않는다.
- 원문에 등장하는 AWS 사례는 공통 계약을 설명하는 예시일 뿐이다. 이를 OS 코드에 그대로 복제하지 않는다.

## 최우선 작업 방식

1. 코드를 수정하기 전에 현재 저장소 구조와 기존 구현을 조사한다.
2. 아래 요구사항별로 `구현됨 / 부분 구현 / 미구현 / OS에 부적합` 상태와 근거 파일·심볼을 정리한 커버리지 표를 만든다.
3. 이미 구현된 기능은 중복 작성하거나 새 프레임워크로 교체하지 않는다.
4. 부분 구현과 미구현 항목만 현재 아키텍처에 맞춰 최소 변경으로 완성한다.
5. 요구사항과 현 코드가 충돌하면 안전한 fail-closed 동작과 기존 API 호환성을 우선하고, 충돌 내용을 결과에 명시한다.
6. 실제 EC2/호스트/컨테이너 공격 실행, 실제 권한 변경, `terraform apply/destroy`, 외부 배포는 하지 않는다. 단위 테스트와 정적 검증까지만 수행한다.

## 공통 요구사항

### 1. 실행 수명주기

다음 흐름이 코드와 실행 이벤트에서 추적 가능해야 한다.

```text
사용자 입력
→ 실행 범위와 역할 검사
→ 자격 증명을 LLM과 분리
→ 자산과 권한 정찰
→ 실행 가능한 Action 후보 생성
→ LLM/Planner가 등록된 후보 중 경로와 목표 선택
→ 하네스가 선택 결과를 다시 Grounding
→ 실행 직전 Guardrail 검사
→ Action 실행
→ 독립 Verifier 검증
→ Reset 또는 OS 인프라 복구
→ 결과와 증거 저장
→ 회귀 평가
→ 선택적 최소 권한 조합 실험
```

각 실행에는 안정적인 `run_id`가 있어야 하며 `queued`, `running`, `completed`, `failed`와 현재 단계, 오류 코드, 최종 결과를 조회할 수 있어야 한다. 상태 파일을 사용하는 경우 임시 파일 작성 후 원자적으로 교체한다.

### 2. 입력 계약과 실행 범위

- 정의되지 않은 필드와 잘못된 타입은 실행 시작 전에 거부한다.
- 모델, 반복 횟수, 결과 수 제한, Reset 여부 등 실행 조건에 명시적인 상한과 검증이 있어야 한다.
- 입구 검사는 Action 직전 Guardrail과 분리한다.
- 입구 검사 실패는 실행을 시작하지 않고 구조화된 HTTP/도메인 오류로 반환한다.
- LLM Provider 자격 증명이 없으면 명확한 서비스 설정 오류로 종료한다.

### 3. 자격 증명 및 컨텍스트 분리

- API Key, 실행 자격 증명, Verifier/Reset 또는 Permission Controller의 민감 정보는 프론트엔드 입력과 LLM 컨텍스트에 포함하지 않는다.
- 민감 정보는 백엔드 환경변수나 제한된 런타임 세션에서만 사용한다.
- 다음 Scenario에는 이전 Action/Verifier/Reset의 구조화된 결과와 남은 후보만 전달한다.
- 이전 LLM 원문 추론, 원시 시스템 응답 전체, 자격 증명, 비밀값, 예상 정답 경로는 다음 LLM 세션에 전달하지 않는다.

### 4. Adapter와 Tool 계약

Recon과 Action을 구분하고, 각 Tool은 가능한 범위에서 다음 메타데이터를 가져야 한다.

- 이름과 설명
- 엄격한 입력 스키마(`additionalProperties: false`에 준하는 동작)
- 도메인과 Tool 종류
- 위험 등급
- 실행 함수
- 대상 자원을 식별하는 필드
- 필요한 권한 또는 OS 조건
- 독립 Verifier
- Resetter 또는 명시적인 OS 복구 전략
- 검증 가능한 예상 Impact Fact

다음 Action은 자동 실행하지 않고 fail-closed 처리한다.

- 독립 Verifier가 없음
- 가역 변경인데 Resetter와 OS 복구 전략이 모두 없음
- 입력 스키마가 추가 필드를 허용함
- 등록 이름, 실행 명세, Adapter 도메인이 불일치함
- Verifier나 복구에 필요한 조건이 계약에 누락됨

분석 전용 Tool과 자율 실행 가능한 Tool을 명시적으로 구분한다.

### 5. 정찰, Agent State, Asset Graph

- 정찰은 고정 순서가 아니라 현재 권한/조건과 이미 발견한 대상에 따라 실행 가능한 Recon 후보를 스케줄링한다.
- 선언상 허용과 실제 실행 확인을 구분한다.
- 최소 상태는 `declared`, `confirmed`, `denied`, `conditional_or_unknown`, `skipped_not_declared` 또는 이에 대응하는 기존 상태 모델을 표현해야 한다.
- 실행하지 않은 Probe를 `denied`로 기록하지 않는다.
- 원시 명령 출력을 그대로 LLM에 전달하지 말고 자산, Identity/Subject, 권한, 관계, Evidence Reference를 구조화한 Agent State로 정규화한다.
- 자산 간 관계를 그래프로 표현할 수 있어야 하며, 관계가 없는 독립 자산을 하나의 공격 체인으로 간주하지 않는다.

### 6. Capability와 Action Frontier

- Capability는 단일 권한이 아니라 권한, 대상 자산, Trust Boundary, 런타임 조건을 함께 평가한 효과 단위다.
- Capability 상태는 `inferred`, `confirmed`, `denied`, `conditional_or_unknown`, `unavailable` 또는 기존 모델의 동등 상태로 관리한다.
- LLM의 주장만으로 `confirmed`가 되면 안 된다. Action과 독립 검증 성공이 필요하다.
- Action Frontier 후보는 안정적인 `candidate_id`, 등록 Tool, 구체적인 대상과 인자, 예상 상태 변화, 필요한 Evidence, 상태(`ready`, `conditional`, `blocked`)를 포함한다.
- 같은 효과·대상·인자를 가진 별칭 후보는 중복 제거한다.
- 후보 ID는 정책/권한 상태, 도메인, Tool, 인자, 대상 등 재현 가능한 입력에서 결정적으로 생성한다.

### 7. LLM, Scenario, Planner Grounding

- LLM은 등록되지 않은 Tool, 임의 명령, 임의 대상, 임의 Verifier/Reset, 허용 범위 밖 인자를 만들 수 없다.
- LLM에는 페이지 가능한 Tool Discovery Catalog와 하네스가 만든 Candidate만 제공한다.
- 선택한 Candidate가 실제 Frontier에 존재하고 LLM에 공개되었으며 현재 자산·권한 상태와 연결되는지 다시 검증한다.
- Scenario의 목표, 성공 기준, 대상, Verifier, 복구 전략은 하네스가 고정한다. LLM은 허용된 목표나 Candidate를 선택하고 이유만 제시한다.
- Planner의 인자 변경은 하네스가 사전에 허용한 값 안에서만 가능하다.
- 다중 Agent 경로가 이미 있다면 Explorer/Critic/Supervisor 역할도 동일한 Frontier 계약을 따르고 Critic이 대상이나 인자를 새로 만들지 못하게 한다.
- JSON 스키마 위반 응답은 제한된 교정만 허용하고, Provider Timeout에 무제한 재시도하지 않는다.

### 8. 실행 직전 Guardrail

최소한 다음을 검사한다.

- Tool의 도메인과 현재 실행 환경 일치
- 위험 등급이 실행 범위 상한 이하
- 대상이 승인된 OS 환경과 Trust Boundary 안에 있음
- Candidate와 대상이 Agent State에 Grounding됨
- 독립 Verifier 존재
- 가역 변경에 Resetter 또는 OS 복구 전략 존재
- Verifier와 복구 경로가 필요한 권한/조건을 충족
- 변경 전 Baseline이 유효함
- Frozen Scenario라면 허용 Tool과 대상 목록 및 실행 순서가 정확히 일치함

안전 여부를 확정할 수 없으면 실행하지 않는다.

### 9. Action, Verifier, Reset 및 영수증

- Action은 구조화된 Receipt를 남긴다. Receipt에는 실행 대상, 실제 변경, 생성된 식별자, Evidence Reference가 포함되어야 한다.
- Verifier는 Action 실행 주체 및 Action Evidence와 독립된 관측으로 판정한다.
- 검증 상태는 `VERIFIED`, `REJECTED`, `INCONCLUSIVE` 또는 기존 모델의 명확한 동등 상태를 사용한다.
- Action API/명령의 성공만으로 Scenario 성공을 선언하지 않는다.
- 최종 영향은 독립 Evidence로 확인된 Impact Fact를 통해서만 확정한다.
- Reset은 Receipt에 기록된 정확한 변경만 되돌리고, 복구 후 상태를 다시 확인하여 별도 Reset Receipt를 남긴다.
- Action Evidence ID와 Verifier Evidence ID의 재사용을 금지한다.

### 10. Idempotency, 재시도, 오류 분류

- `run_id + candidate_id + tool + arguments`에 준하는 결정적 Idempotency Key를 사용한다.
- 자동 재시도는 `TIMEOUT`, `THROTTLED`처럼 재시도 가능한 오류에만 제한한다.
- 최소 오류 분류는 `ACCESS_DENIED`, `NOT_FOUND`, `INVALID_INPUT`, `TIMEOUT`, `THROTTLED`, `EXECUTION_ERROR` 또는 OS에 맞는 동등 분류를 제공한다.
- 성공 결과에는 오류가 없어야 하고 실패 결과에는 오류 코드와 메시지가 있어야 한다.
- 예상하지 못한 프로그래밍 예외를 권한 거부나 공격 실패로 위장하지 말고 Harness 오류로 처리한다.

### 11. 다단계 Scenario와 Reset 정책

- 다단계 Scenario는 앞 단계의 실제 출력이 다음 단계의 인자로 연결되어야 한다.
- 선언된 Tool 순서와 실제 실행 순서가 정확히 일치해야 한다.
- 연결이 끊기면 `SCENARIO_CHAIN_BLOCKED` 또는 기존 동등 상태로 종료한다.
- Scenario 단위 Reset은 실행 역순으로 수행한다.
- 명백히 변경이 접수되지 않은 `ACCESS_DENIED`, `INVALID_INPUT`, `NOT_FOUND`에는 존재하지 않는 대상의 Reset을 호출하지 않는다.
- 변경 가능성이 남는 `TIMEOUT`, `EXECUTION_ERROR`는 복구 필요 여부를 보수적으로 판단한다.
- Reset 실패 시 Action/Verifier 결과를 보존하고 다음 Scenario를 중단한다.
- `reset_after_run=false`이면 첫 상태 변경 뒤 추가 Scenario를 만들지 않고 상태 유지 종료를 명시한다.

### 12. 결과, Evidence Bundle, 회귀 평가

실행 결과에는 다음 정보가 구조화되어야 한다.

- 실행 범위 및 권한/환경 Snapshot과 Hash
- 정찰 결과와 자산 관계
- Capability, Frontier, Hypothesis, Scenario, Planner 선택
- Action/Verifier/Reset Receipt
- Impact/Attack Graph
- 종료 상태와 오류
- LLM 상호작용 메타데이터(비밀값 및 불필요한 원문 추론 제외)

Evidence Bundle은 최소한 다음 구조 또는 기존 저장소의 동등 구조를 제공한다.

```text
<run-id>.evidence/
  manifest.json
  events.jsonl
  evidence.jsonl
  scores/
    baseline-integrity.json
```

- Manifest에는 Run/Scenario ID, 계약 및 Catalog Hash, 종료 상태, 파일별 SHA-256, Redaction 개수를 기록한다.
- Bundle에서 토큰, 암호, Authorization Header, 일반적인 Access Key 패턴과 프로젝트의 비밀값을 제거한다.
- Bundle을 읽을 때 파일 Hash를 검증한다.
- 회귀 Scorer는 외부 시스템에 접속하지 않고 Bundle만으로 `goal_integrity`, `declared_tool_chain`, `evidence_independence`, `reset_integrity`, 필수/금지 이벤트·문자열, 종료 상태를 평가할 수 있어야 한다.

### 13. 최소 권한 실험

- 독립 검증과 정상 Reset까지 완료된 Frozen Scenario만 최소 권한 실험 대상으로 삼는다.
- Tool 계약에서 OS 권한/조건의 전체 후보 집합을 만들고 와일드카드 최대 권한을 사용하지 않는다.
- 기준 프로필을 반복 실행해 재현 가능성이 확인된 뒤 축소한다.
- LLM은 기존 Atom ID만 선택할 수 있고 새로운 권한 표현을 만들 수 없다.
- 후보가 성공하면 단일 Atom 제거와 복구 검증을 수행한다.
- 안정적인 권한 실패라면 큰 그룹을 먼저 줄이고 `ddmin` 후 단일 Atom 제거로 1-minimal을 검증한다.
- 모든 실험은 동일한 목표, Tool 순서, 대상, 성공 기준을 유지한다.

## OS 전용 요구사항

### 1. OS 실행 입력

다음 의미를 기존 API 모델에 맞춰 제공한다.

```json
{
  "environment": "os",
  "source_id": "approved-host-01",
  "os_subject_mode": "host",
  "os_trust_boundary_id": "TB-HH-U1U2",
  "os_permission_profile": {
    "owner_write": true,
    "group_write": false,
    "limited_sudo": false
  },
  "model": "openai/gpt-...",
  "max_iterations": 10,
  "reset_after_run": true
}
```

- 현재 저장소가 다른 필드명을 사용한다면 무리하게 API를 깨지 말고 호환 계층 또는 명시적 매핑을 둔다.
- `source_id`는 승인된 OS Host ID 목록에 포함되어야 한다.
- `os_subject_mode`는 현재 지원하는 `host`/`container` 등 Subject Mode와 일치해야 한다.
- Trust Boundary의 출발 Subject, 도착 Subject, 실행 환경이 실제 토폴로지와 일치해야 한다.
- OS 권한 프로필은 허용된 키만 받고 각 값은 실제 Boolean이어야 한다. 키 누락, 추가 키, 문자열 `"true"`를 거부한다.

### 2. OS Entrypoint와 정찰

- OS 실행은 `os-host` 또는 현재 코드의 동등 Entrypoint에서 시작한다.
- Host/Container 자산, 사용자·그룹, 파일 권한, sudo/no-new-privileges, 프로세스·서비스, Mount/Namespace 등 현재 지원 범위를 구조화한다.
- 명령 출력 원문을 그대로 Planner에 넘기지 않고 Recon Adapter를 통해 정규화한다.
- Trust Boundary를 넘는 경로가 실제 자산 관계와 권한 조건으로 연결되는지 검증한다.

### 3. OS 검증과 복구 전략

- AWS의 Verifier Role/Reset Role을 OS에 강제로 도입하지 않는다.
- OS에서는 독립된 Control Backend/Verifier 경로 또는 현재 구현된 독립 검증 Adapter를 사용한다.
- OS 변경의 Reset은 Tool별 Resetter 또는 Terraform 기반 환경 재생성/복구 전략 중 하나로 명시한다.
- Terraform 복구를 사용하는 Action은 Tool별 Resetter 부재만으로 거부하지 않되, 등록된 복구 전략, Baseline Snapshot, 복구 확인 방법이 없으면 fail-closed 처리한다.
- 실제 Terraform 실행은 이번 작업에서 하지 않는다. 인터페이스, 상태 전이, 계약, 테스트 더블로만 검증한다.

### 4. OS 권한 최소화

- AWS IAM 권한 대신 현재 저장소의 Host/Container 권한 통제 항목을 Atom으로 사용한다.
- 예: owner/group write, limited sudo, 실행 비트, 경로 접근, capability/no-new-privileges 등 저장소에 실제 등록된 통제만 대상으로 한다.
- 고정된 Trust Boundary와 Frozen Scenario에서만 프로필을 변경한다.
- Permission Controller의 자격 증명과 제어 채널은 LLM 및 공격 Runtime과 분리한다.

## 기존 코드 우선 조사 위치

다음은 탐색 시작점이며, 실제 코드 구조를 확인한 뒤 조정한다.

- API/입력/상태: `backend/app/main.py`, `backend/app/schemas.py`, `backend/app/config.py`
- 실행 제어: `backend/app/agent_orchestrator.py`, `backend/app/executor.py`, `backend/app/execution_gate.py`
- 공통 하네스: `backend/app/harness/`
- OS Tool/Verifier: `backend/app/attack_tools.py`, `backend/app/verifiers.py`, `backend/runtime_agent/`
- Host 제어: `backend/host_runtime/`
- 저장소/이벤트: `backend/app/repository.py`, `backend/app/harness/repository.py`, `data/`
- 인프라 복구: `infra/terraform/`
- 프론트 계약: `frontend/src/types.ts`, `frontend/src/api.ts`, 관련 실행·결과 컴포넌트
- 테스트: `backend/tests/`

## 구현 원칙

- 현재의 OS 모델과 명명 규칙을 우선한다.
- 공개 API나 DB 스키마 변경이 필요하면 하위 호환과 마이그레이션을 제공한다.
- 로그, 이벤트, Evidence, 예외 메시지에 비밀값을 남기지 않는다.
- Fail-open 기본값을 추가하지 않는다.
- 기존 Vector 로그 수집 및 인프라 구성을 훼손하지 않는다.
- 사용자 또는 팀원의 관련 없는 변경을 덮어쓰지 않는다.
- 대규모 재작성보다 작은 단위의 검증 가능한 커밋을 선호한다.

## 필수 테스트

실제 외부 실행 없이 최소한 다음을 자동 테스트한다.

- OS 입력의 누락/추가 키와 잘못된 Boolean 타입 거부
- 승인되지 않은 Host ID와 불일치 Trust Boundary 거부
- Frontier에 없는 Candidate 및 임의 인자 거부
- Verifier/복구 전략이 없는 변경 Action의 fail-closed 처리
- Action/Verifier Evidence 독립성
- Idempotency Key 안정성과 중복 실행 방지
- 오류 분류와 재시도 허용 범위
- 다단계 출력 연결 및 실행 순서 검사
- 역순 Reset과 Reset 실패 시 캠페인 중단
- Context Isolation과 Credential/비밀값 Redaction
- Evidence Bundle Hash 위변조 검출
- Frozen Scenario의 목표·Tool·대상 고정
- OS Permission Atom 축소의 재현성과 1-minimal 판정
- 기존 API, 하네스, Agent chain, Verifier, Permission minimizer 회귀 테스트

## 완료 보고 형식

작업 완료 후 다음 순서로 보고한다.

1. 요구사항 커버리지 표: 요구사항, 변경 전 상태, 변경 후 상태, 근거 파일/테스트
2. 실제 수정한 파일과 핵심 변경 내용
3. 실행한 정적 검사·단위 테스트와 결과
4. 실행하지 않은 실제 환경 검증 목록
5. 남은 불명확점, 위험, 후속 작업

완료 조건은 “코드가 존재함”이 아니라 공통 하네스 계약과 OS 전용 계약이 테스트로 입증되고, AWS 전용 범위가 섞이지 않으며, 실제 인프라 실행 없이 안전하게 검토 가능한 상태가 되는 것이다.
