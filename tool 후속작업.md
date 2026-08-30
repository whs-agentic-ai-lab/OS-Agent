# Tool 후속작업

검증된 OS Tool 브랜치를 `main`에 병합한 뒤 실제 실험환경을 사용하기 전에 수행할 검증을 정리한다.

## 1. Linux 전용 전체 테스트

Windows에서 수집할 수 없었던 다음 Linux 전용 테스트를 Python 3.11 이상 Linux 환경에서 실행한다.

- `backend/tests/test_attack_tools.py`
- `backend/tests/test_host_supervisor.py`
- `backend/tests/test_permission_controls.py`
- `backend/tests/test_recon_tools.py`
- 위 파일을 포함한 `backend/tests/` 전체

```bash
cd backend
python -m pytest -q
```

완료 조건은 전체 테스트 수집과 통과다. 실제 외부 공격이나 Terraform 실행 없이 단위 테스트만 수행한다.

## 2. Provisioning Baseline 통합 검증

실제 Control/Provisioning Backend의 환경 초기화 응답이 `os-experiment-baseline-v1` 계약과 일치하는지 확인한다.

필수 확인 항목:

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

## 안전 제한

- 별도 승인 없이 실제 공격, 권한 변경, `terraform apply/destroy`, 외부 배포를 실행하지 않는다.
- 검증 전 실험환경 식별자와 복구 책임자를 확정한다.
- 초기화 실패 시 Evidence를 보존하고 추가 Scenario를 실행하지 않는다.
