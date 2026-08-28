import type { PermissionCatalogSummary, PermissionTest } from "../types";

interface PermissionControlProps {
  tests: PermissionTest[];
  selections: Record<string, boolean>;
  onChange: (permissionId: string, enabled: boolean) => void;
  catalogSummary?: PermissionCatalogSummary;
}

export function PermissionControl({
  tests,
  selections,
  onChange,
  catalogSummary,
}: PermissionControlProps) {
  const privilegedConfounded = selections.privileged === true && [
    "dac_override", "setuid_capability", "setgid_capability", "sys_ptrace_capability",
    "apparmor_unconfined", "seccomp_unconfined", "systempaths_unconfined",
  ].some((id) => selections[id] === true);
  const privilegedNeedsRoot = selections.privileged === true && selections.run_as_root !== true;
  const sudoBlockedByNnp = selections.limited_sudo === true && selections.no_new_privileges === true;

  return (
    <fieldset className="permission-control">
      <legend className="field-label">권한 테스트 항목</legend>
      <p className="helper-text permission-guide">
        각 항목은 권한 카탈로그의 핵심 축을 실제 Runtime 설정으로 적용합니다.
        <strong>{tests.length}개 제어 권한</strong>
      </p>
      {catalogSummary ? (
        <p className="helper-text">
          {catalogSummary.source_version} 원천 {catalogSummary.total_entries}개 · {catalogSummary.policy}
        </p>
      ) : null}
      {privilegedConfounded ? (
        <p className="error-message" role="alert">
          privileged와 개별 capability·격리 해제를 함께 선택하면 어느 권한이 결과를 만든 것인지 분리할 수 없습니다.
        </p>
      ) : null}
      {privilegedNeedsRoot ? (
        <p className="error-message" role="alert">
          privileged 축은 UID 변수를 고정해야 하므로 Container UID 0도 ON으로 선택해야 합니다.
        </p>
      ) : null}
      {sudoBlockedByNnp ? (
        <p className="error-message" role="alert">
          limited_sudo는 허용됐지만 no_new_privs가 ON이면 sudo의 setuid root 전환은 OS에서 차단됩니다.
        </p>
      ) : null}

      <div className="permission-matrix">
        <div aria-hidden="true" className="permission-matrix-header">
          <span>테스트 항목</span>
          <span>OFF 프로파일</span>
          <span>ON 프로파일</span>
        </div>

        {tests.map((test, index) => {
          const selected = selections[test.id] ?? test.default_enabled;
          const offSelected = !selected;
          const onSelected = selected;
          const descriptionId = `permission-description-${test.id}`;

          return (
            <div className={`permission-matrix-row${offSelected || onSelected ? " is-selected" : ""}`} key={test.id}>
              <div className="permission-test-copy">
                <span>{String(index + 1).padStart(2, "0")}</span>
                <strong>{test.label}</strong>
                <small id={descriptionId}>{test.description}</small>
                <small>{test.axis} · {test.catalog_ids.join(", ")}</small>
              </div>

              <label className={`permission-profile-choice${offSelected ? " is-active" : ""}`}>
                <input
                  aria-describedby={descriptionId}
                  checked={offSelected}
                  name={`${test.id}-profile`}
                  onChange={() => onChange(test.id, false)}
                  type="radio"
                  value={`${test.id}:OFF`}
                />
                <span className="permission-profile-state">OFF</span>
                <strong>{test.off_profile}</strong>
                <small>{test.off_description}</small>
              </label>

              <label className={`permission-profile-choice${onSelected ? " is-active" : ""}`}>
                <input
                  aria-describedby={descriptionId}
                  checked={onSelected}
                  name={`${test.id}-profile`}
                  onChange={() => onChange(test.id, true)}
                  type="radio"
                  value={`${test.id}:ON`}
                />
                <span className="permission-profile-state">ON</span>
                <strong>{test.on_profile}</strong>
                <small>{test.on_description}</small>
              </label>
            </div>
          );
        })}
      </div>
    </fieldset>
  );
}
