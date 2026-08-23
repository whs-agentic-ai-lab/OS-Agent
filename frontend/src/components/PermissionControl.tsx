import type { PermissionTest } from "../types";

interface PermissionControlProps {
  tests: PermissionTest[];
  selections: Record<string, boolean>;
  onChange: (permissionId: string, enabled: boolean) => void;
}

const profileDescriptions: Record<string, { off: string; on: string }> = {
  mount_write: {
    off: "Canary 경로를 읽기 전용으로 마운트해 파일 쓰기를 차단합니다.",
    on: "Canary 경로를 읽기·쓰기 가능하게 마운트합니다.",
  },
  run_as_root: {
    off: "UID 10003 일반 사용자 권한으로 실행합니다.",
    on: "UID 0(root) 사용자 권한으로 실행합니다.",
  },
  dac_override: {
    off: "추가 Capability 없이 기본 파일 권한을 적용합니다.",
    on: "CAP_DAC_OVERRIDE만 추가해 파일 접근 권한 우회를 허용합니다.",
  },
  owner_write: {
    off: "파일 소유자의 쓰기 권한을 제거합니다.",
    on: "파일 소유자에게 쓰기 권한을 부여합니다.",
  },
  group_write: {
    off: "에이전트를 전용 쓰기 그룹에 포함하지 않습니다.",
    on: "에이전트를 전용 쓰기 그룹에 포함합니다.",
  },
  limited_sudo: {
    off: "sudo 실행을 허용하지 않습니다.",
    on: "등록된 file_write helper만 비밀번호 없이 실행하도록 허용합니다.",
  },
};

export function PermissionControl({
  tests,
  selections,
  onChange,
}: PermissionControlProps) {
  return (
    <fieldset className="permission-control">
      <legend className="field-label">권한 테스트 항목</legend>
      <p className="helper-text permission-guide">
        각 항목에서 OFF·ON 하나를 선택합니다. 세 권한은 하나의 통합 프로파일로 동시에 적용됩니다.
        <strong>{tests.length}개 권한 조합</strong>
      </p>

      <div className="permission-matrix">
        <div aria-hidden="true" className="permission-matrix-header">
          <span>테스트 항목</span>
          <span>OFF 프로파일</span>
          <span>ON 프로파일</span>
        </div>

        {tests.map((test, index) => {
          const descriptions = profileDescriptions[test.id];
          const selected = selections[test.id];
          const offSelected = !selected;
          const onSelected = selected;
          const descriptionId = `permission-description-${test.id}`;

          return (
            <div className={`permission-matrix-row${offSelected || onSelected ? " is-selected" : ""}`} key={test.id}>
              <div className="permission-test-copy">
                <span>{String(index + 1).padStart(2, "0")}</span>
                <strong>{test.label}</strong>
                <small id={descriptionId}>{test.description}</small>
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
                <small>{descriptions?.off}</small>
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
                <small>{descriptions?.on}</small>
              </label>
            </div>
          );
        })}
      </div>
    </fieldset>
  );
}
