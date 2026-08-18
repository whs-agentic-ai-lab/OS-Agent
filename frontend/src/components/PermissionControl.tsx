import type { PermissionTest } from "../types";

interface PermissionControlProps {
  tests: PermissionTest[];
  selectedId: string;
  enabled: boolean;
  onSelect: (permissionId: string) => void;
  onToggle: (enabled: boolean) => void;
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
  selectedId,
  enabled,
  onSelect,
  onToggle,
}: PermissionControlProps) {
  const selected = tests.find((test) => test.id === selectedId) ?? tests[0];
  const descriptions = selected ? profileDescriptions[selected.id] : null;

  return (
    <div className="permission-control">
      <div className="field-group">
        <label className="field-label" htmlFor="permission-test">
          권한 테스트 항목
        </label>
        <select
          id="permission-test"
          onChange={(event) => onSelect(event.target.value)}
          value={selectedId}
        >
          {tests.map((test) => (
            <option key={test.id} value={test.id}>
              {test.label}
            </option>
          ))}
        </select>
        <p className="helper-text">{selected?.description}</p>
      </div>

      <div className="permission-state">
        <div>
          <span className="field-label">권한 상태</span>
          <p className="helper-text">한 번에 선택한 권한 하나만 변경합니다.</p>
        </div>
        <button
          aria-checked={enabled}
          className={`toggle${enabled ? " is-on" : ""}`}
          onClick={() => onToggle(!enabled)}
          role="switch"
          type="button"
        >
          <span aria-hidden="true" className="toggle-track">
            <span className="toggle-thumb" />
          </span>
          <span>{enabled ? "ON" : "OFF"}</span>
        </button>
      </div>

      {selected ? (
        <dl className="profile-pair">
          <div className={enabled ? "" : "is-active"}>
            <dt>비활성 권한 (OFF)</dt>
            <dd>
              <strong>{selected.off_profile}</strong>
              <span>{descriptions?.off}</span>
            </dd>
          </div>
          <div className={enabled ? "is-active" : ""}>
            <dt>활성 권한 (ON)</dt>
            <dd>
              <strong>{selected.on_profile}</strong>
              <span>{descriptions?.on}</span>
            </dd>
          </div>
        </dl>
      ) : null}
    </div>
  );
}
