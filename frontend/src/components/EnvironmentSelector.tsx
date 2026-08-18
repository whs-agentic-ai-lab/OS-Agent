import type { SubjectMode, SubjectModeId } from "../types";

interface EnvironmentSelectorProps {
  modes: SubjectMode[];
  selected: SubjectModeId;
  onChange: (mode: SubjectModeId) => void;
}

export function EnvironmentSelector({ modes, selected, onChange }: EnvironmentSelectorProps) {
  return (
    <fieldset className="field-group">
      <legend className="field-label">실행 환경</legend>
      <div className="environment-grid">
        {modes.map((mode) => (
          <label
            className={`environment-option${selected === mode.id ? " is-selected" : ""}`}
            key={mode.id}
          >
            <input
              checked={selected === mode.id}
              disabled={!mode.enabled}
              name="subject-mode"
              onChange={() => onChange(mode.id)}
              type="radio"
              value={mode.id}
            />
            <span className="radio-mark" aria-hidden="true" />
            <span>
              <strong>{mode.label}</strong>
              <small>{mode.description}</small>
            </span>
          </label>
        ))}
      </div>
    </fieldset>
  );
}

