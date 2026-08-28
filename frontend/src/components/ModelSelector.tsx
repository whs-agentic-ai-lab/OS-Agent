import type { PlannerModelId, PlannerModelOption } from '../types'

interface ModelSelectorProps {
  disabled: boolean
  models: PlannerModelOption[]
  onChange: (model: PlannerModelId) => void
  selected: PlannerModelId
}

export function ModelSelector({
  disabled,
  models,
  onChange,
  selected,
}: ModelSelectorProps) {
  return (
    <fieldset className="field-group">
      <legend className="field-label">OpenRouter Planner 모델</legend>
      <div className="environment-grid">
        {models.map((model) => (
          <label
            className={`environment-option${selected === model.id ? ' is-selected' : ''}`}
            key={model.id}
          >
            <input
              checked={selected === model.id}
              disabled={disabled}
              name="planner-model"
              onChange={() => onChange(model.id)}
              type="radio"
              value={model.id}
            />
            <span className="radio-mark" aria-hidden="true" />
            <span>
              <strong>{model.label}</strong>
              <small>{model.description}</small>
            </span>
          </label>
        ))}
      </div>
      <div className="input-meta">
        <span>
          {disabled
            ? 'OPENROUTER_API_KEY가 없어 로컬 규칙 플래너를 사용합니다.'
            : '선택 모델은 이 Run의 Tool Call 생성에만 사용됩니다.'}
        </span>
      </div>
    </fieldset>
  )
}
