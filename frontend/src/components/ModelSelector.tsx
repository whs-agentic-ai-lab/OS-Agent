import type { PlannerModelId, PlannerModelOption } from '../types'

interface ModelSelectorProps {
  active: boolean
  models: PlannerModelOption[]
  onChange: (model: PlannerModelId) => void
  selected: PlannerModelId
}

export function ModelSelector({
  active,
  models,
  onChange,
  selected,
}: ModelSelectorProps) {
  return (
    <fieldset className={`field-group model-selector${active ? ' is-active' : ' is-fallback'}`}>
      <legend className="field-label">OpenRouter Planner 모델</legend>
      <div className="environment-grid">
        {models.map((model) => (
          <label
            className={`environment-option${selected === model.id ? ' is-selected' : ''}`}
            key={model.id}
          >
            <input
              checked={selected === model.id}
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
          {active
            ? '선택 모델은 이 Run의 TB별 구조화 Tool Call 생성에 사용됩니다.'
            : '모델 선택은 저장됩니다. 현재 연결된 Runtime은 OPENROUTER_API_KEY가 없어 실행 시 로컬 규칙 Planner를 사용합니다.'}
        </span>
      </div>
    </fieldset>
  )
}
