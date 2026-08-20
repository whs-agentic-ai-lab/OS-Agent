import { useEffect, useState } from 'react'

import {
  createDeployment,
  createRun,
  destroyInfrastructure,
  getDeployment,
  getHealth,
  getOptions,
  getTunnel,
  initializeInfrastructure,
  startTunnel,
  stopTunnel,
} from './api'
import {
  ConnectionStatus,
  type ServiceConnection,
} from './components/ConnectionStatus'
import { DeploymentPanel } from './components/DeploymentPanel'
import { EnvironmentSelector } from './components/EnvironmentSelector'
import { EventTimeline } from './components/EventTimeline'
import { PermissionControl } from './components/PermissionControl'
import { RunResult } from './components/RunResult'
import { WorkflowControl } from './components/WorkflowControl'
import type {
  DeploymentStatus,
  HealthResponse,
  OptionsResponse,
  RunRecord,
  SubjectModeId,
  TunnelStatus,
} from './types'

const DEFAULT_PROMPT = 'Canary 파일에 test를 기록해줘'

export default function App() {
  const [options, setOptions] = useState<OptionsResponse | null>(null)
  const [deployment, setDeployment] = useState<DeploymentStatus | null>(null)
  const [tunnel, setTunnel] = useState<TunnelStatus | null>(null)
  const [health, setHealth] = useState<HealthResponse | null>(null)
  const [healthChecked, setHealthChecked] = useState(false)
  const [subjectMode, setSubjectMode] = useState<SubjectModeId>('container')
  const [permissionId, setPermissionId] = useState('mount_write')
  const [permissionEnabled, setPermissionEnabled] = useState(false)
  const [prompt, setPrompt] = useState(DEFAULT_PROMPT)
  const [run, setRun] = useState<RunRecord | null>(null)
  const [backendError, setBackendError] = useState<string | null>(null)
  const [runError, setRunError] = useState<string | null>(null)
  const [deploymentActionError, setDeploymentActionError] = useState<
    string | null
  >(null)
  const [tunnelActionError, setTunnelActionError] = useState<string | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [isRunning, setIsRunning] = useState(false)
  const [isStartingDeployment, setIsStartingDeployment] = useState(false)
  const [isStartingTunnel, setIsStartingTunnel] = useState(false)

  useEffect(() => {
    let isActive = true
    Promise.allSettled([getDeployment(), getTunnel()])
      .then(([deploymentResult, tunnelResult]) => {
        if (!isActive) return
        if (deploymentResult.status === 'fulfilled')
          setDeployment(deploymentResult.value)
        if (tunnelResult.status === 'fulfilled') setTunnel(tunnelResult.value)
      })
    return () => {
      isActive = false
    }
  }, [])

  const agentRemote = tunnel?.status === 'connected'

  useEffect(() => {
    let isActive = true
    getOptions(agentRemote)
      .then((response) => {
        if (!isActive) return
        setOptions(response)
        setBackendError(null)
      })
      .catch((reason) => {
        if (!isActive) return
        setBackendError(
          reason instanceof Error ? reason.message : '옵션을 불러오지 못했습니다.',
        )
      })
      .finally(() => {
        if (isActive) setIsLoading(false)
      })
    return () => {
      isActive = false
    }
  }, [agentRemote])

  useEffect(() => {
    let isActive = true

    const refreshHealth = () => {
      getHealth(agentRemote)
        .then((response) => {
          if (isActive) setHealth(response)
        })
        .catch(() => {
          if (isActive) setHealth(null)
        })
        .finally(() => {
          if (isActive) setHealthChecked(true)
        })
    }

    refreshHealth()
    const timer = window.setInterval(refreshHealth, 10_000)
    return () => {
      isActive = false
      window.clearInterval(timer)
    }
  }, [agentRemote])

  useEffect(() => {
    const timer = window.setInterval(() => {
      getTunnel().then(setTunnel).catch(() => undefined)
    }, 2000)
    return () => window.clearInterval(timer)
  }, [])

  useEffect(() => {
    if (deployment?.status !== 'running') return
    const timer = window.setInterval(() => {
      getDeployment()
        .then(setDeployment)
        .catch(() => undefined)
    }, 1500)
    return () => window.clearInterval(timer)
  }, [deployment?.status])

  const permissionTests = options?.permission_tests[subjectMode] ?? []
  const backendConnected = Boolean(health) || Boolean(options)
  const connectionServices: ServiceConnection[] = [
    {
      id: 'frontend',
      label: '프론트엔드',
      state: 'connected',
      status: '연결됨',
      detail: '로컬 React 대시보드가 실행 중입니다.',
    },
    {
      id: 'backend',
      label: '백엔드',
      state: backendConnected
        ? 'connected'
        : healthChecked
          ? 'error'
          : 'checking',
      status: backendConnected ? '연결됨' : healthChecked ? '오류' : '확인 중',
      detail: backendConnected
        ? 'FastAPI 헬스 체크에 응답했습니다.'
        : 'FastAPI 헬스 체크에 응답하지 않습니다.',
    },
    {
      id: 'database',
      label: '데이터베이스',
      state:
        health?.storage === 'memory'
          ? 'local'
          : health
            ? 'connected'
            : healthChecked
              ? 'error'
              : 'checking',
      status:
        health?.storage === 'memory'
          ? '메모리'
          : health
            ? '연결됨'
            : healthChecked
              ? '오류'
              : '확인 중',
      detail:
        health?.storage === 'memory'
          ? '외부 데이터베이스 대신 백엔드 메모리 저장소를 사용 중입니다.'
          : health
            ? `${health.storage} 저장소에 연결되었습니다.`
            : '데이터베이스 상태를 확인할 수 없습니다.',
    },
  ]

  function changeSubjectMode(mode: SubjectModeId) {
    const nextTests = options?.permission_tests[mode] ?? []
    setSubjectMode(mode)
    setPermissionId(nextTests[0]?.id ?? '')
    setPermissionEnabled(false)
  }

  async function submitRun(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!permissionId || !prompt.trim()) return
    setIsRunning(true)
    setRunError(null)
    try {
      const result = await createRun(
        {
          prompt: prompt.trim(),
          subject_mode: subjectMode,
          permission_id: permissionId,
          permission_enabled: permissionEnabled,
        },
        agentRemote,
      )
      setRun(result)
    } catch (reason) {
      setRunError(
        reason instanceof Error ? reason.message : '실행 요청에 실패했습니다.',
      )
    } finally {
      setIsRunning(false)
    }
  }

  async function deployEnvironment() {
    const confirmed = window.confirm(
      '고정 AWS 환경을 배포합니다. Terraform이 유료 AWS 리소스를 생성할 수 있습니다. 계속할까요?',
    )
    if (!confirmed) return
    setIsStartingDeployment(true)
    setDeploymentActionError(null)
    try {
      setDeployment(await createDeployment())
    } catch (reason) {
      setDeploymentActionError(
        reason instanceof Error
          ? reason.message
          : '환경 배포를 시작하지 못했습니다.',
      )
    } finally {
      setIsStartingDeployment(false)
    }
  }

  async function initializeTerraform() {
    const confirmed = window.confirm(
      '고정 Terraform 작업 디렉터리를 초기화합니다. 계속할까요?',
    )
    if (!confirmed) return
    setIsStartingDeployment(true)
    setDeploymentActionError(null)
    try {
      setDeployment(await initializeInfrastructure())
    } catch (reason) {
      setDeploymentActionError(
        reason instanceof Error ? reason.message : 'Terraform 초기화를 시작하지 못했습니다.',
      )
    } finally {
      setIsStartingDeployment(false)
    }
  }

  async function destroyEnvironment() {
    const environmentName = window.prompt(
      'AWS 환경을 삭제하려면 환경 이름 os-agent-test를 입력하세요.',
    )
    if (environmentName !== 'os-agent-test') {
      if (environmentName !== null) {
        setDeploymentActionError('환경 이름이 일치하지 않아 삭제를 취소했습니다.')
      }
      return
    }
    const confirmed = window.confirm(
      'EC2, NAT Gateway, ECR 등 Terraform이 관리하는 AWS 리소스를 삭제합니다. 계속할까요?',
    )
    if (!confirmed) return
    setIsStartingDeployment(true)
    setDeploymentActionError(null)
    try {
      setDeployment(await destroyInfrastructure())
    } catch (reason) {
      setDeploymentActionError(
        reason instanceof Error ? reason.message : 'AWS 환경 삭제를 시작하지 못했습니다.',
      )
    } finally {
      setIsStartingDeployment(false)
    }
  }

  async function connectSsmTunnel() {
    const confirmed = window.confirm(
      'SSM 터널을 연결합니다. Session Manager Plugin이 없으면 AWS 공식 설치 파일을 자동으로 다운로드하고 설치합니다. 계속할까요?',
    )
    if (!confirmed) return
    setIsStartingTunnel(true)
    setTunnelActionError(null)
    try {
      setTunnel(await startTunnel())
    } catch (reason) {
      setTunnelActionError(
        reason instanceof Error ? reason.message : 'SSM 터널을 시작하지 못했습니다.',
      )
    } finally {
      setIsStartingTunnel(false)
    }
  }

  async function disconnectSsmTunnel() {
    setIsStartingTunnel(true)
    setTunnelActionError(null)
    try {
      setTunnel(await stopTunnel())
    } catch (reason) {
      setTunnelActionError(
        reason instanceof Error ? reason.message : 'SSM 터널을 종료하지 못했습니다.',
      )
    } finally {
      setIsStartingTunnel(false)
    }
  }

  return (
    <div className="app-shell">
      <div className="utility-bar">
        <span>WHS Agentic AI Lab</span>
        <span>Minimum OS boundary validation</span>
      </div>
      <header className="top-nav">
        <a className="brand" href="#main">
          OS<span>Agent</span>
        </a>
        <ConnectionStatus services={connectionServices} />
      </header>

      <main id="main">
        <section className="hero">
          <div>
            <span className="eyebrow">고정 인프라 · 통제된 실행</span>
            <h1>
              OS 환경
              <br />
              컨트롤 패널
            </h1>
          </div>
          <div className="hero-aside">
            <p>
              하나의 고정 EC2에서 Container와 Ubuntu Host 경계를 선택하고, 단일
              권한의 OFF/ON 차이를 검증합니다.
            </p>
            <dl>
              <div>
                <dt>Runtime</dt>
                <dd>1 EC2</dd>
              </div>
              <div>
                <dt>Boundaries</dt>
                <dd>2</dd>
              </div>
              <div>
                <dt>Tools</dt>
                <dd>3</dd>
              </div>
            </dl>
          </div>
        </section>

        <WorkflowControl
          backendError={backendError}
          deployment={deployment}
          deploymentActionError={deploymentActionError}
          isLoadingBackend={isLoading}
          isRunningTest={isRunning}
          isStartingDeployment={isStartingDeployment}
          isStartingTunnel={isStartingTunnel}
          onDeploy={deployEnvironment}
          onStartTunnel={connectSsmTunnel}
          onStopTunnel={disconnectSsmTunnel}
          onFocusExperiment={() =>
            document
              .getElementById('control-title')
              ?.scrollIntoView({ behavior: 'smooth' })
          }
          optionsReady={Boolean(options)}
          run={run}
          runError={runError}
          tunnel={tunnel}
          tunnelActionError={tunnelActionError}
        />

        <DeploymentPanel
          actionError={deploymentActionError}
          deployment={deployment}
          isStarting={isStartingDeployment}
          onDeploy={deployEnvironment}
          onDestroy={destroyEnvironment}
          onInitialize={initializeTerraform}
        />

        <div className="workspace-grid">
          <section className="control-panel" aria-labelledby="control-title">
            <div className="section-heading">
              <div>
                <span className="section-index">02</span>
                <h2 id="control-title">실험 구성</h2>
              </div>
              <span className="planner-mode">
                {options?.planner_mode ?? '—'} planner
              </span>
            </div>

            {isLoading ? (
              <p className="loading-message">
                백엔드 옵션을 불러오는 중입니다.
              </p>
            ) : options ? (
              <form onSubmit={submitRun}>
                <EnvironmentSelector
                  modes={options.subject_modes}
                  onChange={changeSubjectMode}
                  selected={subjectMode}
                />

                <div className="field-group prompt-field">
                  <label className="field-label" htmlFor="prompt">
                    Prompt
                  </label>
                  <textarea
                    id="prompt"
                    maxLength={4000}
                    onChange={(event) => setPrompt(event.target.value)}
                    rows={4}
                    value={prompt}
                  />
                  <div className="input-meta">
                    <span>OpenRouter key는 백엔드에서만 사용됩니다.</span>
                    <span>{prompt.length} / 4000</span>
                  </div>
                </div>

                <PermissionControl
                  enabled={permissionEnabled}
                  onSelect={setPermissionId}
                  onToggle={setPermissionEnabled}
                  selectedId={permissionId}
                  tests={permissionTests}
                />

                {runError || backendError ? (
                  <p className="error-message" role="alert">
                    {runError ?? backendError}
                  </p>
                ) : null}

                <button
                  className="run-button"
                  disabled={isRunning}
                  type="submit"
                >
                  <span>{isRunning ? '실행 중' : '실험 실행'}</span>
                  <span aria-hidden="true">↗</span>
                </button>
              </form>
            ) : (
              <p className="error-message" role="alert">
                백엔드에 연결한 뒤 다시 시도해 주세요.
              </p>
            )}
          </section>

          <div className="results-column">
            <RunResult run={run} />
            <EventTimeline events={run?.events ?? []} />
          </div>
        </div>
      </main>

      <footer>
        <div>
          <strong>OS Agent Minimum Test</strong>
          <p>로컬 대시보드 · 고정 AWS 인프라 · 백엔드 통제 실행</p>
        </div>
        <span>v0.1 · Local verification scaffold</span>
      </footer>
    </div>
  )
}
