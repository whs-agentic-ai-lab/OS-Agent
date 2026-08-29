import { useEffect, useState } from 'react'

import {
  createDeployment,
  createAgentRun,
  cancelAgentRun,
  resumeAgentRun,
  destroyInfrastructure,
  getDeployment,
  getAgentRun,
  getHealth,
  getOptions,
  getTunnel,
  resetExperimentEnvironment,
  startTunnel,
  stopTunnel,
  terminateInstance,
} from './api'
import {
  ConnectionStatus,
  type ServiceConnection,
} from './components/ConnectionStatus'
import { DeploymentPanel } from './components/DeploymentPanel'
import { AgentRunLiveCard } from './components/AgentRunLiveCard'
import { AgentRunMonitorPage } from './components/AgentRunMonitorPage'
import { ModelSelector } from './components/ModelSelector'
import { OsResultDetailPage } from './components/OsResultDetailPage'
import { WorkflowControl } from './components/WorkflowControl'
import type {
  AgentRunRecord,
  DeploymentStatus,
  ExperimentEnvironmentResetResult,
  HealthResponse,
  OptionsResponse,
  PlannerModelId,
  TunnelStatus,
} from './types'

const SELECTED_INSTANCE_STORAGE_KEY = 'os-agent-test.selected-instance.v1'
const ACTIVE_AGENT_RUN_STORAGE_KEY = 'os-agent-test.active-agent-run.v1'
const RESULT_DETAIL_HASH_PREFIX = '#/os-results/'
const AGENT_MONITOR_HASH_PREFIX = '#/agent-runs/'
const LOGS_HASH = '#/logs'

interface ActiveAgentRunTarget {
  version: 1
  runId: string
  remote: boolean
}

function getDetailRunId(hash: string): string | null {
  if (!hash.startsWith(RESULT_DETAIL_HASH_PREFIX)) return null
  try {
    return decodeURIComponent(hash.slice(RESULT_DETAIL_HASH_PREFIX.length)) || null
  } catch {
    return null
  }
}

function getAgentMonitorTarget(hash: string): ActiveAgentRunTarget | null {
  if (!hash.startsWith(AGENT_MONITOR_HASH_PREFIX)) return null
  const route = hash.slice(AGENT_MONITOR_HASH_PREFIX.length)
  const [encodedRunId, rawQuery = ''] = route.split('?', 2)
  try {
    const runId = decodeURIComponent(encodedRunId)
    if (!runId) return null
    const query = new URLSearchParams(rawQuery)
    return { version: 1, runId, remote: query.get('source') === 'remote' }
  } catch {
    return null
  }
}

function readActiveAgentRunTarget(): ActiveAgentRunTarget | null {
  try {
    const stored = window.localStorage.getItem(ACTIVE_AGENT_RUN_STORAGE_KEY)
    if (!stored) return null
    const value = JSON.parse(stored) as Partial<ActiveAgentRunTarget>
    if (value.version !== 1 || typeof value.runId !== 'string' || typeof value.remote !== 'boolean') return null
    return { version: 1, runId: value.runId, remote: value.remote }
  } catch {
    return null
  }
}

function agentMonitorHash(target: ActiveAgentRunTarget): string {
  return `${AGENT_MONITOR_HASH_PREFIX}${encodeURIComponent(target.runId)}?source=${target.remote ? 'remote' : 'local'}`
}

export default function App() {
  const [options, setOptions] = useState<OptionsResponse | null>(null)
  const [deployment, setDeployment] = useState<DeploymentStatus | null>(null)
  const [tunnel, setTunnel] = useState<TunnelStatus | null>(null)
  const [health, setHealth] = useState<HealthResponse | null>(null)
  const [storageHealth, setStorageHealth] = useState<HealthResponse | null>(null)
  const [healthChecked, setHealthChecked] = useState(false)
  const [storageHealthChecked, setStorageHealthChecked] = useState(false)
  const [plannerModel, setPlannerModel] = useState<PlannerModelId>(
    'deepseek/deepseek-v4-flash-0731',
  )
  const [environmentName, setEnvironmentName] = useState('')
  const [run, setRun] = useState<AgentRunRecord | null>(null)
  const [activeAgentRunTarget, setActiveAgentRunTarget] = useState<ActiveAgentRunTarget | null>(
    () => getAgentMonitorTarget(window.location.hash) ?? readActiveAgentRunTarget(),
  )
  const [monitorError, setMonitorError] = useState<string | null>(null)
  const [lastRunRefreshAt, setLastRunRefreshAt] = useState<Date | null>(null)
  const [runPollRevision, setRunPollRevision] = useState(0)
  const [isResuming, setIsResuming] = useState(false)
  const [isCancellingRun, setIsCancellingRun] = useState(false)
  const [routeHash, setRouteHash] = useState(() => window.location.hash)
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
  const [isResettingExperiment, setIsResettingExperiment] = useState(false)
  const [experimentResetResult, setExperimentResetResult] = useState<ExperimentEnvironmentResetResult | null>(null)
  const [experimentResetError, setExperimentResetError] = useState<string | null>(null)
  const [selectedInstancePreference, setSelectedInstancePreference] = useState<string | null>(
    () => window.localStorage.getItem(SELECTED_INSTANCE_STORAGE_KEY),
  )

  useEffect(() => {
    const handleHashChange = () => {
      const hash = window.location.hash
      setRouteHash(hash)
      const target = getAgentMonitorTarget(hash)
      if (target) {
        setActiveAgentRunTarget((current) =>
          current?.runId === target.runId && current.remote === target.remote
            ? current
            : target,
        )
      }
    }
    window.addEventListener('hashchange', handleHashChange)
    return () => window.removeEventListener('hashchange', handleHashChange)
  }, [])

  useEffect(() => {
    if (!activeAgentRunTarget) {
      window.localStorage.removeItem(ACTIVE_AGENT_RUN_STORAGE_KEY)
      return
    }
    window.localStorage.setItem(ACTIVE_AGENT_RUN_STORAGE_KEY, JSON.stringify(activeAgentRunTarget))
  }, [activeAgentRunTarget])

  const activeAgentRunId = activeAgentRunTarget?.runId ?? null
  const activeAgentRunRemote = activeAgentRunTarget?.remote ?? false

  useEffect(() => {
    if (!activeAgentRunId) return
    let isActive = true
    let timer: number | undefined
    let controller: AbortController | null = null

    const poll = async () => {
      controller = new AbortController()
      try {
        const snapshot = await getAgentRun(activeAgentRunId, activeAgentRunRemote, controller.signal)
        if (!isActive) return
        setRun(snapshot)
        setMonitorError(null)
        setLastRunRefreshAt(new Date())
        if (
          snapshot.status === 'RECEIVED'
          || snapshot.status === 'RUNNING'
          || (snapshot.status === 'CANCELLED' && snapshot.completed_at === null)
        ) {
          timer = window.setTimeout(poll, 1000)
        }
      } catch (reason) {
        if (!isActive || (reason instanceof DOMException && reason.name === 'AbortError')) return
        setMonitorError(reason instanceof Error ? reason.message : '실험 상태를 갱신하지 못했습니다.')
        timer = window.setTimeout(poll, 2000)
      }
    }

    void poll()
    return () => {
      isActive = false
      controller?.abort()
      if (timer !== undefined) window.clearTimeout(timer)
    }
  }, [activeAgentRunId, activeAgentRunRemote, runPollRevision])

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
      const localHealthRequest = getHealth(false)
      const runtimeHealthRequest = agentRemote
        ? getHealth(true)
        : localHealthRequest

      Promise.allSettled([localHealthRequest, runtimeHealthRequest]).then(
        ([storageResult, runtimeResult]) => {
          if (!isActive) return
          setStorageHealth(
            storageResult.status === 'fulfilled' ? storageResult.value : null,
          )
          setHealth(
            runtimeResult.status === 'fulfilled' ? runtimeResult.value : null,
          )
          setStorageHealthChecked(true)
          setHealthChecked(true)
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

  useEffect(() => {
    if (deployment?.status === 'running') return
    const timer = window.setInterval(() => {
      getDeployment()
        .then(setDeployment)
        .catch(() => undefined)
    }, 10_000)
    return () => window.clearInterval(timer)
  }, [deployment?.status])

  const selectedInstanceId =
    deployment?.instances.find(
      (instance) => instance.instance_id === selectedInstancePreference,
    )?.instance_id ??
    deployment?.instances.find((instance) => instance.state === 'running')
      ?.instance_id ??
    deployment?.instances[0]?.instance_id ??
    null

  const hostPermissionTests = options?.permission_tests.host ?? []
  const containerPermissionTests = options?.permission_tests.container ?? []
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
        storageHealth?.storage === 'memory'
          ? 'local'
          : storageHealth
            ? 'connected'
            : storageHealthChecked
              ? 'error'
              : 'checking',
      status:
        storageHealth?.storage === 'memory'
          ? '메모리'
          : storageHealth?.storage === 'supabase'
            ? 'Supabase'
            : storageHealth
              ? '연결됨'
              : storageHealthChecked
              ? '오류'
              : '확인 중',
      detail:
        storageHealth?.storage === 'memory'
          ? '외부 데이터베이스 대신 백엔드 메모리 저장소를 사용 중입니다.'
          : storageHealth
            ? `${storageHealth.storage} 저장소에 연결되었습니다.`
            : '데이터베이스 상태를 확인할 수 없습니다.',
    },
    ...(agentRemote
      ? [
          {
            id: 'host-supervisor',
            label: '에이전트',
            state:
              health?.host_supervisor === 'connected'
                ? ('connected' as const)
                : ('error' as const),
            status:
              health?.host_supervisor === 'connected' ? '연결됨' : '오류',
            detail:
              health?.host_supervisor === 'connected'
                ? 'AWS 에이전트와 실제 OS 실행기가 준비됐습니다.'
                : 'AWS 에이전트 실행기에 연결할 수 없습니다.',
          },
        ]
      : []),
  ]

  async function submitRun(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setIsRunning(true)
    setRunError(null)
    setRun(null)
    try {
      const result = await createAgentRun(
        {
          scope: 'all_trust_boundaries',
          planner_model: plannerModel,
        },
        agentRemote,
        storageHealth?.agent_run_api_version === 'os-agent-orchestrator-v1',
      )
      setRun(result)
      const target: ActiveAgentRunTarget = { version: 1, runId: result.run_id, remote: agentRemote }
      setActiveAgentRunTarget(target)
      setLastRunRefreshAt(new Date())
      setRunPollRevision((revision) => revision + 1)
      window.location.hash = agentMonitorHash(target)
    } catch (reason) {
      setRunError(reason instanceof Error ? reason.message : '8개 TB 통합 실행 요청에 실패했습니다.')
    } finally {
      setIsRunning(false)
    }
  }

  async function resumeRun() {
    if (!run) return
    setIsResuming(true)
    setRunError(null)
    try {
      const remote = activeAgentRunTarget?.runId === run.run_id
        ? activeAgentRunTarget.remote
        : agentRemote
      const resumed = await resumeAgentRun(run.run_id, remote)
      const target: ActiveAgentRunTarget = { version: 1, runId: resumed.run_id, remote }
      setRun(resumed)
      setActiveAgentRunTarget(target)
      setLastRunRefreshAt(new Date())
      setRunPollRevision((revision) => revision + 1)
    } catch (reason) {
      setRunError(reason instanceof Error ? reason.message : '공격 체인 재개에 실패했습니다.')
    } finally {
      setIsResuming(false)
    }
  }

  async function cancelRun() {
    if (!run || !activeAgentRunTarget) return
    const confirmed = window.confirm('현재 Agent 실험을 중단할까요? 마지막 정상 스냅샷과 이벤트는 보존됩니다.')
    if (!confirmed) return
    setIsCancellingRun(true)
    setMonitorError(null)
    try {
      const cancelled = await cancelAgentRun(run.run_id, activeAgentRunTarget.remote)
      setRun(cancelled)
      setLastRunRefreshAt(new Date())
      setRunPollRevision((revision) => revision + 1)
    } catch (reason) {
      setMonitorError(reason instanceof Error ? reason.message : '실험 중단 요청에 실패했습니다.')
    } finally {
      setIsCancellingRun(false)
    }
  }

  function selectInstance(instanceId: string) {
    setSelectedInstancePreference(instanceId)
    setExperimentResetResult(null)
    setExperimentResetError(null)
    window.localStorage.setItem(SELECTED_INSTANCE_STORAGE_KEY, instanceId)
  }

  async function deployEnvironment(requestedName: string) {
    const normalizedName = requestedName.trim().toLowerCase()
    if (!/^[a-z0-9](?:[a-z0-9-]{1,14}[a-z0-9])$/.test(normalizedName)) {
      setDeploymentActionError(
        '환경 이름은 3~16자의 영문 소문자, 숫자, 하이픈만 사용할 수 있습니다.',
      )
      return
    }
    const environmentId = deployment?.caller_identity
      ? `${deployment.caller_identity.environment_prefix}-${normalizedName}`
      : normalizedName
    const confirmed = window.confirm(
      `${environmentId} 환경을 배포합니다. Terraform이 유료 AWS 리소스를 생성할 수 있습니다. 계속할까요?`,
    )
    if (!confirmed) return
    setIsStartingDeployment(true)
    setDeploymentActionError(null)
    try {
      setDeployment(await createDeployment(normalizedName))
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

  async function destroyEnvironment(environmentId: string) {
    const environmentName = window.prompt(
      `AWS 환경 전체를 삭제하려면 ${environmentId}를 입력하세요.`,
    )
    if (environmentName !== environmentId) {
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
      setDeployment(await destroyInfrastructure(environmentId))
    } catch (reason) {
      setDeploymentActionError(
        reason instanceof Error ? reason.message : 'AWS 환경 삭제를 시작하지 못했습니다.',
      )
    } finally {
      setIsStartingDeployment(false)
    }
  }

  async function terminateSelectedInstance(instanceId: string) {
    const confirmedId = window.prompt(
      `EC2만 종료합니다. NAT Gateway, ECR 등 나머지 리소스는 유지됩니다. 계속하려면 ${instanceId}를 입력하세요.`,
    )
    if (confirmedId !== instanceId) return
    setIsStartingDeployment(true)
    setDeploymentActionError(null)
    try {
      setDeployment(await terminateInstance(instanceId))
    } catch (reason) {
      setDeploymentActionError(
        reason instanceof Error ? reason.message : 'EC2 종료 요청에 실패했습니다.',
      )
    } finally {
      setIsStartingDeployment(false)
    }
  }

  async function resetSelectedExperimentEnvironment() {
    if (!selectedInstanceId || tunnel?.target_instance_id !== selectedInstanceId) {
      setExperimentResetError('선택한 EC2에 SSM 터널을 먼저 연결하세요.')
      return
    }
    const confirmed = window.confirm(
      'EC2와 AWS 인프라는 유지하고 실험 컨테이너·fixture·권한·체인 상태를 초기화합니다. 진행 중인 실험 데이터는 사라집니다. 계속할까요?',
    )
    if (!confirmed) return
    setIsResettingExperiment(true)
    setExperimentResetResult(null)
    setExperimentResetError(null)
    try {
      setExperimentResetResult(await resetExperimentEnvironment())
      setRun(null)
      setActiveAgentRunTarget(null)
      setLastRunRefreshAt(null)
      setMonitorError(null)
    } catch (reason) {
      setExperimentResetError(
        reason instanceof Error ? reason.message : '실험 환경 초기화에 실패했습니다.',
      )
    } finally {
      setIsResettingExperiment(false)
    }
  }

  async function refreshAwsInventory() {
    setDeploymentActionError(null)
    try {
      setDeployment(await getDeployment())
    } catch (reason) {
      setDeploymentActionError(
        reason instanceof Error ? reason.message : 'AWS EC2 목록을 갱신하지 못했습니다.',
      )
    }
  }

  async function connectSsmTunnel() {
    if (!selectedInstanceId) {
      setTunnelActionError('연결할 EC2 인스턴스를 먼저 선택하세요.')
      return
    }
    const confirmed = window.confirm(
      'SSM 터널을 연결합니다. Session Manager Plugin이 없으면 AWS 공식 설치 파일을 자동으로 다운로드하고 설치합니다. 계속할까요?',
    )
    if (!confirmed) return
    setIsStartingTunnel(true)
    setTunnelActionError(null)
    try {
      setTunnel(await startTunnel(selectedInstanceId))
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

  const monitorTarget = getAgentMonitorTarget(routeHash)
  const monitoredRun = activeAgentRunId && run?.run_id === activeAgentRunId ? run : null
  const isAgentExecuting = isRunning
    || monitoredRun?.status === 'RECEIVED'
    || monitoredRun?.status === 'RUNNING'
    || (monitoredRun?.status === 'CANCELLED' && monitoredRun.completed_at === null)
  const detailRunId = getDetailRunId(routeHash)
  const isLogPage = routeHash === LOGS_HASH || detailRunId !== null

  if (monitorTarget) {
    return (
      <div className="app-shell agent-monitor-shell">
        <div className="utility-bar">
          <span>WHS Agentic AI Lab</span>
          <span>Live autonomous attack trace</span>
        </div>
        <header className="top-nav">
          <a className="brand" href="#main">
            OS<span>Agent</span>
          </a>
          <div className="top-nav-actions">
            <ConnectionStatus services={connectionServices} />
            <a className="nav-page-link" href="#main">컨트롤 패널</a>
          </div>
        </header>

        <AgentRunMonitorPage
          boundaries={options?.trust_boundaries ?? []}
          isResuming={isResuming}
          isCancelling={isCancellingRun}
          key={monitorTarget.runId}
          lastRefreshAt={lastRunRefreshAt}
          monitorError={monitorError}
          onBack={() => { window.location.hash = '#main' }}
          onCancel={cancelRun}
          onResume={resumeRun}
          remote={monitorTarget.remote}
          run={monitoredRun}
          runId={monitorTarget.runId}
        />

        <footer>
          <div>
            <strong>OS Agent Live Experiment</strong>
            <p>실시간 Agent 단계 · Tool 선택 · 누적 상태 · 이벤트</p>
          </div>
          <span>{monitorTarget.remote ? 'EC2 via SSM' : 'Local runtime'} · {monitorTarget.runId}</span>
        </footer>
      </div>
    )
  }

  if (isLogPage) {
    return (
      <div className="app-shell result-detail-shell">
        <div className="utility-bar">
          <span>WHS Agentic AI Lab</span>
          <span>Common minimum experiment result</span>
        </div>
        <header className="top-nav">
          <a className="brand" href="#main">
            OS<span>Agent</span>
          </a>
          <div className="top-nav-actions">
            <ConnectionStatus services={connectionServices} />
            <a className="nav-page-link" href="#main">컨트롤 패널</a>
          </div>
        </header>

        <OsResultDetailPage
          initialRunId={detailRunId}
          key={detailRunId ?? 'logs'}
          storageName={storageHealth?.storage ?? null}
        />

        <footer>
          <div>
            <strong>OS Agent Minimum Test</strong>
            <p>Supabase 전체 실행 로그 · 선택 실행 상세</p>
          </div>
          <span>run_id · events · policy · runtime · verifier</span>
        </footer>
      </div>
    )
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
        <div className="top-nav-actions">
          <ConnectionStatus services={connectionServices} />
          <a className="nav-page-link" href={LOGS_HASH}>로그 조회</a>
        </div>
      </header>

      <main id="main">
        <section className="hero">
          <div>
            <span className="eyebrow">고정 인프라 · 통제된 실행</span>
            <h1>
              OS 경계
              <br />
              검증 대시보드
            </h1>
          </div>
          <div className="hero-aside">
            <p>
              하나의 고정 EC2에서 Host·Container 권한을 함께 잠그고,
              8개 Trust Boundary의 실제 침해 가능성과 최악 경로를 비교합니다.
            </p>
            <dl>
              <div>
                <dt>Runtime</dt>
                <dd>1 EC2</dd>
              </div>
              <div>
                <dt>Boundaries</dt>
                <dd>{options?.trust_boundaries.length ?? '—'}</dd>
              </div>
              <div>
                <dt>Tools</dt>
                <dd>{options?.tools.filter((tool) => tool.implemented).length ?? '—'}</dd>
              </div>
            </dl>
          </div>
        </section>

        <WorkflowControl
          key={
            deployment?.operation === 'destroy' &&
            deployment.status === 'succeeded'
              ? deployment.completed_at ?? 'destroyed'
              : 'active'
          }
          backendError={backendError}
          deployment={deployment}
          deploymentActionError={deploymentActionError}
          environmentName={environmentName}
          isLoadingBackend={isLoading}
          isRunningTest={isAgentExecuting}
          isStartingDeployment={isStartingDeployment}
          isStartingTunnel={isStartingTunnel}
          onDeploy={deployEnvironment}
          onEnvironmentNameChange={setEnvironmentName}
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
          environmentName={environmentName}
          isStarting={isStartingDeployment}
          isStartingTunnel={isStartingTunnel}
          isResettingExperiment={isResettingExperiment}
          experimentResetResult={experimentResetResult}
          experimentResetError={experimentResetError}
          onDeploy={deployEnvironment}
          onDestroy={destroyEnvironment}
          onEnvironmentNameChange={setEnvironmentName}
          onRefresh={refreshAwsInventory}
          onResetExperiment={resetSelectedExperimentEnvironment}
          onSelectInstance={selectInstance}
          onStartTunnel={connectSsmTunnel}
          onStopTunnel={disconnectSsmTunnel}
          onTerminateInstance={terminateSelectedInstance}
          selectedInstanceId={selectedInstanceId}
          tunnel={tunnel}
        />

        <div className="workspace-grid">
          <section className="control-panel" aria-labelledby="control-title">
            <div className="section-heading">
              <div>
                <span className="section-index">02</span>
                <h2 id="control-title">전체 경계 Agent 실험</h2>
              </div>
              <span className="planner-mode">
                {agentRemote ? 'EC2 via SSM' : 'SSM 연결 필요'}
              </span>
            </div>

            {isLoading ? (
              <p className="loading-message">
                백엔드 옵션을 불러오는 중입니다.
              </p>
            ) : options ? (
              <form onSubmit={submitRun}>
                <div className="runtime-path" aria-label="실제 Agent 실행 경로">
                  <div className={agentRemote ? 'is-ready' : 'is-waiting'}>
                    <span>01</span>
                    <strong>SSM</strong>
                    <small>{agentRemote ? '연결됨' : '연결 필요'}</small>
                  </div>
                  <div className={health?.host_supervisor === 'connected' ? 'is-ready' : 'is-waiting'}>
                    <span>02</span>
                    <strong>Supervisor</strong>
                    <small>{health?.host_supervisor === 'connected' ? '준비됨' : '대기'}</small>
                  </div>
                  <div className={agentRemote && health?.host_supervisor === 'connected' ? 'is-ready' : 'is-waiting'}>
                    <span>03</span>
                    <strong>U1 + C1</strong>
                    <small>8개 TB 순차 실행</small>
                  </div>
                  <div className={agentRemote && health?.host_supervisor === 'connected' ? 'is-ready' : 'is-waiting'}>
                    <span>04</span>
                    <strong>Verifier</strong>
                    <small>Evidence 판정</small>
                  </div>
                </div>

                <div className="agent-scope-card">
                  <span>고정 분석 범위</span>
                  <strong>EC2 내부 Trust Boundary 8개 전체</strong>
                  <p>등록된 권한을 자동으로 최대화해 공격 후보를 찾고, 성공한 최악 경로 하나를 고정한 뒤 같은 공격으로 최소 권한을 계산합니다.</p>
                  <div>
                    {options.trust_boundaries.map((boundary) => <code key={boundary.id}>{boundary.label}</code>)}
                  </div>
                </div>

                <div className="planner-contract-card">
                  <span>Planner</span>
                  <strong>
                    {options.planner_mode === 'openrouter'
                      ? 'OpenRouter 자율 공격 Planner'
                      : '규칙 기반 재현 가능 Planner v1'}
                  </strong>
                  <p>
                    {options.planner_mode === 'openrouter'
                      ? '선택한 모델이 Recon과 고정 권한을 바탕으로 TB별 구조화 Tool Call을 생성합니다. 임의 셸은 실행할 수 없습니다.'
                      : '관측된 유효 권한만 사용해 TB별 실행 가능한 시나리오를 선택합니다. OPENROUTER_API_KEY를 설정하면 모델 선택이 활성화됩니다.'}
                  </p>
                </div>

                <ModelSelector
                  active={options.planner_mode === 'openrouter'}
                  models={options.planner_models}
                  onChange={setPlannerModel}
                  selected={plannerModel}
                />

                <div className="autonomous-agent-card">
                  <span>Autonomous Attack Agent</span>
                  <strong>사용자 Prompt 없이 스스로 공격 가설과 실행 계획을 생성합니다.</strong>
                  <p>고정 권한과 Recon 증거를 입력으로 받아 8개 TB별 최고 위험 시나리오를 계획하고, 검증 가능한 Tool만 실행합니다.</p>
                  <ol>
                    <li>권한 자동 수집·최대화</li>
                    <li>Recon과 공격 후보 생성</li>
                    <li>실제 실행·별도 검증</li>
                    <li>최대 피해 Attack Contract 고정</li>
                    <li>LLM ID 제안 + 프로그램식 권한 축소</li>
                  </ol>
                </div>

                <div className="automatic-permission-card" aria-label="자동 권한 실험">
                  <span>Automatic permission experiment</span>
                  <strong>권한을 직접 고르지 않아도 됩니다.</strong>
                  <p>프로그램이 Host {hostPermissionTests.length}개와 Container {containerPermissionTests.length}개 통제를 공격 가능 방향으로 합칩니다. 공격 성공 후에는 서비스 묶음 → 분할 → 단일 권한 순서로 자동 축소합니다.</p>
                  <div>
                    <code>MAXIMUM</code>
                    <code>ATTACK CONTRACT</code>
                    <code>1-MINIMAL</code>
                  </div>
                </div>

                {runError || backendError ? (
                  <p className="error-message" role="alert">
                    {runError ?? backendError}
                  </p>
                ) : null}

                <button
                  className="run-button"
                  disabled={
                    isAgentExecuting
                    || !agentRemote
                    || health?.host_supervisor !== 'connected'
                    || Boolean(health?.active_executor)
                    || options.planner_mode !== 'openrouter'
                    || hostPermissionTests.length === 0
                    || containerPermissionTests.length === 0
                  }
                  type="submit"
                >
                  <span>
                    {isAgentExecuting
                      ? '실험 상세 화면에서 실행 중'
                      : health?.active_executor
                        ? `${health.active_executor} Executor 실행 중`
                        : !agentRemote
                          ? 'SSM 연결 후 실행할 수 있습니다'
                          : health?.host_supervisor !== 'connected'
                            ? 'Runtime 준비 상태를 확인하세요'
                            : options.planner_mode !== 'openrouter'
                              ? 'OpenRouter AI 연결이 필요합니다'
                              : '자율 공격·최소 권한 실험 실행'}
                  </span>
                  <span aria-hidden="true">↗</span>
                </button>

                <div className="experiment-reset-panel">
                  <div>
                    <strong>실험을 마쳤나요?</strong>
                    <p>EC2와 AWS 인프라는 유지하고 실험 컨테이너·fixture·권한·체인 상태만 기준 상태로 초기화합니다.</p>
                  </div>
                  <button
                    className="infrastructure-button is-secondary"
                    disabled={
                      isAgentExecuting
                      || isResettingExperiment
                      || !agentRemote
                      || health?.host_supervisor !== 'connected'
                      || Boolean(health?.active_executor)
                    }
                    onClick={resetSelectedExperimentEnvironment}
                    type="button"
                  >
                    {isResettingExperiment ? '실험 환경 초기화 중' : '실험 환경 초기화'}
                  </button>
                </div>
                {experimentResetResult?.status === 'RESET' ? (
                  <p className="experiment-reset-status" role="status">
                    기준 상태 검증까지 완료되었습니다. ({(experimentResetResult.duration_ms / 1000).toFixed(1)}초)
                  </p>
                ) : null}
                {experimentResetError ? (
                  <p className="error-message" role="alert">{experimentResetError}</p>
                ) : null}
              </form>
            ) : (
              <p className="error-message" role="alert">
                백엔드에 연결한 뒤 다시 시도해 주세요.
              </p>
            )}
          </section>

          <div className="results-column">
            <AgentRunLiveCard
              monitorError={monitorError}
              onOpen={() => {
                const target = activeAgentRunTarget
                  ?? (run ? { version: 1 as const, runId: run.run_id, remote: agentRemote } : null)
                if (!target) return
                setActiveAgentRunTarget(target)
                window.location.hash = agentMonitorHash(target)
              }}
              run={monitoredRun}
            />
          </div>
        </div>

      </main>

      <footer>
        <div>
          <strong>OS Agent Minimum Test</strong>
          <p>로컬 대시보드 · 고정 AWS 인프라 · 백엔드 통제 실행</p>
        </div>
        <span>Agent Orchestrator v3 · OpenRouter AI · EC2 via SSM</span>
      </footer>
    </div>
  )
}
