[CmdletBinding()]
param(
    [string]$AwsProfile = "whs-team",
    [string]$AwsRegion = "us-east-1",
    [switch]$SkipAwsLogin
)

$ErrorActionPreference = "Stop"
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Split-Path -Parent $scriptRoot
$backendRoot = Join-Path $projectRoot "backend"
$frontendRoot = Join-Path $projectRoot "frontend"
$backendUrl = "http://127.0.0.1:8000"
$frontendUrl = "http://127.0.0.1:5173"

function Show-LauncherMessage {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Message,
        [string]$Title = "OS Agent Launcher",
        [ValidateSet("Information", "Warning", "Error")]
        [string]$Icon = "Information"
    )

    if ([string]::IsNullOrWhiteSpace($Message)) {
        $Message = "알 수 없는 오류가 발생했습니다. CMD 창의 상세 오류를 확인하세요."
    }

    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        [System.Windows.Forms.MessageBox]::Show(
            $Message,
            $Title,
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::$Icon
        ) | Out-Null
    }
    catch {
        Write-Host "[$Title] $Message"
    }
}

function Confirm-LauncherAction {
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        [string]$Title = "OS Agent Launcher"
    )

    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        $answer = [System.Windows.Forms.MessageBox]::Show(
            $Message,
            $Title,
            [System.Windows.Forms.MessageBoxButtons]::OKCancel,
            [System.Windows.Forms.MessageBoxIcon]::Information
        )
        return $answer -eq [System.Windows.Forms.DialogResult]::OK
    }
    catch {
        $answer = Read-Host "$Message`n계속하려면 Y를 입력하세요"
        return $answer -match "^[Yy]$"
    }
}

function Get-WorkingCommand {
    param(
        [Parameter(Mandatory)]
        [string[]]$Names,
        [string[]]$VersionArguments = @("--version")
    )

    foreach ($name in $Names) {
        $commands = @(Get-Command $name -All -ErrorAction SilentlyContinue)
        foreach ($command in $commands) {
            try {
                & $command.Source @VersionArguments *> $null
                if ($LASTEXITCODE -eq 0) {
                    return $command.Source
                }
            }
            catch {
                continue
            }
        }
    }
    return $null
}

function Get-AwsCli {
    $candidates = @()
    if ($env:ProgramFiles) {
        $candidates += Join-Path $env:ProgramFiles "Amazon\AWSCLIV2\aws.exe"
    }
    if (${env:ProgramFiles(x86)}) {
        $candidates += Join-Path ${env:ProgramFiles(x86)} "Amazon\AWSCLIV2\aws.exe"
    }
    $candidates += @((Get-Command aws.exe, aws.cmd, aws -All -ErrorAction SilentlyContinue).Source)

    foreach ($candidate in ($candidates | Where-Object { $_ } | Select-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $candidate)) {
            continue
        }
        try {
            & $candidate --version *> $null
            if ($LASTEXITCODE -eq 0) {
                return $candidate
            }
        }
        catch {
            continue
        }
    }
    return $null
}

function Get-TerraformCli {
    $candidate = Get-WorkingCommand -Names @("terraform.exe", "terraform") -VersionArguments @("version")
    if (-not $candidate) {
        return $null
    }
    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $versionOutput = (& $candidate version -json 2>$null | Out-String).Trim()
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    try {
        if ([version](ConvertFrom-Json $versionOutput).terraform_version -ge [version]"1.6.0") {
            return $candidate
        }
    }
    catch {}
    return $null
}

function Get-DockerCli {
    $candidates = @()
    if ($env:ProgramFiles) {
        $candidates += Join-Path $env:ProgramFiles "Docker\Docker\resources\bin\docker.exe"
    }
    $candidates += @((Get-Command docker.exe, docker -All -ErrorAction SilentlyContinue).Source)

    foreach ($candidate in ($candidates | Where-Object { $_ } | Select-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $candidate)) {
            continue
        }
        try {
            & $candidate --version *> $null
            if ($LASTEXITCODE -eq 0) {
                return $candidate
            }
        }
        catch {
            continue
        }
    }
    return $null
}

function Test-DockerEngine {
    param([Parameter(Mandatory)][string]$DockerCli)

    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        & $DockerCli info *> $null
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    return $exitCode -eq 0
}

function Ensure-DockerEngine {
    param([Parameter(Mandatory)][string]$DockerCli)

    if (Test-DockerEngine -DockerCli $DockerCli) {
        Write-Host "Docker Desktop 실행 확인 완료"
        return
    }

    $continue = Confirm-LauncherAction -Message (
        "Docker Desktop이 실행되고 있지 않습니다.`n" +
        "확인을 누르면 Docker Desktop을 시작하고 Engine이 준비될 때까지 기다립니다."
    )
    if (-not $continue) {
        throw "Docker Desktop 시작이 취소되었습니다."
    }

    $dockerDesktop = Join-Path $env:ProgramFiles "Docker\Docker\Docker Desktop.exe"
    if (-not (Test-Path -LiteralPath $dockerDesktop)) {
        throw "Docker Desktop 실행 파일을 찾지 못했습니다. setup.cmd를 먼저 실행하세요."
    }
    Start-Process -FilePath $dockerDesktop | Out-Null

    Write-Host "Docker Engine 시작을 기다립니다..."
    for ($attempt = 0; $attempt -lt 48; $attempt++) {
        if (Test-DockerEngine -DockerCli $DockerCli) {
            Write-Host "Docker Desktop 실행 확인 완료"
            return
        }
        Start-Sleep -Seconds 5
    }
    throw "Docker Engine이 4분 안에 준비되지 않았습니다. Docker Desktop의 약관/WSL/재부팅 안내를 완료하거나 setup.cmd를 다시 실행하세요."
}

function Test-AwsSession {
    param([Parameter(Mandatory)][string]$AwsCli)

    # AWS CLI는 미로그인/세션 만료를 stderr로 알린다. 전역 Stop 정책에서
    # 이를 예외로 만들지 않고 종료 코드만 사용해 로그인 필요 여부를 판단한다.
    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        & $AwsCli sts get-caller-identity `
            --profile $AwsProfile `
            --region $AwsRegion `
            --output json 2>$null | Out-Null
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    return $exitCode -eq 0
}

function Get-AwsProfileValue {
    param(
        [Parameter(Mandatory)][string]$AwsCli,
        [Parameter(Mandatory)][string]$Key
    )

    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $output = & $AwsCli configure get $Key --profile $AwsProfile 2>$null
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }

    if ($exitCode -ne 0) {
        return ""
    }
    return ($output | Out-String).Trim()
}

function Invoke-AwsInteractiveLogin {
    param(
        [Parameter(Mandatory)][string]$AwsCli,
        [Parameter(Mandatory)][ValidateSet("login", "sso")][string]$Mode
    )

    $previousErrorActionPreference = $ErrorActionPreference
    try {
        # 브라우저 로그인 안내는 콘솔에 그대로 보여주되, 성공 여부는 AWS CLI의
        # 종료 코드로 판단한다.
        $ErrorActionPreference = "Continue"
        if ($Mode -eq "sso") {
            & $AwsCli sso login --profile $AwsProfile | Out-Host
        }
        else {
            & $AwsCli login --profile $AwsProfile --region $AwsRegion | Out-Host
        }
        $exitCode = $LASTEXITCODE
        return [int]$exitCode
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
}

function Connect-AwsSession {
    param([Parameter(Mandatory)][string]$AwsCli)

    if (Test-AwsSession -AwsCli $AwsCli) {
        Write-Host "AWS 로그인 확인 완료: $AwsProfile ($AwsRegion)"
        return
    }

    $continue = Confirm-LauncherAction -Message (
        "AWS 프로필 '$AwsProfile'이 로그인되어 있지 않거나 세션이 만료되었습니다.`n" +
        "확인을 누르면 AWS 브라우저 로그인을 시작합니다."
    )
    if (-not $continue) {
        throw "사용자가 AWS 로그인을 취소했습니다."
    }

    $ssoSession = Get-AwsProfileValue -AwsCli $AwsCli -Key "sso_session"
    $ssoStartUrl = Get-AwsProfileValue -AwsCli $AwsCli -Key "sso_start_url"

    if ($ssoSession -or $ssoStartUrl) {
        $loginExitCode = Invoke-AwsInteractiveLogin -AwsCli $AwsCli -Mode "sso"
    }
    else {
        $loginExitCode = Invoke-AwsInteractiveLogin -AwsCli $AwsCli -Mode "login"
    }

    if ($loginExitCode -ne 0 -or -not (Test-AwsSession -AwsCli $AwsCli)) {
        Show-LauncherMessage `
            -Message "AWS 로그인에 실패했습니다. '$AwsProfile' 프로필 설정과 AWS CLI 버전을 확인하세요." `
            -Icon Error
        throw "AWS 로그인 검증에 실패했습니다."
    }

    Show-LauncherMessage -Message "AWS 로그인이 완료되었습니다. 프론트엔드와 백엔드를 시작합니다."
}

function Test-TcpPort {
    param([Parameter(Mandatory)][int]$Port)

    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $asyncResult = $client.BeginConnect("127.0.0.1", $Port, $null, $null)
        if (-not $asyncResult.AsyncWaitHandle.WaitOne(250)) {
            return $false
        }
        $client.EndConnect($asyncResult)
        return $true
    }
    catch {
        return $false
    }
    finally {
        $client.Dispose()
    }
}

function Get-ListeningProcessId {
    param([Parameter(Mandatory)][int]$Port)

    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $lines = & "$env:SystemRoot\System32\netstat.exe" -ano -p tcp 2>$null
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }

    foreach ($line in $lines) {
        if ($line -match "^\s*TCP\s+\S+:$Port\s+\S+\s+LISTENING\s+(\d+)\s*$") {
            return [int]$Matches[1]
        }
    }
    return $null
}

function Stop-FrontendServerForDependencySync {
    $processIds = [System.Collections.Generic.HashSet[int]]::new()
    $nodeModulesRoot = [System.IO.Path]::GetFullPath((Join-Path $frontendRoot "node_modules"))

    # Vite의 부모 프로세스뿐 아니라 Rolldown 파일을 직접 로드한 자식 Node
    # 프로세스까지 찾는다. Windows에서는 자식이 남으면 .node 파일을 지울 수 없다.
    foreach ($nodeProcess in @(Get-Process node -ErrorAction SilentlyContinue)) {
        try {
            foreach ($module in @($nodeProcess.Modules)) {
                if ($module.FileName.StartsWith(
                    $nodeModulesRoot,
                    [System.StringComparison]::OrdinalIgnoreCase
                )) {
                    $processIds.Add([int]$nodeProcess.Id) | Out-Null
                    break
                }
            }
        }
        catch {
            # 다른 사용자나 시스템 Node 프로세스의 모듈을 읽지 못하면 건너뛴다.
        }
    }

    $listenerProcessId = Get-ListeningProcessId -Port 5173
    if ($listenerProcessId) {
        $listener = Get-Process -Id $listenerProcessId -ErrorAction SilentlyContinue
        if ($listener -and $listener.ProcessName -ne "node") {
            throw "5173 포트를 '$($listener.ProcessName)' 프로세스가 사용 중입니다. 해당 프로그램을 종료한 뒤 다시 실행하세요."
        }
        if ($listener) {
            $processIds.Add([int]$listenerProcessId) | Out-Null
        }
    }

    if ($processIds.Count -eq 0) {
        return
    }

    $idText = (($processIds | Sort-Object) -join ", ")
    Write-Host "의존성 갱신을 위해 이 프로젝트의 Node 프로세스(PID $idText)를 종료합니다..."
    foreach ($processIdToStop in $processIds) {
        Stop-Process -Id $processIdToStop -Force -ErrorAction SilentlyContinue
    }

    for ($attempt = 0; $attempt -lt 20; $attempt++) {
        $remaining = @(
            $processIds | Where-Object {
                Get-Process -Id $_ -ErrorAction SilentlyContinue
            }
        )
        if ($remaining.Count -eq 0) {
            Start-Sleep -Milliseconds 500
            return
        }
        Start-Sleep -Milliseconds 250
    }
    throw "기존 프론트엔드 프로세스를 종료하지 못했습니다. PID: $idText"
}

function Initialize-BackendEnvironment {
    $environmentFile = Join-Path $backendRoot ".env"

    if (-not (Test-Path -LiteralPath $environmentFile)) {
        Show-LauncherMessage -Message (
            "backend/.env 파일이 없습니다.`n`n" +
            "프로젝트 관리자에게 .env 파일을 받아 아래 경로에 넣은 뒤 run.cmd를 다시 실행하세요.`n`n" +
            "$environmentFile"
        ) -Icon Warning
        throw "backend/.env 파일이 없습니다. 관리자에게 파일을 받아 backend/.env에 넣으세요."
    }

    $loadedKeys = [System.Collections.Generic.List[string]]::new()
    $lineNumber = 0
    foreach ($rawLine in Get-Content -LiteralPath $environmentFile) {
        $lineNumber++
        $line = $rawLine.Trim()
        if (-not $line -or $line.StartsWith("#")) {
            continue
        }
        if ($line -notmatch "^([A-Za-z_][A-Za-z0-9_]*)=(.*)$") {
            Write-Host "backend/.env ${lineNumber}번째 줄을 해석할 수 없어 건너뜁니다." -ForegroundColor Yellow
            continue
        }

        $key = $Matches[1]
        $value = $Matches[2].Trim()
        if (
            $value.Length -ge 2 -and
            (($value.StartsWith('"') -and $value.EndsWith('"')) -or
             ($value.StartsWith("'") -and $value.EndsWith("'")))
        ) {
            $value = $value.Substring(1, $value.Length - 2)
        }

        # CMD/PowerShell에서 명시적으로 전달한 값이 있으면 .env보다 우선한다.
        $existingValue = [Environment]::GetEnvironmentVariable($key, "Process")
        if ([string]::IsNullOrEmpty($existingValue)) {
            [Environment]::SetEnvironmentVariable($key, $value, "Process")
        }
        $loadedKeys.Add($key) | Out-Null
    }

    Write-Host "backend/.env 확인 완료 ($($loadedKeys.Count)개 항목, 값은 표시하지 않음)"
    $openRouterKey = [Environment]::GetEnvironmentVariable("OPENROUTER_API_KEY", "Process")
    if ([string]::IsNullOrWhiteSpace($openRouterKey)) {
        Write-Host "OPENROUTER_API_KEY가 비어 있어 로컬 규칙 플래너를 사용합니다." -ForegroundColor Yellow
    }
    else {
        Write-Host "OPENROUTER_API_KEY 설정 확인 완료" -ForegroundColor Green
    }
}

function Sync-BackendDependencies {
    param([Parameter(Mandatory)][string]$Python)

    $venvRoot = Join-Path $backendRoot ".venv"
    $venvPython = Join-Path $venvRoot "Scripts\python.exe"
    $requirements = Join-Path $backendRoot "requirements.txt"
    $stampFile = Join-Path $venvRoot ".requirements.sha256"

    if (-not (Test-Path -LiteralPath $venvPython)) {
        Write-Host "Python 가상환경을 생성합니다..."
        & $Python -m venv $venvRoot
        if ($LASTEXITCODE -ne 0) {
            throw "Python 가상환경 생성에 실패했습니다."
        }
    }

    $currentHash = (Get-FileHash -LiteralPath $requirements -Algorithm SHA256).Hash
    $savedHash = if (Test-Path -LiteralPath $stampFile) {
        (Get-Content -LiteralPath $stampFile -Raw).Trim()
    }
    else {
        ""
    }

    if ($currentHash -ne $savedHash) {
        Write-Host "백엔드 의존성을 설치합니다..."
        & $venvPython -m pip install -r $requirements
        if ($LASTEXITCODE -ne 0) {
            throw "백엔드 의존성 설치에 실패했습니다."
        }
        Set-Content -LiteralPath $stampFile -Value $currentHash -NoNewline
    }

    return $venvPython
}

function Sync-FrontendDependencies {
    param([Parameter(Mandatory)][string]$Npm)

    $lockFile = Join-Path $frontendRoot "package-lock.json"
    $nodeModules = Join-Path $frontendRoot "node_modules"
    $stampFile = Join-Path $nodeModules ".package-lock.sha256"
    $currentHash = (Get-FileHash -LiteralPath $lockFile -Algorithm SHA256).Hash
    $savedHash = if (Test-Path -LiteralPath $stampFile) {
        (Get-Content -LiteralPath $stampFile -Raw).Trim()
    }
    else {
        ""
    }

    if ($currentHash -ne $savedHash) {
        # 실행 중인 Vite가 Rolldown 네이티브 모듈을 잠그고 있으면 npm ci가
        # Windows EPERM으로 실패하므로 이 프로젝트가 사용하는 5173 서버만 종료한다.
        Stop-FrontendServerForDependencySync
        Write-Host "프론트엔드 의존성을 설치합니다..."
        Push-Location $frontendRoot
        try {
            $installSucceeded = $false
            for ($attempt = 1; $attempt -le 2; $attempt++) {
                & $Npm ci
                if ($LASTEXITCODE -eq 0) {
                    $installSucceeded = $true
                    break
                }
                if ($attempt -lt 2) {
                    Write-Host "파일 잠금 해제를 기다린 뒤 프론트엔드 설치를 한 번 더 시도합니다..."
                    Start-Sleep -Seconds 2
                }
            }
            if (-not $installSucceeded) {
                throw "프론트엔드 의존성 설치에 실패했습니다. 실행 중인 Node/Vite 또는 보안 프로그램의 파일 잠금을 확인하세요."
            }
        }
        finally {
            Pop-Location
        }
        Set-Content -LiteralPath $stampFile -Value $currentHash -NoNewline
    }
}

$launcherStage = "초기화"

try {
    Write-Host "OS Agent 실행 준비를 시작합니다."

    $launcherStage = "Python 및 Node.js 확인"
    $python = Get-WorkingCommand -Names @("python.exe", "python") -VersionArguments @("--version")
    $npm = Get-WorkingCommand -Names @("npm.cmd", "npm") -VersionArguments @("--version")
    if (-not $python) {
        throw "Python을 찾을 수 없습니다. setup.cmd를 먼저 실행하세요."
    }
    if (-not $npm) {
        throw "npm을 찾을 수 없습니다. setup.cmd를 먼저 실행하세요."
    }

    if (-not $SkipAwsLogin) {
        $launcherStage = "Terraform 및 Docker 확인"
        $terraformCli = Get-TerraformCli
        if (-not $terraformCli) {
            throw "Terraform 1.6 이상을 찾을 수 없습니다. setup.cmd를 먼저 실행하세요."
        }
        $dockerCli = Get-DockerCli
        if (-not $dockerCli) {
            throw "Docker Desktop을 찾을 수 없습니다. setup.cmd를 먼저 실행하세요."
        }
        Ensure-DockerEngine -DockerCli $dockerCli

        $launcherStage = "AWS CLI 확인"
        $awsCli = Get-AwsCli
        if (-not $awsCli) {
            Write-Host "정상 동작하는 AWS CLI v2를 찾지 못했습니다." -ForegroundColor Red
            Show-LauncherMessage `
                -Message "정상 동작하는 AWS CLI v2를 찾지 못했습니다. setup.cmd를 먼저 실행하세요." `
                -Icon Error
            throw "AWS CLI v2를 찾지 못했습니다."
        }
        $launcherStage = "AWS 로그인"
        Connect-AwsSession -AwsCli $awsCli
    }

    $launcherStage = "환경변수 파일 확인"
    Initialize-BackendEnvironment

    $launcherStage = "프로젝트 의존성 설치"
    $venvPython = Sync-BackendDependencies -Python $python
    Sync-FrontendDependencies -Npm $npm

    $previousEnvironment = @{
        AWS_PROFILE = $env:AWS_PROFILE
        AWS_REGION = $env:AWS_REGION
    }

    try {
        $launcherStage = "프론트엔드 및 백엔드 시작"
        $env:AWS_PROFILE = $AwsProfile
        $env:AWS_REGION = $AwsRegion

        if (-not (Test-TcpPort -Port 8000)) {
            Write-Host "백엔드를 시작합니다..."
            Start-Process `
                -FilePath $venvPython `
                -ArgumentList @("-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8000") `
                -WorkingDirectory $backendRoot | Out-Null
        }
        else {
            Write-Host "8000 포트가 이미 사용 중이므로 기존 백엔드를 사용합니다."
        }

        if (-not (Test-TcpPort -Port 5173)) {
            Write-Host "프론트엔드를 시작합니다..."
            Start-Process `
                -FilePath $npm `
                -ArgumentList @("run", "dev", "--", "--host", "127.0.0.1") `
                -WorkingDirectory $frontendRoot | Out-Null
        }
        else {
            Write-Host "5173 포트가 이미 사용 중이므로 기존 프론트엔드를 사용합니다."
        }
    }
    finally {
        $env:AWS_PROFILE = $previousEnvironment.AWS_PROFILE
        $env:AWS_REGION = $previousEnvironment.AWS_REGION
    }

    $launcherStage = "백엔드 헬스 체크"
    Write-Host "백엔드 시작을 기다립니다..."
    $backendReady = $false
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        try {
            $health = Invoke-RestMethod -Uri "$backendUrl/api/health" -TimeoutSec 2
            if ($health.status -eq "ok") {
                $backendReady = $true
                break
            }
        }
        catch {
            Start-Sleep -Seconds 1
        }
    }

    if (-not $backendReady) {
        throw "30초 안에 백엔드 헬스 체크가 성공하지 않았습니다."
    }

    Start-Process $frontendUrl
    Write-Host "실행 완료: $frontendUrl"
}
catch {
    $caughtError = $_
    $errorMessage = [string]$caughtError.Exception.Message
    if ([string]::IsNullOrWhiteSpace($errorMessage)) {
        $errorMessage = ($caughtError | Out-String).Trim()
    }
    if ([string]::IsNullOrWhiteSpace($errorMessage)) {
        $errorMessage = "알 수 없는 오류"
    }
    $displayMessage = "실행 단계: $launcherStage`n`n$errorMessage"
    Show-LauncherMessage -Message $displayMessage -Icon Error
    Write-Host $displayMessage -ForegroundColor Red
    Write-Error -ErrorRecord $caughtError
    exit 1
}
