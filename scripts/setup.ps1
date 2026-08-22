[CmdletBinding()]
param(
    [switch]$SkipDockerReadyCheck,
    [switch]$SkipSessionManagerPlugin
)

$ErrorActionPreference = "Stop"
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Split-Path -Parent $scriptRoot

function Write-SetupSection {
    param([Parameter(Mandatory)][string]$Title)

    Write-Host ""
    Write-Host "============================================================" -ForegroundColor DarkCyan
    Write-Host " $Title" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor DarkCyan
}

function Confirm-SetupStep {
    param([Parameter(Mandatory)][string]$Message)

    while ($true) {
        $answer = (Read-Host "$Message [Y/N]").Trim()
        if ($answer -match "^[Yy]$") {
            return $true
        }
        if ($answer -match "^[Nn]$") {
            return $false
        }
        Write-Host "Y 또는 N을 입력하세요." -ForegroundColor Yellow
    }
}

function Refresh-ProcessPath {
    $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $env:Path = (@($machinePath, $userPath) | Where-Object { $_ }) -join ";"
}

function Get-WorkingExecutable {
    param(
        [Parameter(Mandatory)][string[]]$Names,
        [string[]]$KnownPaths = @(),
        [string[]]$VersionArguments = @("--version")
    )

    $candidates = @($KnownPaths)
    foreach ($name in $Names) {
        $candidates += @((Get-Command $name -All -ErrorAction SilentlyContinue).Source)
    }

    foreach ($candidate in ($candidates | Where-Object { $_ } | Select-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $candidate)) {
            continue
        }
        $previousErrorActionPreference = $ErrorActionPreference
        try {
            $ErrorActionPreference = "Continue"
            & $candidate @VersionArguments *> $null
            $exitCode = $LASTEXITCODE
        }
        catch {
            $exitCode = 1
        }
        finally {
            $ErrorActionPreference = $previousErrorActionPreference
        }
        if ($exitCode -eq 0) {
            return $candidate
        }
    }
    return $null
}

function Get-PythonExecutable {
    $knownPaths = @(
        (Join-Path $env:LOCALAPPDATA "Programs\Python\Python310\python.exe"),
        (Join-Path $env:ProgramFiles "Python310\python.exe")
    )
    foreach ($candidate in @(
        Get-WorkingExecutable -Names @("python.exe", "python") -KnownPaths $knownPaths
    )) {
        if (-not $candidate) {
            continue
        }
        $versionText = (& $candidate -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>$null | Out-String).Trim()
        try {
            if ([version]$versionText -ge [version]"3.10") {
                return $candidate
            }
        }
        catch {
            continue
        }
    }
    return $null
}

function Get-NodeExecutable {
    $knownPaths = @((Join-Path $env:ProgramFiles "nodejs\node.exe"))
    $candidate = Get-WorkingExecutable -Names @("node.exe", "node") -KnownPaths $knownPaths
    if (-not $candidate) {
        return $null
    }
    $versionText = ((& $candidate --version 2>$null | Out-String).Trim() -replace "^v", "")
    try {
        if ([version]$versionText -ge [version]"22.0") {
            return $candidate
        }
    }
    catch {}
    return $null
}

function Get-AwsCliExecutable {
    $knownPaths = @(
        (Join-Path $env:LOCALAPPDATA "Programs\Amazon\AWSCLIV2\aws.exe"),
        (Join-Path $env:ProgramFiles "Amazon\AWSCLIV2\aws.exe")
    )
    $candidate = Get-WorkingExecutable -Names @("aws.exe", "aws.cmd", "aws") -KnownPaths $knownPaths
    if (-not $candidate) {
        return $null
    }

    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $versionOutput = (& $candidate --version 2>&1 | Out-String)
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    if ($versionOutput -match "aws-cli/(\d+\.\d+\.\d+)" -and [version]$Matches[1] -ge [version]"2.32.0") {
        return $candidate
    }
    return $null
}

function Get-TerraformExecutable {
    $candidate = Get-WorkingExecutable -Names @("terraform.exe", "terraform")
    if (-not $candidate) {
        return $null
    }
    $versionOutput = (& $candidate version -json 2>$null | Out-String).Trim()
    try {
        $terraformVersion = (ConvertFrom-Json $versionOutput).terraform_version
        if ([version]$terraformVersion -ge [version]"1.6.0") {
            return $candidate
        }
    }
    catch {}
    return $null
}

function Get-DockerExecutable {
    $knownPaths = @((Join-Path $env:ProgramFiles "Docker\Docker\resources\bin\docker.exe"))
    Get-WorkingExecutable -Names @("docker.exe", "docker") -KnownPaths $knownPaths
}

function Get-SessionManagerPluginExecutable {
    $knownPaths = @(
        (Join-Path $env:ProgramFiles "Amazon\SessionManagerPlugin\bin\session-manager-plugin.exe"),
        (Join-Path ${env:ProgramFiles(x86)} "Amazon\SessionManagerPlugin\bin\session-manager-plugin.exe")
    )
    Get-WorkingExecutable `
        -Names @("session-manager-plugin.exe", "session-manager-plugin") `
        -KnownPaths $knownPaths `
        -VersionArguments @()
}

function Get-WingetExecutable {
    Get-WorkingExecutable -Names @("winget.exe", "winget") -VersionArguments @("--version")
}

function Install-WingetPackage {
    param(
        [Parameter(Mandatory)][string]$DisplayName,
        [Parameter(Mandatory)][string]$PackageId,
        [Parameter(Mandatory)][scriptblock]$Detect
    )

    $existing = & $Detect
    if ($existing) {
        Write-Host "[완료] $DisplayName" -ForegroundColor Green
        return $existing
    }

    Write-Host ""
    Write-Host "$DisplayName 이(가) 설치되어 있지 않거나 요구 버전보다 낮습니다." -ForegroundColor Yellow
    Write-Host "다운로드 패키지: $PackageId"
    if (-not (Confirm-SetupStep "$DisplayName 을(를) 자동 다운로드하고 설치할까요?")) {
        throw "$DisplayName 설치가 취소되었습니다."
    }

    $winget = Get-WingetExecutable
    if (-not $winget) {
        Write-Host "winget이 없어 $DisplayName 자동 설치를 시작할 수 없습니다." -ForegroundColor Yellow
        Write-Host "1. Microsoft Store에서 '앱 설치 관리자' 또는 'App Installer'를 검색합니다."
        Write-Host "2. 앱을 설치하거나 최신 버전으로 업데이트합니다."
        Write-Host "3. 완료 후 setup.cmd를 다시 실행합니다."
        if (Confirm-SetupStep "Microsoft Store의 App Installer 검색 화면을 열까요?") {
            Start-Process "ms-windows-store://search/?query=App%20Installer"
        }
        throw "App Installer 설치 후 setup.cmd를 다시 실행하세요."
    }

    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        & $winget install `
            --id $PackageId `
            --exact `
            --source winget `
            --accept-package-agreements `
            --accept-source-agreements `
            --silent `
            --disable-interactivity
        $installExitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }

    Refresh-ProcessPath
    $installed = & $Detect
    if ($installed) {
        Write-Host "[설치 완료] $DisplayName" -ForegroundColor Green
        return $installed
    }

    Write-Host ""
    Write-Host "$DisplayName 자동 설치를 완료하지 못했습니다. winget 종료 코드: $installExitCode" -ForegroundColor Red
    Write-Host "아래 명령을 관리자 CMD에서 실행할 수 있습니다:"
    Write-Host "winget install --id $PackageId -e --source winget" -ForegroundColor White
    throw "$DisplayName 설치 후 setup.cmd를 다시 실행하세요."
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

function Complete-DockerDesktopSetup {
    param([Parameter(Mandatory)][string]$DockerCli)

    if (Test-DockerEngine -DockerCli $DockerCli) {
        Write-Host "[완료] Docker Desktop 실행 확인" -ForegroundColor Green
        return
    }

    $dockerDesktop = Join-Path $env:ProgramFiles "Docker\Docker\Docker Desktop.exe"
    if (Test-Path -LiteralPath $dockerDesktop) {
        Write-Host "Docker Desktop을 시작합니다..."
        Start-Process -FilePath $dockerDesktop | Out-Null
    }

    Write-Host ""
    Write-Host "Docker Desktop 최초 설정이 필요합니다." -ForegroundColor Yellow
    Write-Host "1. 화면에 약관이 나오면 Accept를 누르세요."
    Write-Host "2. WSL 업데이트 또는 재부팅을 요구하면 안내에 따르세요."
    Write-Host "3. Docker Desktop 왼쪽 아래가 'Engine running'이 될 때까지 기다리세요."
    Write-Host "4. 재부팅했다면 이 setup.cmd를 다시 실행하면 완료된 항목은 자동으로 건너뜁니다."

    while (-not (Test-DockerEngine -DockerCli $DockerCli)) {
        if (-not (Confirm-SetupStep "Docker Desktop에 Engine running이 표시되면 Y를 누르세요")) {
            throw "Docker Desktop 최초 설정을 완료한 뒤 setup.cmd를 다시 실행하세요."
        }
        Start-Sleep -Seconds 2
    }
    Write-Host "[완료] Docker Desktop 실행 확인" -ForegroundColor Green
}

function Install-SessionManagerPlugin {
    $existing = Get-SessionManagerPluginExecutable
    if ($existing) {
        Write-Host "[완료] AWS Session Manager Plugin" -ForegroundColor Green
        return $existing
    }

    Write-Host ""
    Write-Host "SSM 터널 연결에 AWS Session Manager Plugin이 필요합니다." -ForegroundColor Yellow
    if (-not (Confirm-SetupStep "AWS 공식 설치 파일을 다운로드하고 설치할까요?")) {
        throw "Session Manager Plugin 설치가 취소되었습니다."
    }

    $installerUrl = "https://s3.amazonaws.com/session-manager-downloads/plugin/latest/windows/SessionManagerPluginSetup.exe"
    $installerPath = Join-Path $env:TEMP "OSAgent-SessionManagerPluginSetup.exe"
    Write-Host "Session Manager Plugin을 다운로드합니다..."
    Invoke-WebRequest -Uri $installerUrl -OutFile $installerPath -UseBasicParsing
    try {
        Write-Host "설치 창이 뜨면 기본값으로 설치를 완료하세요. 관리자 권한 확인창이 표시될 수 있습니다."
        $process = Start-Process -FilePath $installerPath -Verb RunAs -Wait -PassThru
        if ($process.ExitCode -ne 0) {
            throw "Session Manager Plugin 설치 프로그램이 종료 코드 $($process.ExitCode)을 반환했습니다."
        }
    }
    finally {
        Remove-Item -LiteralPath $installerPath -Force -ErrorAction SilentlyContinue
    }

    Refresh-ProcessPath
    $installed = Get-SessionManagerPluginExecutable
    if (-not $installed) {
        throw "Session Manager Plugin 설치를 확인하지 못했습니다. 설치를 완료한 뒤 setup.cmd를 다시 실행하세요."
    }
    Write-Host "[설치 완료] AWS Session Manager Plugin" -ForegroundColor Green
    return $installed
}

try {
    Write-Host ""
    Write-Host "OS Agent 최초 환경설정" -ForegroundColor Cyan
    Write-Host "Git만 설치된 Windows PC를 기준으로 필요한 도구를 준비합니다."
    Write-Host "이미 설치된 항목은 자동으로 건너뜁니다. 설치 중 Windows 관리자 권한 확인창이 나타날 수 있습니다."

    Write-SetupSection -Title "0/4 Windows 패키지 관리자 확인"
    Refresh-ProcessPath
    if (-not (Get-WingetExecutable)) {
        Write-Host "winget이 없습니다. 이미 설치된 도구는 계속 확인하고, 새 설치가 필요한 시점에 App Installer 설치를 안내합니다." -ForegroundColor Yellow
    }
    else {
        Write-Host "[완료] winget" -ForegroundColor Green
    }

    Write-SetupSection -Title "1/4 개발 런타임 설치"
    $python = Install-WingetPackage `
        -DisplayName "Python 3.10 이상" `
        -PackageId "Python.Python.3.10" `
        -Detect { Get-PythonExecutable }
    $node = Install-WingetPackage `
        -DisplayName "Node.js 22 이상 LTS" `
        -PackageId "OpenJS.NodeJS.LTS" `
        -Detect { Get-NodeExecutable }

    Write-SetupSection -Title "2/4 AWS 및 인프라 도구 설치"
    $awsCli = Install-WingetPackage `
        -DisplayName "AWS CLI v2" `
        -PackageId "Amazon.AWSCLI" `
        -Detect { Get-AwsCliExecutable }
    $terraform = Install-WingetPackage `
        -DisplayName "Terraform 1.6 이상" `
        -PackageId "Hashicorp.Terraform" `
        -Detect { Get-TerraformExecutable }

    if (-not $SkipSessionManagerPlugin) {
        $sessionManagerPlugin = Install-SessionManagerPlugin
    }

    Write-SetupSection -Title "3/4 Docker Desktop 설치 및 최초 실행"
    $docker = Install-WingetPackage `
        -DisplayName "Docker Desktop" `
        -PackageId "Docker.DockerDesktop" `
        -Detect { Get-DockerExecutable }
    if (-not $SkipDockerReadyCheck) {
        Complete-DockerDesktopSetup -DockerCli $docker
    }

    Write-SetupSection -Title "4/4 환경설정 완료"
    Write-Host "Python:     $python"
    Write-Host "Node.js:    $node"
    Write-Host "AWS CLI:    $awsCli"
    Write-Host "Terraform:  $terraform"
    Write-Host "Docker CLI: $docker"
    Write-Host ""
    Write-Host "이후에는 setup.cmd가 아니라 run.cmd만 실행하면 됩니다." -ForegroundColor Green
    Write-Host "run.cmd 실행 중 AWS 세션이 없으면 브라우저 로그인 안내가 표시됩니다."

    if (Confirm-SetupStep "지금 OS Agent를 실행할까요?") {
        & (Join-Path $projectRoot "run.cmd")
        exit $LASTEXITCODE
    }
}
catch {
    Write-Host ""
    Write-Host "환경설정 중단: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
