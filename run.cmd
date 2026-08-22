@echo off
setlocal

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\run.ps1" %*
set "OS_AGENT_EXIT_CODE=%ERRORLEVEL%"

if not "%OS_AGENT_EXIT_CODE%"=="0" (
    echo.
    echo OS Agent launcher failed. Exit code: %OS_AGENT_EXIT_CODE%
    pause
)

exit /b %OS_AGENT_EXIT_CODE%
