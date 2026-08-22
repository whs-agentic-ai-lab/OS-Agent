@echo off
setlocal

title OS Agent - First-time setup
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\setup.ps1" %*
set "OS_AGENT_SETUP_EXIT_CODE=%ERRORLEVEL%"

if not "%OS_AGENT_SETUP_EXIT_CODE%"=="0" (
    echo.
    echo OS Agent environment setup failed. Exit code: %OS_AGENT_SETUP_EXIT_CODE%
    echo Fix the item shown above, then run setup.cmd again.
    pause
)

exit /b %OS_AGENT_SETUP_EXIT_CODE%
