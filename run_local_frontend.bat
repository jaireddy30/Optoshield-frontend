@echo off
title Optox Shield - Node.js Frontend Console
echo =======================================================
echo   OPTOX SHIELD - PURE NODE.JS SOC DASHBOARD
echo =======================================================
echo.

set "NODE_CMD=node"
where node >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    if exist "%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\node\bin\node.exe" (
        set "NODE_CMD=%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\node\bin\node.exe"
    ) else (
        echo [-] Error: Node.js is not found on your system PATH.
        echo [*] Please install Node.js from https://nodejs.org/
        pause
        exit /b 1
    )
)

echo [*] Starting Node.js Frontend Web Server on port 9000...
"%NODE_CMD%" server.js
pause
