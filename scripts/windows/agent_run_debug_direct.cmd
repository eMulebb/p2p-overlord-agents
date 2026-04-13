@ECHO OFF
CHCP 65001
TITLE OVERLORDEMULEAGENT

START "" /MIN /WAIT POWERSHELL.EXE -NoProfile -Command ^
"Get-CimInstance Win32_Process ^
| Where-Object { $_.Name -eq 'overlord-agent-emule.exe' } ^
| ForEach-Object { Write-Host ('Killing PID ' + $_.ProcessId); Stop-Process -Id $_.ProcessId -Force }"

TIMEOUT /T 2 >nul

ECHO OVERLORD_PROJECT_DIR = [ %OVERLORD_PROJECT_DIR% ] [ %TIME% ]

CD /D %OVERLORD_PROJECT_DIR%\p2p-overlord-agents

cargo build -p overlord-agent-emule --bin overlord-agent-emule
IF ERRORLEVEL 1 EXIT /B %ERRORLEVEL%

SET RUST_BACKTRACE=1

START "" /MIN target\debug\overlord-agent-emule.exe --config %OVERLORD_TMP_DIR%\agent-real-miniupnpc.toml
