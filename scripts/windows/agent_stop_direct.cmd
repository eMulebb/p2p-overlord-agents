START "" /MIN /WAIT POWERSHELL.EXE -NoProfile -Command ^
"Get-CimInstance Win32_Process ^
| Where-Object { $_.Name -eq 'overlord-agent-emule.exe' } ^
| ForEach-Object { Write-Host ('Killing PID ' + $_.ProcessId); Stop-Process -Id $_.ProcessId -Force }"
