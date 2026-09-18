@echo off
setlocal

echo Stopping AEROS V1 server on port 8765...

powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$stopped = $false; foreach ($connection in @(Get-NetTCPConnection -LocalPort 8765 -State Listen -ErrorAction SilentlyContinue)) { $process = Get-CimInstance Win32_Process -Filter ('ProcessId=' + $connection.OwningProcess); if ($process -and $process.Name -match '(?i)^pythonw?\.exe$' -and $process.CommandLine -match '(?i)server\.py') { Write-Host ('Stopping AEROS server PID ' + $process.ProcessId); Stop-Process -Id $process.ProcessId -Force -ErrorAction SilentlyContinue; $stopped = $true } }; if (-not $stopped) { Write-Host 'No AEROS server was listening on port 8765.' }"

echo Done.
pause
