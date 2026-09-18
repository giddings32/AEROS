# Installed Applications x86 / 32-bit

32-bit installed software from the WOW6432Node uninstall registry path.

## PowerShell

```powershell
Get-ItemProperty HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
Select-Object DisplayName,DisplayVersion,Publisher,InstallDate,InstallLocation |
Sort-Object DisplayName
```
