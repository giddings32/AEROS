# Installed Applications x64

64-bit installed software from the native uninstall registry path.

## PowerShell

```powershell
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
Select-Object DisplayName,DisplayVersion,Publisher,InstallDate,InstallLocation |
Sort-Object DisplayName
```
