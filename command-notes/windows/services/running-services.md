# Running Services

Running Windows services, filtered to remove default System32-backed services.

## PowerShell

```powershell
Get-CimInstance -ClassName Win32_Service |
Where-Object {
  $_.State -eq 'Running' -and
  $_.PathName -and
  $_.PathName -notmatch '^[\"'']?C:\\Windows\\System32\\'
} |
Select-Object Name,State,PathName |
Sort-Object Name
```
