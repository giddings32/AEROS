# User Group Memberships — {{entity}}

## CMD

```bat
net user "{{entity}}"
```

## PowerShell

```powershell
Get-LocalUser "{{entity}}"
```

```powershell
Get-LocalGroup | ForEach-Object {
    $group = $_.Name
    Get-LocalGroupMember $group -ErrorAction SilentlyContinue |
        Where-Object Name -like "*\{{entity}}" |
        ForEach-Object { "$group -> $($_.Name)" }
}
```
