# Kerberos / SPNs / Roasting

SPNs, Kerberoasting, AS-REP roasting, ticket notes, and cracked credential context.

## PowerShell

```powershell
setspn -Q */*
```

```powershell
Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName
```

```powershell
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth
```
