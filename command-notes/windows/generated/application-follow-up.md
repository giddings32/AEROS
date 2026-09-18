# Application Follow-up — {{entity}}

```bat
where /r C:\ "{{entity}}*"
```

```powershell
Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue -Filter "*{{entity}}*"
```
