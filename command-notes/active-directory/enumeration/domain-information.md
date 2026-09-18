# Domain Information

Domain name, DCs, DNS, domain role, trust notes, and current domain context.

## CMD

```bat
echo %USERDOMAIN%
```

```bat
nltest /dsgetdc:<domain>
```

```bat
net config workstation
```

```bat
net view /domain
```
