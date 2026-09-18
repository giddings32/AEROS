# Token Privileges — {{entity}}

Run these commands after obtaining a shell or session as **{{entity}}**.

## CMD / PowerShell

```bat
whoami
```

```bat
whoami /user
```

```bat
whoami /groups
```

```bat
whoami /priv
```

`net user "{{entity}}"` shows account and group information, but it does not show the active token privileges reported by `whoami /priv`.
