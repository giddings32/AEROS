# Group Members — {{entity}}

```bash
getent group {{entity}} 2>/dev/null
```

```bash
grep '^{{entity}}:' /etc/group 2>/dev/null
```

## High-impact group follow-up

```bash
id <user> 2>/dev/null
```

```bash
getent group sudo admin wheel docker lxd adm shadow staff 2>/dev/null
```
