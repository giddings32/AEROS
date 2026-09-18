# Listening Ports

Local listeners, PIDs, service names, and loopback-only services.

## Linux

```bash
ss -tulpena
```

```bash
ss -tulpen 2>/dev/null
```

```bash
netstat -tulpen 2>/dev/null
```

```bash
lsof -i -P -n 2>/dev/null
```
