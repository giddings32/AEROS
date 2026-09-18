# Services

systemd services, init scripts, enabled services, custom service paths, and service users.

## Linux

```bash
systemctl list-units --type=service --state=running 2>/dev/null
```

```bash
systemctl list-unit-files --type=service 2>/dev/null
```

```bash
service --status-all 2>/dev/null
```

```bash
ls -la /etc/systemd/system /lib/systemd/system /etc/init.d 2>/dev/null
```
