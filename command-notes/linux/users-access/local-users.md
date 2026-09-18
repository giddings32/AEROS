# Local Users

root and UID >= 1000 users highlight inline, feed the Users tab, and generate per-user fields; Backtick users to manually add.

## Linux

```bash
cat /etc/passwd
```

```bash
getent passwd
```

```bash
awk -F: '{print $1,$3,$4,$6,$7}' /etc/passwd
```

```bash
ls -la /home /root 2>/dev/null
```
