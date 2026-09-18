# Sudoers / Privilege Policy

## Linux

```bash
cat /etc/sudoers 2>/dev/null
```

```bash
find /etc/sudoers.d -maxdepth 1 -type f -exec sh -c 'echo "--- $1"; cat "$1"' sh {} \; 2>/dev/null
```

```bash
cat /etc/doas.conf 2>/dev/null
```

```bash
find /etc -maxdepth 2 -iname '*doas*' -type f -exec sh -c 'echo "--- $1"; cat "$1"' sh {} \; 2>/dev/null
```
