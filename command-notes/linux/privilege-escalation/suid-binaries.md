# SUID Binaries

Setuid binaries, custom binaries, and Binary Context SUID candidates.

## Linux

```bash
find / -perm -4000 -type f -ls 2>/dev/null
```

```bash
find / -perm -u=s -type f -ls 2>/dev/null
```
