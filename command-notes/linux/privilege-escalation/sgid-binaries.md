# SGID Binaries

Setgid binaries, custom group-execution binaries, and unusual group-owned paths.

## Linux

```bash
find / -perm -2000 -type f -ls 2>/dev/null
```

```bash
find / -perm -g=s -type f -ls 2>/dev/null
```
