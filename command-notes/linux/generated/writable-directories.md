# Writable Directories — {{entity}}

## Recommended → Fallback

```bash
find / -path '{{home}}' -prune -o -writable -type d -print 2>/dev/null
```

```bash
find /tmp /var/tmp /dev/shm /opt /var/www /srv /etc /usr/local -writable -type d -print 2>/dev/null
```

```bash
find / -path '{{home}}' -prune -o -perm -0002 -type d -print 2>/dev/null
```
