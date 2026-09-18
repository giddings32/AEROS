# Interesting Files / Credentials

Config files, history files, keys, backups, database creds, web configs, and loot paths.

## Linux

```bash
find /home /root /var/www /opt -type f 2>/dev/null
```

```bash
find / -name '*pass*' -o -name '*cred*' -o -name '*.bak' 2>/dev/null
```
