# Packages / Installed Software

Package/version leads, unusual apps, and targeted software checks. Full package lists can be huge.

## Linux

<div class="line-title bold-text">Full list can be thousands of lines. Paste only if useful:</div>

```bash
dpkg -l 2>/dev/null
```

<div class="line-title bold-text">Usually cleaner for the report builder:</div>

```bash
dpkg -l 2>/dev/null | grep -Ei 'apache|nginx|mysql|maria|postgres|tomcat|java|python|perl|ruby|docker|lxd|backup|agent|ftp|ssh|nfs|samba|redis|jenkins|git|sudo|doas'
```

```bash
rpm -qa 2>/dev/null
```

```bash
apk info 2>/dev/null
```

```bash
find /opt /var/www /srv -maxdepth 3 \( -type f -o -type d \) 2>/dev/null
```
