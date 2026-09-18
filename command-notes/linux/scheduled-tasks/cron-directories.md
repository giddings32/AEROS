# Cron Directories

## Linux

```bash
find /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.monthly /etc/cron.weekly -mindepth 1 -maxdepth 1 -print 2>/dev/null | sort
```
