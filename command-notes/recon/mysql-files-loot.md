# MySQL · Files / Loot

Run from Kali. Replace uppercase values such as DOMAIN, USERNAME, COMMUNITY, SHARE and PATH when present. Commands are alternatives; paste the useful output into this box.

## mysql · configured paths

```bash
mysql -h {{target}} -P {{port}} -u USERNAME -p -e "SHOW VARIABLES WHERE Variable_name IN ('datadir','secure_file_priv','log_error');"
```

## mysqladmin · available server variables

```bash
mysqladmin -h {{target}} -P {{port}} -u USERNAME -p variables
```
