# MySQL · Access & Privileges

Run from Kali. Replace uppercase values such as DOMAIN, USERNAME, COMMUNITY, SHARE and PATH when present. Commands are alternatives; paste the useful output into this box.

## mysql · current identity and grants

```bash
mysql -h {{target}} -P {{port}} -u USERNAME -p -e 'SELECT USER(), CURRENT_USER(); SHOW GRANTS;'
```

## mysqladmin · confirm authenticated access

```bash
mysqladmin -h {{target}} -P {{port}} -u USERNAME -p status
```
