# MySQL · Databases, Tables & Data

Run from Kali. Replace uppercase values such as DOMAIN, USERNAME, COMMUNITY, SHARE and PATH when present. Commands are alternatives; paste the useful output into this box.

## mysqlshow · database list

```bash
mysqlshow -h {{target}} -P {{port}} -u USERNAME -p
```

## mysql · schemas and tables

```bash
mysql -h {{target}} -P {{port}} -u USERNAME -p -e 'SELECT table_schema, table_name FROM information_schema.tables;'
```
