# MSSQL · Databases, Tables & Data

Run from Kali. Replace uppercase values such as DOMAIN, USERNAME, COMMUNITY, SHARE and PATH when present. Commands are alternatives; paste the useful output into this box.

## sqlcmd · accessible databases

```bash
sqlcmd -S {{mssql_server}} -U USERNAME -C -Q 'SELECT name FROM sys.databases;'
```

## Impacket · interactive query session

```bash
impacket-mssqlclient {{sql_target}} -port {{port}}
```
