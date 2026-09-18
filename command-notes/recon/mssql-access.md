# MSSQL · Access & Privileges

Run from Kali. Replace uppercase values such as DOMAIN, USERNAME, COMMUNITY, SHARE and PATH when present. Commands are alternatives; paste the useful output into this box.

## Impacket · interactive SQL client

```bash
impacket-mssqlclient {{sql_target}} -port {{port}}
```

## sqlcmd · identity and server role

```bash
sqlcmd -S {{mssql_server}} -U USERNAME -C -Q "SELECT SYSTEM_USER, ORIGINAL_LOGIN(), IS_SRVROLEMEMBER('sysadmin');"
```
