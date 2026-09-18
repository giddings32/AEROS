# MSSQL · Files / Loot

Run from Kali. Replace uppercase values such as DOMAIN, USERNAME, COMMUNITY, SHARE and PATH when present. Commands are alternatives; paste the useful output into this box.

The Impacket command opens an interactive SQL session. Use SELECT queries to inspect the relevant data.

## sqlcmd · database file paths

```bash
sqlcmd -S {{mssql_server}} -U USERNAME -C -Q 'SELECT DB_NAME(database_id) AS db_name, physical_name FROM sys.master_files;'
```

## Impacket · inspect a recorded database

```bash
impacket-mssqlclient {{sql_target}} -port {{port}}
```
