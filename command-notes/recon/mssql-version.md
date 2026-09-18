# MSSQL · Version & Configuration

Run from Kali. Replace uppercase values such as DOMAIN, USERNAME, COMMUNITY, SHARE and PATH when present. Commands are alternatives; paste the useful output into this box.

## Nmap

```bash
{{nmap}} -n -Pn {{transport}} -sV -p {{port}} --script ms-sql-info {{target}}
```

## sqlcmd

```bash
sqlcmd -S {{mssql_server}} -U USERNAME -C -Q 'SELECT @@VERSION;'
```
