# PostgreSQL · Files / Loot

Run from Kali. Replace uppercase values such as DOMAIN, USERNAME, COMMUNITY, SHARE and PATH when present. Commands are alternatives; paste the useful output into this box.

Some settings require elevated database privileges. Replace SCHEMA.TABLE with a table you have identified.

## psql · configured file paths

```bash
psql {{postgres_conn}} -X -c 'SHOW data_directory; SHOW config_file; SHOW hba_file;'
```

## pg_dump · selected table data to standard output

```bash
pg_dump --dbname={{postgres_conn}} --data-only --table=SCHEMA.TABLE --no-owner --no-privileges
```
