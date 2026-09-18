# PostgreSQL · Databases, Tables & Data

Run from Kali. Replace uppercase values such as DOMAIN, USERNAME, COMMUNITY, SHARE and PATH when present. Commands are alternatives; paste the useful output into this box.

Replace dbname=postgres with the database being inspected.

## psql · database and table names

```bash
psql {{postgres_conn}} -X -c 'SELECT datname FROM pg_database; SELECT table_schema, table_name FROM information_schema.tables;'
```

## pg_dump · schema only

```bash
pg_dump --dbname={{postgres_conn}} --schema-only --no-owner --no-privileges
```
