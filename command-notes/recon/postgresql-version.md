# PostgreSQL · Version & Configuration

Run from Kali. Replace uppercase values such as DOMAIN, USERNAME, COMMUNITY, SHARE and PATH when present. Commands are alternatives; paste the useful output into this box.

## pg_isready · server response

```bash
pg_isready -h {{target}} -p {{port}} -t 5
```

## psql · version

```bash
psql {{postgres_conn}} -X -c 'SELECT version();'
```
