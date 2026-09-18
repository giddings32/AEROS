# Redis · Databases, Tables & Data

Run from Kali. Replace uppercase values such as DOMAIN, USERNAME, COMMUNITY, SHARE and PATH when present. Commands are alternatives; paste the useful output into this box.

SCAN returns a cursor; repeat with that cursor to continue. Select the relevant database with redis-cli -n NUMBER when needed.

## redis-cli · keyspace and sampled key names

```bash
redis-cli -h {{target}} -p {{port}} INFO keyspace && redis-cli -h {{target}} -p {{port}} SCAN 0 COUNT 100
```

## Nmap · database statistics

```bash
{{nmap}} -n -Pn {{transport}} -sV -p {{port}} --script redis-info {{target}}
```
