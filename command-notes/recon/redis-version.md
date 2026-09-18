# Redis · Version & Configuration

Run from Kali. Replace uppercase values such as DOMAIN, USERNAME, COMMUNITY, SHARE and PATH when present. Commands are alternatives; paste the useful output into this box.

## redis-cli · server information

```bash
redis-cli -h {{target}} -p {{port}} INFO server
```

## Nmap

```bash
{{nmap}} -n -Pn {{transport}} -sV -p {{port}} --script redis-info {{target}}
```
