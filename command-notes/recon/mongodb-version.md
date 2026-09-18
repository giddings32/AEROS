# MongoDB · Version & Configuration

Run from Kali. Replace uppercase values such as DOMAIN, USERNAME, COMMUNITY, SHARE and PATH when present. Commands are alternatives; paste the useful output into this box.

## mongosh

```bash
mongosh {{mongo_uri}} --quiet --eval 'JSON.stringify(db.adminCommand({buildInfo:1}), null, 2)'
```

## Nmap

```bash
{{nmap}} -n -Pn {{transport}} -sV -p {{port}} --script mongodb-info {{target}}
```
