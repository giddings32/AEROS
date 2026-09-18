# MongoDB · Databases, Tables & Data

Run from Kali. Replace uppercase values such as DOMAIN, USERNAME, COMMUNITY, SHARE and PATH when present. Commands are alternatives; paste the useful output into this box.

## mongosh · database names

```bash
mongosh {{mongo_uri}} --quiet --eval 'JSON.stringify(db.adminCommand({listDatabases:1,nameOnly:true}), null, 2)'
```

## Nmap · database inventory

```bash
{{nmap}} -n -Pn {{transport}} -sV -p {{port}} --script mongodb-databases {{target}}
```
