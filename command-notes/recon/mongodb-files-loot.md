# MongoDB · Files / Loot

Run from Kali. Replace uppercase values such as DOMAIN, USERNAME, COMMUNITY, SHARE and PATH when present. Commands are alternatives; paste the useful output into this box.

Replace DATABASE and COLLECTION with names already found; startup options require sufficient privileges.

## mongosh · startup settings and paths

```bash
mongosh {{mongo_uri}} --quiet --eval 'JSON.stringify(db.adminCommand({getCmdLineOpts:1}), null, 2)'
```

## mongoexport · selected collection to standard output

```bash
mongoexport --uri={{mongo_uri}} --db=DATABASE --collection=COLLECTION --jsonArray
```
