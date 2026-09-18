# MongoDB · Access & Privileges

Run from Kali. Replace uppercase values such as DOMAIN, USERNAME, COMMUNITY, SHARE and PATH when present. Commands are alternatives; paste the useful output into this box.

For a known account, add --username USERNAME --authenticationDatabase admin --password to mongosh; --password prompts without putting the secret in the command.

## mongosh · current authentication state

```bash
mongosh {{mongo_uri}} --quiet --eval 'JSON.stringify(db.runCommand({connectionStatus:1,showPrivileges:true}), null, 2)'
```

## Nmap · anonymous server information

```bash
{{nmap}} -n -Pn {{transport}} -sV -p {{port}} --script mongodb-info {{target}}
```
