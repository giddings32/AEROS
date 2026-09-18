# Kerberos · Notes

Run from Kali. Replace uppercase values such as DOMAIN, USERNAME, COMMUNITY, SHARE and PATH when present. Commands are alternatives; paste the useful output into this box.

klist reads the local Kali credential cache; it does not query the selected host.

## Nmap · confirm the selected service

```bash
{{nmap}} -n -Pn {{transport}} -sV -p {{port}} --script krb5-enum-users --script-args krb5-enum-users.realm=DOMAIN,userdb=USERS_FILE {{target}}
```

## klist · inspect your local ticket cache

```bash
klist -e
```
