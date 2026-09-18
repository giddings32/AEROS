# Kerberos · Principals & Domain

Run from Kali. Replace uppercase values such as DOMAIN, USERNAME, COMMUNITY, SHARE and PATH when present. Commands are alternatives; paste the useful output into this box.

Kerbrute uses the domain controller on standard Kerberos port 88. Nmap targets the selected port. USERS_FILE is a local candidate username list.

## Nmap · candidate principal enumeration

```bash
{{nmap}} -n -Pn {{transport}} -sV -p {{port}} --script krb5-enum-users --script-args krb5-enum-users.realm=DOMAIN,userdb=USERS_FILE {{target}}
```

## Kerbrute · candidate users on the domain controller

```bash
kerbrute userenum --dc {{target}} -d DOMAIN USERS_FILE
```
