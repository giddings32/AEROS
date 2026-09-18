# Kerberos · Ticket / Account Findings

Run from Kali. Replace uppercase values such as DOMAIN, USERNAME, COMMUNITY, SHARE and PATH when present. Commands are alternatives; paste the useful output into this box.

These domain-controller workflows use standard Kerberos/LDAP ports. Replace DOMAIN and USERS_FILE; the authenticated command prompts for a password.

## Impacket · accounts without preauthentication

```bash
impacket-GetNPUsers 'DOMAIN/' -dc-ip {{target}} -usersfile USERS_FILE -no-pass
```

## Impacket · service principal inventory with a known account

```bash
impacket-GetUserSPNs 'DOMAIN/USERNAME' -dc-ip {{target}}
```
