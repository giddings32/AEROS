# Redis · Access & Privileges

Run from Kali. Replace uppercase values such as DOMAIN, USERNAME, COMMUNITY, SHARE and PATH when present. Commands are alternatives; paste the useful output into this box.

## redis-cli · current ACL identity

```bash
redis-cli -h {{target}} -p {{port}} ACL WHOAMI
```

## redis-cli · password prompt for a known account

```bash
redis-cli -h {{target}} -p {{port}} --user USERNAME --askpass ACL WHOAMI
```

## Nmap · unauthenticated information

```bash
{{nmap}} -n -Pn {{transport}} -sV -p {{port}} --script redis-info {{target}}
```
