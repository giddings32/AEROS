# SMB · Users & Groups

Run from Kali. Replace uppercase values such as DOMAIN, USERNAME, COMMUNITY, SHARE and PATH when present. Commands are alternatives; paste the useful output into this box.

## rpcclient · anonymous user and group listing

```bash
rpcclient -U '' -N -p {{port}} {{target}} -c 'enumdomusers; enumdomgroups'
```

## Nmap · users and groups

```bash
{{nmap}} -n -Pn {{transport}} -sV -p {{port}} --script smb-enum-users,smb-enum-groups {{target}}
```
