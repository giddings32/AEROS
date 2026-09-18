# SMB · Shares & Access

Run from Kali. Replace uppercase values such as DOMAIN, USERNAME, COMMUNITY, SHARE and PATH when present. Commands are alternatives; paste the useful output into this box.

## smbclient · anonymous share list

```bash
smbclient -L {{target}} -p {{port}} -N
```

## smbmap · anonymous share permissions

```bash
smbmap -H {{target}} -P {{port}} -u '' -p ''
```

## Nmap · share enumeration

```bash
{{nmap}} -n -Pn {{transport}} -sV -p {{port}} --script smb-enum-shares {{target}}
```
