# SMB · Server & Security Settings

Run from Kali. Replace uppercase values such as DOMAIN, USERNAME, COMMUNITY, SHARE and PATH when present. Commands are alternatives; paste the useful output into this box.

## Nmap · dialects, signing and OS clues

```bash
{{nmap}} -n -Pn {{transport}} -sV -p {{port}} --script smb-protocols,smb2-security-mode,smb-os-discovery {{target}}
```

## rpcclient · server and domain information

```bash
rpcclient -U '' -N -p {{port}} {{target}} -c 'srvinfo; querydominfo'
```
