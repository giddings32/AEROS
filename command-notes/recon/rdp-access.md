# RDP · Access Findings

Run from Kali. Replace uppercase values such as DOMAIN, USERNAME, COMMUNITY, SHARE and PATH when present. Commands are alternatives; paste the useful output into this box.

On installations with FreeRDP 2, use xfreerdp instead of xfreerdp3.

## FreeRDP · authentication only, password prompt

```bash
xfreerdp3 {{rdp_target}} /u:USERNAME /cert:ignore /auth-only
```

## Nmap · authentication layer and encryption

```bash
{{nmap}} -n -Pn {{transport}} -sV -p {{port}} --script rdp-enum-encryption {{target}}
```
