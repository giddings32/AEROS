# RDP · Service Information

Run from Kali. Replace uppercase values such as DOMAIN, USERNAME, COMMUNITY, SHARE and PATH when present. Commands are alternatives; paste the useful output into this box.

## Nmap · identity and encryption

```bash
{{nmap}} -n -Pn {{transport}} -sV -p {{port}} --script rdp-ntlm-info,rdp-enum-encryption {{target}}
```

## FreeRDP · verbose connection diagnostics

```bash
xfreerdp3 {{rdp_target}} /u:USERNAME /cert:ignore /auth-only /log-level:INFO
```
