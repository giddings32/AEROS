# RDP · Notes / Loot

Run from Kali. Replace uppercase values such as DOMAIN, USERNAME, COMMUNITY, SHARE and PATH when present. Commands are alternatives; paste the useful output into this box.

## Nmap · domain and hostname clues

```bash
{{nmap}} -n -Pn {{transport}} -sV -p {{port}} --script rdp-ntlm-info {{target}}
```

## FreeRDP · connection diagnostics

```bash
xfreerdp3 {{rdp_target}} /u:USERNAME /cert:ignore /auth-only /log-level:DEBUG
```
