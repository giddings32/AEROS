# VNC · Access Findings

Run from Kali. Replace uppercase values such as DOMAIN, USERNAME, COMMUNITY, SHARE and PATH when present. Commands are alternatives; paste the useful output into this box.

## Nmap · offered authentication types

```bash
{{nmap}} -n -Pn {{transport}} -sV -p {{port}} --script vnc-info {{target}}
```

## TigerVNC · interactive connection

```bash
vncviewer {{vnc_target}}
```
