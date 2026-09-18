# FTP · Banner & Capabilities

Run from Kali. Replace uppercase values such as DOMAIN, USERNAME, COMMUNITY, SHARE and PATH when present. Commands are alternatives; paste the useful output into this box.

## Nmap · system and anonymous access

```bash
{{nmap}} -n -Pn {{transport}} -sV -p {{port}} --script ftp-syst,ftp-anon {{target}}
```

## curl · verbose protocol exchange

```bash
curl -k -v --connect-timeout 5 {{ftp_url}}
```
