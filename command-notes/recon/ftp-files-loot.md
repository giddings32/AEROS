# FTP · Files & Permissions

Run from Kali. Replace uppercase values such as DOMAIN, USERNAME, COMMUNITY, SHARE and PATH when present. Commands are alternatives; paste the useful output into this box.

## curl · inspect a discovered file

```bash
curl -k -sS {{ftp_path}}
```

## Nmap · anonymous listing with permission details

```bash
{{nmap}} -n -Pn {{transport}} -sV -p {{port}} --script ftp-anon --script-args ftp-anon.maxlist=100 {{target}}
```
