# FTP · Anonymous / Account Access

Run from Kali. Replace uppercase values such as DOMAIN, USERNAME, COMMUNITY, SHARE and PATH when present. Commands are alternatives; paste the useful output into this box.

## curl · anonymous directory listing

```bash
curl -k -sS --list-only {{ftp_url}}
```

## Nmap · anonymous login and permissions

```bash
{{nmap}} -n -Pn {{transport}} -sV -p {{port}} --script ftp-anon {{target}}
```

## curl · known account, password prompt

```bash
curl -k -u USERNAME --list-only {{ftp_url}}
```
