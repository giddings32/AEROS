# MAIL · Users & Access

Run from Kali. Replace uppercase values such as DOMAIN, USERNAME, COMMUNITY, SHARE and PATH when present. Commands are alternatives; paste the useful output into this box.

## curl · known account, password prompt

```bash
curl -k -v -u USERNAME --request {{mail_request}} {{mail_url}}
```

## Nmap · advertised authentication capabilities

```bash
{{nmap}} -n -Pn {{transport}} -sV -p {{port}} --script smtp-commands,imap-capabilities,pop3-capabilities {{target}}
```
