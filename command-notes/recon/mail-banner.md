# MAIL · Banner & Capabilities

Run from Kali. Replace uppercase values such as DOMAIN, USERNAME, COMMUNITY, SHARE and PATH when present. Commands are alternatives; paste the useful output into this box.

## Nmap · SMTP, IMAP or POP3 capabilities

```bash
{{nmap}} -n -Pn {{transport}} -sV -p {{port}} --script smtp-commands,imap-capabilities,pop3-capabilities {{target}}
```

## curl · protocol dialogue

```bash
curl -k -v --connect-timeout 5 {{mail_url}}
```

## OpenSSL · TLS or STARTTLS dialogue

```bash
openssl s_client -connect {{target_port}} {{tls_options}} -showcerts
```
