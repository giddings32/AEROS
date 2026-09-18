# MAIL · Notes / Loot

Run from Kali. Replace uppercase values such as DOMAIN, USERNAME, COMMUNITY, SHARE and PATH when present. Commands are alternatives; paste the useful output into this box.

## curl · inspect protocol responses

```bash
curl -k -v --request {{mail_request}} {{mail_url}}
```

## OpenSSL · certificate and TLS details

```bash
openssl s_client -connect {{target_port}} {{tls_options}} -showcerts
```
