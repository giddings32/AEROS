# TLS · Certificates & Configuration

Run from Kali. Replace uppercase values such as DOMAIN, USERNAME, COMMUNITY, SHARE and PATH when present. Commands are alternatives; paste the useful output into this box.

## OpenSSL · chain and negotiated TLS

```bash
openssl s_client -connect {{target_port}} {{tls_options}} -showcerts
```

## Nmap · certificate and cipher suites

```bash
{{nmap}} -n -Pn {{transport}} -sV -p {{port}} --script ssl-cert,ssl-enum-ciphers {{target}}
```
