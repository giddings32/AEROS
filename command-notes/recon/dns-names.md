# DNS · Hostnames & Subdomains

Run from Kali. Replace uppercase values such as DOMAIN, USERNAME, COMMUNITY, SHARE and PATH when present. Commands are alternatives; paste the useful output into this box.

## dig · resolve a discovered name

```bash
dig @{{target}} -p {{port}} HOST.DOMAIN A +noall +answer
```

## nslookup · mail exchanger names

```bash
nslookup -port={{port}} -type=MX DOMAIN {{target}}
```
