# DNS · Zone Transfer

Run from Kali. Replace uppercase values such as DOMAIN, USERNAME, COMMUNITY, SHARE and PATH when present. Commands are alternatives; paste the useful output into this box.

## dig · full zone transfer

```bash
dig @{{target}} -p {{port}} DOMAIN AXFR
```

## Nmap · zone transfer

```bash
{{nmap}} -n -Pn {{transport}} -sV -p {{port}} --script dns-zone-transfer --script-args dns-zone-transfer.domain=DOMAIN {{target}}
```
