# DNS · Records

Run from Kali. Replace uppercase values such as DOMAIN, USERNAME, COMMUNITY, SHARE and PATH when present. Commands are alternatives; paste the useful output into this box.

## dig · SOA and nameserver records

```bash
dig @{{target}} -p {{port}} DOMAIN SOA +noall +answer && dig @{{target}} -p {{port}} DOMAIN NS +noall +answer
```

## nslookup · address records

```bash
nslookup -port={{port}} DOMAIN {{target}}
```
