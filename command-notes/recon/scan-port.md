# Port Scan

Run from Kali. Replace uppercase values such as DOMAIN, USERNAME, COMMUNITY, SHARE and PATH when present. Commands are alternatives; paste the useful output into this box.

## Nmap · all TCP ports

```bash
{{nmap_tcp}} -n -Pn -sT -p- --open {{target}}
```

## RustScan · discover TCP ports, then identify services

```bash
rustscan -a {{target}} --ulimit 5000 -- -n -Pn -sV
```
