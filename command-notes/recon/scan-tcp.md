# Nmap Service Scan

Run from Kali. Replace uppercase values such as DOMAIN, USERNAME, COMMUNITY, SHARE and PATH when present. Commands are alternatives; paste the useful output into this box.

OPEN_PORTS is replaced by confirmed open TCP ports from this host. If no ports have been found yet, replace it with a comma-separated list.

## Nmap · versions and default scripts on open TCP ports

```bash
{{nmap_tcp}} -n -Pn -sT -sV -sC -p {{open_ports}} {{target}}
```

## Nmap · deeper version probes

```bash
{{nmap_tcp}} -n -Pn -sT -sV --version-all --reason -p {{open_ports}} {{target}}
```

## RustScan · repeat discovery with Nmap service detection

```bash
rustscan -a {{target}} --ulimit 5000 -- -n -Pn -sV -sC
```
