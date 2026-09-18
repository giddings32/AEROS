# UDP Scan

Run from Kali. Replace uppercase values such as DOMAIN, USERNAME, COMMUNITY, SHARE and PATH when present. Commands are alternatives; paste the useful output into this box.

Unicornscan is an optional IPv4 tool. An open|filtered UDP result is not confirmation that a port is open.

## Nmap · common UDP ports

```bash
{{nmap_udp}} -n -Pn -sU --top-ports 100 --reason {{target}}
```

## Nmap · service probes on common UDP ports

```bash
{{nmap_udp}} -n -Pn -sU -sV --top-ports 100 {{target}}
```

## Unicornscan · IPv4 UDP discovery

```bash
sudo unicornscan -mU -I {{target}}:1-65535
```
