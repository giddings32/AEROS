# SNMP · Community / Access

Run from Kali. Replace uppercase values such as DOMAIN, USERNAME, COMMUNITY, SHARE and PATH when present. Commands are alternatives; paste the useful output into this box.

## snmpget · test a recorded community

```bash
snmpget -v2c -c COMMUNITY -t 2 -r 1 {{snmp_target}} 1.3.6.1.2.1.1.1.0
```

## Nmap · SNMPv3 engine information

```bash
{{nmap}} -n -Pn {{transport}} -sV -p {{port}} --script snmp-info {{target}}
```
