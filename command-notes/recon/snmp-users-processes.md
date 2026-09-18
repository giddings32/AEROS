# SNMP · Users, Processes & Interfaces

Run from Kali. Replace uppercase values such as DOMAIN, USERNAME, COMMUNITY, SHARE and PATH when present. Commands are alternatives; paste the useful output into this box.

## snmpwalk · running software

```bash
snmpwalk -v2c -c COMMUNITY -t 2 -r 1 {{snmp_target}} 1.3.6.1.2.1.25.4.2
```

## snmpwalk · interfaces

```bash
snmpwalk -v2c -c COMMUNITY -t 2 -r 1 {{snmp_target}} 1.3.6.1.2.1.2
```

## Nmap · processes and interfaces

```bash
{{nmap}} -n -Pn {{transport}} -sV -p {{port}} --script snmp-processes,snmp-interfaces --script-args creds.snmp=COMMUNITY {{target}}
```
