# SNMP · Walk

Run from Kali. Replace uppercase values such as DOMAIN, USERNAME, COMMUNITY, SHARE and PATH when present. Commands are alternatives; paste the useful output into this box.

## snmpwalk · system subtree

```bash
snmpwalk -v2c -c COMMUNITY -t 2 -r 1 {{snmp_target}} 1.3.6.1.2.1.1
```

## snmpbulkwalk · host resources

```bash
snmpbulkwalk -v2c -c COMMUNITY -t 2 -r 1 {{snmp_target}} 1.3.6.1.2.1.25
```

## Nmap · system description

```bash
{{nmap}} -n -Pn {{transport}} -sV -p {{port}} --script snmp-sysdescr --script-args creds.snmp=COMMUNITY {{target}}
```
