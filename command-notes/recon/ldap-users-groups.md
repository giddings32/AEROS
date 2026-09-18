# LDAP · Users & Groups

Run from Kali. Replace uppercase values such as DOMAIN, USERNAME, COMMUNITY, SHARE and PATH when present. Commands are alternatives; paste the useful output into this box.

Use the naming context discovered in Directory Information. In Nmap script arguments, quote a DN containing commas as shown in the Nmap NSE argument syntax, or use ldapsearch for an explicit base.

## ldapsearch · account and group attributes

```bash
ldapsearch -LLL -x -H {{ldap_url}} -b 'DC=DOMAIN,DC=TLD' '(|(objectClass=person)(objectClass=group))' sAMAccountName memberOf member description
```

## Nmap · bounded directory search

```bash
{{nmap}} -n -Pn {{transport}} -sV -p {{port}} --script ldap-search --script-args 'ldap.base="DC=DOMAIN,DC=TLD",ldap.maxobjects=100' {{target}}
```
