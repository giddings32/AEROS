# LDAP · Directory Information

Run from Kali. Replace uppercase values such as DOMAIN, USERNAME, COMMUNITY, SHARE and PATH when present. Commands are alternatives; paste the useful output into this box.

## ldapsearch · anonymous RootDSE

```bash
ldapsearch -LLL -x -H {{ldap_url}} -s base -b '' namingContexts defaultNamingContext dnsHostName supportedLDAPVersion
```

## Nmap · RootDSE

```bash
{{nmap}} -n -Pn {{transport}} -sV -p {{port}} --script ldap-rootdse {{target}}
```
