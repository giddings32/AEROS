# LDAP · Access & Interesting Attributes

Run from Kali. Replace uppercase values such as DOMAIN, USERNAME, COMMUNITY, SHARE and PATH when present. Commands are alternatives; paste the useful output into this box.

## ldapwhoami · authenticated bind, password prompt

```bash
ldapwhoami -x -H {{ldap_url}} -D 'USERNAME@DOMAIN' -W
```

## ldapsearch · authenticated account attributes

```bash
ldapsearch -LLL -x -H {{ldap_url}} -D 'USERNAME@DOMAIN' -W -b 'DC=DOMAIN,DC=TLD' '(sAMAccountName=USERNAME)' memberOf userAccountControl servicePrincipalName description
```
