# MySQL · Version & Configuration

Run from Kali. Replace uppercase values such as DOMAIN, USERNAME, COMMUNITY, SHARE and PATH when present. Commands are alternatives; paste the useful output into this box.

## Nmap

```bash
{{nmap}} -n -Pn {{transport}} -sV -p {{port}} --script mysql-info {{target}}
```

## mysql

```bash
mysql -h {{target}} -P {{port}} -u USERNAME -p -e 'SELECT VERSION(), @@hostname, @@version_compile_os;'
```
