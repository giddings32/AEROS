# SSH · Banner & Host Keys

Run from Kali. Replace uppercase values such as DOMAIN, USERNAME, COMMUNITY, SHARE and PATH when present. Commands are alternatives; paste the useful output into this box.

## ssh-keyscan · advertised keys

```bash
ssh-keyscan -T 5 -p {{port}} {{target}}
```

## Nmap · keys and algorithms

```bash
{{nmap}} -n -Pn {{transport}} -sV -p {{port}} --script ssh-hostkey,ssh2-enum-algos {{target}}
```
