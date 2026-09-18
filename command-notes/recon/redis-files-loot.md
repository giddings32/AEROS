# Redis · Files / Loot

Run from Kali. Replace uppercase values such as DOMAIN, USERNAME, COMMUNITY, SHARE and PATH when present. Commands are alternatives; paste the useful output into this box.

## redis-cli · persistence directory and filename

```bash
redis-cli -h {{target}} -p {{port}} CONFIG GET dir && redis-cli -h {{target}} -p {{port}} CONFIG GET dbfilename
```

## Nmap · persistence and server details

```bash
{{nmap}} -n -Pn {{transport}} -sV -p {{port}} --script redis-info {{target}}
```
