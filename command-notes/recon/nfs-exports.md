# NFS · Exports

Run from Kali. Replace uppercase values such as DOMAIN, USERNAME, COMMUNITY, SHARE and PATH when present. Commands are alternatives; paste the useful output into this box.

showmount uses the server RPC mount service; Nmap begins with the selected NFS port.

## showmount · advertised exports

```bash
showmount -e {{target}}
```

## Nmap · export and filesystem information

```bash
{{nmap}} -n -Pn {{transport}} -sV -p {{port}} --script nfs-showmount,nfs-statfs {{target}}
```
