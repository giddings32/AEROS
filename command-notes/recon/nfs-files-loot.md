# NFS · Files / Loot

Run from Kali. Replace uppercase values such as DOMAIN, USERNAME, COMMUNITY, SHARE and PATH when present. Commands are alternatives; paste the useful output into this box.

The find command requires the read-only mount from Access & Permissions.

## Nmap · remote file listing

```bash
{{nmap}} -n -Pn {{transport}} -sV -p {{port}} --script nfs-ls --script-args ls.maxfiles=100 {{target}}
```

## find · readable files on an already mounted export

```bash
find /mnt/aeros-nfs -maxdepth 3 -type f -readable -ls
```
