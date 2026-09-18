# NFS · Access & Permissions

Run from Kali. Replace uppercase values such as DOMAIN, USERNAME, COMMUNITY, SHARE and PATH when present. Commands are alternatives; paste the useful output into this box.

Replace EXPORT with an advertised export. Mount only at an unused local mountpoint; unmount after inspection with sudo umount /mnt/aeros-nfs. Adjust the NFS version if the server requires it.

## Nmap · exposed file attributes

```bash
{{nmap}} -n -Pn {{transport}} -sV -p {{port}} --script nfs-ls {{target}}
```

## mount · read-only NFSv3 inspection

```bash
sudo mkdir -p /mnt/aeros-nfs && sudo mount -t nfs -o ro,nolock,vers=3,port={{port}} {{nfs_export}} /mnt/aeros-nfs
```

## ls · numeric ownership on the mounted export

```bash
ls -lan /mnt/aeros-nfs
```
