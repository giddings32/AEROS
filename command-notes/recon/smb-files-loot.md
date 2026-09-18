# SMB · Files / Loot

Run from Kali. Replace uppercase values such as DOMAIN, USERNAME, COMMUNITY, SHARE and PATH when present. Commands are alternatives; paste the useful output into this box.

Replace SHARE with a discovered share. If authentication is required, use an account you have recorded; smbclient -U USERNAME prompts for its password.

## smbclient · recursively list a share

```bash
smbclient {{smb_share}} -p {{port}} -N -c 'recurse ON; ls'
```

## smbmap · list a selected share

```bash
smbmap -H {{target}} -P {{port}} -u '' -p '' -r SHARE
```
