# SSH · Notes / Loot

Run from Kali. Replace uppercase values such as DOMAIN, USERNAME, COMMUNITY, SHARE and PATH when present. Commands are alternatives; paste the useful output into this box.

The SFTP command opens an interactive session and prompts for authentication.

## SSH · verbose connection diagnostics

```bash
ssh -vv -o BatchMode=yes -o PreferredAuthentications=none -o ConnectTimeout=5 -p {{port}} {{ssh_target}}
```

## sftp · inspect files with a known account

```bash
sftp -P {{port}} {{ssh_target}}
```
