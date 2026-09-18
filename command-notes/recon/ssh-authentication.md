# SSH · Authentication Findings

Run from Kali. Replace uppercase values such as DOMAIN, USERNAME, COMMUNITY, SHARE and PATH when present. Commands are alternatives; paste the useful output into this box.

## SSH · inspect supported authentication without a password attempt

```bash
ssh -v -o BatchMode=yes -o PreferredAuthentications=none -o ConnectTimeout=5 -p {{port}} {{ssh_target}}
```

## Nmap · methods for a selected account

```bash
{{nmap}} -n -Pn {{transport}} -sV -p {{port}} --script ssh-auth-methods --script-args ssh.user=USERNAME {{target}}
```
