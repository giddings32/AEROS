# Custom Service Output

Run from Kali. Replace uppercase values such as DOMAIN, USERNAME, COMMUNITY, SHARE and PATH when present. Commands are alternatives; paste the useful output into this box.

For an unrecognized protocol, identify it first and edit this Command Note to add tool-specific one-liners. A UDP listener may require a valid request before replying.

## Nmap · full version probes

```bash
{{nmap}} -n -Pn {{transport}} -sV --version-all -p {{port}} {{target}}
```

## Netcat · protocol response

```bash
timeout 5 nc {{nc_udp}} -nv -w 3 {{target}} {{port}}
```
