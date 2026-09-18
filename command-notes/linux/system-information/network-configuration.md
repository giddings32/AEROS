# Network Configuration

Interfaces, IPs, DNS, gateways, hostname, hosts file, and resolver config.

## Linux

<div class="line-title bold-text">Interfaces / IPs:</div>

```bash
ip addr
```

```bash
ifconfig -a 2>/dev/null
```

```bash
hostname -I 2>/dev/null
```

<div class="line-title bold-text">Routes / DNS / host mappings:</div>

```bash
ip route
```

```bash
cat /etc/resolv.conf 2>/dev/null
```

```bash
cat /etc/hosts 2>/dev/null
```
