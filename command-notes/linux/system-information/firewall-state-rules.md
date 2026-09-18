# Firewall State / Rules

iptables/nftables/ufw/firewalld state, local firewall profiles, and saved rule files.

## Linux

```bash
iptables -S 2>/dev/null
```

```bash
iptables -L -n -v 2>/dev/null
```

```bash
ip6tables -S 2>/dev/null
```

```bash
nft list ruleset 2>/dev/null
```

```bash
ufw status verbose 2>/dev/null
```

```bash
firewall-cmd --state 2>/dev/null
```

```bash
firewall-cmd --list-all 2>/dev/null
```

```bash
cat /etc/iptables 2>/dev/null
```

```bash
cat /etc/iptables/rules.v4 2>/dev/null
```

```bash
cat /etc/iptables/rules.v6 2>/dev/null
```
