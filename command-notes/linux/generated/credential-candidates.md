# Credential Candidates — {{entity}}

## Recommended

```bash
find {{home}} /var/www /opt /srv -xdev -maxdepth 6 -type f   \( -iname '*.env' -o -iname '*.ini' -o -iname '*.conf' -o -iname '*.cnf' -o -iname '*.cfg' -o -iname '*.yaml' -o -iname '*.yml' -o -iname '*.properties' -o -iname '*.toml' -o -iname '*.json' -o -iname '*.xml' -o -iname '*.php' \)   -readable -print0 2>/dev/null | xargs -0 grep -IlEi '(pass(word|wd)?|secret|api[_-]?key|access[_-]?token|auth[_-]?token|BEGIN [A-Z ]*PRIVATE KEY)' 2>/dev/null
```

## Fallback

```bash
grep -RIlEi '(pass(word|wd)?|secret|api[_-]?key|access[_-]?token|auth[_-]?token|BEGIN [A-Z ]*PRIVATE KEY)' {{home}} /var/www /opt /srv 2>/dev/null
```
