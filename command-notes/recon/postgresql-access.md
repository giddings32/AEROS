# PostgreSQL · Access & Privileges

Run from Kali. Replace uppercase values such as DOMAIN, USERNAME, COMMUNITY, SHARE and PATH when present. Commands are alternatives; paste the useful output into this box.

## psql · identity and roles

```bash
psql {{postgres_conn}} -X -c 'SELECT current_user, session_user; SELECT rolname, rolsuper, rolcanlogin FROM pg_roles;'
```

## OpenSSL · PostgreSQL TLS negotiation

```bash
openssl s_client -starttls postgres -connect {{target_port}} -showcerts
```
