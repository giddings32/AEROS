const DEFAULT_SERVICES = [
  { key:"ftp",label:"FTP",defaultPort:"21",ports:[21],hint:"Anonymous, upload/write, creds, version" },
  { key:"ssh",label:"SSH",defaultPort:"22",ports:[22],hint:"Banner, creds, RSA keys, password attacks" },
  { key:"smtp",label:"SMTP",defaultPort:"25",ports:[25,587],hint:"VRFY/EXPN, users, phishing/file tricks" },
  { key:"dns",label:"DNS",defaultPort:"53",ports:[53],hint:"Zone transfer, subdomains, hostnames" },
  { key:"http",label:"HTTP",defaultPort:"80",ports:[80,8000,8080,8081,8888],hint:"Fingerprinting, dirs, auth, upload, SQLi" },
  { key:"https",label:"HTTPS",defaultPort:"443",ports:[443,8443],hint:"Same as web, cert/SNI clues" },
  { key:"smb",label:"SMB",defaultPort:"445",ports:[139,445],hint:"Shares, users, anon, signing, relay leads" },
  { key:"rdp",label:"RDP",defaultPort:"3389",ports:[3389],hint:"Remote access, password/hash auth" },
  { key:"winrm",label:"WinRM",defaultPort:"5985",ports:[5985,5986],hint:"Remote shell with creds" },
  { key:"snmp",label:"SNMP",defaultPort:"161",ports:[161],hint:"Community strings, snmpwalk loot" },
  { key:"ldap",label:"LDAP",defaultPort:"389",ports:[389,636],hint:"AD enum, users, domain info" },
  { key:"kerberos",label:"Kerberos",defaultPort:"88",ports:[88],hint:"AS-REP, Kerberoast, AD clues" },
  { key:"mssql",label:"MSSQL",defaultPort:"1433",ports:[1433],hint:"Login, xp_cmdshell, SQLi shell paths" },
  { key:"mysql",label:"MySQL",defaultPort:"3306",ports:[3306],hint:"Login, outfile, creds" },
  { key:"postgresql",label:"PostgreSQL",defaultPort:"5432",ports:[5432],hint:"Login, COPY TO PROGRAM" },
  { key:"vnc",label:"VNC",defaultPort:"5900",ports:[5900,5901],hint:"Password auth, remote GUI" }
];
