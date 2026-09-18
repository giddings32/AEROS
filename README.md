# AEROS · My Workspace

Local, single-operator workspace for Kali Linux. Host inputs and outputs are
ordinary files; no database service is required.

## Run on Kali

Install Python's virtual-environment support once:

```sh
sudo apt install python3-venv
bash run-kali.sh
```

Open `http://127.0.0.1:8765/index.html`. The first launch installs the report
libraries into `.venv`; subsequent launches work offline. Run as your regular Kali
user. The server listens only on localhost. Stop it with Ctrl+C.

## Recon workflow

Recon uses the same tabs and paste-card layout as Host Enumeration. Paste Nmap
output into **Port Scan** and **Nmap Service Scan**. Open services create tabs such
as **WEB**, **SMB**, **SSH**, **FTP**, **DNS**, **SNMP**, **LDAP**, **Kerberos**, **NFS**,
mail, databases and remote access. Select a port inside a service tab to work on
that port's outputs independently.

The paste boxes follow the bundled reference-note topics. WEB includes directory
discovery, technologies and headers, virtual hosts, interesting pages and
parameters, and findings/loot. **Command Note** opens short, copyable one-line
commands for multiple tools, filled in with the selected host and port. Use the
same personal-edit and reset controls as Host Enumeration to customize them.
**Add custom box** adds your own named output field and editable Command Note;
TLS/certificate boxes start with OpenSSL and Nmap commands.

Previews automatically highlight useful ports, services, versions, discovered
paths, headers, users and other service details. Manual backtick highlights still
work. Highlighting only changes the preview; saved files and copied output retain
the original text. Discovery misses and closed or uncertain ports stay unhighlighted.

Each Recon paste box has **Remove Auto Highlighting** / **Restore Auto Highlighting**.
Its setting is saved independently for the host, port and box, including custom
boxes and scans. Manual backtick highlights remain active when automatic highlighting
is off; toggling never rewrites the output or creates an empty output folder.

Recognized WhatWeb output emphasizes detected products and versions, redirects,
authentication fields, directory listings, useful paths, hostnames and disclosure
headers. Session-cookie names have subtle emphasis. Feroxbuster result rows emphasize
401/403/500 and redirects, plus authentication/admin/setup/WebDAV and other useful
endpoints. Repeated nested endpoints highlight their common leaf rather than the
whole URL. Routine 200 responses, static assets, response counts and repeated target
IP addresses stay normal. These are enumeration cues, not vulnerability conclusions.

Use **Manage Ports** to correct a service assignment, select **Automatic** to undo
an override, add a verified port, or define a custom service type. Reassigning a
port preserves its outputs. Closed ports and unconfirmed `open|filtered` results
do not generate new tabs or folders. Previously collected output stays available
even when its port is no longer confirmed open. Imported originals remain under
**Imported outputs**.

The Host Workbench, Credentials, Movement, Attack Map, Investigations & Evidence,
Web App Review and Progress pages have been removed. Existing collected records
remain available to the remaining Notes, Host Enumeration and report workflows.

## Network context and tunneling notes

In **Host Enumeration > System Information > OS & Network**, Network Configuration
recognizes Linux `ip addr`, `ip -br addr` and common `ifconfig` output. It matches
the host IP to an interface and highlights additional addresses/subnets, with quieter
emphasis for virtual/down interfaces or another interface on the same subnet.
Loopback and link-local addresses remain quiet. Use **Working interface** to correct
the match when NAT, an existing tunnel or missing output makes it uncertain.
The existing **Routes** field adds observed routes; these do not confirm reachability.

**Listening Ports** recognizes `ss` and `netstat` rows, including IPv6, mapped IPv4,
zone identifiers and process names. It distinguishes loopback-only, all-interface
and address-bound listeners, groups repeated established peers and relates their
local addresses to interfaces. Local DNS resolvers receive subtle emphasis. Stale
connections, queue sizes, inode/PID noise and ordinary prose stay quiet. A peer port
is not automatically classified as a service, and a listener does not establish
external reachability or create a Recon port tab.

Each of these three boxes provides **Remove/Restore Auto Highlighting** and
**Tunneling Notes**. Manual backticks remain active. The helper offers SSH local/SOCKS,
Chisel reverse TCP and Ligolo-ng routed tunnel commands with editable values, copy
buttons, prerequisites, verification and cleanup. Choose a parsed observation to
fill a destination or subnet. Commands label Kali versus target versus proxy-console
steps; AEROS never runs them. Ligolo's IPv4 loopback case uses its special
`240.0.0.1/32` mapping; use SSH/Chisel for other loopback addresses.

Raw text stays in the existing ordinary `host_enumeration/network/` files, unchanged.
Parsed summaries are derived from those files. Per-host highlighting, interface and
helper settings live in the hidden structural index and create no output folders.

## Exploitation Path

Open **Exploitation Path** below Host Enumeration. Every host starts with an empty
**Initial Exploitation** tab. **Add Privilege Escalation** lets you select discovered
users or services, or type identities such as `www-data`, `joe` and `root`. Tabs
use the form **joe → root**.

Write Markdown and use **Insert command** for a fenced command block. Choose
Write, Side by side or Preview. **Add screenshots**, clipboard paste and drag/drop
accept PNG and JPEG files and display them inside the preview. Click an image to
open it at full size. Changes save automatically; **Save Path** saves immediately.

The initial write-up lives at `<engagement>/<IP>/exploitation/initial_exploitation/path.md`.
Escalations live under `exploitation/privilege_escalation/joe-to-root--<id>/path.md`;
each path stores its screenshots in its own `images/` directory. Markdown uses
relative image links, so copy the complete path folder to keep images visible in
another Markdown viewer. Empty paths create no directories. Removing a path from
AEROS keeps its existing files on disk.

## Engagement directories

Set **Parent directory** when creating a Lab/Engagement, or under
**Options → Engagement**. With `/home/kali/Documents/Labs/Course` as the parent
and `OSCP` as the engagement name, AEROS creates `Course/OSCP`. Adding a host
creates its IP folder. The following is an example after collecting data;
sections appear only when they have content:

```text
/home/kali/Documents/Labs/Course/OSCP/
├── .aeros/
│   ├── workspace.json          # IDs, settings, relationships and file mappings
│   ├── hosts/<IP>/             # Internal scan/service/OS records and editor state
│   └── revisions/              # Previous saves as file-layout ZIPs (up to 100)
├── documents/
├── reports/
├── scans/                      # Engagement-wide AutoRecon logs
└── 10.0.1.30/
    ├── recon/
    │   ├── port_scan.nmap
    │   ├── service_scan.nmap
    │   ├── udp_scan.nmap
    │   ├── vulnerability_scan.nmap
    │   └── services/
    │       └── tcp/
    │           ├── 80/
    │           │   └── directory_discovery.txt
    │           └── 8080/
    │               ├── technologies_headers.txt
    │               └── custom_<id>.txt
    ├── host_enumeration/
    │   ├── users_and_privileges/
    │   │   ├── local_users     # Contents pasted from /etc/passwd
    │   │   ├── local_groups
    │   │   ├── sudoers
    │   │   ├── root/
    │   │   └── bob/
    │   │       ├── sudo_permissions
    │   │       └── user_files
    │   ├── network/
    │   ├── software_and_processes/
    │   ├── scheduled_tasks/
    │   ├── privilege_escalation/
    │   └── filesystems/
    ├── scans/                  # Imported original scanner artifacts
    ├── peas-output/
    ├── screenshots/
    ├── evidence/
    ├── credentials/
    └── notes/report_notes.md
```

Each populated text box gets its own UTF-8 file; blank boxes do not create files
or folders. An empty Linux host has no Active Directory tree, and unused service
templates and closed/filtered scan observations do not create service folders.
Service outputs use `recon/services/<protocol>/<port>/<box>.txt`, so correcting a
service label does not move or duplicate the files. Custom box titles are kept in
the structural index; their content is stored in ordinary files like other boxes.
Adding data to a section creates the needed parents automatically, including
uploads, screenshots and reports. These files are the source used when reopening
the workspace. Linux users found
in passwd output, manually highlighted users, and saved user entries get folders.
Populated per-user follow-up boxes save beneath the matching username. Empty
follow-up boxes do not create files. Other
host records use readable field names and stable record IDs in their paths.

Internal bookkeeping lives under `.aeros/hosts/<IP>/`: scan summaries and import
projections, OS observations, service inventory and contexts, software analysis,
service port selections and imported-field editor state. Its nonempty text fields
remain ordinary files in that hidden structure; IDs and other structural values
stay in `.aeros/workspace.json`. This keeps generated labels and status explanations
out of the visible host output tree. On Kali, use **Ctrl+H** in the file manager
or `ls -a` / `tree -a` to see hidden files.

Existing engagements migrate their tracked bookkeeping files on the next save.
The move and index update use the same recoverable save transaction. AEROS removes
only the old tracked files and then their empty parent folders; unrelated files,
collected output, screenshots and discovered-user folders are preserved. A
conflicting file at the new destination is never silently overwritten.

You can edit existing field files directly, then reload the engagement. An
external edit advances its revision, preventing an older browser session from
silently overwriting it. Empty a file to clear a field; a missing file produces
an error so accidental deletion cannot silently erase a populated box. On the
next save, cleared fields lose their generated file and any empty parent folders.
Existing engagements also shed their old generated placeholders on the next
save. Collected output, discovered-user folders, and unrelated files are retained.
Files created
outside AEROS still need importing or pasting to establish their workspace link.

The small hidden JSON index preserves UI structure, classifications and blank
fields; populated text boxes use ordinary files. Keep `.aeros` when copying or backing up a lab.
New engagements do not create a combined `engagement.json` or `host.json`.
Archive exports include a JSON transport snapshot for compatibility.

Imported artifact revisions keep their
exact bytes and distinct filenames. Generated commands use the engagement path
directly, followed by the IP and output category. AEROS organizes output you
import or capture; commands you execute separately must use those output paths.

Leave the directory blank to use AEROS's local data directory. `AEROS_DATA_DIR`
overrides the app settings/catalog location. Paths refer to the machine running
the Python server. Windows paths work when running the source on Windows.

Changing the parent directory copies the engagement folder into an empty destination, switches
future saves to that destination, and preserves the old files. Removing an
engagement from the selector preserves its directory. Archive export includes
the engagement and retained output files.

Existing SQLite and legacy JSON saves are read once at startup. The importer
copies host artifacts and preserves the original database and files. SQLite is
used only by that legacy reader; all normal operations use the file store.
Existing files-v1 engagements upgrade on their next save, preserving their
original combined JSON and directory location without appending the name twice.
Back up the engagement directories and the app catalog together.

If a lab folder becomes unavailable, other labs can still open and save. AEROS
repairs older catalog pointers to a parent folder when a matching engagement
index exists in its named child. Otherwise use **Open existing engagement →
Locate folder**, and enter the existing engagement folder (or its parent) to
reconnect it. If the index itself was deleted, restore the engagement from a
backup. Removing an unavailable entry from the selector preserves its files.

Creation checks existing names on the server. If the name is already used,
choose **Open existing engagement** or give the new lab a different name.

The Windows `.exe` in older distributions predates this source refactor. Use the
Kali launcher or `python server.py` to run this version.

