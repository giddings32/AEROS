(function(root,factory){
  const services=typeof module==="object"&&module.exports?require("../imports/autorecon-live-import.js"):root.AEROSAutoReconLiveImport;
  const triage=typeof module==="object"&&module.exports?require("./recon-triage.js"):root.AEROSReconTriage;
  const api=factory(services||{},triage||{});
  if(typeof module==="object"&&module.exports)module.exports=api;
  if(root)root.AEROSReconWorkspace=api;
})(typeof window!=="undefined"?window:globalThis,function(serviceApi,triageApi){
  "use strict";
  const sessions=new WeakMap();
  const list=value=>Array.isArray(value)?value:[];
  const object=value=>value&&typeof value==="object"&&!Array.isArray(value)?value:{};
  const text=value=>String(value??"");
  const esc=value=>text(value).replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;").replaceAll('"',"&quot;").replaceAll("'","&#39;");
  const own=(value,key)=>Object.prototype.hasOwnProperty.call(value,key);
  const hasOutput=port=>Object.values(object(port?.outputs)).some(row=>text(row?.text).trim());
  const keyFor=row=>`${row.protocol||"tcp"}:${Number(row.port)}`;
  const validKey=key=>/^(tcp|udp):[1-9]\d{0,4}$/.test(key)&&Number(key.split(":")[1])<=65535;
  const FAMILY_ALIASES=new Map([["SMB / NetBIOS","SMB"],["SMTP / Mail","MAIL"],["Other / Unclassified","OTHER"],["Microsoft SQL Server","MSSQL"]]);
  const familyName=value=>FAMILY_ALIASES.get(value)||text(value).trim()||"OTHER";
  const FAMILIES=Object.freeze(["WEB","SMB","SSH","FTP","DNS","SNMP","LDAP","Kerberos","NFS","MAIL","MSSQL","MySQL","PostgreSQL","Redis","MongoDB","RDP","WinRM","VNC","OTHER"]);
  const box=(id,title,hint,terms)=>Object.freeze({id,title,hint,terms:terms||title});
  // These are the enumeration topics in the installed Reference Notes and service catalog.
  // Rendering a template never creates a saved output record or a file.
  const TEMPLATES=Object.freeze({
    WEB:[box("directory_discovery","Directory Discovery","Paste Feroxbuster, Gobuster, ffuf, Dirb or Dirsearch output.","directory discovery feroxbuster gobuster ffuf"),box("technologies_headers","Technologies & Headers","Paste WhatWeb, curl headers, server versions and application clues.","whatweb fingerprinting headers"),box("virtual_hosts","Virtual Hosts & Names","Paste virtual-host discovery, hostnames and certificate names.","virtual hosts vhost dns"),box("interesting_pages","Interesting Pages & Parameters","Record login pages, API routes, parameters, uploads and useful responses.","web enumeration authentication parameters upload"),box("findings_loot","Findings / Loot","Record useful files, paths and findings for this web port.","web files loot")],
    SMB:[box("shares","Shares & Access","Paste smbclient, NetExec or share-listing output.","smb shares anonymous"),box("users_groups","Users & Groups","Paste enum4linux, RPC or SMB user/group enumeration.","smb enum4linux rpc users"),box("configuration","Server & Security Settings","Record domain, signing, dialect and OS information.","smb signing enumeration"),box("files_loot","Files / Loot","Record interesting share paths and file contents.","smb loot files")],
    SSH:[box("banner","Banner & Host Keys","Paste SSH banner, host-key or version output.","ssh banner keys"),box("authentication","Authentication Findings","Record supported authentication, tested accounts and key-related findings.","ssh authentication keys"),box("notes","Notes / Loot","Record SSH-specific observations and useful paths.","ssh enumeration")],
    FTP:[box("banner","Banner & Capabilities","Paste FTP banner and supported features.","ftp enumeration"),box("access","Anonymous / Account Access","Record tested access and directory listings.","ftp anonymous"),box("files_loot","Files & Permissions","Record readable or writable paths and collected files.","ftp upload files")],
    DNS:[box("records","DNS Records","Paste dig, host or nslookup output.","dns records dig"),box("zone_transfer","Zone Transfer","Paste attempted zone-transfer results.","dns zone transfer axfr"),box("names","Hostnames & Subdomains","Record discovered names and resolutions.","dns subdomains")],
    SNMP:[box("access","Community / Access","Record discovered SNMP access and response details.","snmp community"),box("walk","SNMP Walk","Paste snmpwalk output.","snmp snmpwalk"),box("users_processes","Users, Processes & Interfaces","Record useful users, processes, network and configuration output.","snmp enumeration")],
    LDAP:[box("directory","Directory Information","Paste naming contexts, domain and directory information.","ldap naming contexts"),box("users_groups","Users & Groups","Paste LDAP user, group and membership results.","ldap users groups"),box("access","Access & Interesting Attributes","Record bind results and useful attributes.","ldap enumeration")],
    Kerberos:[box("principals","Principals & Domain","Record principal enumeration and domain information.","kerberos users"),box("tickets","Ticket / Account Findings","Paste account and ticket-related enumeration output.","kerberos asrep kerberoasting"),box("notes","Notes","Record useful Kerberos observations.","kerberos enumeration")],
    NFS:[box("exports","Exports","Paste showmount or export-listing output.","nfs showmount"),box("permissions","Access & Permissions","Record export options, identity mapping and permissions.","nfs no_root_squash"),box("files_loot","Files / Loot","Record collected files and paths.","nfs files")],
    MAIL:[box("banner","Banner & Capabilities","Paste SMTP, IMAP or POP3 capabilities.","smtp imap pop3"),box("users","Users & Access","Record user enumeration and tested access.","smtp vrfy expn"),box("notes","Notes / Loot","Record useful mail-service output.","mail enumeration")],
    DATABASE:[box("version","Version & Configuration","Paste database identification and configuration output.","database enumeration"),box("access","Access & Privileges","Record login results, roles and permissions.","database privileges"),box("databases","Databases, Tables & Data","Paste useful database, table and query results.","database tables"),box("files_loot","Files / Loot","Record useful values, file paths and collected data.","database files")],
    REMOTE:[box("service_info","Service Information","Paste protocol, banner and configuration output.","remote access enumeration"),box("access","Access Findings","Record tested access, account restrictions and session observations.","remote access authentication"),box("notes","Notes / Loot","Record useful output and paths.")],
    OTHER:[box("service_info","Service Information","Paste banners, protocol responses and version information."),box("enumeration","Enumeration Output","Paste service-specific enumeration output."),box("notes","Notes / Loot","Record findings and useful paths.")]
  });
  function templates(family){
    if(own(TEMPLATES,family))return TEMPLATES[family];
    if(/mysql|mssql|postgres|redis|mongo|oracle|database|memcache|cassandra/i.test(family))return TEMPLATES.DATABASE;
    if(["RDP","WinRM","VNC"].includes(family))return TEMPLATES.REMOTE;
    return TEMPLATES.OTHER;
  }
  function ensureState(candidate){
    const state=object(candidate);
    state.schemaVersion=1;
    if(typeof state.selectedTab!=="string")state.selectedTab="port";
    for(const key of ["selectedPorts","mappings","ports","autoHighlightDisabled"])state[key]=object(state[key]);
    state.customFamilies=list(state.customFamilies).map(familyName).filter(value=>value!=="OTHER");
    return state;
  }
  function project(host,base={}){
    const state=ensureState({...object(host.recon?.serviceWorkspace)}),byKey=new Map();
    for(const endpoint of list(base.workspaces)){
      const key=keyFor(endpoint);if(!validKey(key))continue;
      const family=familyName(state.mappings[key]||endpoint.classification?.family);
      const previous=byKey.get(key);
      byKey.set(key,{...endpoint,key,family,retained:false,artifacts:[...list(previous?.artifacts),...list(endpoint.artifacts)]});
    }
    for(const [key,saved] of Object.entries(state.ports)){
      if(!validKey(key)||byKey.has(key)||!hasOutput(saved))continue;
      const [protocol,port]=key.split(":");
      byKey.set(key,{key,id:key,protocol,port:Number(port),family:familyName(state.mappings[key]||saved.family),retained:true,artifacts:[]});
    }
    const endpoints=[...byKey.values()].sort((a,b)=>a.port-b.port||a.protocol.localeCompare(b.protocol));
    const families=[...new Set(endpoints.map(row=>row.family))].sort((a,b)=>{
      const rank=value=>FAMILIES.includes(value)?FAMILIES.indexOf(value):FAMILIES.length;
      return rank(a)-rank(b)||a.localeCompare(b);
    });
    return {hostId:host.id,endpoints,families,artifacts:list(base.artifacts),base};
  }
  function getPort(runtime,key){return object(runtime.state.ports[key]);}
  function outputBoxes(runtime,endpoint){
    const defaults=templates(endpoint.family),saved=object(getPort(runtime,endpoint.key).outputs),ids=new Set(defaults.map(row=>row.id));
    return [...defaults,...Object.entries(saved).filter(([id])=>!ids.has(id)).map(([id,row])=>box(id,row.title||id,"Your saved output for this port."))];
  }
  function outputValue(runtime,key,id){return text(getPort(runtime,key).outputs?.[id]?.text);}
  function setOutput(runtime,key,id,value,title){
    if(!validKey(key)||!/^[-a-zA-Z0-9_]+$/.test(id))throw new Error("Invalid output destination");
    const endpoint=runtime.model.endpoints.find(row=>row.key===key);
    const record=runtime.state.ports[key]||(runtime.state.ports[key]={family:endpoint?.family||"OTHER",outputs:{}});
    record.outputs=object(record.outputs);
    record.outputs[id]={...object(record.outputs[id]),title:text(title||record.outputs[id]?.title||id),text:text(value)};
    record.family=endpoint?.family||record.family;
  }
  const shellQuote=value=>"'"+text(value).replaceAll("'","'\"'\"'")+"'";
  function commandNoteSpec(host,endpoint,boxId,scan,title=""){
    const family=endpoint?.family||"OTHER",group=family.toLowerCase(),port=Number(endpoint?.port)||0,protocol=endpoint?.protocol||"tcp";
    let noteId=scan?"recon.scan."+scan:FAMILIES.includes(family)&&templates(family).some(row=>row.id===boxId)?`recon.${group}.${boxId}`:"recon.service";
    if(!scan&&/^custom_/.test(boxId)&&/\btls\b|\bssl\b|certificate/i.test(title))noteId="recon.tls";
    const address=text(host?.ip||host?.hostname||"TARGET"),ipv6=address.includes(":"),networkHost=ipv6?"["+address.replace(/^\[|\]$/g,"")+"]":address;
    const identity=[endpoint?.service,endpoint?.serviceRaw,endpoint?.product,endpoint?.tunnel].filter(Boolean).join(" ");
    const secure=/https|ssl\/http|\btls\b|\bssl\b/i.test(identity)||!/(?:^|\s)http(?:-proxy)?(?:\s|$)/i.test(identity)&&[443,8443,9443,5986].includes(port);
    const scheme=secure?"https":"http",base=`${scheme}://${networkHost}:${port||80}/`,targetPort=`${networkHost}:${port}`;
    const nmap=`${protocol==="udp"?"sudo ":""}nmap${ipv6?" -6":""}`,transport=protocol==="udp"?"-sU":"-sT";
    const tlsOptions=[25,587].includes(port)||/smtp/i.test(identity)&&port!==465?"-starttls smtp":port===143||/\bimap\b/i.test(identity)&&port!==993?"-starttls imap":port===110||/\bpop3\b/i.test(identity)&&port!==995?"-starttls pop3":port===21?"-starttls ftp":"";
    const mailType=[110,995].includes(port)||/pop3/i.test(identity)?"pop3":[143,993].includes(port)||/imap/i.test(identity)?"imap":"smtp",mailScheme=mailType+([465,993,995].includes(port)?"s":"");
    const openPorts=[...new Set(list(host?.serviceInventory).filter(row=>row.state==="open"&&(row.protocol||"tcp")==="tcp").map(row=>Number(row.port)).filter(value=>Number.isInteger(value)&&value>0&&value<=65535))].sort((a,b)=>a-b).join(",")||"OPEN_PORTS";
    return {noteId,context:{target:shellQuote(address),port:String(port),target_port:shellQuote(targetPort),url:shellQuote(base),url_fuzz:shellQuote(base+"FUZZ"),url_robots:shellQuote(base+"robots.txt"),url_sitemap:shellQuote(base+"sitemap.xml"),url_security:shellQuote(base+".well-known/security.txt"),url_path:shellQuote(base+"PATH"),
      nmap,transport,nmap_tcp:`nmap${ipv6?" -6":""}`,nmap_udp:`sudo nmap${ipv6?" -6":""}`,nc_udp:protocol==="udp"?"-u":"",tls_options:tlsOptions,
      ftp_url:shellQuote(`${port===990?"ftps":"ftp"}://${networkHost}:${port}/`),ftp_path:shellQuote(`${port===990?"ftps":"ftp"}://${networkHost}:${port}/PATH`),smb_share:shellQuote(`//${networkHost}/SHARE`),
      ldap_url:shellQuote(`${[636,3269].includes(port)||/ldaps/i.test(identity)?"ldaps":"ldap"}://${networkHost}:${port}`),ssh_target:shellQuote(`USERNAME@${address}`),sql_target:shellQuote(`USERNAME@${address}`),postgres_conn:shellQuote(`host=${address} port=${port} dbname=postgres user=USERNAME connect_timeout=5`),mongo_uri:shellQuote(`mongodb://${networkHost}:${port}/`),rdp_target:shellQuote(`/v:${targetPort}`),
      open_ports:openPorts,mssql_server:shellQuote(`tcp:${networkHost},${port}`),vnc_target:shellQuote(`${networkHost}::${port}`),nfs_export:shellQuote(`${networkHost}:/EXPORT`),winrm_tls:secure?"-S":"",mail_url:shellQuote(`${mailScheme}://${networkHost}:${port}/`),mail_request:shellQuote(mailType==="imap"?'LIST "" "*"':mailType==="pop3"?"LIST":"HELP"),
      url_wsman:shellQuote(base+"wsman"),snmp_target:shellQuote(`${ipv6?"udp6:":"udp:"}${targetPort}`),host:address,entity:`${family} ${port}/${protocol}`}};
  }
  function preview(runtime,value,meta={}){
    const rows=triageApi.pasteTriage?.(value,meta);
    if(rows)return '<pre>'+rows.map(row=>row.segments.map(segment=>segment.signal?'<span class="inline-glow" data-highlight-source="'+(segment.manual?'manual':'automatic')+'" data-highlight-priority="'+esc(segment.priority||'high')+'">'+esc(segment.text)+'</span>':esc(segment.text)).join("")).join("\n")+'</pre>';
    return '<pre>'+esc(value).replace(/`([^`\n]+)`/g,'<mark>$1</mark>')+'</pre>';
  }
  function pasteCard(runtime,{id,title,hint,value,port,scan,terms}){
    const key=scan?"scan:"+scan:port+"/"+id,mode=runtime.modes.get(key)||(value.trim()?"preview":"edit");
    const automatic=runtime.state.autoHighlightDisabled[key]!==true;
    const endpoint=runtime.model.endpoints.find(row=>row.key===port),meta={scan,family:endpoint?.family||"OTHER",boxId:id,autoHighlight:automatic};
    const command=commandNoteSpec(runtime.host,endpoint,id,scan,title),commandButton=runtime.adapters.commandNoteButton?.(command.noteId,command.context)||`<button class="secondary-btn small" data-command-note-id="${esc(command.noteId)}" data-command-note-context="${esc(JSON.stringify(command.context))}" type="button">Command Note</button>`;
    const destination=scan?`data-recon-scan="${scan}"`:`data-recon-output="${esc(id)}" data-output-port="${esc(port)}"`;
    return `<article class="sys-paste-card is-${mode==="edit"?"editing":"previewing"}" data-paste-key="${esc(key)}">
      <div class="sys-paste-title"><div><h4>${esc(title)}</h4><p>${esc(hint)}</p></div><div class="sys-paste-actions">
        ${commandButton}
        <button class="secondary-btn small" data-paste-auto="${esc(key)}" aria-pressed="${!automatic}" title="${automatic?'Remove automatic highlights from this box; manual backtick highlights stay.':'Restore automatic highlights for this box.'}" type="button">${automatic?'Remove Auto Highlighting':'Restore Auto Highlighting'}</button>
        <button class="secondary-btn small" data-paste-copy="${esc(key)}" type="button">Copy</button>
        <button class="secondary-btn small" data-paste-mode="${esc(key)}" aria-pressed="${mode==="preview"}" type="button">${mode==="edit"?"Preview":"Edit"}</button>
      </div></div>
      <textarea class="notes-area sys-paste-area" aria-label="${esc(title)}" ${destination} placeholder="${esc(hint)}" spellcheck="false">${esc(value)}</textarea>
      <div class="sys-paste-preview">${value?preview(runtime,value,meta):'<div class="section-empty">No output added yet.</div>'}</div>
    </article>`;
  }
  function tabHtml(key,label,active,kind="recon-tab"){
    return `<button class="${kind==="recon-tab"?"section-tab":"sys-tab"}${active?" active":""}" data-${kind}="${esc(key)}" type="button" role="tab" aria-selected="${active}" tabindex="${active?0:-1}" aria-controls="${kind==="recon-tab"?"reconPastePanel":"reconPortPanel"}">${esc(label)}</button>`;
  }
  function paintTabs(runtime){
    const tabs=runtime.root.querySelector('[data-recon-tabs]');
    const choices=[{key:"port",label:"Port Scan"},{key:"tcp",label:"Nmap Service Scan"},...runtime.model.families.map(family=>({key:"family:"+family,label:family}))];
    if(!choices.some(row=>row.key===runtime.state.selectedTab))runtime.state.selectedTab="port";
    tabs.innerHTML=choices.map(row=>tabHtml(row.key,row.label,row.key===runtime.state.selectedTab)).join("");
  }
  function familyOptions(runtime,selected,automatic=false){
    const families=[...new Set([...FAMILIES,...runtime.state.customFamilies,...runtime.model.families])];
    return (automatic?'<option value="">Automatic</option>':"")+families.map(family=>`<option value="${esc(family)}"${family===selected?" selected":""}>${esc(family)}</option>`).join("");
  }
  function managerHtml(runtime){
    return `<details class="recon-port-manager"${runtime.manageOpen?" open":""}><summary>Manage Ports</summary>
      <p>Correct a service assignment, return it to Automatic, or add a port you verified. Output stays with its host and port.</p>
      <div class="recon-port-assignments">${runtime.model.endpoints.map(row=>`<label><strong>${row.port} / ${esc(row.protocol.toUpperCase())}</strong><span>${esc(row.service||row.serviceRaw||"Unidentified")}${row.retained?" · Saved output":""}</span><select aria-label="Service for ${esc(row.key)}" data-map-port="${esc(row.key)}">${familyOptions(runtime,runtime.state.mappings[row.key]||"",true)}</select></label>`).join("")||'<div class="section-empty">No open ports detected yet.</div>'}</div>
      <form data-add-recon-port class="recon-add-port"><label>Port<input name="port" type="number" min="1" max="65535" required aria-label="Port number"/></label><label>Protocol<select name="protocol"><option value="tcp">TCP</option><option value="udp">UDP</option></select></label><label>Service<select name="family">${familyOptions(runtime,"WEB")}</select></label><button class="secondary-btn" type="submit">Add Port</button></form>
      <form data-add-recon-family class="recon-add-family"><label>Custom service name<input name="family" maxlength="48" required placeholder="e.g. MQTT"/></label><button class="secondary-btn" type="submit">Add Service Type</button></form>
      <p class="recon-inline-status" data-manager-status role="status"></p>
    </details>`;
  }
  function selectedEndpoint(runtime){
    const family=runtime.state.selectedTab.slice(7),rows=runtime.model.endpoints.filter(row=>row.family===family);
    return rows.find(row=>row.key===runtime.state.selectedPorts[family])||rows[0];
  }
  function panelHtml(runtime){
    const selection=runtime.state.selectedTab;
    if(selection==="port"||selection==="tcp"){
      const title=selection==="port"?"Port Scan":"Nmap Service Scan",hint=selection==="port"?"Paste Nmap port-discovery output. Open ports create service tabs automatically.":"Paste Nmap service/version scan output. Detected services update the port assignments.";
      const primary=pasteCard(runtime,{id:selection,scan:selection,title,hint,value:text(runtime.host.scans?.[selection]),terms:"nmap "+(selection==="port"?"port discovery":"service enumeration version")});
      const additional=selection==="port"?`<details class="recon-optional-scan"><summary>UDP scan output</summary>${pasteCard(runtime,{id:"udp",scan:"udp",title:"UDP Scan",hint:"Paste UDP scan output. Unconfirmed open|filtered results stay in the scan until verified.",value:text(runtime.host.scans?.udp),terms:"nmap udp"})}</details>`:"";
      return `<section class="card"><div class="card-head"><div><h3>${title}</h3><p>Paste output below. Use backticks to highlight useful values.</p></div></div><div class="sys-paste-stack">${primary}${additional}</div></section>`;
    }
    const endpoint=selectedEndpoint(runtime);if(!endpoint)return '<div class="section-empty">No ports in this service yet.</div>';
    const rows=runtime.model.endpoints.filter(row=>row.family===endpoint.family);
    runtime.state.selectedPorts[endpoint.family]=endpoint.key;
    const boxes=outputBoxes(runtime,endpoint);
    return `<section class="card"><div class="card-head"><div><h3>${esc(endpoint.family)} Enumeration</h3><p>${esc(runtime.host.ip)} · ${esc(endpoint.service||endpoint.serviceRaw||endpoint.family)}${endpoint.product?" · "+esc(endpoint.product):""}${endpoint.retained?" · Saved output; not currently confirmed open":""}</p></div><button class="secondary-btn" data-add-output-box type="button">Add custom box</button></div>
      <div class="sys-tabs" role="tablist" aria-label="${esc(endpoint.family)} ports">${rows.map(row=>tabHtml(row.key,String(row.port)+(row.protocol==="udp"?" / UDP":""),row.key===endpoint.key,"recon-port")).join("")}</div>
      <div id="reconPortPanel" role="tabpanel" aria-label="${esc(endpoint.family)} ${endpoint.port}" class="sys-paste-stack">${boxes.map(row=>pasteCard(runtime,{...row,port:endpoint.key,value:outputValue(runtime,endpoint.key,row.id)})).join("")}</div>
    </section>`;
  }
  function importRows(runtime){
    const endpoint=runtime.state.selectedTab.startsWith("family:")?selectedEndpoint(runtime):null;
    if(endpoint)return list(runtime.model.artifacts).filter(row=>row.endpointKey===endpoint.key||row.endpointId===endpoint.id);
    return runtime.model.artifacts;
  }
  function paintImports(runtime){
    const root=runtime.root.querySelector('[data-recon-retained]'),rows=importRows(runtime);
    root.hidden=!rows.length;
    root.querySelector('summary').textContent=`Imported outputs (${rows.length})`;
    if(root.open&&runtime.adapters.renderArtifacts)runtime.adapters.renderArtifacts(root.querySelector('[data-recon-artifact-viewer]'),rows,runtime.model.base);
  }
  function paint(runtime){
    const manager=runtime.root.querySelector('.recon-port-manager');
    if(manager)runtime.manageOpen=manager.open;
    paintTabs(runtime);
    runtime.root.querySelector('[data-recon-manager]').innerHTML=managerHtml(runtime);
    runtime.root.querySelector('#reconPastePanel').innerHTML=panelHtml(runtime);
    paintImports(runtime);
  }
  function changed(runtime){runtime.adapters.onChange?.();}
  function notify(runtime,message,error=false){
    const status=runtime.root.querySelector('[data-recon-save-status]');
    if(status){status.textContent=message;status.classList.toggle("bad-text",error);}
    if(error)runtime.adapters.notify?.(message,"error");
  }
  function updateModel(runtime){runtime.model=project(runtime.host,runtime.adapters.getModel?.()||runtime.model.base);}
  function valueForKey(runtime,key){
    if(key.startsWith("scan:"))return text(runtime.host.scans?.[key.slice(5)]);
    const slash=key.indexOf("/");return outputValue(runtime,key.slice(0,slash),key.slice(slash+1));
  }
  function bind(root){
    if(root.dataset.reconBound)return;root.dataset.reconBound="true";
    root.addEventListener("input",event=>{
      const runtime=sessions.get(root),field=event.target;if(!runtime)return;
      if(field.matches('[data-recon-scan]')){
        const type=field.dataset.reconScan;runtime.host.scans=object(runtime.host.scans);runtime.host.scans[type]=field.value;
        runtime.adapters.scanChanged?.(type,field.value);updateModel(runtime);paintTabs(runtime);
        runtime.root.querySelector('[data-recon-manager]').innerHTML=managerHtml(runtime);
        changed(runtime);notify(runtime,"Changes ready to save");
      }else if(field.matches('[data-recon-output]')){
        const endpoint=runtime.model.endpoints.find(row=>row.key===field.dataset.outputPort),definition=endpoint&&outputBoxes(runtime,endpoint).find(row=>row.id===field.dataset.reconOutput);
        setOutput(runtime,field.dataset.outputPort,field.dataset.reconOutput,field.value,definition?.title);changed(runtime);notify(runtime,"Changes ready to save");
      }
    });
    root.addEventListener("change",event=>{
      const runtime=sessions.get(root),field=event.target;if(!runtime||!field.matches('[data-map-port]'))return;
      const key=field.dataset.mapPort;if(!validKey(key))return;
      if(field.value)runtime.state.mappings[key]=familyName(field.value);else delete runtime.state.mappings[key];
      updateModel(runtime);changed(runtime);paint(runtime);notify(runtime,"Port assignment updated");
    });
    root.addEventListener("toggle",event=>{
      const runtime=sessions.get(root);if(!runtime)return;
      if(!root.contains(event.target))return;
      if(event.target.matches('.recon-port-manager'))runtime.manageOpen=event.target.open;
      if(event.target.matches('[data-recon-retained]')&&event.target.open)paintImports(runtime);
    },true);
    root.addEventListener("submit",async event=>{
      const runtime=sessions.get(root),form=event.target;if(!runtime||!form.matches('[data-add-recon-port],[data-add-recon-family]'))return;
      event.preventDefault();
      try{
        const data=new FormData(form);
        if(form.matches('[data-add-recon-family]')){
          const family=text(data.get('family')).trim().slice(0,48);if(!family)throw new Error("Enter a service name.");
          if(!runtime.state.customFamilies.includes(family))runtime.state.customFamilies.push(family);
        }else{
          const port=Number(data.get('port')),protocol=text(data.get('protocol')),key=keyFor({protocol,port});
          if(!Number.isInteger(port)||!validKey(key))throw new Error("Enter a port from 1 to 65535.");
          await runtime.adapters.addPort?.({protocol,port,family:familyName(data.get('family'))});
          runtime.state.mappings[key]=familyName(data.get('family'));updateModel(runtime);
          runtime.state.selectedTab="family:"+runtime.state.mappings[key];runtime.state.selectedPorts[runtime.state.mappings[key]]=key;
        }
        changed(runtime);paint(runtime);notify(runtime,"Port settings updated");
      }catch(error){notify(runtime,error.message,true);}
    });
    root.addEventListener("click",async event=>{
      const button=event.target.closest('button'),runtime=sessions.get(root);if(!button||!runtime)return;
      try{
        if(button.hasAttribute('data-recon-tab')){runtime.state.selectedTab=button.dataset.reconTab;paint(runtime);changed(runtime);root.querySelector('[data-recon-tab].active')?.focus();}
        else if(button.hasAttribute('data-recon-port')){runtime.state.selectedPorts[selectedEndpoint(runtime).family]=button.dataset.reconPort;paint(runtime);changed(runtime);root.querySelector('[data-recon-port].active')?.focus();}
        else if(button.hasAttribute('data-paste-mode')){const key=button.dataset.pasteMode,card=button.closest('[data-paste-key]'),mode=card.classList.contains('is-editing')?"preview":"edit";runtime.modes.set(key,mode);paint(runtime);root.querySelector(`[data-paste-key="${CSS.escape(key)}"] ${mode==="edit"?'textarea':'[data-paste-mode]'}`)?.focus();}
        else if(button.hasAttribute('data-paste-auto')){
          const key=button.dataset.pasteAuto;
          runtime.modes.set(key,button.closest('[data-paste-key]').classList.contains('is-editing')?"edit":"preview");
          if(runtime.state.autoHighlightDisabled[key]===true)delete runtime.state.autoHighlightDisabled[key];
          else runtime.state.autoHighlightDisabled[key]=true;
          changed(runtime);paint(runtime);notify(runtime,runtime.state.autoHighlightDisabled[key]?"Auto highlighting removed; manual highlights remain":"Auto highlighting restored");
          root.querySelector(`[data-paste-auto="${CSS.escape(key)}"]`)?.focus();
        }
        else if(button.hasAttribute('data-paste-copy')){await navigator.clipboard.writeText(valueForKey(runtime,button.dataset.pasteCopy));notify(runtime,"Output copied");}
        else if(button.hasAttribute('data-add-output-box')){
          const endpoint=selectedEndpoint(runtime),title=await runtime.adapters.prompt?.("Name this output box",{title:"Add custom box",placeholder:"e.g. TLS certificate review"});
          if(!title?.trim()||sessions.get(root)?.host!==runtime.host)return;
          const id="custom_"+(globalThis.crypto?.randomUUID?.()||Date.now().toString(36)).replaceAll('-','_');
          setOutput(runtime,endpoint.key,id,"",title.trim().slice(0,100));runtime.modes.set(endpoint.key+"/"+id,"edit");changed(runtime);paint(runtime);
          root.querySelector(`[data-recon-output="${CSS.escape(id)}"]`)?.focus();
        }else if(button.hasAttribute('data-save-recon')){
          button.disabled=true;notify(runtime,"Saving…");await runtime.adapters.saveNow?.();notify(runtime,"Recon saved");button.disabled=false;
        }
      }catch(error){button.disabled=false;notify(runtime,error.message,true);}
    });
    root.addEventListener("keydown",event=>{
      const button=event.target.closest('[role="tab"]');if(!button)return;
      const tabs=[...button.closest('[role="tablist"]').querySelectorAll('[role="tab"]')],index=tabs.indexOf(button);
      const next=event.key==="Home"?0:event.key==="End"?tabs.length-1:["ArrowRight","ArrowLeft"].includes(event.key)?(index+(event.key==="ArrowRight"?1:-1)+tabs.length)%tabs.length:null;
      if(next!==null){event.preventDefault();tabs[next].click();}
    });
  }
  function render(root,host,base,adapters={}){
    if(!root)return;
    if(!host){sessions.delete(root);root.querySelector('[data-recon-tabs]').innerHTML="";root.querySelector('[data-recon-manager]').innerHTML="";root.querySelector('[data-recon-retained]').hidden=true;root.querySelector('#reconPastePanel').innerHTML='<div class="section-empty">Select a host to add scan output.</div>';return;}
    host.recon=object(host.recon);host.recon.serviceWorkspace=ensureState(host.recon.serviceWorkspace);
    const previous=sessions.get(root),same=previous?.host?.id===host.id;
    const runtime={root,host,adapters,state:host.recon.serviceWorkspace,model:project(host,base),modes:same?previous.modes:new Map(),manageOpen:same&&previous.manageOpen};
    sessions.set(root,runtime);bind(root);paint(runtime);
  }
  function activate(root,key){
    const runtime=sessions.get(root);if(!runtime)return;
    const aliases={overview:"port","port-scans":"port",ports:"port",coverage:"port","service-scan":"tcp"};
    const requested=own(aliases,key)?aliases[key]:key;
    runtime.state.selectedTab=requested==="services"?"family:"+(runtime.model.families[0]||"OTHER"):requested;
    paint(runtime);
    if(["artifact-inventory","report-evidence","loot-exploit","commands-signals"].includes(requested)){
      const retained=root.querySelector('[data-recon-retained]');retained.open=true;paintImports(runtime);
    }
    changed(runtime);return runtime.state.selectedTab;
  }
  function openArtifact(root,id){
    const runtime=sessions.get(root);if(!runtime)return false;
    const artifact=runtime.model.artifacts.find(row=>row.id===id||row.artifactId===id||row.recordId===id);if(!artifact)return false;
    runtime.state.selectedTab="port";paint(runtime);
    const retained=root.querySelector('[data-recon-retained]');retained.open=true;paintImports(runtime);
    runtime.adapters.openArtifact?.(retained.querySelector('[data-recon-artifact-viewer]'),artifact.id);
    retained.scrollIntoView({block:"start"});return true;
  }
  return Object.freeze({FAMILIES,TEMPLATES,ensureState,project,templates,commandNoteSpec,render,activate,openArtifact,validKey});
});
