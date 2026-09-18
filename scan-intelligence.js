(function(root,factory){
  const api=factory();
  if(typeof module==="object"&&module.exports)module.exports=api;
  if(root)root.AerosScanIntelligence=api;
})(typeof globalThis!=="undefined"?globalThis:this,function(){
  "use strict";

  const SERVICE_ALIASES={
    "ftp":"ftp","ssh":"ssh","smtp":"smtp","submission":"smtp","domain":"dns","dns":"dns",
    "http":"http","http-proxy":"http","http-alt":"http","https":"https","ssl/http":"https","ssl/https":"https",
    "microsoft-ds":"smb","netbios-ssn":"smb","smb":"smb","ms-wbt-server":"rdp","rdp":"rdp",
    "wsman":"winrm","winrm":"winrm","snmp":"snmp","ldap":"ldap","ldaps":"ldap",
    "kerberos-sec":"kerberos","kerberos":"kerberos","ms-sql-s":"mssql","mssql":"mssql",
    "mysql":"mysql","postgresql":"postgresql","vnc":"vnc","vnc-http":"vnc"
  };
  const PORT_SERVICE={21:"ftp",22:"ssh",25:"smtp",53:"dns",80:"http",88:"kerberos",110:"pop3",111:"rpc",135:"rpc",139:"smb",143:"imap",161:"snmp",389:"ldap",443:"https",445:"smb",587:"smtp",636:"ldap",1433:"mssql",3306:"mysql",3389:"rdp",5432:"postgresql",5900:"vnc",5985:"winrm",5986:"winrm",8000:"http",8008:"http",8080:"http",8081:"http",8443:"https",8888:"http"};

  function clean(value){return String(value??"").trim();}
  function token(value){return clean(value).toLowerCase();}
  function unique(values){return [...new Set((Array.isArray(values)?values:[]).map(value=>Number(value)).filter(value=>Number.isInteger(value)&&value>0&&value<=65535))].sort((a,b)=>a-b);}
  function uniqueText(values){const seen=new Set(),rows=[];(Array.isArray(values)?values:[]).map(clean).filter(Boolean).forEach(value=>{const key=token(value).replace(/^\[|\]$/g,"").replace(/[.]$/,"");if(!key||seen.has(key))return;seen.add(key);rows.push(value);});return rows;}
  const NULL_EVIDENCE_VALUES=new Set(["","-","/","unknown","n/a","na","none","null","nil","not available","not applicable","undefined"]);
  const SERVICE_SCAN_COVERAGE=Object.freeze({
    NOT_RUN:"not-run",COMPLETED:"completed",PARTIAL:"partial",FAILED:"failed",INCOMPLETE:"incomplete",STALE:"stale"
  });
  const SERVICE_SCAN_COVERAGE_RANK=Object.freeze({
    [SERVICE_SCAN_COVERAGE.NOT_RUN]:0,[SERVICE_SCAN_COVERAGE.STALE]:1,[SERVICE_SCAN_COVERAGE.INCOMPLETE]:2,
    [SERVICE_SCAN_COVERAGE.FAILED]:3,[SERVICE_SCAN_COVERAGE.PARTIAL]:4,[SERVICE_SCAN_COVERAGE.COMPLETED]:5
  });
  function meaningfulEvidenceValue(value,{assignedLabel=""}={}){
    const text=clean(value).replace(/\s+/g," ");
    if(!text||NULL_EVIDENCE_VALUES.has(token(text)))return "";
    if(/^[\s\-_/\\|.,:;()[\]{}]+$/.test(text))return "";
    if(assignedLabel&&token(text)===token(assignedLabel))return "";
    return text;
  }
  function normalizePath(value){return clean(value).replace(/\\/g,"/").replace(/^\.\//,"").replace(/\/+/g,"/");}
  function hostnameFromUrl(value){try{return new URL(clean(value)).hostname||"";}catch(_error){return "";}}
  function portFromUrl(value){try{const url=new URL(clean(value));return Number(url.port)||(/https:/i.test(url.protocol)?443:80);}catch(_error){return 0;}}
  function targetToken(value){let raw=clean(value);const urlHost=hostnameFromUrl(raw);if(urlHost)return urlHost.replace(/^\[|\]$/g,"");raw=raw.replace(/^\/\//,"").replace(/^@/,"").split("/")[0];const bracketed=/^\[([^\]]+)\](?::\d+)?$/.exec(raw);if(bracketed)return bracketed[1];if((raw.match(/:/g)||[]).length===1)raw=raw.split(":")[0];return raw.replace(/^\[|\]$/g,"").replace(/[.]$/,"");}
  function activeTargetIdentity(host={},explicitMappings){
    const explicit=[];
    [host.aliases,host.targetAliases,host.hostAliases,host.ipAliases,host.hostnameAliases,host.addresses,host.hostnames].forEach(value=>{
      if(Array.isArray(value))explicit.push(...value);
      else if(typeof value==="string")explicit.push(value);
    });
    if(Array.isArray(host.networkAddresses))host.networkAddresses.filter(row=>row?.active!==false).forEach(row=>explicit.push(row?.address));
    if(Array.isArray(explicitMappings))explicit.push(...explicitMappings);
    const aliases=uniqueText([host.ip,host.hostname,...explicit].filter(value=>typeof value==="string"||typeof value==="number").map(targetToken).filter(Boolean));
    return {primary:targetToken(host.ip||host.hostname||aliases[0]||""),aliases,mappings:aliases.slice()};
  }
  function reliablePathTarget(filename=""){
    const parts=normalizePath(filename).split("/").filter(Boolean);if(parts.length<2)return "";
    const first=targetToken(parts[0]),generic=new Set(["root","target","targets","result","results","output","outputs","autorecon","scans","report","reports","tmp","temp"]);
    if(!first||generic.has(token(first))||/^[a-z]:$/i.test(first))return "";
    return /^(?:\d{1,3}[.]){3}\d{1,3}$/.test(first)||/^(?=.{1,253}$)(?=.*[a-z])(?=.*(?:[0-9.-]))[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/i.test(first)?first:"";
  }
  function targetCandidatesFromCommand(command){const operation=operationFromCommand(command,-1);return operation.targetCandidates||[];}
  function targetCandidatesFromText(text,kind=""){
    const raw=String(text||""),values=[];let match;
    const nmap=/^\s*Nmap scan report for\s+(.+?)\s*$/gim;while((match=nmap.exec(raw))){const value=clean(match[1]);const parenthesized=(/\(([^)]+)\)\s*$/.exec(value)||[])[1];values.push(parenthesized||value.split(/\s+/).pop());}
    const grepable=/^\s*Host:\s+(\S+)(?:\s+\([^)]*\))?(?:\s+Ports:|\s+Status:|\s*$)/gim;while((match=grepable.exec(raw)))values.push(targetToken(match[1]));
    const nikto=/^\s*(?:\+\s*)?Target\s+(?:Host|IP)\s*:\s*(\S+)/gim;while((match=nikto.exec(raw)))values.push(targetToken(match[1]));
    const url=/(?:^|\s)(?:Target URL|URL)\s*:\s*(https?:\/\/\S+)/gim;while((match=url.exec(raw)))values.push(hostnameFromUrl(match[1]));
    if(/wpscan|wordpress/i.test(kind||raw.slice(0,500))){const wpscan=/^\s*(?:\[+\]\s*)?(?:Target URL|Scan URL|URL)\s*:\s*https?:\/\/([a-z0-9.-]+)(?::\d+)?/gim;while((match=wpscan.exec(raw)))values.push(match[1]);}
    return uniqueText(values.map(targetToken));
  }
  function mappedTargetSet(selectedTarget,mappings){
    const selected=token(targetToken(selectedTarget)),allowed=new Set(selected?[selected]:[]);if(!mappings)return allowed;
    if(Array.isArray(mappings))mappings.forEach(value=>allowed.add(token(targetToken(value))));
    else if(typeof mappings==="object")Object.entries(mappings).forEach(([key,value])=>{const values=Array.isArray(value)?value:[value];if(token(targetToken(key))===selected)values.forEach(item=>allowed.add(token(targetToken(item))));else if(values.some(item=>token(targetToken(item))===selected))allowed.add(token(targetToken(key)));});
    return allowed;
  }
  function knownPathTarget(filename,aliases=[]){
    const first=targetToken(normalizePath(filename).split("/").filter(Boolean)[0]||"");
    const allowed=new Set((Array.isArray(aliases)?aliases:[]).map(value=>token(targetToken(value))).filter(Boolean));
    return first&&allowed.has(token(first))?first:reliablePathTarget(filename);
  }
  function resolveTargetOwnership(selectedTarget,candidates=[],options={}){
    const rows=uniqueText(candidates.map(targetToken).filter(Boolean)),normalized=rows.map(token),distinct=[...new Set(normalized)],allowed=mappedTargetSet(selectedTarget,options.mappings);
    const allMapped=!!selectedTarget&&distinct.length>0&&distinct.every(value=>allowed.has(value));let targetConflict=false,targetReason="";
    if(distinct.length>1&&!allMapped){targetConflict=true;targetReason=`Conflicting target evidence was found: ${rows.join(", ")}.`;}
    else if(selectedTarget&&distinct.length&&![...allowed].includes(distinct[0])){targetConflict=true;targetReason=`Evidence target ${rows[0]} does not match selected host ${targetToken(selectedTarget)}.`;}
    else if(selectedTarget&&!distinct.length&&options.requireEvidence===true){targetConflict=true;targetReason="Folder evidence has no reliable target and cannot be routed safely.";}
    else if(distinct.length)targetReason=distinct.length>1?`Mapped target evidence matches selected host ${targetToken(selectedTarget)}.`:`Target evidence matches ${rows[0]}.`;
    else targetReason=options.manualFallback===true?`No target evidence was present; the explicitly selected host ${targetToken(selectedTarget)} is used for this single-file import.`:"No reliable target evidence was present.";
    return {target:distinct.length===1?rows[0]:allMapped?targetToken(selectedTarget):"",targetCandidates:rows,targetConflict,targetReason};
  }
  function endpointValidation(raw={}){const port=Number(raw.port),protocol=token(raw.protocol);if(!Number.isInteger(port)||port<1||port>65535)return {valid:false,reason:"invalid-port"};if(!["tcp","udp"].includes(protocol))return {valid:false,reason:"unsupported-protocol"};return {valid:true,port,protocol};}
  function decodeEntities(value){return clean(value).replace(/&#x([0-9a-f]+);/gi,(_match,hex)=>String.fromCodePoint(Number.parseInt(hex,16))).replace(/&#(\d+);/g,(_match,number)=>String.fromCodePoint(Number(number))).replace(/&lt;/g,"<").replace(/&gt;/g,">").replace(/&quot;/g,'"').replace(/&#39;/g,"'").replace(/&amp;/g,"&");}
  function attr(attrs,name){return decodeEntities((new RegExp(`\\b${name}="([^"]*)"`,"i").exec(attrs)||[])[1]||"");}
  function normalizeServiceName(name,port,protocol="tcp"){
    const raw=token(name).replace(/[?]+$/,"").replace(/^ssl\//,match=>match);
    if(SERVICE_ALIASES[raw])return SERVICE_ALIASES[raw];
    if(raw.includes("http"))return protocol==="tcp"&&[443,8443,5986].includes(Number(port))?"https":"http";
    if(raw.includes("smb")||raw.includes("netbios"))return "smb";
    if(raw.includes("sql server"))return "mssql";
    return raw&&raw!=="unknown"?raw:`${protocol}-${port}`;
  }
  function serviceHint(name,port,protocol="tcp"){
    const raw=token(name).replace(/[?]+$/,"");
    if(raw&&raw!=="unknown"&&raw!=="general")return normalizeServiceName(raw,port,protocol);
    return PORT_SERVICE[Number(port)]||"";
  }
  function evidenceQuality(raw={}){
    const protocol=token(raw.protocol)||"tcp",method=token(raw.serviceMethod||raw.method);
    const serviceRaw=meaningfulEvidenceValue(raw.serviceRaw||raw.service);
    const meaningful=!![
      meaningfulEvidenceValue(raw.product,{assignedLabel:serviceRaw}),
      meaningfulEvidenceValue(raw.version,{assignedLabel:serviceRaw}),
      meaningfulEvidenceValue(raw.cpe),
      meaningfulEvidenceValue(raw.extraInfo,{assignedLabel:serviceRaw}),
      meaningfulEvidenceValue(raw.serviceFingerprint||raw.servicefp)
    ].find(Boolean);
    const manual=raw.manualConfirmed===true;
    const protocolProof=raw.protocolResponse===true;
    const credibleService=!!serviceRaw&&!["unknown","general","tcpwrapped"].includes(token(serviceRaw));
    const probed=method==="probed"&&(Number(raw.serviceConfidence||raw.conf)||0)>=3&&credibleService;
    const textProbe=raw.probeCommand===true&&credibleService&&meaningful;
    const legacy=protocol==="tcp"&&raw.legacyIdentified===true&&!/\bnmap\b/i.test([raw.source,raw.parserType,raw.command].map(clean).join(" "))&&!clean(raw.sourceArtifactId);
    const authoritativeState=token(raw.state||"open")==="open",automaticUdpWeb=protocol==="udp"&&/http/.test(token(raw.service||raw.serviceRaw));
    const identified=manual||authoritativeState&&!automaticUdpWeb&&(protocolProof||probed||textProbe||legacy);
    return {identified,kind:manual?"manual":protocolProof?"protocol-response":probed||textProbe?"probed":legacy&&meaningful?"legacy-confirmed":"hint"};
  }
  function lifecycle(row={}){
    const identified=row.identified===true;
    const probe=token(row.probeResult);
    const identificationState=identified?"identified":probe==="completed-inconclusive"?"unknown-after-probing":"identification-needed";
    const enumerationState=identified&&row.enumerationComplete===true?"fully-enumerated":identified&&row.enumerationStarted===true?"in-progress":"not-started";
    const displayState=enumerationState==="fully-enumerated"?"Fully enumerated":enumerationState==="in-progress"?"Enumeration in progress":identified?"Identified":identificationState==="unknown-after-probing"?"Unknown after probing":token(row.state)==="open|filtered"?"Open|filtered / confirmation needed":"Discovered / identification needed";
    return {identificationState,enumerationState,displayState};
  }
  function splitBanner(banner){
    const text=meaningfulEvidenceValue(banner).replace(/\s+/g," ");
    if(!text)return {product:"",version:"",extraInfo:"",details:""};
    const parts=text.split(" ");
    const index=parts.findIndex(part=>/^(?:v?\d+(?:[.][\w+~:-]+)+|\d+[a-z]\d|\d{4}[.-]\d|[a-z]+\d+[.]\d+)/i.test(part));
    if(index>0){
      return {
        product:parts.slice(0,index).join(" "),
        version:parts[index],
        extraInfo:parts.slice(index+1).join(" "),
        details:text
      };
    }
    return {product:text,version:"",extraInfo:"",details:text};
  }
  function decodeNmapFingerprint(value){
    return decodeEntities(String(value||""))
      .replace(/\\x([0-9a-f]{2})/gi,(_match,hex)=>String.fromCharCode(Number.parseInt(hex,16)))
      .replace(/\\r/g,"\r").replace(/\\n/g,"\n").replace(/\\t/g,"\t")
      .replace(/\\([.()/"'])/g,"$1");
  }
  function productVersionFromHeader(value){
    const text=meaningfulEvidenceValue(value).replace(/\s+/g," ");if(!text)return {product:"",version:""};
    const slash=/^(.+?)\/([a-z0-9][a-z0-9._+~:-]*)$/i.exec(text);
    if(slash)return {product:meaningfulEvidenceValue(slash[1]),version:meaningfulEvidenceValue(slash[2])};
    const split=splitBanner(text);
    return {product:meaningfulEvidenceValue(split.product),version:meaningfulEvidenceValue(split.version)};
  }
  function deterministicProtocolEvidence(value){
    const text=decodeNmapFingerprint(value),normalized=text.replace(/\\[.]|\\ /g,match=>match.slice(1));
    const httpStatus=/(?:^|[\r\n"(])HTTP\/(?:0[.]9|1[.][01]|2|3)\s+\d{3}(?:\s+[^\r\n"]*)?/im.exec(normalized);
    const httpHeaders=[...normalized.matchAll(/(?:^|[\r\n])\s*([A-Za-z][A-Za-z0-9-]{1,63})\s*:\s*([^\r\n"]+)/gim)];
    if(httpStatus&&httpHeaders.some(match=>/^(?:server|date|connection|content-length|content-type|location|access-control-[a-z-]+)$/i.test(match[1]))){
      const server=httpHeaders.find(match=>/^server$/i.test(match[1]))?.[2]||"",parsed=productVersionFromHeader(server);
      return {confirmed:true,service:"http",product:parsed.product,version:parsed.version,protocolResponse:true,evidenceKind:"http-response",summary:[clean(httpStatus[0]),server?`Server: ${clean(server)}`:""].filter(Boolean).join(" · ")};
    }
    const ssh=/(?:^|[\r\n"(])SSH-(?:1[.]5|1[.]99|2[.]0)-([^\s\r\n"]+)/im.exec(normalized);
    if(ssh){
      const productVersion=productVersionFromHeader(clean(ssh[1]).replace(/^OpenSSH_/i,"OpenSSH/"));
      return {confirmed:true,service:"ssh",product:productVersion.product,version:productVersion.version,protocolResponse:true,evidenceKind:"ssh-handshake",summary:clean(ssh[0])};
    }
    const greeting=/(?:^|[\r\n"(])220[ -]([^\r\n"]+)/im.exec(normalized);
    if(greeting&&/\b(?:ESMTP|SMTP)\b/i.test(greeting[1]))return {confirmed:true,service:"smtp",product:"",version:"",protocolResponse:true,evidenceKind:"smtp-greeting",summary:clean(greeting[0])};
    if(greeting&&/\bFTP\b/i.test(greeting[1]))return {confirmed:true,service:"ftp",product:"",version:"",protocolResponse:true,evidenceKind:"ftp-greeting",summary:clean(greeting[0])};
    return {confirmed:false,service:"",product:"",version:"",protocolResponse:false,evidenceKind:"",summary:""};
  }
  function applyDeterministicProtocolEvidence(row,values=[]){
    const candidates=Array.isArray(values)?values:[values];
    const observations=[...candidates,candidates.join("\n")].map(deterministicProtocolEvidence).filter(item=>item.confirmed);
    if(!observations.length)return row;
    const observation=observations.sort((a,b)=>Number(!!b.product)-Number(!!a.product)||Number(!!b.version)-Number(!!a.version)||clean(b.version).length-clean(a.version).length||clean(b.summary).length-clean(a.summary).length)[0];
    row.protocolResponse=true;row.identified=true;row.service=normalizeServiceName(observation.service,row.port,row.protocol);
    row.product=meaningfulEvidenceValue(observation.product)||row.product;
    row.version=meaningfulEvidenceValue(observation.version)||row.version;
    row.identificationEvidence=observation.evidenceKind;
    row.directEvidenceSummary=observation.summary;
    return row;
  }
  function uniqueLabels(...values){
    const seen=new Set(),output=[];
    values.flatMap(value=>clean(value).split(/\s*[·|]\s*/)).map(clean).filter(Boolean).forEach(value=>{
      const key=value.toLowerCase();
      if(seen.has(key))return;
      seen.add(key);output.push(value);
    });
    return output;
  }
  function serviceId(service){
    return clean(service?.id||service?.endpointId)||[
      clean(service?.engagementId),clean(service?.hostId),
      targetToken(service?.targetAddress||service?.observedTargetAddress||service?.address||service?.target),
      token(service?.protocol)||"tcp",Number(service?.port)||0
    ].filter(Boolean).join("|")||`${token(service?.protocol)||"tcp"}:${Number(service?.port)||0}`;
  }
  function stripTags(value){return decodeEntities(String(value||"").replace(/<[^>]+>/g," ").replace(/\s+/g," ")).trim();}
  function vulnerabilityLeadId(row){
    const target=clean(row?.endpointId)||[
      targetToken(row?.targetAddress||row?.observedTargetAddress||row?.address||row?.target),
      token(row?.protocol)||"tcp",Number(row?.port)||0
    ].filter(Boolean).join("|")||`${token(row?.protocol)||"tcp"}:${Number(row?.port)||0}`;
    return `${target}:${token(row?.cve||row?.title||row?.script||"lead").replace(/[^a-z0-9.-]+/g,"-")}`;
  }
  function scoreNearCve(text,cve=""){
    const value=clean(text);
    const start=cve?value.toUpperCase().indexOf(String(cve).toUpperCase()):-1;
    const tail=start>=0?value.slice(start+String(cve).length):value;
    const match=tail.match(/(?:^|\s)(10(?:[.]0)?|[0-9](?:[.][0-9])?)(?=\s|$|\t|https?:)/);
    const score=match?Number(match[1]):NaN;
    return Number.isFinite(score)&&score>=0&&score<=10?score:null;
  }
  function vulnerabilityLeadsFromEvidence(text,context={}){
    const value=clean(text);if(!value)return [];
    if(/\bNOT\s+VULNERABLE\b|\b(?:ERROR|TIMEOUT|ABORTED|FATAL|CONNECTION REFUSED)\b/i.test(value))return [];
    const ownership={
      engagementId:clean(context.engagementId),hostId:clean(context.hostId),
      targetAddress:targetToken(context.targetAddress||context.observedTargetAddress||context.address||context.target),
      endpointId:clean(context.endpointId||context.id),sourceArtifactId:clean(context.sourceArtifactId),
      sourceRevision:Number(context.sourceRevision)||0,objective:clean(context.objective)
    };
    const leads=[];const cves=[...value.matchAll(/CVE-[0-9]{4}-[0-9]+/gi)].map(match=>match[0].toUpperCase());
    cves.forEach(cve=>leads.push({
      id:"",cve,title:cve,cvss:scoreNearCve(value,cve),script:clean(context.script),port:Number(context.port)||0,
      protocol:token(context.protocol)||"tcp",service:clean(context.service),product:clean(context.product),version:clean(context.version),
      source:clean(context.source),raw:value.slice(0,1200),...ownership
    }));
    if(!cves.length&&/\bVULNERABLE\b/i.test(value)&&clean(context.script)){
      leads.push({id:"",cve:"",title:clean(context.script),cvss:null,script:clean(context.script),port:Number(context.port)||0,
        protocol:token(context.protocol)||"tcp",service:clean(context.service),product:clean(context.product),version:clean(context.version),
        source:clean(context.source),raw:value.slice(0,1200),...ownership});
    }
    return leads.map(row=>({...row,id:vulnerabilityLeadId(row)}));
  }
  function mergeVulnerabilityLeads(leads){
    const merged=new Map();
    (Array.isArray(leads)?leads:[]).forEach(raw=>{
      const row={...raw,port:Number(raw?.port)||0,protocol:token(raw?.protocol)||"tcp",cve:clean(raw?.cve).toUpperCase(),
        title:clean(raw?.title||raw?.cve||raw?.script||"Potential vulnerability"),cvss:Number.isFinite(Number(raw?.cvss))?Number(raw.cvss):null,
        script:clean(raw?.script),service:clean(raw?.service),product:clean(raw?.product),version:clean(raw?.version),source:clean(raw?.source),raw:clean(raw?.raw),
        engagementId:clean(raw?.engagementId),hostId:clean(raw?.hostId),targetAddress:targetToken(raw?.targetAddress||raw?.observedTargetAddress||raw?.address||raw?.target),
        endpointId:clean(raw?.endpointId),sourceArtifactId:clean(raw?.sourceArtifactId),sourceRevision:Number(raw?.sourceRevision)||0,objective:clean(raw?.objective)};
      row.id=clean(raw?.id)||vulnerabilityLeadId(row);
      const current=merged.get(row.id);
      if(!current){merged.set(row.id,row);return;}
      const score=Math.max(Number(current.cvss)||0,Number(row.cvss)||0);
      merged.set(row.id,{...current,...row,cvss:score||current.cvss||row.cvss||null,source:uniqueLabels(current.source,row.source).join(" · "),
        raw:[current.raw,row.raw].filter(Boolean).sort((a,b)=>b.length-a.length)[0]||"",status:current.status||row.status||"lead",notes:current.notes||row.notes||""});
    });
    return [...merged.values()].sort((a,b)=>(Number(b.cvss)||-1)-(Number(a.cvss)||-1)||a.protocol.localeCompare(b.protocol)||a.port-b.port||a.title.localeCompare(b.title));
  }
  function compactFingerprint(value){return token(value).replace(/[^a-z0-9]+/g,"");}
  function compatibleFingerprint(leftValue,rightValue){
    const left=compactFingerprint(leftValue),right=compactFingerprint(rightValue);
    if(!left||!right)return false;
    if(left===right)return true;
    return Math.min(left.length,right.length)>=5&&(left.includes(right)||right.includes(left));
  }
  function comparableVersion(value){return token(value).replace(/^v(?=[0-9])/i,"").replace(/\s+/g,"");}
  function vulnerabilityLeadMatch(lead={},services=[]){
    const port=Number(lead.port)||0,protocol=token(lead.protocol)||"tcp";
    const rows=(Array.isArray(services)?services:[]).filter(row=>row?.active!==false&&Number(row?.port)===port&&(token(row?.protocol)||"tcp")===protocol);
    const endpointId=clean(lead.endpointId),targetAddress=targetToken(lead.targetAddress||lead.observedTargetAddress||lead.address||lead.target);
    let candidates=rows;
    if(endpointId)candidates=rows.filter(row=>clean(row?.endpointId||row?.id)===endpointId);
    else if(targetAddress)candidates=rows.filter(row=>token(targetToken(row?.targetAddress||row?.observedTargetAddress||row?.address||row?.target))===token(targetAddress));
    const endpoint=candidates.length===1?candidates[0]:null;
    if(candidates.length>1)return {tier:"unverified",label:"Ambiguous endpoint match",reason:`More than one current ${port||"?"}/${protocol.toUpperCase()} endpoint matches this Lead. Open its exact endpoint context before assessing applicability.`,endpointMatched:false,productMatched:false,serviceMatched:false,versionMatched:false};
    if(!endpoint)return {tier:"unverified",label:"Unverified service match",reason:`No current ${port||"?"}/${protocol.toUpperCase()} endpoint record is available for correlation.`,endpointMatched:false,productMatched:false,serviceMatched:false,versionMatched:false};
    const leadService=normalizeServiceName(lead.service,port,protocol),endpointService=normalizeServiceName(endpoint.service||endpoint.serviceRaw||endpoint.serviceHint,port,protocol);
    const serviceMatched=!!leadService&&!!endpointService&&leadService===endpointService;
    const leadProduct=clean(lead.product),endpointProduct=clean(endpoint.product);
    const productMatched=!!leadProduct&&!!endpointProduct&&compatibleFingerprint(leadProduct,endpointProduct);
    const leadVersion=clean(lead.version),endpointVersion=clean(endpoint.version);
    const versionMatched=!!leadVersion&&!!endpointVersion&&comparableVersion(leadVersion)===comparableVersion(endpointVersion);
    const endpointLabel=`${port||"?"}/${protocol.toUpperCase()}`;
    if(leadProduct&&endpointProduct&&!productMatched){
      return {tier:"unverified",label:"Unverified service match",reason:`The imported lead names ${leadProduct}, but the current ${endpointLabel} inventory identifies ${endpointProduct}. Verify the service before treating the CVE as applicable.`,endpointMatched:true,productMatched:false,serviceMatched,versionMatched:false};
    }
    if(leadVersion&&endpointVersion&&!versionMatched){
      return {tier:"unverified",label:"Unverified service match",reason:`The imported lead references version ${leadVersion}, while the current ${endpointLabel} inventory records ${endpointVersion}. Resolve the version conflict before attempting the CVE.`,endpointMatched:true,productMatched,serviceMatched,versionMatched:false};
    }
    if((productMatched||serviceMatched)&&versionMatched){
      const identity=[endpointProduct||leadProduct,endpointVersion||leadVersion].filter(Boolean).join(" ")||endpointService||leadService;
      return {tier:"version-match",label:"Version match",reason:`${identity} matches the current ${endpointLabel} service inventory. CVE applicability and target configuration still require manual verification.`,endpointMatched:true,productMatched,serviceMatched,versionMatched:true};
    }
    if(productMatched||serviceMatched){
      const identity=endpointProduct||leadProduct||endpointService||leadService||"Service";
      return {tier:"possible-match",label:"Possible match",reason:`${identity} aligns with the current ${endpointLabel} endpoint, but an exact version match is not available. Verify the installed version and vulnerable configuration.`,endpointMatched:true,productMatched,serviceMatched,versionMatched:false};
    }
    return {tier:"unverified",label:"Unverified service match",reason:`The lead is tied to ${endpointLabel}, but the current inventory does not provide enough matching service or product detail. Verify the endpoint before treating the CVE as actionable.`,endpointMatched:true,productMatched:false,serviceMatched:false,versionMatched:false};
  }
  function vulnerabilityLeadTriage(lead={},services=[]){
    const match=vulnerabilityLeadMatch(lead,services),score=Number(lead.cvss),status=token(lead.status)||"lead";
    const high=Number.isFinite(score)&&score>=7,manualVerified=status==="verified",notApplicable=status==="na";
    const credible=["version-match","possible-match"].includes(match.tier);
    const priority=!notApplicable&&(manualVerified||(high&&credible));
    let rank=60;
    if(notApplicable)rank=99;
    else if(manualVerified)rank=0;
    else if(high&&match.tier==="version-match")rank=10;
    else if(high&&match.tier==="possible-match")rank=20;
    else if(match.tier==="version-match")rank=30;
    else if(match.tier==="possible-match")rank=40;
    else if(high)rank=50;
    return {match,score:Number.isFinite(score)?score:null,high,manualVerified,notApplicable,credible,priority,rank};
  }
  function triageVulnerabilityLeads(leads=[],services=[],filter="all"){
    const mode=token(filter)||"all";
    return (Array.isArray(leads)?leads:[]).map(row=>({...row,triage:vulnerabilityLeadTriage(row,services)})).filter(row=>{
      if(mode==="priority")return row.triage.priority;
      if(mode==="high")return row.triage.high&&!row.triage.notApplicable;
      if(mode==="version")return row.triage.match.tier==="version-match"&&!row.triage.notApplicable;
      if(mode==="review")return row.triage.match.tier==="unverified"&&!row.triage.notApplicable;
      return true;
    }).sort((a,b)=>a.triage.rank-b.triage.rank||(b.triage.score??-1)-(a.triage.score??-1)||a.protocol.localeCompare(b.protocol)||a.port-b.port||a.title.localeCompare(b.title));
  }
  function mergeServices(services){
    const merged=new Map();
    (Array.isArray(services)?services:[]).forEach(raw=>{
      const validation=endpointValidation(raw);if(!validation.valid)return;
      const {port,protocol}=validation;
      const targetAddress=targetToken(raw.targetAddress||raw.observedTargetAddress||raw.address||raw.target);
      const serviceRaw=meaningfulEvidenceValue(raw.serviceRaw||raw.service);
      const product=meaningfulEvidenceValue(raw.product,{assignedLabel:serviceRaw});
      const version=meaningfulEvidenceValue(raw.version,{assignedLabel:serviceRaw});
      const extraInfo=meaningfulEvidenceValue(raw.extraInfo,{assignedLabel:serviceRaw});
      const details=meaningfulEvidenceValue(raw.details,{assignedLabel:serviceRaw});
      const row={
        id:clean(raw.id||raw.endpointId)||`${protocol}:${port}`,endpointId:clean(raw.endpointId||raw.id)||`${protocol}:${port}`,
        engagementId:clean(raw.engagementId),hostId:clean(raw.hostId),targetAddress,observedTargetAddress:targetToken(raw.observedTargetAddress||raw.targetAddress||raw.address||raw.target),
        endpointIdentitySchemaVersion:Number(raw.endpointIdentitySchemaVersion)||0,
        port,protocol,state:clean(raw.state)||"open",
        serviceRaw,serviceHint:meaningfulEvidenceValue(raw.serviceHint)||serviceHint(serviceRaw,port,protocol),
        product,version,extraInfo,details,
        tunnel:meaningfulEvidenceValue(raw.tunnel),cpe:meaningfulEvidenceValue(raw.cpe),serviceFingerprint:meaningfulEvidenceValue(raw.serviceFingerprint||raw.servicefp),scriptEvidence:!!raw.scriptEvidence,
        active:raw.active!==false,deletedAt:clean(raw.deletedAt),archivedAt:clean(raw.archivedAt),
        endpointOwnershipConflict:raw.endpointOwnershipConflict===true,endpointOwnershipConflictReason:clean(raw.endpointOwnershipConflictReason),
        serviceMethod:clean(raw.serviceMethod||raw.method),serviceConfidence:Number(raw.serviceConfidence||raw.conf)||0,
        manualConfirmed:raw.manualConfirmed===true,protocolResponse:raw.protocolResponse===true,probeCommand:raw.probeCommand===true,
        probeResult:clean(raw.probeResult),operationStatus:clean(raw.operationStatus),operationCompleted:raw.operationCompleted===true,
        enumerationStarted:raw.enumerationStarted===true,enumerationComplete:raw.enumerationComplete===true,
        completedChecks:uniqueText(raw.completedChecks||[]),enumerationObjectives:uniqueText(raw.enumerationObjectives||[]),enumerationCoverage:clean(raw.enumerationCoverage),
        source:clean(raw.source),sourceSlot:clean(raw.sourceSlot),sourceOwner:clean(raw.sourceOwner),parserType:clean(raw.parserType||raw.importType),
        command:clean(raw.command),evidence:Array.isArray(raw.evidence)?raw.evidence:[],
        sourceArtifactId:clean(raw.sourceArtifactId),sourceRevision:Number(raw.sourceRevision)||0,objective:clean(raw.objective),
        serviceScanCoverageState:token(raw.serviceScanCoverageState)||SERVICE_SCAN_COVERAGE.NOT_RUN,
        serviceScanCoverageReason:clean(raw.serviceScanCoverageReason),serviceScanCoverageSource:clean(raw.serviceScanCoverageSource),
        serviceScanCoverageCommand:clean(raw.serviceScanCoverageCommand),
        observedAt:clean(raw.observedAt),createdAt:clean(raw.createdAt),updatedAt:clean(raw.updatedAt)
      };
      const quality=evidenceQuality({...raw,...row,legacyIdentified:protocol==="tcp"&&clean(raw.service)&&raw.identified!==false});
      row.identified=quality.identified;
      row.identificationEvidence=clean(raw.identificationEvidence)||quality.kind;
      row.service=row.identified?normalizeServiceName(raw.service||row.serviceRaw,port,protocol):"";
      Object.assign(row,lifecycle(row));
      const current=merged.get(row.id);
      if(!current){merged.set(row.id,row);return;}
      const rank=candidate=>{
        const kind=evidenceQuality(candidate);
        return (candidate.manualConfirmed?500:candidate.protocolResponse?450:token(candidate.serviceMethod)==="probed"&&candidate.identified?400:candidate.identified?350:candidate.probeCommand?200:100)
          +[candidate.product,candidate.version,candidate.extraInfo,candidate.details,candidate.cpe,candidate.serviceFingerprint].filter(Boolean).join(" ").length
          +(candidate.scriptEvidence?20:0)+(kind.identified?10:0);
      };
      const preferred=rank(row)>rank(current)?row:current;
      const other=preferred===row?current:row;
      const evidence=[...(current.evidence||[]),...(row.evidence||[])].filter((item,index,all)=>all.findIndex(other=>JSON.stringify(other)===JSON.stringify(item))===index);
      const combined={...other,...preferred,
        serviceRaw:preferred.serviceRaw||other.serviceRaw,serviceHint:preferred.serviceHint||other.serviceHint,
        product:preferred.product||other.product,version:preferred.version||other.version,
        extraInfo:preferred.extraInfo||other.extraInfo,details:preferred.details||other.details,
        cpe:preferred.cpe||other.cpe,serviceFingerprint:preferred.serviceFingerprint||other.serviceFingerprint,
        active:current.active!==false||row.active!==false,identified:current.identified||row.identified,
        manualConfirmed:current.manualConfirmed||row.manualConfirmed,protocolResponse:current.protocolResponse||row.protocolResponse,
        scriptEvidence:current.scriptEvidence||row.scriptEvidence,operationCompleted:current.operationCompleted||row.operationCompleted,
        enumerationStarted:current.enumerationStarted||row.enumerationStarted,enumerationComplete:current.enumerationComplete||row.enumerationComplete,
        completedChecks:uniqueText([...(current.completedChecks||[]),...(row.completedChecks||[])]),
        enumerationObjectives:uniqueText([...(current.enumerationObjectives||[]),...(row.enumerationObjectives||[])]),
        source:uniqueLabels(current.source,row.source).join(" · "),sourceSlot:uniqueLabels(current.sourceSlot,row.sourceSlot).join(" · "),evidence
      };
      Object.assign(combined,mergeServiceScanCoverage(current,row));
      if(token(current.state)==="open"||token(row.state)==="open")combined.state="open";
      const confirmedService=[preferred,other].find(candidate=>candidate.identified&&meaningfulEvidenceValue(candidate.service||candidate.serviceRaw));
      combined.service=combined.identified?normalizeServiceName(confirmedService?.service||confirmedService?.serviceRaw,port,protocol):"";
      Object.assign(combined,lifecycle(combined));merged.set(row.id,combined);
    });
    return [...merged.values()].sort((a,b)=>a.protocol.localeCompare(b.protocol)||a.port-b.port);
  }
  function commandFromText(text){
    const lines=String(text||"").split(/\r?\n/).slice(0,25);
    const line=lines.find(value=>!/^\s*Nmap scan report for\b/i.test(value)&&/(?:^|\s)(?:sudo\s+)?(?:nmap|autorecon|threader3000|masscan|rustscan|nc|netcat)\b/i.test(value));
    return clean(line||"").replace(/^\s*[#$>]\s*/,"");
  }
  function nmapRunIdentity(command="",text=""){
    let value=clean(command);
    const initiated=/^\s*#\s*Nmap\b[^\r\n]*?\s+as:\s*(.+?)\s*$/im.exec(String(text||""));
    if(initiated)value=clean(initiated[1]);
    return value.replace(/&#x([0-9a-f]+);/gi,(_match,number)=>String.fromCodePoint(Number.parseInt(number,16))).replace(/&#(\d+);/g,(_match,number)=>String.fromCodePoint(Number(number))).replace(/&amp;/g,"&").toLowerCase().replace(/\s+/g," ").trim();
  }
  function commandsFromLog(text){
    const seen=new Set(),commands=[];
    String(text||"").split(/\r?\n/).forEach(raw=>{
      let line=clean(raw);if(!line)return;
      line=line.replace(/^\[[^\]]+\]\s*/,"").replace(/^(?:command|cmd)\s*:\s*/i,"").replace(/^\s*[#$>]\s*/,"");
      const index=line.search(/(?:^|\s)(?:sudo\s+)?(?:env\s+[^\s]+\s+)?(?:[^\s]+\/)?(?:nmap|masscan|rustscan|nikto|wpscan|enum4linux(?:-ng)?|smbclient|snmpwalk|dig)\b/i);
      if(index<0)return;
      const command=clean(line.slice(index));if(!command)return;
      const key=command.toLowerCase();if(seen.has(key))return;
      seen.add(key);commands.push(command);
    });
    return commands;
  }
  function toolFrom(command,text="",filename=""){
    const hay=`${command} ${filename} ${String(text||"").slice(0,500)}`.toLowerCase();
    if(/autorecon/.test(hay))return "AutoRecon";
    if(/threader3000/.test(hay))return "Threader3000";
    if(/rustscan/.test(hay))return "RustScan";
    if(/masscan/.test(hay))return "Masscan";
    if(/\bnmap\b|nmap scan report/.test(hay))return "Nmap";
    if(/\bnetcat\b|\bnc\b/.test(hay))return "Netcat";
    return "Imported scan";
  }
  function fullTcpCoverage(command,servicesRange=""){
    const value=`${command} ${servicesRange}`.toLowerCase().replace(/\s+/g," ");
    return /(?:^|\s)-p-(?:\s|$)/.test(value)||/(?:^|\s)-p\s*1-65535(?:\s|$)/.test(value)||/--ports?\s+1-65535/.test(value)||/services="?1-65535/.test(value)||/numservices="?65535/.test(value)||/all[- ]ports/.test(value);
  }
  function serviceEnumerationCommand(command){
    const value=clean(command);
    return /(?:^|\s)-(?:sV|sC|A)(?:\s|$)|--version-(?:all|intensity)/i.test(value)
      ||/--script(?:=|\s+)(?:["']?[^"' \r\n,]*,?)*(?:banner|service-info|version)[^"' \r\n]*/i.test(value);
  }
  function targetedVulnerabilityCommand(command){
    const value=clean(command);
    return /--script(?:=|\s+)(?:["']?[^\r\n]*?(?:\bvulners\b|\bvuln\s+and\s+safe\b))/i.test(value);
  }
  function udpCommand(command){return /(?:^|\s)-sU(?:\s|$)/i.test(command);}
  function commandTokens(command){const rows=[];String(command||"").replace(/"([^"]*)"|'([^']*)'|(\S+)/g,(_match,doubleQuoted,singleQuoted,bare)=>{rows.push(doubleQuoted??singleQuoted??bare);return "";});return rows;}
  function optionValue(tokens,names){for(let index=0;index<tokens.length;index++){const item=tokens[index],lower=token(item);for(const name of names){if(lower===token(name))return clean(tokens[index+1]);if(lower.startsWith(`${token(name)}=`))return clean(item.slice(name.length+1));}}return "";}
  function safeRedirectPath(tokens){for(let index=0;index<tokens.length;index++){const item=tokens[index];if(item===">"||item===">>")return normalizePath(tokens[index+1]);const match=/^>>?(.+)$/.exec(item);if(match)return normalizePath(match[1]);}return "";}
  function scanScopeLike(value){
    const item=clean(value).replace(/^['"]|['"]$/g,"");
    return /\/(?:\d|[12]\d|3[0-2]|12[0-8])$/.test(item)||/[*,]/.test(item)||/^(?:\d{1,3}[.]){3}\d{1,3}-(?:(?:\d{1,3}[.]){3})?\d{1,3}$/.test(item);
  }
  function hostLike(value){
    const raw=clean(value);if(!raw||scanScopeLike(raw)||/[\\/]/.test(raw.replace(/^https?:\/\//i,"")))return "";
    const item=targetToken(raw);
    return /^(?:\d{1,3}[.]){3}\d{1,3}$/.test(item)||(/:/.test(item)&&/^[0-9a-f:]+$/i.test(item))||/^(?=.{1,253}$)(?=.*[a-z])[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/i.test(item)?item:"";
  }
  function operationFromCommand(command,index=0){
    const value=clean(command),tokens=commandTokens(value);const tool=(value.match(/(?:^|\s)(?:sudo\s+)?(?:[^\s]+\/)?(nmap|nikto|wpscan|masscan|rustscan|enum4linux(?:-ng)?|smbclient|snmpwalk|dig)\b/i)||[])[1]?.toLowerCase()||"unknown";
    const outputs=[];let target="",targetCandidates=[],scanScopes=[],protocol="tcp",port=0;
    if(tool==="nmap"||tool==="masscan"||tool==="rustscan"){
      const consumesValue=new Set(["-on","-ox","-og","-oa","-il","-p","--ports","--top-ports","--exclude","--excludefile","--script","--script-args","-d","-e","-g","-s","-t","--host-timeout","--max-retries","--min-rate","--max-rate"]);
      const positional=[];
      for(let i=0;i<tokens.length;i++){
        const item=tokens[i],option=token(item);
        if(["-on","-ox","-og"].includes(option)&&tokens[i+1]){outputs.push(tokens[++i]);continue;}
        if(option==="-oa"&&tokens[i+1]){const base=tokens[++i];outputs.push(`${base}.nmap`,`${base}.xml`,`${base}.gnmap`);continue;}
        if(option==="-il"&&tokens[i+1]){scanScopes.push(`input-list:${normalizePath(tokens[++i])}`);continue;}
        if(option.startsWith("-il=")&&item.slice(4)){scanScopes.push(`input-list:${normalizePath(item.slice(4))}`);continue;}
        if(option.startsWith("-il")&&item.length>3){scanScopes.push(`input-list:${normalizePath(item.slice(3))}`);continue;}
        if(item===">"||item===">>"){i++;continue;}
        if(/^>>?/.test(item))continue;
        if(option.startsWith("-")&&option.includes("="))continue;
        if(consumesValue.has(option)){i++;continue;}
        if(option.startsWith("-")||/^(?:sudo|env|nmap|masscan|rustscan)$/i.test(item)||/^[a-z_][a-z0-9_]*=/i.test(item))continue;
        positional.push(item);
      }
      const portMatch=value.match(/(?:^|\s)-p\s*([TU]:)?(\d{1,5})/i);port=Number(portMatch?.[2])||0;protocol=udpCommand(value)||token(portMatch?.[1]).startsWith("u")?"udp":"tcp";
      positional.forEach(item=>{if(scanScopeLike(item))scanScopes.push(item);else{const candidate=hostLike(item);if(candidate)targetCandidates.push(candidate);}});
      targetCandidates=uniqueText(targetCandidates);
      if(targetCandidates.length>1){scanScopes.push(...targetCandidates);targetCandidates=[];}
      target=targetCandidates.length===1?targetCandidates[0]:"";
    }else if(tool==="nikto"){
      const hostValue=optionValue(tokens,["-h","-host"]);target=hostnameFromUrl(hostValue)||hostLike(hostValue);port=Number(optionValue(tokens,["-p","-port"]))||portFromUrl(hostValue)||0;outputs.push(optionValue(tokens,["-o","-output"]));
    }else if(tool==="wpscan"){
      const url=optionValue(tokens,["--url"]);target=hostnameFromUrl(url)||hostLike(url);port=portFromUrl(url);outputs.push(optionValue(tokens,["--output","-o"]));
    }else if(/^enum4linux/.test(tool)){
      const positional=tokens.slice(1).map(hostLike).filter(Boolean);target=positional[positional.length-1]||"";outputs.push(optionValue(tokens,["-o","--output"]));
    }else if(tool==="smbclient"){
      const share=tokens.find(item=>/^\/\//.test(item))||optionValue(tokens,["-L","--list"]);target=hostLike(targetToken(share));port=Number(optionValue(tokens,["-p","--port"]))||445;
    }else if(tool==="snmpwalk"){
      protocol="udp";port=Number(optionValue(tokens,["-p","--port"]))||161;const valueOptions=new Set(["-v","-c","-p","-t","-r","-l","-u","-a","-x"]);const candidates=tokens.slice(1).filter((item,itemIndex)=>!(itemIndex>=0&&valueOptions.has(token(tokens[itemIndex])))).map(hostLike).filter(Boolean);target=candidates[0]||"";
    }else if(tool==="dig"){
      protocol=tokens.some(item=>token(item)==="+tcp")?"tcp":"udp";port=Number(optionValue(tokens,["-p"]))||53;target=hostLike((tokens.find(item=>item.startsWith("@"))||"").slice(1));
    }
    const redirected=safeRedirectPath(tokens);if(redirected)outputs.push(redirected);
    const outputPaths=uniqueText(outputs.filter(Boolean).map(normalizePath));
    if(!targetCandidates.length&&target)targetCandidates=uniqueText([targetToken(target)]);
    return {id:`operation-${index}`,command:value,tool,outputPaths,outputPath:outputPaths[0]||"",target:targetToken(target),targetCandidates,scanScopes:uniqueText(scanScopes),protocol,port,status:"unverified",reason:"Command recorded; matching completed output is required."};
  }
  function resultState(text){
    const value=String(text||"");
    if(/\b(?:fatal|aborted|interrupted|timed out|timeout|connection refused|unreachable)\b/i.test(value))return "failed";
    if(/\bpartial\b|\bincomplete\b/i.test(value))return "partial";
    return value.trim()?"completed":"unverified";
  }
  function portExpressionCount(expression=""){
    let count=0;
    clean(expression).split(",").map(value=>value.trim()).filter(Boolean).forEach(value=>{
      const range=/^(\d{1,5})-(\d{1,5})$/.exec(value);
      if(range){const start=Number(range[1]),end=Number(range[2]);if(start>=1&&end<=65535&&end>=start)count+=end-start+1;return;}
      const port=Number(value);if(Number.isInteger(port)&&port>=1&&port<=65535)count++;
    });
    return count;
  }
  function commandIncludesProtocol(command="",protocol="tcp"){
    const value=clean(command),udp=protocol==="udp",hasUdp=udpCommand(value);
    if(udp)return hasUdp;
    return !hasUdp||/(?:^|\s)-s(?:S|T|A|N|F|X|M|W)(?:\s|$)/i.test(value)||/(?:^|\s)-p\s*T:/i.test(value);
  }
  function commandCoverage(command="",protocol="tcp"){
    const value=clean(command),udp=protocol==="udp";
    if(!commandIncludesProtocol(value,protocol))return {scannedPortCount:0,scannedPortExpression:"",bounded:false,full:false};
    const top=/--top-ports(?:=|\s+)(\d{1,5})/i.exec(value);
    if(top)return {scannedPortCount:Number(top[1]),scannedPortExpression:`top-${Number(top[1])}`,bounded:true,full:false};
    if((udp?udpCommand(value):!udpCommand(value))&&fullTcpCoverage(value))return {scannedPortCount:65535,scannedPortExpression:"1-65535",bounded:false,full:true};
    const specific=new RegExp(`(?:^|\\s)-p\\s*(?:${udp?"U":"T"}:)?([0-9,\\-]+)(?=\\s|$)`,"i").exec(value);
    if(specific){
      const expression=specific[1],count=portExpressionCount(expression);
      if(count)return {scannedPortCount:count,scannedPortExpression:expression,bounded:count<65535,full:count===65535};
    }
    return {scannedPortCount:0,scannedPortExpression:"",bounded:false,full:false};
  }
  function portInExpression(port,expression=""){
    const target=Number(port);if(!Number.isInteger(target)||target<1||target>65535)return false;
    return clean(expression).split(",").map(value=>value.trim()).filter(Boolean).some(value=>{
      const range=/^(\d{1,5})-(\d{1,5})$/.exec(value);
      if(range)return target>=Number(range[1])&&target<=Number(range[2]);
      return Number(value)===target;
    });
  }
  function serviceScanCoverageForEndpoint(row={},context={}){
    const serviceRequested=context.serviceRequested===true;
    const recognized=context.recognized===true;
    const operationStatus=token(context.operationStatus);
    const scope=context.scope||{};
    const inScope=scope.full===true||portInExpression(row.port,scope.scannedPortExpression)
      ||(Number(scope.scannedPortCount)===1&&Number(row.port)>0&&Number(context.exactPort)===Number(row.port));
    if(!serviceRequested)return {state:SERVICE_SCAN_COVERAGE.NOT_RUN,reason:"No completed service/version scan covers this endpoint."};
    if(operationStatus==="failed")return {state:SERVICE_SCAN_COVERAGE.FAILED,reason:"The service/version scan failed before coverage could complete."};
    if(operationStatus==="partial")return {state:SERVICE_SCAN_COVERAGE.PARTIAL,reason:"The service/version scan is partial."};
    if(operationStatus!=="completed"||!recognized)return {state:SERVICE_SCAN_COVERAGE.INCOMPLETE,reason:"The service/version result is incomplete or unrecognized."};
    if(!inScope)return {state:SERVICE_SCAN_COVERAGE.NOT_RUN,reason:"This endpoint is outside the retained service/version scan scope."};
    return {state:SERVICE_SCAN_COVERAGE.COMPLETED,reason:"A completed service/version scan processed this exact endpoint."};
  }
  function mergeServiceScanCoverage(current={},candidate={}){
    const currentState=token(current.serviceScanCoverageState)||SERVICE_SCAN_COVERAGE.NOT_RUN;
    const candidateState=token(candidate.serviceScanCoverageState)||SERVICE_SCAN_COVERAGE.NOT_RUN;
    const preferred=(SERVICE_SCAN_COVERAGE_RANK[candidateState]||0)>(SERVICE_SCAN_COVERAGE_RANK[currentState]||0)?candidate:current;
    return {
      serviceScanCoverageState:token(preferred.serviceScanCoverageState)||SERVICE_SCAN_COVERAGE.NOT_RUN,
      serviceScanCoverageReason:clean(preferred.serviceScanCoverageReason),
      serviceScanCoverageSource:clean(preferred.serviceScanCoverageSource||preferred.source),
      serviceScanCoverageCommand:clean(preferred.serviceScanCoverageCommand||preferred.command)
    };
  }
  function stateSummaryFromText(text="",services=[],protocol="",command=""){
    const summary={};
    const add=(state,count=1)=>{const key=token(state);if(!key||!Number.isFinite(Number(count))||Number(count)<1)return;summary[key]=(summary[key]||0)+Number(count);};
    const selected=token(protocol);
    (Array.isArray(services)?services:[]).filter(row=>!selected||token(row.protocol)===selected).forEach(row=>add(row.state||"open"));
    const scannedLine=/^\s*#\s*Ports scanned:\s*TCP\((\d+);([^)]*)\)\s+UDP\((\d+);([^)]*)\)/im.exec(String(text||""));
    const protocolHasScope=()=>{
      if(!selected)return true;
      if(scannedLine)return Number(scannedLine[selected==="udp"?3:1])>0;
      return commandIncludesProtocol(command,selected);
    };
    String(text||"").split(/\r?\n/).forEach(line=>{
      let match=line.match(/\bNot shown:\s*(\d+)\s+(closed|filtered|open\|filtered)\s+(?:tcp|udp)\s+ports?\b/i);
      if(match){
        const lineProtocol=(/\s+(tcp|udp)\s+ports?\b/i.exec(line)||[])[1]||"";
        if(!selected||token(lineProtocol)===selected)add(match[2],Number(match[1]));
        return;
      }
      match=line.match(/\bIgnored State:\s*(closed|filtered|open\|filtered)\s*\((\d+)\)/i);
      if(match){if(protocolHasScope())add(match[1],Number(match[2]));return;}
      match=line.match(/\bAll\s+(\d+)\s+scanned ports?.*?\bare\s+(closed|filtered|open\|filtered)\b/i);
      if(match&&protocolHasScope())add(match[2],Number(match[1]));
    });
    return summary;
  }
  function coverageFactsFromText(text="",command="",services=[]){
    const raw=String(text||""),hostState=/\bHost seems down\b/i.test(raw)?"down":/\bHost is up\b/i.test(raw)||/\bStatus:\s*Up\b/i.test(raw)?"up":/\bStatus:\s*Down\b/i.test(raw)?"down":"unknown";
    const scanned={tcp:commandCoverage(command,"tcp"),udp:commandCoverage(command,"udp")};
    const scannedLine=/^\s*#\s*Ports scanned:\s*TCP\((\d+);([^)]*)\)\s+UDP\((\d+);([^)]*)\)/im.exec(raw);
    if(scannedLine){
      scanned.tcp={scannedPortCount:Number(scannedLine[1])||0,scannedPortExpression:clean(scannedLine[2]),bounded:Number(scannedLine[1])>0&&Number(scannedLine[1])<65535,full:Number(scannedLine[1])===65535};
      scanned.udp={scannedPortCount:Number(scannedLine[3])||0,scannedPortExpression:clean(scannedLine[4]),bounded:Number(scannedLine[3])>0&&Number(scannedLine[3])<65535,full:Number(scannedLine[3])===65535};
    }
    const summary=stateSummaryFromText(raw,services);
    scanned.tcp.endpointStateSummary=stateSummaryFromText(raw,services,"tcp",command);
    scanned.udp.endpointStateSummary=stateSummaryFromText(raw,services,"udp",command);
    return {hostState,endpointStateSummary:summary,tcp:scanned.tcp,udp:scanned.udp};
  }
  function correlateAutoRecon(commandText,errorText,outputs=[]){
    const operations=commandsFromLog(commandText).map(operationFromCommand),unmatchedErrors=[];
    const normalized=(value)=>normalizePath(value).toLowerCase();
    (Array.isArray(outputs)?outputs:[]).forEach(output=>{
      const path=normalized(output.path||output.filename),match=operations.find(op=>(op.outputPaths||[]).some(candidate=>path.endsWith(normalized(candidate))));
      if(!match)return;
      const next=resultState(output.text),rank={unverified:0,completed:1,partial:2,failed:3};if((rank[next]||0)>=(rank[match.status]||0))match.status=next;match.resultPath=clean(output.path||output.filename);match.resultPaths=uniqueText([...(match.resultPaths||[]),match.resultPath]);match.reason=match.status==="completed"?"Matching result output completed.":`Matching result output is ${match.status}.`;
    });
    String(errorText||"").split(/\r?\n/).map(clean).filter(Boolean).forEach(line=>{
      const normalizedLine=normalized(line);const match=operations.find(op=>(op.outputPaths||[]).some(candidate=>normalizedLine.includes(normalized(candidate)))||line.includes(op.command));
      if(match){match.status="failed";match.error=line;match.reason="A matching AutoRecon error prevents completion.";}else unmatchedErrors.push(line);
    });
    const resultPathLookup={};operations.forEach(operation=>{(operation.resultPaths||[]).forEach(path=>{resultPathLookup[normalized(path)]=operation;});(operation.outputPaths||[]).forEach(candidate=>{const key=normalized(candidate);if(key&&!resultPathLookup[key])resultPathLookup[key]=operation;});});
    return {operations,unmatchedErrors,resultPathLookup};
  }
  function operationForPath(correlation,path=""){
    const value=normalizePath(path).toLowerCase();if(!value)return null;
    if(correlation?.resultPathLookup?.[value])return correlation.resultPathLookup[value];
    const keys=Object.keys(correlation?.resultPathLookup||{}).sort((a,b)=>b.length-a.length);const suffix=keys.find(key=>value.endsWith(key));
    return suffix?correlation.resultPathLookup[suffix]:null;
  }
  function incompleteObjectives(parsed,status,reason){
    const objectives={...(parsed.objectives||{})};["tcpDiscovery","serviceEnumeration","udpDiscovery","targetedVulnerability"].forEach(key=>{objectives[key]={...(objectives[key]||{}),confirmed:false,coverage:status,reason};});return objectives;
  }
  function applyOperationAuthority(parsed,operation){
    if(!parsed)return parsed;const status=clean(operation?.status)||"unverified",reason=clean(operation?.reason)||(status==="completed"?"Matching result output completed.":`The routed operation is ${status}.`);
    const result={...parsed,operationStatus:status,operationCompleted:status==="completed",status,error:clean(operation?.error),resultReason:reason,command:clean(operation?.command)||parsed.command||"",operation:{id:operation?.id||"",tool:operation?.tool||parsed.tool||parsed.source||"",target:operation?.target||"",protocol:operation?.protocol||"",port:Number(operation?.port)||0,outputPath:operation?.outputPath||"",resultPath:operation?.resultPath||"",status,error:clean(operation?.error),reason}};
    if(status==="completed")return result;
    result.objectives=incompleteObjectives(result,status,reason);result.operationCompleted=false;result.completedChecks=[];result.enumerationObjectives=[];result.enumerationCoverage="none";result.negativeCompleted=false;result.vulnerabilityLeads=[];
    if(status==="unverified")result.services=[];
    else result.services=mergeServices((result.services||[]).map(row=>({...row,identified:false,manualConfirmed:false,protocolResponse:false,probeCommand:false,product:"",version:"",extraInfo:"",cpe:"",service:"",probeResult:status==="failed"?"failed":"partial",operationStatus:status,operationCompleted:false,enumerationStarted:false,enumerationComplete:false,completedChecks:[],enumerationObjectives:[],enumerationCoverage:"none",details:clean(row.details)||`Explicit endpoint evidence retained under a ${status} operation.`})));
    return result;
  }
  function resolveParsedTarget(parsed,selectedTarget,context={}){
    const operation=context.operation||parsed?.operation||null;
    const aliases=context.targetIdentity?.aliases||context.mappings||[];
    const candidates=uniqueText([...(parsed?.targetCandidates||[]),parsed?.target,...targetCandidatesFromCommand(parsed?.command||""),...(operation?.targetCandidates||[]),operation?.target,context.folderTarget,knownPathTarget(context.filename||"",aliases)].filter(Boolean));
    const mappings=uniqueText([...(Array.isArray(context.mappings)?context.mappings:[]),...(parsed?.scopedTargetAliases||[])]);
    const ownership=resolveTargetOwnership(selectedTarget,candidates,{mappings,requireEvidence:context.requireEvidence===true,manualFallback:context.manualFallback===true});
    return {...parsed,...ownership,targetCandidates:ownership.targetCandidates};
  }
  function endpointFromPath(filename=""){
    const value=clean(filename).replace(/\\/g,"/");
    const match=value.match(/(?:^|\/)(tcp|udp)[_\/-]?(\d{1,5})(?:[_\/-]|$)/i)||value.match(/(?:^|\/)(?:tcp|udp)?[_-]?(\d{1,5})[_-](?:http|https|smb|microsoft-ds|snmp|dns|domain)/i);
    if(!match)return {protocol:"",port:0};
    return match.length>2&&/^(tcp|udp)$/i.test(match[1])?{protocol:token(match[1]),port:Number(match[2])}:{protocol:/udp/i.test(value)?"udp":"tcp",port:Number(match[1])};
  }
  function parseToolOutput(text,options={}){
    const raw=String(text||""),filename=clean(options.filename),lower=`${filename} ${clean(options.command)} ${raw.slice(0,500)}`.toLowerCase(),status=resultState(raw),commandOperation=operationFromCommand(options.command||"",-1);
    const pathEndpoint=endpointFromPath(filename),rawPort=Number((/^\s*(?:\+\s*)?Target Port\s*:\s*(\d{1,5})/im.exec(raw)||[])[1])||0;
    const route=`${filename} ${clean(options.command)}`;
    const tool=(/nikto/i.test(route)||/^\s*Nikto\b/im.test(raw))?"Nikto":(/wpscan/i.test(route)||/^\s*WPScan\b/im.test(raw))?"WPScan":/vulners/i.test(filename)?"Vulners":/(?:smb|microsoft-ds).*(?:nse|vuln)|(?:smb-[a-z0-9_.-]+)\s*:/i.test(lower)?"SMB NSE":(/\bsnmpwalk\b/i.test(options.command||"")||/sysDescr|SNMPv\d|iso[.]3[.]6[.]1/i.test(raw))?"SNMP":(/(?:^|\s)dig(?:\s|$)/i.test(options.command||"")||/status:\s*(?:NOERROR|NXDOMAIN)|ANSWER SECTION|SERVER:/i.test(raw))?"DNS":/nse/i.test(filename)?"Nmap NSE":"";
    if(!tool)return null;
    const endpoint={protocol:pathEndpoint.protocol||commandOperation.protocol||(tool==="SNMP"||tool==="DNS"?"udp":"tcp"),port:pathEndpoint.port||rawPort||commandOperation.port||0};
    let service="";if(tool==="Nikto"||tool==="WPScan")service=/ssl|https|443|8443/i.test(`${filename} ${raw.slice(0,300)}`)?"https":"http";else if(tool==="SMB NSE")service="smb";else if(tool==="SNMP")service="snmp";else if(tool==="DNS")service="dns";
    const protocolProof=status==="completed"&&((tool==="Nikto"&&/Nikto v|Target (?:IP|Host|Port)|Server:/i.test(raw))||(tool==="WPScan"&&/WordPress version|WordPress found|WordPress readme found/i.test(raw))||(tool==="SMB NSE"&&/smb|netbios|workgroup|dialect|message signing/i.test(raw))||(tool==="SNMP"&&/sysDescr|SNMPv\d|iso[.]3[.]6[.]1/i.test(raw))||(tool==="DNS"&&/status:\s*(?:NOERROR|NXDOMAIN)|ANSWER SECTION|SERVER:/i.test(raw)));
    const script=(raw.match(/\b((?:smb|ssl|http|ssh|ftp|dns|snmp)-[a-z0-9_.-]+)\s*:/i)||[])[1]||(/vulners/i.test(lower)?"vulners":"");
    const check=tool==="Nikto"?"nikto-web-vulnerability-scan":tool==="WPScan"?"wpscan-wordpress-assessment":tool==="SMB NSE"?(script||"smb-nse-check"):tool==="Vulners"?"vulners":tool==="Nmap NSE"?(script||"nmap-nse-check"):tool==="SNMP"?(/snmpwalk/i.test(options.command||filename)?"snmp-walk":"snmp-response"):tool==="DNS"?"dns-query":"";
    const fullEnumeration=status==="completed"&&(options.fullServiceEnumeration===true||token(options.enumerationCoverage)==="full");
    const checkProof=protocolProof||(tool==="Vulners"&&/\bvulners\b|\bCVE-\d{4}-\d+\b|\bno findings\b/i.test(raw))||(tool==="Nmap NSE"&&!!script);
    const completedChecks=status==="completed"&&check&&checkProof?[check]:[],enumerationObjectives=completedChecks.slice();
    const services=endpoint.port&&protocolProof&&service?[{...endpoint,state:"open",service,serviceRaw:service,identified:true,protocolResponse:true,operationStatus:status,operationCompleted:status==="completed",enumerationStarted:status==="completed",enumerationComplete:fullEnumeration,completedChecks,enumerationObjectives,enumerationCoverage:fullEnumeration?"full":"check-specific",source:tool,details:"Protocol-specific result evidence",probeResult:"completed"}]:[];
    const vulnerabilityLeads=status==="completed"?vulnerabilityLeadsFromEvidence(raw,{...endpoint,service,script:tool,source:tool}):[];
    const exactTargeted=completedChecks.length>0&&(["Nikto","WPScan","Vulners"].includes(tool)||(["SMB NSE","Nmap NSE"].includes(tool)&&/vuln|vulners/i.test(check)));
    const candidates=uniqueText([...targetCandidatesFromText(raw,tool),...targetCandidatesFromCommand(options.command||""),options.target,knownPathTarget(filename,options.targetMappings||[])].filter(Boolean));
    const ownership=resolveTargetOwnership(options.activeTarget||"",candidates,{mappings:options.targetMappings,manualFallback:options.manualFallback===true,requireEvidence:options.requireTargetEvidence===true});
    return {format:"tool-output",source:tool,tool,status,operationStatus:status,operationCompleted:status==="completed",negativeCompleted:status==="completed"&&!vulnerabilityLeads.length,resultReason:status==="completed"?"Completed result output is preserved.":`Result is ${status}; no objective is completed.`,command:clean(options.command),services:mergeServices(services),vulnerabilityLeads:mergeVulnerabilityLeads(vulnerabilityLeads),completedChecks,enumerationObjectives,enumerationCoverage:fullEnumeration?"full":completedChecks.length?"check-specific":"none",tcpPorts:endpoint.protocol==="tcp"&&endpoint.port?[endpoint.port]:[],udpPorts:endpoint.protocol==="udp"&&endpoint.port?[endpoint.port]:[],hasOutput:!!raw.trim(),rawText:raw,...ownership,endpoint,objectives:{tcpDiscovery:{confirmed:false},serviceEnumeration:{confirmed:fullEnumeration,coverage:fullEnumeration?"complete":"check-specific",reason:fullEnumeration?"Explicit evidence defines complete service-enumeration coverage.":"The completed tool operation covers only its exact check."},udpDiscovery:{confirmed:false},targetedVulnerability:{confirmed:exactTargeted,coverage:exactTargeted?"check-specific":"unknown",ports:endpoint.port?[endpoint.port]:[],reason:exactTargeted?`Completed ${check||tool} check is recorded.`:"No targeted vulnerability-check completion is recorded."}}};
  }
  function parseCommandLog(text,options={}){
    const commands=commandsFromLog(text);
    const operations=commands.map(operationFromCommand);
    const udpCommands=commands.filter(udpCommand);
    const source=clean(options.source)||(/autorecon|_commands[.]log/i.test(`${options.filename||""} ${text||""}`)?"AutoRecon":"Imported command log");
    const udpEvidence=udpCommands.join("\n");
    const candidates=uniqueText([...operations.flatMap(row=>row.targetCandidates||[]),knownPathTarget(options.filename||"",options.targetMappings||[])].filter(Boolean));
    const ownership=resolveTargetOwnership(options.activeTarget||"",candidates,{mappings:options.targetMappings,manualFallback:options.manualFallback===true,requireEvidence:options.requireTargetEvidence===true});
    return {
      format:"command-log",source,command:udpCommands[0]||"",commands,operations,services:[],vulnerabilityLeads:[],tcpPorts:[],udpPorts:[],hasOutput:commands.length>0,...ownership,
      rawText:udpEvidence,
      objectiveEvidence:{udpDiscovery:udpEvidence},
      objectives:{
        tcpDiscovery:{confirmed:false,coverage:"unknown",reason:"Command history alone does not confirm complete TCP-port coverage."},
        serviceEnumeration:{confirmed:false,coverage:"unknown",reason:"Command history alone does not confirm complete service-enumeration coverage."},
        udpDiscovery:{confirmed:false,coverage:udpCommands.length?"scheduled":"unknown",resultState:udpCommands.length?"unverified":"",reason:udpCommands.length?"AutoRecon command history records UDP work, but output is required to prove completion.":"No UDP scan command was found in the command history."},
        targetedVulnerability:{confirmed:false,coverage:"unknown",ports:[],reason:"Command history alone does not confirm a completed targeted vulnerability check."}
      }
    };
  }
  function grepableNmapServices(text,{command="",source="",objectiveHint=""}={}){
    const rows=[];
    String(text||"").split(/\r?\n/).forEach(line=>{
      const match=line.match(/^\s*Host:\s+(\S+)(?:\s+\([^)]*\))?\s+Ports:\s+([^\t]+)(?:\t|$)/i);
      if(!match)return;
      const targetAddress=targetToken(match[1]);
      match[2].split(/,\s*/).forEach(entry=>{
        const fields=entry.trim().split("/");
        const port=Number(fields[0]),state=token(fields[1]),protocol=token(fields[2]);
        if(!Number.isInteger(port)||port<1||port>65535||!["tcp","udp"].includes(protocol)||!state.startsWith("open"))return;
        const serviceRaw=meaningfulEvidenceValue(fields[4])||"unknown",banner=meaningfulEvidenceValue(fields.slice(6).join("/"));
        const probeCommand=serviceEnumerationCommand(command),split=probeCommand?splitBanner(banner):{product:"",version:"",extraInfo:"",details:""};
        const credibleService=!!serviceRaw&&!["unknown","general","tcpwrapped"].includes(token(serviceRaw));
        const identified=probeCommand&&credibleService&&!!split.details;
        rows.push({
          port,protocol,state,service:identified?normalizeServiceName(serviceRaw,port,protocol):"",
          serviceRaw,serviceHint:serviceHint(serviceRaw,port,protocol),product:split.product,version:split.version,
          details:split.details,extraInfo:split.extraInfo,scriptEvidence:false,probeCommand,
          probeCompleted:probeCommand,
          probeResult:protocol==="udp"&&probeCommand&&!banner?"completed-inconclusive":"",identified,
          targetAddress,observedTargetAddress:targetAddress,source,sourceSlot:clean(objectiveHint),command
        });
      });
    });
    return rows;
  }
  function nmapEndpointEvidenceSlice(raw,protocol,port){
    const source=String(raw??""),normalizedProtocol=token(protocol),normalizedPort=Number(port);
    if(!source||!["tcp","udp"].includes(normalizedProtocol)||!Number.isInteger(normalizedPort)||normalizedPort<1||normalizedPort>65535)return source;

    const xmlPattern=new RegExp(`<port\\b(?=[^>]*\\bprotocol=["']${normalizedProtocol}["'])(?=[^>]*\\bportid=["']${normalizedPort}["'])[^>]*>[\\s\\S]*?<\\/port>`,`i`),xmlMatch=source.match(xmlPattern);
    if(xmlMatch)return xmlMatch[0];

    const lines=source.replace(/\r/g,"").split("\n"),portHeader=/^\s*(\d{1,5})\/(tcp|udp)\s+\S+(?:\s+.*)?$/i,headers=[];
    lines.forEach((line,index)=>{const match=line.match(portHeader);if(match)headers.push({index,port:Number(match[1]),protocol:token(match[2])});});
    if(headers.length){
      const selectedIndex=headers.findIndex(row=>row.port===normalizedPort&&row.protocol===normalizedProtocol);
      if(selectedIndex<0)return "";
      const start=headers[selectedIndex].index,end=selectedIndex+1<headers.length?headers[selectedIndex+1].index:lines.length;
      return lines.slice(start,end).join("\n").trim();
    }

    const grepLine=lines.find(line=>/^\s*Host:\s+\S+/i.test(line)&&/\bPorts:\s*/i.test(line));
    if(grepLine){
      const ports=(grepLine.split(/\bPorts:\s*/i)[1]||"").split(/,\s*/);
      const selected=ports.find(value=>{const fields=value.trim().split("/");return Number(fields[0])===normalizedPort&&token(fields[2])===normalizedProtocol;});
      return selected?selected.trim():"";
    }
    return source;
  }

  function parseNmapText(text,options={}){
    const raw=String(text||""); const command=clean(options.command)||commandFromText(raw); const source=clean(options.source)||toolFrom(command,raw,options.filename);
    const services=grepableNmapServices(raw,{command,source,objectiveHint:options.objectiveHint}); const vulnerabilityLeads=[]; const scriptChecks=[]; let current=null,currentScript="";
    raw.split(/\r?\n/).forEach(line=>{
      const match=line.match(/^\s*(\d{1,5})\/(tcp|udp)\s+(open(?:\|filtered)?|filtered|closed)\s+(\S+)(?:\s+(.+?))?\s*$/i);
      if(match){
        const port=Number(match[1]),protocol=token(match[2]),state=token(match[3]),serviceRaw=clean(match[4]),banner=clean(match[5]);
        const probeCommand=serviceEnumerationCommand(command);
        const split=probeCommand?splitBanner(banner):{product:"",version:"",extraInfo:"",details:""};
        const credibleService=!!meaningfulEvidenceValue(serviceRaw)&&!["unknown","general","tcpwrapped"].includes(token(serviceRaw));
        const identified=probeCommand&&credibleService&&!!split.details;
        current={port,protocol,state,service:identified?normalizeServiceName(serviceRaw,port,protocol):"",serviceRaw,serviceHint:serviceHint(serviceRaw,port,protocol),product:split.product,version:split.version,details:split.details,extraInfo:split.extraInfo,scriptEvidence:false,probeCommand,probeCompleted:probeCommand,probeResult:protocol==="udp"&&probeCommand&&!split.details?"completed-inconclusive":"",identified,source,sourceSlot:clean(options.objectiveHint),command,_directEvidence:[]};
        currentScript="";
        if(state.startsWith("open"))services.push(current);
        return;
      }
      if(current&&/^\s*[|\\]/.test(line)&&clean(line.replace(/^\s*[|\\]_?\s?/,""))){
        current._directEvidence.push(clean(line.replace(/^\s*[|\\]_?\s?/,"")));
        current.scriptEvidence=true;
        const scriptMatch=line.match(/^\s*[|\\]_?\s*([a-z0-9][a-z0-9_.-]+):\s*(.*)$/i);
        if(scriptMatch){currentScript=clean(scriptMatch[1]);scriptChecks.push(currentScript);current.completedChecks=uniqueText([...(current.completedChecks||[]),currentScript]);current.enumerationObjectives=uniqueText([...(current.enumerationObjectives||[]),currentScript]);}
        vulnerabilityLeads.push(...vulnerabilityLeadsFromEvidence(line,{...current,script:currentScript,source}));
        return;
      }
      if(current&&/^\s*SF:|^\s*SF-Port/i.test(line))current._directEvidence.push(clean(line.replace(/^\s*SF:/i,"")));
    });
    services.forEach(row=>applyDeterministicProtocolEvidence(row,row._directEvidence||[]));
    const tcpPorts=unique(services.filter(row=>row.protocol==="tcp").map(row=>row.port));
    const udpPorts=unique(services.filter(row=>row.protocol==="udp").map(row=>row.port));
    const hasOutput=raw.trim().length>0;
    const scanResultRecognized=services.length>0||/^\s*Nmap scan report for\b/im.test(raw)||/^\s*Host:\s+\S+(?:\s+\([^)]*\))?(?:\s+Ports:|\s+Status:)/im.test(raw)||/^\s*#?\s*Nmap done\b/im.test(raw)||/\bAll\s+\d+\s+scanned ports\b/i.test(raw)||/\b\d+\s+ports? scanned\b/i.test(raw)||/^\s*#\s*Ports scanned:/im.test(raw);
    const runState=resultState(raw),completed=runState==="completed";
    const hint=token(options.objectiveHint);
    const fullTcp=fullTcpCoverage(command)||((hint==="port"||hint==="tcp-discovery")&&hasOutput&&options.trustObjectiveHint!==false);
    const serviceEnum=serviceEnumerationCommand(command)||services.some(row=>row.product||row.version)||((hint==="tcp"||hint==="service")&&hasOutput&&options.trustObjectiveHint!==false);
    const udp=udpCommand(command)||udpPorts.length>0||((hint==="udp")&&hasOutput&&options.trustObjectiveHint!==false);
    const targetedVulnerability=targetedVulnerabilityCommand(command)||scriptChecks.some(value=>/vuln|vulners/i.test(value))||vulnerabilityLeads.length>0||((hint==="vuln")&&hasOutput&&options.trustObjectiveHint!==false);
    const candidates=uniqueText([...targetCandidatesFromText(raw,"Nmap"),...targetCandidatesFromCommand(command),knownPathTarget(options.filename||"",options.targetMappings||[])].filter(Boolean));
    const ownership=resolveTargetOwnership(options.activeTarget||"",candidates,{mappings:options.targetMappings,manualFallback:options.manualFallback===true,requireEvidence:options.requireTargetEvidence===true});
    const coverageFacts=coverageFactsFromText(raw,command,services);
    const tcpScope=coverageFacts.tcp,udpScope=coverageFacts.udp;
    services.forEach(row=>{
      const coverage=serviceScanCoverageForEndpoint(row,{
        serviceRequested:serviceEnumerationCommand(command),recognized:scanResultRecognized,operationStatus:runState,
        scope:row.protocol==="udp"?udpScope:tcpScope,exactPort:operationFromCommand(command,-1).port
      });
      row.serviceScanCoverageState=coverage.state;row.serviceScanCoverageReason=coverage.reason;
      row.serviceScanCoverageSource=source;row.serviceScanCoverageCommand=command;
      delete row._directEvidence;
    });
    const representation=/[.]gnmap$/i.test(clean(options.filename))
      ||/^\s*Host:\s+\S+(?:\s+\([^)]*\))?(?:\s+Ports:|\s+Status:)/im.test(raw)
      ?"grepable":"normal";
    const parsed={
      format:"text",representation,runIdentity:nmapRunIdentity(command,raw),source,command,status:runState,operationStatus:runState,operationCompleted:completed,scanResultRecognized,completedChecks:completed?uniqueText(scriptChecks):[],enumerationObjectives:completed?uniqueText(scriptChecks):[],enumerationCoverage:completed&&options.fullServiceEnumeration===true?"full":scriptChecks.length?"check-specific":"none",services:mergeServices(services.map(row=>({...row,operationStatus:runState,operationCompleted:completed,enumerationStarted:completed&&(row.probeCommand===true||(row.completedChecks||[]).length>0),enumerationComplete:completed&&options.fullServiceEnumeration===true,enumerationCoverage:completed&&options.fullServiceEnumeration===true?"full":(row.completedChecks||[]).length?"check-specific":row.probeCommand?"probe-specific":"none"}))),vulnerabilityLeads:completed?mergeVulnerabilityLeads(vulnerabilityLeads):[],tcpPorts,udpPorts,hasOutput,...ownership,
      coverageFacts,
      objectives:{
        tcpDiscovery:{confirmed:!!(completed&&scanResultRecognized&&fullTcp),coverage:runState==="failed"?"failed":fullTcp&&scanResultRecognized?"full":tcpPorts.length?"partial":"unknown",...tcpScope,hostState:coverageFacts.hostState,endpointStateSummary:tcpScope.endpointStateSummary||{},reason:runState==="failed"?"The scan failed or was interrupted; TCP discovery is not complete.":!scanResultRecognized?"The file is not a recognized Nmap result and cannot confirm TCP discovery.":fullTcp?"Full TCP-port coverage is recorded.":tcpPorts.length?"TCP results are present, but full-port coverage is not confirmed.":"No TCP discovery evidence is recorded."},
        serviceEnumeration:{confirmed:!!(completed&&scanResultRecognized&&serviceEnum),coverage:runState==="failed"?"failed":runState==="incomplete"?"incomplete":serviceEnum&&scanResultRecognized?"recorded":"unknown",reason:runState==="failed"?"The scan failed or was interrupted; service enumeration is not complete.":runState==="incomplete"?"The Nmap result is truncated or lacks a completion marker.":!scanResultRecognized?"The file is not a recognized Nmap result and cannot confirm service enumeration.":serviceEnum?"Service/version or default-script enumeration output is recorded.":"Service-enumeration coverage is not confirmed."},
        udpDiscovery:{confirmed:!!(completed&&scanResultRecognized&&udp),coverage:runState==="failed"?"failed":udp&&scanResultRecognized?(udpScope.bounded?"bounded":"recorded"):"unknown",...udpScope,hostState:coverageFacts.hostState,endpointStateSummary:udpScope.endpointStateSummary||{},reason:runState==="failed"?"The UDP scan failed or was interrupted; discovery is not complete.":!scanResultRecognized?"The file is not a recognized Nmap result and cannot confirm UDP discovery.":udpScope.scannedPortCount?`${udpScope.bounded?"Bounded":"Recorded"} UDP discovery covers ${udpScope.scannedPortCount} port${udpScope.scannedPortCount===1?"":"s"} (${udpScope.scannedPortExpression||"exact retained scope"}); assigned service labels remain hints.`:udp?"UDP discovery output is recorded.":"No UDP discovery evidence is recorded."},
        targetedVulnerability:{confirmed:!!(completed&&scanResultRecognized&&targetedVulnerability),coverage:runState==="failed"?"failed":targetedVulnerability&&scanResultRecognized?"recorded":"unknown",ports:unique(services.map(row=>row.port)),reason:runState==="failed"?"The targeted check failed or was interrupted.":!scanResultRecognized?"The file is not a recognized Nmap result and cannot confirm a targeted check.":targetedVulnerability?"Targeted vulnerability-check output is recorded.":"No targeted vulnerability-check evidence is recorded."}
      }
    };
    return completed?parsed:applyOperationAuthority(parsed,{status:runState,command,reason:runState==="failed"?"The scan failed or was interrupted; parsed state is retained only as failed evidence.":`The scan result is ${runState}; no broad objective is completed.`});
  }
  function xmlHostIdentities(block){
    const addresses=[...String(block||"").matchAll(/<address\b([^>]*)>/gi)].filter(row=>token(attr(row[1],"addrtype"))!=="mac").map(row=>attr(row[1],"addr"));
    const hostnames=[...String(block||"").matchAll(/<hostname\b[^>]*\bname="([^"]+)"/gi)].map(row=>row[1]);
    return uniqueText([...addresses,...hostnames].map(targetToken).filter(Boolean));
  }
  function hostScope(xmlText,selectedTarget,aliases=[]){
    const text=String(xmlText||""),blocks=text.match(/<host\b[\s\S]*?<\/host>/gi)||[];
    const allowed=mappedTargetSet(selectedTarget,aliases);
    if(!blocks.length)return {scope:text,identities:[],blocks:0,matches:selectedTarget?0:1,reason:""};
    if(!selectedTarget){
      if(blocks.length===1)return {scope:blocks[0],identities:xmlHostIdentities(blocks[0]),blocks:1,matches:1,reason:""};
      return {scope:"",identities:[],blocks:blocks.length,matches:0,reason:"Nmap XML contains multiple hosts; select an exact host before importing it."};
    }
    const matches=blocks.map(block=>({block,identities:xmlHostIdentities(block)})).filter(row=>row.identities.some(value=>allowed.has(token(targetToken(value)))));
    if(matches.length===1)return {scope:matches[0].block,identities:matches[0].identities,blocks:blocks.length,matches:1,reason:""};
    if(matches.length>1)return {scope:"",identities:[],blocks:blocks.length,matches:matches.length,reason:`Nmap XML contains ${matches.length} host blocks matching selected host ${targetToken(selectedTarget)}; routing is ambiguous.`};
    return {scope:"",identities:[],blocks:blocks.length,matches:0,reason:`Nmap XML does not contain the selected host ${targetToken(selectedTarget)}.`};
  }
  function parseNmapXml(xmlText,ip="",options={}){
    const text=String(xmlText||""); const scoped=hostScope(text,ip,options.targetMappings);const scope=scoped.scope;
    const nmaprun=(/<nmaprun\b([^>]*)>/i.exec(text)||[])[1]||""; const command=attr(nmaprun,"args");
    const scaninfos=[]; let scanMatch; const scanRe=/<scaninfo\b([^>]*)\/?\s*>/gi;
    while((scanMatch=scanRe.exec(text))){const attrs=scanMatch[1];scaninfos.push({protocol:token(attr(attrs,"protocol")),services:attr(attrs,"services"),numservices:Number(attr(attrs,"numservices")||0),type:attr(attrs,"type")});}
    const services=[]; const vulnerabilityLeads=[]; const scriptChecks=[]; let match; const portRe=/<port\b([^>]*)>([\s\S]*?)<\/port>/gi;
    while((match=portRe.exec(scope))){
      const attrs=match[1],body=match[2],port=Number(attr(attrs,"portid")),protocol=token(attr(attrs,"protocol"))||"tcp";
      const stateAttrs=(/<state\b([^>]*)\/?\s*>/i.exec(body)||[])[1]||""; const state=token(attr(stateAttrs,"state"));
      if(!state.startsWith("open"))continue;
      const serviceAttrs=(/<service\b([^>]*)\/?\s*>/i.exec(body)||[])[1]||"";
      const serviceMethod=attr(serviceAttrs,"method"),serviceConfidence=Number(attr(serviceAttrs,"conf")||0);
      const serviceRaw=meaningfulEvidenceValue(attr(serviceAttrs,"name")),tableAssigned=token(serviceMethod)==="table";
      const product=tableAssigned?"":meaningfulEvidenceValue(attr(serviceAttrs,"product"),{assignedLabel:serviceRaw}),version=tableAssigned?"":meaningfulEvidenceValue(attr(serviceAttrs,"version"),{assignedLabel:serviceRaw}),extraInfo=tableAssigned?"":meaningfulEvidenceValue(attr(serviceAttrs,"extrainfo"),{assignedLabel:serviceRaw}),tunnel=tableAssigned?"":meaningfulEvidenceValue(attr(serviceAttrs,"tunnel")),serviceFingerprint=meaningfulEvidenceValue(attr(serviceAttrs,"servicefp")),cpe=tableAssigned?"":meaningfulEvidenceValue(decodeEntities((/<cpe>([\s\S]*?)<\/cpe>/i.exec(body)||[])[1]||""));
      const meaningfulService=!!serviceRaw&&!["unknown","general","tcpwrapped"].includes(token(serviceRaw));
      const identified=!tableAssigned&&(serviceMethod.toLowerCase()==="probed"&&serviceConfidence>=3&&meaningfulService||!!(product||version||extraInfo||cpe||serviceFingerprint));
      const serviceRow={port,protocol,state,service:identified?normalizeServiceName(serviceRaw,port,protocol):"",serviceRaw,serviceHint:serviceHint(serviceRaw,port,protocol),serviceMethod,serviceConfidence,identified,product,version,extraInfo,details:[product,version,extraInfo].filter(Boolean).join(" "),tunnel,cpe,serviceFingerprint,scriptEvidence:/<script\b/i.test(body),source:"Nmap XML",sourceSlot:"xml",command};
      services.push(serviceRow);
      let scriptMatch;const scriptRe=/<script\b([^>]*?)(?:\/\s*>|>([\s\S]*?)<\/script>)/gi;
      while((scriptMatch=scriptRe.exec(body))){
        const scriptAttrs=scriptMatch[1]||"",scriptBody=scriptMatch[2]||"";
        const scriptId=attr(scriptAttrs,"id"),output=attr(scriptAttrs,"output"),combined=[output,stripTags(scriptBody)].filter(Boolean).join(" ");
        if(scriptId){scriptChecks.push(scriptId);serviceRow.completedChecks=uniqueText([...(serviceRow.completedChecks||[]),scriptId]);serviceRow.enumerationObjectives=uniqueText([...(serviceRow.enumerationObjectives||[]),scriptId]);}
        vulnerabilityLeads.push(...vulnerabilityLeadsFromEvidence(combined,{...serviceRow,script:scriptId,source:"Nmap XML"}));
        applyDeterministicProtocolEvidence(serviceRow,[serviceRow.serviceFingerprint,combined]);
      }
      applyDeterministicProtocolEvidence(serviceRow,serviceRow.serviceFingerprint);
    }
    const tcpInfo=scaninfos.filter(row=>row.protocol==="tcp"); const udpInfo=scaninfos.filter(row=>row.protocol==="udp");
    const finishedAttrs=(/<finished\b([^>]*)\/?\s*>/i.exec(text)||[])[1]||"",xmlFailed=token(attr(finishedAttrs,"exit"))==="error",xmlCompleted=!xmlFailed;
    const tcpRange=tcpInfo.map(row=>`services=${row.services} numservices=${row.numservices}`).join(" ");
    const fullTcp=fullTcpCoverage(command,tcpRange); const serviceEnum=serviceEnumerationCommand(command)||services.some(row=>row.product||row.version||row.extraInfo); const udp=udpCommand(command)||udpInfo.length>0||services.some(row=>row.protocol==="udp"); const targetedVulnerability=targetedVulnerabilityCommand(command)||scriptChecks.some(value=>/vuln|vulners/i.test(value))||vulnerabilityLeads.length>0;
    const hostname=decodeEntities((/<hostname\b[^>]*\bname="([^"]*)"/i.exec(scope)||[])[1]||"");
    const os=decodeEntities((/<osmatch\b[^>]*\bname="([^"]*)"/i.exec(scope)||[])[1]||"");
    const tcpPorts=unique(services.filter(row=>row.protocol==="tcp").map(row=>row.port)); const udpPorts=unique(services.filter(row=>row.protocol==="udp").map(row=>row.port));
    const commandOperation=operationFromCommand(command,-1);
    const endpointStateSummary={},protocolStateSummary={tcp:{},udp:{}};
    const addState=(state,count=1,protocol="")=>{
      const key=token(state),amount=Number(count);if(!key||amount<1)return;
      endpointStateSummary[key]=(endpointStateSummary[key]||0)+amount;
      const scoped=protocolStateSummary[token(protocol)];if(scoped)scoped[key]=(scoped[key]||0)+amount;
    };
    services.forEach(row=>addState(row.state,1,row.protocol));
    let extraMatch;const extraRe=/<extraports\b([^>]*)>/gi;
    while((extraMatch=extraRe.exec(scope||text))){
      const attrs=extraMatch[1]||"",extraProtocol=tcpInfo.length&&!udpInfo.length?"tcp":udpInfo.length&&!tcpInfo.length?"udp":"";
      addState(attr(attrs,"state"),Number(attr(attrs,"count")||0),extraProtocol);
    }
    const statusAttrs=(/<status\b([^>]*)\/?\s*>/i.exec(scope||text)||[])[1]||"";
    const hostState=token(attr(statusAttrs,"state"))||"unknown";
    const scopeFor=(protocol,rows)=>{
      const info=rows[0]||{},fromInfo={scannedPortCount:Number(info.numservices)||portExpressionCount(info.services),scannedPortExpression:clean(info.services),bounded:false,full:false};
      if(fromInfo.scannedPortCount){fromInfo.full=fromInfo.scannedPortCount===65535;fromInfo.bounded=!fromInfo.full;}
      const fallback=commandCoverage(command,protocol);
      return fromInfo.scannedPortCount?fromInfo:fallback;
    };
    const tcpScope={...scopeFor("tcp",tcpInfo),endpointStateSummary:protocolStateSummary.tcp};
    const udpScope={...scopeFor("udp",udpInfo),endpointStateSummary:protocolStateSummary.udp};
    const scanResultRecognized=/<nmaprun\b/i.test(text)&&(
      scaninfos.length>0||scoped.blocks>0||/<(?:runstats|finished|hosts|verbose|debugging)\b/i.test(text)
    );
    const pathTarget=knownPathTarget(options.filename||"",options.targetMappings||[]);
    const candidates=uniqueText([...scoped.identities,...commandOperation.targetCandidates,pathTarget].filter(Boolean));
    const scopedMappings=uniqueText([...(Array.isArray(options.targetMappings)?options.targetMappings:[]),...scoped.identities]);
    const ownershipTarget=ip||(scoped.blocks===1?scoped.identities[0]||"":"");
    const ownership=resolveTargetOwnership(ownershipTarget,candidates,{mappings:scopedMappings,manualFallback:options.manualFallback===true,requireEvidence:options.requireTargetEvidence===true});
    if(!scope&&scoped.reason){ownership.targetConflict=true;ownership.target="";ownership.targetReason=scoped.reason;ownership.targetCandidates=candidates;}
    services.forEach(row=>{
      const coverage=serviceScanCoverageForEndpoint(row,{
        serviceRequested:serviceEnumerationCommand(command),recognized:scanResultRecognized,
        operationStatus:xmlFailed?"failed":xmlCompleted?"completed":"incomplete",
        scope:row.protocol==="udp"?udpScope:tcpScope,exactPort:commandOperation.port
      });
      row.serviceScanCoverageState=coverage.state;row.serviceScanCoverageReason=coverage.reason;
      row.serviceScanCoverageSource="Nmap XML";row.serviceScanCoverageCommand=command;
    });
    const parsed={
      format:"xml",representation:"xml",runIdentity:nmapRunIdentity(command,text),source:"Nmap XML",command,scanScopes:commandOperation.scanScopes||[],scopedTargetAliases:scoped.identities,xmlHostBlocks:scoped.blocks,xmlHostMatches:scoped.matches,status:xmlFailed?"failed":xmlCompleted?"completed":"incomplete",operationStatus:xmlFailed?"failed":xmlCompleted?"completed":"incomplete",operationCompleted:xmlCompleted,scanResultRecognized,coverageFacts:{hostState,endpointStateSummary,tcp:tcpScope,udp:udpScope},completedChecks:xmlCompleted?uniqueText(scriptChecks):[],enumerationObjectives:xmlCompleted?uniqueText(scriptChecks):[],enumerationCoverage:xmlCompleted&&options.fullServiceEnumeration===true?"full":scriptChecks.length?"check-specific":"none",services:mergeServices(services.map(row=>({...row,operationStatus:xmlFailed?"failed":xmlCompleted?"completed":"incomplete",operationCompleted:xmlCompleted,enumerationStarted:xmlCompleted&&(serviceEnum||(row.completedChecks||[]).length>0),enumerationComplete:xmlCompleted&&options.fullServiceEnumeration===true,enumerationCoverage:xmlCompleted&&options.fullServiceEnumeration===true?"full":(row.completedChecks||[]).length?"check-specific":serviceEnum?"probe-specific":"none"}))),vulnerabilityLeads:xmlCompleted?mergeVulnerabilityLeads(vulnerabilityLeads):[],tcpPorts,udpPorts,hostname,os,scaninfos,...ownership,
      objectives:{
        tcpDiscovery:{confirmed:!xmlFailed&&fullTcp,coverage:xmlFailed?"failed":fullTcp?"full":tcpInfo.length||tcpPorts.length?"partial":"unknown",...tcpScope,hostState,endpointStateSummary:tcpScope.endpointStateSummary,reason:xmlFailed?"Nmap XML reports a failed scan.":fullTcp?"Nmap XML confirms a full TCP-port range.":tcpInfo.length||tcpPorts.length?"Nmap XML contains TCP results, but does not prove all 65,535 ports were scanned.":"No TCP scan metadata is present."},
        serviceEnumeration:{confirmed:xmlCompleted&&!!serviceEnum,coverage:xmlFailed?"failed":!xmlCompleted?"incomplete":serviceEnum?"recorded":"unknown",reason:xmlFailed?"Nmap XML reports a failed scan.":!xmlCompleted?"Nmap XML lacks a successful completion marker.":serviceEnum?"Nmap XML records service/version or default-script enumeration.":"The XML does not show service/version enumeration."},
        udpDiscovery:{confirmed:!xmlFailed&&!!udp,coverage:xmlFailed?"failed":udp?(udpScope.bounded?"bounded":"recorded"):"unknown",...udpScope,hostState,endpointStateSummary:udpScope.endpointStateSummary,reason:xmlFailed?"Nmap XML reports a failed scan.":udpScope.scannedPortCount?`${udpScope.bounded?"Bounded":"Recorded"} UDP discovery covers ${udpScope.scannedPortCount} port${udpScope.scannedPortCount===1?"":"s"} (${udpScope.scannedPortExpression||"exact retained scope"}); assigned service labels remain hints.`:udp?"Nmap XML records UDP discovery.":"No UDP scan metadata is present."},
        targetedVulnerability:{confirmed:!xmlFailed&&!!targetedVulnerability,coverage:xmlFailed?"failed":targetedVulnerability?"recorded":"unknown",ports:unique(services.map(row=>row.port)),reason:xmlFailed?"Nmap XML reports a failed scan.":targetedVulnerability?"Nmap XML records a targeted vulnerability check.":"No targeted vulnerability-check metadata is present."}
      }
    };
    return xmlCompleted?parsed:applyOperationAuthority(parsed,{status:xmlFailed?"failed":"incomplete",command,reason:xmlFailed?"Nmap XML reports a failed scan.":"Nmap XML lacks a successful completion marker."});
  }
  function scanLines(services,protocol){return mergeServices(services).filter(row=>!protocol||row.protocol===protocol).map(row=>`${row.port}/${row.protocol} ${row.state||"open"} ${[row.serviceRaw||row.service,row.product,row.version,row.extraInfo].filter(Boolean).join(" ")}`.trim()).join("\n");}
  function rawEvidencePage(rawText,options={}){
    const raw=String(rawText??"");
    const lines=raw?raw.split("\n").map(line=>line.endsWith("\r")?line.slice(0,-1):line):[];
    const query=String(options.query||"").toLowerCase(),limit=Math.max(1,Math.min(2000,Number(options.limit)||500));
    const targetLine=Math.max(0,Math.min(lines.length,Number(options.targetLine)||0));
    const matches=[];
    lines.forEach((text,index)=>{
      if(!query||text.toLowerCase().includes(query))matches.push({lineNumber:index+1,text});
    });
    let offset=Math.max(0,Number(options.offset)||0);
    if(targetLine){
      const targetIndex=matches.findIndex(row=>row.lineNumber>=targetLine);
      offset=targetIndex<0?Math.max(0,matches.length-limit):Math.max(0,targetIndex-Math.floor(limit/4));
    }
    offset=Math.min(offset,Math.max(0,matches.length-1));
    const rows=matches.slice(offset,offset+limit);
    return {
      totalLines:lines.length,
      matchingLines:matches.length,
      query:String(options.query||""),
      offset,
      limit,
      rows,
      nextOffset:offset+rows.length,
      complete:offset+rows.length>=matches.length
    };
  }
  function coverageSummary(portAnalysis,tcpAnalysis,udpAnalysis){
    const discovered=unique([...(portAnalysis?.tcpPorts||[]),...(portAnalysis?.objectives?.tcpDiscovery?.confirmed?[]:[])]);
    const servicePorts=unique((tcpAnalysis?.services||[]).filter(row=>token(row.serviceScanCoverageState)===SERVICE_SCAN_COVERAGE.COMPLETED).map(row=>row.port)); const uncovered=discovered.filter(port=>!servicePorts.includes(port));
    const serviceConfirmed=!!tcpAnalysis?.objectives?.serviceEnumeration?.confirmed&&(discovered.length===0||uncovered.length===0);
    return {
      tcpDiscovery:{...(portAnalysis?.objectives?.tcpDiscovery||{}),ports:discovered},
      serviceEnumeration:{confirmed:serviceConfirmed,coverage:serviceConfirmed?"complete":servicePorts.length?"partial":"unknown",ports:servicePorts,uncoveredPorts:uncovered,reason:serviceConfirmed?(discovered.length?`Service scan coverage is complete for all ${discovered.length} discovered TCP port${discovered.length===1?"":"s"}; unresolved identities remain separate review work.`:"Completed service/version scan coverage is recorded."):(uncovered.length?`Completed service scan coverage is still missing TCP port${uncovered.length===1?"":"s"}: ${uncovered.join(", ")}.`:(tcpAnalysis?.objectives?.serviceEnumeration?.reason||"Service-scan coverage is not confirmed."))},
      udpDiscovery:{...(udpAnalysis?.objectives?.udpDiscovery||{}),ports:unique(udpAnalysis?.udpPorts||[])}
    };
  }

  return {SERVICE_SCAN_COVERAGE,normalizeServiceName,serviceHint,meaningfulEvidenceValue,evidenceQuality,lifecycle,endpointValidation,splitBanner,decodeNmapFingerprint,deterministicProtocolEvidence,applyDeterministicProtocolEvidence,uniqueLabels,mergeServices,mergeVulnerabilityLeads,vulnerabilityLeadMatch,vulnerabilityLeadTriage,triageVulnerabilityLeads,nmapEndpointEvidenceSlice,parseNmapText,parseNmapXml,parseCommandLog,parseToolOutput,correlateAutoRecon,operationFromCommand,operationForPath,applyOperationAuthority,resolveTargetOwnership,resolveParsedTarget,activeTargetIdentity,targetCandidatesFromText,targetCandidatesFromCommand,reliablePathTarget,normalizePath,resultState,endpointFromPath,commandsFromLog,scanLines,rawEvidencePage,coverageSummary,fullTcpCoverage,serviceEnumerationCommand,targetedVulnerabilityCommand,udpCommand,toolFrom,serviceId,coverageFactsFromText,portExpressionCount,commandCoverage,portInExpression,serviceScanCoverageForEndpoint,nmapRunIdentity};
});
