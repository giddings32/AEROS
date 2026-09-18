(function(root,factory){
  const api=factory();
  if(typeof module==="object"&&module.exports)module.exports=api;
  if(root)root.AEROSAccessLeads=api;
})(typeof globalThis!=="undefined"?globalThis:this,function(){
  "use strict";

  const LEAD_TYPES=Object.freeze([
    "known-vulnerability","injection","authentication-session","authorization-access-control",
    "file-upload-handling","file-read-traversal-inclusion","command-execution",
    "credential-password-use","exposed-misconfigured-service","information-disclosure","other"
  ]);
  const LEAD_TYPE_LABELS=Object.freeze({
    "known-vulnerability":"Known Vulnerability / CVE",
    injection:"Injection",
    "authentication-session":"Authentication / Session",
    "authorization-access-control":"Authorization / Access Control",
    "file-upload-handling":"File Upload / File Handling",
    "file-read-traversal-inclusion":"File Read / Path Traversal / Inclusion",
    "command-execution":"Command Execution",
    "credential-password-use":"Credential / Password Use",
    "exposed-misconfigured-service":"Exposed or Misconfigured Service",
    "information-disclosure":"Information Disclosure",
    other:"Other"
  });
  const ORIGIN_TYPES=Object.freeze([
    "imported-scan","service-inventory","web-target","manual-research",
    "manual-testing","credential-observation","other-manual"
  ]);
  const ORIGIN_LABELS=Object.freeze({
    "imported-scan":"Imported Scan",
    "service-inventory":"Service Inventory",
    "web-target":"Web Target",
    "manual-research":"Manual Research",
    "manual-testing":"Manual Testing",
    "credential-observation":"Credential Observation",
    "other-manual":"Other Manual Source"
  });
  const STATUSES=Object.freeze(["lead","verified","na"]);
  const STATUS_LABELS=Object.freeze({
    lead:"Unverified Lead",verified:"Applicability Verified",na:"Not Applicable"
  });

  function clean(value){return String(value??"").trim();}
  function list(value){return Array.isArray(value)?value:[];}
  function nowIso(options={}){return clean(options.now)||new Date().toISOString();}
  function token(value){return clean(value).toLowerCase().replace(/[^a-z0-9]+/g,"-").replace(/^-|-$/g,"");}
  function defaultId(options={}){
    if(typeof options.idFactory==="function")return clean(options.idFactory("access-lead"));
    return `access-lead-${Date.now()}-${Math.random().toString(16).slice(2)}`;
  }
  function normalizePort(value){
    if(value===""||value===null||value===undefined)return null;
    const port=Number(value);return Number.isInteger(port)&&port>=1&&port<=65535?port:null;
  }
  function normalizeProtocol(value){
    const valueToken=clean(value).toLowerCase();return ["tcp","udp"].includes(valueToken)?valueToken:"";
  }
  function normalizeStatus(value){
    const valueToken=clean(value).toLowerCase();
    if(valueToken==="applicability-verified")return "verified";
    if(valueToken==="not-applicable")return "na";
    return STATUSES.includes(valueToken)?valueToken:"lead";
  }
  function normalizeType(value,cve=""){
    const valueToken=token(value);
    if(LEAD_TYPES.includes(valueToken))return valueToken;
    return clean(cve)?"known-vulnerability":"other";
  }
  function inferOrigin(raw={}){
    const explicit=token(raw.originType);
    if(ORIGIN_TYPES.includes(explicit))return explicit;
    if(raw.manual===true||raw.operatorCreated===true)return "other-manual";
    if(clean(raw.script)||/nmap|autorecon|scan/i.test(clean(raw.source)))return "imported-scan";
    return "other-manual";
  }
  function isManualLead(value={}){
    return normalizeLead(value,{now:clean(value.updatedAt)||clean(value.createdAt)||new Date(0).toISOString(),idFactory:()=>clean(value.id)||"lead"}).originType!=="imported-scan";
  }
  function safeHttpUrl(value){
    const raw=clean(value);if(!raw)return "";
    try{const parsed=new URL(raw);return ["http:","https:"].includes(parsed.protocol)?parsed.href:"";}catch{return "";}
  }
  function importedIdentity(raw={}){
    return [
      clean(raw.engagementId),clean(raw.hostId),
      clean(raw.endpointId||raw.serviceEndpointId),
      clean(raw.targetAddress||raw.observedTargetAddress||raw.address).toLowerCase(),
      normalizeProtocol(raw.protocol)||"tcp",normalizePort(raw.port)||"",
      clean(raw.cve||raw.identifier).toUpperCase(),token(raw.script||raw.title),
      token(raw.service),token(raw.product),token(raw.version)
    ].join(":");
  }
  function normalizeLead(value={},options={}){
    const raw=value&&typeof value==="object"&&!Array.isArray(value)?value:{};
    const createdAt=clean(raw.createdAt)||nowIso(options),updatedAt=clean(raw.updatedAt)||createdAt;
    const originType=inferOrigin(raw),manual=originType!=="imported-scan";
    const cve=clean(raw.cve).toUpperCase(),cwe=clean(raw.cwe).toUpperCase();
    const port=normalizePort(raw.port),protocol=normalizeProtocol(raw.protocol);
    const id=clean(raw.id)||(manual?defaultId(options):`scan-lead:${importedIdentity(raw)}`);
    return {
      ...raw,
      id,
      title:clean(raw.title)||cve||clean(raw.identifier)||clean(raw.script)||(manual?"Untitled access lead":"Imported vulnerability lead"),
      leadType:normalizeType(raw.leadType,cve),
      status:normalizeStatus(raw.status),
      originType,
      originLabel:clean(raw.originLabel)||ORIGIN_LABELS[originType],
      manual,
      cve,
      cwe,
      identifier:clean(raw.identifier),
      cvss:raw.cvss===""||raw.cvss===null||raw.cvss===undefined?null:(Number.isFinite(Number(raw.cvss))?Number(raw.cvss):null),
      port,
      protocol,
      service:clean(raw.service),
      product:clean(raw.product),
      version:clean(raw.version),
      endpointId:clean(raw.endpointId)||(port&&protocol?`${protocol}:${port}`:""),
      engagementId:clean(raw.engagementId),
      hostId:clean(raw.hostId),
      targetAddress:clean(raw.targetAddress||raw.observedTargetAddress||raw.address),
      observedTargetAddress:clean(raw.observedTargetAddress||raw.targetAddress||raw.address),
      sourceArtifactId:clean(raw.sourceArtifactId),
      sourceRevision:Number(raw.sourceRevision)||0,
      objective:clean(raw.objective),
      webTargetId:clean(raw.webTargetId),
      webOrigin:clean(raw.webOrigin),
      url:clean(raw.url),
      path:clean(raw.path),
      httpMethod:clean(raw.httpMethod).toUpperCase(),
      parameter:clean(raw.parameter),
      locationNotes:clean(raw.locationNotes),
      description:clean(raw.description||raw.observation),
      raw:clean(raw.raw),
      source:clean(raw.source),
      sourceUrl:clean(raw.sourceUrl),
      sourceObservation:clean(raw.sourceObservation),
      notes:clean(raw.notes),
      createdAt,
      updatedAt
    };
  }
  function validateLead(value={},options={}){
    const lead=normalizeLead(value,{...options,now:clean(options.now)||clean(value.updatedAt)||clean(value.createdAt)||new Date(0).toISOString()});
    const errors=[];
    if(!clean(value.title))errors.push("Lead Title is required.");
    if(value.cvss!==""&&value.cvss!==null&&value.cvss!==undefined){
      const score=Number(value.cvss);if(!Number.isFinite(score)||score<0||score>10)errors.push("CVSS must be a number from 0.0 through 10.0.");
    }
    if(value.port!==""&&value.port!==null&&value.port!==undefined&&!normalizePort(value.port))errors.push("Port must be between 1 and 65535.");
    if(clean(value.sourceUrl)&&!safeHttpUrl(value.sourceUrl))errors.push("Source or Reference URL must use http:// or https://.");
    return {lead,errors};
  }
  function ensureHostLeads(host,options={}){
    if(!host||typeof host!=="object")return [];
    host.vulnerabilityLeads=list(host.vulnerabilityLeads).map(row=>normalizeLead(row,options));
    return host.vulnerabilityLeads;
  }
  function createManualLead(host,input={},options={}){
    const rows=ensureHostLeads(host,options),at=nowIso(options);
    const result=validateLead({...input,originType:inferOrigin({...input,manual:true}),manual:true,createdAt:at,updatedAt:at},options);
    if(result.errors.length)return result;
    let lead=result.lead;
    if(rows.some(row=>row.id===lead.id))lead=normalizeLead({...lead,id:defaultId(options)},{...options,now:at});
    rows.push(lead);return {lead,errors:[]};
  }
  function updateManualLead(host,id,patch={},options={}){
    const rows=ensureHostLeads(host,options),index=rows.findIndex(row=>row.id===id);
    if(index<0)return {lead:null,errors:["Access lead was not found."]};
    if(rows[index].originType==="imported-scan")return {lead:null,errors:["Imported scan leads cannot be edited as manual leads."]};
    const result=validateLead({...rows[index],...patch,id:rows[index].id,originType:rows[index].originType,manual:true,createdAt:rows[index].createdAt,updatedAt:nowIso(options)},options);
    if(result.errors.length)return result;
    rows[index]=result.lead;return {lead:result.lead,errors:[]};
  }
  function deleteManualLead(host,id,options={}){
    const rows=ensureHostLeads(host,options),index=rows.findIndex(row=>row.id===id);
    if(index<0||rows[index].originType==="imported-scan")return {removed:null,linkedAttempts:[]};
    const linkedAttempts=list(host.exploitAttempts).filter(row=>clean(row?.leadId)===id);
    const removed=rows.splice(index,1)[0];return {removed,linkedAttempts};
  }
  function mergeScanRefresh(existing=[],incoming=[],options={}){
    const prior=list(existing).map(row=>normalizeLead(row,options));
    const manual=prior.filter(row=>row.originType!=="imported-scan");
    const priorImported=new Map(prior.filter(row=>row.originType==="imported-scan").map(row=>[row.id,row]));
    const refreshed=[],refreshedIds=new Set();
    list(incoming).forEach(value=>{
      const row=normalizeLead({...value,originType:"imported-scan",manual:false},options);
      if(refreshedIds.has(row.id))return;
      refreshedIds.add(row.id);
      const old=priorImported.get(row.id);
      if(old){
        refreshed.push(normalizeLead({
          ...row,
          status:old.status,
          notes:old.notes,
          title:old.title||row.title,
          leadType:old.leadType||row.leadType,
          cwe:old.cwe||row.cwe,
          identifier:old.identifier||row.identifier,
          sourceUrl:old.sourceUrl||row.sourceUrl,
          description:old.description||row.description,
          locationNotes:old.locationNotes||row.locationNotes,
          updatedAt:old.updatedAt||row.updatedAt,
          createdAt:old.createdAt||row.createdAt
        },options));
        priorImported.delete(row.id);
      }else refreshed.push(row);
    });
    return [...manual,...refreshed,...priorImported.values()];
  }
  function serviceLabel(row={}){
    const endpoint=row.port?`${row.port}/${clean(row.protocol||"tcp").toUpperCase()}`:"Host";
    return [endpoint,clean(row.service).toUpperCase(),clean(row.product),clean(row.version)].filter(Boolean).join(" · ");
  }
  function fromService(host={},service={}){
    const protocol=normalizeProtocol(service.protocol)||"tcp",port=normalizePort(service.port);
    return {
      originType:"service-inventory",originLabel:"Service Inventory",leadType:"other",status:"lead",
      endpointId:clean(service.id||service.endpointId)||(port?`${protocol}:${port}`:""),
      engagementId:clean(service.engagementId),hostId:clean(service.hostId||host.id),
      targetAddress:clean(service.targetAddress||service.observedTargetAddress||service.address||host.ip),
      observedTargetAddress:clean(service.observedTargetAddress||service.targetAddress||service.address||host.ip),
      port,protocol,service:clean(service.service||service.serviceRaw),
      product:clean(service.product),version:clean(service.version),
      source:clean(service.source)||"Service Inventory",
      sourceObservation:[clean(service.sourceSlot),clean(service.details||service.extraInfo)].filter(Boolean).join(" · "),
      locationNotes:clean(host.ip||host.hostname)
    };
  }
  function parseWebFacts(value){
    const raw=clean(value?.url||value?.value||value);if(!raw)return {};
    try{
      const url=new URL(raw),scheme=url.protocol.replace(":",""),port=Number(url.port)||(scheme==="https"?443:80);
      return {url:url.href,webOrigin:url.origin,host:url.hostname,port,protocol:"tcp",path:`${url.pathname||"/"}${url.search||""}`,scheme,service:scheme};
    }catch{return {path:raw.startsWith("/")?raw:"",url:"",webOrigin:"",host:clean(value?.host),port:normalizePort(value?.port),protocol:normalizeProtocol(value?.protocol)||"tcp",scheme:clean(value?.scheme)};}
  }
  function correlateWebService(services=[],facts={}){
    const port=normalizePort(facts.port);if(!port)return null;
    const candidates=list(services).filter(row=>normalizeProtocol(row.protocol||"tcp")==="tcp"&&normalizePort(row.port)===port&&(
      /https?|ssl|tls|web/i.test([row.service,row.product,row.details].filter(Boolean).join(" "))||[80,443,8000,8008,8080,8081,8443,8888].includes(port)
    ));
    const target=clean(facts.host).toLowerCase();
    if(target){
      const exact=candidates.filter(row=>clean(row.targetAddress||row.observedTargetAddress||row.address).toLowerCase()===target);
      if(exact.length===1)return exact[0];
      if(exact.length>1)return null;
    }
    return candidates.length===1?candidates[0]:null;
  }
  function fromWebTarget(host={},target={},services=[]){
    const facts=parseWebFacts(target),service=correlateWebService(services,facts),latest=list(target.sources).at(-1)||{};
    return {
      originType:"web-target",originLabel:"Web Target",leadType:"other",status:"lead",
      webTargetId:clean(target.id),url:facts.url||clean(target.url),webOrigin:facts.webOrigin,
      path:facts.path||clean(target.path),port:facts.port,protocol:facts.protocol||"tcp",
      service:clean(service?.service)||facts.service||"",product:clean(service?.product),version:clean(service?.version),
      endpointId:clean(service?.id||service?.endpointId),
      engagementId:clean(service?.engagementId),hostId:clean(service?.hostId||host.id),
      targetAddress:clean(service?.targetAddress||service?.observedTargetAddress||facts.host||host.ip),
      observedTargetAddress:clean(service?.observedTargetAddress||service?.targetAddress||facts.host||host.ip),
      source:[clean(latest.tool),clean(latest.filename)].filter(Boolean).join(" · ")||"Web Target",
      sourceObservation:clean(target.value||target.url||target.path),
      locationNotes:clean(host.ip||host.hostname)
    };
  }
  function scopeLabel(lead={}){
    const row=normalizeLead(lead,{now:clean(lead.updatedAt)||clean(lead.createdAt)||new Date(0).toISOString(),idFactory:()=>clean(lead.id)||"lead"});
    if(row.url||row.path)return row.url||row.path;
    if(row.port)return `${row.port}/${clean(row.protocol||"tcp").toUpperCase()}`;
    return "Host-level lead";
  }
  function safeSourceUrl(lead={}){return safeHttpUrl(lead.sourceUrl);}
  function matchesFilter(lead,filter="all"){
    const row=normalizeLead(lead,{now:clean(lead.updatedAt)||clean(lead.createdAt)||new Date(0).toISOString(),idFactory:()=>clean(lead.id)||"lead"});
    if(filter==="priority")return !!row.triage?.priority;
    if(filter==="high")return !!row.triage?.high&&row.status!=="na";
    if(filter==="version")return row.triage?.match?.tier==="version-match"&&row.status!=="na";
    if(filter==="review")return row.originType==="imported-scan"
      ?row.triage?.match?.tier==="unverified"&&row.status!=="na"
      :row.status==="lead";
    if(filter==="verified")return row.status==="verified";
    if(filter==="known-vulnerability")return row.leadType==="known-vulnerability"||!!row.cve;
    if(filter==="web")return !!(row.url||row.path||row.webTargetId)||["injection","authentication-session","authorization-access-control","file-upload-handling","file-read-traversal-inclusion"].includes(row.leadType);
    if(filter==="na")return row.status==="na";
    return true;
  }
  function sortLeads(rows=[],attempts=[]){
    const linked=new Set(list(attempts).filter(row=>!["successful","dismissed"].includes(clean(row.status))).map(row=>clean(row.leadId)));
    const rank=row=>{
      if(row.status==="verified")return 0;
      if(linked.has(row.id))return 1;
      if(Number(row.cvss)>=7&&row.port)return 2;
      if(row.status==="na")return 4;
      return 3;
    };
    return list(rows).slice().sort((a,b)=>rank(a)-rank(b)||Number(b.cvss||-1)-Number(a.cvss||-1)||String(b.updatedAt||"").localeCompare(String(a.updatedAt||"")));
  }

  return Object.freeze({
    LEAD_TYPES,LEAD_TYPE_LABELS,ORIGIN_TYPES,ORIGIN_LABELS,STATUSES,STATUS_LABELS,
    normalizePort,normalizeProtocol,normalizeStatus,normalizeType,normalizeLead,validateLead,
    isManualLead,safeHttpUrl,safeSourceUrl,ensureHostLeads,createManualLead,updateManualLead,
    deleteManualLead,mergeScanRefresh,serviceLabel,fromService,parseWebFacts,correlateWebService,
    fromWebTarget,scopeLabel,matchesFilter,sortLeads
  });
});
