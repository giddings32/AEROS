(function(root,factory){
  const serviceApi=(typeof module==="object"&&module.exports)?require("../imports/autorecon-live-import.js"):(root&&root.AEROSAutoReconLiveImport);
  const api=factory(serviceApi||{});
  if(typeof module==="object"&&module.exports)module.exports=api;
  if(root)root.AEROSInitialRecon=api;
})(typeof window!=="undefined"?window:globalThis,function(serviceApi){
  "use strict";

  const VIEW_KEYS=Object.freeze([
    "overview","port-scans","services","commands-signals",
    "report-evidence","loot-exploit","artifact-inventory"
  ]);
  const VIEW_LABELS=Object.freeze({
    overview:"Overview",
    "port-scans":"Port Scans",
    services:"Services",
    "commands-signals":"Commands & Signals",
    "report-evidence":"Report & Evidence",
    "loot-exploit":"Loot & Exploit",
    "artifact-inventory":"Artifact Inventory"
  });
  const REVIEW_STATES=Object.freeze(["new","reviewed","follow-up-required","resolved"]);
  const PREVIEW_LINE_BUDGET=2500;
  const LARGE_ARTIFACT_BYTES=6000;
  const INVENTORY_PAGE_SIZE=500;
  const STATE_SCHEMA_VERSION=3;
  const runtimeByRoot=new WeakMap();

  const values=value=>Array.isArray(value)?value:[];
  const object=value=>value&&typeof value==="object"&&!Array.isArray(value)?value:{};
  const string=value=>String(value??"");
  const text=value=>string(value).trim();
  const lower=value=>text(value).toLowerCase();
  const number=value=>Number.isFinite(Number(value))?Number(value):0;
  const own=(value,key)=>Object.prototype.hasOwnProperty.call(value,key);
  const unique=list=>[...new Set(values(list).map(text).filter(Boolean))];
  const normalizePath=value=>text(value).replace(/\\/g,"/").replace(/\/{2,}/g,"/");
  const basename=value=>normalizePath(value).split("/").filter(Boolean).pop()||"";
  const extension=value=>{const match=basename(value).match(/\.([^.]+)$/);return match?match[1].toLowerCase():"";};
  const pretty=value=>text(value).replace(/[-_]+/g," ").replace(/\b\w/g,character=>character.toUpperCase())||"Unknown";
  const escapeHtml=value=>string(value).replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;").replaceAll('"',"&quot;").replaceAll("'","&#039;");
  const escapeAttr=value=>escapeHtml(value).replaceAll("\n"," ");
  const endpointKey=(protocol,port)=>lower(protocol||"tcp")+":"+number(port);
  const now=()=>new Date().toISOString();

  function hash32(value){
    let hash=0x811c9dc5;
    const source=string(value);
    for(let index=0;index<source.length;index++){hash^=source.charCodeAt(index);hash=Math.imul(hash,0x01000193);}
    return (hash>>>0).toString(36);
  }
  function safeId(value){
    const slug=string(value).replace(/[^a-zA-Z0-9_-]+/g,"-").replace(/^-+|-+$/g,"").slice(0,76)||"item";
    return slug+"-"+hash32(value);
  }
  function formatBytes(value){
    const size=Math.max(0,number(value));
    if(size<1024)return size+" B";
    if(size<1024*1024)return (size/1024).toFixed(1)+" KB";
    return (size/1024/1024).toFixed(1)+" MB";
  }
  function reviewState(value){
    const candidate=lower(value);
    return REVIEW_STATES.includes(candidate)?candidate:"new";
  }
  function lifecycle(row={}){
    return row.provisional===true||lower(row.artifactLifecycle)==="provisional"?"provisional":"canonical";
  }
  function deepFreeze(value){
    if(!value||typeof value!=="object"||Object.isFrozen(value))return value;
    Object.values(value).forEach(deepFreeze);
    return Object.freeze(value);
  }

  function ensureState(candidate){
    const state=object(candidate);
    state.schemaVersion=STATE_SCHEMA_VERSION;
    if(!VIEW_KEYS.includes(state.selectedTab))state.selectedTab="overview";
    if(!state.cards||typeof state.cards!=="object"||Array.isArray(state.cards))state.cards={};
    if(!state.followUps||typeof state.followUps!=="object"||Array.isArray(state.followUps))state.followUps={};
    if(!state.serviceMappings||typeof state.serviceMappings!=="object"||Array.isArray(state.serviceMappings))state.serviceMappings={};
    if(!Array.isArray(state.customServiceFamilies))state.customServiceFamilies=[];
    state.customServiceFamilies=unique(state.customServiceFamilies.map(value=>serviceApi.normalizedFamilyLabel?.(value)||text(value))).slice(0,100);
    if(!["review-priority","port","name"].includes(state.serviceSort))state.serviceSort="review-priority";
    if(typeof state.selectedServiceFamily!=="string")state.selectedServiceFamily="";
    if(typeof state.selectedServiceEndpoint!=="string")state.selectedServiceEndpoint="";
    if(typeof state.serviceMappingOpen!=="boolean")state.serviceMappingOpen=false;
    state.inventoryPage=Math.max(0,Math.floor(number(state.inventoryPage)));
    if(typeof state.updatedAt!=="string")state.updatedAt="";
    return state;
  }

  function artifactCategory(row={}){
    const path=normalizePath(row.logicalPath||row.path||row.sourcePath),name=lower(row.filename||row.originalFilename||basename(path));
    const declared=lower(row.classification?.category||row.category);
    if(declared==="external-notes"||row.semanticKind==="external-autorecon-notes")return "external-notes";
    if(name==="_commands.log")return "commands";
    if(name==="_manual_commands.txt")return "manual-commands";
    if(name==="_errors.log")return "errors";
    if(name==="_patterns.log")return "patterns";
    if(/\/loot\//i.test(path)||declared==="loot")return "loot";
    if(/\/exploit\//i.test(path)||declared==="exploit")return "exploit";
    if(/\/report\/screenshots\//i.test(path)||declared==="screenshot")return "screenshot";
    if(/\/report\//i.test(path)||["report","aggregate-report"].includes(declared))return declared||"report";
    if(["port-scan","portscan"].includes(declared))return "port-scan";
    if(["endpoint-artifact","origin-artifact","service"].includes(declared))return "endpoint-artifact";
    if(/\/scans\/(?:xml\/)?_(?:quick|full|all|top).*nmap/i.test(path)||/\/scans\/_.*nmap/i.test(path))return "port-scan";
    if(/\/scans\/(?:tcp|udp)\d+\//i.test(path)||/\/scans\/(?:tcp|udp)_?\d+_/i.test(path))return "endpoint-artifact";
    if(["commands","manual-commands","errors","patterns"].includes(declared))return declared;
    if(["screenshot","report","aggregate-report","loot","exploit"].includes(declared))return declared;
    return "other";
  }

  function recordRank(row={}){
    return (lifecycle(row)==="canonical"?1e15:0)+Math.max(0,number(row.revision||row.sourceRevision))*1e12+(Date.parse(text(row.updatedAt||row.observedAt))||0);
  }
  function stableArtifactId(row={},index=0){
    const path=normalizePath(row.logicalPath||row.path||row.sourcePath);
    if(path)return "path:"+path.toLowerCase();
    const artifact=text(row.artifactId||row.sourceArtifactId);
    if(artifact)return "artifact:"+artifact;
    return "record:"+text(row.id||index);
  }
  function artifactProjection(row={},index=0){
    const classification=object(row.classification),owner=object(row.owner);
    const path=normalizePath(row.logicalPath||row.path||row.sourcePath);
    const filename=text(row.filename||row.originalFilename||basename(path))||"Retained artifact";
    const category=artifactCategory(row),recordLifecycle=lifecycle(row);
    const originalId=text(row.id),artifactId=text(row.artifactId||row.sourceArtifactId);
    const ownerProtocol=lower(owner.protocol||row.protocol),ownerPort=number(owner.port||row.port);
    const semanticKind=text(row.semanticKind||classification.semanticKind),previewSource=semanticKind==="external-autorecon-notes"?row.semanticPreview:(row.preview??row.raw??"");
    const tool=text(classification.tool||row.tool||row.source||row.parser||row.parserType)||"Unparsed artifact";
    const artifactParser=value=>lower(tool)==="feroxbuster"?"feroxbuster-text":text(value)||"Unparsed";
    return {
      id:stableArtifactId(row,index),recordId:originalId,artifactId,
      filename,path,physicalSourcePath:normalizePath(row.physicalSourcePath),sourceRelativePath:normalizePath(row.sourceRelativePath||row.physicalSourcePath),category,
      tool,parser:artifactParser(row.parser||row.parserType||classification.parser||classification.tool),
      representation:lower(row.representation||classification.representation||extension(filename))||"unknown",
      routingLevel:text(classification.routingLevel||row.routingLevel)||pretty(owner.kind||"host"),
      owner:{
        kind:lower(owner.kind||row.ownerKind)||"host",
        id:text(owner.id),endpointId:text(owner.endpointId||row.endpointId),
        protocol:ownerProtocol,port:ownerPort,url:text(owner.url||row.originUrl),reason:text(owner.reason)
      },
      routeReason:text(row.routeReason||owner.reason),
      artifactLifecycle:recordLifecycle,provisional:recordLifecycle==="provisional",
      revision:recordLifecycle==="provisional"?0:Math.max(1,number(row.revision||row.sourceRevision)||1),
      size:Math.max(0,number(row.size)),
      reviewState:reviewState(row.reviewState),annotation:string(row.annotation||""),
      preview:string(previewSource),previewTruncated:row.previewTruncated===true,previewPolicy:lower(row.previewPolicy),
      metadataOnly:row.metadataOnly===true,binary:row.binary===true,
      image:row.image===true||/^image\//i.test(text(row.mime))||/^(png|jpe?g|gif|webp|bmp|svg|avif)$/i.test(extension(filename)),
      activeContent:row.activeContent===true||/^(html?|svg|js)$/i.test(extension(filename)),
      exactRetained:row.exactRetained===true,unparsed:row.unparsed===true,
      displayScope:text(row.displayScope||row.scope)||"host",
      runId:text(row.runId),runStatus:text(row.runStatus),lastModified:Math.max(0,number(row.lastModified)),updatedAt:text(row.updatedAt||row.observedAt),
      fallback:row.fallback===true,canonicalRaw:row.fallback===true?string(row.raw??row.preview??""):"",
      operationStatus:lower(row.operationStatus||row.status),command:text(row.command),target:text(row.targetAddress||row.target),
      semanticKind,scannerEvidence:classification.scannerEvidence!==false,
      endpointReferences:values(row.endpointReferences).map(reference=>({endpointId:text(reference?.endpointId),protocol:lower(reference?.protocol||"tcp"),port:number(reference?.port)}))
    };
  }

  function fallbackScanArtifacts(host={},existing=[]){
    const artifactIds=new Set(existing.map(row=>row.artifactId).filter(Boolean));
    const paths=new Set(existing.map(row=>lower(row.path)).filter(Boolean));
    const output=[];
    values(host?.scanImportProjection?.sources).forEach((source,index)=>{
      const path=normalizePath(source?.sourcePath),artifactId=text(source?.sourceArtifactId);
      if(!source||artifactIds.has(artifactId)||(path&&paths.has(lower(path))))return;
      const revision=Math.max(1,number(source.sourceRevision)||1),stored=values(host.scanArtifacts).find(row=>text(row.id)===artifactId);
      const retainedRevision=values(stored?.revisions).find(row=>number(row.revision)===revision)||(stored&&Math.max(1,number(stored.currentRevision)||1)===revision?stored:null);
      const retained=Boolean(retainedRevision?.storedFilename),raw=string(source.raw||"");
      output.push(artifactProjection({
        id:"scan-source:"+text(source.key||index),artifactId,path,
        filename:basename(path)||text(source.source)||"Imported scan",
        category:"port-scan",classification:{category:"port-scan",tool:text(source.source)||"Nmap"},
        parserType:source.parserType,representation:source.representation,
        provisional:source.provisional===true,sourceRevision:source.sourceRevision,
        size:retained?number(retainedRevision.size):raw.length,preview:raw,
        previewTruncated:retained&&!raw.length,exactRetained:retained||Boolean(raw),fallback:!retained,raw,
        operationStatus:source.operationStatus,command:source.command,targetAddress:source.targetAddress,
        updatedAt:source.updatedAt
      },index));
    });
    return output;
  }

  function artifactRows(host={},additional=[]){
    const candidates=[...values(host?.recon?.autoReconArtifacts),...values(additional)],byId=new Map();
    candidates.forEach((row,index)=>{
      if(!row||typeof row!=="object")return;
      const semantic=serviceApi.semanticDisposition?.({path:row.logicalPath||row.path||row.sourcePath,classification:object(row.classification),text:row.previewTruncated===true?undefined:row.preview,contentAvailable:row.previewTruncated!==true&&own(row,"preview")})||{action:"retain"};
      if(semantic.action==="ignore")return;
      const source=semantic.kind==="external-autorecon-notes"?{...row,classification:serviceApi.applySemanticClassification?.(row.classification,semantic)||row.classification,semanticKind:semantic.kind,semanticPreview:semantic.meaningfulText}:row;
      const projected=artifactProjection(source,index),current=byId.get(projected.id),rank=recordRank(row);
      if(!current||rank>=current.rank)byId.set(projected.id,{rank,row:projected});
    });
    const projected=[...byId.values()].map(item=>item.row);
    for(const fallback of fallbackScanArtifacts(host,projected))if(!byId.has(fallback.id))projected.push(fallback);
    return projected.sort((left,right)=>left.path.localeCompare(right.path)||left.filename.localeCompare(right.filename));
  }

  function strongServiceEvidence(row={}){
    const protocol=lower(row.protocol||"tcp"),state=lower(row.state||"open");
    if(protocol==="tcp")return state==="open";
    if(protocol!=="udp")return false;
    if(state==="open")return true;
    const response=row.protocolResponse===true||row.manualConfirmed===true||lower(row.serviceMethod)==="probed";
    const product=lower(row.product||row.details);
    return state==="open|filtered"&&response&&product!=="no-response";
  }

  function endpointRows(host={}){
    const byId=new Map();
    values(host.serviceInventory).forEach((row,index)=>{
      if(!row||row.active===false)return;
      const protocol=lower(row.protocol||"tcp"),port=number(row.port);
      if(!port||!["tcp","udp"].includes(protocol))return;
      const id=text(row.endpointId||row.id)||"endpoint:"+protocol+":"+port+":"+index;
      const state=lower(row.state||"open")||"open";
      const established=text(row.service),rawHint=text(row.serviceRaw||row.serviceHint);
      const identified=row.identified===true||lower(row.identificationState)==="identified";
      const projected={
        id,endpointId:id,key:endpointKey(protocol,port),protocol,port,state,
        service:established,serviceHint:text(row.serviceHint),serviceRaw:text(row.serviceRaw),
        product:text(row.product),version:text(row.version),extraInfo:text(row.extraInfo),
        cpe:text(row.cpe),identified,confidence:text(row.serviceIdentity?.state||row.identificationState||row.confidence)||"unknown",
        source:text(row.source),sourceSlot:text(row.sourceSlot),sourceArtifactId:text(row.sourceArtifactId),sourceRevision:number(row.sourceRevision),
        provisional:lifecycle(row)==="provisional",artifactLifecycle:lifecycle(row),
        workspace:strongServiceEvidence(row),protocolResponse:row.protocolResponse===true,
        manualConfirmed:row.manualConfirmed===true,serviceConfirmed:row.serviceConfirmed===true,serviceMethod:text(row.serviceMethod),identificationState:text(row.identificationState),serviceIdentity:object(row.serviceIdentity),
        rawHintDifferent:Boolean(rawHint&&established&&lower(rawHint)!==lower(established)),
        displayState:text(row.displayState||row.enumerationState||state)
      };
      const current=byId.get(id);
      if(!current||projected.workspace&&!current.workspace||projected.identified&&!current.identified)byId.set(id,projected);
    });
    return [...byId.values()].sort((left,right)=>left.protocol.localeCompare(right.protocol)||left.port-right.port);
  }

  function exactOriginRows(host={}){
    const byOrigin=new Map();
    values(host?.recon?.webTargets).forEach((row,index)=>{
      if(!row||row.recordRole!=="web-origin"||row.active===false)return;
      let parsed;
      try{parsed=new URL(text(row.url||row.value));}catch(_error){return;}
      if(!["http:","https:"].includes(parsed.protocol))return;
      const url=parsed.origin,key=url.toLowerCase();
      if(byOrigin.has(key))return;
      byOrigin.set(key,{
        id:text(row.id||row.originId||row.key)||"origin-"+index,
        url,scheme:parsed.protocol.slice(0,-1),host:parsed.hostname,
        port:number(parsed.port)||(parsed.protocol==="https:"?443:80),
        endpointId:text(row.endpointId||row.serviceEndpointId),
        sourceArtifactId:text(row.sourceArtifactId)
      });
    });
    return [...byOrigin.values()].sort((left,right)=>left.url.localeCompare(right.url));
  }

  function sourceMetadata(host={}){
    const byArtifact=new Map();
    values(host?.scanImportProjection?.sources).forEach(source=>{
      const record={
        artifactId:text(source?.sourceArtifactId),path:normalizePath(source?.sourcePath),
        representation:lower(source?.representation||source?.format),parser:text(source?.parserType),
        target:text(source?.targetAddress),operationStatus:lower(source?.operationStatus||source?.status),
        command:text(source?.command),runIdentity:text(source?.runIdentity)
      };
      if(record.artifactId)byArtifact.set(record.artifactId,record);
      if(record.path)byArtifact.set("path:"+lower(record.path),record);
    });
    return byArtifact;
  }

  function feroxbusterResultsForArtifact(host={},artifact={},endpoint=null){
    const ferox=[artifact.tool,artifact.parser,artifact.representation].some(value=>lower(value).includes("feroxbuster"));
    if(!ferox)return null;
    const sources=values(host?.recon?.webImportProjection?.sources).filter(source=>lower(source?.tool)==="feroxbuster"&&values(source?.records).length);
    if(!sources.length)return null;
    const artifactPath=lower(artifact.path),physicalPath=lower(artifact.physicalSourcePath),endpointId=text(endpoint?.id||artifact.owner?.endpointId),originId=text(artifact.owner?.kind==="origin"?artifact.owner.id:""),artifactId=text(artifact.artifactId);
    const scored=sources.map(source=>{
      const sourcePaths=[lower(source?.logicalPath),lower(source?.physicalSourcePath)].filter(Boolean),exactArtifact=artifactId&&text(source?.artifactId)===artifactId,exactPath=sourcePaths.some(path=>path===artifactPath||path===physicalPath||path.endsWith("/"+artifactPath)),sameEndpoint=endpointId&&text(source?.endpointId)===endpointId,sameOrigin=originId&&values(source?.originIds).map(text).includes(originId),sameLifecycle=lifecycle(source)===artifact.artifactLifecycle;
      return {source,exactArtifact,exactPath,sameEndpoint,sameOrigin,score:(exactArtifact?1000:0)+(exactPath?800:0)+(sameEndpoint?120:0)+(sameOrigin?80:0)+(sameLifecycle?20:0)+(Date.parse(source?.observedAt)||0)/1e15};
    }).filter(candidate=>candidate.exactArtifact||candidate.exactPath||candidate.sameEndpoint||candidate.sameOrigin).sort((left,right)=>right.score-left.score);
    const selected=scored[0]?.source;if(!selected)return null;
    const records=values(selected.records).filter(row=>Number.isFinite(Number(row?.status))).map(row=>({
      status:Number(row.status),method:text(row.method)||"GET",lines:Math.max(0,number(row.lines)),words:Math.max(0,number(row.words)),bytes:Math.max(0,number(row.length??row.bytes)),
      url:text(row.url||row.value),path:text(row.path)||"/",redirect:text(row.redirect),origin:text(row.origin),host:text(row.host),port:Math.max(0,number(row.port))
    }));
    return records.length?{tool:"Feroxbuster",format:"feroxbuster-text",artifactId:text(selected.artifactId),resultCount:Math.max(records.length,number(selected.resultCount)),endpointId:text(selected.endpointId),observedAt:text(selected.observedAt),records}:null;
  }

  function endpointOwnerKey(protocol,port){return string(protocol||"tcp")+"\u241f"+typeof port+"\u241f"+string(port);}
  function endpointRelationshipIndexes(endpoints,origins){
    const endpointById=new Map(),endpointByKey=new Map(),endpointByOwner=new Map(),originById=new Map(),originByUrl=new Map();
    endpoints.forEach(endpoint=>{
      endpointById.set(endpoint.id,endpoint);
      if(!endpointByKey.has(endpoint.key))endpointByKey.set(endpoint.key,endpoint);
      const ownerKey=endpointOwnerKey(endpoint.protocol,endpoint.port);
      if(!endpointByOwner.has(ownerKey))endpointByOwner.set(ownerKey,endpoint);
    });
    origins.forEach(origin=>{
      if(!originById.has(origin.id))originById.set(origin.id,origin);
      if(!originByUrl.has(lower(origin.url)))originByUrl.set(lower(origin.url),origin);
    });
    return {endpointById,endpointByKey,endpointByOwner,originById,originByUrl};
  }

  function endpointForArtifact(artifact,endpoints,origins,indexes=endpointRelationshipIndexes(endpoints,origins)){
    const owner=artifact.owner||{};
    const direct=owner.endpointId||((owner.kind==="endpoint"&&owner.id)?owner.id:"");
    if(direct){
      const match=indexes.endpointById.get(direct);
      if(match)return match;
    }
    if(owner.kind==="origin"){
      const origin=indexes.originById.get(owner.id)||indexes.originByUrl.get(lower(owner.url));
      if(origin){
        const match=indexes.endpointById.get(origin.endpointId);
        if(match)return match;
      }
    }
    if(owner.port){
      const match=indexes.endpointByOwner.get(endpointOwnerKey(owner.protocol||"tcp",owner.port));
      if(match)return match;
    }
    const pathMatch=artifact.path.match(/\/scans\/(tcp|udp)(\d+)\//i)||artifact.filename.match(/^(tcp|udp)_?(\d+)_/i);
    if(pathMatch)return indexes.endpointByKey.get(endpointKey(pathMatch[1],pathMatch[2]))||null;
    return null;
  }

  function canonicalSection(artifact,endpoint){
    if(artifact.category==="port-scan")return "port-scans";
    if(artifact.category==="endpoint-artifact")return endpoint?.workspace?"services":endpoint?.protocol==="udp"?"port-scans":"artifact-inventory";
    if(["commands","manual-commands","errors","patterns"].includes(artifact.category))return "commands-signals";
    if(["report","aggregate-report","screenshot","external-notes"].includes(artifact.category))return "report-evidence";
    if(["loot","exploit"].includes(artifact.category))return "loot-exploit";
    return "artifact-inventory";
  }

  function artifactLabel(artifact){
    const name=artifact.filename,suffix=extension(name)==="xml"?" · XML":extension(name)==="gnmap"?" · Grepable":extension(name)==="nmap"?" · Nmap format":"";
    if(artifact.category==="port-scan"){
      if(/quick.*tcp/i.test(name))return "Quick TCP Nmap"+suffix;
      if(/(?:full|all).*tcp/i.test(name))return "Full TCP Nmap"+suffix;
      if(/top.*udp|udp/i.test(name))return "UDP Nmap"+suffix;
      return "Port Scan · "+name+suffix;
    }
    if(artifact.category==="commands")return "Commands Run";
    if(artifact.category==="manual-commands")return "Manual Follow-up Commands";
    if(artifact.category==="errors")return "AutoRecon Errors";
    if(artifact.category==="patterns")return "Pattern Matches";
    if(artifact.category==="report"){
      if(lower(name)==="notes.txt")return "Report Notes";
    }
    if(artifact.category==="external-notes")return "External AutoRecon Notes";
    return artifact.tool+" · "+name;
  }

  function serviceName(endpoint={}){
    const service=text(endpoint.service);
    if(service)return /^(ssh|http|https|ftp|smtp|smb|ldap|rdp|dns|snmp|nfs|rpc|imap|pop3|vnc)$/i.test(service)?service.toUpperCase():service;
    const hint=text(endpoint.serviceHint||endpoint.serviceRaw);
    return hint&&hint!=="unknown"?hint+"?":"Unknown";
  }

  function serviceSummary(endpoint,origins=[]){
    const lines=[
      "Endpoint: "+endpoint.port+"/"+endpoint.protocol,
      "State: "+endpoint.state,
      "Service: "+(endpoint.service||"Unknown"),
      "Service family: "+(endpoint.classification?.family||"Other / Unclassified"),
      "Classification: "+(endpoint.classification?.source||"Automatic"),
      "Product / version: "+([endpoint.product,endpoint.version].filter(Boolean).join(" ")||"Unresolved")
    ];
    if(endpoint.rawHintDifferent)lines.push("Nmap scanner hint: "+(endpoint.serviceRaw||endpoint.serviceHint)+"?");
    if(endpoint.extraInfo)lines.push("Extra information: "+endpoint.extraInfo);
    if(endpoint.cpe)lines.push("CPE: "+endpoint.cpe);
    if(origins.length)lines.push("Exact web origins: "+origins.map(row=>row.url).join(", "));
    lines.push("Evidence owner: "+endpoint.id);
    lines.push("");
    lines.push("Complete source artifacts are retained below. Automatic glow is visual only; add manual markers in Edit mode to create operator follow-up boxes.");
    return lines.join("\n");
  }

  function attackSurfaceSummary(host,endpoints,workspaces,origins,artifacts){
    const tcp=endpoints.filter(row=>row.protocol==="tcp"),udp=endpoints.filter(row=>row.protocol==="udp");
    const lines=[
      "Host: "+text(host.ip||host.hostname||"Selected host"),
      "Retained open endpoint candidates: "+endpoints.length+" (TCP "+tcp.length+" · UDP "+udp.length+")",
      "Authoritative service workspaces: "+workspaces.length,
      "Retained AutoRecon artifacts: "+artifacts.length,
      "",
      "Confirmed/open service workspaces:"
    ];
    if(workspaces.length)workspaces.forEach(row=>lines.push("- "+row.port+"/"+row.protocol+" "+serviceName(row)+" — "+([row.product,row.version].filter(Boolean).join(" ")||"product/version unresolved")));
    else lines.push("- None retained");
    const uncertainUdp=udp.filter(row=>!row.workspace);
    if(uncertainUdp.length)lines.push("","UDP candidates retained in Port Scans: "+uncertainUdp.length+" open|filtered/no-response endpoint"+(uncertainUdp.length===1?"":"s")+"; none promoted to a confirmed service.");
    if(origins.length)lines.push("","Exact web origins:",...origins.map(row=>"- "+row.url));
    return lines.join("\n");
  }

  function lowHangingSummary(host,workspaces,origins){
    const lines=[];
    values(host.vulnerabilityLeads).filter(row=>row&&row.active!==false).slice(0,12).forEach(row=>{
      lines.push("- "+text(row.title||row.name||row.summary||"Retained access lead")+" — "+pretty(row.status||"lead"));
    });
    workspaces.filter(row=>row.product||row.version).forEach(row=>{
      lines.push("- Research "+([row.product,row.version].filter(Boolean).join(" "))+" for public exploits / CVEs; retained identity is evidence, not proof of applicability.");
    });
    if(origins.length)lines.push("- Review "+origins.length+" exact web origin"+(origins.length===1?"":"s")+" in the existing Web App Review while service validation continues.");
    return lines.length?lines.join("\n"):"No obvious lead is promoted automatically. Record operator-owned versions, login surfaces, shares, default credentials, or parallel research here.";
  }

  function takeawaySummary(host,artifacts,endpoints,workspaces){
    const existing=text(host?.recon?.notes),lines=existing?[existing,""]:[];
    const reviewCount=artifacts.filter(row=>["new","follow-up-required"].includes(row.reviewState)).length;
    const uncertain=endpoints.filter(row=>!row.workspace).length;
    if(reviewCount)lines.push("- Review "+reviewCount+" new or follow-up artifact"+(reviewCount===1?"":"s")+".");
    if(uncertain)lines.push("- Keep "+uncertain+" uncertain endpoint candidate"+(uncertain===1?"":"s")+" in evidence-only validation lanes.");
    if(workspaces.some(row=>row.rawHintDifferent))lines.push("- Preserve scanner hints separately from established protocol identity.");
    if(!lines.length)lines.push("Record operator priorities and next actions after reviewing retained evidence.");
    return lines.join("\n");
  }

  function project(host={},options={}){
    const artifacts=artifactRows(host,options.artifacts),endpoints=endpointRows(host),origins=exactOriginRows(host),metadata=sourceMetadata(host);
    const workspaces=endpoints.filter(row=>row.workspace);
    const relationshipIndexes=endpointRelationshipIndexes(endpoints,origins);
    artifacts.forEach(artifact=>{
      const source=metadata.get(artifact.artifactId)||metadata.get("path:"+lower(artifact.path));
      if(source){
        artifact.representation=source.representation||artifact.representation;
        artifact.parser=lower(artifact.tool)==="feroxbuster"?"feroxbuster-text":source.parser||artifact.parser;
        artifact.target=source.target||artifact.target;
        artifact.operationStatus=source.operationStatus||artifact.operationStatus;
        artifact.command=source.command||artifact.command;
      }
      const endpoint=endpointForArtifact(artifact,endpoints,origins,relationshipIndexes);
      artifact.endpointId=endpoint?.id||"";
      artifact.endpointKey=endpoint?.key||"";
      artifact.structuredResults=feroxbusterResultsForArtifact(host,artifact,endpoint);
      artifact.section=canonicalSection(artifact,endpoint);
      artifact.label=artifactLabel(artifact);
    });
    const originsByEndpoint=new Map(),serviceArtifactsByEndpoint=new Map(),referencesByEndpoint=new Map();
    const workspaceIdsByKey=new Map(),workspaceIdsBySourceArtifact=new Map();
    const append=(map,key,value)=>{if(!key)return;if(!map.has(key))map.set(key,[]);map.get(key).push(value);};
    const appendUnique=(map,key,value)=>{if(!key)return;if(!map.has(key))map.set(key,new Set());map.get(key).add(value);};
    workspaces.forEach(endpoint=>{
      append(workspaceIdsByKey,endpoint.key,endpoint.id);
      if(endpoint.sourceArtifactId)append(workspaceIdsBySourceArtifact,endpoint.sourceArtifactId,endpoint.id);
    });
    origins.forEach(origin=>append(originsByEndpoint,origin.endpointId,origin));
    artifacts.forEach(artifact=>{
      if(artifact.section==="services"){
        appendUnique(serviceArtifactsByEndpoint,artifact.endpointId,artifact);
        (workspaceIdsByKey.get(artifact.endpointKey)||[]).forEach(endpointId=>appendUnique(serviceArtifactsByEndpoint,endpointId,artifact));
        return;
      }
      if(artifact.artifactId)(workspaceIdsBySourceArtifact.get(artifact.artifactId)||[]).forEach(endpointId=>appendUnique(referencesByEndpoint,endpointId,artifact));
      artifact.endpointReferences.forEach(reference=>{
        if(reference.endpointId&&relationshipIndexes.endpointById.has(reference.endpointId))appendUnique(referencesByEndpoint,reference.endpointId,artifact);
        const referenced=relationshipIndexes.endpointByKey.get(endpointKey(reference.protocol,reference.port));
        if(referenced)(workspaceIdsByKey.get(referenced.key)||[]).forEach(endpointId=>appendUnique(referencesByEndpoint,endpointId,artifact));
      });
    });
    const state=ensureState(options.state||{}),serviceRows=workspaces.map(endpoint=>{
      const endpointOrigins=originsByEndpoint.get(endpoint.id)||[];
      const endpointArtifacts=[...(serviceArtifactsByEndpoint.get(endpoint.id)||[])];
      const references=[...(referencesByEndpoint.get(endpoint.id)||[])];
      const classification=serviceApi.classifyServiceEndpoint?.(endpoint,endpointArtifacts,{manualMappings:state.serviceMappings,customFamilies:state.customServiceFamilies})||{family:"Other / Unclassified",source:"Automatic",reason:"No service classifier is available.",reviewRank:1000,detectedAs:endpoint.service||endpoint.serviceHint||"unknown"};
      const row={...endpoint,classification,origins:endpointOrigins,artifacts:endpointArtifacts,references};
      return {...row,summary:serviceSummary(row,endpointOrigins)};
    });
    const sections={};
    VIEW_KEYS.forEach(key=>sections[key]=[]);
    artifacts.forEach(artifact=>(sections[artifact.section]||sections["artifact-inventory"]).push(artifact));
    const unclassified=sections["artifact-inventory"].length;
    const model={
      host:{id:text(host.id),label:text(options.projection?.host?.label||host.hostname||host.ip)||"Selected host",address:text(options.projection?.host?.primaryAddress||host.ip||host.hostname)},
      artifacts,endpoints,origins,workspaces:serviceRows,sections,
      overview:{
        attackSurface:attackSurfaceSummary(host,endpoints,workspaces,origins,artifacts),
        lowHanging:lowHangingSummary(host,workspaces,origins),
        takeaways:takeawaySummary(host,artifacts,endpoints,workspaces)
      },
      metrics:{
        artifacts:artifacts.length,represented:artifacts.length,services:serviceRows.length,endpointCandidates:endpoints.length,
        serviceWorkspaces:new Set(serviceRows.map(row=>row.classification.family)).size,serviceFamilies:new Set(serviceRows.map(row=>row.classification.family)).size,unclassified,
        canonical:artifacts.filter(row=>!row.provisional).length,
        provisional:artifacts.filter(row=>row.provisional).length
      },
      gaps:values(options.projection?.gaps)
    };
    return deepFreeze(model);
  }

  function cardEntry(runtime,key){
    const cards=runtime.state.cards;
    if(!cards[key]||typeof cards[key]!=="object"||Array.isArray(cards[key]))cards[key]={};
    return cards[key];
  }
  function artifactCardKey(artifact){return "artifact::"+artifact.id;}
  function derivedSpec(key,title,description,baseline,options={}){
    return {key,title,description,baseline:string(baseline),imported:false,autoTriage:options.autoTriage===true,kind:options.kind||"derived",extraAction:options.extraAction||"",commandNote:options.commandNote===true,commandEntity:text(options.commandEntity)};
  }
  function artifactSpec(artifact,options={}){
    return {
      key:artifactCardKey(artifact),title:artifact.label,description:artifact.path,
      baseline:artifact.preview,imported:true,autoTriage:true,kind:"artifact",
      artifact,sensitive:options.sensitive===true,commandNote:options.commandNote!==false,commandEntity:text(options.commandEntity||artifact.endpointKey||artifact.endpointId||artifact.filename)
    };
  }
  function baselineValue(runtime,spec){
    if(spec.imported&&runtime.rawCache.has(spec.artifact.id))return runtime.rawCache.get(spec.artifact.id);
    return string(spec.baseline);
  }
  function currentValue(runtime,spec){
    const entry=cardEntry(runtime,spec.key);
    return entry.edited===true&&own(entry,"workingCopy")?string(entry.workingCopy):baselineValue(runtime,spec);
  }
  function hasCompleteRetainedSource(artifact){return artifact?.fallback===true||artifact?.exactRetained===true;}
  function artifactSourceVersion(artifact={}){
    return [artifact.artifactLifecycle,artifact.artifactId,artifact.revision,artifact.size,artifact.lastModified,artifact.path].map(string).join("\u241f");
  }
  function sourceLoadable(runtime,artifact={}){
    if(artifact.provisional===true)return typeof runtime.adapters.readCurrentRaw==="function";
    return hasCompleteRetainedSource(artifact)&&(artifact.fallback===true||typeof runtime.adapters.readRaw==="function");
  }
  function sourceKind(artifact={}){return artifact.provisional===true?"provisional":"canonical";}
  function completeSourceRequired(runtime,spec){
    if(!spec?.imported||!spec.artifact||spec.artifact.size===0||spec.artifact.binary||spec.artifact.image)return false;
    const entry=cardEntry(runtime,spec.key),artifact=spec.artifact,policy=lower(artifact.previewPolicy);
    if(entry.edited===true||runtime.rawCache.has(artifact.id))return false;
    return artifact.previewTruncated===true||artifact.metadataOnly===true||!string(spec.baseline).length||policy.includes("suppressed")||policy==="metadata-only";
  }
  function shouldLoadCompleteSource(runtime,spec){return completeSourceRequired(runtime,spec)&&!spec?.sensitive&&sourceLoadable(runtime,spec?.artifact);}
  function defaultCollapsed(spec){
    if(!spec.imported||spec.artifact.size===0)return false;
    return extension(spec.artifact.filename)==="xml"||spec.artifact.size>=LARGE_ARTIFACT_BYTES;
  }
  function isCollapsed(runtime,spec){
    const entry=cardEntry(runtime,spec.key);
    return own(entry,"collapsed")?entry.collapsed===true:defaultCollapsed(spec);
  }
  function cardMode(runtime,spec){
    const entry=cardEntry(runtime,spec.key);
    if(entry.mode==="edit"||entry.mode==="preview")return entry.mode;
    if(spec.imported&&spec.artifact?.size>0)return "preview";
    return currentValue(runtime,spec).trim()?"preview":"edit";
  }
  function statePill(value){
    const normalized=lower(value).replace(/[^a-z0-9-]+/g,"-")||"unknown";
    return '<span class="initial-recon-state status-'+escapeAttr(normalized)+'">'+escapeHtml(pretty(value))+"</span>";
  }
  function emptyState(title,detail){
    return '<div class="initial-recon-empty"><strong>'+escapeHtml(title)+"</strong><span>"+escapeHtml(detail)+"</span></div>";
  }
  function annotatedLineHtml(row){
    const segments=values(row?.segments);
    const body=segments.length?segments.map(segment=>segment.signal?'<span class="inline-glow">'+escapeHtml(segment.text)+"</span>":escapeHtml(segment.text)).join(""):escapeHtml(row?.text??row?.raw??"");
    return '<span class="recon-output-line '+(row?.kind==="noise"?"recon-output-noise":"recon-output-normal")+'">'+(body||"&nbsp;")+"</span>";
  }
  function manualPreviewHtml(value){
    const source=string(value);
    if(!source.trim())return '<span class="artifact-empty-message">Nothing recorded yet.</span>';
    const expression=/\x60([^\x60\n]+)\x60/g;
    let output="",cursor=0,match;
    while((match=expression.exec(source))){
      output+=escapeHtml(source.slice(cursor,match.index));
      output+='<span class="inline-glow">'+escapeHtml(match[1])+"</span>";
      cursor=match.index+match[0].length;
    }
    output+=escapeHtml(source.slice(cursor));
    return output.replace(/\r?\n/g,"<br>");
  }
  function redirectReview(row={}){
    if(!row.redirect)return {external:false,label:""};
    try{
      const source=new URL(row.url),target=new URL(row.redirect);
      return {external:source.hostname.toLowerCase()!==target.hostname.toLowerCase(),label:source.hostname.toLowerCase()!==target.hostname.toLowerCase()?"Observed external redirect target · Operator review required":"Observed redirect target"};
    }catch(_error){return {external:true,label:"Observed redirect target · Operator review required"};}
  }
  function feroxbusterResultsHtml(artifact={}){
    const summary=artifact.structuredResults,records=values(summary?.records);if(!records.length)return "";
    const groups=new Map();records.forEach(row=>{const key=number(row.status);if(!groups.has(key))groups.set(key,[]);groups.get(key).push(row);});
    const endpoint=artifact.endpointKey?artifact.endpointKey.replace(":","/").toUpperCase():artifact.owner?.port?lower(artifact.owner.protocol||"tcp").toUpperCase()+"/"+number(artifact.owner.port):"SELECTED ENDPOINT";
    const grouped=[...groups.entries()].sort((left,right)=>left[0]-right[0]).map(([status,rows])=>{
      const resultRows=rows.map(row=>{
        const redirect=redirectReview(row),metadata=[text(row.method)||"GET",number(row.lines)+"l",number(row.words)+"w",number(row.bytes)+"c"].join(" ");
        const redirectHtml=row.redirect?'<small class="feroxbuster-redirect'+(redirect.external?' is-external':'')+'"><span>'+escapeHtml(redirect.label)+'</span><br><code>→ '+escapeHtml(row.redirect)+'</code></small>':"";
        return '<article class="feroxbuster-result-row feature-list-row" data-ferox-status="'+status+'" data-ferox-url="'+escapeAttr(row.url)+'"><div class="feature-list-copy"><div class="feature-row-meta"><span class="feroxbuster-result-status feature-state-tag status-'+status+'">'+status+'</span><code class="feroxbuster-result-metadata">'+escapeHtml(metadata)+'</code></div><strong title="'+escapeAttr(row.url)+'">'+escapeHtml(row.path||row.url||"/")+'</strong>'+redirectHtml+'</div></article>';
      }).join("");
      return '<details class="feroxbuster-status-group feature-disclosure" data-ferox-status-group="'+status+'" open><summary><span>'+status+' responses</span><small>'+rows.length+' response'+(rows.length===1?"":"s")+'</small></summary><div class="feature-disclosure-body">'+resultRows+'</div></details>';
    }).join("");
    return '<section class="feroxbuster-results feature-content-panel" data-feroxbuster-results><header class="feroxbuster-results-heading feature-content-head"><div><span class="initial-recon-kicker">Parsed Results</span><h4>FEROXBUSTER · '+escapeHtml(endpoint)+'</h4><p>'+number(summary.resultCount||records.length)+' responses discovered · enumeration evidence only</p></div></header><div class="feroxbuster-status-groups feature-compact-list">'+grouped+'</div></section>';
  }
  function retainedSourceStateHtml(runtime,spec){
    const artifact=spec.artifact,status=object(runtime.rawStatus.get(artifact.id));
    const kind=status.kind||sourceKind(artifact);
    if(status.state==="loading")return kind==="provisional"?'<div class="initial-recon-sensitive-preview" data-retained-source-state="loading" data-source-state="provisional-loading" role="status"><strong>Loading current / provisional source…</strong><span>Reading the current watched file into this browser session only. This is not canonical retained evidence.</span></div>':'<div class="initial-recon-sensitive-preview" data-retained-source-state="loading" data-source-state="canonical-loading" role="status"><strong>Loading retained source…</strong><span>Retrieving this artifact’s exact canonical text into the current browser session only.</span></div>';
    if(status.state==="error")return kind==="provisional"?'<div class="initial-recon-sensitive-preview" data-retained-source-state="read-failed" data-source-state="provisional-read-failed" role="alert"><strong>Current source read failed</strong><span>'+escapeHtml(status.message||"The active watched source could not be read.")+'</span><button class="secondary-btn small" data-card-load-complete="'+escapeAttr(spec.key)+'" type="button">Retry current source</button></div>':'<div class="initial-recon-sensitive-preview" data-retained-source-state="unavailable" data-source-state="canonical-read-failed" role="alert"><strong>Retained source unavailable</strong><span>'+escapeHtml(status.message||"The exact retained text could not be retrieved.")+'</span><button class="secondary-btn small" data-card-load-complete="'+escapeAttr(spec.key)+'" type="button">Retry retained source</button></div>';
    if(runtime.rawCache.has(artifact.id)){
      const cachedKind=object(runtime.rawSourceMeta.get(artifact.id)).kind||sourceKind(artifact);
      return cachedKind==="provisional"?'<div class="preview-truncated-note" data-retained-source-state="provisional-available" data-source-state="provisional-available"><strong>Current / provisional source</strong> · Read from the watched filesystem and cached only for this browser session. A later file change invalidates this copy; canonical retention becomes authoritative after promotion.</div>':'<div class="preview-truncated-note" data-retained-source-state="canonical-available" data-source-state="canonical-available"><strong>Canonical retained source</strong> · Exact text is available and cached only for this browser session.</div>';
    }
    if(artifact.provisional===true){
      const detail="Source is still being written. Showing current live/provisional evidence. Exact canonical retention will be available after the artifact reaches its terminal state.";
      return typeof runtime.adapters.readCurrentRaw==="function"?'<div class="preview-truncated-note" data-retained-source-state="provisional-pending" data-source-state="bounded-preview-available">'+escapeHtml(detail)+' <button class="secondary-btn small" data-card-load-complete="'+escapeAttr(spec.key)+'" type="button">Load current source</button></div>':'<div class="initial-recon-sensitive-preview" data-retained-source-state="provisional-pending" data-source-state="provisional-source-pending"><strong>Source is still being written</strong><span>'+escapeHtml(detail)+' The watched filesystem reader is unavailable in this session.</span></div>';
    }
    if(!hasCompleteRetainedSource(artifact))return '<div class="initial-recon-sensitive-preview" data-retained-source-state="unavailable" data-source-state="source-genuinely-unavailable" role="alert"><strong>Retained source unavailable</strong><span>This nonempty canonical inventory record has no exact retained text source. Its metadata remains available.</span></div>';
    if(!artifact.fallback&&typeof runtime.adapters.readRaw!=="function")return '<div class="initial-recon-sensitive-preview" data-retained-source-state="unavailable" role="alert"><strong>Retained source unavailable</strong><span>The exact source is retained, but the canonical reader is unavailable in this session.</span></div>';
    const detail=artifact.previewTruncated?"The persisted engagement contains only a bounded or suppressed preview.":"The persisted preview is unavailable.";
    return '<div class="preview-truncated-note" data-retained-source-state="available" data-source-state="bounded-preview-available">'+escapeHtml(detail)+' Exact text remains immutable and will be cached only for this browser session. <button class="secondary-btn small" data-card-load-complete="'+escapeAttr(spec.key)+'" type="button">Load complete source</button></div>';
  }
  function previewHtml(runtime,spec){
    const artifact=spec.artifact,value=currentValue(runtime,spec),entry=cardEntry(runtime,spec.key);
    if(artifact?.size===0)return '<span class="artifact-empty-message">Empty artifact retained — AutoRecon wrote zero bytes.</span>';
    if(spec.sensitive&&!runtime.revealedSensitive.has(spec.key))return '<div class="initial-recon-sensitive-preview"><strong>Safe metadata view</strong><span>Loot and exploit bytes are retained but never exposed in the ordinary persisted preview state. Use Inspect Safely for an escaped, session-only text view, or Download Copy for the exact retained file.</span></div>';
    if(artifact?.binary||artifact?.image)return '<div class="initial-recon-sensitive-preview"><strong>'+escapeHtml(artifact.image?"Image artifact retained":"Binary artifact retained")+'</strong><span>No fake text preview is generated. Use Download Copy for the exact retained file.</span></div>';
    const structured=feroxbusterResultsHtml(artifact);
    if(entry.edited===true&&!value.length)return structured+'<div class="initial-recon-sensitive-preview"><strong>Empty operator working copy</strong><span>Reset Imported restores the imported baseline.</span></div>';
    if(!value.length)return spec.imported?structured+retainedSourceStateHtml(runtime,spec):'<div class="initial-recon-sensitive-preview"><strong>No operator text yet</strong><span>Use Edit to add operator-owned notes.</span></div>';
    if(!spec.autoTriage)return manualPreviewHtml(value);
    const triage=runtime.adapters.triage,sourceLines=value.split(/\r?\n/),renderAll=entry.renderAll===true,truncated=!renderAll&&sourceLines.length>PREVIEW_LINE_BUDGET;
    const previewSource=truncated?sourceLines.slice(0,PREVIEW_LINE_BUDGET).join("\n"):value;
    const rows=triage?.triage?triage.triage(previewSource,{path:artifact?.path||spec.key,filename:artifact?.filename||spec.title,tool:artifact?.tool||spec.title,classification:{tool:artifact?.tool||spec.title}}):previewSource.split(/\r?\n/).map(raw=>({kind:"normal",raw,text:raw,segments:[{text:raw,signal:false}]}));
    const shown=rows;
    let rawHtml='<div class="recon-triage-preview">'+shown.map(annotatedLineHtml).join("")+"</div>";
    if(truncated)rawHtml+='<div class="preview-truncated-note">Preview is showing the first '+PREVIEW_LINE_BUDGET.toLocaleString()+" of "+sourceLines.length.toLocaleString()+' lines. No source text was discarded. <button class="secondary-btn small" data-card-render-all="'+escapeAttr(spec.key)+'" type="button">Render all '+sourceLines.length.toLocaleString()+" lines</button></div>";
    let html=rawHtml;
    if(structured){
      const cached=runtime.rawCache.has(artifact.id),cachedKind=object(runtime.rawSourceMeta.get(artifact.id)).kind||sourceKind(artifact),label=cached?(cachedKind==="provisional"?"Current / provisional source":"Canonical retained source"):"Configuration / bounded raw preview";
      html=structured+'<details class="feroxbuster-raw-source feature-disclosure" data-source-state="'+(cached?cachedKind+"-available":"bounded-preview-available")+'"'+(cached?" open":"")+'><summary><span>Raw Source</span><small>'+escapeHtml(label)+'</small></summary><div class="feroxbuster-raw-source-body feature-disclosure-body">'+rawHtml+"</div></details>";
    }
    if(artifact&&(completeSourceRequired(runtime,spec)||runtime.rawStatus.has(artifact.id)||runtime.rawSourceMeta.has(artifact.id)))html+=retainedSourceStateHtml(runtime,spec);
    return html;
  }
  function followUpTerms(runtime,value){
    const triage=runtime.adapters.triage;
    if(triage?.manualFollowUps)return triage.manualFollowUps(value);
    const output=[],seen=new Set();
    for(const match of string(value).matchAll(/\x60([^\x60\r\n]+)\x60/g)){
      const item=match[1].trim(),key=lower(item);
      if(item&&!seen.has(key)){seen.add(key);output.push(item);}
    }
    return output.slice(0,100);
  }
  function followUpsHtml(runtime,spec){
    const entry=cardEntry(runtime,spec.key);
    if(entry.edited!==true)return "";
    const terms=followUpTerms(runtime,currentValue(runtime,spec));
    if(!terms.length)return "";
    const persisted=object(runtime.state.followUps[spec.key]);
    return '<div class="dynamic-box-container"><div class="sys-generated-banner">Generated follow-up boxes from <span class="inline-glow">'+escapeHtml(spec.title)+"</span></div>"+terms.map(term=>{
      const termKey=lower(term),record=object(persisted[termKey]),notes=string(record.notes||""),mode=record.mode==="edit"||record.mode==="preview"?record.mode:(notes.trim()?"preview":"edit");
       return '<article class="sys-paste-card sys-dynamic-card '+(mode==="edit"?"is-editing":"is-previewing")+'" data-followup-source="'+escapeAttr(spec.key)+'" data-followup-term="'+escapeAttr(termKey)+'"><div class="sys-paste-title"><div><h4>Recon Follow-up — <span class="inline-glow">'+escapeHtml(term)+'</span></h4><span>Source: '+escapeHtml(spec.title)+' · generated only from an operator-authored marker in Edit mode.</span></div><div class="sys-paste-actions"><button class="secondary-btn small" data-followup-mode type="button">'+(mode==="edit"?"Preview":"Edit")+'</button></div></div><textarea class="notes-area sys-paste-area sys-dynamic-area" data-followup-notes placeholder="Validation, exploit research, notes, or follow-up output...">'+escapeHtml(notes)+'</textarea><div class="sys-paste-preview">'+manualPreviewHtml(notes)+"</div></article>";
    }).join("")+"</div>";
  }
  function artifactMetaHtml(artifact){
    const fields=[
      artifact.tool,pretty(artifact.category),artifact.parser,
      artifact.representation!=="unknown"?pretty(artifact.representation):"",
      artifact.target?"Target "+artifact.target:"",
      artifact.operationStatus?"Operation "+pretty(artifact.operationStatus):"",
      formatBytes(artifact.size)
    ].filter(Boolean);
    return '<div class="initial-recon-artifact-meta">'+fields.map(value=>"<span>"+escapeHtml(value)+"</span>").join("")+"</div>";
  }
  function cardHtml(runtime,spec){
    const entry=cardEntry(runtime,spec.key),artifact=spec.artifact,value=currentValue(runtime,spec),mode=cardMode(runtime,spec),collapsed=isCollapsed(runtime,spec);
    const empty=spec.imported&&artifact.size===0;
    const classes=["sys-paste-card","initial-recon-card",spec.imported?"artifact-card":"initial-recon-derived-card",mode==="edit"?"is-editing":"is-previewing",collapsed?"is-collapsed":"",empty?"artifact-empty-card":"",spec.sensitive?"is-sensitive":""].filter(Boolean).join(" ");
    const reset=spec.imported&&entry.edited===true?'<button class="secondary-btn small reset-import-btn" data-card-reset="'+escapeAttr(spec.key)+'" type="button">Reset Imported</button>':"";
    const collapse=spec.imported&&!empty?'<button class="secondary-btn small artifact-collapse-btn" aria-expanded="'+String(!collapsed)+'" data-card-collapse="'+escapeAttr(spec.key)+'" type="button">'+(collapsed?"Expand":"Collapse")+"</button>":"";
    const editable=!artifact?.binary&&!artifact?.image&&(!spec.sensitive||runtime.revealedSensitive.has(spec.key));
    const edit=editable?'<button class="secondary-btn small sys-edit-toggle" data-card-mode="'+escapeAttr(spec.key)+'" type="button">'+(mode==="edit"?"Preview":"Edit")+"</button>":"";
    const download=spec.imported&&(spec.sensitive||artifact?.binary||artifact?.image)?'<button class="secondary-btn small" data-card-download="'+escapeAttr(spec.key)+'" type="button">Download Copy</button>':"";
    const commandContext=JSON.stringify({host:runtime.model?.host?.address||"",entity:spec.commandEntity||artifact?.endpointKey||artifact?.filename||spec.title});
    const commandNote=spec.commandNote?'<button class="secondary-btn small command-note-open-btn" data-command-note-id="dynamic.port-notes" data-command-note-context="'+escapeAttr(commandContext)+'" type="button"><span>Command Note</span></button>':"";
    const sensitiveInspect=spec.sensitive&&!artifact?.binary&&!artifact?.image?'<button class="secondary-btn small" data-card-inspect-sensitive="'+escapeAttr(spec.key)+'" type="button">'+(runtime.revealedSensitive.has(spec.key)?"Hide Sensitive Preview":"Inspect Safely")+"</button>":"";
    let special=sensitiveInspect;
    if(spec.extraAction==="lead")special='<button class="secondary-btn small" data-initial-recon-add-lead type="button">Add Lead</button>';
    if(spec.extraAction==="notes")special='<button class="secondary-btn small" data-initial-recon-open-notes data-section-target="initial-recon-open-notes" type="button">Open full Notes</button>';
    const provenance=spec.imported?'<span class="sys-import-provenance">Imported · AutoRecon</span>':"";
    const lifecycleHtml=spec.imported?statePill(artifact.artifactLifecycle)+statePill("revision "+artifact.revision):"";
    const evidenceOnly=spec.imported&&["errors","patterns"].includes(artifact.category)?'<span class="initial-recon-evidence-only">Evidence only · not a Finding</span>':"";
    const revisionWarning=spec.imported&&entry.edited===true&&number(entry.baselineRevision)!==artifact.revision?'<p class="initial-recon-revision-warning">Canonical baseline advanced from revision '+number(entry.baselineRevision)+" to "+artifact.revision+". Your working copy is preserved; Reset Imported restores the current canonical baseline.</p>":"";
    const warning=artifact?.activeContent?'<p class="initial-recon-content-warning">Active content is untrusted. Preview is escaped, scripts never execute, and retained bytes remain attachment-only.</p>':"";
    const route=artifact?.routeReason?'<p class="initial-recon-route-reason">'+escapeHtml(artifact.routeReason)+"</p>":"";
    return '<article class="'+classes+'" id="initial-recon-artifact-'+safeId(spec.imported?artifact.id:spec.key)+'" data-card-key="'+escapeAttr(spec.key)+'"'+(spec.imported?' data-canonical-artifact-card="'+escapeAttr(artifact.id)+'"':"")+'><div class="sys-paste-title"><div><div class="initial-recon-card-badges">'+provenance+lifecycleHtml+evidenceOnly+'</div><h4>'+escapeHtml(spec.title)+"</h4><span>"+escapeHtml(spec.description)+"</span></div><div class=\"sys-paste-actions\">"+special+collapse+download+reset+edit+commandNote+"</div></div>"+(spec.imported?artifactMetaHtml(artifact):"")+route+warning+revisionWarning+'<div class="artifact-card-body"><textarea class="notes-area sys-paste-area'+(artifact?.size>=LARGE_ARTIFACT_BYTES?" tall-area":"")+'" data-card-editor="'+escapeAttr(spec.key)+'" aria-label="Edit '+escapeAttr(spec.title)+'">'+escapeHtml(value)+'</textarea><div class="sys-paste-preview">'+previewHtml(runtime,spec)+"</div>"+followUpsHtml(runtime,spec)+"</div></article>";
  }
  function artifactStack(runtime,artifacts,options={}){
    if(!artifacts.length)return emptyState(options.emptyTitle||"No retained artifacts",options.emptyDetail||"Current evidence has no artifact for this canonical section.");
    return '<div class="sys-paste-stack">'+artifacts.map(artifact=>cardHtml(runtime,artifactSpec(artifact,{sensitive:artifact.section==="loot-exploit",...options}))).join("")+"</div>";
  }

  function overviewHtml(runtime){
    const model=runtime.model;
    const specs=[
      derivedSpec("overview.attack-surface","Attack Surface Summary","Derived from retained endpoint and AutoRecon evidence. Automatic glow is visual only; manual markers create follow-up boxes.",model.overview.attackSurface,{autoTriage:true}),
      derivedSpec("overview.low-hanging","Low-Hanging Leads / Parallel Work","Operator-owned versions, login surfaces, exposed shares, public exploit research, and work that can proceed while scans continue.",model.overview.lowHanging,{autoTriage:true,extraAction:"lead"}),
      derivedSpec("overview.takeaways","Initial Recon Takeaways / Next Actions","Operator priorities after reviewing the imported evidence.",model.overview.takeaways,{extraAction:"notes"})
    ];
    return '<div class="sys-paste-stack initial-recon-overview-stack">'+specs.map(spec=>cardHtml(runtime,spec)).join("")+"</div>";
  }
  function uncertainUdpHtml(model){
    const rows=model.endpoints.filter(row=>row.protocol==="udp"&&!row.workspace);
    if(!rows.length)return "";
    return '<section class="initial-recon-udp-boundary"><strong>'+rows.length+' UDP open|filtered / no-response candidate'+(rows.length===1?"":"s")+' retained here</strong><p>These candidates remain scan evidence and are not promoted to confirmed Services without stronger protocol-specific evidence.</p><div>'+rows.map(row=>"<span>"+row.port+"/UDP · "+escapeHtml(row.serviceHint||row.serviceRaw||"unknown")+"</span>").join("")+"</div></section>";
  }
  function portScansHtml(runtime){
    return uncertainUdpHtml(runtime.model)+artifactStack(runtime,runtime.model.sections["port-scans"],{emptyTitle:"No retained port scans",emptyDetail:"Nmap normal, XML, grepable, TCP, and UDP source cards appear here as distinct evidence."});
  }
  function originsHtml(workspace){
    if(!workspace.origins.length)return "";
    return '<div class="initial-recon-origin-actions"><span>Exact web origins</span>'+workspace.origins.map(origin=>'<button class="secondary-btn small" data-open-web-origin="'+escapeAttr(origin.id)+'" type="button">'+escapeHtml(origin.url)+" · Open WEB Recon</button>").join("")+"</div>";
  }
  function classifiedWorkspaces(runtime){
    if(runtime.classifiedWorkspaces)return runtime.classifiedWorkspaces;
    runtime.classifiedWorkspaces=runtime.model.workspaces.map(workspace=>{
      const classification=serviceApi.classifyServiceEndpoint?.(workspace,workspace.artifacts,{manualMappings:runtime.state.serviceMappings,customFamilies:runtime.state.customServiceFamilies})||workspace.classification;
      const row={...workspace,classification};return {...row,summary:serviceSummary(row,row.origins)};
    });
    runtime.serviceWorkspaceById=new Map(runtime.classifiedWorkspaces.map(workspace=>[workspace.id,workspace]));
    runtime.serviceWorkspaceByKey=new Map(runtime.classifiedWorkspaces.map(workspace=>[workspace.key,workspace]));
    return runtime.classifiedWorkspaces;
  }
  function invalidateClassifiedWorkspaces(runtime){
    runtime.classifiedWorkspaces=null;runtime.serviceWorkspaceById=null;runtime.serviceWorkspaceByKey=null;
  }
  function serviceFamilyRows(runtime){
    const workspaces=classifiedWorkspaces(runtime),byFamily=new Map();
    for(const workspace of workspaces){const family=workspace.classification.family;if(!byFamily.has(family))byFamily.set(family,{name:family,reviewRank:workspace.classification.reviewRank,endpoints:[]});byFamily.get(family).endpoints.push(workspace);}
    const rows=[...byFamily.values()];for(const family of rows)family.endpoints.sort((left,right)=>left.port-right.port||left.protocol.localeCompare(right.protocol));
    const sort=runtime.state.serviceSort;
    rows.sort((left,right)=>sort==="port"?left.endpoints[0].port-right.endpoints[0].port||left.name.localeCompare(right.name):sort==="name"?left.name.localeCompare(right.name):(Number(left.reviewRank)-Number(right.reviewRank)||left.name.localeCompare(right.name)));
    return rows;
  }
  function serviceMappingOptions(families,selected=""){
    const automatic='<option value="">Automatic classification</option>',rows=unique(families).sort((left,right)=>(serviceApi.familyReviewRank?.(left)||0)-(serviceApi.familyReviewRank?.(right)||0)||left.localeCompare(right));
    return automatic+rows.map(family=>'<option value="'+escapeAttr(family)+'"'+(family===selected?' selected':'')+'>'+escapeHtml(family)+"</option>").join("");
  }
  function serviceMappingHtml(runtime,workspaces,families){
    if(!runtime.state.serviceMappingOpen)return "";
    const rows=workspaces.map(workspace=>{
      const mapping=object(runtime.state.serviceMappings[workspace.key]),manual=text(typeof runtime.state.serviceMappings[workspace.key]==="string"?runtime.state.serviceMappings[workspace.key]:mapping.family),classification=serviceApi.classifyServiceEndpoint?.(workspace,workspace.artifacts,{manualMappings:runtime.state.serviceMappings,customFamilies:runtime.state.customServiceFamilies})||workspace.classification;
      return '<tr data-service-mapping-row="'+escapeAttr(workspace.key)+'"><td><code>'+workspace.port+"/"+workspace.protocol.toUpperCase()+"</code></td><td>"+escapeHtml(classification.detectedAs||"unknown")+'</td><td><label class="sr-only" for="service-map-'+safeId(workspace.key)+'">Assigned family for '+workspace.port+"/"+workspace.protocol+'</label><select id="service-map-'+safeId(workspace.key)+'" data-service-mapping="'+escapeAttr(workspace.key)+'">'+serviceMappingOptions(families,manual)+"</select></td><td>"+escapeHtml(classification.source)+(manual?'<button class="secondary-btn small" data-service-reset="'+escapeAttr(workspace.key)+'" type="button">Reset to Automatic</button>':"")+"</td></tr>";
    }).join("");
    return '<section class="service-mapping-panel" aria-label="Manage Service Mapping"><header><div><h4>Manage Service Mapping</h4><p>Manual assignments organize the endpoint without changing detected Nmap evidence.</p></div></header><div class="service-mapping-table-wrap"><table><thead><tr><th>Port</th><th>Detected as</th><th>Assigned to</th><th>Source</th></tr></thead><tbody>'+rows+'</tbody></table></div><div class="service-family-create"><label for="newServiceFamily">Create new service group</label><input id="newServiceFamily" data-new-service-family maxlength="80" placeholder="CUSTOM ADMIN SERVICE" type="text"/><button class="secondary-btn small" data-create-service-family type="button">Create group</button></div></section>';
  }
  function serviceReferencesHtml(workspace){
    const rows=values(workspace.references);if(!rows.length)return "";
    return '<section class="service-evidence-references"><span>Canonical linked evidence</span><div>'+rows.map(artifact=>'<button class="secondary-btn small" data-open-inventory-artifact="'+escapeAttr(artifact.id)+'" type="button">'+escapeHtml(artifact.label||artifact.filename)+'</button>').join("")+"</div></section>";
  }
  function serviceDetailHtml(runtime,workspace){
    if(!workspace)return emptyState("Select an endpoint","Choose one exact endpoint to review its canonical identity and evidence.");
    const summarySpec=derivedSpec("service."+workspace.id+".summary","Service Summary","Canonical identity and classification provenance for "+workspace.port+"/"+workspace.protocol+".",workspace.summary,{autoTriage:true,commandNote:true,commandEntity:workspace.port+"/"+workspace.protocol});
    const notes=derivedSpec("service."+workspace.id+".notes","Operator Notes / Low-Hanging Leads","Manual interpretation, version research, validation, and parallel work for this endpoint.","",{extraAction:"lead",commandNote:true,commandEntity:workspace.port+"/"+workspace.protocol});
    return '<section class="service-workspace-section" id="initial-recon-service-'+safeId(workspace.id)+'" data-service-endpoint="'+escapeAttr(workspace.id)+'"><div class="service-workspace-heading"><div><span class="service-workspace-kicker">'+escapeHtml(workspace.classification.family)+' · Classification: '+escapeHtml(workspace.classification.source)+'</span><h3>'+workspace.port+"/"+workspace.protocol.toUpperCase()+" · "+escapeHtml(serviceName(workspace))+"</h3><p>"+escapeHtml([workspace.product,workspace.version].filter(Boolean).join(" ")||"Product/version unresolved")+'</p><small title="'+escapeAttr(workspace.classification.reason)+'">Why: '+escapeHtml(workspace.classification.reason)+"</small></div></div>"+originsHtml(workspace)+serviceReferencesHtml(workspace)+'<div class="sys-paste-stack">'+cardHtml(runtime,summarySpec)+cardHtml(runtime,notes)+"</div>"+artifactStack(runtime,workspace.artifacts,{commandNote:true,commandEntity:workspace.port+"/"+workspace.protocol,emptyTitle:"No service-specific artifact retained",emptyDetail:"The endpoint remains authoritative from retained port-scan evidence."})+"</section>";
  }
  function servicesHtml(runtime){
    const workspaces=classifiedWorkspaces(runtime),families=serviceFamilyRows(runtime);
    if(!workspaces.length)return emptyState("No authoritative service workspaces","UDP open|filtered/no-response candidates stay in Port Scans. A workspace appears for an open TCP endpoint or strongly evidenced open UDP service.");
    if(!families.some(row=>row.name===runtime.state.selectedServiceFamily))runtime.state.selectedServiceFamily=families[0].name;
    const selectedFamily=families.find(row=>row.name===runtime.state.selectedServiceFamily)||families[0];
    if(!selectedFamily.endpoints.some(row=>row.id===runtime.state.selectedServiceEndpoint))runtime.state.selectedServiceEndpoint=selectedFamily.endpoints[0].id;
    const allFamilies=unique([...families.map(row=>row.name),...runtime.state.customServiceFamilies,serviceApi.OTHER_SERVICE_FAMILY||"Other / Unclassified"]);
    const summary='<div class="service-workspace-intro"><div><strong>'+workspaces.length+' open endpoint'+(workspaces.length===1?'':'s')+'</strong><span>'+families.length+' service famil'+(families.length===1?'y':'ies')+' · canonical host attack surface</span></div><label>Sort<select data-service-sort><option value="review-priority"'+(runtime.state.serviceSort==='review-priority'?' selected':'')+'>Review Priority</option><option value="port"'+(runtime.state.serviceSort==='port'?' selected':'')+'>Port Number</option><option value="name"'+(runtime.state.serviceSort==='name'?' selected':'')+'>Service Name</option></select></label><button class="secondary-btn small" data-manage-service-mapping aria-expanded="'+String(runtime.state.serviceMappingOpen)+'" type="button">Manage Service Mapping</button></div>';
    const familyNav='<div class="service-selector-row service-family-selector"><span class="service-browser-label">Service families</span><nav class="service-family-nav section-tabs" aria-label="Service families">'+families.map(family=>'<button type="button" data-service-family="'+escapeAttr(family.name)+'" class="section-tab '+(family.name===selectedFamily.name?'active':'')+'" aria-pressed="'+String(family.name===selectedFamily.name)+'"><span>'+escapeHtml(family.name)+'</span><strong class="section-tab-count">'+family.endpoints.length+'</strong></button>').join("")+"</nav></div>";
    const endpointNav='<div class="service-selector-row service-endpoint-selector"><span class="service-browser-label">'+escapeHtml(selectedFamily.name)+' endpoints</span><nav class="service-endpoint-nav feature-filter-pills" aria-label="'+escapeAttr(selectedFamily.name)+' endpoints">'+selectedFamily.endpoints.map(workspace=>'<button type="button" data-service-endpoint-select="'+escapeAttr(workspace.id)+'" class="feature-filter-pill '+(workspace.id===runtime.state.selectedServiceEndpoint?'active':'')+'" aria-pressed="'+String(workspace.id===runtime.state.selectedServiceEndpoint)+'"><strong>'+workspace.port+'/'+workspace.protocol.toUpperCase()+'</strong><span>'+escapeHtml(workspace.classification.detectedAs||serviceName(workspace))+'</span></button>').join("")+"</nav></div>";
    const selectedWorkspace=runtime.serviceWorkspaceById?.get(runtime.state.selectedServiceEndpoint)||selectedFamily.endpoints[0];
    const details=serviceDetailHtml(runtime,selectedWorkspace);
    return summary+serviceMappingHtml(runtime,workspaces,allFamilies)+'<div class="service-browser"><div class="service-selector-stack">'+familyNav+endpointNav+'</div><div class="service-workbench">'+details+"</div></div>";
  }
  function renderServiceEndpointSelection(runtime,id){
    classifiedWorkspaces(runtime);
    const workspace=runtime.serviceWorkspaceById?.get(id);if(!workspace)return false;
    runtime.state.selectedServiceEndpoint=id;runtime.state.selectedServiceFamily=workspace.classification.family;
    runtime.root.querySelectorAll("[data-service-endpoint-select]").forEach(button=>{
      const active=button.dataset.serviceEndpointSelect===id;
      button.classList.toggle("active",active);button.setAttribute("aria-pressed",String(active));
    });
    const workbench=runtime.root.querySelector(".service-workbench");
    if(workbench)workbench.innerHTML=serviceDetailHtml(runtime,workspace);
    touch(runtime,false);measureCoverage(runtime);
    requestAnimationFrame(()=>runtime.root.querySelector('[data-service-endpoint="'+CSS.escape(id)+'"]')?.focus?.({preventScroll:true}));
    return true;
  }
  function commandsHtml(runtime){
    const order={"commands":1,"manual-commands":2,"errors":3,"patterns":4};
    const rows=[...runtime.model.sections["commands-signals"]].sort((left,right)=>(order[left.category]||99)-(order[right.category]||99)||left.path.localeCompare(right.path));
    return artifactStack(runtime,rows,{emptyTitle:"No command or signal artifacts",emptyDetail:"Commands, manual commands, errors, and patterns appear here in canonical order."});
  }
  function reportHtml(runtime){
    return artifactStack(runtime,runtime.model.sections["report-evidence"],{emptyTitle:"No report or evidence artifacts",emptyDetail:"Nested report output and screenshot metadata will appear here with escaped previews."});
  }
  function lootHtml(runtime){
    return artifactStack(runtime,runtime.model.sections["loot-exploit"],{sensitive:true,emptyTitle:"No loot or exploit artifacts",emptyDetail:"Applicable files are listed as safe metadata without persistent inline raw content."});
  }
  function homeLabel(artifact){
    if(artifact.section==="services"){
      const endpoint=artifact.endpointKey||artifact.endpointId;
      return "Services · "+(endpoint||"exact endpoint");
    }
    return VIEW_LABELS[artifact.section]||"Artifact Inventory";
  }
  function inventoryHtml(runtime){
    const rows=runtime.model.artifacts;
    if(!rows.length)return emptyState("No AutoRecon artifacts","Live Import and manual folder import share this one measured inventory.");
    const pages=Math.max(1,Math.ceil(rows.length/INVENTORY_PAGE_SIZE));
    runtime.state.inventoryPage=Math.min(runtime.state.inventoryPage,pages-1);
    const start=runtime.state.inventoryPage*INVENTORY_PAGE_SIZE,end=Math.min(rows.length,start+INVENTORY_PAGE_SIZE),visibleRows=rows.slice(start,end);
    const table='<div class="artifact-inventory-wrap"><table class="artifact-inventory"><thead><tr><th>Artifact</th><th>Canonical home</th><th>Tool / type</th><th>Size</th><th>Status</th><th></th></tr></thead><tbody>'+visibleRows.map(artifact=>'<tr data-inventory-artifact="'+escapeAttr(artifact.id)+'"><td><code>'+escapeHtml(artifact.path||artifact.filename)+"</code></td><td>"+escapeHtml(homeLabel(artifact))+"</td><td>"+escapeHtml(artifact.tool+" · "+artifact.parser)+"</td><td>"+escapeHtml(formatBytes(artifact.size))+"</td><td>"+statePill(artifact.artifactLifecycle)+'</td><td><button class="secondary-btn small" data-open-inventory-artifact="'+escapeAttr(artifact.id)+'" type="button">Open</button></td></tr>').join("")+"</tbody></table></div>";
    const custom=visibleRows.filter(artifact=>artifact.section==="artifact-inventory");
    const other=custom.length?'<section class="initial-recon-other-section"><h3>Other / Custom AutoRecon Outputs</h3><p>Unknown plugin output has a conservative editable working copy and is never discarded.</p>'+artifactStack(runtime,custom)+"</section>":"";
    const pager='<nav class="artifact-inventory-pager" aria-label="Artifact Inventory pages"><span>Showing '+(start+1)+'–'+end+' of '+rows.length+'</span><div><button class="secondary-btn small" data-inventory-page="'+Math.max(0,runtime.state.inventoryPage-1)+'" type="button"'+(runtime.state.inventoryPage===0?' disabled':'')+'>Previous</button><span>Page '+(runtime.state.inventoryPage+1)+' of '+pages+'</span><button class="secondary-btn small" data-inventory-page="'+Math.min(pages-1,runtime.state.inventoryPage+1)+'" type="button"'+(runtime.state.inventoryPage===pages-1?' disabled':'')+'>Next</button></div></nav>';
    return '<div class="coverage-summary" id="artifactCoverageSummary"><strong>Measuring canonical artifact coverage…</strong><span>Every artifact remains represented in the model; this page bounds the live DOM.</span></div>'+pager+table+other;
  }
  function panelHtml(key,body){
    return '<section aria-labelledby="initial-recon-tab-'+key+'" class="initial-recon-tabpanel" data-initial-recon-panel="'+key+'" id="initial-recon-panel-'+key+'" role="tabpanel">'+body+"</section>";
  }
  function panelBodyHtml(runtime,key){
    if(key==="port-scans")return portScansHtml(runtime);
    if(key==="services")return servicesHtml(runtime);
    if(key==="commands-signals")return commandsHtml(runtime);
    if(key==="report-evidence")return reportHtml(runtime);
    if(key==="loot-exploit")return lootHtml(runtime);
    if(key==="artifact-inventory")return inventoryHtml(runtime);
    return overviewHtml(runtime);
  }
  function selectedPanelHtml(runtime){
    if(Array.isArray(runtime.adapters.collection)){
      const selected=new Set(runtime.adapters.collection);
      return artifactStack(runtime,runtime.model.artifacts.filter(row=>selected.has(row.id)));
    }
    const selected=VIEW_KEYS.includes(runtime.state.selectedTab)?runtime.state.selectedTab:"overview";
    return panelHtml(selected,panelBodyHtml(runtime,selected));
  }

  function coverageReport(artifacts,renderedIds=[]){
    const expected=values(artifacts).map(row=>row.id),counts=new Map();
    values(renderedIds).forEach(id=>counts.set(id,(counts.get(id)||0)+1));
    const missing=expected.filter(id=>!counts.has(id)),duplicates=[...counts].filter(([,count])=>count>1).map(([id])=>id),unexpected=[...counts.keys()].filter(id=>!expected.includes(id));
    return {total:expected.length,rendered:expected.length-missing.length,missing,duplicates,unexpected,complete:missing.length===0&&duplicates.length===0&&unexpected.length===0};
  }
  function measureCoverage(runtime){
    const ids=VIEW_KEYS.flatMap(key=>values(runtime.model?.sections?.[key]).map(artifact=>artifact.id));
    const coverage=coverageReport(runtime.model.artifacts,ids),summary=runtime.root.querySelector("#artifactCoverageSummary");
    if(summary){
      if(coverage.complete)summary.innerHTML='<strong class="coverage-ok">'+coverage.rendered+"/"+coverage.total+' artifacts rendered exactly once by the canonical section model</strong><span>Inventory rows are navigation only; the selected panel renders its bounded projection without duplicating raw evidence.</span>';
      else summary.innerHTML='<strong class="coverage-missing">Coverage problem: '+coverage.rendered+"/"+coverage.total+' artifacts represented</strong><span>Missing '+coverage.missing.length+" · duplicate "+coverage.duplicates.length+" · unexpected "+coverage.unexpected.length+".</span>";
    }
    const metric=runtime.root.querySelector("#initialReconCoverageCount");
    if(metric){metric.textContent=coverage.rendered+" / "+coverage.total;metric.classList.toggle("stat-problem",!coverage.complete);}
    runtime.coverage=coverage;
    return coverage;
  }
  function setMetric(root,id,value){const node=root.querySelector("#"+id);if(node)node.textContent=string(value);}
  function paintMetrics(runtime){
    const metrics=runtime.model?.metrics||{};
    const families=runtime.model?serviceFamilyRows(runtime):[];
    setMetric(runtime.root,"initialReconHostStat",runtime.model?.host?.address||"No host");
    setMetric(runtime.root,"initialReconArtifactCount",metrics.artifacts||0);
    setMetric(runtime.root,"initialReconCoverageCount","0 / "+(metrics.artifacts||0));
    setMetric(runtime.root,"initialReconServiceCount",runtime.model?classifiedWorkspaces(runtime).length:(metrics.services||0));
    setMetric(runtime.root,"initialReconWorkspaceCount",runtime.model?families.length:(metrics.serviceWorkspaces||0));
    setMetric(runtime.root,"initialReconUnclassifiedCount",metrics.unclassified||0);
  }
  function touch(runtime,immediate=false){
    runtime.state.updatedAt=now();
    if(typeof runtime.adapters.onStateChange==="function")runtime.adapters.onStateChange(runtime.state,{immediate});
  }
  function activate(root,key,options={}){
    const runtime=runtimeByRoot.get(root);
    if(!runtime)return "overview";
    const selected=VIEW_KEYS.includes(key)?key:"overview";
    const changed=runtime.state.selectedTab!==selected;
    runtime.state.selectedTab=selected;
    root.dataset.initialReconView=selected;
    root.querySelectorAll("[data-initial-recon-view]").forEach(button=>{
      const active=button.dataset.initialReconView===selected;
      button.classList.toggle("active",active);button.setAttribute("aria-selected",String(active));button.tabIndex=active?0:-1;
    });
    const currentPanel=root.querySelector("[data-initial-recon-panel]");
    if(options.render!==false&&(changed||currentPanel?.dataset.initialReconPanel!==selected))rerender(runtime);
    if(options.persist!==false)touch(runtime,false);
    if(typeof runtime.adapters.onTabChange==="function")runtime.adapters.onTabChange(selected);
    return selected;
  }
  function rerender(runtime){
    const content=runtime.root.querySelector("#initialReconContent");
    if(!content)return;
    content.innerHTML=selectedPanelHtml(runtime);
    runtime.root.dataset.initialReconView=runtime.state.selectedTab;
    runtime.root.querySelectorAll("[data-initial-recon-view]").forEach(button=>{
      const active=button.dataset.initialReconView===runtime.state.selectedTab;
      button.classList.toggle("active",active);button.setAttribute("aria-selected",String(active));button.tabIndex=active?0:-1;
    });
    measureCoverage(runtime);
  }
  function findSpec(runtime,key){
    if(key==="overview.attack-surface")return derivedSpec(key,"Attack Surface Summary","Derived from retained endpoint and AutoRecon evidence.",runtime.model.overview.attackSurface,{autoTriage:true});
    if(key==="overview.low-hanging")return derivedSpec(key,"Low-Hanging Leads / Parallel Work","Operator-owned evidence and parallel work.",runtime.model.overview.lowHanging,{autoTriage:true,extraAction:"lead"});
    if(key==="overview.takeaways")return derivedSpec(key,"Initial Recon Takeaways / Next Actions","Operator priorities.",runtime.model.overview.takeaways,{extraAction:"notes"});
    for(const workspace of classifiedWorkspaces(runtime)){
      if(key==="service."+workspace.id+".summary")return derivedSpec(key,"Service Summary","Clean evidence-derived endpoint identity.",workspace.summary,{autoTriage:true,commandNote:true,commandEntity:workspace.port+"/"+workspace.protocol});
      if(key==="service."+workspace.id+".notes")return derivedSpec(key,"Operator Notes / Low-Hanging Leads","Manual service interpretation.","",{extraAction:"lead",commandNote:true,commandEntity:workspace.port+"/"+workspace.protocol});
    }
    const artifact=runtime.model.artifacts.find(row=>artifactCardKey(row)===key);
    return artifact?artifactSpec(artifact,{sensitive:artifact.section==="loot-exploit"}):null;
  }
  async function canonicalRaw(runtime,artifact){
    if(runtime.rawCache.has(artifact.id))return runtime.rawCache.get(artifact.id);
    if(artifact.fallback){runtime.rawCache.set(artifact.id,artifact.canonicalRaw);runtime.rawSourceMeta.set(artifact.id,{kind:"canonical",recordVersion:artifactSourceVersion(artifact)});return artifact.canonicalRaw;}
    const preview=string(artifact.preview),policy=lower(artifact.previewPolicy),completePreview=artifact.size===0||Boolean(preview.length&&!artifact.previewTruncated&&!artifact.metadataOnly&&!artifact.binary&&!policy.includes("suppressed"));
    if(completePreview){runtime.rawCache.set(artifact.id,preview);runtime.rawSourceMeta.set(artifact.id,{kind:"canonical",recordVersion:artifactSourceVersion(artifact)});return preview;}
    if(typeof runtime.adapters.readRaw!=="function")throw new Error("The complete retained source is unavailable.");
    const raw=await runtime.adapters.readRaw(artifact.recordId,artifact);
    if(typeof raw!=="string")throw new Error("The retained source did not return text.");
    if(artifact.size>0&&!raw.length)throw new Error("The retained source returned no text for a nonempty artifact.");
    runtime.rawCache.set(artifact.id,raw);
    runtime.rawSourceMeta.set(artifact.id,{kind:"canonical",recordVersion:artifactSourceVersion(artifact)});
    return raw;
  }
  async function provisionalRaw(runtime,artifact){
    if(runtime.rawCache.has(artifact.id))return runtime.rawCache.get(artifact.id);
    if(typeof runtime.adapters.readCurrentRaw!=="function")throw new Error("The current watched source is unavailable in this browser session.");
    const result=await runtime.adapters.readCurrentRaw(artifact.recordId,artifact),raw=typeof result==="string"?result:result?.text;
    if(typeof raw!=="string")throw new Error("The current watched source did not return text.");
    if(artifact.size>0&&!raw.length)throw new Error("The current watched source returned no text for a nonempty artifact.");
    runtime.rawCache.set(artifact.id,raw);
    runtime.rawSourceMeta.set(artifact.id,{kind:"provisional",recordVersion:artifactSourceVersion(artifact),size:number(result?.size),lastModified:number(result?.lastModified),relativePath:text(result?.relativePath)});
    return raw;
  }
  function artifactRaw(runtime,artifact){return artifact?.provisional===true?provisionalRaw(runtime,artifact):canonicalRaw(runtime,artifact);}
  function repaintRuntime(runtime){const active=runtimeByRoot.get(runtime.root);if(active)rerender(active);}
  async function loadCompleteSource(runtime,spec){
    if(!spec?.imported||!spec.artifact)throw new Error("The retained artifact is unavailable.");
    const id=spec.artifact.id;
    if(runtime.rawCache.has(id))return runtime.rawCache.get(id);
    if(runtime.rawLoads.has(id))return runtime.rawLoads.get(id);
    const kind=sourceKind(spec.artifact);runtime.rawStatus.set(id,{state:"loading",kind});repaintRuntime(runtime);
    const pending=(async()=>{
      try{
        const raw=await artifactRaw(runtime,spec.artifact);
        runtime.rawStatus.delete(id);
        return raw;
      }catch(error){
        runtime.rawStatus.set(id,{state:"error",kind,message:error?.message||(kind==="provisional"?"The current watched source could not be read.":"The exact retained text could not be retrieved.")});
        throw error;
      }finally{
        runtime.rawLoads.delete(id);repaintRuntime(runtime);
      }
    })();
    runtime.rawLoads.set(id,pending);
    return pending;
  }
  async function writeClipboard(value){
    if(globalThis.navigator?.clipboard?.writeText){await globalThis.navigator.clipboard.writeText(string(value));return true;}
    if(typeof document==="undefined")return false;
    const field=document.createElement("textarea");field.value=string(value);field.style.cssText="position:fixed;top:-1000px;left:-1000px;opacity:0";document.body.appendChild(field);field.select();
    let copied=false;try{copied=document.execCommand("copy");}finally{field.remove();}
    if(!copied)throw new Error("Clipboard access was blocked.");
    return true;
  }
  function notify(runtime,message,tone="success"){
    if(typeof runtime.adapters.notify==="function")runtime.adapters.notify(message,tone);
  }
  function notifyError(runtime,error){
    if(typeof runtime.adapters.onError==="function")runtime.adapters.onError(error);
    else notify(runtime,error?.message||"Initial Recon action failed.","error");
  }
  function downloadText(value,filename){
    const blob=new Blob([string(value)],{type:"text/plain;charset=utf-8"}),url=URL.createObjectURL(blob),anchor=document.createElement("a");
    try{anchor.href=url;anchor.download=filename||"recon-working-copy.txt";anchor.hidden=true;document.body.appendChild(anchor);anchor.click();}
    finally{anchor.remove();URL.revokeObjectURL(url);}
  }
  async function setCardMode(runtime,key){
    const spec=findSpec(runtime,key);if(!spec)return;
    const entry=cardEntry(runtime,key),next=cardMode(runtime,spec)==="edit"?"preview":"edit";
    if(next==="edit"&&spec.imported&&!spec.artifact.binary&&!spec.artifact.image&&!spec.sensitive){
      if(completeSourceRequired(runtime,spec))await loadCompleteSource(runtime,spec);else await artifactRaw(runtime,spec.artifact);
    }
    entry.mode=next;touch(runtime,false);rerender(runtime);
    requestAnimationFrame(()=>runtime.root.querySelector('[data-card-key="'+CSS.escape(key)+'"] '+(next==="edit"?"textarea":"button[data-card-mode]"))?.focus());
  }
  function updateCardValue(runtime,key,value){
    const spec=findSpec(runtime,key);if(!spec)return;
    const entry=cardEntry(runtime,key),baseline=baselineValue(runtime,spec),next=string(value);
    if(next===baseline){
      delete entry.workingCopy;delete entry.edited;delete entry.baselineRevision;
      delete runtime.state.followUps[key];
    }else{
      entry.workingCopy=next;entry.edited=true;
      if(spec.imported&&!own(entry,"baselineRevision"))entry.baselineRevision=spec.artifact.revision;
    }
    touch(runtime,false);
  }
  async function copyCard(runtime,key){
    const spec=findSpec(runtime,key);if(!spec)return;
    const value=spec.imported?await artifactRaw(runtime,spec.artifact):currentValue(runtime,spec);
    await writeClipboard(value);notify(runtime,spec.imported?"Untouched imported artifact copied.":"Raw working text copied.");
  }
  async function downloadCard(runtime,key){
    const spec=findSpec(runtime,key);if(!spec||!spec.imported)return;
    if((spec.artifact.binary||spec.artifact.image)&&typeof runtime.adapters.downloadRaw==="function"){await runtime.adapters.downloadRaw(spec.artifact.recordId,spec.artifact);return;}
    let value=currentValue(runtime,spec);
    if(cardEntry(runtime,key).edited!==true)value=await artifactRaw(runtime,spec.artifact);
    downloadText(value,spec.artifact.filename+(cardEntry(runtime,key).edited===true?".working-copy.txt":".txt"));
  }
  function resetCard(runtime,key){
    const spec=findSpec(runtime,key);if(!spec?.imported)return;
    const entry=cardEntry(runtime,key);
    delete entry.workingCopy;delete entry.edited;delete entry.baselineRevision;delete entry.renderAll;
    entry.mode="preview";delete runtime.state.followUps[key];touch(runtime,true);rerender(runtime);
    notify(runtime,"Restored the current immutable imported baseline.");
  }
  function openArtifact(root,id){
    const runtime=runtimeByRoot.get(root);if(!runtime)return false;
    const artifact=runtime.model.artifacts.find(row=>row.id===id||row.recordId===id||row.artifactId===id);
    if(!artifact)return false;
    const spec=artifactSpec(artifact,{sensitive:artifact.section==="loot-exploit"}),entry=cardEntry(runtime,spec.key);entry.collapsed=false;
    if(artifact.section==="artifact-inventory"){
      const index=runtime.model.artifacts.findIndex(row=>row.id===artifact.id);
      runtime.state.inventoryPage=Math.max(0,Math.floor(index/INVENTORY_PAGE_SIZE));
    }
    activate(root,artifact.section,{persist:true,render:false});rerender(runtime);
    if(shouldLoadCompleteSource(runtime,spec))loadCompleteSource(runtime,spec).catch(error=>notifyError(runtime,error));
    requestAnimationFrame(()=>{
      const card=root.querySelector('[data-canonical-artifact-card="'+CSS.escape(artifact.id)+'"]');
      if(card){card.setAttribute("tabindex","-1");card.focus({preventScroll:true});card.scrollIntoView({behavior:"smooth",block:"center"});}
    });
    return true;
  }

  function bindRoot(root){
    if(root.dataset.initialReconBound==="1")return;
    root.dataset.initialReconBound="1";
    root.addEventListener("click",async event=>{
      const runtime=runtimeByRoot.get(root);if(!runtime)return;
      const button=event.target.closest("button");if(!button)return;
      try{
        if(button.matches("[data-initial-recon-view]")){activate(root,button.dataset.initialReconView);return;}
        if(button.matches("[data-card-mode]")){button.disabled=true;await setCardMode(runtime,button.dataset.cardMode);return;}
        if(button.matches("[data-card-copy]")){button.disabled=true;await copyCard(runtime,button.dataset.cardCopy);button.disabled=false;return;}
        if(button.matches("[data-card-download]")){button.disabled=true;await downloadCard(runtime,button.dataset.cardDownload);button.disabled=false;return;}
        if(button.matches("[data-card-reset]")){resetCard(runtime,button.dataset.cardReset);return;}
        if(button.matches("[data-card-collapse]")){const spec=findSpec(runtime,button.dataset.cardCollapse);if(!spec)return;const entry=cardEntry(runtime,spec.key),expanding=isCollapsed(runtime,spec);entry.collapsed=!expanding;touch(runtime,false);if(expanding&&shouldLoadCompleteSource(runtime,spec)){await loadCompleteSource(runtime,spec);return;}rerender(runtime);return;}
        if(button.matches("[data-card-inspect-sensitive]")){const key=button.dataset.cardInspectSensitive,spec=findSpec(runtime,key);if(!spec?.sensitive)return;if(runtime.revealedSensitive.has(key)){runtime.revealedSensitive.delete(key);cardEntry(runtime,key).mode="preview";}else{button.disabled=true;await artifactRaw(runtime,spec.artifact);runtime.revealedSensitive.add(key);}rerender(runtime);return;}
        if(button.matches("[data-card-render-all]")){cardEntry(runtime,button.dataset.cardRenderAll).renderAll=true;touch(runtime,false);rerender(runtime);return;}
        if(button.matches("[data-card-load-complete]")){const spec=findSpec(runtime,button.dataset.cardLoadComplete);if(!spec)return;button.disabled=true;await loadCompleteSource(runtime,spec);return;}
        if(button.matches("[data-inventory-page]")){runtime.state.inventoryPage=Math.max(0,number(button.dataset.inventoryPage));touch(runtime,false);rerender(runtime);return;}
        if(button.matches("[data-open-inventory-artifact]")){openArtifact(root,button.dataset.openInventoryArtifact);return;}
        if(button.matches("[data-open-web-origin]")){runtime.adapters.openOrigin?.(button.dataset.openWebOrigin);return;}
        if(button.matches("[data-service-family]")){runtime.state.selectedServiceFamily=button.dataset.serviceFamily;const family=serviceFamilyRows(runtime).find(row=>row.name===runtime.state.selectedServiceFamily);runtime.state.selectedServiceEndpoint=family?.endpoints?.[0]?.id||"";touch(runtime,false);rerender(runtime);return;}
        if(button.matches("[data-service-endpoint-select]")){renderServiceEndpointSelection(runtime,button.dataset.serviceEndpointSelect);return;}
        if(button.matches("[data-manage-service-mapping]")){runtime.state.serviceMappingOpen=!runtime.state.serviceMappingOpen;touch(runtime,false);rerender(runtime);return;}
        if(button.matches("[data-service-reset]")){const key=button.dataset.serviceReset,workspace=classifiedWorkspaces(runtime).find(row=>row.key===key);delete runtime.state.serviceMappings[key];if(workspace){const automatic=serviceApi.classifyServiceEndpoint?.(workspace,workspace.artifacts,{manualMappings:runtime.state.serviceMappings,customFamilies:runtime.state.customServiceFamilies});runtime.state.selectedServiceFamily=automatic?.family||"";runtime.state.selectedServiceEndpoint=workspace.id;}invalidateClassifiedWorkspaces(runtime);touch(runtime,true);rerender(runtime);notify(runtime,"Service mapping reset to automatic classification.");return;}
        if(button.matches("[data-create-service-family]")){const input=root.querySelector("[data-new-service-family]"),family=serviceApi.normalizedFamilyLabel?.(input?.value)||text(input?.value);if(!family){notify(runtime,"Enter a service group name.","warning");input?.focus();return;}if(!runtime.state.customServiceFamilies.some(value=>lower(value)===lower(family)))runtime.state.customServiceFamilies.push(family);invalidateClassifiedWorkspaces(runtime);touch(runtime,true);rerender(runtime);notify(runtime,`Service group “${family}” is available for assignment.`);return;}
        if(button.matches("[data-initial-recon-add-service]")){runtime.adapters.addService?.();return;}
        if(button.matches("[data-initial-recon-add-lead]")){runtime.adapters.addLead?.();return;}
        if(button.matches("[data-initial-recon-open-notes]")){runtime.adapters.openNotes?.();return;}
        if(button.matches("[data-copy-followup]")){const card=button.closest("[data-followup-source]"),notes=card?.querySelector("[data-followup-notes]")?.value||"";await writeClipboard(notes);notify(runtime,"Follow-up text copied.");return;}
        if(button.matches("[data-followup-mode]")){const card=button.closest("[data-followup-source]"),source=card?.dataset.followupSource,term=card?.dataset.followupTerm;if(!source||!term)return;if(!runtime.state.followUps[source]||typeof runtime.state.followUps[source]!=="object")runtime.state.followUps[source]={};const record=object(runtime.state.followUps[source][term]),current=record.mode==="edit"||record.mode==="preview"?record.mode:(string(record.notes).trim()?"preview":"edit");runtime.state.followUps[source][term]={...record,term,notes:string(record.notes),mode:current==="edit"?"preview":"edit",updatedAt:now()};touch(runtime,false);rerender(runtime);return;}
      }catch(error){button.disabled=false;notifyError(runtime,error);}
    });
    root.addEventListener("keydown",event=>{
      const button=event.target.closest("[data-initial-recon-view]");if(!button)return;
      const tabs=[...root.querySelectorAll("[data-initial-recon-view]")],index=tabs.indexOf(button),directions={ArrowRight:1,ArrowDown:1,ArrowLeft:-1,ArrowUp:-1};
      let next=null;
      if(own(directions,event.key))next=(index+directions[event.key]+tabs.length)%tabs.length;
      else if(event.key==="Home")next=0;
      else if(event.key==="End")next=tabs.length-1;
      if(next==null)return;
      event.preventDefault();activate(root,tabs[next].dataset.initialReconView);tabs[next].focus();
    });
    root.addEventListener("input",event=>{
      const runtime=runtimeByRoot.get(root);if(!runtime)return;
      if(event.target.matches("[data-card-editor]"))updateCardValue(runtime,event.target.dataset.cardEditor,event.target.value);
      if(event.target.matches("[data-followup-notes]")){
        const card=event.target.closest("[data-followup-source]"),source=card?.dataset.followupSource,term=card?.dataset.followupTerm;
        if(!source||!term)return;
        if(!runtime.state.followUps[source]||typeof runtime.state.followUps[source]!=="object")runtime.state.followUps[source]={};
        const existing=object(runtime.state.followUps[source][term]);runtime.state.followUps[source][term]={...existing,term,notes:event.target.value,mode:"edit",updatedAt:now()};touch(runtime,false);
      }
    });
    root.addEventListener("change",event=>{
      const runtime=runtimeByRoot.get(root);if(!runtime)return;
      if(event.target.matches("[data-artifact-review]")){
        const artifact=runtime.model.artifacts.find(row=>row.id===event.target.dataset.artifactReview);
        runtime.adapters.reviewArtifact?.(artifact?.recordId,event.target.value,artifact);
      }
      if(event.target.matches("[data-service-sort]")){runtime.state.serviceSort=event.target.value;touch(runtime,false);rerender(runtime);return;}
      if(event.target.matches("[data-service-mapping]")){
        const key=event.target.dataset.serviceMapping,family=serviceApi.normalizedFamilyLabel?.(event.target.value)||text(event.target.value),workspace=classifiedWorkspaces(runtime).find(row=>row.key===key);
        if(family)runtime.state.serviceMappings[key]={family,source:"manual",assignedAt:now()};else delete runtime.state.serviceMappings[key];
        if(workspace){const current=serviceApi.classifyServiceEndpoint?.(workspace,workspace.artifacts,{manualMappings:runtime.state.serviceMappings,customFamilies:runtime.state.customServiceFamilies});runtime.state.selectedServiceFamily=current?.family||"";runtime.state.selectedServiceEndpoint=workspace.id;}
        invalidateClassifiedWorkspaces(runtime);touch(runtime,true);rerender(runtime);notify(runtime,family?`Endpoint assigned to ${family}.`:"Endpoint returned to automatic classification.");return;
      }
      if(event.target.matches("[data-card-editor]"))touch(runtime,true);
    });
    root.querySelector("#saveInitialReconBtn")?.addEventListener("click",async()=>{
      const runtime=runtimeByRoot.get(root);if(!runtime)return;
      try{touch(runtime,true);await runtime.adapters.saveNow?.();notify(runtime,"Initial Recon saved to the current engagement.");}catch(error){notifyError(runtime,error);}
    });
  }

  function reconcileSessionRawCache(runtime){
    const artifacts=new Map(values(runtime.model?.artifacts).map(artifact=>[artifact.id,artifact]));
    for(const [id,metaValue] of runtime.rawSourceMeta){
      const artifact=artifacts.get(id),meta=object(metaValue),changed=!artifact||meta.kind!==sourceKind(artifact)||meta.recordVersion!==artifactSourceVersion(artifact);
      if(!changed)continue;
      runtime.rawCache.delete(id);runtime.rawSourceMeta.delete(id);runtime.rawStatus.delete(id);runtime.rawLoads.delete(id);
    }
  }

  function render(root,model,adapters={}){
    if(!root)return null;
    const content=root.querySelector("#initialReconContent");
    if(!content)return null;
    const previous=runtimeByRoot.get(root),state=ensureState(adapters.state||previous?.state||{});
    const runtime={root,model,adapters,state,rawCache:previous?.rawCache||new Map(),rawSourceMeta:previous?.rawSourceMeta||new Map(),rawStatus:previous?.rawStatus||new Map(),rawLoads:previous?.rawLoads||new Map(),revealedSensitive:previous?.revealedSensitive||new Set(),coverage:null};
    reconcileSessionRawCache(runtime);
    runtimeByRoot.set(root,runtime);bindRoot(root);
    if(!model){
      paintMetrics(runtime);
      content.innerHTML=panelHtml("overview",emptyState("Select an exact host","Initial Recon derives from the currently selected canonical host only."));
      activate(root,"overview",{persist:false});
      return {selectedTab:"overview",coverage:{total:0,rendered:0,complete:true}};
    }
    paintMetrics(runtime);rerender(runtime);
    return {selectedTab:state.selectedTab,coverage:runtime.coverage};
  }

  return Object.freeze({
    VIEW_KEYS,VIEW_LABELS,REVIEW_STATES,PREVIEW_LINE_BUDGET,LARGE_ARTIFACT_BYTES,INVENTORY_PAGE_SIZE,
    ensureState,artifactCategory,artifactRows,strongServiceEvidence,endpointRows,
    exactOriginRows,canonicalSection,serviceName,serviceSummary,project,coverageReport,render,activate,openArtifact
  });
});
