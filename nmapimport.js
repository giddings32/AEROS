/* Scan-evidence import for Guided Methodology.
 * Accepts individual scan files or known results-folder layouts, detects the
 * producing tool where the file structure makes that reliable, and routes one
 * import across every workflow objective supported by the evidence.
 */
(function(){
  "use strict";

  let pendingTaskId="";
  const SCAN_IMPORT_PROJECTION_SCHEMA_VERSION=4;
  const SCAN_IMPORT_SLOTS=["port","tcp","udp","vuln"];

  function api(){return window.AerosScanIntelligence||null;}
  function clean(value){return String(value??"").trim();}
  function importFilePath(file){return clean(file?.webkitRelativePath||file?.aerosPhysicalSourcePath||file?.aerosRelativePath||file?.name);}
  function canonicalImportFilePath(file){return clean(file?.aerosCanonicalLogicalPath)||importFilePath(file);}
  function liveImportProvisional(options={}){return options.liveImportProvisional===true||options.liveImport===true&&options.liveImportCompletionEstablished===false;}
  function importSourceRevision(options={}){return liveImportProvisional(options)?0:(Number(options.sourceRevision)||1);}
  function activeTargetIdentity(host){
    const parser=api();
    return parser?.activeTargetIdentity?parser.activeTargetIdentity(host||{}):{primary:clean(host?.ip||host?.hostname),aliases:[host?.ip,host?.hostname].map(clean).filter(Boolean),mappings:[host?.ip,host?.hostname].map(clean).filter(Boolean)};
  }
  function objectiveHint(taskId){return taskId==="tcp-port-discovery"?"port":["service-version-enumeration","tcp-service-discovery"].includes(taskId)?"tcp":["udp-port-discovery","udp-service-discovery"].includes(taskId)?"udp":taskId==="targeted-safe-vulnerability-enumeration"?"vuln":"";}
  function applicationState(){return typeof window.getAerosState==="function"?window.getAerosState():null;}
  function resolveImportHost(options={}){
    if(options.host&&typeof options.host==="object")return options.host;
    const hostId=clean(options.hostId);
    if(hostId){
      const matches=Object.entries(applicationState()?.hosts||{}).filter(([key,host])=>host&&(clean(key)===hostId||clean(host.id||key)===hostId));
      const unique=[];matches.forEach(([,host])=>{if(!unique.includes(host))unique.push(host);});
      if(unique.length!==1)throw new Error(unique.length?"The selected import host is ambiguous.":"The selected import host is missing or stale.");
      return unique[0];
    }
    return typeof activeHost==="function"?activeHost():null;
  }
  function importEngagementId(options={}){
    const value=applicationState()||{};
    return clean(options.engagementId||value.projectId||value.projectName);
  }
  function observedTargetAddress(host,parsed={},options={}){
    const known=(window.AerosHostProfile?.networkAddresses?.(host)||[]).map(row=>clean(row.address));
    const candidates=[options.targetAddress,parsed.target,...(parsed.targetCandidates||[])].map(clean).filter(Boolean);
    return candidates.find(value=>known.some(address=>address.toLowerCase()===value.toLowerCase()))||clean(options.targetAddress||host?.ip||known[0]);
  }
  function ownParsedRecords(parsed,host,filename="",options={}){
    const engagementId=importEngagementId(options),hostId=clean(host?.id),targetAddress=observedTargetAddress(host,parsed,options),at=new Date().toISOString();
    const services=(parsed.services||[]).map(row=>{
      const owned={
        ...row,engagementId,hostId,targetAddress,
        observedTargetAddress:clean(row.observedTargetAddress||row.targetAddress||parsed.target||targetAddress),
        parserType:clean(options.parserType||parsed.tool||parsed.source||"nmap"),
        sourceOwner:"scan-import",
        sourceArtifactId:clean(options.sourceArtifactId||filename),
        sourceRevision:importSourceRevision(options),
        artifactLifecycle:liveImportProvisional(options)?"provisional":"canonical",
        provisional:liveImportProvisional(options),
        objective:clean(options.taskId),
        createdAt:clean(row.createdAt)||at,updatedAt:at
      };
      const endpointId=window.AerosHostProfile?.endpointIdentity?.(owned,{host,engagementId})||clean(row.id||row.endpointId);
      return {...owned,id:endpointId,endpointId};
    });
    const endpoints=new Map(services.map(row=>[`${row.protocol||"tcp"}:${Number(row.port)||0}`,row]));
    const vulnerabilityLeads=(parsed.vulnerabilityLeads||[]).map(row=>{
      const endpoint=endpoints.get(`${row.protocol||"tcp"}:${Number(row.port)||0}`);
      return {
        ...row,engagementId,hostId,
        targetAddress:endpoint?.targetAddress||targetAddress,
        observedTargetAddress:endpoint?.observedTargetAddress||targetAddress,
        endpointId:endpoint?.id||clean(row.endpointId),
        parserType:clean(options.parserType||parsed.tool||parsed.source||"nmap"),
        sourceOwner:"scan-import",
        sourceArtifactId:clean(options.sourceArtifactId||filename),
        sourceRevision:importSourceRevision(options),
        artifactLifecycle:liveImportProvisional(options)?"provisional":"canonical",
        provisional:liveImportProvisional(options),
        objective:clean(options.taskId),
        createdAt:clean(row.createdAt)||at,updatedAt:at
      };
    });
    return {...parsed,services,vulnerabilityLeads,engagementId,hostId,targetAddress};
  }
  function uniqueLabels(...values){
    const parser=api();
    return parser?.uniqueLabels?parser.uniqueLabels(...values):[...new Set(values.flatMap(value=>clean(value).split(/\s*[·|]\s*/)).map(clean).filter(Boolean))];
  }
  function appendUnique(existing,incoming){
    const current=clean(existing),next=clean(incoming);
    if(!next)return current;
    if(!current)return next;
    const seen=new Set(current.split(/\r?\n/).map(line=>line.trim()).filter(Boolean));
    const add=next.split(/\r?\n/).filter(line=>!seen.has(line.trim()));
    return add.length?`${current}\n${add.join("\n")}`:current;
  }
  function cloneImportValue(value,fallback){
    try{return JSON.parse(JSON.stringify(value??fallback));}
    catch(_error){return fallback;}
  }
  function ensureEvidence(host){
    if(typeof window.ensureScanEvidenceState==="function")window.ensureScanEvidenceState(host);
    else{
      if(!host.scans)host.scans={port:"",tcp:"",udp:"",vuln:""};
      if(!host.scanEvidence)host.scanEvidence={};
      ["port","tcp","udp"].forEach(key=>{host.scanEvidence[key]={command:"",customCommand:false,trustObjectiveHint:true,source:"",confirmed:false,coverage:"unknown",reason:"",ports:[],updatedAt:"",manualConfirmed:false,importedConfirmed:false,importedReason:"",...(host.scanEvidence[key]||{})};});
      if(!Array.isArray(host.serviceInventory))host.serviceInventory=[];
      host.vulnerabilityEvidence={confirmed:false,source:"",command:"",ports:[],reason:"",updatedAt:"",importedConfirmed:false,importedReason:"",...(host.vulnerabilityEvidence||{})};
      if(!Array.isArray(host.vulnerabilityLeads))host.vulnerabilityLeads=[];
      if(!Array.isArray(host.scanArtifacts))host.scanArtifacts=[];
      if(!Array.isArray(host.endpointEvidence))host.endpointEvidence=[];
    }
  }
  function ensureScanImportProjection(host){
    ensureEvidence(host);
    const existing=host.scanImportProjection;
    if(existing&&Number(existing.schemaVersion)===SCAN_IMPORT_PROJECTION_SCHEMA_VERSION&&existing.baseline&&Array.isArray(existing.sources)){
      if(existing.sources.some(source=>Math.max(Number(source?.projectionSchemaVersion)||0,Number(source?.originProjectionSchemaVersion)||0)<SCAN_IMPORT_PROJECTION_SCHEMA_VERSION))rebuildScanImportProjection(host,existing);
      return existing;
    }
    if(existing&&existing.baseline&&Array.isArray(existing.sources)){
      const previousVersion=Math.max(1,Number(existing.schemaVersion)||1);
      existing.schemaVersion=SCAN_IMPORT_PROJECTION_SCHEMA_VERSION;
      if(previousVersion<2)existing.baseline.webTargets=cloneImportValue(host.recon?.webTargets,[]);
      existing.sources=existing.sources.map(source=>({...source,projectionSchemaVersion:Number(source?.projectionSchemaVersion)||previousVersion}));
      existing.migration=previousVersion<2
        ?"Legacy scan state and pre-v2 web origins were preserved as a non-separable baseline; tracked source revisions are replaceable."
        :"Tracked scan-import sources were preserved and marked for bounded projection replay when their parser projection predates the current schema.";
      existing.migratedAt=new Date().toISOString();
      rebuildScanImportProjection(host,existing);
      return existing;
    }
    const baseline={
      scans:Object.fromEntries(SCAN_IMPORT_SLOTS.map(slot=>[slot,clean(host.scans?.[slot])])),
      scanEvidence:Object.fromEntries(["port","tcp","udp"].map(slot=>[slot,cloneImportValue(host.scanEvidence?.[slot],{})])),
      serviceInventory:cloneImportValue(host.serviceInventory,[]),
      endpointEvidence:cloneImportValue(host.endpointEvidence,[]),
      vulnerabilityLeads:cloneImportValue(host.vulnerabilityLeads,[]),
      vulnerabilityEvidence:cloneImportValue(host.vulnerabilityEvidence,{}),
      webTargets:cloneImportValue(host.recon?.webTargets,[])
    };
    host.scanImportProjection={
      schemaVersion:SCAN_IMPORT_PROJECTION_SCHEMA_VERSION,
      migration:"Existing scan state was preserved as a legacy baseline; only subsequently tracked source revisions are replaceable.",
      baseline,sources:[],migratedAt:new Date().toISOString()
    };
    return host.scanImportProjection;
  }
  function scanImportProjectionKey(filename,parsed,options={}){
    const artifactId=clean(options.sourceArtifactId);
    if(artifactId)return `artifact:${artifactId}`;
    return `source:${clean(filename).replace(/\\/g,"/").toLowerCase()}|${clean(parsed?.source||parsed?.tool||"nmap").toLowerCase()}`;
  }
  function scanCoverageRank(value){
    return ({complete:7,full:7,bounded:6,recorded:5,partial:4,"check-specific":3,"probe-specific":2,unknown:1,failed:0})[clean(value).toLowerCase()]??1;
  }
  function scanRepresentationRank(value){
    return ({xml:3,normal:2,grepable:1})[clean(value).toLowerCase()]||0;
  }
  function httpOriginScheme(row={}){
    const service=clean(row.service).toLowerCase(),tunnel=clean(row.tunnel).toLowerCase();
    if(service==="https")return "https";
    if(service!=="http")return "";
    return /(?:^|[^a-z])(?:ssl|tls)(?:[^a-z]|$)/.test(tunnel)?"https":"http";
  }
  function authoritativeHttpOriginService(row={},parsed={}){
    const protocol=clean(row.protocol||"tcp").toLowerCase(),state=clean(row.state).toLowerCase(),scheme=httpOriginScheme(row),endpointId=clean(row.id||row.endpointId);
    if(protocol!=="tcp"||state!=="open"||!scheme||!endpointId||row.identified!==true||row.active===false||row.endpointOwnershipConflict===true)return false;
    const statuses=[parsed.operationStatus||parsed.status,row.operationStatus].map(value=>clean(value).toLowerCase()).filter(Boolean);
    if(statuses.some(value=>value!=="completed"))return false;
    if(/failed|incomplete|partial|inconclusive|no[- ]?response|timed[- ]?out|unreachable|refused/.test(clean(row.probeResult).toLowerCase()))return false;
    const method=clean(row.serviceMethod||row.method).toLowerCase(),confidence=Number(row.serviceConfidence||row.conf)||0;
    const evidenceKind=clean(row.identificationEvidence).toLowerCase(),fingerprint=clean(row.serviceFingerprint||row.servicefp),details=[row.product,row.version,row.extraInfo,row.details,row.cpe,fingerprint].map(clean).filter(Boolean).join(" ");
    const protocolHttp=row.protocolResponse===true&&(evidenceKind.includes("http")||method!=="table"||/\bHTTP\/[0-9]/i.test(fingerprint));
    const probed=method==="probed"&&confidence>=3;
    const textProbe=row.probeCommand===true&&!!details;
    return protocolHttp||probed||textProbe;
  }
  function projectedOrigins(parsed={},options={}){
    const artifactId=clean(options.sourceArtifactId),revision=importSourceRevision(options),provisional=liveImportProvisional(options),at=new Date().toISOString();
    const seen=new Set(),rows=[];
    (parsed.services||[]).filter(row=>authoritativeHttpOriginService(row,parsed)).forEach(row=>{
      const address=clean(row.targetAddress||row.observedTargetAddress||parsed.targetAddress||parsed.target),port=Number(row.port),scheme=httpOriginScheme(row);
      if(!address||!Number.isInteger(port)||port<1||port>65535)return;
      const displayAddress=address.includes(":")&&!address.startsWith("[")?`[${address}]`:address;
      const url=`${scheme}://${displayAddress}:${port}`,key=`url:${scheme}://${address.toLowerCase()}:${port}/`;
      if(seen.has(key))return;seen.add(key);
      rows.push({
        id:`scan-origin:${clean(parsed.hostId)||"host"}:${scheme}:${port}`,key,kind:"url",recordRole:"web-origin",value:url,url,scheme,
        host:address,port,path:"/",query:"",method:"GET",unresolved:false,active:true,
        engagementId:clean(parsed.engagementId),hostId:clean(parsed.hostId),targetAddress:address,observedTargetAddress:address,
        endpointId:clean(row.id||row.endpointId),sourceOwner:"scan-import",sourceArtifactId:artifactId,sourceRevision:revision,artifactLifecycle:provisional?"provisional":"canonical",provisional,
        firstSeenAt:at,lastSeenAt:at,sources:[{artifactId,revision,filename:clean(options.sourcePath),tool:clean(parsed.source||parsed.tool),artifactLifecycle:provisional?"provisional":"canonical",provisional,observedAt:at}]
      });
    });
    return rows;
  }
  function migrateSourceOrigins(source={}){
    const sourceVersion=Number(source.projectionSchemaVersion)||0,originVersion=Number(source.originProjectionSchemaVersion)||0;
    if(sourceVersion>=SCAN_IMPORT_PROJECTION_SCHEMA_VERSION||originVersion>=SCAN_IMPORT_PROJECTION_SCHEMA_VERSION)return source;
    const services=Array.isArray(source.services)?source.services:[],owned=services.find(row=>row&&typeof row==="object")||{};
    source.origins=projectedOrigins({
      services,hostId:clean(owned.hostId),engagementId:clean(owned.engagementId),targetAddress:clean(source.targetAddress||owned.targetAddress||owned.observedTargetAddress),
      source:clean(source.source),tool:clean(source.source),operationStatus:clean(source.operationStatus),status:clean(source.operationStatus)
    },{
      sourceArtifactId:clean(source.sourceArtifactId),sourceRevision:Number(source.sourceRevision)||1,sourcePath:clean(source.sourcePath),
      liveImportProvisional:source.provisional===true||clean(source.artifactLifecycle)==="provisional"
    });
    source.originProjectionSchemaVersion=SCAN_IMPORT_PROJECTION_SCHEMA_VERSION;
    if(sourceVersion>=3)source.projectionSchemaVersion=SCAN_IMPORT_PROJECTION_SCHEMA_VERSION;
    return source;
  }
  function originDescriptor(row={}){
    const raw=clean(row.url||row.value);if(!raw)return null;
    try{
      const parsed=new URL(raw),scheme=parsed.protocol.replace(/:$/,""),port=Number(parsed.port)||(scheme==="https"?443:scheme==="http"?80:0);
      if(!["http","https"].includes(scheme)||!port)return null;
      return {scheme,host:clean(parsed.hostname).replace(/^\[|\]$/g,"").toLowerCase(),port};
    }catch(_error){return null;}
  }
  function supportedScanOrigin(row={},services=[]){
    if(clean(row.sourceOwner)!=="scan-import")return true;
    const descriptor=originDescriptor(row),endpointId=clean(row.endpointId||row.serviceEndpointId);if(!descriptor||!endpointId)return false;
    const endpoint=(services||[]).find(service=>clean(service?.id||service?.endpointId)===endpointId);if(!endpoint||!authoritativeHttpOriginService(endpoint,{}))return false;
    const address=clean(endpoint.targetAddress||endpoint.observedTargetAddress).replace(/^\[|\]$/g,"").toLowerCase();
    return !!address&&address===descriptor.host&&Number(endpoint.port)===descriptor.port&&httpOriginScheme(endpoint)===descriptor.scheme;
  }
  const SCAN_ORIGIN_REVIEW_FIELDS=["fingerprintReview","webReview","reviewState","reviewed","reviewedAt","annotation","notes","operatorNotes"];
  function originReviewIdentity(row={}){return `${clean(row.key)}|${clean(row.endpointId||row.serviceEndpointId)}`;}
  function originReviewOverlay(row={}){
    const overlay={};SCAN_ORIGIN_REVIEW_FIELDS.forEach(field=>{if(Object.prototype.hasOwnProperty.call(row,field))overlay[field]=cloneImportValue(row[field],row[field]);});return overlay;
  }
  function importContributionFor(parsed,filename,options={},endpointRecords=[]){
    const parser=api(),operationComplete=!clean(parsed.operationStatus||parsed.status)||clean(parsed.operationStatus||parsed.status)==="completed";
    const fullTcp=operationComplete&&parsed.objectives?.tcpDiscovery?.confirmed===true;
    const serviceEnum=operationComplete&&parsed.objectives?.serviceEnumeration?.confirmed===true;
    const udp=operationComplete&&(parsed.objectives?.udpDiscovery?.confirmed===true||(parsed.udpPorts||[]).length>0);
    const targeted=operationComplete&&(parsed.objectives?.targetedVulnerability?.confirmed===true||(parsed.vulnerabilityLeads||[]).length>0);
    const tcpLines=parser.scanLines(parsed.services,"tcp"),udpLines=parser.scanLines(parsed.services,"udp");
    const scans={port:"",tcp:"",udp:"",vuln:""};
    if(fullTcp)scans.port=tcpLines||parsed.rawText||"";
    if(serviceEnum||(!fullTcp&&tcpLines))scans.tcp=tcpLines||parsed.rawText||"";
    if(udp)scans.udp=udpLines||parsed.objectiveEvidence?.udpDiscovery||parsed.rawText||"";
    if(targeted)scans.vuln=parsed.rawText||"";
    if(operationComplete&&parsed.format!=="tool-output"&&!fullTcp&&!serviceEnum&&!udp&&!targeted&&parsed.rawText&&!parsed.vulnerabilityLeads?.length){
      scans[(parsed.tcpPorts||[]).length&&objectiveHint(options.taskId)==="tcp"?"tcp":"port"]=parsed.rawText;
    }
    const sourceSlot=fullTcp&&serviceEnum?"Imported scan":serviceEnum?"Service Enumeration":udp?"UDP Discovery":"TCP Discovery";
    return {
      key:scanImportProjectionKey(filename,parsed,options),
      projectionSchemaVersion:SCAN_IMPORT_PROJECTION_SCHEMA_VERSION,
      rawParserServiceCount:Number.isFinite(Number(parsed.rawParserServiceCount))?Number(parsed.rawParserServiceCount):(Number(parsed.services?.length)||0),
      postAuthorityServiceCount:Number.isFinite(Number(parsed.postAuthorityServiceCount))?Number(parsed.postAuthorityServiceCount):(Number(parsed.services?.length)||0),
      intrinsicServicesRestored:Number(parsed.intrinsicServicesRestored)||0,
      operationPathMatch:clean(parsed.operationPathMatch),
      sourceArtifactId:clean(options.sourceArtifactId||filename),
      sourceRevision:importSourceRevision(options),
      artifactLifecycle:liveImportProvisional(options)?"provisional":"canonical",
      provisional:liveImportProvisional(options),
      immutable:!liveImportProvisional(options),
      sourcePath:clean(filename),
      parserType:clean(options.parserType||parsed.tool||parsed.source||"nmap"),
      objective:clean(options.taskId),
      source:clean(parsed.source||parsed.tool||"Imported scan"),
      targetAddress:clean(parsed.targetAddress),
      operationStatus:clean(parsed.operationStatus||parsed.status),
      representation:clean(parsed.representation||parsed.format),
      runIdentity:clean(parsed.runIdentity),
      command:clean(parsed.command),
      scans,
      objectives:cloneImportValue(parsed.objectives,{}),
      services:(parsed.services||[]).map(row=>({...row,source:parsed.source||row.source,sourceSlot})),
      origins:projectedOrigins(parsed,{...options,sourcePath:filename}),
      endpointEvidence:cloneImportValue(endpointRecords,[]),
      vulnerabilityLeads:cloneImportValue(parsed.vulnerabilityLeads,[]),
      vulnerabilityEvidence:targeted?{
        sourceOwner:"scan-import",
        sourceArtifactId:clean(options.sourceArtifactId||filename),
        sourceRevision:importSourceRevision(options),
        artifactLifecycle:liveImportProvisional(options)?"provisional":"canonical",
        provisional:liveImportProvisional(options),
        confirmed:parsed.objectives?.targetedVulnerability?.confirmed===true,
        source:clean(parsed.source||"Imported scan"),
        command:clean(parsed.command),
        ports:Array.isArray(parsed.objectives?.targetedVulnerability?.ports)&&parsed.objectives.targetedVulnerability.ports.length?parsed.objectives.targetedVulnerability.ports:(parsed.services||[]).map(row=>Number(row.port)).filter(Boolean),
        reason:clean(parsed.objectives?.targetedVulnerability?.reason),
        updatedAt:new Date().toISOString()
      }:null,
      updatedAt:new Date().toISOString()
    };
  }
  function rebuildScanImportProjection(host,projection){
    const parser=api(),sources=projection.sources||[],baseline=projection.baseline||{};
    sources.forEach(migrateSourceOrigins);
    SCAN_IMPORT_SLOTS.forEach(slot=>{
      host.scans[slot]=(sources||[]).reduce((text,row)=>appendUnique(text,row.scans?.[slot]||""),clean(baseline.scans?.[slot]));
    });
    const objectiveBySlot={port:"tcpDiscovery",tcp:"serviceEnumeration",udp:"udpDiscovery"};
    ["port","tcp","udp"].forEach(slot=>{
      const current={...(host.scanEvidence?.[slot]||{})},base={...(baseline.scanEvidence?.[slot]||{})},objectiveKey=objectiveBySlot[slot];
      const candidates=sources.map(source=>({source,objective:source.objectives?.[objectiveKey]||{}})).filter(row=>row.source.scans?.[slot]||Object.keys(row.objective).length);
      const confirmed=candidates.filter(row=>row.objective.confirmed===true);
      const preferred=[...candidates].sort((a,b)=>Number(b.objective.confirmed===true)-Number(a.objective.confirmed===true)||scanCoverageRank(b.objective.coverage)-scanCoverageRank(a.objective.coverage)||scanRepresentationRank(b.source.representation)-scanRepresentationRank(a.source.representation)||String(b.source.updatedAt||"").localeCompare(String(a.source.updatedAt||"")))[0];
      const importedRecorded=base.importedRecorded===true||confirmed.length>0;
      const importedConfirmed=base.importedConfirmed===true||confirmed.length>0;
      host.scanEvidence[slot]={
        ...base,...current,
        command:preferred?.source.command||base.command||current.command||"",
        customCommand:Boolean(preferred?.source.command)||base.customCommand===true||current.customCommand===true,
        source:uniqueLabels(base.source,...candidates.map(row=>row.source.source)).join(" · "),
        importedRecorded,importedConfirmed,
        importedReason:preferred?.objective.reason||base.importedReason||"",
        coverage:preferred?.objective.coverage||base.coverage||"unknown",
        resultState:preferred?.objective.resultState||base.resultState||"",
        scannedPortCount:Number(preferred?.objective.scannedPortCount)||Number(base.scannedPortCount)||0,
        scannedPortExpression:clean(preferred?.objective.scannedPortExpression||base.scannedPortExpression),
        bounded:preferred?preferred.objective.bounded===true:base.bounded===true,
        full:preferred?preferred.objective.full===true:base.full===true,
        hostState:clean(preferred?.objective.hostState||base.hostState),
        endpointStateSummary:cloneImportValue(preferred?.objective.endpointStateSummary||base.endpointStateSummary,{}),
        updatedAt:preferred?.source.updatedAt||base.updatedAt||current.updatedAt||""
      };
    });
    const manualServices=(host.serviceInventory||[]).filter(row=>!["scan-import","host.scans"].includes(clean(row.sourceOwner)));
    host.serviceInventory=parser.mergeServices([
      ...(baseline.serviceInventory||[]),...manualServices,
      ...sources.flatMap(source=>source.services||[])
    ]);
    const evidence=new Map();
    const manualEvidence=(host.endpointEvidence||[]).filter(row=>clean(row.sourceOwner)!=="scan-import");
    [...(baseline.endpointEvidence||[]),...manualEvidence,...sources.flatMap(source=>source.endpointEvidence||[])].forEach(row=>{if(row?.id)evidence.set(row.id,row);});
    host.endpointEvidence=[...evidence.values()];
    const previousLeads=new Map((host.vulnerabilityLeads||[]).map(row=>[row.id,row]));
    host.vulnerabilityLeads=parser.mergeVulnerabilityLeads([
      ...(baseline.vulnerabilityLeads||[]),...(host.vulnerabilityLeads||[]).filter(row=>!["scan-import","host.scans"].includes(clean(row.sourceOwner))),
      ...sources.flatMap(source=>source.vulnerabilityLeads||[])
    ]).map(row=>{const prior=previousLeads.get(row.id);return {...row,status:prior?.status||row.status||"lead",notes:prior?.notes||row.notes||"",updatedAt:prior?.updatedAt||row.updatedAt||new Date().toISOString()};});
    const vulnerabilityRows=sources.map(source=>source.vulnerabilityEvidence).filter(Boolean);
    const preferredVulnerability=[...vulnerabilityRows].sort((a,b)=>Number(b.confirmed===true)-Number(a.confirmed===true)||String(b.updatedAt||"").localeCompare(String(a.updatedAt||"")))[0];
    const currentVulnerability=clean(host.vulnerabilityEvidence?.sourceOwner)==="scan-import"?{}:(host.vulnerabilityEvidence||{});
    host.vulnerabilityEvidence={...(baseline.vulnerabilityEvidence||{}),...currentVulnerability,...(preferredVulnerability||{})};
    if(preferredVulnerability)host.vulnerabilityEvidence.sourceOwner="scan-import";
    if(!host.recon||typeof host.recon!=="object")host.recon={};
    const currentOrigins=host.recon.webTargets||[],existingOrigins=[...(baseline.webTargets||[]),...currentOrigins],reviewOverlays=new Map();
    existingOrigins.forEach(row=>{const identity=originReviewIdentity(row);if(identity!=="|")reviewOverlays.set(identity,{...(reviewOverlays.get(identity)||{}),...originReviewOverlay(row)});});
    const nonScanOrigins=[...(baseline.webTargets||[]),...currentOrigins].filter(row=>clean(row?.sourceOwner)!=="scan-import");
    const retainedScanOrigins=[...currentOrigins,...(baseline.webTargets||[])].filter(row=>clean(row?.sourceOwner)==="scan-import"&&supportedScanOrigin(row,host.serviceInventory));
    const originRows=[...nonScanOrigins,...retainedScanOrigins,...sources.flatMap(source=>source.origins||[])];
    const origins=new Map();
    originRows.forEach(row=>{
      if(!row||!clean(row.key))return;
      const current=origins.get(row.key);
      if(!current){origins.set(row.key,cloneImportValue(row,{}));return;}
      const observations=[...(current.sources||[]),...(row.sources||[])].filter((item,index,all)=>all.findIndex(other=>clean(other.artifactId)===clean(item.artifactId)&&Number(other.revision)===Number(item.revision))===index);
      const operatorOwned=clean(current.sourceOwner)&&clean(current.sourceOwner)!=="scan-import";
      origins.set(row.key,{...current,...row,id:current.id||row.id,sourceOwner:operatorOwned?current.sourceOwner:row.sourceOwner||current.sourceOwner,firstSeenAt:current.firstSeenAt||row.firstSeenAt,sources:observations});
    });
    host.recon.webTargets=[...origins.values()].map(row=>({...row,...(reviewOverlays.get(originReviewIdentity(row))||{})}));
    window.AerosHostProfile?.ensureEndpointOwnership?.(host,sources.find(source=>source.services?.length)?.services?.[0]?.engagementId||"");
  }
  function upsertScanImportContribution(host,contribution){
    const projection=ensureScanImportProjection(host),index=projection.sources.findIndex(row=>row.key===contribution.key);
    if(index>=0)projection.sources[index]=contribution;else projection.sources.push(contribution);
    projection.sources=projection.sources.filter(row=>row&&row.key);
    projection.updatedAt=contribution.updatedAt;
    rebuildScanImportProjection(host,projection);
    return projection;
  }
  function stableImportId(value=""){
    let hash=2166136261;for(const char of String(value)){hash^=char.charCodeAt(0);hash=Math.imul(hash,16777619);}
    return `scan-run-${(hash>>>0).toString(16).padStart(8,"0")}`;
  }
  function logicalSourceKey(source={}){
    const pathFamily=clean(source.sourcePath).replace(/\\/g,"/").toLowerCase().replace(/[.](?:xml|nmap|gnmap)$/,"");
    return [
      clean(source.runIdentity||source.command||source.key).toLowerCase(),
      clean(source.targetAddress).toLowerCase(),
      pathFamily
    ].join("|");
  }
  function hasLegacyImportBaseline(baseline={}){
    return SCAN_IMPORT_SLOTS.some(slot=>clean(baseline.scans?.[slot]))
      ||["serviceInventory","endpointEvidence","vulnerabilityLeads"].some(key=>Array.isArray(baseline[key])&&baseline[key].length)
      ||Object.values(baseline.scanEvidence||{}).some(row=>row?.importedRecorded===true||row?.importedConfirmed===true);
  }
  function logicalImportedResults(host){
    const projection=ensureScanImportProjection(host),groups=new Map();
    (projection.sources||[]).forEach(source=>{
      const key=logicalSourceKey(source),id=stableImportId(key);
      if(!groups.has(id))groups.set(id,{id,key,sourceOwned:true,runIdentity:clean(source.runIdentity),command:clean(source.command),targetAddress:clean(source.targetAddress),sourceKeys:[],artifactIds:[],artifactLifecycles:[],files:[],representations:[],protocols:[],scopes:[],objectives:[],operationStates:[],sourceRows:[],serviceKeys:[],originKeys:[],leadKeys:[],services:0,origins:0,leads:0,updatedAt:""});
      const group=groups.get(id);
      group.sourceKeys.push(source.key);group.artifactIds.push(clean(source.sourceArtifactId));group.artifactLifecycles.push(clean(source.artifactLifecycle)||"canonical");group.files.push(clean(source.sourcePath));
      group.representations.push(clean(source.representation));
      group.serviceKeys.push(...(source.services||[]).map(row=>[clean(row.targetAddress||source.targetAddress).toLowerCase(),clean(row.protocol||"tcp").toLowerCase(),Number(row.port)||0].join("|")));
      group.originKeys.push(...(source.origins||[]).map(row=>clean(row.originId||row.id||row.url||row.value).toLowerCase()));
      group.leadKeys.push(...(source.vulnerabilityLeads||[]).map(row=>clean(row.id||[row.title,row.protocol,row.port,row.cve].filter(Boolean).join("|")).toLowerCase()));
      const objectiveRows=Object.entries(source.objectives||{}).filter(([,value])=>{
        if(!value||typeof value!=="object"||!Object.keys(value).length)return false;
        const coverage=clean(value.coverage).toLowerCase();
        return value.confirmed===true||Number(value.scannedPortCount)>0||clean(value.scannedPortExpression)||coverage&&coverage!=="unknown";
      });
      const protocols=[...new Set([
        ...(source.services||[]).map(row=>clean(row.protocol).toLowerCase()),
        ...objectiveRows.map(([name])=>name==="udpDiscovery"?"udp":name==="tcpDiscovery"||name==="serviceEnumeration"?"tcp":"").filter(Boolean)
      ].filter(Boolean))];
      const scopes=objectiveRows.map(([name,value])=>{
        const expression=clean(value.scannedPortExpression),count=Number(value.scannedPortCount)||0;
        return [name,expression||count?`${expression||count}${count&&expression?` (${count})`:""}`:""].filter(Boolean).join(": ");
      });
      group.protocols.push(...protocols);group.scopes.push(...scopes);
      group.objectives.push(clean(source.objective));group.operationStates.push(clean(source.operationStatus));
      group.sourceRows.push({
        key:source.key,artifactId:clean(source.sourceArtifactId),path:clean(source.sourcePath),
        representation:clean(source.representation),source:clean(source.source),parserType:clean(source.parserType),artifactLifecycle:clean(source.artifactLifecycle)||"canonical",provisional:source.provisional===true,
        objective:clean(source.objective),operationStatus:clean(source.operationStatus),protocols,scopes,
        targetAddress:clean(source.targetAddress),updatedAt:clean(source.updatedAt)
      });
      if(String(source.updatedAt||"")>group.updatedAt)group.updatedAt=String(source.updatedAt||"");
    });
    const rows=[...groups.values()].map(group=>{
      const serviceKeys=[...new Set(group.serviceKeys.filter(Boolean))],originKeys=[...new Set(group.originKeys.filter(Boolean))],leadKeys=[...new Set(group.leadKeys.filter(Boolean))];
      const {serviceKeys:_serviceKeys,originKeys:_originKeys,leadKeys:_leadKeys,artifactLifecycles:_artifactLifecycles,...visible}=group;
      const artifactLifecycles=[...new Set(group.artifactLifecycles.filter(Boolean))],provisional=artifactLifecycles.length>0&&artifactLifecycles.every(value=>value==="provisional");
      return {...visible,artifactLifecycle:provisional?"provisional":"canonical",provisional,sourceKeys:[...new Set(group.sourceKeys.filter(Boolean))],artifactIds:[...new Set(group.artifactIds.filter(Boolean))],files:[...new Set(group.files.filter(Boolean))],representations:[...new Set(group.representations.filter(Boolean))],protocols:[...new Set(group.protocols.filter(Boolean))],scopes:[...new Set(group.scopes.filter(Boolean))],objectives:[...new Set(group.objectives.filter(Boolean))],operationStates:[...new Set(group.operationStates.filter(Boolean))],services:serviceKeys.length,origins:originKeys.length,leads:leadKeys.length};
    });
    if(hasLegacyImportBaseline(projection.baseline))rows.unshift({id:"legacy-scan-baseline",sourceOwned:false,legacy:true,files:[],representations:[],services:projection.baseline.serviceInventory?.length||0,origins:0,leads:projection.baseline.vulnerabilityLeads?.length||0,updatedAt:projection.migratedAt||"",message:projection.migration});
    return rows.sort((a,b)=>Number(a.legacy===true)-Number(b.legacy===true)||String(b.updatedAt||"").localeCompare(String(a.updatedAt||"")));
  }
  function restoreHostSnapshot(host,snapshot){
    Object.keys(host).forEach(key=>delete host[key]);
    Object.assign(host,cloneImportValue(snapshot,{}));
  }
  function appendImportAudit(host,action,group,details={}){
    if(!Array.isArray(host.scanImportAudit))host.scanImportAudit=[];
    host.scanImportAudit=[...host.scanImportAudit,{id:`scan-audit-${Date.now()}-${Math.random().toString(16).slice(2)}`,action,logicalRunId:group.id,targetAddress:clean(group.targetAddress),runIdentity:clean(group.runIdentity),sourceFiles:group.files||[],sourceCount:group.sourceKeys?.length||0,at:new Date().toISOString(),...details}].slice(-100);
  }
  async function persistLifecycleMutation(host,options={}){
    if(typeof options.persistRequired==="function"){await options.persistRequired(host);return;}
    if(typeof save==="function"){save();return;}
    throw new Error("Required canonical persistence is unavailable.");
  }
  async function deleteLogicalImportedResult(host,logicalRunId,options={}){
    const group=logicalImportedResults(host).find(row=>row.id===clean(logicalRunId));
    if(!group)throw new Error("The selected imported result is stale or missing.");
    if(!group.sourceOwned)throw new Error("This legacy baseline is not source-separable and cannot be deleted safely.");
    const snapshot=cloneImportValue(host,{}),projection=ensureScanImportProjection(host);
    try{
      const sourceKeys=new Set(group.sourceKeys),artifactIds=new Set(group.artifactIds);
      projection.sources=projection.sources.filter(source=>!sourceKeys.has(source.key));
      host.scanArtifacts=(host.scanArtifacts||[]).filter(artifact=>!artifactIds.has(clean(artifact.id)));
      rebuildScanImportProjection(host,projection);
      if(typeof analyzeScanEvidenceForHost==="function")analyzeScanEvidenceForHost(host,{persist:false});
      appendImportAudit(host,"delete",group);
      await persistLifecycleMutation(host,options);
      return {ok:true,group,recalculated:true};
    }catch(error){
      restoreHostSnapshot(host,snapshot);
      if(typeof save==="function")save();
      throw error;
    }
  }
  function toolFromFile(file,parsed){
    const path=importFilePath(file).replace(/\\/g,"/");
    const lower=path.toLowerCase();
    if(/autorecon/.test(lower)||/\/scans\/(?:xml\/)?_(?:full|top|quick|manual).*nmap/.test(lower)||/(?:^|\/)(?:scans\/)?_commands[.]log$/.test(lower)||/\/report\/(?:local|remote)\//.test(lower))return "AutoRecon";
    const parts=path.split("/").filter(Boolean);
    if(parts.length===2&&/\.xml$/i.test(parts[1])){
      const parent=parts[0].toLowerCase(),base=parts[1].replace(/\.xml$/i,"").toLowerCase();
      if(parent===base||/^\d{1,3}(?:\.\d{1,3}){3}$/.test(parent))return "Threader3000";
    }
    return parsed?.source||"Imported scan";
  }
  function artifactExtension(filename){const match=clean(filename).toLowerCase().match(/([.][a-z0-9]+)$/);return match?match[1]:"";}
  function artifactType(filename,objective=""){const ext=artifactExtension(filename).replace(/^\./,"")||"file";const task=clean(objective).toLowerCase().replace(/[^a-z0-9]+/g,"-").replace(/^-|-$/g,"");return `scan-${ext}${task?`:${task}`:""}`;}
  async function fileSha256(file){
    if(!file?.arrayBuffer||!globalThis.crypto?.subtle)return "";
    const digest=await globalThis.crypto.subtle.digest("SHA-256",await file.arrayBuffer());
    return [...new Uint8Array(digest)].map(value=>value.toString(16).padStart(2,"0")).join("");
  }
  function liveImportProvisionalArtifactId(file,options={}){
    const host=resolveImportHost(options),logicalPath=canonicalImportFilePath(file)||"scan-artifact",identity={engagementId:importEngagementId(options),hostId:clean(host?.id||host?.ip),logicalPath,objective:clean(options.taskId),runId:clean(options.liveImportRunId||options.runId)};
    if(typeof window.AEROSLiveImportCore?.provisionalArtifactId!=="function")throw new Error("The authoritative Live Import identity mechanism is unavailable.");
    return window.AEROSLiveImportCore.provisionalArtifactId(identity);
  }
  function provisionalScanArtifact(file,parsed,options={},routing={}){
    const logicalPath=canonicalImportFilePath(file)||"scan-artifact",physicalSourcePath=importFilePath(file)||logicalPath,originalFilename=clean(file?.name)||logicalPath.split("/").pop()||"scan-artifact",observedAt=new Date().toISOString();
    return {
      id:liveImportProvisionalArtifactId(file,options),kind:"live-scan-projection",artifactLifecycle:"provisional",provisional:true,immutable:false,
      originalFilename,logicalPath,physicalSourcePath,runId:clean(options.liveImportRunId||options.runId),size:Number(file?.size)||0,extension:artifactExtension(originalFilename),artifactType:artifactType(originalFilename,options.taskId),
      source:clean(parsed?.source)||toolFromFile(file,parsed),hostKey:clean(resolveImportHost(options)?.id||resolveImportHost(options)?.ip),objective:clean(options.taskId),
      currentRevision:0,revisionCount:0,revisions:[],importHistory:[],storedFilename:"",sha256:"",lastImportStatus:"provisional",observedAt,updatedAt:observedAt,...routing
    };
  }
  function removeLiveImportProvisionalContribution(host,file,options={}){
    return removeLiveImportProvisionalArtifact(host,liveImportProvisionalArtifactId(file,{...options,host}));
  }
  function removeLiveImportProvisionalArtifact(host,artifactId){
    if(!host?.scanImportProjection?.sources||!clean(artifactId))return 0;
    const projection=ensureScanImportProjection(host),before=projection.sources.length;
    projection.sources=projection.sources.filter(source=>!(source?.provisional===true&&clean(source.sourceArtifactId)===clean(artifactId)));
    const removed=before-projection.sources.length;
    if(removed)rebuildScanImportProjection(host,projection);
    return removed;
  }
  async function retainScanArtifact(file,parsed,options={}){
    const host=resolveImportHost(options);if(!host)return {stored:false,outcome:"none"};ensureEvidence(host);
    const identity=window.AEROSArtifactIdentity;
    const logicalPath=canonicalImportFilePath(file)||"scan-artifact",physicalSourcePath=importFilePath(file)||logicalPath,runId=clean(options.liveImportRunId||options.runId);
    const originalFilename=clean(file?.name)||logicalPath.split("/").pop()||"scan-artifact";
    const size=Number(file?.size)||0;
    const lab=typeof activeLabName==="function"?clean(activeLabName()):"";
    const source=clean(parsed?.source)||toolFromFile(file,parsed);
    const ownership={engagementId:importEngagementId(options),hostId:clean(host.id),targetAddress:observedTargetAddress(host,parsed,options),parserType:clean(options.parserType||parsed?.tool||parsed?.source||"nmap"),objective:clean(options.taskId)};
    const routing={status:clean(parsed?.operationStatus||parsed?.status),target:clean(parsed?.target),targetCandidates:Array.isArray(parsed?.targetCandidates)?parsed.targetCandidates:[],targetConflict:parsed?.targetConflict===true,targetReason:clean(parsed?.targetReason),operation:parsed?.operation||null,...ownership};
    if(liveImportProvisional(options))return {stored:false,outcome:"provisional",provisional:true,artifact:provisionalScanArtifact(file,parsed,options,routing)};
    if(!lab){
      const observedAt=new Date().toISOString(),sha256=await fileSha256(file);
      const metadata={id:`metadata-${Date.now()}-${Math.random().toString(16).slice(2)}`,originalFilename,logicalPath,physicalSourcePath,runId,size,extension:artifactExtension(originalFilename),artifactType:artifactType(originalFilename,options.taskId),source,hostKey:host.id||host.ip||"",uploadedAt:observedAt,observedAt,sha256,storedFilename:"",lastImportStatus:"metadata",...routing};
      if(identity?.observeMetadata&&sha256){const observed=identity.observeMetadata(host.scanArtifacts,metadata);return {stored:false,metadata:true,outcome:observed.outcome,artifact:observed.artifact};}
      if(identity?.mergeArtifact)identity.mergeArtifact(host.scanArtifacts,metadata);else host.scanArtifacts.push(metadata);
      return {stored:false,metadata:true,outcome:"metadata"};
    }
    const form=new FormData();
    form.append("labName",lab);form.append("hostKey",host.id||host.ip||"");form.append("objective",clean(options.taskId));form.append("source",source);form.append("logicalPath",logicalPath);form.append("physicalSourcePath",physicalSourcePath);form.append("runId",runId);
    form.append("knownArtifacts",JSON.stringify(host.scanArtifacts||[]));form.append("artifact",file,originalFilename);
    try{
      const response=await fetch("/api/upload-scan-artifact",{method:"POST",body:form});const data=await response.json();
      if(!response.ok||!data.ok)throw new Error(data.error||"Artifact upload failed");
      const artifact={...data.artifact,...routing,updatedAt:new Date().toISOString()};
      if(identity?.mergeArtifact)identity.mergeArtifact(host.scanArtifacts,artifact);else{const index=host.scanArtifacts.findIndex(row=>row.id===artifact.id);if(index>=0)host.scanArtifacts[index]=artifact;else host.scanArtifacts.push(artifact);}
      return {stored:data.result?.storedNewFile===true,outcome:data.result?.outcome||"new",artifact};
    }catch(error){
      const metadata={id:`metadata-${Date.now()}-${Math.random().toString(16).slice(2)}`,originalFilename,logicalPath,physicalSourcePath,runId,size,extension:artifactExtension(originalFilename),source,hostKey:host.id||host.ip||"",uploadedAt:new Date().toISOString(),storedFilename:"",storageError:String(error?.message||error),lastImportStatus:"error",...routing};
      if(identity?.mergeArtifact)identity.mergeArtifact(host.scanArtifacts,metadata);else host.scanArtifacts.push(metadata);
      return {stored:false,outcome:"error",error:String(error?.message||error),artifact:metadata};
    }
  }
  function applyParsedImport(parsed,filename="",options={}){
    const host=resolveImportHost(options);if(!host)throw new Error("Select a host first, then import its scan evidence.");
    const parser=api();if(!parser)throw new Error("Scan intelligence module is unavailable.");
    parsed=ownParsedRecords(parsed,host,filename,options);
    ensureEvidence(host);
    if(!Array.isArray(host.endpointEvidence))host.endpointEvidence=[];
    const tcpLines=parser.scanLines(parsed.services,"tcp"),udpLines=parser.scanLines(parsed.services,"udp");
    const fullTcp=!!parsed.objectives?.tcpDiscovery?.confirmed;
    const serviceEnum=!!parsed.objectives?.serviceEnumeration?.confirmed;
    const udpConfirmed=!!parsed.objectives?.udpDiscovery?.confirmed;
    const operationComplete=!clean(parsed.operationStatus||parsed.status)||clean(parsed.operationStatus||parsed.status)==="completed";
    const udp=operationComplete&&(udpConfirmed||parsed.udpPorts?.length>0);
    const targetedVulnerability=!!parsed.objectives?.targetedVulnerability?.confirmed;

    const evidenceEndpoints=[...(parsed.services||[]),parsed.endpoint,parsed.operation?.protocol&&parsed.operation?.port?{protocol:parsed.operation.protocol,port:Number(parsed.operation.port),targetAddress:parsed.targetAddress}:null].filter(Boolean).filter((row,index,all)=>row.protocol&&row.port&&all.findIndex(other=>other.protocol===row.protocol&&Number(other.port)===Number(row.port)&&clean(other.targetAddress||parsed.targetAddress)===clean(row.targetAddress||parsed.targetAddress))===index);
    const endpointRecords=[];
    evidenceEndpoints.forEach(endpoint=>{
      const targetAddress=clean(endpoint.targetAddress||parsed.targetAddress),endpointId=clean(endpoint.id||endpoint.endpointId)||window.AerosHostProfile?.endpointIdentity?.({...endpoint,engagementId:parsed.engagementId,hostId:parsed.hostId,targetAddress},{host,engagementId:parsed.engagementId})||"";
      const evidenceId=`${clean(filename).replace(/\\/g,"/").toLowerCase()}|${clean(parsed.tool||parsed.source).toLowerCase()}|${endpointId||`${endpoint.protocol||""}:${Number(endpoint.port)||0}`}`;
      const index=host.endpointEvidence.findIndex(row=>row.id===evidenceId),previous=index>=0?host.endpointEvidence[index]:null,at=new Date().toISOString();
      const endpointService=(parsed.services||[]).find(row=>row.protocol===endpoint.protocol&&Number(row.port)===Number(endpoint.port));
      const scopedRaw=typeof parser.nmapEndpointEvidenceSlice==="function"?parser.nmapEndpointEvidenceSlice(parsed.rawText||"",endpoint.protocol,endpoint.port):(parsed.rawText||"");
      const provisional=liveImportProvisional(options),record={id:evidenceId,engagementId:parsed.engagementId,hostId:parsed.hostId,targetAddress,observedTargetAddress:clean(endpoint.observedTargetAddress||parsed.target||targetAddress),endpointId,sourceOwner:"scan-import",sourceArtifactId:clean(options.sourceArtifactId||filename),sourceRevision:importSourceRevision(options),artifactLifecycle:provisional?"provisional":"canonical",provisional,objective:clean(options.taskId),parserType:clean(options.parserType||parsed.tool||parsed.source||"nmap"),sourcePath:clean(filename),tool:parsed.tool||parsed.source,target:parsed.target||"",targetCandidates:parsed.targetCandidates||[],targetConflict:parsed.targetConflict===true,targetReason:parsed.targetReason||"",protocol:endpoint.protocol||"",port:Number(endpoint.port)||0,status:parsed.operationStatus||parsed.status||"unverified",probeResult:endpointService?.probeResult||((parsed.operationStatus||parsed.status)==="failed"?"failed":""),negativeCompleted:parsed.negativeCompleted===true,reason:parsed.resultReason||parsed.operation?.reason||"",error:parsed.error||parsed.operation?.error||"",command:parsed.command||"",outputPath:parsed.operation?.outputPath||"",completedChecks:endpointService?.completedChecks||[],enumerationObjectives:endpointService?.enumerationObjectives||[],enumerationCoverage:endpointService?.enumerationCoverage||parsed.enumerationCoverage||"",raw:scopedRaw,createdAt:clean(previous?.createdAt)||at,updatedAt:at};
      endpointRecords.push(record);
    });
    const rawFallback=operationComplete&&parsed.format!=="tool-output"&&!fullTcp&&!serviceEnum&&!udp&&!targetedVulnerability&&parsed.rawText&&!parsed.vulnerabilityLeads?.length;
    const fallbackSlot=rawFallback&&parsed.tcpPorts?.length?(objectiveHint(options.taskId)==="tcp"?"tcp":"port"):"";
    const contribution=importContributionFor(parsed,filename,options,endpointRecords);
    upsertScanImportContribution(host,contribution);
    if(fallbackSlot&&host.scanEvidence?.[fallbackSlot])host.scanEvidence[fallbackSlot].trustObjectiveHint=false;
    if(parsed.hostname&&!host.hostname)host.hostname=parsed.hostname;
    if(window.AerosHostProfile?.reconcileOsObservations){
      const family=window.AerosHostProfile.osFamily(parsed.os);
      const ownerKey=`scan-import:${clean(filename)||clean(parsed.source)||"nmap"}`;
      window.AerosHostProfile.reconcileOsObservations(host,ownerKey,!parsed.os||family==="unknown"?[]:[{
        family,authority:"explicit-scan-metadata",sourceType:"scan-import",
        sourceLabel:`${parsed.source||"Nmap"} OS metadata: ${clean(filename)||"imported scan"}`,
        ownerRef:{tab:"recon",filename:clean(filename)},
        evidence:clean(parsed.os),observedAt:new Date().toISOString()
      }]);
    }
    if(options.persist!==false&&typeof save==="function")save();
    if(options.render!==false){
      if(typeof parseScans==="function")parseScans({silent:true});
      else if(typeof render==="function")render();
    }
    return {services:parsed.services?.length||0,vulnerabilityLeads:parsed.vulnerabilityLeads?.length||0,contributionKey:contribution.key,sourceArtifactId:contribution.sourceArtifactId,objectives:[fullTcp&&"TCP discovery",serviceEnum&&"service enumeration",udpConfirmed&&"UDP discovery",targetedVulnerability&&"targeted vulnerability checks",parsed.vulnerabilityLeads?.length&&"vulnerability leads"].filter(Boolean)};
  }
  function importNmapXml(xmlText,filename="Nmap XML",options={}){
    const host=resolveImportHost(options);
    if(!host)throw new Error("Select a host first, then import its Nmap XML.");
    const parser=api();if(!parser)throw new Error("Scan intelligence module is unavailable.");
    const identity=activeTargetIdentity(host);
    const parsed=parser.parseNmapXml(xmlText,identity.primary,{filename,targetMappings:identity.mappings});
    if(parsed.targetConflict)throw new Error(`Target conflict: ${parsed.targetReason||`The Nmap XML does not contain the active host ${identity.primary}.`}`);
    if(!parsed.scanResultRecognized)throw new Error("The selected XML has no complete Nmap run structure.");
    parsed.rawText=String(xmlText||"");
    if(options.source)parsed.source=options.source;
    return applyParsedImport(parsed,filename,{...options,host});
  }
  function importScanText(text,filename="Scan output",options={}){
    const parser=api();if(!parser)throw new Error("Scan intelligence module is unavailable.");
    const hint=objectiveHint(options.taskId);
    const host=resolveImportHost(options);
    if(!host)throw new Error("Select a host first, then import its scan output.");
    const identity=activeTargetIdentity(host);
    const parsed=parser.parseNmapText(text,{filename,objectiveHint:hint,trustObjectiveHint:false,activeTarget:identity.primary,targetMappings:identity.mappings,manualFallback:true});
    parsed.rawText=String(text||"");
    if(!parsed.hasOutput)throw new Error("The selected scan file is empty.");
    if(parsed.targetConflict)throw new Error(`Target conflict: ${parsed.targetReason||`${filename} does not match the active host.`}`);
    if(options.source)parsed.source=options.source;
    return applyParsedImport(parsed,filename,{...options,host});
  }
  function isCandidate(file,folderMode){
    const path=importFilePath(file).toLowerCase();
    if(folderMode&&/(?:^|\/)(?:scans\/)?_(?:commands|errors)[.]log$/.test(path))return true;
    if(/\.(xml|nmap|gnmap)$/i.test(path))return true;
    if(!/\.txt$/i.test(path))return false;
    if(!folderMode)return true;
    return /(?:nmap|port|scan|tcp|udp|service|nikto|wpscan|wordpress|smb|vulners|nse|_errors)/i.test(path);
  }
  function normalizedBatchPath(file){return importFilePath(file).replace(/\\/g,"/").replace(/^\.\//,"").replace(/\/{2,}/g,"/");}
  function autoReconBatchReportFiles(fileList){
    const rows=[...fileList].map(file=>({file,path:normalizedBatchPath(file)})).filter(row=>row.path),groups=new Map();
    for(const row of rows){
      const match=/^(.*?)(?:\/)?report\/(local|proof|notes)[.]txt$/i.exec(row.path);if(!match)continue;
      const root=clean(match[1]).replace(/\/$/,""),key=root.toLowerCase();if(!groups.has(key))groups.set(key,{root,names:new Map(),rows:[]});
      const group=groups.get(key);group.names.set(match[2].toLowerCase(),row);group.rows.push(row);
    }
    const recognized=[];
    for(const group of groups.values()){
      const scanPrefix=`${group.root?`${group.root}/`:""}scans/`.toLowerCase(),scanPaths=rows.map(row=>row.path.toLowerCase()).filter(path=>path.startsWith(scanPrefix)),hasCommandLog=scanPaths.some(path=>/(?:^|\/)scans\/_commands[.]log$/.test(path)),hasAutoReconScanShape=scanPaths.some(path=>/(?:^|\/)scans\/(?:tcp|udp)\d+(?:\/|$)/.test(path)||/(?:^|\/)scans\/(?:xml\/)?_(?:full|quick|top|manual|port|udp)[^/]*(?:nmap|scan)/.test(path)),hasReportTrio=["local","proof","notes"].every(name=>group.names.has(name));
      if(!hasCommandLog&&!(hasAutoReconScanShape&&hasReportTrio))continue;
      recognized.push({...group,hasCommandLog,hasAutoReconScanShape});
    }
    const placeholders=recognized.flatMap(group=>[group.names.get("local"),group.names.get("proof")].filter(Boolean)),notes=recognized.map(group=>group.names.get("notes")).filter(Boolean);
    return {recognized:recognized.length>0,groups,recognizedGroups:recognized,placeholders,notes};
  }
  async function classifyAutoReconBatchNotes(reportFiles,host,options={}){
    const model=window.AEROSAutoReconLiveImport,results=[],route={scope:"host",host,hostId:clean(host?.id),hostAddress:clean(options.targetAddress||host?.ip),engagement:clean(options.engagementId||importEngagementId(options)),artifactPath:"report/notes.txt",autoReconOwned:true,autoReconOwnershipSource:"recognized-batch-tree"};
    if(!reportFiles?.recognized||typeof model?.semanticDisposition!=="function")return {results,ignored:0,retained:0,errors:[]};
    let ignored=reportFiles.placeholders.length,retained=0;const errors=[];
    for(const row of reportFiles.notes){
      try{
        if(Number(row.file?.size)>25*1024*1024)throw new Error("AutoRecon report/notes.txt exceeds the 25 MiB content-aware import limit.");
        const text=await readFile(row.file),semantic=model.semanticDisposition({path:"report/notes.txt",route,text,contentAvailable:true});
        if(semantic.action==="ignore"){ignored++;results.push({path:row.path,semantic,ignored:true});continue;}
        if(semantic.kind!=="external-autorecon-notes"){results.push({path:row.path,semantic});continue;}
        if(typeof window.AEROSAutoReconBatchSemanticImport!=="function")throw new Error("The AutoRecon operator-notes retention bridge is unavailable.");
        const result=await window.AEROSAutoReconBatchSemanticImport({file:row.file,text,physicalSourcePath:row.path,host,engagementId:route.engagement,semantic});
        if(!result?.ok)throw new Error(result?.reason||"External AutoRecon Notes could not be retained.");
        retained++;results.push({path:row.path,semantic,result});
      }catch(error){errors.push(`${row.file?.name||row.path}: ${String(error?.message||error)}`);}
    }
    return {results,ignored,retained,errors};
  }
  function looksLikeNmapText(text="",path=""){
    return /\.(?:nmap|gnmap)$/i.test(clean(path))
      ||/^\s*#\s*Nmap\b.*scan initiated\b/im.test(text)
      ||/^\s*Nmap scan report for\s+.+$/im.test(text)
      ||/^\s*Host:\s+\S+(?:\s+\([^)]*\))?(?:\s+Status:|\s+Ports:|\s*$)/im.test(text);
  }

  function normalizeCorrelationPath(value=""){
    let path=clean(value).replace(/^file:\/\//i,"").replace(/\\/g,"/").replace(/^['"]|['"]$/g,"").replace(/\/{2,}/g,"/");
    if(/^\/[a-z]:\//i.test(path))path=path.slice(1);
    return path.replace(/^\.\//,"").replace(/\/$/,"");
  }
  function correlationPathAliases(...values){
    const aliases=[],seen=new Set(),add=value=>{
      const normalized=normalizeCorrelationPath(value).toLowerCase();
      if(normalized&&!seen.has(normalized)){seen.add(normalized);aliases.push(normalized);}
    };
    values.flat().forEach(value=>{
      const normalized=normalizeCorrelationPath(value);if(!normalized)return;
      add(normalized);
      const lower=normalized.toLowerCase();
      ["/aeros-import-staging/","/aeros_import_staging/"].forEach(marker=>{const index=lower.lastIndexOf(marker);if(index>=0)add(normalized.slice(index+marker.length));});
      if(lower.startsWith("aeros-import-staging/")||lower.startsWith("aeros_import_staging/"))add(normalized.split("/").slice(1).join("/"));
      const scansIndex=lower.lastIndexOf("/scans/");
      if(scansIndex>=0){
        const scanSuffix=normalized.slice(scansIndex+1),before=normalized.slice(0,scansIndex),target=before.split("/").filter(Boolean).at(-1)||"";
        add(scanSuffix);if(target)add(`${target}/${scanSuffix}`);
      }
    });
    return aliases;
  }
  function commandOutputPaths(command=""){
    const paths=[],text=String(command||"");
    const expression=/(?:^|\s)(-o[ANGX]|--(?:output|output-file|outfile))(?:\s+|=)(?:"([^"]+)"|'([^']+)'|([^\s]+))/gi;
    for(const match of text.matchAll(expression)){
      const option=clean(match[1]).toLowerCase(),value=clean(match[2]||match[3]||match[4]);if(!value)continue;
      if(option==="-oa"){paths.push(`${value}.nmap`,`${value}.xml`,`${value}.gnmap`);}
      else paths.push(value);
    }
    return paths;
  }
  function operationOutputPaths(operation={}){
    const values=[];
    ["resultPath","outputPath","outfile","outFile","stdoutPath","xmlPath","normalPath","grepablePath"].forEach(key=>{if(operation?.[key])values.push(operation[key]);});
    ["outputPaths","outputs","resultPaths"].forEach(key=>{if(Array.isArray(operation?.[key]))values.push(...operation[key]);});
    values.push(...commandOutputPaths(operation?.command));
    return [...new Set(values.map(normalizeCorrelationPath).filter(Boolean))];
  }
  function operationForImportPath(parser,correlation,path,canonicalPath=""){
    const wanted=correlationPathAliases(path,canonicalPath),wantedSet=new Set(wanted);
    for(const alias of wanted){
      try{
        const direct=parser.operationForPath(correlation,alias);
        if(direct){if(!direct.resultPath)direct.resultPath=path;direct.aerosPathMatch=alias===normalizeCorrelationPath(path).toLowerCase()?"direct":"normalized-alias";return direct;}
      }catch(_error){}
    }
    const operations=Array.isArray(correlation?.operations)?correlation.operations:[],matches=[];
    for(const operation of operations){
      const candidateAliases=correlationPathAliases(operationOutputPaths(operation));
      if(candidateAliases.some(alias=>wantedSet.has(alias)))matches.push({operation,match:"normalized-alias"});
    }
    if(matches.length===1){const operation=matches[0].operation;if(!operation.resultPath)operation.resultPath=path;operation.aerosPathMatch=matches[0].match;return operation;}
    const basename=normalizeCorrelationPath(path).split("/").at(-1)?.toLowerCase()||"";
    if(!basename)return null;
    const basenameMatches=operations.filter(operation=>operationOutputPaths(operation).some(value=>normalizeCorrelationPath(value).split("/").at(-1)?.toLowerCase()===basename));
    if(basenameMatches.length===1){const operation=basenameMatches[0];if(!operation.resultPath)operation.resultPath=path;operation.aerosPathMatch="unique-basename";return operation;}
    return null;
  }
  function explicitNmapCompletion(parsed={},text=""){
    const raw=String(text||parsed.rawText||""),format=clean(parsed.format||parsed.representation).toLowerCase();
    if(format==="xml"||/<nmaprun\b/i.test(raw))return /<finished\b/i.test(raw)&&/<\/nmaprun>\s*$/i.test(raw);
    if(format==="grepable"||/\.gnmap$/i.test(clean(parsed.filename)))return /^\s*#\s*Nmap done at\b/im.test(raw);
    return /^\s*Nmap done:\s+/im.test(raw)||/^\s*#\s*Nmap done at\b/im.test(raw);
  }
  function completedMatchedNmapOperation(operation,parsed,text,options={}){
    if(!operation||liveImportProvisional(options)||!explicitNmapCompletion(parsed,text))return operation;
    const status=clean(operation.status).toLowerCase();
    if(["completed","failed","partial","interrupted"].includes(status))return operation;
    if(!["direct","normalized-alias"].includes(clean(operation.aerosPathMatch)))return operation;
    operation.status="completed";
    operation.reason=clean(operation.reason)||"The AutoRecon command output path matches this result and the Nmap file contains an explicit completion marker.";
    operation.completedBy="matched-nmap-output";
    return operation;
  }
  function positiveNmapEndpoint(row={}){
    const state=clean(row.state).toLowerCase();
    return Number.isInteger(Number(row.port))&&Number(row.port)>0&&Number(row.port)<=65535&&["open","open|filtered"].includes(state);
  }
  function restoreIntrinsicNmapEndpointEvidence(intrinsic,governed,operation,options={}){
    const rawServices=Array.isArray(intrinsic?.services)?intrinsic.services:[],postServices=Array.isArray(governed?.services)?governed.services:[],status=clean(governed?.operationStatus||governed?.status||operation?.status||"unverified").toLowerCase()||"unverified";
    let result={...governed,rawParserServiceCount:rawServices.length,postAuthorityServiceCount:postServices.length,operationPathMatch:clean(operation?.aerosPathMatch)};
    if(options.nmapParsed!==true||!rawServices.length||postServices.length||governed?.targetConflict===true||intrinsic?.targetConflict===true)return result;
    if(!["completed","unverified","partial","failed","interrupted"].includes(status))return result;
    const authorityReason=clean(governed?.resultReason||governed?.operation?.reason||operation?.reason)||"AutoRecon command/output authority did not establish broad scan completion.";
    const services=rawServices.filter(positiveNmapEndpoint).map(row=>{
      const completed=status==="completed",failed=status==="failed";
      const enumerationState=completed?row.enumerationState:failed?"identification-needed":clean(row.enumerationState)==="fully-enumerated"?"not-started":clean(row.enumerationState);
      return {...row,identified:failed?false:row.identified,identificationState:failed?"identification-needed":row.identificationState,operationStatus:status,operationAuthority:status,authorityReason,probeResult:failed?"failed":clean(row.probeResult),completedChecks:completed?cloneImportValue(row.completedChecks,[]):[],enumerationObjectives:completed?cloneImportValue(row.enumerationObjectives,[]):[],enumerationCoverage:completed?clean(row.enumerationCoverage):"",enumerationComplete:completed&&row.enumerationComplete===true,fullyEnumerated:completed&&row.fullyEnumerated===true,enumerationState};
    });
    if(!services.length)return result;
    const tcpPorts=[...new Set(services.filter(row=>clean(row.protocol).toLowerCase()==="tcp").map(row=>Number(row.port)).filter(Boolean))].sort((a,b)=>a-b),udpPorts=[...new Set(services.filter(row=>clean(row.protocol).toLowerCase()==="udp").map(row=>Number(row.port)).filter(Boolean))].sort((a,b)=>a-b);
    return {...result,services,tcpPorts,udpPorts,runIdentity:clean(governed?.runIdentity||intrinsic?.runIdentity),representation:clean(governed?.representation||intrinsic?.representation),format:clean(governed?.format||intrinsic?.format),scaninfos:Array.isArray(governed?.scaninfos)&&governed.scaninfos.length?governed.scaninfos:cloneImportValue(intrinsic?.scaninfos,[]),scanResultRecognized:governed?.scanResultRecognized===true||intrinsic?.scanResultRecognized===true,target:clean(governed?.target||intrinsic?.target),targetCandidates:Array.isArray(governed?.targetCandidates)&&governed.targetCandidates.length?governed.targetCandidates:cloneImportValue(intrinsic?.targetCandidates,[]),vulnerabilityLeads:cloneImportValue(governed?.vulnerabilityLeads,[]),intrinsicServicesRestored:services.length,intrinsicEndpointEvidence:true};
  }
  function needsLiveImportProjectionRepair(host,artifactId="",detectedType=""){
    if(!host||!host.scanImportProjection||!["nmap","scan-tool"].includes(clean(detectedType)))return false;
    const projection=host.scanImportProjection,sources=Array.isArray(projection.sources)?projection.sources:[],id=clean(artifactId);
    return sources.some(source=>{
      if(source?.provisional===true||id&&clean(source?.sourceArtifactId||source?.artifactId)!==id)return false;
      const parserType=clean(source?.parserType).toLowerCase(),representation=clean(source?.representation).toLowerCase(),nmap=/nmap/.test(parserType)||["xml","normal","grepable","text"].includes(representation);
      if(!nmap)return false;
      const sourceVersion=Number(source?.projectionSchemaVersion)||Number(projection.schemaVersion)||0;
      return sourceVersion<SCAN_IMPORT_PROJECTION_SCHEMA_VERSION;
    });
  }
  function applyLiveImportLifecycle(parsed,options={}){
    if(!parsed)return parsed;
    const manifestStatus=clean(options.liveImportRunStatus).toLowerCase(),terminalFailure=["failed","interrupted"].includes(manifestStatus)&&clean(options.liveImportCompletionKind)==="manifest-terminal";
    if(!liveImportProvisional(options)&&!terminalFailure)return parsed;
    const objectives={};
    const lifecycleState=manifestStatus==="failed"?"failed":"partial",reason=terminalFailure?`The AutoRecon run ended ${manifestStatus}; final bytes are retained without upgrading incomplete objectives.`:"Live Import retained current records without claiming file completion.";
    Object.entries(parsed.objectives||{}).forEach(([key,value])=>{objectives[key]=value&&typeof value==="object"?{...value,confirmed:false,reason:value.reason||reason}:value;});
    return {...parsed,status:lifecycleState,operationStatus:lifecycleState,operationCompleted:false,negativeCompleted:false,objectives,operation:parsed.operation?{...parsed.operation,status:lifecycleState,reason:parsed.operation.reason||reason}:parsed.operation};
  }
  function readFile(file){return new Promise((resolve,reject)=>{const reader=new FileReader();reader.onload=()=>resolve(String(reader.result||""));reader.onerror=()=>reject(new Error(`Could not read ${file.name}.`));reader.readAsText(file);});}
  async function maybeConfirmFullCoverage(taskId,host){
    if(taskId!=="tcp-port-discovery"||!host)return;
    ensureEvidence(host);
    if(host.scanEvidence.port.confirmed||!(host.scanEvidence.port.ports||[]).length)return;
    const message="The imported file contains TCP results, but its command or metadata does not prove that ports 1-65535 were scanned. Confirm that this evidence came from a complete TCP-range scan?";
    let confirmed=false;
    if(typeof themedConfirm==="function")confirmed=await themedConfirm(message,{title:"Confirm Full TCP Coverage",confirmText:"Confirm Coverage"})===true;
    else confirmed=window.confirm(message);
    if(!confirmed)return;
    host.scanEvidence.port.manualConfirmed=true;
    host.scanEvidence.port.updatedAt=new Date().toISOString();
    if(typeof parseScans==="function")parseScans({silent:true});
  }
  async function processFiles(fileList,options={}){
    const beforeHost=resolveImportHost(options);
    if(!beforeHost){if(!options.silent)alert("Select a host before importing scan evidence.");return {ok:false,errors:["No exact host is selected."]};}
    const replacementLogicalRunId=clean(options.replacementLogicalRunId);
    const replacementSnapshot=replacementLogicalRunId?cloneImportValue(beforeHost,{}):null;
    const replacementGroup=replacementLogicalRunId?logicalImportedResults(beforeHost).find(row=>row.id===replacementLogicalRunId):null;
    if(replacementLogicalRunId&&(!replacementGroup||!replacementGroup.sourceOwned))throw new Error("The selected replacement owner is stale, missing, or not source-separable.");
    const replacementContributionKeys=new Set(),replacementArtifactIds=new Set();
    const lockedOptions={...options,host:beforeHost,hostId:clean(beforeHost.id),engagementId:importEngagementId(options)};
    ensureEvidence(beforeHost);const beforeEndpoints=new Map((beforeHost.serviceInventory||[]).map(row=>[clean(row.id||row.endpointId)||`${row.protocol||"tcp"}:${Number(row.port)||0}`,JSON.stringify(row)]));const beforeLeads=new Map((beforeHost.vulnerabilityLeads||[]).map(row=>[row.id,JSON.stringify(row)]));
    const beforeContextKeys=new Set((beforeHost?.serviceContexts||[]).filter(row=>row?.active!==false).map(row=>clean(row.endpointId)||`${row?.protocol||"tcp"}|${Number(row?.port)||0}`));
    const parser=api(),identity=activeTargetIdentity(beforeHost),selectedTarget=clean(options.targetAddress)||identity.primary,targetMappings=identity.mappings;
    const folderMode=options.mode==="folder";
    const batchReportFiles=folderMode?autoReconBatchReportFiles(fileList):{recognized:false,placeholders:[],notes:[]};
    const batchNotes=await classifyAutoReconBatchNotes(batchReportFiles,beforeHost,{...lockedOptions,targetAddress:selectedTarget});
    const semanticReportFiles=new Set([...(batchReportFiles.placeholders||[]),...(batchReportFiles.notes||[])].map(row=>row.file));
    const files=[...fileList].filter(file=>!semanticReportFiles.has(file)&&isCandidate(file,folderMode)).sort((a,b)=>{
      const ax=/\.xml$/i.test(a.name)?0:/\.(nmap|gnmap)$/i.test(a.name)?1:2;
      const bx=/\.xml$/i.test(b.name)?0:/\.(nmap|gnmap)$/i.test(b.name)?1:2;
      return ax-bx||importFilePath(a).localeCompare(importFilePath(b));
    });
    if(!files.length&&!batchReportFiles.recognized){if(!options.silent)alert(folderMode?"No supported scan files were found in that folder.":"Choose an XML, NMAP, GNMAP, or text scan result.");return {ok:false,errors:["No supported scan files were found."]};}
    const textCache=new Map();
    for(const file of files){if(file.size<=25*1024*1024)textCache.set(file,await readFile(file));}
    const commandFile=files.find(file=>/(?:^|[\\/])(?:scans[\\/])?_commands[.]log$/i.test(importFilePath(file)));
    const errorFile=files.find(file=>/(?:^|[\\/])(?:scans[\\/])?_errors[.]log$/i.test(importFilePath(file)));
    const correlation=folderMode&&commandFile?api().correlateAutoRecon(textCache.get(commandFile)||"",errorFile?(textCache.get(errorFile)||""):"",files.filter(file=>file!==commandFile&&file!==errorFile).map(file=>({path:importFilePath(file),text:textCache.get(file)||""}))):null;
    let imported=0,supplementalApplied=0,supplementalTargetConflicts=0,services=0,vulnerabilityLeads=0,artifactsStored=0,artifactsRetained=batchNotes.retained,artifactsNew=0,artifactsUpdated=0,artifactsUnchanged=0,provisionalArtifacts=0,provisionalPromotions=0,rawOnlyRecognized=0,supportFiles=0,unmatched=0,targetConflicts=0,skipped=0,examined=0,rawParserServices=0,postAuthorityServices=0,intrinsicServicesRestored=0,operationPathAliasesMatched=0;const objectives=new Set(),nmapRuns=new Map(),errors=[],artifactErrors=[...batchNotes.errors],artifactObservations=[];
    for(const row of batchNotes.results.filter(item=>item.result?.ok)){
      const outcome=clean(row.result.outcome),logicalPath=clean(row.result.logicalPath||row.result.canonicalLogicalPath||row.path);if(outcome==="new")artifactsNew++;else if(outcome==="updated")artifactsUpdated++;else if(outcome==="unchanged")artifactsUnchanged++;if(row.result.stored===true)artifactsStored++;
      artifactObservations.push({path:logicalPath,physicalSourcePath:row.path,runId:"",id:clean(row.result.artifactId),revision:Number(row.result.artifactRevision)||1,outcome:outcome||"retained",artifactLifecycle:"canonical",provisional:false,semanticKind:"external-autorecon-notes"});
    }
    for(const file of files.slice(0,250)){
      let parsed=null;
      try{
        examined++;
        if(file.size>25*1024*1024){skipped++;errors.push(`${file.name}: skipped because it exceeds the 25 MiB import limit.`);continue;}
        const text=textCache.get(file)??await readFile(file);
        const path=importFilePath(file),canonicalPath=canonicalImportFilePath(file)||path;
        const operation=correlation?operationForImportPath(parser,correlation,path,canonicalPath):null;
        if(operation?.aerosPathMatch&&operation.aerosPathMatch!=="direct")operationPathAliasesMatched++;
        let routedOperation=operation?{...operation,resultPath:path}:null;
        let result=null,parsedAsNmap=false;
        if(/(?:^|[\\/])(?:scans[\\/])?_(?:errors|commands)[.]log$/i.test(path)){
          const commandText=commandFile?(textCache.get(commandFile)||""):text;
          parsed=parser.parseCommandLog(commandText,{filename:path,source:"AutoRecon",activeTarget:selectedTarget,targetMappings,requireTargetEvidence:folderMode});
          parsed.rawText=text;
          parsed=parser.resolveParsedTarget(parsed,selectedTarget,{filename:path,targetIdentity:identity,mappings:targetMappings,requireEvidence:folderMode,manualFallback:!folderMode});
          parsed.supportOnly=true;
          supportFiles++;
        }else if(/<nmaprun\b/i.test(text)||/\.xml$/i.test(file.name)){
          parsed=parser.parseNmapXml(text,selectedTarget,{filename:path,targetMappings,requireTargetEvidence:folderMode});parsed.rawText=text;parsedAsNmap=true;
          if(!parsed.scanResultRecognized&&!parsed.services.length&&!parsed.scaninfos?.length&&!parsed.vulnerabilityLeads?.length&&!parsed.objectives?.targetedVulnerability?.confirmed)parsed=null;
        }else if(looksLikeNmapText(text,path)){
          parsed=parser.parseNmapText(text,{filename:path,command:routedOperation?.command||"",objectiveHint:folderMode?"":objectiveHint(options.taskId),trustObjectiveHint:false,activeTarget:selectedTarget,targetMappings,requireTargetEvidence:folderMode,manualFallback:!folderMode});parsed.rawText=text;parsedAsNmap=true;
          if(!parsed.hasOutput||(!parsed.scanResultRecognized&&!parsed.services.length&&!parsed.command&&!parsed.vulnerabilityLeads?.length&&!parsed.objectives?.targetedVulnerability?.confirmed))parsed=null;
        }else if((parsed=parser.parseToolOutput(text,{filename:path,command:routedOperation?.command||"",activeTarget:selectedTarget,targetMappings,requireTargetEvidence:folderMode}))){
          parsed.rawText=text;
        }else{
          parsed=parser.parseNmapText(text,{filename:path,command:routedOperation?.command||"",objectiveHint:folderMode?"":objectiveHint(options.taskId),trustObjectiveHint:false,activeTarget:selectedTarget,targetMappings,requireTargetEvidence:folderMode,manualFallback:!folderMode});parsed.rawText=text;parsedAsNmap=true;
          if(!parsed.hasOutput||(!parsed.scanResultRecognized&&!parsed.services.length&&!parsed.command&&!parsed.vulnerabilityLeads?.length&&!parsed.objectives?.targetedVulnerability?.confirmed))parsed=null;
        }
        if(parsed){
          const intrinsicParsed=parsed;
          if(parsedAsNmap&&operation){completedMatchedNmapOperation(operation,intrinsicParsed,text,options);routedOperation={...operation,resultPath:path};}
          if(parsedAsNmap)rawParserServices+=Array.isArray(intrinsicParsed.services)?intrinsicParsed.services.length:0;
          if(correlation){
            const governed=parser.applyOperationAuthority(parsed,routedOperation||{status:"unverified",reason:"No matching AutoRecon command/output operation was found for this result."});
            if(parsedAsNmap)postAuthorityServices+=Array.isArray(governed?.services)?governed.services.length:0;
            parsed=restoreIntrinsicNmapEndpointEvidence(intrinsicParsed,governed,routedOperation,{nmapParsed:parsedAsNmap});
            intrinsicServicesRestored+=Number(parsed.intrinsicServicesRestored)||0;
          }
          parsed=applyLiveImportLifecycle(parsed,options);
          parsed=parser.resolveParsedTarget(parsed,selectedTarget,{filename:path,operation:routedOperation,targetIdentity:identity,mappings:targetMappings,requireEvidence:folderMode,manualFallback:!folderMode});
          parsed.source=parsed.tool||toolFromFile(file,parsed);
          if(parsed.runIdentity){
            if(!nmapRuns.has(parsed.runIdentity))nmapRuns.set(parsed.runIdentity,new Set());
            nmapRuns.get(parsed.runIdentity).add(parsed.representation||parsed.format||"nmap");
          }
          if(operation&&operation.status==="completed"&&["text","xml"].includes(parsed.format)&&(parsed.format==="xml"||parsed.scanResultRecognized===true)&&parsed.objectives?.udpDiscovery?.confirmed){operation.parsedUdpScan=true;operation.parsedUdpOpenPorts=[...(parsed.udpPorts||[])];operation.parsedFormat=parsed.format;}
          if(parsed.targetConflict){targetConflicts++;errors.push(`${file.name}: Target conflict: ${parsed.targetReason}`);}
          else{
            const retained=await retainScanArtifact(file,parsed,lockedOptions);
            if(["new","updated","unchanged","metadata","error"].includes(retained.outcome))artifactsRetained++;
            if(retained.provisional)provisionalArtifacts++;
            if(retained.outcome==="new")artifactsNew++;
            if(retained.outcome==="updated")artifactsUpdated++;
            if(retained.outcome==="unchanged")artifactsUnchanged++;
            if(retained.stored)artifactsStored++;
            if(clean(retained.artifact?.id))replacementArtifactIds.add(clean(retained.artifact.id));
            artifactObservations.push({path:canonicalPath,physicalSourcePath:path,runId:clean(options.liveImportRunId||options.runId),id:clean(retained.artifact?.id),revision:retained.provisional?0:(Number(retained.artifact?.currentRevision||retained.artifact?.revision||retained.artifact?.revisionCount)||1),outcome:clean(retained.outcome),artifactLifecycle:retained.provisional?"provisional":"canonical",provisional:retained.provisional===true});
            if(retained.error)artifactErrors.push(`${file.name}: ${retained.error}`);
            if(!parsed.supportOnly){
              const artifactOptions={...lockedOptions,persist:false,render:false,liveImportProvisional:retained.provisional===true,sourceArtifactId:clean(retained.artifact?.id)||canonicalPath,sourceRevision:retained.provisional?0:(Number(retained.artifact?.currentRevision||retained.artifact?.revision||retained.artifact?.revisionCount)||1)};
              result=applyParsedImport(parsed,canonicalPath,artifactOptions);imported++;services+=result.services;vulnerabilityLeads+=result.vulnerabilityLeads||0;result.objectives.forEach(value=>objectives.add(value));if(result.contributionKey)replacementContributionKeys.add(result.contributionKey);
            }
            if(options.liveImport===true&&!retained.provisional&&retained.outcome!=="error")provisionalPromotions+=removeLiveImportProvisionalContribution(beforeHost,file,lockedOptions);
          }
        }else if(!/(?:^|[\\/])(?:scans[\\/])?_(?:commands|errors)[.]log$/i.test(path)){unmatched++;}
      }catch(error){const message=String(error?.message||error);if(/target conflict/i.test(message))targetConflicts++;else unmatched++;errors.push(`${file.name}: ${message}`);}
    }
    if(commandFile&&correlation){
      const completedZeroUdp=(correlation.operations||[]).filter(row=>row.protocol==="udp"&&row.status==="completed"&&row.parsedUdpScan===true&&Array.isArray(row.parsedUdpOpenPorts)&&row.parsedUdpOpenPorts.length===0);
      if(completedZeroUdp.length){
        let commandEvidence=parser.parseCommandLog(textCache.get(commandFile)||"",{filename:importFilePath(commandFile),source:"AutoRecon",activeTarget:selectedTarget,targetMappings,requireTargetEvidence:true});
        commandEvidence.objectives.udpDiscovery={confirmed:true,coverage:"recorded",resultState:"executed-no-open-ports",reason:"A completed correlated UDP scan was parsed successfully and reported zero open or open|filtered UDP endpoints."};commandEvidence.operationEvidence=completedZeroUdp;
        if(commandEvidence.targetConflict){supplementalTargetConflicts++;errors.push(`${commandFile.name}: Target conflict: ${commandEvidence.targetReason}`);}
        else{commandEvidence=applyLiveImportLifecycle(commandEvidence,lockedOptions);const result=applyParsedImport(commandEvidence,canonicalImportFilePath(commandFile),{...lockedOptions,persist:false,render:false});supplementalApplied++;result.objectives.forEach(value=>objectives.add(value));if(result.contributionKey)replacementContributionKeys.add(result.contributionKey);}
      }
    }
    if(correlation?.unmatchedErrors?.length)errors.push(...correlation.unmatchedErrors.map(line=>`Unmatched AutoRecon error: ${line}`));
    const host=beforeHost;
    const appliedAny=imported+supplementalApplied>0;
    if(replacementGroup){
      const invalid=!appliedAny||errors.length>0||artifactErrors.length>0||targetConflicts>0||supplementalTargetConflicts>0||unmatched>0||skipped>0;
      if(invalid){
        restoreHostSnapshot(host,replacementSnapshot);
        if(typeof save==="function")save();
        throw new Error(`Replacement was not committed because validation failed.${errors.length?` ${errors[0]}`:""}`);
      }
      const projection=ensureScanImportProjection(host),oldKeys=new Set(replacementGroup.sourceKeys),oldArtifacts=new Set(replacementGroup.artifactIds);
      projection.sources=projection.sources.filter(source=>!oldKeys.has(source.key)||replacementContributionKeys.has(source.key));
      host.scanArtifacts=(host.scanArtifacts||[]).filter(artifact=>!oldArtifacts.has(clean(artifact.id))||replacementArtifactIds.has(clean(artifact.id)));
      rebuildScanImportProjection(host,projection);
      appendImportAudit(host,"replace",replacementGroup,{replacementSourceCount:replacementContributionKeys.size});
    }
    if(appliedAny){
      const udpInventory=(host?.serviceInventory||[]).filter(row=>String(row?.protocol||"").toLowerCase()==="udp");
      if(host?.scanEvidence?.udp?.importedConfirmed&&String(host.scanEvidence.udp.source||"").toLowerCase().includes("autorecon")){
        const noOpenUdp=udpInventory.length===0;
        const reason=noOpenUdp?"AutoRecon command history confirms that UDP discovery was executed; no open UDP ports were identified in the imported results.":"AutoRecon command history confirms that UDP discovery was executed.";
        host.scanEvidence.udp.reason=reason;host.scanEvidence.udp.importedReason=reason;host.scanEvidence.udp.resultState=noOpenUdp?"executed-no-open-ports":"open-ports-found";
      }
      if(typeof analyzeScanEvidenceForHost==="function")analyzeScanEvidenceForHost(host,{persist:false});
      if(typeof activeHost==="function"&&activeHost()===host&&typeof render==="function")render();
      if(!options.suppressPrompts)await maybeConfirmFullCoverage(options.taskId,host);
    }
    const afterEndpoints=new Map((host.serviceInventory||[]).map(row=>[clean(row.id||row.endpointId)||`${row.protocol||"tcp"}:${Number(row.port)||0}`,JSON.stringify(row)]));const endpointNew=[...afterEndpoints.keys()].filter(key=>!beforeEndpoints.has(key)).length;const endpointUpdated=[...afterEndpoints.keys()].filter(key=>beforeEndpoints.has(key)&&beforeEndpoints.get(key)!==afterEndpoints.get(key)).length;const endpointUnchanged=[...afterEndpoints.keys()].filter(key=>beforeEndpoints.get(key)===afterEndpoints.get(key)).length;
    const afterLeads=new Map((host.vulnerabilityLeads||[]).map(row=>[row.id,JSON.stringify(row)]));const leadsNew=[...afterLeads.keys()].filter(key=>!beforeLeads.has(key)).length;const leadsUpdated=[...afterLeads.keys()].filter(key=>beforeLeads.has(key)&&beforeLeads.get(key)!==afterLeads.get(key)).length;const udpRows=(host.serviceInventory||[]).filter(row=>row.protocol==="udp");
    const operations=correlation?.operations||[],filesNotExamined=Math.max(0,files.length-250),meaningfulSelected=Math.max(0,fileList.length-batchNotes.ignored),semanticAdmitted=batchNotes.retained,excludedFiles=Math.max(0,meaningfulSelected-files.length-semanticAdmitted);const summary={filesSelected:meaningfulSelected,filesAdmitted:files.length+semanticAdmitted,filesExamined:examined+semanticAdmitted,filesNotExamined,excludedFiles,filesParsed:imported,parsedResultFiles:imported,supplementalEvidenceApplied:supplementalApplied,recognizedSupportFiles:supportFiles,externalAutoReconNotesRetained:batchNotes.retained,rawOnlyRecognizedFiles:rawOnlyRecognized,rawOnlyFiles:rawOnlyRecognized+targetConflicts,unmatchedFiles:unmatched,targetConflicts,supplementalTargetConflicts,skippedFiles:skipped,classifiedFiles:imported+supportFiles+semanticAdmitted+rawOnlyRecognized+unmatched+targetConflicts+skipped,artifactsRetained,artifactsStored,artifactsNew,artifactsUpdated,artifactsUnchanged,provisionalArtifacts,provisionalPromotions,nmapRuns:nmapRuns.size,nmapSiblingRuns:[...nmapRuns.values()].filter(representations=>representations.size>1).length,nmapRepresentations:[...nmapRuns.values()].reduce((total,representations)=>total+representations.size,0),rawParserServices,postAuthorityServices,intrinsicServicesRestored,operationPathAliasesMatched,commandsCorrelated:operations.filter(row=>row.resultPath).length,completedOperations:operations.filter(row=>row.status==="completed").length,negativeCompletedOperations:operations.filter(row=>{if(row.status!=="completed")return false;const resultFile=files.find(file=>(file.webkitRelativePath||file.name)===row.resultPath);return !/\bopen(?:\|filtered)?\b/i.test(textCache.get(resultFile)||"");}).length,failedOperations:operations.filter(row=>row.status==="failed").length,partialOperations:operations.filter(row=>row.status==="partial").length,unverifiedOperations:operations.filter(row=>row.status==="unverified").length,endpointsDiscovered:afterEndpoints.size,endpointsNew:endpointNew,endpointsUpdated:endpointUpdated,endpointsUnchanged:endpointUnchanged,udpIdentificationNeeded:udpRows.filter(row=>row.identificationState==="identification-needed").length,udpIdentified:udpRows.filter(row=>row.identificationState==="identified").length,udpUnknownAfterProbing:udpRows.filter(row=>row.identificationState==="unknown-after-probing").length,udpFullyEnumerated:udpRows.filter(row=>row.enumerationState==="fully-enumerated").length,vulnerabilityLeadsNew:leadsNew,vulnerabilityLeadsUpdated:leadsUpdated,vulnerabilityLeadsUnchanged:[...afterLeads.keys()].filter(key=>beforeLeads.get(key)===afterLeads.get(key)).length,objectivesConfirmed:objectives.size,objectivesNotConfirmed:Math.max(0,4-objectives.size),warnings:errors.length+artifactErrors.length};host.lastScanImportSummary=summary;
    try{
      if(replacementGroup)await persistLifecycleMutation(host,options);
      else if(typeof save==="function")save();
    }catch(error){
      if(replacementSnapshot){restoreHostSnapshot(host,replacementSnapshot);if(typeof save==="function")save();}
      throw error;
    }
    const activeContexts=(host?.serviceContexts||[]).filter(row=>row?.active!==false);
    const addedContexts=activeContexts.filter(row=>!beforeContextKeys.has(clean(row.endpointId)||`${row?.protocol||"tcp"}|${Number(row?.port)||0}`)).length;
    const confirmed=[host?.scanEvidence?.port?.confirmed&&"TCP discovery",host?.scanEvidence?.tcp?.confirmed&&"service enumeration",host?.scanEvidence?.udp?.confirmed&&"UDP discovery"].filter(Boolean);
    const notesUpdate=addedContexts?` Added ${addedContexts} port context${addedContexts===1?"":"s"} to Notes.`:"";
    const leadUpdate=vulnerabilityLeads?` Added ${vulnerabilityLeads} vulnerability lead${vulnerabilityLeads===1?"":"s"}.`:"";
    const artifactUpdate=artifactsRetained?` Artifacts: ${artifactsNew} new, ${artifactsUpdated} updated revision${artifactsUpdated===1?"":"s"}, ${artifactsUnchanged} unchanged duplicate${artifactsUnchanged===1?"":"s"}${artifactsStored?`; ${artifactsStored} new file${artifactsStored===1?" was":"s were"} stored internally`:""}.`:provisionalArtifacts?` ${provisionalArtifacts} open artifact${provisionalArtifacts===1?" is":"s are"} represented provisionally without canonical revision retention.`:artifactErrors.length?" Scan data was parsed, but one or more original artifacts could not be stored.":"";
    const udpNoOpen=host?.scanEvidence?.udp?.resultState==="executed-no-open-ports";
    const message=`Examined ${summary.filesExamined}/${summary.filesSelected} files; parsed ${summary.parsedResultFiles}, support ${summary.recognizedSupportFiles}, raw-only recognized ${summary.rawOnlyRecognizedFiles}, unmatched ${summary.unmatchedFiles}, conflicts ${summary.targetConflicts}. Endpoints: ${summary.endpointsNew} new, ${summary.endpointsUpdated} updated, ${summary.endpointsUnchanged} unchanged; UDP identification needed ${summary.udpIdentificationNeeded}. Operations: ${summary.completedOperations} completed, ${summary.failedOperations} failed, ${summary.partialOperations} partial, ${summary.unverifiedOperations} unverified.${leadUpdate}${notesUpdate}${confirmed.length?` Confirmed: ${confirmed.join(", ")}.`:""}${udpNoOpen?" UDP discovery completed with no open UDP ports identified.":""}${artifactUpdate}`;
    const intentionalScaffoldingOnly=!files.length&&batchReportFiles.recognized&&!batchNotes.retained&&!batchNotes.errors.length,supportOnlyAccepted=!appliedAny&&(intentionalScaffoldingOnly||batchNotes.retained>0||options.allowSupportOnly===true&&(artifactsRetained>0||provisionalArtifacts>0))&&!targetConflicts&&!supplementalTargetConflicts&&!errors.length&&!artifactErrors.length;
    if(!appliedAny&&!supportOnlyAccepted){if(!options.silent)alert(`No usable scan evidence was applied. ${message}${errors.length?`\n\n${errors.slice(0,3).join("\n")}`:""}`);return {ok:false,summary,errors:[...errors,...artifactErrors],artifactIds:[...replacementArtifactIds],artifactObservations};}
    if(!options.silent){if(typeof showToast==="function")showToast(message,confirmed.length?"success":"warning");else alert(message);}
    return {ok:true,summary,errors,hostId:clean(host.id),supportOnly:supportOnlyAccepted,provisional:liveImportProvisional(options),artifactIds:[...replacementArtifactIds],artifactObservations,contributionKeys:[...replacementContributionKeys]};
  }
  function openScanEvidenceImport(taskId,mode="file"){
    pendingTaskId=clean(taskId);
    const input=document.getElementById(mode==="folder"?"scanFolderImportInput":"nmapImportInput");
    if(!input){alert("The scan importer is unavailable in this build.");return;}
    input.value="";input.click();
  }
  function nmapXmlToScan(xmlText,ip){
    const parser=api();if(!parser)return {tcp:[],udp:[],hostname:"",os:""};
    const parsed=parser.parseNmapXml(xmlText,ip);
    return {tcp:parser.scanLines(parsed.services,"tcp").split(/\r?\n/).filter(Boolean),udp:parser.scanLines(parsed.services,"udp").split(/\r?\n/).filter(Boolean),hostname:parsed.hostname,os:parsed.os,command:parsed.command,objectives:parsed.objectives,services:parsed.services};
  }
  function init(){
    const fileInput=document.getElementById("nmapImportInput"),folderInput=document.getElementById("scanFolderImportInput");
    fileInput?.addEventListener("change",()=>{const files=fileInput.files;if(files?.length)processFiles(files,{taskId:pendingTaskId,mode:"file"}).catch(error=>alert(`Scan import failed: ${error?.message||error}`));});
    folderInput?.addEventListener("change",()=>{const files=folderInput.files;if(files?.length)processFiles(files,{taskId:pendingTaskId,mode:"folder"}).catch(error=>alert(`Results-folder import failed: ${error?.message||error}`));});
  }
  if(document.readyState==="loading")document.addEventListener("DOMContentLoaded",init);else init();
  window.openScanEvidenceImport=openScanEvidenceImport;
  window.importNmapXml=(xmlText,filename)=>importNmapXml(xmlText,filename,{taskId:pendingTaskId});
  window.importScanText=(text,filename)=>importScanText(text,filename,{taskId:pendingTaskId});
  window.nmapXmlToScan=nmapXmlToScan;
  window.AerosScanImportTestHooks={applyParsedImport,processFiles,retainScanArtifact,ensureScanImportProjection,rebuildScanImportProjection,logicalImportedResults,deleteLogicalImportedResult,projectedOrigins,authoritativeHttpOriginService,supportedScanOrigin,scanRepresentationRank,isCandidate,autoReconBatchReportFiles,classifyAutoReconBatchNotes,looksLikeNmapText,applyLiveImportLifecycle,liveImportProvisionalArtifactId,removeLiveImportProvisionalContribution,removeLiveImportProvisionalArtifact,normalizeCorrelationPath,correlationPathAliases,operationForImportPath,explicitNmapCompletion,completedMatchedNmapOperation,restoreIntrinsicNmapEndpointEvidence,needsLiveImportProjectionRepair};
})();
