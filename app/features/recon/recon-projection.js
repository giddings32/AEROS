(function(root,factory){
  const reconImportApi=(typeof module==="object"&&module.exports)?require("../imports/recon-import.js"):(root&&root.AEROSReconImport);
  const scanApi=(typeof module==="object"&&module.exports)?require("../../../scan-intelligence.js"):(root&&root.AerosScanIntelligence);
  const api=factory(reconImportApi||{},scanApi||{});
  if(typeof module==="object"&&module.exports)module.exports=api;
  if(root)root.AEROSReconProjection=api;
})(typeof window!=="undefined"?window:globalThis,function(reconImportApi,scanApi){
  "use strict";

  const STATES=Object.freeze(["not-run","partial","bounded","negative","conflict","complete","deferred"]);
  const OPEN_STATES=new Set(["not-run","partial","bounded","conflict","deferred"]);
  const STATE_ORDER=Object.freeze({conflict:0,"not-run":1,partial:2,bounded:3,deferred:4,negative:5,complete:6});
  const COVERAGE_DIMENSION_IDS=Object.freeze([
    "tcp-discovery",
    "tcp-service-identity",
    "udp-scoped-discovery",
    "web-mapping",
    "technology-fingerprinting",
    "evidence-review"
  ]);
  const TECHNOLOGY_DISPLAY_LIMITS=Object.freeze({globalObservations:500,perOriginObservations:200,globalSourceOutcomes:250,perOriginSourceOutcomes:100,targetUrlsPerOutcome:5,errorsPerOutcome:3,corroboratingProvenance:5,serviceApplicationObservations:100});
  const EVIDENCE_REVIEW_LIMITS=Object.freeze({results:200,endpoints:200,coverage:100,origins:200,observations:200,leads:200,webRecords:200,technologyRecords:200,operations:100,revisions:100,importHistory:250});
  const TECHNOLOGY_OPEN_STATES=new Set(["conflicting","stale","partial","failed","deferred","unknown"]);
  const TECHNOLOGY_OBJECTIVE_LIMITS=Object.freeze({identities:50,supportingObservations:20,provenancePerIdentity:50,known:50,unknown:50,nextSteps:4});

  function text(value){return String(value??"").trim();}
  function number(value){const parsed=Number(value);return Number.isFinite(parsed)?parsed:0;}
  function values(input){return Array.isArray(input)?input:[];}
  function unique(input){return [...new Set(values(input).filter(value=>value!==null&&value!==undefined&&text(value)!==""))];}
  function idPart(value,fallback="unknown"){return text(value).toLowerCase().replace(/[^a-z0-9._:-]+/g,"-").replace(/^-+|-+$/g,"")||fallback;}
  function normalizeState(value,fallback="not-run"){const state=text(value).toLowerCase();return STATES.includes(state)?state:fallback;}
  function percent(part,total){return total>0?Math.max(0,Math.min(100,Math.round(number(part)/number(total)*100))):0;}
  function severityForState(value){
    const state=normalizeState(value);
    if(state==="conflict"||state==="not-run")return "high";
    if(state==="partial"||state==="bounded")return "medium";
    if(state==="deferred")return "low";
    return "resolved";
  }
  function deepFreeze(value){
    if(!value||typeof value!=="object"||Object.isFrozen(value))return value;
    Object.values(value).forEach(deepFreeze);
    return Object.freeze(value);
  }
  function destination(section,details={}){
    return {
      section:text(section)||"overview",
      workspace:text(details.workspace)||"recon",
      selector:text(details.selector),
      endpointId:text(details.endpointId),
      originId:text(details.originId),
      artifactId:text(details.artifactId),
      recordId:text(details.recordId)
    };
  }
  function fact(input){
    const owner=destination(input.section,input.owner||{});
    const state=normalizeState(input.state);
    return {
      id:text(input.id),
      label:text(input.label),
      reason:text(input.reason),
      state,
      severity:text(input.severity)||severityForState(state),
      blocking:input.blocking===true,
      sourceFacts:unique(input.sourceFacts),
      dimension:text(input.dimension)||"recon",
      scope:{
        kind:text(input.scope?.kind)||"host",
        id:text(input.scope?.id),
        label:text(input.scope?.label)||"Selected host"
      },
      owner
    };
  }
  function scanState(entry={},kind=""){
    const coverage=text(entry.coverage).toLowerCase();
    if(coverage==="conflict")return "conflict";
    if(coverage==="deferred")return "deferred";
    if(coverage==="negative")return "negative";
    if(entry.confirmed===true){
      if(entry.bounded===true||coverage==="bounded"||(kind==="udp"&&entry.full!==true))return "bounded";
      return "complete";
    }
    if(coverage==="partial"||coverage==="incomplete")return "partial";
    if(coverage==="bounded")return "bounded";
    return "not-run";
  }
  function conciseUdpReason(entry,state,missing){
    const count=number(entry.scannedPortCount),expression=text(entry.scannedPortExpression);
    const topHundred=count===100||/top[\s-]*100/i.test(expression);
    if(state==="bounded"){
      const scope=topHundred?"Top-100":count?`${count}-port`:"Bounded";
      return `${scope} UDP scope is complete; overall UDP coverage remains partial.`;
    }
    if(state==="complete")return "The recorded UDP discovery scope is complete.";
    if(state==="negative")return "The recorded UDP discovery scope completed without an open UDP endpoint.";
    if(state==="not-run")return missing;
    return `Targeted UDP coverage remains ${state}; review the exact retained scope in Evidence & Scans.`;
  }
  function scanFact(host,key,entry={}){
    const definitions={
      port:{
        id:"scan:tcp-discovery",
        label:"TCP discovery coverage",
        missing:"No full TCP discovery evidence is recorded for this host.",
        section:"evidence"
      },
      tcp:{
        id:"scan:service-enumeration",
        label:"TCP service-enumeration coverage",
        missing:"No complete service-enumeration evidence is recorded for the discovered TCP endpoints.",
        section:"evidence"
      },
      udp:{
        id:"scan:udp-coverage",
        label:"UDP coverage",
        missing:"No targeted UDP discovery evidence is recorded for this host.",
        section:"evidence"
      }
    };
    const definition=definitions[key],state=scanState(entry,key);
    let reason=text(entry.reason)||definition.missing;
    if(key==="udp")reason=conciseUdpReason(entry,state,definition.missing);
    return fact({
      id:definition.id,label:definition.label,reason,state,dimension:"scan",
      severity:key==="udp"&&state==="not-run"?"medium":"",
      scope:{kind:"host",id:text(host.id),label:text(host.hostname)||text(host.ip)||"Selected host"},
      section:definition.section,
      owner:{selector:`#scanPanel${key==="port"?"Port":key==="tcp"?"Tcp":"Udp"}`}
    });
  }
  function endpointIdentity(row,index){
    return text(row.id)||text(row.endpointId)||[
      "endpoint",idPart(row.engagementId,"engagement"),idPart(row.hostId,"host"),
      idPart(row.targetAddress||row.observedTargetAddress||row.address,"address"),idPart(row.protocol||"tcp"),number(row.port)||index+1
    ].join("|");
  }
  function endpointLabel(row){
    const protocol=text(row.protocol||"tcp").toUpperCase(),port=number(row.port);
    return `${protocol} ${port||"unknown port"}`;
  }
  function isWebEndpoint(row){
    const protocol=text(row.protocol||"tcp").toLowerCase(),state=text(row.state||"open").toLowerCase();
    if(protocol!=="tcp"||state!=="open"||row.identified!==true)return false;
    if(row.isWeb===true)return true;
    const service=text(row.service).toLowerCase();
    return ["http","https","ssl/http","http-proxy"].includes(service);
  }
  function originIdentity(row,index){
    return text(row.id)||text(row.originId)||text(row.key)||`origin-${index+1}`;
  }
  function exactOrigins(host){
    return values(host?.recon?.webTargets).filter(row=>row&&row.recordRole==="web-origin");
  }
  function coverageState(value){
    const state=text(value).toLowerCase();
    if(["complete","completed"].includes(state))return "complete";
    if(state==="bounded")return "bounded";
    if(["failed","conflict","conflicting"].includes(state))return "conflict";
    if(["partial","incomplete"].includes(state))return "partial";
    if(["negative","zero"].includes(state))return "negative";
    if(state==="deferred")return "deferred";
    return "not-run";
  }
  function serviceStrength(row={}){
    const coverage=coverageState(row.serviceScanCoverageState||row.coverage);
    return (row.identified===true?1000:0)+({complete:100,bounded:80,partial:50,negative:40,conflict:20,"not-run":0}[coverage]||0)
      +[row.product,row.version,row.cpe,row.serviceFingerprint,row.details].map(value=>text(value).length).reduce((sum,value)=>sum+value,0)
      +(text(row.serviceMethod).toLowerCase()==="probed"?100:0)+(number(row.serviceConfidence)||0);
  }
  function serviceProvenance(row={}){
    return {
      sourceOwner:text(row.sourceOwner),source:text(row.source||row.sourceSlot||row.parserType),artifactId:text(row.sourceArtifactId||row.artifactId),
      revision:number(row.sourceRevision||row.revision),representation:text(row.representation||row.sourceSlot),operation:text(row.objective||row.command),observedAt:text(row.updatedAt||row.observedAt)
    };
  }
  function serviceProvenanceKey(row={}){
    return [text(row.artifactId),number(row.revision),text(row.source),text(row.sourceOwner),text(row.representation),text(row.operation),text(row.observedAt)].join("|");
  }
  function serviceRepresentationStrength(row={}){
    const source=text(row.representation||row.source||row.sourceSlot||row.parserType).toLowerCase();
    return source.includes("xml")?30:source.includes("gnmap")?10:source.includes("nmap")?20:0;
  }
  function compareServiceAuthority(left={},right={}){
    return serviceStrength(left)-serviceStrength(right)||serviceRepresentationStrength(left)-serviceRepresentationStrength(right)||serviceProvenanceKey(serviceProvenance(left)).localeCompare(serviceProvenanceKey(serviceProvenance(right)));
  }
  function boundedServiceProvenance(rows=[],authority={}){
    const authoritativeKey=serviceProvenanceKey(authority),uniqueRows=[...new Map(values(rows).map(row=>[serviceProvenanceKey(row),row])).values()].sort((left,right)=>serviceProvenanceKey(left).localeCompare(serviceProvenanceKey(right))),authoritative=uniqueRows.find(row=>serviceProvenanceKey(row)===authoritativeKey)||authority;
    return [authoritative,...uniqueRows.filter(row=>serviceProvenanceKey(row)!==authoritativeKey)].filter(row=>serviceProvenanceKey(row)).slice(0,100);
  }
  function canonicalServices(host={}){
    const rows=[],byId=new Map();
    values(host.serviceInventory).forEach((raw,index)=>{
      if(!raw||typeof raw!=="object")return;
      const id=endpointIdentity(raw,index),provenance=serviceProvenance(raw),current=byId.get(id);
      if(!current){const row={...raw,id,endpointId:id,authoritativeIdentityProvenance:provenance,evidenceSources:[provenance]};rows.push(row);byId.set(id,row);return;}
      const candidateWins=compareServiceAuthority(raw,current)>0,authority=candidateWins?provenance:current.authoritativeIdentityProvenance||serviceProvenance(current),sources=boundedServiceProvenance([...values(current.evidenceSources),provenance],authority);
      if(candidateWins)Object.assign(current,{...raw,id,endpointId:id,authoritativeIdentityProvenance:authority,evidenceSources:sources});
      else Object.assign(current,{authoritativeIdentityProvenance:authority,evidenceSources:sources});
    });
    return rows.sort((left,right)=>number(left.port)-number(right.port)||text(left.protocol).localeCompare(text(right.protocol))||text(left.id).localeCompare(text(right.id)));
  }
  function endpointScopedNmapEvidence(raw,protocol,port){
    if(typeof scanApi.nmapEndpointEvidenceSlice==="function")return scanApi.nmapEndpointEvidenceSlice(raw,protocol,port);
    return String(raw??"");
  }

  function technologyRecordState(record={},source={}){
    const review=text(record.reviewState||source.reviewState).toLowerCase(),operation=text(record.operationState||source.operationState).toLowerCase();
    if(review==="stale")return "stale";
    if(review==="conflicting"||["conflict","conflicting"].includes(operation))return "conflicting";
    if(operation==="failed")return "failed";
    if(["partial","incomplete"].includes(operation))return "partial";
    if(review==="deferred"||operation==="deferred")return "deferred";
    if(["complete","completed"].includes(operation))return number(record.resultCount??values(record.technologies).length)>0?"positive":"zero";
    return "unknown";
  }
  function technologyRecordsByEndpoint(host={}){
    const index=new Map();
    values(host?.recon?.technologyImportProjection?.sources).forEach(source=>values(source.records).forEach(record=>{
      const endpointId=text(record.endpointId||source.endpointId);if(!endpointId)return;if(!index.has(endpointId))index.set(endpointId,[]);index.get(endpointId).push({source,record});
    }));
    return index;
  }
  function explicitApplicationObservationProjection(host,row,endpointId,technologyRecords){
    const visible=[],seen=new Set(),versions=new Map();let totalCount=0,acceptedCount=0,originTotalCount=0;
    const add=raw=>{
      const name=text(raw?.name||raw?.application);if(!name)return;
      const originId=text(raw.originId),ownerKind=originId?"origin":"endpoint",state=["established","candidate","clue-only","conflicting","failed","partial","stale","deferred","unknown"].includes(text(raw.state))?text(raw.state):"candidate";
      const item={name,version:text(raw.version),state,identityConflict:state==="conflicting"&&raw.identityConflict!==false,ownerKind,endpointId,originId,sourceKind:text(raw.sourceKind)||"endpoint-evidence",artifactId:text(raw.artifactId||row.sourceArtifactId),revision:number(raw.revision||row.sourceRevision),recordId:text(raw.recordId||raw.id),targetUrl:text(raw.targetUrl),sourceOrigin:text(raw.sourceOrigin),operationState:text(raw.operationState),reviewState:text(raw.reviewState),error:text(raw.error)};
      const key=[item.ownerKind,item.endpointId,item.originId,item.name.toLowerCase(),item.version,item.state,item.sourceKind,item.recordId,item.artifactId,item.revision].join("|");if(seen.has(key))return;seen.add(key);totalCount++;if(ownerKind==="origin")originTotalCount++;if(acceptedApplicationIdentity(item))acceptedCount++;
      if(["established","candidate","clue-only"].includes(item.state)&&item.version){const versionKey=[item.ownerKind,item.endpointId,item.originId,item.name.toLowerCase()].join("|");if(!versions.has(versionKey))versions.set(versionKey,new Set());versions.get(versionKey).add(item.version.toLowerCase());}
      if(visible.length<TECHNOLOGY_DISPLAY_LIMITS.serviceApplicationObservations)visible.push(item);
    };
    values(row.applicationObservations).forEach(add);
    values(host.endpointEvidence).filter(evidence=>text(evidence?.endpointId)===endpointId).forEach(evidence=>{
      const raw=endpointScopedNmapEvidence(evidence.raw||evidence.output||evidence.evidence,evidence.protocol||row.protocol,evidence.port||row.port),title=(/(?:id=["']http-title["'][^>]*output=["']([^"']+)|http-title\s*[:=]\s*([^\r\n<]+))/i.exec(raw)||[]).slice(1).find(Boolean)||"";
      const confluence=/\b(?:Atlassian\s+)?Confluence\b(?:\s+([0-9]+(?:[.][0-9A-Za-z_-]+)+))?/i.exec(title);
      if(confluence)add({name:"Confluence",version:text(confluence[1]),state:"clue-only",identityConflict:false,ownerKind:"endpoint",endpointId,originId:"",sourceKind:"nmap-http-title",artifactId:text(evidence.sourceArtifactId),revision:number(evidence.sourceRevision),id:text(evidence.id),operationState:text(evidence.operationState||evidence.operationStatus),reviewState:text(evidence.reviewState)});
    });
    const retainedRecords=Array.isArray(technologyRecords)?technologyRecords:values(host?.recon?.technologyImportProjection?.sources).flatMap(source=>values(source.records).filter(record=>text(record.endpointId||source.endpointId)===endpointId).map(record=>({source,record})));
    retainedRecords.forEach(({source,record})=>{
      const recordState=technologyRecordState(record,source),applicationState=recordState==="positive"?"established":recordState;
      values(record.technologies).filter(technology=>["application","cms","framework"].includes(text(technology.category).toLowerCase())).forEach(technology=>add({name:text(technology.name),version:text(technology.version),state:applicationState,identityConflict:Boolean(record.identityConflict),ownerKind:"origin",endpointId,originId:text(record.originId),sourceKind:"whatweb",artifactId:text(record.artifactId||source.artifactId),revision:number(record.revision||source.revision),recordId:text(source.key),targetUrl:text(record.targetUrl),sourceOrigin:text(record.sourceOrigin),operationState:text(record.operationState||source.operationState),reviewState:text(record.reviewState||source.reviewState),error:text(record.error)}));
    });
    const rows=visible.map(item=>(versions.get([item.ownerKind,item.endpointId,item.originId,item.name.toLowerCase()].join("|"))?.size||0)>1?{...item,state:"conflicting",identityConflict:true}:item);
    return {rows,totalCount,visibleCount:rows.length,omittedCount:Math.max(0,totalCount-rows.length),truncated:rows.length<totalCount,acceptedCount,originTotalCount};
  }
  function serviceCoverageProjection(row={}){
    const state=coverageState(row.serviceScanCoverageState||row.coverage);
    return {state,operation:text(row.objective||row.command)||"Service/version coverage",reason:text(row.coverageReason||row.reason),provenance:values(row.evidenceSources)};
  }
  function serviceIdentityProjection(row={}){
    const product=text(row.product),version=text(row.version),hint=text(row.serviceHint||row.serviceRaw),established=row.identified===true;
    const authoritativeProvenance=row.authoritativeIdentityProvenance||values(row.evidenceSources)[0]||{},provenance=boundedServiceProvenance(row.evidenceSources,authoritativeProvenance),corroboratingProvenance=provenance.filter(item=>serviceProvenanceKey(item)!==serviceProvenanceKey(authoritativeProvenance));
    return {state:established?"established":hint?"hint-only":"unknown",name:established?text(row.service)||"Unknown":"Unknown",hint:hint||"Unknown",product:product||"Unknown",version:version||"Unknown",cpe:text(row.cpe)||"Unknown",fingerprint:text(row.serviceFingerprint)||"Unknown",authority:text(row.serviceMethod||row.sourceOwner||row.source)||"Unknown",confidence:number(row.serviceConfidence),authoritativeProvenance,corroboratingProvenance,provenance};
  }
  function acceptedApplicationIdentity(item={}){
    const state=text(item.state).toLowerCase();return ["established","positive","candidate","clue-only"].includes(state)||state==="conflicting"&&item.identityConflict===true;
  }
  function applicationIdentityProjection(host,row,endpointId,technologyRecords){
    const projection=explicitApplicationObservationProjection(host,row,endpointId,technologyRecords),observations=projection.rows,priority={conflicting:4,established:3,candidate:2,"clue-only":1,unknown:0};
    const endpointObservations=observations.filter(item=>item.ownerKind==="endpoint"),originObservations=observations.filter(item=>item.ownerKind==="origin"),selected=endpointObservations.slice().sort((left,right)=>(priority[right.state]-priority[left.state])||left.name.localeCompare(right.name))[0];
    const acceptedObservations=observations.filter(acceptedApplicationIdentity);
    return {state:selected?.state||"unknown",name:selected?.name||"Unknown",version:selected?.version||"Unknown",observations,endpointObservations,originObservations,acceptedObservations,acceptedOriginApplications:originObservations.filter(acceptedApplicationIdentity),establishedOriginApplications:originObservations.filter(item=>item.state==="established"),hasAcceptedIdentity:projection.acceptedCount>0,hasOriginSpecificIdentity:projection.originTotalCount>0,totalObservationCount:projection.totalCount,visibleObservationCount:projection.visibleCount,omittedObservationCount:projection.omittedCount,displayTruncated:projection.truncated};
  }
  function sourceState(value){
    const state=text(value).toLowerCase();
    if(state==="conflict"||state==="failed")return "conflict";
    if(state==="partial"||state==="incomplete")return "partial";
    if(state==="deferred")return "deferred";
    if(state==="negative")return "negative";
    if(state==="complete"||state==="completed")return "complete";
    return "";
  }
  function importRows(host,options={}){
    const scan=values(options.logicalScanImports).length?values(options.logicalScanImports):values(host.scanArtifacts);
    const web=values(options.logicalWebImports).length?values(options.logicalWebImports):values(host?.recon?.webImports);
    const technology=values(options.logicalTechnologyImports).length?values(options.logicalTechnologyImports):values(host?.recon?.technologyImportProjection?.sources);
    return [...scan.map((row,index)=>({
      id:text(row.id)||`scan-import-${index+1}`,
      kind:"scan",
      label:text(row.label||row.originalFilename||row.filename||row.logicalPath||row.source)||"Imported scan",
      outcome:text(row.outcome||row.lastImportStatus||row.operationStatus||row.status)||"retained",
      resultCount:number(row.resultCount??row.services??row.endpointCount),
      observedAt:text(row.lastSeenAt||row.importedAt||row.updatedAt||row.observedAt),
      artifactId:text(row.artifactId||row.id),
      reviewed:row.reviewed===true||Boolean(text(row.reviewedAt))||text(row.reviewState).toLowerCase()==="reviewed"
    })),...web.map((row,index)=>({
      id:text(row.id)||`web-import-${index+1}`,
      kind:"web",
      label:text(row.label||row.filename||row.tool)||"Web discovery import",
      outcome:text(row.outcome||row.lastImportStatus||row.operationState||row.status)||"retained",
      resultCount:number(row.resultCount),
      observedAt:text(row.lastSeenAt||row.completedAt||row.observedAt||row.updatedAt),
      artifactId:text(row.artifactId),
      originIds:unique([row.originId,...values(row.originIds)]),
      reviewed:row.reviewed===true||Boolean(text(row.reviewedAt))||text(row.reviewState).toLowerCase()==="reviewed"
    })),...technology.map((row,index)=>({
      id:text(row.id||row.key)||`technology-import-${index+1}`,kind:"technology",label:text(row.label||row.filename||row.tool)||"Technology import",outcome:text(row.reviewState)==="stale"?"stale":text(row.outcome||row.operationState||row.status)||"retained",resultCount:number(row.resultCount),observedAt:text(row.observedAt||row.updatedAt),artifactId:text(row.artifactId),originIds:unique(row.originIds),reviewed:text(row.reviewState).toLowerCase()==="reviewed"
    }))].sort((left,right)=>right.observedAt.localeCompare(left.observedAt)||left.id.localeCompare(right.id));
  }
  function evidenceArtifactRevisionRows(artifact={}){
    const rows=values(artifact.revisions).filter(row=>row&&typeof row==="object").map((row,index)=>({...row,revision:Math.max(1,number(row.revision)||index+1)})).sort((left,right)=>left.revision-right.revision);
    if(!rows.length)rows.push({...artifact,revision:Math.max(1,number(artifact.currentRevision)||1)});
    return rows;
  }
  function evidenceArtifactRevision(artifact={},revision=0){
    const rows=evidenceArtifactRevisionRows(artifact),wanted=Math.max(1,number(revision)||number(artifact.currentRevision)||rows.at(-1)?.revision||1);
    return rows.find(row=>row.revision===wanted)||null;
  }
  function evidenceRouteId(kind,logicalResultId){
    const source=`${text(kind)||"evidence"}|${text(logicalResultId)}`;
    let hash=2166136261;
    for(let index=0;index<source.length;index++){hash^=source.charCodeAt(index);hash=Math.imul(hash,16777619);}
    const label=idPart(logicalResultId,kind||"result").slice(0,72);
    return `evidence:${idPart(kind,"result")}:${label}:${(hash>>>0).toString(36)}`;
  }
  function evidenceReviewCollection(input,limit,keyFor){
    const byKey=new Map();
    values(input).filter(row=>row&&typeof row==="object").forEach((row,index)=>{
      const key=text(keyFor?.(row,index))||`row-${index+1}`;
      if(!byKey.has(key))byKey.set(key,row);
    });
    const all=[...byKey.entries()].sort((left,right)=>left[0].localeCompare(right[0])).map(entry=>entry[1]),maximum=Math.max(1,number(limit)||100),rows=all.slice(0,maximum);
    return {rows,totalCount:all.length,visibleCount:rows.length,omittedCount:Math.max(0,all.length-rows.length),truncated:rows.length<all.length};
  }
  function emptyEvidenceReviewCollections(){
    return Object.fromEntries(["endpoints","coverage","origins","observations","leads","webRecords","technologyRecords","operations"].map(name=>[name,evidenceReviewCollection([],EVIDENCE_REVIEW_LIMITS[name])]));
  }
  function evidenceOperationState(source={},resultCount=0){
    const state=text(source.operationState||source.operationStatus||source.status).toLowerCase();
    if(["complete","completed"].includes(state))return number(resultCount)>0?"positive":"zero";
    if(["failed","partial","incomplete","conflict","conflicting","stale","deferred"].includes(state))return state==="incomplete"?"partial":state==="conflict"?"conflicting":state;
    return state||"unknown";
  }
  function evidenceRecordState(record={},source={},resultCount=0,{positiveWhenPresent=false}={}){
    const review=text(record.reviewState||source.reviewState).toLowerCase(),operation=text(record.operationState||record.operationStatus||source.operationState||source.operationStatus).toLowerCase();
    if(review==="stale"||operation==="stale")return "stale";
    if(review==="conflicting"||["conflict","conflicting"].includes(operation))return "conflicting";
    if(operation==="failed")return "failed";
    if(["partial","incomplete"].includes(operation))return "partial";
    if(review==="deferred"||operation==="deferred")return "deferred";
    if(["complete","completed"].includes(operation))return number(resultCount)>0||positiveWhenPresent?"positive":"zero";
    return operation||review||"unknown";
  }
  function evidenceHttpOrigin(value){try{return new URL(text(value)).origin;}catch{return text(value);}}
  function evidenceSourceOwnership(host,source,artifactId,revision,options={}){
    const sourcePath=text(source?.sourcePath||source?.filename),sourceFilename=text(source?.filename)||sourcePath.split(/[\/]/).pop()||"";
    return {engagementId:text(options.engagementId),hostId:text(host.id),canonicalOwner:`${text(options.engagementId)||"engagement"}/${text(host.id)||"host"}`,targetAddress:text(source?.targetAddress||host.ip),artifactId,revision,sourceFilename,sourcePath,sourceTool:text(source?.source||source?.tool),parserType:text(source?.parserType),representation:text(source?.representation)};
  }
  function evidenceReviewCatalog(host={},options={}){
    const artifacts=values(host.scanArtifacts),artifactById=new Map(artifacts.map(row=>[text(row?.id),row])),scanSources=values(host.scanImportProjection?.sources);
    const logicalScanImports=values(options.logicalScanImports).filter(row=>row&&row.sourceOwned===true);
    const nmapResults=logicalScanImports.map((logical,index)=>{
      const sourceKeys=new Set(unique(logical.sourceKeys)),declaredArtifacts=unique(logical.artifactIds),ownedSources=scanSources.filter(source=>sourceKeys.has(text(source.key))||declaredArtifacts.includes(text(source.sourceArtifactId||source.artifactId)));
      const artifactIds=unique([...declaredArtifacts,...ownedSources.map(source=>text(source.sourceArtifactId||source.artifactId))]);
      const logicalResultId=text(logical.id)||`nmap-result-${index+1}`;
      return {logicalResultId,routeId:evidenceRouteId("nmap",logicalResultId),kind:"nmap",label:text(logical.label||logical.command||logical.runIdentity)||"Nmap result",engagementId:text(options.engagementId),hostId:text(host.id),targetAddress:text(logical.targetAddress),endpointIds:unique(ownedSources.flatMap(source=>values(source.services).map(row=>row.endpointId||row.id))),originIds:unique(ownedSources.flatMap(source=>values(source.origins).map(row=>row.originId||row.id))),artifactIds,sourceKeys:unique([...logical.sourceKeys,...ownedSources.map(source=>source.key)]),resultCount:number(logical.services),observedAt:text(logical.updatedAt||logical.observedAt),operationState:text(logical.operationStatus||logical.status)||"retained",sourceSeparable:true};
    });
    const webResults=values(host.recon?.webImportProjection?.sources).map((source,index)=>{const logicalResultId=text(source.key||source.id)||`web-result-${index+1}`;return {logicalResultId,routeId:evidenceRouteId("web",logicalResultId),kind:"web",label:text(source.label||source.filename||source.tool)||"Web discovery result",engagementId:text(options.engagementId),hostId:text(host.id),targetAddress:text(source.targetAddress||host.ip),endpointIds:unique([source.endpointId,...values(source.records).map(row=>row.endpointId)]),originIds:unique([...values(source.originIds),...values(source.records).map(row=>row.originId)]),artifactIds:unique([source.artifactId]),sourceKeys:unique([source.key]),resultCount:number(source.resultCount??values(source.records).length),observedAt:text(source.observedAt||source.updatedAt),operationState:text(source.operationState||source.status)||"retained",sourceSeparable:true};});
    const technologyResults=values(host.recon?.technologyImportProjection?.sources).map((source,index)=>{const logicalResultId=text(source.key||source.id)||`technology-result-${index+1}`;return {logicalResultId,routeId:evidenceRouteId("technology",logicalResultId),kind:"technology",label:text(source.label||source.filename||source.tool)||"Technology result",engagementId:text(options.engagementId),hostId:text(host.id),targetAddress:text(source.targetAddress||host.ip),endpointIds:unique([source.endpointId,...values(source.records).map(row=>row.endpointId)]),originIds:unique([...values(source.originIds),...values(source.records).map(row=>row.originId)]),artifactIds:unique([source.artifactId]),sourceKeys:unique([source.key]),resultCount:number(source.resultCount),observedAt:text(source.observedAt||source.updatedAt),operationState:text(source.operationState||source.status)||"retained",sourceSeparable:true};});
    const results=[...nmapResults,...webResults,...technologyResults].filter(row=>row.logicalResultId&&row.artifactIds.length).sort((left,right)=>right.observedAt.localeCompare(left.observedAt)||left.logicalResultId.localeCompare(right.logicalResultId)).map(row=>({...row,artifacts:row.artifactIds.map(artifactId=>{
      const artifact=artifactById.get(artifactId);return {artifactId,available:Boolean(artifact),currentRevision:number(artifact?.currentRevision)||evidenceArtifactRevisionRows(artifact||{}).at(-1)?.revision||1};
    })}));
    return {results,visibleResults:results.slice(0,EVIDENCE_REVIEW_LIMITS.results),totalCount:results.length,visibleCount:Math.min(results.length,EVIDENCE_REVIEW_LIMITS.results),omittedCount:Math.max(0,results.length-EVIDENCE_REVIEW_LIMITS.results),truncated:results.length>EVIDENCE_REVIEW_LIMITS.results};
  }
  function nmapEvidenceCollections(host,source,artifactId,revision,options={}){
    const ownership=evidenceSourceOwnership(host,source,artifactId,revision,options);
    const exactOwner=row=>text(row?.sourceArtifactId||row?.artifactId)===artifactId&&number(row?.sourceRevision||row?.revision)===revision;
    const endpoints=values(source.services).map((row,index)=>({...row,id:text(row.id||row.endpointId)||`endpoint-${index+1}`,endpointId:text(row.endpointId||row.id)||`endpoint-${index+1}`,targetAddress:text(row.targetAddress||source.targetAddress),protocol:text(row.protocol)||"tcp",port:number(row.port),state:text(row.state)||"unknown",service:text(row.service),product:text(row.product),version:text(row.version),cpe:text(row.cpe),fingerprint:text(row.serviceFingerprint||row.fingerprint),...ownership}));
    const coverage=Object.entries(source.objectives||{}).map(([objectiveId,row])=>({objectiveId,state:scanState(row,objectiveId),confirmed:row?.confirmed===true,coverage:text(row?.coverage),scope:text(row?.scannedPortExpression),scannedPortCount:number(row?.scannedPortCount),reason:text(row?.reason),...ownership}));
    const origins=values(source.origins).map((row,index)=>({...row,id:text(row.id||row.originId)||`origin-${index+1}`,originId:text(row.originId||row.id)||`origin-${index+1}`,url:text(row.url||row.value),endpointId:text(row.endpointId||row.serviceEndpointId),...ownership}));
    const observationRows=[...values(source.endpointEvidence),...values(host.endpointEvidence).filter(exactOwner)].filter(row=>!text(row.sourceArtifactId||row.artifactId)||exactOwner(row)).map((row,index)=>({...row,raw:endpointScopedNmapEvidence(row.raw||row.output||row.evidence,row.protocol,row.port),id:text(row.id)||`observation-${index+1}`,endpointId:text(row.endpointId),...ownership}));
    const leadRows=[...values(source.vulnerabilityLeads),...values(host.vulnerabilityLeads).filter(exactOwner)].filter(row=>!text(row.sourceArtifactId||row.artifactId)||exactOwner(row)).map((row,index)=>({...row,id:text(row.id)||`lead-${index+1}`,endpointId:text(row.endpointId),factKind:"Lead hypothesis",...ownership}));
    const operations=[{id:text(source.key)||`${artifactId}:${revision}`,kind:"nmap",state:evidenceOperationState(source,endpoints.length),resultCount:endpoints.length,command:text(source.command),...ownership}];
    return {
      endpoints:evidenceReviewCollection(endpoints,EVIDENCE_REVIEW_LIMITS.endpoints,row=>[number(row.port).toString().padStart(6,"0"),row.protocol,row.endpointId].join("|")),
      coverage:evidenceReviewCollection(coverage,EVIDENCE_REVIEW_LIMITS.coverage,row=>row.objectiveId),
      origins:evidenceReviewCollection(origins,EVIDENCE_REVIEW_LIMITS.origins,row=>row.originId),
      observations:evidenceReviewCollection(observationRows,EVIDENCE_REVIEW_LIMITS.observations,row=>row.id),
      leads:evidenceReviewCollection(leadRows,EVIDENCE_REVIEW_LIMITS.leads,row=>row.id),
      webRecords:evidenceReviewCollection([],EVIDENCE_REVIEW_LIMITS.webRecords),technologyRecords:evidenceReviewCollection([],EVIDENCE_REVIEW_LIMITS.technologyRecords),
      operations:evidenceReviewCollection(operations,EVIDENCE_REVIEW_LIMITS.operations,row=>row.id)
    };
  }
  function webEvidenceCollections(host,source,artifactId,revision,options={}){
    const ownership=evidenceSourceOwnership(host,source,artifactId,revision,options),sourceOperationState=evidenceOperationState(source,source.resultCount??values(source.records).length),knownOrigins=new Map(values(host.recon?.webTargets).filter(row=>row?.recordRole==="web-origin").map(row=>[text(row.id||row.originId),row]));
    const records=values(source.records).map((row,index)=>{const originId=text(row.originId),mapped=knownOrigins.get(originId)||{},recordResultCount=row.resultCount===undefined?1:number(row.resultCount),state=evidenceRecordState(row,source,recordResultCount,{positiveWhenPresent:true});return {...row,id:text(row.id||row.key)||`web-record-${index+1}`,url:text(row.url||row.targetUrl),targetUrl:text(row.targetUrl||row.url),sourceTarget:text(row.targetUrl||row.url||source.targetAddress),origin:text(row.origin||row.sourceOrigin),normalizedOrigin:evidenceHttpOrigin(row.sourceOrigin||row.origin||row.targetUrl||row.url),mappedOrigin:text(mapped.url||mapped.value),originId,endpointId:text(row.endpointId||source.endpointId),path:text(row.path),method:text(row.method)||"GET",status:number(row.status),redirect:text(row.redirect),contentType:text(row.contentType),length:number(row.length),host:text(row.host),domain:text(row.domain||row.host),state,operationState:text(row.operationState||source.operationState),reviewState:text(row.reviewState||source.reviewState),resultCount:recordResultCount,error:text(row.error||source.error),...ownership};});
    const origins=unique([...values(source.originIds),...records.map(row=>row.originId)]).map(originId=>{const row=knownOrigins.get(originId)||{};return {id:originId,originId,url:text(row.url||row.value)||text(records.find(record=>record.originId===originId)?.origin),endpointId:text(row.endpointId||records.find(record=>record.originId===originId)?.endpointId),artifactId,revision};});
    const operations=[{id:`${text(source.key)||`${artifactId}:${revision}`}:source`,scope:"source",kind:"web",tool:text(source.tool),objectiveId:text(source.objectiveId),state:sourceOperationState,resultCount:number(source.resultCount??records.length),endpointId:text(source.endpointId),originIds:unique(source.originIds),operationState:text(source.operationState),reviewState:text(source.reviewState),error:text(source.error),...ownership},...records.map(row=>({id:`${text(source.key)||artifactId}:record:${row.id}`,scope:"record",kind:"web",tool:text(source.tool),objectiveId:text(source.objectiveId),recordId:row.id,targetUrl:row.targetUrl||row.url,normalizedOrigin:row.normalizedOrigin,mappedOrigin:row.mappedOrigin,originId:row.originId,endpointId:row.endpointId,state:row.state,resultCount:row.resultCount,operationState:row.operationState,reviewState:row.reviewState,error:row.error,...ownership}))];
    return {...emptyEvidenceReviewCollections(),origins:evidenceReviewCollection(origins,EVIDENCE_REVIEW_LIMITS.origins,row=>row.originId),webRecords:evidenceReviewCollection(records,EVIDENCE_REVIEW_LIMITS.webRecords,row=>[row.originId,row.url,row.method,row.id].join("|")),operations:evidenceReviewCollection(operations,EVIDENCE_REVIEW_LIMITS.operations,row=>row.id)};
  }
  function technologyEvidenceCollections(host,source,artifactId,revision,options={}){
    const records=[],operations=[],ownership=evidenceSourceOwnership(host,source,artifactId,revision,options),knownOrigins=new Map(values(host.recon?.webTargets).filter(row=>row?.recordRole==="web-origin").map(row=>[text(row.id||row.originId),row]));
    values(source.records).forEach((record,recordIndex)=>{
      const state=typeof reconImportApi.technologyRecordState==="function"?reconImportApi.technologyRecordState(record,source):technologyRecordState(record,source),recordId=text(record.key||record.id)||`record-${recordIndex+1}`,originId=text(record.originId),normalizedOrigin=evidenceHttpOrigin(record.sourceOrigin||record.origin||record.targetUrl),mappedOrigin=text(knownOrigins.get(originId)?.url||knownOrigins.get(originId)?.value),endpointId=text(record.endpointId||source.endpointId);
      operations.push({id:`${text(source.key)||artifactId}:record:${recordId}`,scope:"record",kind:"technology",tool:text(source.tool)||"WhatWeb",objectiveId:text(source.objectiveId),recordId,targetUrl:text(record.targetUrl),normalizedOrigin,mappedOrigin,originId,endpointId,state,resultCount:number(record.resultCount??values(record.technologies).length),operationState:text(record.operationState),reviewState:text(record.reviewState),error:text(record.error),...ownership});
      values(record.technologies).forEach((technology,index)=>{const category=text(technology.category)||"technology",application=["application","cms","framework"].includes(category.toLowerCase());records.push({id:`${recordId}:${index+1}`,recordId,targetUrl:text(record.targetUrl),origin:text(record.origin||record.sourceOrigin),sourceOrigin:text(record.sourceOrigin||record.origin),normalizedOrigin,mappedOrigin,originId,endpointId,name:text(technology.name),category,version:text(technology.version),state,identityState:state==="positive"?(application?"established":"clue-only"):state,identityConflict:record.identityConflict===true,cpe:text(technology.cpe),error:text(record.error||source.error),...ownership});});
    });
    const summary=typeof reconImportApi.technologyOutcomeSummary==="function"?reconImportApi.technologyOutcomeSummary(values(source.records),source):null;
    operations.unshift({id:`${text(source.key)||`${artifactId}:${revision}`}:source`,scope:"source",kind:"technology",tool:text(source.tool)||"WhatWeb",objectiveId:text(source.objectiveId),state:text(summary?.state)||evidenceOperationState(source,source.resultCount),resultCount:number(summary?.resultCount??source.resultCount),recordCount:number(summary?.recordCount??values(source.records).length),positiveObservationCount:number(summary?.positiveObservationCount),positiveRecordCount:number(summary?.positiveRecordCount),completedZeroCount:number(summary?.completedZeroCount),openCount:number(summary?.openCount),mixed:summary?.mixed===true,endpointId:text(source.endpointId),originIds:unique(source.originIds),operationState:text(summary?.operationState||source.operationState),reviewState:text(summary?.reviewState||source.reviewState),error:text(source.error)||text(values(source.records).find(row=>row?.error)?.error),...ownership});
    return {...emptyEvidenceReviewCollections(),technologyRecords:evidenceReviewCollection(records,EVIDENCE_REVIEW_LIMITS.technologyRecords,row=>[row.originId,row.targetUrl,row.name.toLowerCase(),row.version,row.recordId].join("|")),operations:evidenceReviewCollection(operations,EVIDENCE_REVIEW_LIMITS.operations,row=>row.id)};
  }
  function evidenceReview(host={},options={}){
    const catalog=evidenceReviewCatalog(host,options),selection=options.selection||{};
    if(!text(selection.logicalResultId)&&!text(selection.artifactId))return deepFreeze({...catalog,selected:null,error:""});
    const logicalResultId=text(selection.logicalResultId),artifactId=text(selection.artifactId),result=catalog.results.find(row=>row.logicalResultId===logicalResultId||row.routeId===logicalResultId);
    if(!result)return deepFreeze({...catalog,selected:null,error:"The selected Evidence result is missing or stale."});
    if(!artifactId||!result.artifactIds.includes(artifactId))return deepFreeze({...catalog,selected:null,error:"The selected artifact does not belong to the exact Evidence result."});
    const artifact=values(host.scanArtifacts).find(row=>text(row?.id)===artifactId);
    if(!artifact)return deepFreeze({...catalog,selected:null,error:"The selected Evidence artifact is missing or stale."});
    const revision=evidenceArtifactRevision(artifact,selection.revision),selectedRevision=Math.max(1,number(selection.revision)||number(artifact.currentRevision)||1);
    if(!revision)return deepFreeze({...catalog,selected:null,error:`Evidence revision ${selectedRevision} is missing for the selected artifact.`});
    const currentRevision=Math.max(1,number(artifact.currentRevision)||evidenceArtifactRevisionRows(artifact).at(-1)?.revision||1);
    let source=null;
    if(result.kind==="nmap")source=values(host.scanImportProjection?.sources).find(row=>text(row.sourceArtifactId||row.artifactId)===artifactId&&result.sourceKeys.includes(text(row.key)));
    else if(result.kind==="web")source=values(host.recon?.webImportProjection?.sources).find(row=>text(row.artifactId)===artifactId&&result.sourceKeys.includes(text(row.key||row.id)));
    else source=values(host.recon?.technologyImportProjection?.sources).find(row=>text(row.artifactId)===artifactId&&result.sourceKeys.includes(text(row.key||row.id)));
    const sourceRevision=number(source?.sourceRevision||source?.revision),isCurrent=selectedRevision===currentRevision,parsedAvailable=Boolean(source)&&isCurrent&&sourceRevision===selectedRevision;
    let collections=emptyEvidenceReviewCollections();
    if(parsedAvailable&&result.kind==="nmap")collections=nmapEvidenceCollections(host,source,artifactId,selectedRevision,options);
    if(parsedAvailable&&result.kind==="web")collections=webEvidenceCollections(host,source,artifactId,selectedRevision,options);
    if(parsedAvailable&&result.kind==="technology")collections=technologyEvidenceCollections(host,source,artifactId,selectedRevision,options);
    const reason=parsedAvailable?"":!isCurrent?"Historical parsed projection is not retained; Raw, History, and exact Download remain available for this revision.":!source?"The current parsed source projection is missing or stale.":"The retained parsed source revision does not match the artifact current revision.";
    const download={artifactId,revision:selectedRevision,storedFilename:text(revision.storedFilename),originalFilename:text(revision.originalFilename||artifact.originalFilename),sha256:text(revision.sha256),size:number(revision.size),importedAt:text(revision.importedAt)};
    const revisionHistory=evidenceReviewCollection(evidenceArtifactRevisionRows(artifact),EVIDENCE_REVIEW_LIMITS.revisions,row=>String(row.revision).padStart(8,"0")),importHistory=evidenceReviewCollection(values(artifact.importHistory),EVIDENCE_REVIEW_LIMITS.importHistory,(row,index)=>[text(row.observedAt),number(row.revision).toString().padStart(8,"0"),text(row.sha256),index].join("|"));
    const selectedSource=parsedAvailable?source:null,historicalSourceFilename=text(revision.originalFilename||artifact.originalFilename),historicalSourcePath=historicalSourceFilename||text(artifact.logicalPath);
    const selected={logicalResultId:result.logicalResultId,routeId:result.routeId,kind:result.kind,label:result.label,engagementId:text(options.engagementId),hostId:text(host.id),canonicalOwner:`${text(options.engagementId)||"engagement"}/${text(host.id)||"host"}`,targetAddress:text(selectedSource?.targetAddress||result.targetAddress||host.ip),endpointIds:[...values(result.endpointIds)],originIds:[...values(result.originIds)],artifactId,artifactIds:[...result.artifactIds],sourceSeparable:result.sourceSeparable===true,selectedRevision,currentRevision,sourceRevision:parsedAvailable?sourceRevision:selectedRevision,sourcePath:parsedAvailable?text(source?.sourcePath||source?.filename||artifact.logicalPath||revision.originalFilename):historicalSourcePath,sourceFilename:parsedAvailable?text(source?.filename||revision.originalFilename||artifact.originalFilename):historicalSourceFilename,sourceTool:parsedAvailable?text(source?.source||source?.tool||artifact.source):text(artifact.source),parserType:parsedAvailable?text(source?.parserType):"",representation:parsedAvailable?text(source?.representation):"",command:parsedAvailable?text(source?.command):"",operationState:parsedAvailable?text(source?.operationStatus||source?.operationState||result.operationState):"historical-retained",reviewState:parsedAvailable?text(source?.reviewState):"",download,downloadAvailable:Boolean(download.storedFilename),history:{revisions:revisionHistory.rows,revisionTotalCount:revisionHistory.totalCount,revisionVisibleCount:revisionHistory.visibleCount,revisionOmittedCount:revisionHistory.omittedCount,revisionsTruncated:revisionHistory.truncated,imports:importHistory.rows,importTotalCount:importHistory.totalCount,importVisibleCount:importHistory.visibleCount,importOmittedCount:importHistory.omittedCount,importsTruncated:importHistory.truncated},structured:{available:parsedAvailable,reason,collections}};
    return deepFreeze({...catalog,selected,error:""});
  }
  function canonicalFacts(host,options={}){
    const facts=[],scan=host.scanEvidence||{},services=canonicalServices(host),origins=exactOrigins(host);
    facts.push(scanFact(host,"port",scan.port||{}),scanFact(host,"tcp",scan.tcp||{}),scanFact(host,"udp",scan.udp||{}));
    services.forEach((row,index)=>{
      const endpointId=endpointIdentity(row,index),label=endpointLabel(row);
      if(row.identified!==true){
        facts.push(fact({
          id:`endpoint:${idPart(endpointId)}:identity`,
          label:`${label} service identity`,
          reason:"The endpoint is retained, but current evidence does not confirm its service identity.",
          state:"partial",dimension:"services",
          severity:"medium",
          scope:{kind:"endpoint",id:endpointId,label},
          section:"services",owner:{endpointId,selector:`[data-endpoint-id="${endpointId}"]`}
        }));
      }
      if(isWebEndpoint(row)&&!origins.some(origin=>text(origin.endpointId||origin.serviceEndpointId)===endpointId)){
        facts.push(fact({
          id:`endpoint:${idPart(endpointId)}:web-origin`,
          label:`Exact web origin for ${label}`,
          reason:"A web-capable endpoint is retained, but no exact scheme, address, and port origin is owned yet.",
          state:"partial",dimension:"web-origins",
          severity:"medium",
          scope:{kind:"endpoint",id:endpointId,label},
          section:"web-origins",owner:{endpointId,selector:`[data-endpoint-id="${endpointId}"]`}
        }));
      }
    });
    values(host?.recon?.webTargets).forEach((row,index)=>{
      if(!row?.unresolved)return;
      const recordId=originIdentity(row,index),originId=text(row.originId);
      facts.push(fact({
        id:`web-target:${idPart(recordId)}:origin`,
        label:"Unresolved web-origin ownership",
        reason:text(row.reason)||`The retained ${text(row.path||row.url||row.value)||"web result"} is not mapped to one exact HTTP(S) origin.`,
        state:"conflict",dimension:"web-origins",blocking:true,
        sourceFacts:[row.sourcePath,row.filename,row.url||row.value||row.path],
        scope:{kind:originId?"origin":"web-target",id:originId||recordId,label:text(row.url||row.value||row.path)||"Web result"},
        section:"web-origins",owner:{originId,recordId,selector:`[data-web-target-id="${recordId}"]`}
      }));
    });
    values(host.endpointEvidence).filter(row=>row?.targetConflict===true).forEach((row,index)=>{
      const recordId=text(row.id)||`endpoint-conflict-${index+1}`;
      facts.push(fact({
        id:`endpoint-evidence:${idPart(recordId)}:conflict`,
        label:"Endpoint evidence ownership conflict",
        reason:text(row.targetReason||row.reason||row.sourcePath)||"Exact target ownership could not be resolved.",
        state:"conflict",dimension:"conflicts",blocking:true,
        sourceFacts:[row.sourcePath,row.observedTargetAddress,row.targetAddress,row.error],
        scope:{kind:"host",id:text(host.id),label:text(host.hostname)||text(host.ip)||"Selected host"},
        section:"coverage",owner:{recordId,selector:"#reconConflictReview"}
      }));
    });
    values(host?.scanImportProjection?.sources).forEach((row,index)=>{
      const state=sourceState(row.operationStatus);if(!state||state==="complete")return;
      const recordId=text(row.id||row.sourceArtifactId||row.artifactId)||`scan-source-${index+1}`;
      facts.push(fact({
        id:`scan-source:${idPart(recordId)}:${state}`,
        label:`${state==="conflict"?"Conflicting":state==="partial"?"Partial":state==="deferred"?"Deferred":"Negative"} retained scan result`,
        reason:text(row.reason)||`${text(row.sourcePath||row.source)||"Imported scan"} is retained with ${state} operation evidence.`,
        state,dimension:"imports",blocking:false,
        sourceFacts:[row.sourcePath,row.command,row.error],
        scope:{kind:"artifact",id:recordId,label:text(row.sourcePath||row.source)||"Imported scan"},
        section:"evidence",owner:{artifactId:text(row.sourceArtifactId||row.artifactId),recordId,selector:"#scanArtifactList"}
      }));
    });
    if(text(host?.osResolution?.status).toLowerCase()==="conflict"){
      facts.push(fact({
        id:"host:os-resolution:conflict",
        label:"Operating-system evidence conflict",
        reason:"Strong sourced operating-system observations disagree; OS-specific routing remains paused.",
        state:"conflict",dimension:"identity",blocking:true,
        sourceFacts:values(host?.osResolution?.sourceLabels),
        scope:{kind:"host",id:text(host.id),label:text(host.hostname)||text(host.ip)||"Selected host"},
        section:"overview",owner:{workspace:"profile",selector:"#hostOsResolution"}
      }));
    }
    values(options.technologyView?.byOrigin).forEach(row=>{
      const state=({positive:"complete",zero:"negative",conflicting:"conflict",stale:"partial",failed:"partial",partial:"partial",deferred:"deferred",unknown:"not-run"})[row.state]||"not-run",observationCount=number(row.totalObservationCount??values(row.observations).length);
      const reason=row.hasOpenWork&&row.positiveCount
        ?`${row.positiveCount} positive Technology observation${row.positiveCount===1?" is":"s are"} retained with ${row.openCount} open operation${row.openCount===1?"":"s"} for this exact origin.`
        :state==="complete"
          ?`${observationCount} retained Technology observation${observationCount===1?" is":"s are"} owned by this exact origin${row.zeroResultCount?` alongside ${row.zeroResultCount} completed zero-result operation${row.zeroResultCount===1?"":"s"}`:""}.`
          :state==="negative"
            ?`${row.zeroResultCount||1} retained Technology operation${row.zeroResultCount===1?"":"s"} completed for this exact origin with zero positive observations.`
            :state==="conflict"
              ?"Retained Technology evidence conflicts for this exact origin."
              :state==="deferred"
                ?"Technology work is explicitly deferred for this exact origin."
                :state==="partial"
                  ?`Technology work remains ${row.state} for this exact origin.`
                  :"No retained Technology operation or positive observation is owned by this exact origin.";
      facts.push(fact({id:`origin:${idPart(row.originId)}:technology-fingerprinting`,label:"Technology fingerprinting",reason,state,dimension:"technology",blocking:row.state==="conflicting",sourceFacts:row.sourceOutcomes.map(source=>source.artifactId||source.sourceKey),scope:{kind:"origin",id:row.originId,label:row.url||"Exact origin"},section:"web-origins",owner:{originId:row.originId,endpointId:row.endpointId,selector:`[data-origin-id="${row.originId}"]`}}));
    });
    values(options.explicitCoverage).forEach((row,index)=>{
      const recordId=text(row.id)||`explicit-${index+1}`,originId=text(row.originId);
      facts.push(fact({
        id:`explicit:${idPart(recordId)}`,
        label:text(row.label)||"Recorded Recon coverage",
        reason:text(row.reason)||"The operator recorded this exact Recon state.",
        state:normalizeState(row.state,"partial"),
        severity:text(row.severity),
        blocking:row.blocking===true,
        sourceFacts:values(row.sourceFacts),
        dimension:text(row.dimension)||"operator-state",
        scope:{kind:originId?"origin":"host",id:originId||text(host.id),label:text(row.scopeLabel)||text(row.originUrl)||text(host.hostname)||text(host.ip)||"Selected host"},
        section:text(row.section)||"coverage",
        owner:{workspace:text(row.workspace)||"recon",originId,endpointId:text(row.endpointId),recordId,selector:text(row.selector)}
      }));
    });
    return facts.filter(row=>row.id&&row.label&&row.reason).filter((row,index,all)=>all.findIndex(other=>other.id===row.id)===index).sort((left,right)=>(STATE_ORDER[left.state]-STATE_ORDER[right.state])||left.label.localeCompare(right.label)||left.id.localeCompare(right.id));
  }
  function countsFor(gaps){
    const counts=Object.fromEntries(STATES.map(state=>[state,0]));
    values(gaps).forEach(row=>{counts[normalizeState(row.state)]++;});
    counts.open=values(gaps).filter(row=>OPEN_STATES.has(row.state)).length;
    counts.resolved=counts.complete+counts.negative;
    counts.total=values(gaps).length;
    return counts;
  }
  function coverageStateFromRatio(value,total,{bounded=false}={}){
    if(total<=0)return "not-run";
    if(value>=total)return bounded?"bounded":"complete";
    return value>0?"partial":"not-run";
  }
  function dimension(id,label,value,state,summary,details={}){
    return {
      id,
      label,
      value:Math.max(0,Math.min(100,number(value))),
      state:normalizeState(state),
      summary:text(summary),
      numerator:number(details.numerator),
      denominator:number(details.denominator),
      bounded:details.bounded===true
    };
  }
  function coverageDimensions(host,{services,origins,targets,imports,gaps,technologies}){
    const scan=host.scanEvidence||{},portState=scanState(scan.port||{},"port"),udpState=scanState(scan.udp||{},"udp");
    const scannedTcp=number(scan.port?.scannedPortCount);
    const tcpDiscoveryValue=portState==="complete"?100:scannedTcp?percent(scannedTcp,65535):0;
    const tcpServices=services.filter(row=>text(row.protocol||"tcp").toLowerCase()==="tcp");
    const identifiedTcp=tcpServices.filter(row=>row.identified===true).length;
    const tcpIdentityValue=percent(identifiedTcp,tcpServices.length);
    const webServices=services.filter(isWebEndpoint);
    const originEndpoints=new Set(origins.map(row=>text(row.endpointId||row.serviceEndpointId)).filter(Boolean));
    const mappedWebEndpoints=webServices.filter((row,index)=>originEndpoints.has(endpointIdentity(row,index))).length;
    const webDenominator=webServices.length||origins.length;
    const webNumerator=webServices.length?mappedWebEndpoints:origins.length;
    const fingerprinted=values(technologies?.byOrigin).filter(row=>["positive","zero"].includes(row.state)).length;
    const reviewed=imports.filter(row=>row.reviewed===true).length;
    const udpCount=number(scan.udp?.scannedPortCount);
    const udpTopHundred=udpCount===100||/top[\s-]*100/i.test(text(scan.udp?.scannedPortExpression));
    const udpScope=udpTopHundred?"Top-100 scope":udpCount?`${udpCount}-port scope`:"Scoped discovery";
    const unresolvedTcp=Math.max(0,tcpServices.length-identifiedTcp);
    const unmapped=Math.max(0,webDenominator-webNumerator);
    const withoutTechnology=Math.max(0,origins.length-fingerprinted);
    const unreviewed=Math.max(0,imports.length-reviewed);
    const dimensions=[
      dimension(
        "tcp-discovery","TCP discovery",tcpDiscoveryValue,portState,
        portState==="complete"?"Full range complete":portState==="not-run"?"Full-range discovery not recorded":`${scannedTcp||0} of 65,535 ports evidenced`,
        {numerator:portState==="complete"?65535:scannedTcp,denominator:65535}
      ),
      dimension(
        "tcp-service-identity","TCP service identity",tcpIdentityValue,
        coverageStateFromRatio(identifiedTcp,tcpServices.length),
        tcpServices.length?`${unresolvedTcp} unresolved TCP endpoint${unresolvedTcp===1?"":"s"}`:"No discovered TCP endpoints",
        {numerator:identifiedTcp,denominator:tcpServices.length}
      ),
      dimension(
        "udp-scoped-discovery","UDP scoped discovery",scan.udp?.confirmed===true?100:0,udpState,
        scan.udp?.confirmed===true?`${udpScope} complete — ${udpState==="bounded"?"bounded":"recorded scope"}`:"Targeted UDP scope not complete",
        {numerator:scan.udp?.confirmed===true?udpCount||1:0,denominator:udpCount||1,bounded:udpState==="bounded"}
      ),
      dimension(
        "web-mapping","Web mapping",percent(webNumerator,webDenominator),
        coverageStateFromRatio(webNumerator,webDenominator),
        webDenominator?`${unmapped} web endpoint${unmapped===1?"":"s"} without an exact origin`:"No web-capable endpoints",
        {numerator:webNumerator,denominator:webDenominator}
      ),
      dimension(
        "technology-fingerprinting","Technology fingerprinting",percent(fingerprinted,origins.length),
        coverageStateFromRatio(fingerprinted,origins.length),
        origins.length?`${withoutTechnology} exact origin${withoutTechnology===1?"":"s"} without product evidence`:"No exact origins",
        {numerator:fingerprinted,denominator:origins.length}
      ),
      dimension(
        "evidence-review","Evidence review",percent(reviewed,imports.length),
        coverageStateFromRatio(reviewed,imports.length),
        imports.length?`${unreviewed} logical result${unreviewed===1?"":"s"} unreviewed`:"No logical results retained",
        {numerator:reviewed,denominator:imports.length}
      )
    ];
    return dimensions.filter(row=>COVERAGE_DIMENSION_IDS.includes(row.id));
  }
  function serviceRows(host,services,options={}){
    const recordsByEndpoint=options.technologyRecordsByEndpoint||technologyRecordsByEndpoint(host);
    return services.map((row,index)=>{
      const id=endpointIdentity(row,index),protocol=text(row.protocol||"tcp").toLowerCase(),port=number(row.port);
      const coverage=serviceCoverageProjection(row),serviceIdentity=serviceIdentityProjection(row),applicationIdentity=applicationIdentityProjection(host,row,id,recordsByEndpoint.get(id)||[]);
      return {
        id,
        endpoint:`${port||"Unknown"}/${protocol.toUpperCase()}`,
        engagementId:text(row.engagementId),hostId:text(row.hostId),targetAddress:text(row.targetAddress||row.observedTargetAddress||row.address||host.ip),protocol,port,
        state:text(row.displayState||row.state||"open"),service:text(row.service),serviceRaw:text(row.serviceRaw),serviceHint:text(row.serviceHint||row.serviceRaw),product:text(row.product),version:text(row.version),cpe:text(row.cpe),extraInfo:text(row.extraInfo),details:text(row.details),source:text(row.source),sourceSlot:text(row.sourceSlot),productVersion:[text(row.product),text(row.version)].filter(Boolean).join(" "),
        coverageState:coverage.state,identityState:row.identified===true?"confirmed":"not-confirmed",coverage,serviceIdentity,applicationIdentity,
        evidenceCount:values(row.evidenceSources).length
      };
    });
  }
  const WHATWEB_NON_IDENTITY_NAMES=new Set([
    "cookies","cookie","httponly","html5","indexof","opensearch","passwordfield","script",
    "xframeoptions","xuacompatible","xxssprotection","xcontenttypeoptions","contentsecuritypolicy",
    "xaccelbuffering","country","email","httpstatus","ip","redirectlocation","redirect","title","uncommonheaders"
  ]);
  function whatWebIdentityName(value=""){return text(value).toLowerCase().replace(/[^a-z0-9]/g,"");}
  function acceptedWhatWebIdentity(technology={}){return Boolean(text(technology.name))&&!WHATWEB_NON_IDENTITY_NAMES.has(whatWebIdentityName(technology.name));}
  function whatWebIdentityState(technology={},recordState="unknown"){
    const explicit=text(technology.state||technology.identityState).toLowerCase();
    if(["positive","candidate","clue-only","conflicting"].includes(explicit))return explicit;
    if(whatWebIdentityName(technology.name)==="java"&&(!text(technology.version)||text(technology.version).toLowerCase()==="unknown"))return "clue-only";
    return recordState;
  }
  function technologyProjection(host,services,origins,options={}){
    const recordsByEndpoint=options.technologyRecordsByEndpoint||technologyRecordsByEndpoint(host),serviceViews=options.serviceViews||serviceRows(host,services,{technologyRecordsByEndpoint:recordsByEndpoint}),originStats=new Map(),originIdsByEndpoint=new Map(),globalRows=[],globalOutcomes=[],canonicalObservationKeys=new Set(),versionSets=new Map();
    const counters={establishedServiceIdentities:0,establishedApplicationIdentities:0,clueOnlyApplications:0,unknownApplicationVersions:0,positiveObservations:0,completedZeroResults:0};
    let totalSourceOutcomes=0;
    origins.forEach((origin,index)=>{
      const originId=originIdentity(origin,index),endpointId=text(origin.endpointId||origin.serviceEndpointId),stats={id:originId,originId,url:text(origin.url||origin.value),endpointId,observations:[],sourceOutcomes:[],totalObservationCount:0,positiveCount:0,openObservationCount:0,totalSourceOutcomeCount:0,zeroResultCount:0,openOperationCount:0,sourceStates:new Set(),observationStates:new Set(),hasRetainedWork:false};
      originStats.set(originId,stats);if(!originIdsByEndpoint.has(endpointId))originIdsByEndpoint.set(endpointId,[]);originIdsByEndpoint.get(endpointId).push(originId);
    });
    const boundedProvenance=(rows,limit=TECHNOLOGY_DISPLAY_LIMITS.corroboratingProvenance)=>{const all=values(rows),visible=all.slice(0,limit);return {visible,total:all.length,omitted:Math.max(0,all.length-visible.length)};};
    const normalizeObservation=raw=>{
      const name=text(raw.name);if(!name)return null;
      const corroborating=boundedProvenance(raw.corroboratingProvenance),provenance=boundedProvenance(raw.provenance,TECHNOLOGY_DISPLAY_LIMITS.corroboratingProvenance+1);
      return {id:text(raw.id)||`technology:${idPart(raw.sourceKind)}:${idPart(raw.sourceKey)}:${idPart(raw.endpointId)}:${idPart(raw.originId)}:${idPart(name)}:${idPart(raw.version,"unknown")}`,name,version:text(raw.version)||"Unknown",category:text(raw.category)||"technology",state:text(raw.state)||"positive",identityKind:text(raw.identityKind)||"technology",identityConflict:raw.identityConflict===true,ownerKind:text(raw.ownerKind)||"endpoint",sourceKind:text(raw.sourceKind),sourceTool:text(raw.sourceTool),primarySource:text(raw.primarySource),sourceKey:text(raw.sourceKey),endpointId:text(raw.endpointId),originId:text(raw.originId),artifactId:text(raw.artifactId),revision:number(raw.revision),targetUrl:text(raw.targetUrl),sourceOrigin:text(raw.sourceOrigin),operationState:text(raw.operationState),reviewState:text(raw.reviewState),error:text(raw.error),cpe:text(raw.cpe),fingerprint:text(raw.fingerprint),authoritativeProvenance:raw.authoritativeProvenance||null,corroboratingProvenance:corroborating.visible,corroboratingProvenanceTotal:corroborating.total,corroboratingProvenanceOmitted:corroborating.omitted,provenance:provenance.visible,provenanceTotal:provenance.total,provenanceOmitted:provenance.omitted};
    };
    const rawObservations=callback=>{
      serviceViews.forEach(view=>{
        if(!(originIdsByEndpoint.get(view.id)||[]).length)return;
        const identity=view.serviceIdentity,authority=identity.authoritativeProvenance||{};
        if(identity.state==="established"&&identity.product!=="Unknown")callback({name:identity.product,version:identity.version==="Unknown"?"":identity.version,category:"server",identityKind:"service",ownerKind:"endpoint",state:"positive",sourceKind:"nmap",sourceTool:text(authority.source)||"nmap",primarySource:text(authority.source||authority.sourceOwner)||"nmap",sourceKey:text(authority.artifactId||authority.source)||view.id,endpointId:view.id,originId:"",artifactId:authority.artifactId,revision:authority.revision,operationState:view.coverage?.state,reviewState:"current",cpe:identity.cpe==="Unknown"?"":identity.cpe,fingerprint:identity.fingerprint==="Unknown"?"":identity.fingerprint,authoritativeProvenance:authority,corroboratingProvenance:identity.corroboratingProvenance,provenance:identity.provenance});
        view.applicationIdentity.endpointObservations.forEach(observation=>callback({name:observation.name,version:observation.version,category:"application",identityKind:"application",identityConflict:observation.identityConflict===true,ownerKind:"endpoint",state:observation.state==="established"?"positive":observation.state,sourceKind:observation.sourceKind,sourceKey:observation.recordId||observation.artifactId,endpointId:view.id,originId:"",artifactId:observation.artifactId,revision:observation.revision,operationState:observation.operationState,reviewState:observation.reviewState,provenance:[observation]}));
      });
      values(host?.recon?.technologyImportProjection?.sources).forEach(source=>values(source.records).forEach(record=>{
        const recordState=typeof reconImportApi.technologyRecordState==="function"?reconImportApi.technologyRecordState(record,source):technologyRecordState(record,source);
        values(record.technologies).filter(acceptedWhatWebIdentity).forEach(technology=>callback({name:technology.name,version:technology.version,category:technology.category,identityKind:["application","cms","framework"].includes(text(technology.category).toLowerCase())?"application":"technology",identityConflict:record.identityConflict===true,ownerKind:"origin",state:whatWebIdentityState(technology,recordState),sourceKind:"whatweb",sourceTool:text(source.tool)||"WhatWeb",primarySource:text(source.tool)||"WhatWeb",sourceKey:text(source.key),endpointId:text(record.endpointId||source.endpointId),originId:text(record.originId),artifactId:text(record.artifactId||source.artifactId),revision:number(record.revision||source.revision),targetUrl:text(record.targetUrl),sourceOrigin:text(record.sourceOrigin),operationState:text(record.operationState||source.operationState),reviewState:text(record.reviewState||source.reviewState),error:text(record.error),provenance:[{source:text(source.tool)||"WhatWeb",sourceKey:text(source.key),artifactId:text(record.artifactId||source.artifactId),revision:number(record.revision||source.revision),filename:text(source.filename),targetUrl:text(record.targetUrl),sourceOrigin:text(record.sourceOrigin),operationState:text(record.operationState||source.operationState),reviewState:text(record.reviewState||source.reviewState),error:text(record.error)}]}));
      }));
    };
    rawObservations(raw=>{const row=normalizeObservation(raw);if(!row||row.version==="Unknown"||!["positive","candidate","clue-only"].includes(row.state))return;const key=`${row.ownerKind}|${row.originId}|${row.endpointId}|${row.name.toLowerCase()}`;if(!versionSets.has(key))versionSets.set(key,new Set());versionSets.get(key).add(row.version.toLowerCase());});
    rawObservations(raw=>{
      const row=normalizeObservation(raw);if(!row)return;const versionKey=`${row.ownerKind}|${row.originId}|${row.endpointId}|${row.name.toLowerCase()}`;if((versionSets.get(versionKey)?.size||0)>1){row.state="conflicting";row.identityConflict=true;}
      const key=[row.ownerKind,row.sourceKind,row.sourceKey,row.endpointId,row.originId,row.name.toLowerCase(),row.version.toLowerCase(),row.identityKind,row.state,row.targetUrl].join("|");if(canonicalObservationKeys.has(key))return;canonicalObservationKeys.add(key);
      if(row.state==="positive")counters.positiveObservations++;if(row.ownerKind==="endpoint"&&row.identityKind==="service"&&row.state==="positive")counters.establishedServiceIdentities++;if(row.identityKind==="application"&&row.state==="positive")counters.establishedApplicationIdentities++;if(row.identityKind==="application"&&row.state==="clue-only")counters.clueOnlyApplications++;if(row.identityKind==="application"&&row.version==="Unknown"&&acceptedApplicationIdentity(row))counters.unknownApplicationVersions++;
      if(globalRows.length<TECHNOLOGY_DISPLAY_LIMITS.globalObservations)globalRows.push(row);
      const recipientIds=row.ownerKind==="origin"?[row.originId]:(originIdsByEndpoint.get(row.endpointId)||[]);recipientIds.forEach(originId=>{const stats=originStats.get(originId);if(!stats)return;stats.totalObservationCount++;stats.observationStates.add(row.state);if(row.state==="positive")stats.positiveCount++;if(TECHNOLOGY_OPEN_STATES.has(row.state))stats.openObservationCount++;if(stats.observations.length<TECHNOLOGY_DISPLAY_LIMITS.perOriginObservations)stats.observations.push(row);stats.hasRetainedWork=true;});
    });
    const boundedList=(input,limit)=>{const all=unique(input),visible=all.slice(0,limit);return {visible,total:all.length,omitted:Math.max(0,all.length-visible.length)};};
    values(host?.recon?.technologyImportProjection?.sources).forEach(source=>{
      const fullOutcomes=typeof reconImportApi.technologyOriginOutcomes==="function"?reconImportApi.technologyOriginOutcomes(source):[];
      fullOutcomes.forEach(raw=>{
        totalSourceOutcomes++;counters.completedZeroResults+=number(raw.completedZeroCount);
        const targets=boundedList(raw.targetUrls,TECHNOLOGY_DISPLAY_LIMITS.targetUrlsPerOutcome),errors=boundedList(raw.errors,TECHNOLOGY_DISPLAY_LIMITS.errorsPerOutcome),outcome={id:text(raw.id),sourceKey:text(raw.sourceKey),ownerKind:"origin",artifactId:text(raw.artifactId),revision:number(raw.revision),originId:text(raw.originId),originIds:[text(raw.originId)],endpointId:text(raw.endpointId),state:text(raw.state)||"unknown",resultCount:number(raw.resultCount),positiveObservationCount:number(raw.positiveObservationCount),positiveRecordCount:number(raw.positiveRecordCount),recordCount:number(raw.recordCount),completedZeroCount:number(raw.completedZeroCount),openCount:number(raw.openCount),hasOpenWork:raw.hasOpenWork===true,mixed:raw.mixed===true,failedCount:number(raw.failedCount),partialCount:number(raw.partialCount),conflictingCount:number(raw.conflictingCount),staleCount:number(raw.staleCount),deferredCount:number(raw.deferredCount),unknownCount:number(raw.unknownCount),tool:text(raw.tool)||"WhatWeb",operationState:text(raw.operationState),reviewState:text(raw.reviewState),observedAt:text(source.observedAt),targetUrls:targets.visible,targetUrlCount:targets.total,omittedTargetUrlCount:targets.omitted,sourceOrigins:unique(raw.sourceOrigins).slice(0,TECHNOLOGY_DISPLAY_LIMITS.targetUrlsPerOutcome),errors:errors.visible,errorCount:errors.total,omittedErrorCount:errors.omitted};
        if(globalOutcomes.length<TECHNOLOGY_DISPLAY_LIMITS.globalSourceOutcomes)globalOutcomes.push(outcome);
        const stats=originStats.get(outcome.originId);if(!stats)return;stats.totalSourceOutcomeCount++;stats.zeroResultCount+=outcome.completedZeroCount;stats.openOperationCount+=outcome.openCount;stats.sourceStates.add(outcome.state);stats.hasRetainedWork=true;if(stats.sourceOutcomes.length<TECHNOLOGY_DISPLAY_LIMITS.perOriginSourceOutcomes)stats.sourceOutcomes.push(outcome);
      });
    });
    const explicitTechnology=values(options.explicitCoverage).filter(row=>text(row.id).includes("web-technology-fingerprinting")||/technology/i.test(text(row.dimension)||text(row.label)));
    const byOrigin=[...originStats.values()].map(stats=>{
      const explicit=explicitTechnology.filter(row=>text(row.originId)===stats.originId),explicitStates=explicit.map(row=>text(row.state)==="complete"?"positive":text(row.state)==="negative"?"zero":text(row.state)),explicitOpenCount=explicitStates.filter(state=>TECHNOLOGY_OPEN_STATES.has(state)).length,states=[...stats.observationStates,...stats.sourceStates,...explicitStates];
      const precedence=["conflicting","stale","partial","failed","deferred","unknown","positive","zero"],state=precedence.find(candidate=>states.includes(candidate))||"unknown",openCount=Math.max(stats.openObservationCount,stats.openOperationCount)+explicitOpenCount,hasOpenWork=openCount>0,mixed=stats.positiveCount>0&&(stats.zeroResultCount>0||hasOpenWork);
      return {id:stats.id,originId:stats.originId,url:stats.url,endpointId:stats.endpointId,state,mixed,hasOpenWork,observations:stats.observations,sourceOutcomes:stats.sourceOutcomes,positiveCount:stats.positiveCount,zeroResultCount:stats.zeroResultCount,openCount,totalObservationCount:stats.totalObservationCount,visibleObservationCount:stats.observations.length,omittedObservationCount:Math.max(0,stats.totalObservationCount-stats.observations.length),totalSourceOutcomeCount:stats.totalSourceOutcomeCount,visibleSourceOutcomeCount:stats.sourceOutcomes.length,omittedSourceOutcomeCount:Math.max(0,stats.totalSourceOutcomeCount-stats.sourceOutcomes.length),displayTruncated:stats.observations.length<stats.totalObservationCount||stats.sourceOutcomes.length<stats.totalSourceOutcomeCount,hasRetainedWork:stats.hasRetainedWork||explicit.length>0};
    }).sort((left,right)=>left.originId.localeCompare(right.originId));
    const states=Object.fromEntries(["positive","zero","failed","partial","conflicting","stale","deferred","unknown"].map(state=>[state,byOrigin.filter(row=>row.state===state).length]));
    return {limits:TECHNOLOGY_DISPLAY_LIMITS,exactOrigins:origins.length,originsWithWork:byOrigin.filter(row=>row.hasRetainedWork).length,...counters,openWork:byOrigin.filter(row=>row.hasOpenWork).length,states,rows:globalRows,totalObservations:canonicalObservationKeys.size,visibleObservations:globalRows.length,omittedObservations:Math.max(0,canonicalObservationKeys.size-globalRows.length),displayTruncated:globalRows.length<canonicalObservationKeys.size,outcomes:globalOutcomes,totalSourceOutcomes,visibleSourceOutcomes:globalOutcomes.length,omittedSourceOutcomes:Math.max(0,totalSourceOutcomes-globalOutcomes.length),byOrigin};
  }
  function technologyIdentityState(value,identityKind="technology"){
    const state=text(value).toLowerCase();
    if(state==="positive"||state==="established")return identityKind==="service"?"established":"established";
    return ["candidate","clue-only","conflicting","failed","partial","stale","deferred","unknown","zero"].includes(state)?state:"unknown";
  }
  function technologyDisplayStateRank(value=""){
    const state=text(value).toLowerCase();
    return ({conflicting:0,positive:1,established:1,candidate:2,"clue-only":3,stale:4,partial:5,failed:6,deferred:7,unknown:8,zero:9})[state]??10;
  }
  function groupTechnologyDisplayIdentities(observations=[],context={}){
    const endpointId=text(context.endpointId),originId=text(context.originId),groups=new Map();
    values(observations).forEach((raw,index)=>{
      const name=text(raw?.name),rawEndpointId=text(raw?.endpointId),rawOriginId=text(raw?.originId),ownerKind=text(raw?.ownerKind)||"endpoint";
      if(!name||endpointId&&rawEndpointId&&rawEndpointId!==endpointId||ownerKind==="origin"&&originId&&rawOriginId!==originId)return;
      const version=text(raw.version)||"Unknown",identityKind=text(raw.identityKind)||"technology",state=text(raw.state).toLowerCase()||"unknown";
      const exactEndpointId=endpointId||rawEndpointId,exactOriginId=originId||rawOriginId;
      const key=[name.toLowerCase(),version.toLowerCase(),identityKind.toLowerCase(),exactEndpointId,exactOriginId].join("|");
      if(!groups.has(key))groups.set(key,{id:`display:${idPart(exactEndpointId)}:${idPart(exactOriginId)}:${idPart(name)}:${idPart(version)}:${idPart(identityKind)}`,name,version,category:text(raw.category)||identityKind,identityKind,state,displayState:technologyIdentityState(state,identityKind),identityConflict:raw.identityConflict===true||state==="conflicting",endpointId:exactEndpointId,originId:exactOriginId,supportingObservationCount:0,supportingObservations:[],omittedSupportingObservationCount:0,provenance:[],provenanceCount:0,omittedProvenanceCount:0});
      const group=groups.get(key),provenance=values(raw.provenance).length?values(raw.provenance):[raw];
      if(technologyDisplayStateRank(state)<technologyDisplayStateRank(group.state)){group.state=state;group.displayState=technologyIdentityState(state,identityKind);}
      if(raw.identityConflict===true||state==="conflicting"){group.identityConflict=true;group.state="conflicting";group.displayState="conflicting";}
      group.supportingObservationCount++;
      if(group.supportingObservations.length<TECHNOLOGY_OBJECTIVE_LIMITS.supportingObservations)group.supportingObservations.push({id:text(raw.id)||`observation-${index+1}`,sourceKind:text(raw.sourceKind),sourceTool:text(raw.sourceTool),sourceKey:text(raw.sourceKey),ownerKind,endpointId:rawEndpointId||exactEndpointId,originId:rawOriginId,artifactId:text(raw.artifactId),revision:number(raw.revision),targetUrl:text(raw.targetUrl),sourceOrigin:text(raw.sourceOrigin),operationState:text(raw.operationState),reviewState:text(raw.reviewState),state});
      provenance.forEach(item=>{const row={sourceKind:text(item?.sourceKind||item?.source),sourceTool:text(item?.sourceTool),sourceKey:text(item?.sourceKey),ownerKind:text(item?.ownerKind||ownerKind),endpointId:text(item?.endpointId||rawEndpointId||exactEndpointId),originId:text(item?.originId||rawOriginId),artifactId:text(item?.artifactId||raw.artifactId),revision:number(item?.revision||raw.revision),recordId:text(item?.recordId||item?.id||raw.id),targetUrl:text(item?.targetUrl||raw.targetUrl),sourceOrigin:text(item?.sourceOrigin||raw.sourceOrigin)};const provenanceKey=JSON.stringify(row);if(!group._provenanceKeys)group._provenanceKeys=new Set();if(group._provenanceKeys.has(provenanceKey))return;group._provenanceKeys.add(provenanceKey);group.provenanceCount++;if(group.provenance.length<TECHNOLOGY_OBJECTIVE_LIMITS.provenancePerIdentity)group.provenance.push(row);});
    });
    return [...groups.values()].map(group=>{group.omittedSupportingObservationCount=Math.max(0,group.supportingObservationCount-group.supportingObservations.length);group.omittedProvenanceCount=Math.max(0,group.provenanceCount-group.provenance.length);delete group._provenanceKeys;return group;}).sort((left,right)=>left.identityKind.localeCompare(right.identityKind)||left.name.localeCompare(right.name)||left.version.localeCompare(right.version)||technologyDisplayStateRank(left.state)-technologyDisplayStateRank(right.state)).slice(0,TECHNOLOGY_OBJECTIVE_LIMITS.identities);
  }
  function technologyObjectiveEvidenceSummary(technology={},context={}){
    const observations=values(technology.observations),displayIdentities=groupTechnologyDisplayIdentities(observations,context),retainedObservationCount=Math.max(number(technology.totalObservationCount),observations.length),retainedSourceOutcomeCount=Math.max(number(technology.totalSourceOutcomeCount),values(technology.sourceOutcomes).length),retainedMethodOutcomeCount=number(context.methodOutcomeCount),hasEvidence=retainedObservationCount>0||retainedSourceOutcomeCount>0;
    const protocol=text(context.serviceKey||context.service).toLowerCase(),port=number(context.port),originUrl=text(context.originUrl||technology.url),known=[];
    if(hasEvidence&&protocol&&port)known.push({kind:"protocol",label:`${protocol.toUpperCase()} on ${text(context.protocol||"tcp").toUpperCase()} ${port}`,state:"established",endpointId:text(context.endpointId),originId:text(context.originId),provenance:[]});
    displayIdentities.forEach(row=>{if(["failed","partial","stale","deferred","unknown","zero"].includes(row.state))return;known.push({kind:row.identityKind,label:row.name,name:row.name,version:row.version,state:row.displayState,identityConflict:row.identityConflict,supportingObservationCount:row.supportingObservationCount,supportingObservations:row.supportingObservations,omittedSupportingObservationCount:row.omittedSupportingObservationCount,provenance:row.provenance,provenanceCount:row.provenanceCount,omittedProvenanceCount:row.omittedProvenanceCount,endpointId:row.endpointId,originId:row.originId});});
    const unknown=[];
    displayIdentities.filter(row=>row.version==="Unknown"&&["positive","established","candidate","clue-only","conflicting"].includes(row.state)).forEach(row=>{const label=text(row.category).toLowerCase()==="language"&&row.state==="clue-only"?`Whether a ${row.name} runtime is independently confirmed`:`${row.name} version`;if(!unknown.includes(label))unknown.push(label);});
    const clueNames=unique(displayIdentities.filter(row=>row.identityKind==="application"&&row.state==="clue-only").map(row=>row.name));
    clueNames.forEach(name=>unknown.push(`Whether the ${name} clue has been independently confirmed by browser review or stronger application evidence`));
    const serviceNames=unique(displayIdentities.filter(row=>row.identityKind==="service"&&["positive","established"].includes(row.state)).map(row=>row.name)),establishedApplications=unique(displayIdentities.filter(row=>row.identityKind==="application"&&["positive","established"].includes(row.state)).map(row=>row.name));
    let reason="No retained Technology evidence is owned by this exact origin.";
    if(hasEvidence&&serviceNames.length&&clueNames.length)reason=`Retained evidence identifies ${serviceNames.join(", ")} and a ${clueNames.join(", ")} application clue on this exact origin. Review the clue and unknown versions, then mark the objective Complete or Partial.`;
    else if(hasEvidence&&serviceNames.length)reason=`Retained evidence identifies ${serviceNames.join(", ")} on this exact origin. Review remaining unknowns, then mark the objective Complete or Partial.`;
    else if(hasEvidence&&(establishedApplications.length||clueNames.length))reason=`Retained evidence identifies ${[...establishedApplications,...clueNames.map(name=>`${name} application clue`)].join(", ")} on this exact origin. Review remaining unknowns, then mark the objective Complete or Partial.`;
    else if(hasEvidence)reason="Retained Technology evidence is available for this exact origin. Review it, then record the objective disposition.";
    const suggestedNextSteps=hasEvidence?[
      `Open ${originUrl||"the exact origin"} manually and confirm the likely application or framework.`,
      "Do not repeat the existing basic -sC -sV scan unless a fresh run is intentionally needed.",
      "Use the focused HTTP fingerprint command or import retained WhatWeb output if additional headers, version, framework, or application details are needed.",
      "Mark the objective Complete when the stack is sufficiently identified, or Partial when the application remains uncertain."
    ]:[
      `Open ${originUrl||"the exact origin"} manually and identify the visible server and application clues.`,
      "Run or import one exact-endpoint HTTP fingerprint pass when retained evidence is not already available.",
      "Use focused HTTP headers, title, methods, common-path, or WhatWeb evidence when additional detail is needed.",
      "Mark the objective Complete when the stack is sufficiently identified, or Partial when the application remains uncertain."
    ];
    return deepFreeze({evidenceState:hasEvidence?"review-required":"none",evidenceLabel:hasEvidence?"Evidence available — review required":"No retained evidence",reason,retainedObservationCount,displayedIdentityCount:displayIdentities.length,retainedSourceOutcomeCount,retainedMethodOutcomeCount,displayIdentities,known:known.slice(0,TECHNOLOGY_OBJECTIVE_LIMITS.known),unknown:unknown.slice(0,TECHNOLOGY_OBJECTIVE_LIMITS.unknown),suggestedNextSteps:suggestedNextSteps.slice(0,TECHNOLOGY_OBJECTIVE_LIMITS.nextSteps),definitionOfDone:"Complete when the server/runtime and likely application or framework are identified well enough to choose the next enumeration or vulnerability-research step. Exact versions may remain Unknown when the target does not expose them.",limits:TECHNOLOGY_OBJECTIVE_LIMITS});
  }
  function originRows(host,origins,targets,imports,technologies){
    return origins.map((row,index)=>{
      const id=originIdentity(row,index);
      const observations=targets.filter(item=>text(item.originId)===id);
      const negativeImports=imports.filter(item=>item.kind==="web"&&item.originIds?.includes(id)&&/negative|zero/i.test(item.outcome)).length;
      const technology=values(technologies?.byOrigin).find(item=>item.originId===id)||{state:"unknown",observations:[],zeroResultCount:0};
      return {
        id,
        url:text(row.url||row.value),
        endpointId:text(row.endpointId||row.serviceEndpointId),
        mappingState:"mapped",
        observationCount:observations.length,
        positiveCount:observations.filter(item=>number(item.status)>=200&&number(item.status)<400).length,
        negativeCount:negativeImports,
        technologyState:technology.state,
        technologyCount:number(technology.totalObservationCount??technology.observations.length),
        technologyZeroCount:technology.zeroResultCount
      };
    });
  }
  function projectHost(host={},options={}){
    const services=canonicalServices(host),origins=exactOrigins(host),targets=values(host?.recon?.webTargets),recordsByEndpoint=technologyRecordsByEndpoint(host),serviceViewRows=serviceRows(host,services,{technologyRecordsByEndpoint:recordsByEndpoint}),technologies=technologyProjection(host,services,origins,{...options,technologyRecordsByEndpoint:recordsByEndpoint,serviceViews:serviceViewRows});
    const addressRows=options.addresses===undefined?host.networkAddresses:options.addresses;
    const addresses=unique([host.ip,...values(addressRows).map(row=>typeof row==="string"?row:row?.address)]);
    const gaps=canonicalFacts(host,{...options,technologyView:technologies}),counts=countsFor(gaps),imports=importRows(host,options);
    const dimensions=coverageDimensions(host,{services,origins,targets,imports,gaps,technologies});
    const leads=values(host.vulnerabilityLeads),identity=options.identity||{},accessContext=options.accessContext||{};
    const projection={
      host:{
        id:text(host.id),
        label:text(identity.displayName)||text(host.hostname)||text(host.ip)||"Selected host",
        hostname:text(host.hostname),
        primaryAddress:text(host.ip)||addresses[0]||"",
        addresses,
        status:text(host.status),
        scopeLabel:text(options.scope?.label)||text(host.scopeDisposition)||"Scope not recorded",
        scopeState:text(options.scope?.status)||text(host.scopeDisposition)||"unknown",
        osLabel:text(identity.osLabel)||text(options.osLabel)||text(host?.osResolution?.family)||text(host.os)||"Unknown",
        osConfidence:text(identity.osConfidence)||text(host?.osResolution?.confidence)||"Unknown",
        osDetail:text(identity.osDetail),
        architecture:text(identity.architecture),
        accessContext:{
          id:text(accessContext.id),
          label:text(accessContext.label)
        }
      },
      services:{
        total:services.length,
        identified:services.filter(row=>row.identified===true).length,
        needsIdentity:services.filter(row=>row.identified!==true).length,
        tcp:services.filter(row=>text(row.protocol||"tcp").toLowerCase()==="tcp").length,
        udp:services.filter(row=>text(row.protocol).toLowerCase()==="udp").length,
        rows:serviceViewRows
      },
      origins:{
        total:origins.length,
        observations:targets.filter(row=>row.recordRole!=="web-origin").length,
        unresolved:targets.filter(row=>row.unresolved===true).length,
        rows:originRows(host,origins,targets,imports,technologies)
      },
      technologies,
      imports,
      leads:{
        total:leads.length,
        open:leads.filter(row=>text(row.status||"lead").toLowerCase()==="lead").length,
        verified:leads.filter(row=>text(row.status).toLowerCase()==="verified").length,
        notApplicable:leads.filter(row=>text(row.status).toLowerCase()==="na").length
      },
      notesPreview:text((host.recon||{}).notes),
      gaps,
      counts,
      dimensions,
      tabCounts:{
        services:services.length,
        webOrigins:origins.length,
        evidence:imports.length,
        coverage:counts.open,
        leads:leads.length
      }
    };
    return deepFreeze(projection);
  }
  function overview(projection={}){
    const gaps=values(projection.gaps),counts=projection.counts||countsFor(gaps);
    return deepFreeze({
      host:projection.host||{},
      services:projection.services||{},
      origins:projection.origins||{},
      recentImports:values(projection.imports).slice(0,5),
      notesPreview:text(projection.notesPreview),
      topGaps:gaps.filter(row=>OPEN_STATES.has(row.state)).slice(0,5),
      dimensions:values(projection.dimensions).slice(0,4),
      counts
    });
  }
  function coverage(projection={}){
    const gaps=values(projection.gaps),counts=projection.counts||countsFor(gaps);
    const missing=gaps.filter(row=>OPEN_STATES.has(row.state)&&row.state!=="conflict");
    return deepFreeze({
      gaps,
      active:missing,
      missing,
      resolved:gaps.filter(row=>row.state==="complete"||row.state==="negative"),
      conflicts:gaps.filter(row=>row.state==="conflict"),
      dimensions:values(projection.dimensions),
      counts
    });
  }
  function filterGapsByOrigin(gaps,originId){
    const exact=text(originId);
    if(!exact)return deepFreeze([]);
    return deepFreeze(values(gaps).filter(row=>text(row?.owner?.originId)===exact||((row?.scope?.kind==="origin")&&text(row?.scope?.id)===exact)));
  }

  return Object.freeze({STATES,COVERAGE_DIMENSION_IDS,OPEN_STATES:Object.freeze([...OPEN_STATES]),TECHNOLOGY_DISPLAY_LIMITS,TECHNOLOGY_OBJECTIVE_LIMITS,EVIDENCE_REVIEW_LIMITS,evidenceRouteId,canonicalServices,technologyProjection,groupTechnologyDisplayIdentities,technologyObjectiveEvidenceSummary,endpointScopedNmapEvidence,evidenceReview,projectHost,overview,coverage,filterGapsByOrigin});
});
