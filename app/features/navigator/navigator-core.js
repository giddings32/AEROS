(function(root,factory){
  const profileApi=(typeof module==="object"&&module.exports)
    ?require("../../../host-profile.js")
    :(root&&root.AerosHostProfile);
  const api=factory(profileApi||{});
  if(typeof module==="object"&&module.exports)module.exports=api;
  if(root)root.AEROSNavigatorCore=api;
})(typeof globalThis!=="undefined"?globalThis:this,function(profileApi){
  "use strict";

  const VERSION=1;
  const PRESENTATION_VERSION=3;
  const MAX_HOSTS=200;
  const MAX_VISIBLE_HOSTS=50;
  const MAX_ACTIONS=500;
  const MAX_HOST_ACTIONS=50;
  const MAX_CONTEXT_LINKS=50;
  const MAX_EXPANDED_GROUPS=20;
  const MAX_EXPANDED_CARDS=50;
  const MAX_SKIPPED_ACTIONS=100;
  const MAX_FILTERS=12;
  const MAX_TEXT=500;
  const MAX_ID=160;
  const MAX_SCROLL=5000000;

  const STATUS=Object.freeze({
    NOT_STARTED:"not-started",
    IN_PROGRESS:"in-progress",
    PARTIAL:"partial",
    CONFIRMED_NEGATIVE:"confirmed-negative",
    COMPLETE:"confirmed-complete",
    BLOCKED:"blocked",
    CONFLICT:"conflict",
    STALE:"stale-revisit-required",
    UNKNOWN:"unknown-needs-review",
    NOT_APPLICABLE:"not-applicable"
  });
  const STATUS_LABELS=Object.freeze({
    [STATUS.NOT_STARTED]:"Not started",
    [STATUS.IN_PROGRESS]:"In progress",
    [STATUS.PARTIAL]:"Partial",
    [STATUS.CONFIRMED_NEGATIVE]:"Confirmed negative",
    [STATUS.COMPLETE]:"Confirmed / complete",
    [STATUS.BLOCKED]:"Blocked",
    [STATUS.CONFLICT]:"Conflict",
    [STATUS.STALE]:"Stale / revisit required",
    [STATUS.UNKNOWN]:"Unknown / needs review",
    [STATUS.NOT_APPLICABLE]:"Not applicable"
  });
  const STATUS_VALUES=Object.freeze(Object.values(STATUS));
  const DESTINATIONS=Object.freeze([
    "navigator","host-workbench","host-profile","recon","web-app-review","endpoint","web-origin","lead","investigation",
    "access-context","methodology","import","record-outcome","coverage","proof",
    "evidence","finding","report","reference-note","search","host-enumeration",
    "credentials","movement","attack-map","investigations-evidence","progress","review","exploitation-path"
  ]);
  const ROUTE_FIELDS=Object.freeze([
    "engagementId","engagementName","hostId","targetAddress","objectiveId","endpointId","originId","leadId","peasFindingId",
    "investigationId","accessContextId","proofItemId","importItemId","logicalResultId","artifactId","artifactRevision","evidenceId",
    "findingId","reportBlockerId","noteId","subview","focusedRecordId","methodologyInstanceId",
    "returnStateId","returnLabel","replacementLogicalRunId","originatingActionId"
  ]);
  const SUBVIEWS=Object.freeze([
    "","all-hosts","next-actions","required-coverage","secondary-verification",
    "alternative-methods","completed-negative","revisit","conflicts","tcp","udp",
    "services","origins","access","post-access","privilege-escalation","proof","report",
    "scan-files","results-folder","peas","documents","deep-import","addresses","full-coverage",
    "tcp-port-discovery","tcp-service-discovery","udp-port-discovery","udp-service-discovery",
    "origin-overview","technologies","content","inputs","domains","api-content","imported-results",
    "summary","fingerprint","discovered-content","inputs-routes","testing-coverage","imported-sources",
    "structured-results","raw-output","artifact-history","successful-shell"
  ]);
  const GROUPS=Object.freeze([
    "next-actions","required-coverage","secondary-verification","alternative-methods",
    "completed-negative","revisit","conflicts"
  ]);
  const GROUP_LABELS=Object.freeze({
    "next-actions":"Next actions",
    "required-coverage":"Required coverage",
    "secondary-verification":"Secondary verification",
    "alternative-methods":"Alternative methods",
    "completed-negative":"Completed / confirmed negative",
    "revisit":"Revisit after new context",
    "conflicts":"Conflicts / operator decisions"
  });
  const SAFE_ID=/^[A-Za-z0-9][A-Za-z0-9._:@/|+\-[\]%]{0,159}$/;
  const SAFE_ENGAGEMENT_NAME=/^[^\u0000-\u001f\u007f<>"'`\\]{1,160}$/;

  function clean(value,limit=MAX_TEXT){
    const text=String(value??"").trim().replace(/[\u0000-\u001f\u007f]/g," ");
    return text.length>limit?`${text.slice(0,Math.max(0,limit-1))}…`:text;
  }
  function token(value){return clean(value,80).toLowerCase().replace(/[_\s]+/g,"-");}
  function list(value){return Array.isArray(value)?value:[];}
  function object(value){return value&&typeof value==="object"&&!Array.isArray(value)?value:{};}
  function unique(values,limit=MAX_EXPANDED_CARDS){
    const output=[];
    list(values).forEach(value=>{const item=clean(value,MAX_ID);if(item&&!output.includes(item)&&output.length<limit)output.push(item);});
    return output;
  }
  function boundedNumber(value,min,max,fallback=0){
    const parsed=Number(value);
    return Number.isFinite(parsed)?Math.min(max,Math.max(min,Math.round(parsed))):fallback;
  }
  function validId(value,{optional=true}={}){
    const id=clean(value,MAX_ID);
    if(!id)return optional;
    return id.length<=MAX_ID&&SAFE_ID.test(id);
  }
  function stableKey(value){
    const source=clean(value,1000);
    let hash=2166136261;
    for(let index=0;index<source.length;index++){hash^=source.charCodeAt(index);hash=Math.imul(hash,16777619);}
    return (hash>>>0).toString(36);
  }
  function status(value,details={}){
    let state=STATUS_VALUES.includes(value)?value:STATUS.UNKNOWN;
    const reason=clean(details.reason),source=clean(details.source,MAX_ID);
    if(state===STATUS.NOT_APPLICABLE&&(!reason||!source))state=STATUS.UNKNOWN;
    return Object.freeze({
      state,
      label:STATUS_LABELS[state],
      reason:reason||(state===STATUS.UNKNOWN?"No supported canonical fact resolves this dimension.":""),
      source:source||(state===STATUS.UNKNOWN?"canonical-state:unsupported":""),
      count:Number.isFinite(Number(details.count))?Math.max(0,Number(details.count)):undefined,
      total:Number.isFinite(Number(details.total))?Math.max(0,Number(details.total)):undefined,
      conflict:state===STATUS.CONFLICT,
      operatorReview:details.operatorReview===true||[STATUS.CONFLICT,STATUS.UNKNOWN,STATUS.STALE].includes(state)
    });
  }
  function dimension(id,label,state,details={}){
    return Object.freeze({id:clean(id,80),label:clean(label,100),...status(state,details),meta:object(details.meta)});
  }

  function normalizeRoute(input={}){
    const raw=object(input),errors=[];
    const destination=token(raw.destination);
    if(!DESTINATIONS.includes(destination))errors.push("Destination is not supported.");
    const route={version:VERSION,destination:DESTINATIONS.includes(destination)?destination:""};
    ROUTE_FIELDS.forEach(field=>{
      const value=clean(raw[field],MAX_ID);
      if(field==="engagementName"||field==="returnLabel"){
        if(value&&!SAFE_ENGAGEMENT_NAME.test(value))errors.push(`${field} is invalid.`);
        route[field]=SAFE_ENGAGEMENT_NAME.test(value)?value:"";
        return;
      }
      if(value&&!validId(value))errors.push(`${field} is invalid.`);
      route[field]=validId(value)?value:"";
    });
    if(route.subview&&!SUBVIEWS.includes(route.subview))errors.push("Subview is not supported.");
    if(route.destination!=="navigator"&&!route.engagementId&&!route.engagementName)errors.push("An exact engagement owner is required.");
    return Object.freeze({valid:errors.length===0,errors:Object.freeze(errors),route:Object.freeze(route)});
  }

  function normalizeFilters(value={}){
    const output={};
    Object.entries(object(value)).slice(0,MAX_FILTERS).forEach(([key,raw])=>{
      const safeKey=token(key).slice(0,40),safeValue=clean(raw,120);
      if(safeKey&&safeValue)output[safeKey]=safeValue;
    });
    return output;
  }
  function normalizeSkippedActions(value=[],options={}){
    const hostIds=new Set(list(options.validHostIds).map(String)),output=[],seen=new Set();
    list(value).forEach(item=>{
      if(output.length>=MAX_SKIPPED_ACTIONS)return;
      const raw=object(item),skipKey=clean(raw.skipKey,MAX_ID),evidenceSignature=clean(raw.evidenceSignature,MAX_ID),hostId=clean(raw.hostId,MAX_ID);
      if(!validId(skipKey,{optional:false})||!validId(evidenceSignature,{optional:false})||!validId(hostId,{optional:false})||(hostIds.size&&!hostIds.has(hostId))||seen.has(skipKey))return;
      seen.add(skipKey);
      output.push(Object.freeze({
        skipKey,evidenceSignature,hostId,
        title:clean(raw.title,160),
        skippedAt:clean(raw.skippedAt,40)
      }));
    });
    return output;
  }
  function normalizeViewState(input={},options={}){
    const raw=object(input),hostIds=new Set(list(options.validHostIds).map(String));
    const legacyExpanded=unique(raw.expandedCardIds,MAX_EXPANDED_CARDS).filter(validId);
    const migrateLegacySelection=Number(raw.version||1)<PRESENTATION_VERSION&&!clean(raw.staleReference,MAX_TEXT);
    const selectedHostId=clean(raw.selectedHostId,MAX_ID)
      ||(migrateLegacySelection?legacyExpanded.find(value=>!hostIds.size||hostIds.has(value)):"")
      ||"";
    const hostValid=!selectedHostId||!hostIds.size||hostIds.has(selectedHostId);
    const selectedAccessContextId=clean(raw.selectedAccessContextId,MAX_ID);
    const subview=SUBVIEWS.includes(clean(raw.subview,80))?clean(raw.subview,80):"all-hosts";
    return Object.freeze({
      version:PRESENTATION_VERSION,
      selectedHostId:hostValid&&validId(selectedHostId)?selectedHostId:"",
      selectedEndpointId:validId(raw.selectedEndpointId)?clean(raw.selectedEndpointId,MAX_ID):"",
      selectedOriginId:validId(raw.selectedOriginId)?clean(raw.selectedOriginId,MAX_ID):"",
      selectedAccessContextId:validId(selectedAccessContextId)?selectedAccessContextId:"",
      subview,
      filters:Object.freeze(normalizeFilters(raw.filters)),
      expandedGroupIds:Object.freeze(unique(raw.expandedGroupIds,MAX_EXPANDED_GROUPS).filter(value=>GROUPS.includes(value))),
      expandedCardIds:Object.freeze(unique(raw.expandedCardIds,MAX_EXPANDED_CARDS).filter(validId)),
      skippedActions:Object.freeze(normalizeSkippedActions(raw.skippedActions,{validHostIds:[...hostIds]})),
      showFullCoverage:raw.showFullCoverage===true,
      scrollTop:boundedNumber(raw.scrollTop,0,MAX_SCROLL,0),
      focusKey:validId(raw.focusKey)?clean(raw.focusKey,MAX_ID):"",
      staleReference:!hostValid
        ?"The previously selected Navigator host is missing or stale. No neighboring host was selected."
        :clean(raw.staleReference,MAX_TEXT)
    });
  }
  function normalizeNavigationState(input={},options={}){
    const raw=object(input),legacy=object(raw.returnState||raw.navigatorReturn||raw.oscpReturnState);
    const view=normalizeViewState(raw,options),returnState=normalizeViewState(legacy,options);
    const activeRoute=normalizeRoute(raw.activeRoute||{destination:"navigator"}).route;
    return Object.freeze({...view,returnState,activeRoute,routeError:clean(raw.routeError,MAX_TEXT)||view.staleReference||returnState.staleReference});
  }

  function hostEntries(stateValue={}){
    return Object.entries(object(stateValue.hosts)).map(([key,value])=>({key,host:object(value),id:clean(value?.id||key,MAX_ID)})).filter(row=>row.id);
  }
  function hostIdentity(host={}){
    return clean(host.scopeTarget?.identity||host.ip||host.hostname,MAX_ID).toLowerCase();
  }
  function meaningfulServiceFact(value,assignedLabel=""){
    const text=clean(value,500).replace(/\s+/g," "),lower=text.toLowerCase();
    if(!text||["-","/","unknown","n/a","na","none","null","nil","not available","not applicable","undefined"].includes(lower))return "";
    if(/^[^a-z0-9]+$/i.test(text)||assignedLabel&&lower===clean(assignedLabel,240).toLowerCase())return "";
    return text;
  }
  function endpointIdentity(row={},host={},stateValue={}){
    const explicit=clean(row.id||row.endpointId,MAX_ID);
    if(explicit&&profileApi?.parseEndpointIdentity?.(explicit)&&validId(explicit))return explicit;
    const scoped=profileApi?.endpointIdentity?.(row,{
      host,
      engagementId:clean(row.engagementId||stateValue.projectId||stateValue.projectName,MAX_ID)
    });
    if(scoped&&validId(scoped))return scoped;
    if(explicit&&validId(explicit))return explicit;
    const protocol=token(row.protocol||"tcp"),port=Number(row.port);
    return protocol&&Number.isInteger(port)&&port>0&&port<=65535?`${protocol}:${port}`:"";
  }
  function endpointIdentified(row={}){
    if(row.identified===false)return false;
    const assigned=clean(row.serviceHint||row.serviceRaw,240);
    if(meaningfulServiceFact(row.product,assigned)||meaningfulServiceFact(row.version,assigned)||meaningfulServiceFact(row.cpe)||list(row.scripts).length||list(row.scriptResults).length)return true;
    const protocol=token(row.protocol||"tcp")||"tcp",port=Number(row.port),service=token(row.service||row.serviceRaw);
    if(!service||["unknown","unidentified","none","tcpwrapped"].includes(service))return false;
    if(Number.isInteger(port)&&[
      `${protocol}-${port}`,`${protocol}_${port}`,`${protocol}/${port}`,`${protocol}${port}`,String(port)
    ].includes(service))return false;
    return row.identified===true||!!service;
  }
  function endpointRows(host={},stateValue={}){
    const output=[],seen=new Set(),engagementOwners=new Set([
      clean(stateValue.projectId,MAX_ID),clean(stateValue.projectName,MAX_ID)
    ].filter(Boolean));
    list(host.serviceInventory).filter(activeRecord).forEach(row=>{
      if(clean(row.hostId,MAX_ID)&&clean(row.hostId,MAX_ID)!==clean(host.id,MAX_ID))return;
      const ownerEngagement=clean(row.engagementId||row.projectId,MAX_ID);
      if(ownerEngagement&&engagementOwners.size&&!engagementOwners.has(ownerEngagement))return;
      const id=endpointIdentity(row,host,stateValue);
      if(!id||seen.has(id)||output.length>=MAX_CONTEXT_LINKS)return;
      seen.add(id);output.push(row);
    });
    Object.entries(object(host.services)).forEach(([service,value])=>{
      if(output.length>=MAX_CONTEXT_LINKS)return;
      const record=object(value);
      if(record.checked===false||record.active===false)return;
      String(record.ports||"").split(/[\s,;/]+/).forEach(portText=>{
        const port=Number(portText),protocol=token(record.protocol||"tcp")||"tcp";
        const targetAddress=clean(host.ip,MAX_ID);
        const synthetic={engagementId:clean(stateValue.projectId||stateValue.projectName,MAX_ID),hostId:clean(host.id,MAX_ID),targetAddress,protocol,port};
        const id=endpointIdentity(synthetic,host,stateValue);
        if(!Number.isInteger(port)||port<1||port>65535||!validId(id)||seen.has(id)||output.length>=MAX_CONTEXT_LINKS)return;
        seen.add(id);
        output.push(Object.freeze({
          ...synthetic,id,endpointId:id,protocol,port,service:clean(service,160),identified:!!clean(service),
          active:true,sourcePath:`host.services.${clean(service,MAX_ID)}`
        }));
      });
    });
    return output;
  }
  function originIdentity(row={}){
    const explicit=clean(row.id||row.key,MAX_ID);
    if(explicit&&validId(explicit))return explicit;
    try{
      const url=new URL(clean(row.url||row.value,1000));
      return validId(`origin:${url.protocol.replace(":","")}:${url.hostname}:${url.port||(url.protocol==="https:"?443:80)}`)
        ?`origin:${url.protocol.replace(":","")}:${url.hostname}:${url.port||(url.protocol==="https:"?443:80)}`:"";
    }catch{return "";}
  }
  function originOwnerRows(host={},stateValue={}){
    const hostId=clean(host.id,MAX_ID),engagementOwners=new Set([
      clean(stateValue.projectId,MAX_ID),clean(stateValue.projectName,MAX_ID)
    ].filter(Boolean));
    const byOrigin=new Map();
    list(host.recon?.webTargets).filter(activeRecord).filter(row=>{
      const ownerHost=clean(row.hostId||row.assetId,MAX_ID);
      if(ownerHost&&ownerHost!==hostId)return false;
      const ownerEngagement=clean(row.engagementId||row.projectId,MAX_ID);
      return !ownerEngagement||!engagementOwners.size||engagementOwners.has(ownerEngagement);
    }).forEach(row=>{
      let parsed=null;try{parsed=new URL(clean(row.url||row.value,1000));}catch{}
      if(!parsed||!["http:","https:"].includes(parsed.protocol))return;
      const explicit=["web-origin","origin"].includes(token(row.recordRole||row.recordType));
      const scanOwned=token(row.sourceOwner)==="scan-import";
      const legacyRoot=!clean(row.originId,MAX_ID)&&(parsed.pathname||"/")==="/"&&!parsed.search;
      if(!explicit&&!scanOwned&&!legacyRoot)return;
      const key=parsed.origin,current=byOrigin.get(key);
      if(!current||explicit&&!current.explicit||scanOwned&&!current.scanOwned)byOrigin.set(key,{row,explicit,scanOwned});
    });
    return [...byOrigin.values()].map(entry=>entry.row);
  }
  function originRouteFacts(row={}){
    const explicitPort=Number(row.port),explicitAddress=clean(row.targetAddress||row.observedTargetAddress||row.address||row.host,MAX_ID).toLowerCase();
    try{
      const parsed=new URL(clean(row.url||row.value,1000));
      return {
        address:explicitAddress||clean(parsed.hostname,MAX_ID).toLowerCase(),
        port:Number.isInteger(explicitPort)&&explicitPort>0?explicitPort:Number(parsed.port||(parsed.protocol==="https:"?443:80)),
        protocol:token(parsed.protocol.replace(":",""))
      };
    }catch{
      return {address:explicitAddress,port:Number.isInteger(explicitPort)&&explicitPort>0?explicitPort:0,protocol:token(row.scheme||row.protocol)};
    }
  }
  function activeRecord(row){return row&&row.active!==false&&!row.deletedAt&&!row.archivedAt&&token(row.status)!=="archived";}
  function exactMatch(rows,id,identity){
    const matches=list(rows).filter(row=>clean(identity(row),MAX_ID)===id);
    if(matches.length===1&&!activeRecord(matches[0]))return {ok:false,reason:"The exact owning record is archived or inactive."};
    if(matches.length===1)return {ok:true,record:matches[0]};
    if(matches.length>1)return {ok:false,reason:"The exact owning record is ambiguous."};
    return {ok:false,reason:"The exact owning record is missing or stale."};
  }
  function exactEndpointMatch(rows,id,host,stateValue){
    const exact=exactMatch(rows,id,row=>endpointIdentity(row,host,stateValue));
    if(exact.ok)return exact;
    const explicitMatches=list(rows).filter(row=>clean(row.id||row.endpointId,MAX_ID)===id);
    if(explicitMatches.length===1&&!activeRecord(explicitMatches[0]))return {ok:false,reason:"The exact owning record is archived or inactive."};
    if(explicitMatches.length===1)return {ok:true,record:explicitMatches[0]};
    if(explicitMatches.length>1)return {ok:false,reason:"The exact endpoint owner is ambiguous."};
    if(!/^(tcp|udp):(\d{1,5})$/i.test(id))return exact;
    const [,protocolText,portText]=id.match(/^(tcp|udp):(\d{1,5})$/i),port=Number(portText);
    const matches=list(rows).filter(row=>
      token(row.protocol||"tcp")===protocolText.toLowerCase()&&Number(row.port)===port
    );
    if(matches.length===1&&!activeRecord(matches[0]))return {ok:false,reason:"The exact owning record is archived or inactive."};
    if(matches.length===1)return {ok:true,record:matches[0]};
    if(matches.length>1)return {ok:false,reason:"The legacy endpoint route is ambiguous across address-aware owners."};
    return exact;
  }
  function matchEngagement(stateValue,route){
    const state=object(stateValue),id=clean(state.projectId,MAX_ID),name=clean(state.projectName,MAX_ID);
    const exactOwners=new Set([id,name].filter(Boolean));
    if(route.engagementId&&!exactOwners.has(route.engagementId))return false;
    if(route.engagementName&&route.engagementName!==name)return false;
    return !!(route.engagementId||route.engagementName);
  }
  function collectImports(host){
    return [
      ...list(host.scanArtifacts),...list(host.recon?.webImports),...list(host.postExploitation?.imports),
      ...list(host.postexpImports),
      ...list(host.imports),...list(host.importReviews)
    ];
  }
  function collectEvidenceResults(options={}){
    return list(options.evidenceResults).filter(row=>row&&typeof row==="object");
  }
  function artifactRevisionRows(artifact={}){
    const rows=list(artifact.revisions).filter(row=>row&&typeof row==="object").map((row,index)=>({...row,revision:Math.max(1,Number(row.revision)||index+1)}));
    if(!rows.length)rows.push({...artifact,revision:Math.max(1,Number(artifact.currentRevision)||1)});
    return rows;
  }
  function collectProof(host){
    return [
      ...list(host.evidence).filter(row=>["proof","local-proof","proof-file"].includes(token(row.type))),
      ...list(host.exploitAttempts).filter(row=>object(row.success).proof&&Object.keys(object(row.success.proof)).length)
    ];
  }
  function collectFindings(stateValue,host){
    const hostId=clean(host.id,MAX_ID);
    return [...list(host.findings),...list(stateValue.findings).filter(row=>clean(row.assetId||row.hostId,MAX_ID)===hostId)];
  }

  function resolveRoute(stateValue={},routeInput={},options={}){
    const normalized=normalizeRoute(routeInput);
    if(!normalized.valid)return Object.freeze({ok:false,reason:normalized.errors.join(" "),route:normalized.route});
    const route=normalized.route,state=object(stateValue);
    if(route.destination==="navigator"&&!route.hostId)return Object.freeze({ok:true,route,owner:{kind:"navigator",record:null}});
    if(!matchEngagement(state,route))return Object.freeze({ok:false,reason:"The route belongs to a different or stale engagement.",route});
    const hosts=hostEntries(state),hostMatch=route.hostId?exactMatch(hosts,route.hostId,row=>row.id):{ok:true,record:null};
    if(!hostMatch.ok)return Object.freeze({ok:false,reason:hostMatch.reason,route});
    const host=hostMatch.record?.host||null;
    const requireHost=[
      "host-workbench","host-profile","recon","web-app-review","endpoint","web-origin","lead","investigation",
      "access-context","methodology","import","coverage","proof","evidence","finding",
      "reference-note","record-outcome","host-enumeration","credentials","movement",
      "attack-map","investigations-evidence","progress","review","exploitation-path"
    ];
    if((requireHost.includes(route.destination)||route.destination==="navigator"&&route.hostId)&&!host)return Object.freeze({ok:false,reason:"This destination requires an exact host owner.",route});
    const owners={host};
    const checks=[
      ["endpoint",route.endpointId,endpointRows(host||{},state),row=>endpointIdentity(row,host||{},state)],
      ["origin",route.originId,list(host?.recon?.webTargets),originIdentity],
      ["lead",route.leadId,list(host?.vulnerabilityLeads),row=>row.id],
      ["peasFinding",route.peasFindingId,list(host?.peas?.findings),row=>row.id],
      ["investigation",route.investigationId,list(host?.exploitAttempts),row=>row.id],
      ["accessContext",route.accessContextId,list(host?.accessContexts),row=>row.id],
      ["proof",route.proofItemId,collectProof(host),row=>row.id||row.success?.proof?.id],
      ["importItem",route.importItemId,collectImports(host||{}),row=>row.id||row.artifactId],
      ["logicalResult",route.logicalResultId,collectEvidenceResults(options),row=>row.routeId||row.logicalResultId||row.id],
      ["artifact",route.artifactId,list(host?.scanArtifacts),row=>row.id],
      ["evidence",route.evidenceId,list(host?.evidence),row=>row.id],
      ["finding",route.findingId,collectFindings(state,host||{}),row=>row.id],
      ["reportBlocker",route.reportBlockerId,list(options.reportBlockers),row=>row.id],
      ["note",route.noteId,list(options.notes),row=>row.id]
    ];
    for(const [key,id,rows,identity] of checks){
      if(!id)continue;
      const match=key==="endpoint"
        ?exactEndpointMatch(rows,id,host||{},state)
        :exactMatch(rows,id,identity);
      if(!match.ok)return Object.freeze({ok:false,reason:match.reason,route});
      owners[key]=match.record;
    }
    if(route.endpointId&&route.originId&&owners.endpoint&&owners.origin){
      const linkedEndpoint=clean(owners.origin.endpointId||owners.origin.serviceEndpointId,MAX_ID);
      const routeEndpoint=endpointIdentity(owners.endpoint,host||{},state);
      if(linkedEndpoint&&linkedEndpoint!==routeEndpoint&&linkedEndpoint!==route.endpointId){
        return Object.freeze({ok:false,reason:"The exact web origin belongs to a different endpoint.",route});
      }
      if(!linkedEndpoint){
        const originFacts=originRouteFacts(owners.origin),endpointAddress=clean(owners.endpoint.targetAddress||owners.endpoint.observedTargetAddress||owners.endpoint.address||host?.ip,MAX_ID).toLowerCase();
        if(originFacts.port!==Number(owners.endpoint.port)||originFacts.address&&endpointAddress&&originFacts.address!==endpointAddress){
          return Object.freeze({ok:false,reason:"The exact web origin does not match the routed endpoint.",route});
        }
      }
    }
    if(owners.logicalResult&&owners.artifact&&!list(owners.logicalResult.artifactIds).map(value=>clean(value,MAX_ID)).includes(route.artifactId)){
      return Object.freeze({ok:false,reason:"The exact artifact belongs to a different Evidence result.",route});
    }
    if(owners.logicalResult&&route.importItemId&&route.artifactId&&route.importItemId!==route.artifactId){
      return Object.freeze({ok:false,reason:"The exact import owner does not match the routed Evidence artifact.",route});
    }
    if(route.artifactRevision){
      const revision=Number(route.artifactRevision);
      if(!owners.artifact||!Number.isInteger(revision)||revision<1||!artifactRevisionRows(owners.artifact).some(row=>row.revision===revision)){
        return Object.freeze({ok:false,reason:"The exact artifact revision is missing or stale.",route});
      }
    }
    if(owners.lead&&route.endpointId){
      const linkedEndpoint=clean(owners.lead.endpointId,MAX_ID);
      if(!linkedEndpoint||linkedEndpoint!==route.endpointId)return Object.freeze({ok:false,reason:"The exact Lead does not own the routed endpoint.",route});
    }
    if(owners.lead&&route.originId){
      const linkedOrigin=clean(owners.lead.originId||owners.lead.webTargetId,MAX_ID);
      if(!linkedOrigin||linkedOrigin!==route.originId)return Object.freeze({ok:false,reason:"The exact Lead does not own the routed web origin.",route});
    }
    if(owners.lead&&route.artifactId){
      const linkedArtifact=clean(owners.lead.sourceArtifactId||owners.lead.artifactId,MAX_ID);
      if(!linkedArtifact||linkedArtifact!==route.artifactId)return Object.freeze({ok:false,reason:"The exact Lead does not own the routed artifact.",route});
      const linkedRevision=Number(owners.lead.sourceRevision||owners.lead.revision)||0;
      if(route.artifactRevision&&(!linkedRevision||linkedRevision!==Number(route.artifactRevision)))return Object.freeze({ok:false,reason:"The exact Lead does not own the routed source revision.",route});
    }
    if(owners.lead&&route.objectiveId){
      const linkedObjective=clean(owners.lead.objectiveId||owners.lead.objective,MAX_ID);
      if(!linkedObjective||linkedObjective!==route.objectiveId)return Object.freeze({ok:false,reason:"The exact Lead does not own the routed methodology objective.",route});
    }
    if(owners.lead&&route.methodologyInstanceId){
      const linkedInstance=clean(owners.lead.methodologyInstanceId,MAX_ID);
      if(!linkedInstance||linkedInstance!==route.methodologyInstanceId)return Object.freeze({ok:false,reason:"The exact Lead does not own the routed methodology instance.",route});
    }
    if(owners.lead&&route.accessContextId){
      const linkedAccess=clean(owners.lead.accessContextId,MAX_ID);
      if(!linkedAccess||linkedAccess!==route.accessContextId)return Object.freeze({ok:false,reason:"The exact Lead does not own the routed access context.",route});
    }
    if(owners.lead&&route.focusedRecordId&&route.focusedRecordId!==clean(owners.lead.id,MAX_ID)){
      return Object.freeze({ok:false,reason:"The focused record does not match the exact routed Lead.",route});
    }
    const currentEngagementOwners=new Set([clean(state.projectId,MAX_ID),clean(state.projectName,MAX_ID)].filter(Boolean)),hostId=clean(host?.id,MAX_ID);
    for(const [key,record] of Object.entries(owners)){
      if(key==="host"||!record||typeof record!=="object")continue;
      const recordHostId=clean(record.hostId||record.assetId,MAX_ID);
      if(recordHostId&&recordHostId!==hostId)return Object.freeze({ok:false,reason:"The exact owning record belongs to a different host.",route});
      const recordEngagement=clean(record.engagementId||record.projectId,MAX_ID);
      if(recordEngagement&&currentEngagementOwners.size&&!currentEngagementOwners.has(recordEngagement))return Object.freeze({ok:false,reason:"The exact owning record belongs to a different engagement.",route});
    }
    if(route.targetAddress){
      const addressedOwner=owners.endpoint||owners.lead||owners.logicalResult;
      const observed=clean(addressedOwner?.targetAddress||addressedOwner?.observedTargetAddress||addressedOwner?.address,MAX_ID).toLowerCase();
      if(addressedOwner&&!observed)return Object.freeze({ok:false,reason:"The exact routed record has no address owner and cannot be opened safely.",route});
      if(addressedOwner&&observed!==route.targetAddress.toLowerCase())return Object.freeze({ok:false,reason:"The exact routed record belongs to a different target address.",route});
    }
    const primaryKey=({
      endpoint:"endpoint","web-origin":"origin","web-app-review":"origin",lead:"lead",investigation:"investigation",
       "access-context":"accessContext",proof:"proof",import:route.logicalResultId?"logicalResult":route.artifactId?"artifact":"importItem",evidence:"evidence",
      finding:"finding","host-enumeration":route.peasFindingId?"peasFinding":"",
      report:"reportBlocker","reference-note":"note","record-outcome":route.leadId?"lead":"investigation"
    })[route.destination];
    return Object.freeze({ok:true,route,owner:{kind:route.destination,host,record:owners[primaryKey]||host||null,records:Object.freeze(owners)}});
  }

  function linkedScopeTargets(stateValue,host){
    const hostId=clean(host.id,MAX_ID),identity=hostIdentity(host);
    return list(stateValue.engagementConfig?.scope?.targets).filter(row=>{
      const linked=clean(row.hostId,MAX_ID);
      return linked?linked===hostId:!linked&&clean(row.identity,MAX_ID).toLowerCase()===identity&&row.reviewState==="migrated";
    });
  }
  function scopeDimension(stateValue,host,label){
    const rows=linkedScopeTargets(stateValue,host);
    if(!rows.length)return dimension("scope",label,STATUS.UNKNOWN,{reason:"No exact structured scope target is linked to this host.",source:"engagementConfig.scope.targets"});
    const dispositions=new Set(rows.map(row=>token(row.disposition)));
    if(rows.some(row=>row.status==="conflict"||row.reviewState==="needs-review")||dispositions.size>1){
      return dimension("scope",label,STATUS.CONFLICT,{reason:"Linked target scope records conflict or require review.",source:"engagementConfig.scope.targets",count:rows.length});
    }
    if(dispositions.has("out-of-scope"))return dimension("scope",label,STATUS.BLOCKED,{reason:"The exact linked target is explicitly out of scope.",source:"engagementConfig.scope.targets",count:rows.length});
    return dimension("scope",label,STATUS.COMPLETE,{reason:"An exact valid in-scope target owns this host.",source:"engagementConfig.scope.targets",count:rows.length});
  }
  function osDimension(host,label){
    const row=object(host.osResolution),state=token(row.status),family=token(row.family);
    if(state==="conflict")return dimension("os",label,STATUS.CONFLICT,{reason:"Current active sourced OS observations conflict.",source:"host.osResolution"});
    if(state==="locked"){
      const conflicts=new Set(list(row.conflictObservationIds).map(value=>clean(value,MAX_ID)));
      const strongOpposition=list(host.osObservations).filter(item=>conflicts.has(clean(item.id,MAX_ID))&&Number(item.rank)>=60&&item.active!==false);
      if(strongOpposition.length)return dimension("os",label,STATUS.CONFLICT,{reason:"The manual OS lock conflicts with strong current evidence.",source:"host.osResolution"});
    }
    if(!family||family==="unknown"||state==="unknown"||state==="inferred"){
      const observations=list(host.osObservations).filter(item=>item&&item.active!==false&&["linux","windows"].includes(token(item.family))).map(item=>[
        clean(item.id,MAX_ID),token(item.family),token(item.authority),clean(item.observedAt,160)
      ].join("|")).sort();
      const signature=JSON.stringify({
        observations,status:state||"unknown",family:family||"unknown",
        primary:list(row.primaryObservationIds).slice().sort(),conflicts:list(row.conflictObservationIds).slice().sort()
      });
      const disposition=object(host.osReviewDisposition),deferred=state==="unknown"&&family==="unknown"&&disposition.state==="deferred"&&disposition.evidenceSignature===signature;
      return dimension("os",label,deferred?STATUS.STALE:STATUS.UNKNOWN,{
        reason:deferred?"Unknown retained until new OS evidence is available; revisit remains open.":state==="inferred"?"Only weak OS hints are active.":"No authoritative OS resolution is active.",
        source:"host.osResolution",meta:{family:"unknown",confidence:clean(row.confidence||"Unknown",80),deferred}
      });
    }
    return dimension("os",label,STATUS.COMPLETE,{reason:`Resolved as ${family} from active sourced observations.`,source:"host.osResolution",meta:{family,confidence:clean(row.confidence||"Recorded",80)}});
  }
  function scanDimension(host,key,label){
    const entry=object(host.scanEvidence?.[key]),hasContent=clean(host.scans?.[key],1000).length>0,ports=list(entry.ports);
    if(["failed","conflict"].includes(token(entry.resultState)))return dimension(key,label,entry.resultState==="conflict"?STATUS.CONFLICT:STATUS.BLOCKED,{reason:clean(entry.reason)||"Recorded scan evidence did not complete this objective.",source:`host.scanEvidence.${key}`,count:ports.length});
    if(entry.confirmed===true){
      if(!ports.length&&key!=="tcp")return dimension(key,label,STATUS.CONFIRMED_NEGATIVE,{reason:clean(entry.reason)||"Confirmed coverage recorded no open endpoints.",source:`host.scanEvidence.${key}`,count:0});
      return dimension(key,label,STATUS.COMPLETE,{reason:clean(entry.reason)||"Canonical scan evidence confirms this coverage objective.",source:`host.scanEvidence.${key}`,count:ports.length});
    }
    if(token(entry.coverage)==="partial")return dimension(key,label,STATUS.PARTIAL,{reason:clean(entry.reason)||"Only partial coverage is supported.",source:`host.scanEvidence.${key}`,count:ports.length});
    if(hasContent||entry.importedRecorded===true)return dimension(key,label,STATUS.IN_PROGRESS,{reason:"Evidence exists but does not confirm complete coverage.",source:`host.scanEvidence.${key}`,count:ports.length});
    return dimension(key,label,STATUS.NOT_STARTED,{reason:"No accepted coverage evidence is recorded.",source:`host.scanEvidence.${key}`,count:0});
  }
  function endpointsDimension(host,label){
    const rows=endpointRows(host),unresolved=rows.filter(row=>!endpointIdentified(row)).length;
    if(!rows.length)return dimension("endpoints",label,STATUS.UNKNOWN,{reason:"No canonical endpoint record is available; absence is not a confirmed negative.",source:"host.serviceInventory|host.services",count:0});
    if(unresolved)return dimension("endpoints",label,STATUS.PARTIAL,{reason:`${unresolved} endpoint${unresolved===1?"":"s"} still require service identity review.`,source:"host.serviceInventory|host.services",count:rows.length,total:unresolved});
    return dimension("endpoints",label,STATUS.COMPLETE,{reason:"Every current endpoint has a recorded service identity.",source:"host.serviceInventory|host.services",count:rows.length});
  }
  function udpServiceDimension(host,label){
    const entry=object(host.scanEvidence?.udp),ports=list(entry.ports).map(Number).filter(value=>value>0),rows=endpointRows(host).filter(row=>row.protocol==="udp");
    if(entry.confirmed===true&&!ports.length)return dimension("udp-service",label,STATUS.NOT_APPLICABLE,{reason:"Confirmed UDP coverage found no endpoint requiring service identification.",source:"host.scanEvidence.udp",count:0});
    if(entry.confirmed!==true&&!rows.length)return dimension("udp-service",label,STATUS.NOT_STARTED,{reason:"UDP service identification follows exact UDP port discovery.",source:"host.scanEvidence.udp|host.serviceInventory",count:0});
    const applicable=rows.filter(row=>ports.length===0||ports.includes(Number(row.port))),identified=applicable.filter(row=>row.identified);
    if(!applicable.length)return dimension("udp-service",label,STATUS.UNKNOWN,{reason:"UDP endpoint state exists but no canonical endpoint owner is available.",source:"host.serviceInventory",count:0});
    if(identified.length===applicable.length)return dimension("udp-service",label,STATUS.COMPLETE,{reason:"Every discovered UDP endpoint has credible service identity evidence.",source:"host.serviceInventory",count:identified.length,total:applicable.length});
    if(identified.length)return dimension("udp-service",label,STATUS.PARTIAL,{reason:`${identified.length} of ${applicable.length} UDP endpoints have credible service identity evidence.`,source:"host.serviceInventory",count:identified.length,total:applicable.length});
    return dimension("udp-service",label,STATUS.NOT_STARTED,{reason:"Discovered UDP endpoints still require credible service identification; assigned port names are not confirmation.",source:"host.serviceInventory",count:0,total:applicable.length});
  }
  function originsDimension(stateValue,host,label){
    const rows=originOwnerRows(host,stateValue);
    const unresolved=list(host.recon?.webTargets).filter(activeRecord).filter(row=>row.unresolved===true||row.kind==="path").length;
    const confirmedWebEndpoints=endpointRows(host,stateValue).filter(row=>endpointIdentified(row)&&["http","https"].includes(token(row.service||row.serviceRaw)));
    if(!rows.length&&confirmedWebEndpoints.length){
      const first=confirmedWebEndpoints[0];
      return dimension("origins",label,STATUS.PARTIAL,{
        reason:confirmedWebEndpoints.length===1
          ?`Confirm the exact HTTP origin for ${String(first.protocol||"tcp").toUpperCase()} ${Number(first.port)}.`
          :`Confirm exact HTTP origins for ${confirmedWebEndpoints.length} identified web endpoints.`,
        source:"host.serviceInventory|host.recon.webTargets",count:0,total:confirmedWebEndpoints.length
      });
    }
    if(!rows.length&&unresolved)return dimension("origins",label,STATUS.PARTIAL,{reason:`${unresolved} web observation${unresolved===1?"":"s"} require an exact origin mapping.`,source:"host.recon.webTargets",count:0,total:unresolved});
    if(!rows.length)return dimension("origins",label,STATUS.UNKNOWN,{reason:"No confirmed HTTP origin is currently recorded.",source:"host.recon.webTargets",count:0});
    if(unresolved)return dimension("origins",label,STATUS.PARTIAL,{reason:`${unresolved} path-only web observation${unresolved===1?"":"s"} still require exact origin mapping.`,source:"host.recon.webTargets",count:rows.length,total:unresolved});
    return dimension("origins",label,STATUS.COMPLETE,{reason:`${rows.length} exact HTTP origin${rows.length===1?" is":"s are"} recorded.`,source:"host.recon.webTargets",count:rows.length,total:rows.length});
  }
  function accessDimension(host,label){
    const rows=list(host.accessContexts).filter(activeRecord);
    const interactive=rows.filter(row=>typeof profileApi.interactiveAccess==="function"?profileApi.interactiveAccess(row):true);
    if(!interactive.length)return dimension("access",label,STATUS.NOT_STARTED,{reason:rows.length?"Authenticated or candidate state exists, but no valid active interactive host access is confirmed.":"No current verified interactive access context is active.",source:"host.accessContexts",count:0,total:rows.length,meta:{interactiveCount:0,activeCount:rows.length}});
    const ambiguous=interactive.filter(row=>!clean(row.principal)||["unknown","user"].includes(token(row.principal))).length;
    if(ambiguous)return dimension("access",label,STATUS.PARTIAL,{reason:`${ambiguous} interactive context${ambiguous===1?"":"s"} require principal review.`,source:"host.accessContexts",count:interactive.length,total:ambiguous,meta:{interactiveCount:interactive.length,activeCount:rows.length}});
    return dimension("access",label,STATUS.COMPLETE,{reason:"Current verified interactive access contexts retain exact principals and ownership.",source:"host.accessContexts",count:interactive.length,total:rows.length,meta:{interactiveCount:interactive.length,activeCount:rows.length}});
  }
  function reachabilityDimension(stateValue,host,label){
    const result=typeof profileApi.addressReachability==="function"
      ?profileApi.addressReachability(host,stateValue)
      :{hostReachable:true,state:"reachable",addresses:[],endpointForwards:[],blocked:[]};
    if(result.hostReachable)return dimension("reachability",label,STATUS.COMPLETE,{reason:result.directAddresses?.length?"At least one exact host address is directly reachable from the operator.":"An active routed tunnel explicitly covers an exact host address.",source:"host.networkAddresses|state.tunnels",count:result.addresses.length,meta:{...result}});
    if(result.state==="endpoint-only")return dimension("reachability",label,STATUS.PARTIAL,{reason:"Only exact recorded forwarded endpoints are reachable; broader host discovery is not implied.",source:"host.networkAddresses|state.tunnels",count:result.endpointForwards.length,meta:{...result}});
    if(result.state==="unreachable")return dimension("reachability",label,STATUS.BLOCKED,{reason:"No host address is currently reachable for broad discovery. Record or activate an exact route, pivot, or tunnel.",source:"host.networkAddresses|state.tunnels",count:result.addresses.length,meta:{...result}});
    return dimension("reachability",label,STATUS.UNKNOWN,{reason:"Host-address reachability is unknown. AEROS did not test the target network.",source:"host.networkAddresses",count:result.addresses.length,meta:{...result}});
  }
  function leadsDimension(host,label){
    const rows=list(host.vulnerabilityLeads).filter(activeRecord),open=rows.filter(row=>token(row.status)==="lead"),stale=rows.filter(row=>row.stale===true||token(row.status)==="stale");
    if(stale.length)return dimension("leads",label,STATUS.STALE,{reason:`${stale.length} Lead${stale.length===1?"":"s"} require revisit.`,source:"host.vulnerabilityLeads",count:open.length,total:rows.length});
    if(open.length)return dimension("leads",label,STATUS.IN_PROGRESS,{reason:`${open.length} unresolved Lead${open.length===1?"":"s"} remain operator-controlled hypotheses.`,source:"host.vulnerabilityLeads",count:open.length,total:rows.length});
    if(rows.length)return dimension("leads",label,STATUS.COMPLETE,{reason:"Every retained Lead has an explicit verified or not-applicable disposition.",source:"host.vulnerabilityLeads",count:0,total:rows.length});
    return dimension("leads",label,STATUS.NOT_STARTED,{reason:"No Lead has been recorded.",source:"host.vulnerabilityLeads",count:0});
  }
  function credentialDimension(stateValue,host,label){
    const hostId=clean(host.id,MAX_ID);
    const hostRows=list(host.credentials),starting=list(stateValue.engagementConfig?.startingAccess?.entries).filter(row=>clean(row.hostId,MAX_ID)===hostId);
    const candidates=[...hostRows,...starting].filter(row=>row.active!==false&&(row.verified!==true||["candidate","unknown",""].includes(token(row.status||row.classification))));
    if(candidates.length)return dimension("credential-revisit",label,STATUS.STALE,{reason:`${candidates.length} candidate credential${candidates.length===1?"":"s"} require explicit endpoint/context retest.`,source:"host.credentials|engagementConfig.startingAccess.entries",count:candidates.length});
    return dimension("credential-revisit",label,STATUS.NOT_STARTED,{reason:"No exact host-owned candidate credential creates revisit work.",source:"host.credentials|engagementConfig.startingAccess.entries",count:0});
  }
  function methodologyDimension(host,items,label,id,stages){
    const contexts=list(host.accessContexts).filter(activeRecord).filter(row=>typeof profileApi.interactiveAccess==="function"?profileApi.interactiveAccess(row):true);
    if(!contexts.length)return dimension(id,label,STATUS.NOT_APPLICABLE,{reason:"No valid active interactive access context makes this work applicable.",source:"host.accessContexts",meta:{applicable:false}});
    const rows=list(items).filter(row=>stages.includes(token(row.stage))&&(!row.contextId||contexts.some(context=>context.id===row.contextId)));
    if(!rows.length)return dimension(id,label,STATUS.UNKNOWN,{reason:"No supported objective is currently projected for this interactive access context.",source:"methodology.items",meta:{applicable:true}});
    const states=rows.map(row=>token(row.status||row.state||"todo"));
    const stale=states.filter(value=>["stale","revisit"].includes(value)).length;
    const complete=states.filter(value=>["done","complete","confirmed"].includes(value)).length;
    const explicitNa=rows.filter(row=>token(row.status||row.state)==="na"&&clean(row.reason)&&clean(row.decisionSource)).length;
    if(stale)return dimension(id,label,STATUS.STALE,{reason:`${stale} objective${stale===1?"":"s"} reopened after new context.`,source:"methodology.items",count:complete,total:rows.length});
    if(complete+explicitNa===rows.length)return dimension(id,label,STATUS.COMPLETE,{reason:"All applicable objectives are complete or explicitly reasoned not applicable.",source:"methodology.items",count:rows.length,total:rows.length});
    if(complete)return dimension(id,label,STATUS.PARTIAL,{reason:`${complete} of ${rows.length} applicable objectives are complete.`,source:"methodology.items",count:complete,total:rows.length});
    return dimension(id,label,STATUS.NOT_STARTED,{reason:"Applicable context-owned objectives remain untouched.",source:"methodology.items",count:0,total:rows.length});
  }
  function readinessDimensions(host,assessment,labels){
    if(!assessment)return [
      dimension("proof",labels.proof,STATUS.UNKNOWN,{reason:"The current proof projection is unavailable.",source:"readiness.assessHost"}),
      dimension("report",labels.report,STATUS.UNKNOWN,{reason:"The current readiness projection is unavailable.",source:"readiness.assessHost"})
    ];
    const proofIssues=list(assessment.issues).filter(row=>token(row.category)==="proof"),applicability=object(assessment.proofApplicability);
    const localApplicable=object(applicability.local).applicable===true,privilegedApplicable=object(applicability.privileged).applicable===true,proofApplicable=localApplicable||privilegedApplicable;
    const proofState=!proofApplicable?STATUS.NOT_APPLICABLE:proofIssues.length?STATUS.PARTIAL:STATUS.COMPLETE;
    const reportState=assessment.state==="ready"?STATUS.COMPLETE:assessment.state==="blocked"?STATUS.BLOCKED:assessment.state==="review"?STATUS.PARTIAL:STATUS.IN_PROGRESS;
    return [
      dimension("proof",labels.proof,proofState,{reason:!proofApplicable?"Proof is not applicable until valid user/elevated interactive access exists.":proofIssues.length?`${proofIssues.length} exact proof requirement${proofIssues.length===1?"":"s"} remain.`:"No proof blocker is reported for current access.",source:"readiness.assessHost",count:proofIssues.length,meta:{applicable:proofApplicable,localApplicable,privilegedApplicable}}),
      dimension("report",labels.report,reportState,{reason:clean(assessment.stateLabel)||"Readiness is projected from canonical report records.",source:"readiness.assessHost",count:Number(assessment.blockers)||0,total:Number(assessment.issues?.length)||0})
    ];
  }
  function saveDimension(saveFact,label){
    const fact=object(saveFact),value=STATUS_VALUES.includes(fact.state)?fact.state:STATUS.UNKNOWN;
    return dimension("save",label,value,{reason:clean(fact.reason)||"The current runtime does not expose a verified last-save timestamp.",source:clean(fact.source,MAX_ID)||"persistence.current",meta:{label:clean(fact.label,120)}});
  }

  function makeRoute(stateValue,host,destination,extra={}){
    return normalizeRoute({
      destination,
      engagementId:clean(stateValue.projectId,MAX_ID),
      engagementName:clean(stateValue.projectName,MAX_ID),
      hostId:clean(host?.id,MAX_ID),
      ...extra
    }).route;
  }
  function action(stateValue,host,priority,kind,title,reason,source,route,options={}){
    const hostId=clean(host?.id,MAX_ID),ownerId=clean(options.ownerId,MAX_ID),ownerType=clean(options.ownerType,80);
    const normalizedKind=token(kind),normalizedTitle=clean(title,160),normalizedReason=clean(reason);
    const normalizedSource=Object.freeze({type:clean(source.type,80),id:clean(source.id,MAX_ID),path:clean(source.path,160)});
    const routeIdentity=[route?.destination,route?.objectiveId,route?.endpointId,route?.originId,route?.leadId,route?.investigationId,route?.accessContextId,route?.proofItemId,route?.findingId,route?.reportBlockerId,route?.methodologyInstanceId].map(value=>clean(value,MAX_ID)).join("|");
    const skipIdentity=`${hostId}|${normalizedKind}|${ownerType}|${ownerId}|${normalizedSource.type}|${normalizedSource.id}|${routeIdentity}`;
    const skipKey=`nav-skip-${stableKey(skipIdentity)}`;
    const evidenceSignature=`nav-evidence-${stableKey(`${skipIdentity}|${normalizedTitle}|${normalizedReason}|${normalizedSource.path}|${token(options.evidenceState)}|${options.evidenceReviewRequired===true}`)}`;
    return Object.freeze({
      id:`nav-action-${priority}-${stableKey(`${hostId}|${kind}|${ownerId}|${title}|${source}`)}`,
      priority,
      rank:priority,
      kind:normalizedKind,
      title:normalizedTitle,
      reason:normalizedReason,
      source:normalizedSource,
      owner:Object.freeze({hostId,narrowerType:ownerType,narrowerId:ownerId}),
      route,
      skipKey,
      evidenceSignature,
      operatorReview:options.operatorReview===true,
      evidenceState:token(options.evidenceState),
      evidenceReviewRequired:options.evidenceReviewRequired===true,
      group:GROUPS.includes(options.group)?options.group:"next-actions"
    });
  }
  function hostActions(stateValue,host,dimensions,options={}){
    const byId=Object.fromEntries(dimensions.map(row=>[row.id,row])),output=[];
    const add=(...args)=>output.push(action(stateValue,host,...args));
    const interactiveContexts=list(host.accessContexts).filter(activeRecord).filter(context=>profileApi?.interactiveAccess?.(context)===true);
    const activeInteractive=interactiveContexts.find(context=>clean(context.id,MAX_ID)===clean(host.currentAccessContextId,MAX_ID))||interactiveContexts[0]||null;
    ["scope","os"].forEach(id=>{
      const row=byId[id];
      if(row&&(id==="scope"?[STATUS.CONFLICT,STATUS.BLOCKED,STATUS.UNKNOWN]:[STATUS.CONFLICT,STATUS.BLOCKED]).includes(row.state)){
        const title=id==="scope"?"Review scope status":"Review operating-system identity";
        add(1,`${id}-integrity`,title,row.reason,{type:"dimension",id,path:row.source},makeRoute(stateValue,host,id==="scope"?"recon":"host-profile",{subview:id==="scope"?"all-hosts":""}),{operatorReview:true,group:"conflicts"});
      }
    });
    const reachability=byId.reachability,hostReachable=reachability?.meta?.hostReachable!==false;
    if(reachability&&[STATUS.BLOCKED,STATUS.UNKNOWN,STATUS.PARTIAL].includes(reachability.state)){
      add(1.8,"reachability","Review target reachability",reachability.reason,{type:"network-address",id:"reachability",path:reachability.source},makeRoute(stateValue,host,"host-profile",{subview:"addresses"}),{operatorReview:true,group:"revisit"});
    }
    [["port","TCP Port Discovery","tcp-port-discovery"],["tcp","TCP Service Discovery","tcp-service-discovery"],["udp","UDP Port Discovery","udp-port-discovery"],["udp-service","UDP Service Discovery","udp-service-discovery"]].forEach(([id,title,subview],index)=>{
      const row=byId[id];
      if(hostReachable&&row&&![STATUS.COMPLETE,STATUS.CONFIRMED_NEGATIVE,STATUS.NOT_APPLICABLE].includes(row.state)){
        add(2+(index*.1),`${id}-foundation`,title,row.reason,{type:"scan-coverage",id,path:row.source},makeRoute(stateValue,host,"coverage",{subview,objectiveId:subview,targetAddress:clean(host.ip,MAX_ID)}),{operatorReview:row.operatorReview,group:"required-coverage"});
      }
    });
    const revisit=byId["credential-revisit"];
    if(revisit?.state===STATUS.STALE)add(3,"credential-revisit","Retest candidate credentials",revisit.reason,{type:"credential",id:"candidate",path:revisit.source},makeRoute(stateValue,host,"methodology",{subview:"revisit"}),{operatorReview:true,group:"revisit"});
    const endpoint=byId.endpoints;
    if(endpoint&&![STATUS.COMPLETE,STATUS.CONFIRMED_NEGATIVE,STATUS.NOT_APPLICABLE].includes(endpoint.state)){
       const unresolved=endpointRows(host,stateValue).filter(row=>!endpointIdentified(row));
      const reachable=unresolved.filter(row=>hostReachable||(typeof profileApi.endpointReachable==="function"&&profileApi.endpointReachable(host,row,stateValue)));
      if(reachable.length){
        const exact=reachable.length===1?reachable[0]:null;
        const exactId=exact?endpointIdentity(exact,host,stateValue):"";
        const targetAddress=exact?clean(exact.targetAddress||exact.observedTargetAddress||exact.address||host.ip,MAX_ID):"";
        const serviceCoverageComplete=byId.tcp?.state===STATUS.COMPLETE&&reachable.every(row=>token(row.serviceScanCoverageState)==="completed");
        const title=exact
          ?serviceCoverageComplete?`Review service evidence on ${String(exact.protocol||"tcp").toUpperCase()} ${Number(exact.port)}`:`Identify service on ${String(exact.protocol||"tcp").toUpperCase()} ${Number(exact.port)}`
          :serviceCoverageComplete?"Review unresolved service evidence":"Identify services on unresolved endpoints";
        add(4,"endpoint-gap",title,endpoint.reason,{type:"endpoint-inventory",id:exactId||"serviceInventory",path:endpoint.source},makeRoute(stateValue,host,"recon",{subview:"services",objectiveId:"tcp-service-discovery",targetAddress,endpointId:exactId,focusedRecordId:exactId}),{ownerType:exact?"endpoint":"endpoint-group",ownerId:exactId,operatorReview:endpoint.operatorReview,group:serviceCoverageComplete?"revisit":"required-coverage"});
      }
    }
    const origins=byId.origins;
    if(origins&&[STATUS.PARTIAL,STATUS.STALE,STATUS.CONFLICT].includes(origins.state)){
      add(4.9,"origin-gap","Reconcile web origin ownership",origins.reason,{type:"web-origin-inventory",id:"webTargets",path:origins.source},makeRoute(stateValue,host,"recon",{subview:"origins"}),{operatorReview:true,group:"revisit"});
    }
    const endpointOwners=endpointRows(host,stateValue),originOwners=originOwnerRows(host,stateValue);
    const methodologySeen=new Set();
    list(options.methodology).filter(row=>{
      const statusRecord=object(row.status),statusValue=token(statusRecord.state||row.status||row.state||"todo");
      const context=object(row.context),contextType=token(row.contextType||context.type),stage=token(row.stage);
      const ownerHostId=clean(row.hostId||context.hostId,MAX_ID);
      return contextType==="service"&&["recon","enumeration","exploitation"].includes(stage)&&
        !["done","complete","confirmed","na","not-applicable"].includes(statusValue)&&
        (!ownerHostId||ownerHostId===clean(host.id,MAX_ID));
    }).forEach(item=>{
      const context=object(item.context),protocol=token(context.protocol||"tcp")||"tcp",port=Number(context.port);
      const capability=object(item.webCapability||item.task?.webCapability);
      const contextRequiresOrigin=token(context.contextKind)==="web-origin"||capability.requiresOrigin===true;
      const contextAddress=clean(context.targetAddress||context.address,MAX_ID).toLowerCase();
      const explicitEndpointId=clean(context.endpointId,MAX_ID);
      const candidates=endpointOwners.filter(row=>{
        const rowId=endpointIdentity(row,host,stateValue);
        if(explicitEndpointId)return rowId===explicitEndpointId||clean(row.endpointId||row.id,MAX_ID)===explicitEndpointId;
        const rowAddress=clean(row.targetAddress||row.observedTargetAddress||row.address||host.ip,MAX_ID).toLowerCase();
        return (token(row.protocol)||"tcp")===protocol&&Number(row.port)===port&&(!contextAddress||rowAddress===contextAddress);
      });
      if(candidates.length!==1||!endpointIdentified(candidates[0]))return;
      const endpoint=candidates[0],endpointId=explicitEndpointId||endpointIdentity(endpoint,host,stateValue);
      const targetAddress=clean(endpoint.targetAddress||endpoint.observedTargetAddress||endpoint.address||context.targetAddress||host.ip,MAX_ID);
      const originMatches=originOwners.filter(origin=>{
        if(clean(context.originId,MAX_ID))return originIdentity(origin)===clean(context.originId,MAX_ID);
        if(clean(origin.endpointId||origin.serviceEndpointId,MAX_ID))return clean(origin.endpointId||origin.serviceEndpointId,MAX_ID)===endpointId;
        const facts=originRouteFacts(origin);
        return facts.port===Number(endpoint.port)&&(!facts.address||!targetAddress||facts.address===targetAddress.toLowerCase());
      });
      if(contextRequiresOrigin&&originMatches.length!==1)return;
      const exactOrigins=originMatches.length?originMatches:[null];
      exactOrigins.forEach(origin=>{
        const originId=origin?originIdentity(origin):"",taskId=clean(item.taskId||item.task?.id||item.id,MAX_ID);
        const objectiveOwner=clean(item.key||`${taskId}|${item.contextId||context.id}`,MAX_ID);
        const seenKey=`${objectiveOwner}|${endpointId}|${originId}`;
        if(!taskId||methodologySeen.has(seenKey))return;
        methodologySeen.add(seenKey);
        const titleTemplate=clean(capability.actionLabel,160);
        const title=titleTemplate
          ?titleTemplate.replace("{protocol}",protocol.toUpperCase()).replace("{port}",String(port))
          :clean(item.taskTitle||item.title||item.task?.title,160)||"Continue service-specific coverage";
        const contextLabel=clean(item.contextLabel||context.label,160)||`${protocol.toUpperCase()} ${port}`;
        const statusRecord=object(item.status),disposition=token(statusRecord.disposition)||({active:"in-progress",todo:"not-started"}[token(statusRecord.state)]||"not-started"),evidenceSummary=object(item.evidenceSummary),evidenceReviewRequired=disposition==="not-started"&&token(evidenceSummary.evidenceState)==="review-required";
        const active=token(statusRecord.state||item.status||item.state)==="active";
        const reason=evidenceReviewRequired?clean(evidenceSummary.reason)||"Retained evidence is available for review on this exact objective.":({
          "in-progress":`${contextLabel} is in progress.`,
          partial:`${contextLabel} has a partial result that needs review.`,
          failed:`${contextLabel} has a failed method that needs review.`,
          deferred:`${contextLabel} is deferred and remains available.`,
          stale:`${contextLabel} is stale after changed source evidence.`
        })[disposition]||`${contextLabel} is ready to begin.`;
        const fingerprintReview=taskId==="web-technology-fingerprinting"&&contextRequiresOrigin;
        const routeDestination=clean(capability.reconDestination,80)||(fingerprintReview?"web-app-review":"recon");
        const routeSubview=routeDestination==="web-app-review"
          ?(taskId==="web-technology-fingerprinting"?"fingerprint":taskId==="web-content-review"?"discovered-content":clean(capability.reconSubview,80)||"summary")
          :(contextRequiresOrigin?(clean(capability.reconSubview,80)||"origins"):"services");
        const basePriority=token(item.stage)==="exploitation"?5.5:4.2;
        const priority=fingerprintReview&&disposition==="partial"?6.9:disposition==="stale"?3.9:disposition==="deferred"?7.8:basePriority+(Math.min(Number(item.taskOrder)||0,500)/10000);
        add(priority,"methodology-objective",title,reason,{
          type:"methodology-objective",id:objectiveOwner,path:"methodology.items"
        },makeRoute(stateValue,host,routeDestination,{
          subview:routeSubview,
          objectiveId:taskId,targetAddress,endpointId,originId,
          focusedRecordId:originId||endpointId,methodologyInstanceId:objectiveOwner
        }),{
          ownerType:"methodology-objective",ownerId:objectiveOwner,operatorReview:active||evidenceReviewRequired,
          evidenceState:clean(evidenceSummary.evidenceState,80),evidenceReviewRequired,
          group:fingerprintReview&&disposition==="partial"?"revisit":token(item.stage)==="exploitation"?"secondary-verification":"required-coverage"
        });
      });
    });
    list(host.vulnerabilityLeads).filter(activeRecord).filter(row=>token(row.status)==="lead").forEach(lead=>{
      const title=clean(lead.title||lead.name)||"Lead";
      add(5,"lead",`Review ${title}`,clean(lead.reason||lead.summary)||"This operator-created Lead remains unresolved.",{type:"lead",id:lead.id,path:"host.vulnerabilityLeads"},makeRoute(stateValue,host,"lead",{
        leadId:lead.id,endpointId:clean(lead.endpointId||lead.serviceEndpointId,MAX_ID),originId:clean(lead.originId||lead.webTargetId,MAX_ID),focusedRecordId:lead.id
      }),{ownerType:"lead",ownerId:lead.id,operatorReview:true});
    });
    const post=byId["post-access"];
    if(post&&activeInteractive&&post.meta?.applicable!==false&&![STATUS.COMPLETE,STATUS.NOT_APPLICABLE].includes(post.state))add(6,"post-access","Continue post-access coverage",post.reason,{type:"methodology",id:"post-access",path:post.source},makeRoute(stateValue,host,"host-enumeration",{subview:"post-access",accessContextId:clean(activeInteractive.id,MAX_ID)}),{ownerType:"access-context",ownerId:clean(activeInteractive.id,MAX_ID),operatorReview:post.operatorReview});
    const pe=byId["privilege-escalation"];
    if(pe&&activeInteractive&&pe.meta?.applicable!==false&&![STATUS.COMPLETE,STATUS.NOT_APPLICABLE].includes(pe.state))add(7,"privilege-escalation","Continue privilege-escalation coverage",pe.reason,{type:"methodology",id:"privilege-escalation",path:pe.source},makeRoute(stateValue,host,"host-enumeration",{subview:"privilege-escalation",accessContextId:clean(activeInteractive.id,MAX_ID)}),{ownerType:"access-context",ownerId:clean(activeInteractive.id,MAX_ID),operatorReview:pe.operatorReview});
    const proof=byId.proof;
    if(proof&&proof.meta?.applicable===true&&proof.state!==STATUS.COMPLETE)add(8,"proof","Complete required proof",proof.reason,{type:"readiness",id:"proof",path:proof.source},makeRoute(stateValue,host,"proof",{subview:"proof"}),{operatorReview:proof.operatorReview});
    list(options.readiness?.issues).filter(row=>token(row.category)==="reporting").forEach(issue=>{
      add(9,"report-blocker",clean(issue.title)||"Resolve report blocker",clean(issue.detail)||"A canonical readiness requirement remains.",{type:"readiness-issue",id:issue.id,path:"readiness.assessHost.issues"},makeRoute(stateValue,host,"report",{reportBlockerId:clean(issue.id,MAX_ID),subview:"report"}),{ownerType:"report-blocker",ownerId:issue.id,operatorReview:true});
    });
    return output.sort((a,b)=>a.priority-b.priority||a.id.localeCompare(b.id)).slice(0,MAX_HOST_ACTIONS);
  }

  function hostOrder(stateValue,host,index){
    const scope=linkedScopeTargets(stateValue,host).find(row=>token(row.disposition)==="in-scope");
    const reportOrder=Number(scope?.reportOrder);
    return Number.isFinite(reportOrder)&&reportOrder>0?reportOrder:100000+index;
  }
  function projectHost(stateValue,entry,index,policy={},options={}){
    const host=entry.host,labels={scope:"Scope",os:"Operating system",reachability:"Reachability",port:"TCP Port Discovery",tcp:"TCP Service Discovery",udp:"UDP Port Discovery",udpService:"UDP Service Discovery",endpoints:"Endpoints",origins:"Web origins",access:"Access contexts",leads:"Leads",credentials:"Credential revisit",postAccess:"Post-access",pe:"Privilege escalation",proof:"Proof",report:"Readiness / report",save:"Save state",...object(policy.dimensionLabels)};
    const methodology=list(object(options.methodologyByHost)[entry.id]),readiness=object(options.readinessByHost)[entry.id]||null;
    const dimensions=[
      scopeDimension(stateValue,host,labels.scope),
      osDimension(host,labels.os),
      reachabilityDimension(stateValue,host,labels.reachability),
      scanDimension(host,"port",labels.port),
      scanDimension(host,"tcp",labels.tcp),
      scanDimension(host,"udp",labels.udp),
      udpServiceDimension(host,labels.udpService),
      endpointsDimension(host,labels.endpoints),
      originsDimension(stateValue,host,labels.origins),
      accessDimension(host,labels.access),
      leadsDimension(host,labels.leads),
      credentialDimension(stateValue,host,labels.credentials),
      methodologyDimension(host,methodology,labels.postAccess,"post-access",["foothold","looting","lateral"]),
      methodologyDimension(host,methodology,labels.pe,"privilege-escalation",["privesc"]),
      ...readinessDimensions(host,readiness,{proof:labels.proof,report:labels.report}),
      saveDimension(options.saveFact,labels.save)
    ];
    const candidateActions=hostActions(stateValue,host,dimensions,{readiness,methodology});
    const rawSkipped=Object.prototype.hasOwnProperty.call(options,"navigatorSkippedActions")
      ?options.navigatorSkippedActions
      :object(object(stateValue.navigation).navigator).skippedActions;
    const skipRecords=normalizeSkippedActions(rawSkipped,{validHostIds:[entry.id]});
    const matchingSkipKeys=new Set(skipRecords.map(row=>`${row.skipKey}|${row.evidenceSignature}`));
    const skippedActions=candidateActions.filter(row=>matchingSkipKeys.has(`${row.skipKey}|${row.evidenceSignature}`));
    const actions=candidateActions.filter(row=>!matchingSkipKeys.has(`${row.skipKey}|${row.evidenceSignature}`));
    const endpointContexts=endpointRows(host,stateValue).map(row=>Object.freeze({
      id:endpointIdentity(row,host,stateValue),
      protocol:token(row.protocol||"tcp")||"tcp",
      port:Number(row.port),
      targetAddress:clean(row.targetAddress||row.observedTargetAddress||row.address||host.ip,MAX_ID),
      service:clean(row.service||row.serviceRaw||"Unknown service",160),
      source:clean(row.sourcePath,160)||"host.serviceInventory",
      route:makeRoute(stateValue,host,"methodology",{
        endpointId:endpointIdentity(row,host,stateValue),
        targetAddress:clean(row.targetAddress||row.observedTargetAddress||row.address||host.ip,MAX_ID),
        objectiveId:"service-specific-enumeration",
        subview:"services"
      })
    }));
    const originContexts=originOwnerRows(host,stateValue).slice(0,MAX_CONTEXT_LINKS).map(row=>Object.freeze({
      id:originIdentity(row),
      label:clean(row.url||row.value||"Unknown origin",300),
      source:"host.recon.webTargets",
      route:makeRoute(stateValue,host,"methodology",{originId:originIdentity(row),subview:"origins"})
    })).filter(row=>row.id);
    return Object.freeze({
      id:entry.id,
      order:hostOrder(stateValue,host,index),
      label:clean(host.displayLabel||host.hostname||host.ip||entry.id,160),
      address:clean(host.ip||"Unknown",160),
      hostname:clean(host.hostname||"",160),
      groupLabels:Object.freeze(list(options.groupLabelsByHost?.[entry.id]).map(value=>clean(value,120)).slice(0,10)),
      selectedAccessContextId:clean(host.currentAccessContextId,MAX_ID),
      addresses:Object.freeze(typeof profileApi.networkAddresses==="function"?profileApi.networkAddresses(host):[]),
      reachability:dimensions.find(row=>row.id==="reachability")?.meta||{},
      dimensions:Object.freeze(dimensions),
      actions:Object.freeze(actions),
      skippedActions:Object.freeze(skippedActions),
      endpointContexts:Object.freeze(endpointContexts),
      originContexts:Object.freeze(originContexts),
      sourceHost:host
    });
  }
  function completedItems(card){
    return card.dimensions.filter(row=>[STATUS.COMPLETE,STATUS.CONFIRMED_NEGATIVE,STATUS.NOT_APPLICABLE].includes(row.state)).map(row=>Object.freeze({id:`${card.id}:${row.id}`,hostId:card.id,title:row.label,reason:row.reason,status:row.state,source:row.source}));
  }
  function projectEngagement(stateValue={},policy={},options={}){
    const entries=hostEntries(stateValue).slice(0,MAX_HOSTS);
    const rawSkipped=Object.prototype.hasOwnProperty.call(options,"navigatorSkippedActions")
      ?options.navigatorSkippedActions
      :object(object(stateValue.navigation).navigator).skippedActions;
    const navigatorSkippedActions=normalizeSkippedActions(rawSkipped,{validHostIds:entries.map(row=>row.id)});
    const projectionOptions={...options,navigatorSkippedActions};
    const cards=entries.map((entry,index)=>projectHost(stateValue,entry,index,policy,projectionOptions)).sort((a,b)=>a.order-b.order||a.label.localeCompare(b.label)||a.id.localeCompare(b.id));
    const allActions=cards.flatMap(card=>card.actions).sort((a,b)=>a.priority-b.priority||a.owner.hostId.localeCompare(b.owner.hostId)||a.id.localeCompare(b.id)).slice(0,MAX_ACTIONS);
    const allSkippedActions=cards.flatMap(card=>card.skippedActions).sort((a,b)=>a.priority-b.priority||a.owner.hostId.localeCompare(b.owner.hostId)||a.id.localeCompare(b.id)).slice(0,MAX_ACTIONS);
    const focusHostId=clean(options.focusHostId,MAX_ID),focusCard=focusHostId?cards.find(card=>card.id===focusHostId)||null:null;
    const actions=(focusCard?focusCard.actions:allActions).slice(0,MAX_ACTIONS);
    const skippedActions=(focusCard?focusCard.skippedActions:allSkippedActions).slice(0,MAX_ACTIONS);
    const alternatives=Object.values(object(options.methodologyByHost)).flatMap(list).filter(row=>token(row.taskRole).includes("alternative")).slice(0,MAX_ACTIONS).map(row=>Object.freeze({id:clean(row.id||row.taskId,MAX_ID),hostId:clean(row.hostId,MAX_ID),title:clean(row.title,160),reason:clean(row.reason)||"Retained alternative method.",status:token(row.status||"todo"),source:"methodology.items"}));
    const groups=Object.freeze({
      "next-actions":Object.freeze(actions),
      "required-coverage":Object.freeze(allActions.filter(row=>row.group==="required-coverage")),
      "secondary-verification":Object.freeze(allActions.filter(row=>row.group==="secondary-verification")),
      "alternative-methods":Object.freeze(alternatives),
      "completed-negative":Object.freeze(cards.flatMap(completedItems).slice(0,MAX_ACTIONS)),
      "revisit":Object.freeze(allActions.filter(row=>row.group==="revisit")),
      "conflicts":Object.freeze(allActions.filter(row=>row.group==="conflicts"))
    });
    return Object.freeze({
      version:VERSION,
      engagement:Object.freeze({id:clean(stateValue.projectId,MAX_ID),name:clean(stateValue.projectName,160)}),
      hostCount:hostEntries(stateValue).length,
      truncated:hostEntries(stateValue).length>MAX_HOSTS,
      cards:Object.freeze(cards),
      visibleCards:Object.freeze(cards.slice(0,MAX_VISIBLE_HOSTS)),
      actions:Object.freeze(actions),
      allActions:Object.freeze(allActions),
      skippedActions:Object.freeze(skippedActions),
      allSkippedActions:Object.freeze(allSkippedActions),
      focusHostId:focusCard?.id||"",
      groups,
      groupLabels:GROUP_LABELS,
      showFullCoverageAvailable:true
    });
  }

  return Object.freeze({
    VERSION,PRESENTATION_VERSION,STATUS,STATUS_LABELS,STATUS_VALUES,DESTINATIONS,ROUTE_FIELDS,SUBVIEWS,GROUPS,GROUP_LABELS,
    LIMITS:Object.freeze({MAX_HOSTS,MAX_VISIBLE_HOSTS,MAX_ACTIONS,MAX_HOST_ACTIONS,MAX_CONTEXT_LINKS,MAX_EXPANDED_GROUPS,MAX_EXPANDED_CARDS,MAX_SKIPPED_ACTIONS,MAX_FILTERS,MAX_SCROLL}),
    clean,token,validId,status,dimension,endpointIdentity,originIdentity,
    normalizeRoute,normalizeSkippedActions,normalizeViewState,normalizeNavigationState,resolveRoute,projectHost,projectEngagement
  });
});
