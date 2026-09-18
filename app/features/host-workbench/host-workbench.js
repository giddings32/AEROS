(function(root,factory){
  const api=factory(
    typeof module==="object"&&module.exports?require("../navigator/navigator-core.js"):root?.AEROSNavigatorCore,
    typeof module==="object"&&module.exports?require("../../../host-profile.js"):root?.AerosHostProfile
  );
  if(typeof module==="object"&&module.exports)module.exports=api;
  if(root)root.AEROSHostWorkbench=api;
})(typeof globalThis!=="undefined"?globalThis:this,function(core,profileApi){
  "use strict";

  if(!core)throw new Error("The profile-neutral Navigator core is required.");

  const VERSION=2;
  const MAX_HOST_STATES=50;
  const MAX_SECTIONS=16;
  const MAX_ITEMS=40;
  const MAX_THREADS=12;
  const MAX_TIMELINE=30;
  const MAX_FILTERS=8;
  const MAX_TEXT=500;
  const MAX_SCROLL=5000000;
  const SECTION_IDS=Object.freeze([
    "current-next","target","recon","endpoints","leads","access","post-access",
    "privilege-escalation","proof","report"
  ]);
  const DEFAULT_EXPANDED=Object.freeze(["current-next","target"]);
  const ADVANCED_DESTINATIONS=Object.freeze({
    profile:"host-profile",
    recon:"recon",
    "web-app-review":"web-app-review",
    postexp:"host-enumeration",
    "exploitation-path":"exploitation-path",
    credentials:"credentials",
    movement:"movement",
    attackmap:"attack-map",
    evidence:"investigations-evidence",
    progress:"progress",
    review:"review"
  });
  const RETAINED_STATES=new Set([
    core.STATUS.COMPLETE,core.STATUS.CONFIRMED_NEGATIVE,core.STATUS.NOT_APPLICABLE
  ]);

  function clean(value,limit=MAX_TEXT){return core.clean(value,limit);}
  function token(value){return core.token(value);}
  function list(value){return Array.isArray(value)?value:[];}
  function object(value){return value&&typeof value==="object"&&!Array.isArray(value)?value:{};}
  function active(row){return !!row&&row.active!==false&&!row.deletedAt&&!row.archivedAt&&token(row.status)!=="archived";}
  function interactive(row){return active(row)&&profileApi?.interactiveAccess?.(row)===true;}
  function unique(values,limit=MAX_ITEMS){
    const result=[];
    list(values).forEach(value=>{
      const item=clean(value,160);
      if(item&&core.validId(item)&&!result.includes(item)&&result.length<limit)result.push(item);
    });
    return result;
  }
  function boundedNumber(value,max=MAX_SCROLL){
    const number=Number(value);
    return Number.isFinite(number)?Math.max(0,Math.min(max,Math.round(number))):0;
  }
  function normalizeFilters(value={}){
    return Object.fromEntries(Object.entries(object(value)).slice(0,MAX_FILTERS).map(([key,raw])=>[
      token(key).slice(0,40),clean(raw,120)
    ]).filter(([key,raw])=>key&&raw));
  }
  function routeOwnerIds(host={}){
    const endpointIds=[
      ...list(host.serviceInventory).map(core.endpointIdentity),
      ...Object.entries(object(host.services)).flatMap(([service,row])=>String(row?.ports||"").split(/[\s,;/]+/).map(port=>{
        const value=Number(port),protocol=token(row?.protocol||"tcp")||"tcp";
        return row?.checked!==false&&Number.isInteger(value)&&value>0&&value<=65535?`${protocol}:${value}`:"";
      }))
    ].filter(Boolean);
    return {
      endpointIds:new Set(endpointIds),
      originIds:new Set(list(host.recon?.webTargets).filter(active).map(core.originIdentity).filter(Boolean)),
      accessContextIds:new Set(list(host.accessContexts).filter(active).map(row=>clean(row.id,160)).filter(Boolean))
    };
  }
  function normalizeDrawer(value,hostId,owners){
    const raw=object(value);
    if(raw.open!==true)return Object.freeze({open:false,route:null});
    const normalized=core.normalizeRoute(raw.route||{});
    if(!normalized.valid||normalized.route.destination!=="reference-note"||normalized.route.hostId!==hostId){
      return Object.freeze({open:false,route:null});
    }
    const route=normalized.route;
    if(route.endpointId&&!owners.endpointIds.has(route.endpointId))return Object.freeze({open:false,route:null});
    if(route.originId&&!owners.originIds.has(route.originId))return Object.freeze({open:false,route:null});
    if(route.accessContextId&&!owners.accessContextIds.has(route.accessContextId))return Object.freeze({open:false,route:null});
    return Object.freeze({open:true,route});
  }
  function normalizeHostView(value={},hostId,host={},options={}){
    const raw=object(value),owners=options.ownerIds||routeOwnerIds(host);
    const expanded=Array.isArray(raw.expandedSectionIds)
      ?unique(raw.expandedSectionIds,MAX_SECTIONS).filter(id=>SECTION_IDS.includes(id))
      :[...DEFAULT_EXPANDED];
    const endpointId=clean(raw.selectedEndpointId,160),originId=clean(raw.selectedOriginId,160),accessContextId=clean(raw.selectedAccessContextId,160);
    const stale=[];
    if(endpointId&&!owners.endpointIds.has(endpointId))stale.push("endpoint");
    if(originId&&!owners.originIds.has(originId))stale.push("origin");
    if(accessContextId&&!owners.accessContextIds.has(accessContextId))stale.push("access context");
    return Object.freeze({
      version:VERSION,
      expandedSectionIds:Object.freeze(expanded),
      expandedCardIds:Object.freeze(unique(raw.expandedCardIds,50)),
      selectedEndpointId:owners.endpointIds.has(endpointId)?endpointId:"",
      selectedOriginId:owners.originIds.has(originId)?originId:"",
      selectedAccessContextId:owners.accessContextIds.has(accessContextId)?accessContextId:"",
      filters:Object.freeze(normalizeFilters(raw.filters)),
      scrollTop:boundedNumber(raw.scrollTop),
      focusKey:core.validId(raw.focusKey)?clean(raw.focusKey,160):"",
      drawer:normalizeDrawer(raw.drawer,hostId,owners),
      staleReference:stale.length
        ?`The saved ${stale.join(", ")} owner is missing, inactive, or stale. No neighboring owner was selected.`
        :clean(raw.staleReference,MAX_TEXT)
    });
  }
  function hostEntries(state={}){
    return Object.entries(object(state.hosts)).map(([key,host])=>({key,host:object(host),id:clean(host?.id||key,160)})).filter(row=>row.id);
  }
  function normalizeNavigationState(value={},state={},options={}){
    const raw=object(value),entries=hostEntries(state),validIds=new Set(entries.map(row=>row.id));
    const legacy=object(options.legacyNavigator);
    const requested=clean(raw.selectedHostId||legacy.selectedHostId||options.activeHostId,160);
    const selectedHostId=validIds.has(requested)?requested:"";
    const hostStates={},source=object(raw.hostStates);
    entries.filter(row=>source[row.id]||row.id===selectedHostId).slice(0,MAX_HOST_STATES).forEach(row=>{
      const seed=source[row.id]||(row.id===selectedHostId?{
        selectedEndpointId:legacy.selectedEndpointId,
        selectedOriginId:legacy.selectedOriginId,
        selectedAccessContextId:legacy.selectedAccessContextId,
        scrollTop:legacy.scrollTop,
        focusKey:legacy.focusKey
      }:{});
      hostStates[row.id]=normalizeHostView(seed,row.id,row.host);
    });
    const returnRoute=core.normalizeRoute(raw.returnRoute||{}),returnHostId=clean(raw.returnHostId,160);
    const deepReturnActive=raw.deepReturnActive===true&&validIds.has(returnHostId)&&returnRoute.valid&&returnRoute.route.destination==="host-workbench"&&returnRoute.route.hostId===returnHostId;
    return Object.freeze({
      version:VERSION,
      selectedHostId,
      hostStates:Object.freeze(hostStates),
      deepReturnActive,
      returnHostId:deepReturnActive?returnHostId:"",
      returnRoute:deepReturnActive?returnRoute.route:null,
      routeError:clean(raw.routeError,MAX_TEXT)||(!requested||selectedHostId?"":`The saved Workbench host is missing or stale. No neighboring host was selected.`)
    });
  }
  function updateHostView(navigation,hostId,host,patch={}){
    const current=object(navigation?.hostStates?.[hostId]);
    const next=normalizeHostView({...current,...object(patch)},hostId,host);
    const hostStates={...object(navigation?.hostStates),[hostId]:next};
    const keys=Object.keys(hostStates);
    if(keys.length>MAX_HOST_STATES)keys.filter(id=>id!==hostId).slice(0,keys.length-MAX_HOST_STATES).forEach(id=>delete hostStates[id]);
    return Object.freeze({...object(navigation),version:VERSION,selectedHostId:hostId,hostStates:Object.freeze(hostStates),routeError:next.staleReference||""});
  }
  function exactHost(state,hostId){
    const matches=hostEntries(state).filter(row=>row.id===hostId);
    if(matches.length!==1)return {ok:false,reason:matches.length?"The exact Workbench host owner is ambiguous.":"The exact Workbench host owner is missing or stale."};
    if(!active(matches[0].host))return {ok:false,reason:"The exact Workbench host owner is archived or inactive."};
    return {ok:true,...matches[0]};
  }
  function makeRoute(state,hostId,destination,extra={}){
    return core.normalizeRoute({
      destination,engagementId:clean(state.projectId,160),engagementName:clean(state.projectName,160),hostId,...extra
    }).route;
  }
  function dimension(card,id){
    return list(card?.dimensions).find(row=>row.id===id)||core.dimension(id,id,core.STATUS.UNKNOWN,{
      reason:"No current status is available for this work area.",source:"Current host status"
    });
  }
  function worseState(rows){
    const order=[
      core.STATUS.CONFLICT,core.STATUS.BLOCKED,core.STATUS.STALE,core.STATUS.UNKNOWN,
      core.STATUS.NOT_STARTED,core.STATUS.PARTIAL,core.STATUS.IN_PROGRESS,
      core.STATUS.NOT_APPLICABLE,core.STATUS.CONFIRMED_NEGATIVE,core.STATUS.COMPLETE
    ];
    return rows.map(row=>row.state).sort((a,b)=>order.indexOf(a)-order.indexOf(b))[0]||core.STATUS.UNKNOWN;
  }
  function truthDimensions(card){
    const discovery=dimension(card,"port"),identification=dimension(card,"tcp");
    const tcp={...core.dimension("tcp","TCP",worseState([discovery,identification]),{
      reason:`Discovery: ${discovery.reason} Identification: ${identification.reason}`,
      source:`${discovery.source}|${identification.source}`,
      count:Math.max(Number(discovery.count)||0,Number(identification.count)||0)
    }),id:"tcp",label:"TCP"};
    const udpDiscovery=dimension(card,"udp"),udpIdentification=dimension(card,"udp-service");
    const udp={...core.dimension("udp","UDP",worseState([udpDiscovery,udpIdentification]),{
      reason:`Discovery: ${udpDiscovery.reason} Identification: ${udpIdentification.reason}`,
      source:`${udpDiscovery.source}|${udpIdentification.source}`,
      count:Math.max(Number(udpDiscovery.count)||0,Number(udpIdentification.count)||0)
    }),id:"udp",label:"UDP"};
    return Object.freeze([
      tcp,
      udp,
      {...dimension(card,"os"),id:"os",label:"OS"},
      {...dimension(card,"access"),id:"access",label:"Access"},
      {...dimension(card,"privilege-escalation"),id:"privilege-escalation",label:"Privilege Escalation"},
      {...dimension(card,"proof"),id:"proof",label:"Proof"}
    ]);
  }
  function displayValue(value){
    if(value===null||value===undefined)return "";
    if(typeof value==="string"||typeof value==="number"||typeof value==="boolean")return clean(value,300);
    return clean(value.label||value.title||value.name||value.value||value.summary||value.reason||value.id,300);
  }
  function displayList(value,limit=8){return list(value).map(displayValue).filter(Boolean).slice(0,limit);}
  function linkedRows(rows,fields,id,limit=12){
    return list(rows).filter(active).filter(row=>fields.some(field=>clean(row?.[field],160)===id)).slice(0,limit);
  }
  function sourceFacts(row={},fallback="current host record"){
    return displayList([
      row.sourcePath,row.source,row.provenance,row.artifactId,
      ...list(row.sources),...list(row.sourceArtifacts)
    ],8).length?displayList([
      row.sourcePath,row.source,row.provenance,row.artifactId,
      ...list(row.sources),...list(row.sourceArtifacts)
    ],8):[fallback];
  }
  function meaningfulEndpointFact(value,assignedLabel=""){
    const text=clean(value,500).replace(/\s+/g," "),lower=text.toLowerCase();
    if(!text||["-","/","unknown","n/a","na","none","null","nil","not available","not applicable","undefined"].includes(lower))return "";
    if(/^[^a-z0-9]+$/i.test(text)||assignedLabel&&lower===clean(assignedLabel,160).toLowerCase())return "";
    return text;
  }
  function endpointRows(host,card,state){
    return list(card.endpointContexts).slice(0,MAX_ITEMS).map(context=>{
      const matches=list(host.serviceInventory).filter(row=>core.endpointIdentity(row,host,state)===context.id);
      const row=matches.length===1?matches[0]:{};
      const targetAddress=clean(row.targetAddress||row.observedTargetAddress||context.targetAddress||host.ip,160);
      const evidence=linkedRows(host.evidence,["endpointId","serviceEndpointId"],context.id);
      const leads=linkedRows(host.vulnerabilityLeads,["endpointId","serviceEndpointId"],context.id);
      const credentialTests=[
        ...linkedRows(host.credentialTests,["endpointId","serviceEndpointId"],context.id),
        ...list(host.credentials).flatMap(credential=>linkedRows(credential?.testHistory,["endpointId","serviceEndpointId"],context.id))
      ].slice(0,12);
      const hint=clean(row.serviceHint||row.serviceRaw,160),identified=row.identified===true;
      return Object.freeze({
        id:context.id,
        identity:`${String(context.protocol||"tcp").toUpperCase()} ${context.port}`,
        service:identified?clean(row.service||row.serviceRaw||context.service||"Unknown service",160):hint?`${hint} hint`:"Unknown service",
        product:meaningfulEndpointFact(row.product||row.productName,hint),
        version:meaningfulEndpointFact(row.version||row.productVersion,hint),
        confidence:clean(row.confidence||row.matchConfidence||"Unknown / needs review",120),
        sources:Object.freeze(sourceFacts(row,context.source)),
        checks:Object.freeze(displayList([...list(row.checks),...list(row.observations)],8)),
        credentialTests:Object.freeze(credentialTests.map(test=>Object.freeze({
          id:clean(test.id,160),label:displayValue(test)||"Credential test",status:clean(test.status||test.outcome||"Unknown",100),at:clean(test.at||test.updatedAt||test.createdAt,100)
        }))),
        evidence:Object.freeze(evidence.map(item=>Object.freeze({id:clean(item.id,160),label:displayValue(item)||"Evidence",type:clean(item.type,100)}))),
        questions:Object.freeze(displayList(row.questions,8)),
        leads:Object.freeze(leads.map(item=>Object.freeze({id:clean(item.id,160),label:displayValue(item)||"Lead",status:clean(item.status||"lead",100)}))),
        targetAddress,
        route:makeRoute(state,host.id,"endpoint",{endpointId:context.id,targetAddress,objectiveId:"service-specific-enumeration",subview:"services"}),
        notesRoute:makeRoute(state,host.id,"reference-note",{endpointId:context.id,targetAddress,objectiveId:"service-specific-enumeration",subview:"services"})
      });
    });
  }
  function originRows(host,card,state){
    return list(card.originContexts).slice(0,MAX_ITEMS).map(context=>{
      const matches=list(host.recon?.webTargets).filter(row=>core.originIdentity(row)===context.id);
      const row=matches.length===1?matches[0]:{};
      const evidence=linkedRows(host.evidence,["originId","webTargetId"],context.id);
      const leads=linkedRows(host.vulnerabilityLeads,["originId","webTargetId"],context.id);
      return Object.freeze({
        id:context.id,label:clean(row.url||row.value||context.label||"Unknown origin",300),
        confidence:clean(row.confidence||row.status||"Unknown / needs review",120),
        sources:Object.freeze(sourceFacts(row,context.source)),
        checks:Object.freeze(displayList([...list(row.checks),...list(row.observations)],8)),
        credentialTests:Object.freeze(linkedRows(host.credentialTests,["originId","webTargetId"],context.id).map(test=>Object.freeze({
          id:clean(test.id,160),label:displayValue(test)||"Credential test",status:clean(test.status||test.outcome||"Unknown",100),at:clean(test.at||test.updatedAt||test.createdAt,100)
        }))),
        evidence:Object.freeze(evidence.map(item=>Object.freeze({id:clean(item.id,160),label:displayValue(item)||"Evidence",type:clean(item.type,100)}))),
        questions:Object.freeze(displayList(row.questions,8)),
        leads:Object.freeze(leads.map(item=>Object.freeze({id:clean(item.id,160),label:displayValue(item)||"Lead",status:clean(item.status||"lead",100)}))),
        route:makeRoute(state,host.id,"web-origin",{originId:context.id,subview:"origins"}),
        notesRoute:makeRoute(state,host.id,"reference-note",{originId:context.id,subview:"origins"})
      });
    });
  }
  function timelineRows(host){
    const rows=[];
    list(host.exploitAttempts).filter(active).forEach(attempt=>{
      rows.push({id:clean(attempt.id,160),at:clean(attempt.updatedAt||attempt.createdAt,100),label:clean(attempt.title||attempt.name||"Investigation",200),status:clean(attempt.status||attempt.resultType||"Unknown",100),routeKind:"investigation",investigationId:clean(attempt.id,160)});
      list(attempt.runs).forEach(run=>rows.push({id:clean(run.id,160),at:clean(run.at||run.updatedAt||run.createdAt,100),label:clean(run.title||run.outcome||run.body||"Investigation activity",200),status:clean(run.status||run.outcome||"Recorded",100),routeKind:"investigation",investigationId:clean(attempt.id,160)}));
    });
    list(host.activities).filter(active).forEach(activity=>rows.push({id:clean(activity.id,160),at:clean(activity.at||activity.updatedAt||activity.createdAt,100),label:displayValue(activity)||"Activity",status:clean(activity.status||activity.outcome||"Recorded",100),routeKind:""}));
    return rows.sort((a,b)=>String(b.at).localeCompare(String(a.at))||String(a.id).localeCompare(String(b.id))).slice(0,MAX_TIMELINE);
  }
  function leadRows(host,state){
    return list(host.vulnerabilityLeads).filter(active).slice(0,MAX_ITEMS).map(lead=>{
      const leadId=clean(lead.id,160),attempts=list(host.exploitAttempts).filter(row=>clean(row.leadId,160)===leadId).slice(0,12);
      return Object.freeze({
        id:leadId,title:clean(lead.title||lead.name||"Untitled Lead",200),
        status:clean(lead.status||"lead",100),reason:clean(lead.reason||lead.summary||lead.description||"",300),
        source:clean(lead.source||lead.sourcePath||"host.vulnerabilityLeads",200),
        checks:Object.freeze(displayList(lead.checks||lead.guidedChecks,8)),
        attempts:Object.freeze(attempts.map(row=>Object.freeze({
          id:clean(row.id,160),label:clean(row.title||row.name||"Investigation",200),status:clean(row.status||row.resultType||"Unknown",100),at:clean(row.updatedAt||row.createdAt,100),
          route:makeRoute(state,host.id,"investigation",{investigationId:clean(row.id,160)})
        }))),
        route:makeRoute(state,host.id,"lead",{leadId}),
        notesRoute:makeRoute(state,host.id,"reference-note",{leadId,subview:"next-actions"})
      });
    });
  }
  function candidateCredentials(state,host){
    const rows=[
      ...list(host.credentials).map(row=>({...row,_source:"host.credentials"})),
      ...list(state.engagementConfig?.startingAccess?.entries).filter(row=>clean(row.hostId,160)===host.id).map(row=>({...row,_source:"engagementConfig.startingAccess.entries"}))
    ];
    return rows.filter(active).filter(row=>row.verified!==true&&!["verified","successful","confirmed"].includes(token(row.status||row.classification))).slice(0,MAX_ITEMS).map(row=>Object.freeze({
      id:clean(row.id,160),principal:clean(row.principal||row.username||row.user||"Unknown principal",160),
      kind:clean(row.kind||row.type||row.credentialType||"Candidate",100),status:clean(row.status||row.classification||"Candidate",100),
      source:row._source
    }));
  }
  function accessRows(host,state){
    return list(host.accessContexts).filter(active).slice(0,MAX_ITEMS).map(row=>Object.freeze({
      id:clean(row.id,160),principal:clean(row.principal||row.username||row.label||"Unknown principal",160),
      method:clean(row.method||row.accessMethod||row.sessionType||"Access",120),
      privilege:clean(row.privilege||row.privilegeLevel||"Unknown / needs review",120),
      endpointId:clean(row.endpointId,160),originId:clean(row.originId||row.webTargetId,160),
      source:clean(row.source||row.sourcePath||"host.accessContexts",200),
      createdAt:clean(row.verifiedAt||row.updatedAt||row.createdAt,100),
      route:makeRoute(state,host.id,"access-context",{accessContextId:clean(row.id,160),subview:"access"}),
      notesRoute:makeRoute(state,host.id,"reference-note",{accessContextId:clean(row.id,160),subview:"post-access"})
    }));
  }
  function methodRows(items,host,state,stages,presentation,contextIds=new Set()){
    const selected=presentation.selectedAccessContextId;
    return list(items).filter(row=>stages.includes(token(row.stage))).filter(row=>contextIds.has(clean(row.contextId,160))).filter(row=>!selected||row.contextId===selected).slice(0,MAX_ITEMS).map(row=>Object.freeze({
      id:clean(row.id||row.taskId,160),title:clean(row.title||row.label||"Methodology objective",200),
      status:clean(row.status||row.state||"Not started",100),reason:clean(row.reason||row.applicabilityReason||"",300),
      source:clean(row.source||row.sourcePath||"methodology.items",200),contextId:clean(row.contextId,160),
      route:makeRoute(state,host.id,"methodology",{accessContextId:clean(row.contextId,160),subview:stages.includes("privesc")?"privilege-escalation":"post-access",focusedRecordId:clean(row.id||row.taskId,160)}),
      notesRoute:makeRoute(state,host.id,"reference-note",{accessContextId:clean(row.contextId,160),subview:stages.includes("privesc")?"privilege-escalation":"post-access"})
    }));
  }
  function proofRows(host,state){
    return [
      ...list(host.evidence).filter(active).filter(row=>["proof","local-proof","proof-file"].includes(token(row.type))).map(row=>({
        id:clean(row.id,160),label:displayValue(row)||clean(row.type||"Proof Evidence",160),status:clean(row.status||"Recorded",100),
        source:"host.evidence",route:makeRoute(state,host.id,"proof",{proofItemId:clean(row.id,160),subview:"proof"})
      })),
      ...list(host.exploitAttempts).filter(active).filter(row=>object(row.success).proof&&Object.keys(object(row.success.proof)).length).map(row=>({
        id:clean(row.success.proof.id||row.id,160),label:clean(row.success.proof.type||row.title||"Investigation proof",160),status:clean(row.status||"Recorded",100),
        source:"host.exploitAttempts.success.proof",route:makeRoute(state,host.id,"proof",{proofItemId:clean(row.success.proof.id||"",160),investigationId:clean(row.id,160),subview:"proof"})
      }))
    ].slice(0,MAX_ITEMS);
  }
  function reportRows(state,host,readiness){
    const issues=list(readiness?.issues).filter(row=>token(row.category)==="reporting").slice(0,MAX_ITEMS).map(row=>Object.freeze({
      id:clean(row.id,160),label:clean(row.title||row.label||"Readiness item",200),status:clean(row.state||row.severity||"Needs review",100),
      detail:clean(row.detail||row.reason||"",300),route:makeRoute(state,host.id,"report",{reportBlockerId:clean(row.id,160),subview:"report"})
    }));
    const findings=[
      ...list(host.findings),
      ...list(state.findings).filter(row=>clean(row.assetId||row.hostId,160)===host.id)
    ].filter(active).slice(0,MAX_ITEMS).map(row=>Object.freeze({
      id:clean(row.id,160),label:clean(row.title||row.name||"Finding",200),status:clean(row.status||row.stage||"Recorded",100),
      route:makeRoute(state,host.id,"finding",{findingId:clean(row.id,160),subview:"report"})
    }));
    return Object.freeze({issues:Object.freeze(issues),findings:Object.freeze(findings),state:clean(readiness?.state||"Unknown / needs review",120),label:clean(readiness?.stateLabel||"",200)});
  }
  function peasRows(host,state,contextIds=new Set()){
    return list(host.peas?.findings).filter(active).filter(row=>contextIds.has(clean(row.accessContextId,160))).filter(row=>!["dismissed","exploited"].includes(token(row.state))).slice(0,MAX_ITEMS).map(row=>Object.freeze({
      id:clean(row.id,160),
      title:clean(row.title||row.path||row.sectionTitle||row.sourceLine||"PEAS finding",200),
      status:clean(row.state||"observed",100),
      accessContextId:clean(row.accessContextId,160),
      route:makeRoute(state,host.id,"host-enumeration",{
        accessContextId:clean(row.accessContextId,160),
        peasFindingId:clean(row.id,160),
        subview:"privilege-escalation",
        focusedRecordId:clean(row.id,160)
      }),
      notesRoute:makeRoute(state,host.id,"reference-note",{
        accessContextId:clean(row.accessContextId,160),
        peasFindingId:clean(row.id,160),
        subview:"privilege-escalation"
      })
    }));
  }
  function threadGroup(action={}){
    const destination=token(action.route?.destination),kind=token(action.kind);
    if(["proof","finding","report","evidence"].includes(destination)||["proof","report-blocker"].includes(kind))return "Proof & report";
    if(["lead","investigation","record-outcome"].includes(destination)||kind==="lead")return "Leads & investigations";
    if(["access-context","credentials","methodology","host-enumeration"].includes(destination))return "Access & post-access";
    return "Recon & coverage";
  }
  function threadRows(card,hostId,peas=[]){
    const seen=new Set(),rows=[];
    list(card.actions).forEach(action=>{
      const route=object(action.route);
      if(rows.length>=MAX_THREADS||route.hostId!==hostId||route.destination==="navigator"||seen.has(action.id))return;
      seen.add(action.id);
      rows.push(Object.freeze({
        id:clean(action.id,160),kind:clean(action.kind||"open-work",100),title:clean(action.title||"Open work",200),
        reason:clean(action.reason||"",300),group:threadGroup(action),route
      }));
    });
    list(peas).forEach(row=>{
      if(rows.length>=MAX_THREADS||seen.has(`peas:${row.id}`))return;
      seen.add(`peas:${row.id}`);
      rows.push(Object.freeze({
        id:`peas:${row.id}`,kind:"peas-finding",title:`Review ${row.title}`,
        reason:`${clean(row.status||"Observed",100)} PEAS item for this host and access context.`,
        group:"Access & post-access",route:row.route
      }));
    });
    return Object.freeze(rows);
  }
  function retainedRows(card,methodologyItems){
    const dimensions=list(card.dimensions).filter(row=>RETAINED_STATES.has(row.state)).map(row=>({
      id:`dimension:${row.id}`,title:row.label,status:row.state,reason:row.reason,source:row.source
    }));
    const methodology=list(methodologyItems).filter(row=>["complete","completed","done","negative","confirmed-negative","na","not-applicable","alternative","stale","revisit"].includes(token(row.status||row.state||row.taskRole))).map(row=>({
      id:`method:${clean(row.id||row.taskId,160)}`,title:clean(row.title||row.label||"Retained objective",200),status:clean(row.status||row.state||row.taskRole,100),
      reason:clean(row.reason||row.applicabilityReason||"",300),source:clean(row.source||"methodology.items",200)
    }));
    return Object.freeze([...dimensions,...methodology].slice(0,MAX_ITEMS));
  }
  function project(state={},hostId="",options={}){
    const exact=exactHost(state,hostId);
    if(!exact.ok)return Object.freeze({ok:false,reason:exact.reason});
    const host=exact.host,card=options.navigatorCard;
    if(!card||card.id!==hostId)return Object.freeze({ok:false,reason:"The exact host projection is unavailable or stale."});
    const presentation=normalizeHostView(options.presentation||{},hostId,host),scopeMatches=list(state.engagementConfig?.scope?.targets).filter(row=>clean(row.hostId,160)===hostId);
    const scope=scopeMatches.length===1?scopeMatches[0]:null,methodologyItems=list(options.methodologyItems),readiness=options.readiness||null;
    const notesEligible=route=>typeof options.hasRelevantNotes!=="function"||options.hasRelevantNotes(route)===true;
    const withEligibleNotes=row=>row?.notesRoute&&!notesEligible(row.notesRoute)?Object.freeze({...row,notesRoute:null}):row;
    const endpoints=endpointRows(host,card,state).map(withEligibleNotes),origins=originRows(host,card,state).map(withEligibleNotes),leads=leadRows(host,state).map(withEligibleNotes),access=accessRows(host,state).map(withEligibleNotes);
    const selectedEndpoint=endpoints.find(row=>row.id===presentation.selectedEndpointId)||null;
    const selectedOrigin=origins.find(row=>row.id===presentation.selectedOriginId)||null;
    const interactiveContexts=list(host.accessContexts).filter(interactive),interactiveContextIds=new Set(interactiveContexts.map(row=>clean(row.id,160)));
    const selectedAccess=access.find(row=>interactiveContextIds.has(row.id)&&row.id===presentation.selectedAccessContextId)||access.find(row=>interactiveContextIds.has(row.id)&&row.id===host.currentAccessContextId)||access.find(row=>interactiveContextIds.has(row.id))||null;
    const peas=peasRows(host,state,interactiveContextIds),threads=threadRows(card,hostId,peas),proof=proofRows(host,state),report=reportRows(state,host,readiness);
    const target=Object.freeze({
      id:hostId,label:clean(host.displayLabel||host.hostname||host.ip||hostId,200),address:clean(host.ip||"Unknown / needs review",200),
      hostname:clean(host.hostname||"",200),scopeState:clean(scope?.disposition||host.scopeDisposition||"Unknown / needs review",120),
      scopeReason:clean(scope?.reason||scope?.objectiveNote||(scopeMatches.length>1?"Multiple exact scope records require review.":"No exact linked scope record is active."),300),
      attention:clean(host.attentionState||"normal",120),
      objective:clean(host.objectiveNote||scope?.objectiveNote||state.engagementConfig?.objectives?.primary||"No current objective is recorded.",300),
      os:dimension(card,"os")
    });
    const headerNotesRoute=makeRoute(state,hostId,"reference-note",{
      endpointId:selectedEndpoint?.id||"",
      targetAddress:selectedEndpoint?.targetAddress||"",
      objectiveId:selectedEndpoint?"service-specific-enumeration":"",
      originId:selectedOrigin?.id||"",
      accessContextId:selectedAccess?.id||"",
      subview:selectedEndpoint?"services":selectedOrigin?"origins":selectedAccess?"post-access":"next-actions"
    });
    const headerActions=[{id:"notes",label:"Relevant Notes",notes:true,route:headerNotesRoute}];
    return Object.freeze({
      ok:true,version:VERSION,hostId,presentation,target,
      dimensions:truthDimensions(card),
      endpoints:Object.freeze(endpoints),origins:Object.freeze(origins),leads:Object.freeze(leads),
      timeline:Object.freeze(timelineRows(host)),
      candidates:Object.freeze(candidateCredentials(state,host)),access:Object.freeze(access),
      hasInteractiveAccess:interactiveContexts.length>0,
      postAccess:Object.freeze(methodRows(methodologyItems,host,state,["foothold","looting","lateral"],presentation,interactiveContextIds).map(withEligibleNotes)),
      privilegeEscalation:Object.freeze(methodRows(methodologyItems,host,state,["privesc"],presentation,interactiveContextIds).map(withEligibleNotes)),
      proof:Object.freeze(proof),report,peas:Object.freeze(peas),threads,retained:retainedRows(card,methodologyItems),
      selected:Object.freeze({endpoint:selectedEndpoint,origin:selectedOrigin,access:selectedAccess}),
      header:Object.freeze({
        engagement:clean(state.projectName||state.projectId||"Unknown engagement",200),target,
        endpoint:selectedEndpoint,origin:selectedOrigin,access:selectedAccess,actions:Object.freeze(headerActions)
      }),
      routes:Object.freeze({
        target:makeRoute(state,hostId,"host-profile"),
        recon:makeRoute(state,hostId,"recon",{subview:"tcp"}),
        enumeration:selectedAccess?makeRoute(state,hostId,"host-enumeration",{accessContextId:selectedAccess.id,subview:"post-access"}):null,
        credentials:makeRoute(state,hostId,"credentials",{accessContextId:selectedAccess?.id||"",subview:"access"}),
        coverage:makeRoute(state,hostId,"coverage",{subview:"required-coverage"}),
        notes:makeRoute(state,hostId,"reference-note",{subview:"next-actions"}),
        access:makeRoute(state,hostId,"access-context",{accessContextId:selectedAccess?.id||"",subview:"access"}),
        postAccess:makeRoute(state,hostId,"methodology",{accessContextId:selectedAccess?.id||"",subview:"post-access"}),
        privilegeEscalation:makeRoute(state,hostId,"methodology",{accessContextId:selectedAccess?.id||"",subview:"privilege-escalation"}),
        proof:makeRoute(state,hostId,"proof",{subview:"proof"}),
        report:makeRoute(state,hostId,"report",{subview:"report"})
      })
    });
  }
  function advancedRoute(state={},hostId="",tab=""){
    const destination=ADVANCED_DESTINATIONS[tab];
    return destination?makeRoute(state,hostId,destination):null;
  }
  function e(helpers,value){return helpers.escapeHtml(value);}
  function a(helpers,value){return helpers.escapeAttr(value);}
  function routeButton(helpers,route,label,options={}){
    const key=helpers.registerRoute(route),kind=options.notes?"data-workbench-notes-route":"data-workbench-route";
    return `<button class="${options.primary?"primary-btn":"secondary-btn"} small" ${kind}="${a(helpers,key)}" data-workbench-focus="${a(helpers,options.focusKey||`workbench-${label.toLowerCase().replace(/[^a-z0-9]+/g,"-")}`)}" type="button">${e(helpers,label)}</button>`;
  }
  function badge(helpers,value,state=""){
    return `<span class="navigator-status-badge ${state?`status-${a(helpers,state)}`:""}">${e(helpers,value)}</span>`;
  }
  function empty(helpers,message){return `<div class="host-workbench-empty">${e(helpers,message)}</div>`;}
  function section(helpers,model,id,title,summary,body,route=null){
    const open=model.presentation.expandedSectionIds.includes(id);
    return `<details class="host-workbench-section" data-workbench-section="${a(helpers,id)}"${open?" open":""}><summary><span><strong>${e(helpers,title)}</strong><small>${e(helpers,summary)}</small></span><span class="workbench-disclosure-state">${open?"Expanded":"Collapsed"}</span></summary><div class="host-workbench-section-body">${route?`<div class="workbench-section-owner">${routeButton(helpers,route,"Open workspace",{focusKey:`section-${id}-owner`})}</div>`:""}${body}</div></details>`;
  }
  function operatorRouteLabel(route={},fallback="Open"){
    if(route.peasFindingId)return "Open PEAS finding";
    if(route.destination==="lead")return "Review Lead";
    if(route.destination==="investigation")return "Continue investigation";
    if(route.destination==="proof")return "Review proof";
    if(route.destination==="finding"||route.destination==="report")return "Review report blocker";
    if(route.destination==="credentials")return "Open Credentials";
    if(route.destination==="access-context")return "Open access";
    if(route.destination==="coverage")return "Review coverage";
    if(route.destination==="host-profile")return "Open Host Profile";
    if(route.destination==="recon"||route.destination==="endpoint"||route.destination==="web-origin")return "Open Recon";
    if(route.destination==="methodology"||route.destination==="host-enumeration")return "Open Host Enumeration";
    return fallback;
  }
  function operatorThreadReason(reason=""){
    return clean(reason)
      .replace("The current canonical methodology projection exposes no supported objective for this dimension.","No supported objective is available for the selected access context.")
      .replace("Canonical scan evidence","Recorded scan evidence")
      .replace("canonical readiness requirement","readiness requirement");
  }
  function destinationCard(helpers,{title,status,description,route,label,notesRoute,focusKey}){
    return `<article class="workbench-destination"><div><h3>${e(helpers,title)}</h3><span>${e(helpers,status)}</span></div><p>${e(helpers,description)}</p><div class="workbench-card-actions">${routeButton(helpers,route,label,{focusKey})}${notesRoute?routeButton(helpers,notesRoute,"Relevant Notes",{notes:true,focusKey:`${focusKey}-notes`}):""}</div></article>`;
  }
  function render(model,helpers){
    if(!model?.ok)return `<div class="host-workbench-failure" role="alert"><h2>Host Workbench unavailable</h2><p>${e(helpers,model?.reason||"Select one exact active host.")}</p></div>`;
    const reconContext=model.selected.endpoint||model.selected.origin||model.endpoints[0]||model.origins[0]||null;
    const reconRoute=reconContext?.route||model.routes.recon;
    const reconPort=reconContext?.identity?.split(/\s+/).pop()||"";
    const lead=model.leads[0]||null,peas=model.peas[0]||null,proof=model.hasInteractiveAccess?(model.proof[0]||null):null;
    const report=model.report.issues[0]||model.report.findings[0]||null;
    const destinations=[
      destinationCard(helpers,{
        title:"Recon",
        status:`${model.endpoints.length} endpoint${model.endpoints.length===1?"":"s"} · ${model.origins.length} origin${model.origins.length===1?"":"s"}`,
        description:"Review service, origin, scan, and coverage details.",
        route:reconRoute,
        label:reconPort?`Open Recon at ${reconPort}`:"Open Recon",
        notesRoute:reconContext?.notesRoute||null,
        focusKey:"destination-recon"
      }),
      destinationCard(helpers,{
        title:"Host Profile",
        status:core.STATUS_LABELS[model.target.os.state]||model.target.os.label,
        description:"Review identity, scope, OS observations, and conflicts.",
        route:model.routes.target,label:"Open Host Profile",focusKey:"destination-profile"
      }),
      model.hasInteractiveAccess?destinationCard(helpers,{
        title:"Host Enumeration / PEAS",
        status:`Interactive access active · ${model.peas.length} open PEAS item${model.peas.length===1?"":"s"}`,
        description:"Review imported host facts and PEAS output for the selected access context.",
        route:peas?.route||model.routes.enumeration,
        label:peas?"Open PEAS finding":"Open Host Enumeration",
        notesRoute:peas?.notesRoute||model.selected.access?.notesRoute||null,
        focusKey:"destination-enumeration"
      }):"",
      destinationCard(helpers,{
        title:"Credentials & access",
        status:`${model.candidates.length} candidate${model.candidates.length===1?"":"s"} · ${model.access.length} verified context${model.access.length===1?"":"s"}`,
        description:"Review candidate credentials separately from verified access.",
        route:model.routes.credentials,label:"Open Credentials",focusKey:"destination-credentials"
      }),
      destinationCard(helpers,{
        title:"Leads & investigations",
        status:`${model.leads.length} open Lead${model.leads.length===1?"":"s"}`,
        description:"Review the full Lead, investigation, Activity, and Result history.",
        route:lead?.route||model.routes.recon,
        label:lead?(lead.title.startsWith("Review ")?lead.title:`Review ${lead.title}`):"Open Recon Leads",
        notesRoute:lead?.notesRoute||null,
        focusKey:"destination-leads"
      }),
      destinationCard(helpers,{
        title:"Proof & report",
        status:model.report.label||model.report.state,
        description:"Review proof requirements, Findings, and report blockers.",
        route:proof?.route||report?.route||model.routes.report,
        label:proof?"Review proof":report?"Review report blocker":"Open Review",
        focusKey:"destination-proof-report"
      })
    ].join("");
    const groupOrder=["Recon & coverage","Leads & investigations","Access & post-access","Proof & report"];
    const threadGroups=groupOrder.map(group=>{
      const rows=model.threads.filter(row=>row.group===group);
      if(!rows.length)return "";
      return `<section class="workbench-thread-group"><h4>${e(helpers,group)}</h4>${rows.map(row=>`<article><div><strong>${e(helpers,row.title)}</strong><p>${e(helpers,operatorThreadReason(row.reason))}</p></div>${routeButton(helpers,row.route,operatorRouteLabel(row.route),{focusKey:`thread-${row.id}`})}</article>`).join("")}</section>`;
    }).join("");
    const rail=`<aside class="host-workbench-threads" aria-labelledby="hostWorkbenchThreadsTitle"><div class="workbench-thread-head"><div><span class="eyebrow">Read-only</span><h3 id="hostWorkbenchThreadsTitle">Open Threads</h3></div><span>${model.threads.length}</span></div><p class="workbench-thread-help">Opening a thread changes no status and records no outcome.</p>${threadGroups||empty(helpers,"No host-local work is currently open.")}</aside>`;
    const selectedContext=model.selected.endpoint
      ?`${model.selected.endpoint.identity} · ${model.selected.endpoint.service}`
      :model.selected.origin
        ?model.selected.origin.label
        :model.selected.access
          ?`${model.selected.access.principal} · ${model.selected.access.method} · ${model.selected.access.privilege}`
          :"No narrower context selected";
    return `<div class="host-workbench-shell"><header class="host-workbench-title"><div><span class="eyebrow">Host dispatcher</span><h2 tabindex="-1">Host Workbench</h2><p><strong>${e(helpers,model.target.label)}</strong> · ${e(helpers,model.target.address)} · ${e(helpers,selectedContext)}</p></div></header><div class="host-workbench-truth-strip" aria-label="Independent host truth dimensions">${model.dimensions.map(row=>`<article title="${a(helpers,row.reason)}"><span>${e(helpers,row.label)}</span><strong>${e(helpers,core.STATUS_LABELS[row.state]||row.label)}</strong></article>`).join("")}</div><div class="host-workbench-layout"><main class="host-workbench-primary"><div class="workbench-destination-head"><div><span class="eyebrow">Open a dedicated workspace</span><h3>Continue on this host</h3></div><p>Each destination opens the current host and supported context.</p></div><div class="workbench-destinations">${destinations}</div></main>${rail}</div></div>`;
  }

  return Object.freeze({
    VERSION,SECTION_IDS,DEFAULT_EXPANDED,ADVANCED_DESTINATIONS,
    LIMITS:Object.freeze({MAX_HOST_STATES,MAX_SECTIONS,MAX_ITEMS,MAX_THREADS,MAX_TIMELINE,MAX_FILTERS,MAX_SCROLL}),
    normalizeHostView,normalizeNavigationState,updateHostView,project,advancedRoute,render
  });
});
