(function(root,factory){
  const reconApi=(typeof module==="object"&&module.exports)
    ?require("./recon-projection.js")
    :(root&&root.AEROSReconProjection);
  const importApi=(typeof module==="object"&&module.exports)
    ?require("../imports/recon-import.js")
    :(root&&root.AEROSReconImport);
  const api=factory(reconApi||{},importApi||{});
  if(typeof module==="object"&&module.exports)module.exports=api;
  if(root)root.AEROSWebAppReview=api;
})(typeof globalThis!=="undefined"?globalThis:this,function(reconApi,importApi){
  "use strict";

  const VERSION=1;
  const WORKSPACE_VERSION=1;
  const MAX_STRING=500;
  const MAX_OBSERVATION=12000;
  const MAX_SOURCE_CARDS=12;
  const MAX_LIST_ITEMS=32;
  const MAX_RECORD_KEY=1024;
  const MAX_PAGES=1000;
  const MAX_FORMS=200;
  const MAX_PARAMETERS=1000;
  const MAX_ROUTES=1000;
  const MAX_CAPTURE_BYTES=262144;
  const IDENTITY_STATES=new Set(["established","candidate","clue-only","conflicting","unknown"]);
  const OPEN_OUTCOME_STATES=new Set(["failed","partial","conflicting","stale","deferred","unknown"]);
  const GENERIC_SERVER_PRODUCTS=new Set(["http","https","http-proxy","http-alt","ssl/http","www","web"]);
  const PAGE_STATES=new Set(["unreviewed","opened","reviewed","excluded"]);
  const RECOMMENDATION_DECISIONS=new Set(["accepted","dismissed"]);
  const ITEM_STATES=new Set(["unreviewed","mapped","reviewed","excluded"]);
  const COVERAGE_STATES=new Set(["not-reviewed","applicable","testing","tested-negative","lead","not-applicable","deferred"]);
  const RESOLVED_COVERAGE_STATES=new Set(["tested-negative","lead","not-applicable"]);
  const PARAMETER_LOCATIONS=new Set(["query","body","path","cookie","header","upload"]);
  const STAGES=Object.freeze([
    Object.freeze({id:"fingerprint",label:"Fingerprint"}),
    Object.freeze({id:"discovered-content",label:"Discovered Content"}),
    Object.freeze({id:"inputs-routes",label:"Inputs & APIs"}),
    Object.freeze({id:"testing-coverage",label:"Testing Coverage"}),
    Object.freeze({id:"imported-sources",label:"Imported Sources"})
  ]);
  const ATTACK_CLASSES=Object.freeze([
    Object.freeze({id:"sqli",label:"SQL injection"}),
    Object.freeze({id:"xss",label:"Cross-site scripting"}),
    Object.freeze({id:"path-traversal",label:"Path traversal / LFI"}),
    Object.freeze({id:"command-injection",label:"Command injection"}),
    Object.freeze({id:"idor",label:"IDOR / object authorization"}),
    Object.freeze({id:"file-upload",label:"File upload"}),
    Object.freeze({id:"authentication",label:"Authentication"}),
    Object.freeze({id:"authorization",label:"Authorization"}),
    Object.freeze({id:"csrf",label:"CSRF"}),
    Object.freeze({id:"ssrf",label:"SSRF"}),
    Object.freeze({id:"xxe",label:"XXE"}),
    Object.freeze({id:"deserialization",label:"Unsafe deserialization"})
  ]);
  const ATTACK_CLASS_IDS=new Set(ATTACK_CLASSES.map(row=>row.id));
  const INPUT_ATTACK_CLASSES=Object.freeze(ATTACK_CLASSES.filter(row=>["sqli","xss","path-traversal","command-injection","idor","file-upload","authorization"].includes(row.id)));
  const COVERAGE_TARGET_TYPES=new Set(["origin","parameter"]);
  const MAX_COVERAGE_RECORDS=(MAX_PARAMETERS+1)*ATTACK_CLASSES.length;
  const PROPOSAL_FIELDS=Object.freeze({
    server:Object.freeze(["name","version","identityState"]),
    application:Object.freeze(["name","version","identityState"]),
    http:Object.freeze(["title","serverHeader","redirectPath","cookies","methods","responseNote"])
  });
  const METHOD_DEFINITIONS=Object.freeze([
    Object.freeze({id:"nmap",label:"Nmap",noteTitle:"Nmap FingerPrinting Web Server"}),
    Object.freeze({id:"whatweb",label:"WhatWeb",noteTitle:"WhatWeb Fingerprinting Web Server"}),
    Object.freeze({id:"manual",label:"Manual review",noteTitle:"Manual Web Application Fingerprinting"})
  ]);

  function text(value,limit=MAX_STRING){
    const output=String(value??"").trim().replace(/[\u0000-\u001f\u007f]/g," ");
    return output.slice(0,Math.max(0,limit));
  }
  function values(value){return Array.isArray(value)?value:[];}
  function object(value){return value&&typeof value==="object"&&!Array.isArray(value)?value:{};}
  function number(value){const output=Number(value);return Number.isFinite(output)?output:0;}
  function optionalNumber(value){if(value===null||value===undefined||value==="")return null;const output=Number(value);return Number.isFinite(output)?output:null;}
  function unique(input,limit=MAX_LIST_ITEMS){
    const output=[];
    values(input).forEach(value=>{const item=text(value);if(item&&!output.includes(item)&&output.length<limit)output.push(item);});
    return output;
  }
  function originIdentity(origin={}){return text(origin.originId||origin.id);}
  function endpointIdentity(endpoint={}){return text(endpoint.endpointId||endpoint.id);}
  function exactOrigins(host={}){
    return values(host.recon?.webTargets).filter(row=>row&&row.recordRole==="web-origin"&&originIdentity(row));
  }
  function exactOriginUrl(origin={}){
    const candidate=text(origin.url||origin.value);
    try{
      const parsed=new URL(candidate);
      return ["http:","https:"].includes(parsed.protocol)?parsed.origin:"";
    }catch{return "";}
  }
  function identityState(value,fallback="unknown"){
    const state=text(value,40).toLowerCase();
    if(state==="positive")return "established";
    return IDENTITY_STATES.has(state)?state:fallback;
  }
  function sourceType(value){
    const source=text(value,120).toLowerCase();
    if(source.includes("multiple")||source.includes("combined"))return "multiple-sources";
    if(source.includes("whatweb"))return "whatweb";
    if(source.includes("nmap"))return "nmap";
    return source?"retained-evidence":"unknown";
  }
  function normalizedIdentity(input={},owner="manual"){
    const value=object(input);
    return {
      name:text(value.name),
      version:text(value.version)||"Unknown",
      identityState:identityState(value.identityState,value.name?"candidate":"unknown"),
      sourceType:owner==="manual"?"manual-review":sourceType(value.sourceType)
    };
  }
  function normalizedHttp(input={}){
    const value=object(input);
    return {
      title:text(value.title),
      serverHeader:text(value.serverHeader),
      redirectPath:text(value.redirectPath),
      cookies:unique(value.cookies),
      methods:unique(value.methods).map(item=>item.toUpperCase()),
      responseNote:text(value.responseNote,MAX_OBSERVATION)
    };
  }
  function normalizedManual(input={}){
    const value=object(input);
    return {
      methodsUsed:unique(value.methodsUsed),
      supportingObservation:text(value.supportingObservation,MAX_OBSERVATION)
    };
  }
  function normalizedReview(input={},options={}){
    const value=object(input),existing=object(options.existing),now=text(options.now)||new Date().toISOString();
    return {
      schemaVersion:VERSION,
      owner:"manual",
      server:normalizedIdentity(value.server,"manual"),
      application:normalizedIdentity(value.application,"manual"),
      http:normalizedHttp(value.http),
      manual:normalizedManual(value.manual),
      reviewedAt:text(existing.reviewedAt)||now,
      updatedAt:now
    };
  }
  function saveFingerprintReview(origin,input={},options={}){
    if(!origin||typeof origin!=="object"||Array.isArray(origin)||!originIdentity(origin)||!exactOriginUrl(origin))return null;
    const review=normalizedReview(input,{existing:origin.fingerprintReview,now:options.now});
    origin.fingerprintReview=review;
    return review;
  }
  function clearFingerprintReview(origin){
    if(!origin||typeof origin!=="object"||Array.isArray(origin)||!("fingerprintReview" in origin))return false;
    delete origin.fingerprintReview;
    return true;
  }
  function draftCopy(input={}){
    const value=object(input);
    const http={...object(value.http)},manual={...object(value.manual)};
    http.cookies=[...values(http.cookies)];
    http.methods=[...values(http.methods)];
    manual.methodsUsed=[...values(manual.methodsUsed)];
    return {
      server:{...object(value.server)},
      application:{...object(value.application)},
      http,
      manual
    };
  }
  function blank(value){return Array.isArray(value)?value.length===0:value===undefined||value===null||text(value)==="";}
  function emptyFieldValue(section,field){return field==="identityState"?"unknown":section==="http"&&["cookies","methods"].includes(field)?[]:"";}
  function meaningfulProposalValue(section,field,value,sectionProposal={}){
    if(blank(value))return false;
    if((section==="server"||section==="application")&&!text(sectionProposal.name))return false;
    if(field==="identityState")return identityState(value)==="unknown"?false:true;
    return true;
  }
  function assignField(owner,field,value){owner[field]=Array.isArray(value)?[...value]:value;}
  function mergeProposal(draft={},proposal={},options={}){
    const output=draftCopy(draft),originalIdentityNames={server:text(output.server.name),application:text(output.application.name)},proposedFields=[],previousProposed=new Set(values(options.proposedFields).map(value=>text(value))),operatorFields=new Set(values(options.operatorFields).map(value=>text(value))),preserveUnknown=options.preserveUnknown===true;
    Object.entries(PROPOSAL_FIELDS).forEach(([section,fields])=>{
      const sectionProposal=object(proposal[section]);
      fields.forEach(field=>{
        const path=`${section}.${field}`,value=sectionProposal[field],meaningful=meaningfulProposalValue(section,field,value,sectionProposal);
        if(operatorFields.has(path))return;
        if(previousProposed.has(path)){
          if(meaningful){assignField(output[section],field,value);proposedFields.push(path);}
          else assignField(output[section],field,emptyFieldValue(section,field));
          return;
        }
        const current=output[section][field],available=blank(current)||(field==="identityState"&&identityState(current)==="unknown"&&(!preserveUnknown||!originalIdentityNames[section]));
        if(!meaningful||!available)return;
        assignField(output[section],field,value);
        proposedFields.push(path);
      });
    });
    return {draft:output,proposedFields};
  }
  function initializeDraft(review={},proposal={}){
    return mergeProposal(review,proposal,{preserveUnknown:object(review).owner==="manual"});
  }
  function refreshDraft(draft={},proposal={},proposedFields=[],operatorFields=[]){
    return mergeProposal(draft,proposal,{proposedFields,operatorFields});
  }
  function comparable(value){const output=text(value).toLowerCase();return output&&output!=="unknown"?output:"";}
  function identityConflict(manual={},proposal={}){
    return ["name","version","identityState"].some(field=>{
      const left=comparable(manual[field]),right=comparable(proposal[field]);
      return Boolean(left&&right&&left!==right);
    });
  }
  function manualConflicts(manual={},proposal={}){
    const left=object(manual),right=object(proposal);
    return identityConflict(object(left.server),object(right.server))||identityConflict(object(left.application),object(right.application));
  }

  function stableId(prefix,value=""){
    let hash=2166136261;
    for(const character of String(value)){hash^=character.charCodeAt(0);hash=Math.imul(hash,16777619);}
    return `${prefix}-${(hash>>>0).toString(36)}`;
  }
  function normalizedReviewUrl(candidate,baseUrl=""){
    try{
      const parsed=baseUrl?new URL(String(candidate||""),baseUrl):new URL(String(candidate||""));
      if(!["http:","https:"].includes(parsed.protocol))return "";
      parsed.hash="";
      return parsed.toString();
    }catch{return "";}
  }
  function exactReviewOrigin(candidate){
    try{return new URL(candidate).origin;}catch{return "";}
  }
  function discoveredPagePath(page={}){
    const candidate=normalizedReviewUrl(page.url),parsed=candidate?new URL(candidate):null;
    return text(page.path,MAX_RECORD_KEY)||parsed?.pathname||"/";
  }
  function discoveredPageQuery(page={}){
    const candidate=normalizedReviewUrl(page.url),parsed=candidate?new URL(candidate):null;
    const query=text(page.query,MAX_RECORD_KEY)||parsed?.search||"";
    return query&&query.startsWith("?")?query:query?`?${query}`:"";
  }
  function discoveredContentType(page={}){return text(page.contentType,256).split(";",1)[0].trim().toLowerCase();}
  function discoveredLoginRoute(path=""){
    return /(?:^|\/)(?:login|log-in|signin|sign-in|authenticate|authentication|auth)(?:[.\/_-]|$)/i.test(String(path||""));
  }
  function discoveredUploadRoute(path=""){
    return /(?:^|\/)(?:upload|uploads|file-upload|file_upload|attachments?)(?:[.\/_-]|$)/i.test(String(path||""));
  }
  function classifyDiscoveredPageEvidence(page={},originUrl=""){
    const url=normalizedReviewUrl(page.url,originUrl),path=discoveredPagePath({...page,url:url||page.url}),query=discoveredPageQuery({...page,url:url||page.url}),status=optionalNumber(page.status),contentType=discoveredContentType(page),lastComponent=(path.split("/").filter(Boolean).pop()||"").toLowerCase();
    const successful=status!==null&&status>=200&&status<=299,redirect=status!==null&&status>=300&&status<=399,authenticationSurface=status===401||status===403,methodSurface=status===405,serverErrorSurface=status!==null&&status>=500&&status<=599;
    const structuredEndpoint=contentType==="application/json"||contentType==="application/xml"||contentType==="text/xml"||contentType==="text/json"||/^application\/[a-z0-9.!#$&^_+-]+\+(?:json|xml)$/i.test(contentType);
    const staticAsset=contentType.startsWith("image/")||contentType.startsWith("font/")||contentType==="text/css"||lastComponent==="favicon.ico";
    const normalFileSuffix=/\.[a-z0-9]{1,12}$/i.test(lastComponent),directoryCandidate=path!=="/"&&!normalFileSuffix&&!staticAsset&&(successful||authenticationSurface||methodSurface);
    const knownBody=[page.length,page.words,page.lines].some(value=>optionalNumber(value)!==null)||Boolean(contentType),genericContent=successful&&knownBody&&!staticAsset;
    const webdavCandidate=/^\/webdav(?:\/|$)/i.test(path),loginRoute=discoveredLoginRoute(path),uploadSurface=discoveredUploadRoute(path);
    const evidenceFlags={authenticationSurface,methodSurface,serverErrorSurface,structuredEndpoint,directoryCandidate,genericContent,redirect,staticAsset,webdavCandidate,loginRoute,uploadSurface};
    let primary={kind:"other",label:"Other",rank:9,cssClass:"web-app-review-disco-other"};
    if(authenticationSurface)primary={kind:"authentication-surface",label:"Auth surface",rank:1,cssClass:"web-app-review-disco-auth-glow"};
    else if(methodSurface)primary={kind:"method-surface",label:"Method surface",rank:2,cssClass:"web-app-review-disco-method-glow"};
    else if(serverErrorSurface)primary={kind:"server-error-candidate",label:"Server error",rank:3,cssClass:"web-app-review-disco-error-glow"};
    else if(structuredEndpoint)primary={kind:"structured-endpoint",label:"Structured",rank:4,cssClass:"web-app-review-disco-structured-glow"};
    else if(directoryCandidate)primary={kind:"directory-route-candidate",label:"Route candidate",rank:5,cssClass:"web-app-review-disco-route-glow"};
    else if(genericContent)primary={kind:"generic-successful-content",label:"Content",rank:6,cssClass:"web-app-review-disco-content"};
    else if(redirect)primary={kind:"redirect",label:"Redirect",rank:7,cssClass:"web-app-review-disco-redirect"};
    else if(staticAsset)primary={kind:"static-asset",label:"Static",rank:8,cssClass:"web-app-review-disco-static-dim"};
    return {...primary,path,query,pathWithQuery:`${path}${query}`,contentType,status,evidenceFlags,cssClasses:[primary.cssClass]};
  }
  function rankDiscoveredPageEvidence(page={},originUrl=""){
    const current=optionalNumber(page.significanceRank);return current===null?classifyDiscoveredPageEvidence(page,originUrl).rank:current;
  }
  function discoveredPageRecommendations(page={},context={}){
    const classification=page.evidenceFlags?{...page,evidenceFlags:page.evidenceFlags}:classifyDiscoveredPageEvidence(page,context.originUrl),flags=classification.evidenceFlags||{},recordKey=text(page.recordKey,MAX_RECORD_KEY),path=classification.path||discoveredPagePath(page),pathWithQuery=classification.pathWithQuery||`${path}${discoveredPageQuery(page)}`;
    const mappedUpload=values(context.parameters).some(parameter=>text(parameter?.pageKey,MAX_RECORD_KEY)===recordKey&&(text(parameter?.location,32).toLowerCase()==="upload"||text(parameter?.type,80).toLowerCase()==="file")),kinds=[],followUps=[];
    const addFollowUp=value=>{if(value&&!followUps.includes(value))followUps.push(value);};
    if(flags.webdavCandidate){
      kinds.push("webdav-auth-method-review");
      if(flags.authenticationSurface)addFollowUp("Review the authentication boundary.");
      addFollowUp("Review WebDAV behavior and retained method evidence.");addFollowUp("Use the existing deeper-path owner for meaningful child paths.");
    }else if(flags.authenticationSurface){kinds.push("authentication-authorization-review");addFollowUp("Review the authentication and authorization boundary.");}
    if(flags.structuredEndpoint){kinds.push("structured-endpoint-inspection");addFollowUp("Inspect the structured endpoint and map its existing API owner.");}
    if(flags.loginRoute){kinds.push("login-authentication-route");addFollowUp("Review the login or authentication route and its mapped inputs.");}
    if(flags.directoryCandidate&&!flags.webdavCandidate){kinds.push("directory-route-follow-up");addFollowUp("Use the existing deeper-path task for this meaningful route candidate.");}
    if(flags.uploadSurface||mappedUpload){kinds.push("upload-surface-review");addFollowUp("Review the named upload route or already mapped file input.");}
    if(!kinds.length)return [];
    const priority=["webdav-auth-method-review","login-authentication-route","upload-surface-review","authentication-authorization-review","structured-endpoint-inspection","directory-route-follow-up"],primaryKind=priority.find(kind=>kinds.includes(kind))||kinds[0];
    const definitions={
      "webdav-auth-method-review":{label:"WebDAV / auth / method review",reason:"The retained exact-origin path identifies a WebDAV surface and may also expose an authentication boundary or deeper-path interest.",openOwner:{destination:"recon",subview:"content",objectiveId:"web-deeper-path-discovery",label:"Open deeper-path owner"}},
      "authentication-authorization-review":{label:"Authentication / authorization review",reason:"The retained status identifies an authentication or authorization boundary.",openOwner:{destination:"web-app-review",subview:"testing-coverage",objectiveId:"web-application-mapping",label:"Open testing coverage"}},
      "structured-endpoint-inspection":{label:"Structured endpoint inspection",reason:"The retained content type identifies a JSON, XML, or Atom endpoint.",openOwner:{destination:"recon",subview:"api-content",objectiveId:"api-endpoint-discovery",label:"Open API owner"}},
      "login-authentication-route":{label:"Login / authentication route",reason:"The retained path explicitly identifies a login or authentication route.",openOwner:{destination:"web-app-review",subview:"inputs-routes",objectiveId:"web-application-mapping",label:"Open Inputs & APIs"}},
      "directory-route-follow-up":{label:"Directory / route follow-up",reason:"The retained extensionless path is a meaningful deeper-path candidate.",openOwner:{destination:"recon",subview:"content",objectiveId:"web-deeper-path-discovery",label:"Open deeper-path owner"}},
      "upload-surface-review":{label:"Upload surface review",reason:"The route name or an already mapped file input identifies an upload surface.",openOwner:{destination:"web-app-review",subview:"inputs-routes",objectiveId:"web-application-mapping",label:"Open Inputs & APIs"}}
    },definition=definitions[primaryKind];
    return [{
      id:stableId("web-recommendation",`url|${page.url}`),recordKey,url:text(page.url,MAX_RECORD_KEY),path,pathWithQuery,primaryKind,kinds:[...kinds],label:definition.label,reason:definition.reason,followUps,openOwner:definition.openOwner,decision:"suggested",
      metadata:{url:text(page.url,MAX_RECORD_KEY),path:pathWithQuery,status:optionalNumber(page.status),contentType:text(page.contentType,256),length:optionalNumber(page.length),redirect:text(page.redirect,MAX_STRING),sourceTools:[...values(page.sourceTools)],sourceIds:[...values(page.sourceIds)]}
    }];
  }
  function completedExactOriginDiscoverySources(host={},originId="",endpointId=""){
    return values(host.recon?.webImportProjection?.sources).filter(source=>{
      const matchingRecords=values(source?.records).filter(record=>text(record?.originId,MAX_RECORD_KEY)===originId&&text(record?.endpointId,MAX_RECORD_KEY)===endpointId),ownsOrigin=values(source?.originIds).map(value=>text(value,MAX_RECORD_KEY)).includes(originId)||matchingRecords.length>0,ownsEndpoint=text(source?.endpointId,MAX_RECORD_KEY)===endpointId||matchingRecords.length>0,state=text(source?.operationState||source?.operationStatus||source?.status,40).toLowerCase();
      return ownsOrigin&&ownsEndpoint&&["complete","completed","negative"].includes(state);
    }).map(source=>({id:text(source?.key||source?.id,MAX_RECORD_KEY),tool:text(source?.tool,64),operationState:text(source?.operationState||source?.operationStatus||source?.status,40),resultCount:optionalNumber(source?.resultCount)??values(source?.records).length}));
  }
  function canonicalPageRecords(host={},originId="",endpointId=""){
    const rows=[],byUrl=new Map(),sources=values(host.recon?.webImportProjection?.sources);
    const ingest=(record,source={})=>{
      if(text(record?.originId,MAX_RECORD_KEY)!==originId||text(record?.endpointId,MAX_RECORD_KEY)!==endpointId)return;
      const url=normalizedReviewUrl(record?.url);if(!url)return;
      let row=byUrl.get(url);
      if(!row){
        const parsed=new URL(url),recordKey=`url:${url}`;
        row={
          id:stableId("web-page",recordKey),recordKey,canonicalKey:text(record?.key||record?.id,MAX_RECORD_KEY),url,
          path:parsed.pathname||"/",query:parsed.search||"",method:text(record?.method||"GET",24).toUpperCase()||"GET",
          status:optionalNumber(record?.status),length:optionalNumber(record?.length),words:optionalNumber(record?.words),lines:optionalNumber(record?.lines),
          contentType:text(record?.contentType,256),redirect:text(record?.redirect,MAX_STRING),sourceTools:[],sourceIds:[],lastObservedAt:""
        };
        byUrl.set(url,row);rows.push(row);
      }
      for(const field of ["status","length","words","lines"]){if(record?.[field]!==null&&record?.[field]!==undefined&&record?.[field]!=="")row[field]=optionalNumber(record[field]);}
      for(const field of ["contentType","redirect"]){if(text(record?.[field],field==="contentType"?256:MAX_STRING))row[field]=text(record[field],field==="contentType"?256:MAX_STRING);}
      const tool=text(source?.tool||record?.tool||values(record?.sources)[0]?.tool,64),sourceId=text(source?.key||source?.artifactId||record?.sourceContributionKey||values(record?.sources)[0]?.contributionKey||values(record?.sources)[0]?.artifactId,MAX_RECORD_KEY);
      if(tool&&!row.sourceTools.includes(tool))row.sourceTools.push(tool);
      if(sourceId&&!row.sourceIds.includes(sourceId))row.sourceIds.push(sourceId);
      const observedAt=text(source?.observedAt||record?.lastSeenAt||values(record?.sources)[0]?.observedAt,64);if(observedAt>row.lastObservedAt)row.lastObservedAt=observedAt;
    };
    sources.forEach(source=>values(source?.records).forEach(record=>ingest(record,source)));
    values(host.recon?.technologyImportProjection?.sources).forEach(source=>values(source?.records).forEach(record=>{
      if(text(record?.originId,MAX_RECORD_KEY)!==originId||text(record?.endpointId,MAX_RECORD_KEY)!==endpointId)return;
      ingest({originId,endpointId,url:record.targetUrl,status:record.status,redirect:record.redirect,method:"GET",contentType:""},source);
      values(record?.discoveredRoutes).forEach(route=>ingest({originId,endpointId,url:route.url,status:route.status,method:route.method||"GET",contentType:"",redirect:""},source));
    }));
    values(host.recon?.webTargets).filter(record=>record?.recordRole!=="web-origin").forEach(record=>ingest(record,{}));
    return rows.slice(0,MAX_PAGES).sort((left,right)=>left.path.localeCompare(right.path)||left.url.localeCompare(right.url));
  }
  function queryParametersForPages(pages=[]){
    const output=[];
    values(pages).forEach(page=>{
      let parsed;try{parsed=new URL(page.url);}catch{return;}
      const seen=new Set();
      parsed.searchParams.forEach((_value,name)=>{
        const parameterName=text(name,MAX_STRING);if(!parameterName||seen.has(parameterName)||output.length>=MAX_PARAMETERS)return;seen.add(parameterName);
        output.push({
          id:stableId("web-param",[page.recordKey,"","query",parameterName].join("|")),pageKey:page.recordKey,formId:"",name:parameterName,
          location:"query",type:"string",required:false,reviewState:"mapped",notes:"Derived from the retained discovered URL.",sourceOwner:"canonical-url"
        });
      });
    });
    return output;
  }
  function htmlAttributes(source=""){
    const output={};
    String(source||"").replace(/([^\s=/>]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?/g,(_all,key,doubleQuoted,singleQuoted,bare)=>{
      output[String(key||"").toLowerCase()]=doubleQuoted??singleQuoted??bare??true;return _all;
    });
    return output;
  }
  function analyzeCapturedDocument(input={}){
    const value=object(input),originUrl=exactReviewOrigin(normalizedReviewUrl(value.originUrl)),pageUrl=normalizedReviewUrl(value.pageUrl||originUrl,originUrl),pageKey=text(value.pageKey,MAX_RECORD_KEY)||`url:${pageUrl}`;
    if(!originUrl||!pageUrl||exactReviewOrigin(pageUrl)!==originUrl)return {ok:false,reason:"Captured markup requires one exact HTTP(S) origin and an owned page URL.",forms:[],parameters:[],routes:[]};
    const source=String(value.html||value.javascript||"").slice(0,MAX_CAPTURE_BYTES),forms=[],parameters=[],routes=[],parameterKeys=new Set(),routeKeys=new Set();
    const addParameter=raw=>{
      if(parameters.length>=MAX_PARAMETERS)return;
      const location=PARAMETER_LOCATIONS.has(text(raw.location,32).toLowerCase())?text(raw.location,32).toLowerCase():"query",name=text(raw.name);
      if(!name)return;
      const key=[text(raw.pageKey||pageKey,MAX_RECORD_KEY),text(raw.formId,MAX_RECORD_KEY),location,name].join("|");if(parameterKeys.has(key))return;parameterKeys.add(key);
      parameters.push({id:text(raw.id,MAX_RECORD_KEY)||stableId("web-param",key),pageKey:text(raw.pageKey||pageKey,MAX_RECORD_KEY),formId:text(raw.formId,MAX_RECORD_KEY),name,location,type:text(raw.type,80)||"string",required:raw.required===true,reviewState:"mapped",notes:text(raw.notes,MAX_OBSERVATION),sourceOwner:"captured-document"});
    };
    const addRoute=(candidate,metadata={})=>{
      if(routes.length>=MAX_ROUTES)return;
      const url=normalizedReviewUrl(candidate,pageUrl);if(!url||exactReviewOrigin(url)!==originUrl)return;
      const parsed=new URL(url),method=text(metadata.method||"GET",24).toUpperCase()||"GET",key=`${method}|${url}`;if(routeKeys.has(key))return;routeKeys.add(key);
      const kind=text(metadata.kind,80)||(/(?:^|\/)(?:api|rest|graphql)(?:\/|$)/i.test(parsed.pathname)?"api":"client-route");
      const id=stableId("web-route",key);
      routes.push({id,pageKey,path:parsed.pathname||"/",url,method,kind,reviewState:"mapped",testingRequired:null,notes:"",sourceOwner:"captured-document"});
      const seen=new Set();parsed.searchParams.forEach((_entry,name)=>{if(!seen.has(name)){seen.add(name);addParameter({pageKey,formId:"",name,location:"query",type:"string",notes:`Derived from captured ${kind}.`});}});
    };
    const formPattern=/<form\b([^>]*)>([\s\S]*?)<\/form\s*>/gi;
    for(const formMatch of source.matchAll(formPattern)){
      if(forms.length>=MAX_FORMS)break;
      const attrs=htmlAttributes(formMatch[1]),method=text(attrs.method||"GET",24).toUpperCase()||"GET",action=normalizedReviewUrl(attrs.action||pageUrl,pageUrl);
      if(!action||exactReviewOrigin(action)!==originUrl)continue;
      const formId=text(attrs.id||attrs.name,MAX_RECORD_KEY)||stableId("web-form",`${pageKey}|${method}|${action}|${forms.length}`);
      const form={id:formId,pageKey,name:text(attrs.name||attrs.id),action,method,reviewState:"mapped",authenticated:null,notes:"",sourceOwner:"captured-document"};forms.push(form);addRoute(action,{method,kind:"form-action"});
      const controlPattern=/<(?:input|select|textarea|button)\b([^>]*)>/gi;
      for(const controlMatch of formMatch[2].matchAll(controlPattern)){
        const control=htmlAttributes(controlMatch[1]),name=text(control.name);if(!name)continue;
        const type=text(control.type,80).toLowerCase()||"string",location=type==="file"?"upload":method==="GET"?"query":"body";
        addParameter({pageKey,formId,name,location,type,required:Object.prototype.hasOwnProperty.call(control,"required")});
      }
    }
    const taggedUrlPattern=/<(?:a|link|script|img|iframe|form)\b([^>]*)>/gi;
    for(const tagged of source.matchAll(taggedUrlPattern)){const attrs=htmlAttributes(tagged[1]);["href","src","action"].forEach(name=>{if(typeof attrs[name]==="string")addRoute(attrs[name],{method:name==="action"?attrs.method||"GET":"GET",kind:name==="action"?"form-action":"client-route"});});}
    const quotedRoutePattern=/(?:["'`])((?:https?:\/\/|\/)[^"'`\s<>]{1,2048})(?:["'`])/g;
    for(const routeMatch of source.matchAll(quotedRoutePattern))addRoute(routeMatch[1],{kind:/(?:^|\/)(?:api|rest|graphql)(?:\/|$)/i.test(routeMatch[1])?"api":"client-route"});
    return {ok:true,originUrl,pageUrl,pageKey,forms,parameters,routes,summary:{forms:forms.length,parameters:parameters.length,routes:routes.length,truncated:String(value.html||value.javascript||"").length>MAX_CAPTURE_BYTES}};
  }
  function whatWebRecordsForOrigin(host={},originId="",endpointId=""){
    return values(host.recon?.technologyImportProjection?.sources).flatMap(source=>values(source?.records).map(record=>({source,record}))).filter(row=>text(row.record?.originId,MAX_RECORD_KEY)===originId&&text(row.record?.endpointId,MAX_RECORD_KEY)===endpointId);
  }
  function whatWebSourceParameters(host={},originId="",endpointId=""){
    const output=[],seen=new Set();
    whatWebRecordsForOrigin(host,originId,endpointId).forEach(({source,record})=>values(record?.inputs).forEach(raw=>{
      const name=text(raw?.name),pageUrl=normalizedReviewUrl(raw?.pageUrl||record.targetUrl),pageKey=pageUrl?`url:${pageUrl}`:"",location=PARAMETER_LOCATIONS.has(text(raw?.location,32).toLowerCase())?text(raw.location,32).toLowerCase():"body",key=[pageKey,location,name].join("|");
      if(!name||seen.has(key)||output.length>=MAX_PARAMETERS)return;seen.add(key);
      output.push({id:stableId("web-param",`whatweb|${key}`),pageKey,formId:"",name,location,type:text(raw?.type,80)||"string",required:false,reviewState:"mapped",notes:text(raw?.notes,MAX_OBSERVATION)||"Observed by WhatWeb; form method and action remain unconfirmed.",sourceOwner:"whatweb",sourceId:text(source?.key,MAX_RECORD_KEY),coverageEligible:raw?.coverageEligible===true});
    }));
    return output;
  }
  function whatWebSourceRoutes(host={},originId="",endpointId=""){
    const output=[],seen=new Set();
    whatWebRecordsForOrigin(host,originId,endpointId).forEach(({source,record})=>values(record?.discoveredRoutes).forEach(raw=>{
      const url=normalizedReviewUrl(raw?.url,record.targetUrl||record.sourceOrigin),method=text(raw?.method||"GET",24).toUpperCase()||"GET",key=`${method}|${url}`;
      if(!url||seen.has(key)||output.length>=MAX_ROUTES)return;seen.add(key);
      const parsed=new URL(url);output.push({id:stableId("web-route",`whatweb|${key}`),pageKey:`url:${normalizedReviewUrl(record.targetUrl)}`,path:parsed.pathname||"/",url,method,kind:text(raw?.kind,80)||"client-route",reviewState:"mapped",testingRequired:null,notes:text(raw?.notes,MAX_OBSERVATION),sourceOwner:"whatweb",sourceId:text(source?.key,MAX_RECORD_KEY)});
    }));
    return output;
  }
  function normalizePageReviews(input=[],existing=[],now=""){
    const existingByKey=new Map(values(existing).map(row=>[text(row?.recordKey,MAX_RECORD_KEY),row])),seen=new Set(),output=[];
    values(input).forEach(raw=>{
      if(output.length>=MAX_PAGES)return;
      const recordKey=text(raw?.recordKey,MAX_RECORD_KEY);if(!recordKey||seen.has(recordKey))return;seen.add(recordKey);
      const prior=object(existingByKey.get(recordKey)),state=PAGE_STATES.has(text(raw?.state,32).toLowerCase())?text(raw.state,32).toLowerCase():"unreviewed",testingRequired=typeof raw?.testingRequired==="boolean"?raw.testingRequired:null,notes=text(raw?.notes,MAX_OBSERVATION),openedAt=text(prior.openedAt||raw?.openedAt,64)||(state==="opened"||state==="reviewed"?now:""),reviewedAt=text(prior.reviewedAt||raw?.reviewedAt,64)||(state==="reviewed"||state==="excluded"?now:"");
      if(state==="unreviewed"&&testingRequired===null&&!notes&&!openedAt&&!reviewedAt)return;
      output.push({recordKey,state,testingRequired,notes,openedAt,reviewedAt,updatedAt:now});
    });
    return output;
  }
  function normalizeRecommendationDecisions(input=[],existing=[],now=""){
    const existingById=new Map(values(existing).map(row=>[text(row?.id,MAX_RECORD_KEY),row])),seen=new Set(),output=[];
    values(input).forEach(raw=>{const id=text(raw?.id,MAX_RECORD_KEY),decision=text(raw?.decision,32).toLowerCase();if(!id||seen.has(id)||!RECOMMENDATION_DECISIONS.has(decision))return;seen.add(id);const prior=object(existingById.get(id));output.push({id,decision,updatedAt:text(prior.decision,32).toLowerCase()===decision?text(prior.updatedAt,64)||now:now});});
    return output;
  }
  function normalizeForms(input=[]){
    const output=[],seen=new Set();values(input).forEach((raw,index)=>{if(output.length>=MAX_FORMS)return;const pageKey=text(raw?.pageKey,MAX_RECORD_KEY),action=normalizedReviewUrl(raw?.action),method=text(raw?.method||"GET",24).toUpperCase()||"GET",id=text(raw?.id,MAX_RECORD_KEY)||stableId("web-form",`${pageKey}|${method}|${action}|${index}`);if(!id||seen.has(id))return;seen.add(id);const reviewState=ITEM_STATES.has(text(raw?.reviewState,32).toLowerCase())?text(raw.reviewState,32).toLowerCase():"unreviewed";output.push({id,pageKey,name:text(raw?.name),action,method,reviewState,authenticated:typeof raw?.authenticated==="boolean"?raw.authenticated:null,notes:text(raw?.notes,MAX_OBSERVATION),sourceOwner:"manual-review"});});return output;
  }
  function normalizeParameters(input=[]){
    const output=[],seen=new Set();values(input).forEach((raw,index)=>{if(output.length>=MAX_PARAMETERS)return;const pageKey=text(raw?.pageKey,MAX_RECORD_KEY),formId=text(raw?.formId,MAX_RECORD_KEY),name=text(raw?.name),location=PARAMETER_LOCATIONS.has(text(raw?.location,32).toLowerCase())?text(raw.location,32).toLowerCase():"query";if(!name)return;const id=text(raw?.id,MAX_RECORD_KEY)||stableId("web-param",`${pageKey}|${formId}|${location}|${name}|${index}`);if(seen.has(id))return;seen.add(id);const reviewState=ITEM_STATES.has(text(raw?.reviewState,32).toLowerCase())?text(raw.reviewState,32).toLowerCase():"unreviewed";output.push({id,pageKey,formId,name,location,type:text(raw?.type,80)||"string",required:raw?.required===true,reviewState,notes:text(raw?.notes,MAX_OBSERVATION),sourceOwner:"manual-review"});});return output;
  }
  function normalizeRoutes(input=[]){
    const output=[],seen=new Set();values(input).forEach((raw,index)=>{if(output.length>=MAX_ROUTES)return;const pageKey=text(raw?.pageKey,MAX_RECORD_KEY),url=normalizedReviewUrl(raw?.url),path=text(raw?.path,MAX_RECORD_KEY)||(url?new URL(url).pathname:""),method=text(raw?.method||"GET",24).toUpperCase()||"GET";if(!path&&!url)return;const id=text(raw?.id,MAX_RECORD_KEY)||stableId("web-route",`${pageKey}|${method}|${url||path}|${index}`);if(seen.has(id))return;seen.add(id);const reviewState=ITEM_STATES.has(text(raw?.reviewState,32).toLowerCase())?text(raw.reviewState,32).toLowerCase():"unreviewed";output.push({id,pageKey,path,url,method,kind:text(raw?.kind,80)||"client-route",reviewState,testingRequired:typeof raw?.testingRequired==="boolean"?raw.testingRequired:null,notes:text(raw?.notes,MAX_OBSERVATION),sourceOwner:"manual-review"});});return output;
  }
  function normalizeCoverage(input=[]){
    const output=[],seen=new Set();values(input).forEach(raw=>{const attackClass=text(raw?.attackClass,80).toLowerCase(),targetType=COVERAGE_TARGET_TYPES.has(text(raw?.targetType,32).toLowerCase())?text(raw.targetType,32).toLowerCase():"origin",targetId=targetType==="origin"?"":text(raw?.targetId,MAX_RECORD_KEY),key=`${targetType}|${targetId}|${attackClass}`;if(output.length>=MAX_COVERAGE_RECORDS||!ATTACK_CLASS_IDS.has(attackClass)||(targetType!=="origin"&&!targetId)||seen.has(key))return;seen.add(key);const status=COVERAGE_STATES.has(text(raw?.status,40).toLowerCase())?text(raw.status,40).toLowerCase():"not-reviewed";output.push({targetType,targetId,attackClass,status,notes:text(raw?.notes,MAX_OBSERVATION),evidenceRefs:unique(raw?.evidenceRefs,16)});});return output;
  }
  function coverageResolved(row={}){return RESOLVED_COVERAGE_STATES.has(text(row.status,40).toLowerCase())&&Boolean(text(row.notes,MAX_OBSERVATION));}
  function normalizedWorkspaceReview(input={},options={}){
    const value=object(input),existing=object(options.existing),now=text(options.now,64)||new Date().toISOString();
    return {schemaVersion:WORKSPACE_VERSION,owner:"manual",pages:normalizePageReviews(value.pages,existing.pages,now),recommendations:normalizeRecommendationDecisions(value.recommendations,existing.recommendations,now),forms:normalizeForms(value.forms),parameters:normalizeParameters(value.parameters),routes:normalizeRoutes(value.routes),coverage:normalizeCoverage(value.coverage),notes:text(value.notes,MAX_OBSERVATION),reviewedAt:text(existing.reviewedAt,64)||now,updatedAt:now};
  }
  function saveWorkspaceReview(origin,input={},options={}){
    if(!origin||typeof origin!=="object"||Array.isArray(origin)||!originIdentity(origin)||!exactOriginUrl(origin))return null;
    const review=normalizedWorkspaceReview(input,{existing:origin.webReview,now:options.now});origin.webReview=review;return review;
  }
  function clearWorkspaceReview(origin){if(!origin||typeof origin!=="object"||Array.isArray(origin)||!("webReview" in origin))return false;delete origin.webReview;return true;}
  function operationalProjection(host,origin,originId,endpointId,fingerprintReview){
    const review=object(origin.webReview).owner==="manual"?origin.webReview:null,pageAnnotations=new Map(values(review?.pages).map(row=>[text(row?.recordKey,MAX_RECORD_KEY),row]));
    const originUrl=exactOriginUrl(origin),baseline=typeof importApi.webBaselineForOrigin==="function"?importApi.webBaselineForOrigin(object(host.recon),originId):null,baselineOrder={distinct:0,"not-imported":1,unknown:2,"possible-baseline-like":3,"baseline-like":4};let pages=canonicalPageRecords(host,originId,endpointId).map(page=>{const annotation=object(pageAnnotations.get(page.recordKey)),state=PAGE_STATES.has(text(annotation.state,32).toLowerCase())?text(annotation.state,32).toLowerCase():"unreviewed",classification=classifyDiscoveredPageEvidence(page,originUrl),baselineComparison=typeof importApi.compareWebRecordToBaseline==="function"?importApi.compareWebRecordToBaseline(page,baseline):{state:baseline?"unknown":"not-imported",label:baseline?"Baseline comparison unavailable":"No baseline imported",reason:"",cssClass:""};return {...page,significanceKind:classification.kind,significanceLabel:classification.label,significanceRank:classification.rank,evidenceFlags:classification.evidenceFlags,cssClasses:[...classification.cssClasses,baselineComparison.cssClass].filter(Boolean),baselineState:baselineComparison.state,baselineLabel:baselineComparison.label,baselineReason:baselineComparison.reason,baselineShape:baselineComparison.shape,baselineMatchedFields:baselineComparison.matchedFields||[],baselineDifferentFields:baselineComparison.differentFields||[],baselineFilename:baselineComparison.baselineFilename||"",baselineRevision:baselineComparison.baselineRevision||0,state,testingRequired:typeof annotation.testingRequired==="boolean"?annotation.testingRequired:null,notes:text(annotation.notes,MAX_OBSERVATION),openedAt:text(annotation.openedAt,64),reviewedAt:text(annotation.reviewedAt,64),updatedAt:text(annotation.updatedAt,64)};}).sort((left,right)=>(baselineOrder[left.baselineState]??2)-(baselineOrder[right.baselineState]??2)||rankDiscoveredPageEvidence(left)-rankDiscoveredPageEvidence(right)||`${left.path}${left.query}`.localeCompare(`${right.path}${right.query}`)||left.url.localeCompare(right.url));
    const liveKeys=new Set(pages.map(page=>page.recordKey)),orphanedPageReviews=values(review?.pages).filter(row=>!liveKeys.has(text(row?.recordKey,MAX_RECORD_KEY))).length;
    const forms=normalizeForms(review?.forms),manualParameters=normalizeParameters(review?.parameters),parameterById=new Map(queryParametersForPages(pages).map(row=>[row.id,row]));whatWebSourceParameters(host,originId,endpointId).forEach(row=>parameterById.set(row.id,row));manualParameters.forEach(row=>parameterById.set(row.id,row));const parameters=[...parameterById.values()];
    const routeById=new Map(whatWebSourceRoutes(host,originId,endpointId).map(row=>[row.id,row]));normalizeRoutes(review?.routes).forEach(row=>routeById.set(row.id,row));const routes=[...routeById.values()],savedCoverage=normalizeCoverage(review?.coverage),coverageByKey=new Map(savedCoverage.map(row=>[`${row.targetType}|${row.targetId}|${row.attackClass}`,row]));
    const coverage=ATTACK_CLASSES.map(definition=>({...definition,...(coverageByKey.get(`origin||${definition.id}`)||{targetType:"origin",targetId:"",attackClass:definition.id,status:"not-reviewed",notes:"",evidenceRefs:[]})}));
    const inputCoverage=parameters.filter(parameter=>parameter.coverageEligible!==false).map(parameter=>({parameterId:parameter.id,name:parameter.name,location:parameter.location,pageKey:parameter.pageKey,classes:INPUT_ATTACK_CLASSES.map(definition=>({...definition,...(coverageByKey.get(`parameter|${parameter.id}|${definition.id}`)||{targetType:"parameter",targetId:parameter.id,attackClass:definition.id,status:"not-reviewed",notes:"",evidenceRefs:[]})}))}));
    const savedRecommendationDecisions=new Map(values(review?.recommendations).map(row=>[text(row?.id,MAX_RECORD_KEY),row])),recommendations=pages.flatMap(page=>discoveredPageRecommendations(page,{originUrl,parameters,forms,routes,fingerprintReview})).map(recommendation=>{const saved=object(savedRecommendationDecisions.get(recommendation.id)),decision=RECOMMENDATION_DECISIONS.has(text(saved.decision,32).toLowerCase())?text(saved.decision,32).toLowerCase():"suggested";return {...recommendation,decision,decisionUpdatedAt:text(saved.updatedAt,64)};});
    const recommendationsByPage=new Map(recommendations.map(row=>[row.recordKey,row]));pages=pages.map(page=>{const recommendation=recommendationsByPage.get(page.recordKey);return {...page,recommendationIds:recommendation?[recommendation.id]:[],recommendedFollowUps:recommendation?[...recommendation.followUps]:[]};});
    // Evidence counters intentionally overlap: one URL may be auth-protected, structured, and directory-like.
    const pageStats={total:pages.length,baselineDistinct:pages.filter(row=>row.baselineState==="distinct").length,baselineLike:pages.filter(row=>row.baselineState==="baseline-like").length,baselinePossible:pages.filter(row=>row.baselineState==="possible-baseline-like").length,baselineUnknown:pages.filter(row=>["unknown","not-imported"].includes(row.baselineState)).length,authSurfaces:pages.filter(row=>row.evidenceFlags?.authenticationSurface).length,structuredEndpoints:pages.filter(row=>row.evidenceFlags?.structuredEndpoint).length,directoryCandidates:pages.filter(row=>row.evidenceFlags?.directoryCandidate).length,staticAssets:pages.filter(row=>row.evidenceFlags?.staticAsset).length,notesAdded:pages.filter(row=>Boolean(text(row.notes,MAX_OBSERVATION))).length,unreviewed:pages.filter(row=>row.state==="unreviewed").length,opened:pages.filter(row=>row.state==="opened").length,reviewed:pages.filter(row=>row.state==="reviewed").length,excluded:pages.filter(row=>row.state==="excluded").length,testingRequired:pages.filter(row=>row.testingRequired===true).length,testingUndecided:pages.filter(row=>typeof row.testingRequired!=="boolean").length,orphaned:orphanedPageReviews};
    const inputStats={forms:forms.length,parameters:parameters.length,routes:routes.length,unreviewed:forms.filter(row=>row.reviewState==="unreviewed").length+parameters.filter(row=>row.reviewState==="unreviewed").length+routes.filter(row=>row.reviewState==="unreviewed").length};
    const allCoverage=[...coverage,...inputCoverage.flatMap(row=>row.classes)],coverageStats={total:allCoverage.length,resolved:allCoverage.filter(coverageResolved).length,open:allCoverage.filter(row=>!coverageResolved(row)).length,leads:allCoverage.filter(row=>row.status==="lead").length,originTotal:coverage.length,inputTotal:inputCoverage.reduce((total,row)=>total+row.classes.length,0),inputOpen:inputCoverage.flatMap(row=>row.classes).filter(row=>!coverageResolved(row)).length};
    const completedDiscoverySources=completedExactOriginDiscoverySources(host,originId,endpointId),contentReview={ready:completedDiscoverySources.length>0,completedSourceCount:completedDiscoverySources.length,completedZeroResultSourceCount:completedDiscoverySources.filter(row=>row.resultCount===0).length,sources:completedDiscoverySources};
    const blockers=[];
    const block=(id,label,stage,count=0)=>blockers.push({id,label,stage,count});
    if(!fingerprintReview)block("fingerprint","Save the exact-origin fingerprint review.","fingerprint");
    if(!contentReview.ready)block("discovery-source","Import or retain at least one completed or valid negative exact-origin discovery source.","discovered-content");
    if(inputStats.unreviewed)block("inputs-open",`${inputStats.unreviewed} form, parameter, or route record${inputStats.unreviewed===1?" is":"s are"} not mapped or reviewed.`,"inputs-routes",inputStats.unreviewed);
    if(pageStats.testingRequired&&coverageStats.open)block("coverage-open",`${coverageStats.open} testing class${coverageStats.open===1?" remains":"es remain"} unresolved.`,"testing-coverage",coverageStats.open);
    const completedGates=[!fingerprintReview?null:"fingerprint",contentReview.ready?"discovery-source":null,inputStats.unreviewed?null:"inputs-routes",pageStats.testingRequired&&coverageStats.open?null:"coverage"].filter(Boolean);
    const baselineDecision=baseline?{classification:baseline.classification,classificationLabel:baseline.classificationLabel,confidence:baseline.confidence,filename:baseline.filename,revision:baseline.revision,sampleCount:baseline.sampleCount}:null;
    return {workspaceReview:review,pages,pageStats,baselineDecision,recommendations,contentReview,forms,parameters,routes,coverage,inputCoverage,coverageStats,inputStats,completion:{ready:blockers.length===0,blockers,completedGates,totalGates:4,completedGateCount:completedGates.length}};
  }
  function previewWorkspaceReview(host={},options={},input={}){
    const originId=text(options.originId),endpointId=text(options.endpointId),origin=exactOrigins(host).find(row=>originIdentity(row)===originId);
    if(!origin||text(origin.endpointId||origin.serviceEndpointId)!==endpointId)return {ok:false,reason:"Select one exact web origin and endpoint."};
    const previewOrigin={...origin,webReview:normalizedWorkspaceReview(input,{existing:origin.webReview,now:text(origin.webReview?.updatedAt,64)||"preview"})};
    const fingerprint=origin.fingerprintReview&&object(origin.fingerprintReview).owner==="manual"?origin.fingerprintReview:null;
    return {ok:true,...operationalProjection(host,previewOrigin,originId,endpointId,fingerprint)};
  }

  function exactEndpointObservations(host,endpointId){
    return values(host.endpointEvidence).filter(row=>text(row?.endpointId)===endpointId).slice(0,MAX_LIST_ITEMS).map(row=>({...row,raw:typeof reconApi.endpointScopedNmapEvidence==="function"?reconApi.endpointScopedNmapEvidence(row?.raw||row?.output||row?.evidence,row?.protocol,row?.port):(row?.raw||row?.output||row?.evidence||"")}));
  }
  function decodeXmlAttribute(value=""){
    return String(value||"").replace(/&#(x?[0-9a-f]+);/gi,(_all,token)=>{const numeric=token[0].toLowerCase()==="x"?parseInt(token.slice(1),16):parseInt(token,10);return Number.isFinite(numeric)?String.fromCodePoint(numeric):_all;}).replace(/&quot;/gi,'"').replace(/&apos;/gi,"'").replace(/&lt;/gi,"<").replace(/&gt;/gi,">").replace(/&amp;/gi,"&");
  }
  function observationOutputs(rows,scriptId){
    const output=[],escaped=String(scriptId||"").replace(/[.*+?^${}()|[\]\\]/g,"\\$&"),elementPattern=new RegExp(`<script\\b(?=[^>]*\\bid\\s*=\\s*["']${escaped}["'])[^>]*\\boutput\\s*=\\s*(["'])([\\s\\S]*?)\\1[^>]*\\/?\\s*>`,"gi");
    for(const row of rows){
      const source=text(row?.raw,MAX_OBSERVATION);if(!source)continue;
      for(const match of source.matchAll(elementPattern)){const value=text(decodeXmlAttribute(match[2]),MAX_OBSERVATION);if(value&&!output.includes(value))output.push(value);}
      if(text(row?.script).toLowerCase()===String(scriptId||"").toLowerCase()){const value=text(row?.output||row?.raw,MAX_OBSERVATION);if(value&&!value.includes("<script")&&!output.includes(value))output.push(value);}
    }
    return output;
  }
  function cleanHttpTitle(value=""){
    const raw=String(value??"").replace(/\r/g,"");
    const firstLine=(raw.split("\n").find(line=>String(line||"").trim())||"").trim();
    return text(firstLine.replace(/\s+(?:Requested resource was|Did not follow redirect to)\b[\s\S]*$/i,"").trim(),MAX_OBSERVATION);
  }
  function responseChainNote(records=[]){
    const rows=values(records).filter(row=>row?.targetUrl&&number(row?.status)).map(row=>`${number(row.status)} ${text(row.targetUrl,2048)}`);return rows.length?`Response chain: ${rows.join(" → ")}`:"";
  }
  function httpProposal(host,endpointId,originId){
    const rows=exactEndpointObservations(host,endpointId),titles=observationOutputs(rows,"http-title"),methodOutputs=observationOutputs(rows,"http-methods"),redirectOutputs=observationOutputs(rows,"http-redirect"),headerOutputs=[...observationOutputs(rows,"http-server-header"),...observationOutputs(rows,"http-headers")];
    const methods=[];methodOutputs.forEach(value=>{const match=value.match(/supported\s+methods?\s*:\s*([A-Z][A-Z,\s-]*)/i);if(match)match[1].split(/[\s,]+/).filter(Boolean).forEach(method=>methods.push(method.toUpperCase()));});
    const redirectMatch=redirectOutputs.map(value=>value.match(/redirects?\s+to\s+([^\s]+)/i)?.[1]).find(Boolean),serverMatch=headerOutputs.map(value=>value.match(/(?:server\s*:\s*|^)([^\r\n]+)/i)?.[1]).find(Boolean);
    const cookies=[];rows.forEach(row=>{const source=text(row?.raw,MAX_OBSERVATION);for(const match of source.matchAll(/set-cookie\s*:\s*([^=;\s]+)/gi))cookies.push(match[1]);});
    const webRows=values(host.recon?.webImportProjection?.sources).flatMap(source=>values(source?.records)).filter(row=>text(row?.originId)===originId&&text(row?.endpointId)===endpointId);
    const technologyRows=whatWebRecordsForOrigin(host,originId,endpointId).map(row=>row.record),technologyValue=field=>text(technologyRows.find(row=>text(row?.[field]))?.[field],field==="title"||field==="serverHeader"?MAX_OBSERVATION:MAX_STRING);
    technologyRows.forEach(row=>values(row?.cookies).forEach(cookie=>cookies.push(cookie)));
    const noteParts=[responseChainNote(technologyRows)];
    const security=[...new Map(technologyRows.flatMap(row=>values(row?.securityHeaders)).map(row=>[`${text(row?.name)}|${text(row?.value)}`,`${text(row?.name)}: ${text(row?.value)||"Observed"}`])).values()];if(security.length)noteParts.push(`Security headers: ${security.join("; ")}`);
    const observedHeaders=unique(technologyRows.flatMap(row=>values(row?.observedHeaders)));if(observedHeaders.length)noteParts.push(`Observed headers: ${observedHeaders.join(", ")}`);
    const characteristics=unique(technologyRows.flatMap(row=>values(row?.pageCharacteristics)));if(characteristics.length)noteParts.push(`Page characteristics: ${characteristics.join("; ")}`);
    const weakClues=unique(technologyRows.flatMap(row=>values(row?.weakClues)));if(weakClues.length)noteParts.push(`Unconfirmed clues: ${weakClues.join("; ")}`);
    return {
      title:cleanHttpTitle(technologyValue("title"))||titles.map(cleanHttpTitle).find(Boolean)||"",
      serverHeader:text(serverMatch)||technologyValue("serverHeader"),
      redirectPath:text(redirectMatch||webRows.find(row=>row?.redirect)?.redirect)||technologyValue("redirect"),
      cookies:unique(cookies),
      methods:unique(methods).map(item=>item.toUpperCase()),
      responseNote:noteParts.filter(Boolean).join("\n")
    };
  }
  function applicationProposal(technology={},summary=null){
    const identities=values(summary?.displayIdentities).length
      ?values(summary.displayIdentities)
      :typeof reconApi.technologyObjectiveEvidenceSummary==="function"
        ?values(reconApi.technologyObjectiveEvidenceSummary(technology,{endpointId:technology.endpointId,originId:technology.originId,originUrl:technology.url}).displayIdentities)
        :values(technology.observations);
    const applications=identities.filter(row=>text(row?.identityKind).toLowerCase()==="application"&&!['failed','partial','stale','deferred','unknown','zero'].includes(text(row?.state).toLowerCase()));
    const ranked=[...applications].sort((left,right)=>{
      const rank=value=>({established:0,positive:0,candidate:1,"clue-only":2,conflicting:3}[text(value).toLowerCase()]??9);
      return rank(left.state)-rank(right.state)||text(left.name).localeCompare(text(right.name));
    });
    const selected=ranked[0];
    if(!selected||!text(selected.name))return {name:"",version:"",identityState:"unknown",sourceType:"unknown",supportingObservationCount:0};
    const supporting=values(selected.supportingObservations),provenance=values(selected.provenance),sourceTypes=unique((supporting.length?supporting:provenance.length?provenance:[selected]).map(row=>sourceType(row?.sourceTool||row?.sourceKind)).filter(value=>value&&value!=="unknown"));
    return {name:text(selected.name),version:text(selected.version)||"Unknown",identityState:identityState(selected.displayState||selected.state,"candidate"),sourceType:sourceTypes.length>1?"multiple-sources":sourceTypes[0]||"unknown",supportingObservationCount:number(selected.supportingObservationCount)||supporting.length};
  }
  function serverProposal(endpoint={},summary=null){
    const product=text(endpoint.product),name=GENERIC_SERVER_PRODUCTS.has(product.toLowerCase())?"":product;
    const serviceIdentity=values(summary?.displayIdentities).find(row=>text(row?.identityKind).toLowerCase()==="service"&&(!name||text(row?.name).toLowerCase()===name.toLowerCase()));
    const summaryName=text(serviceIdentity?.name),usableSummaryName=GENERIC_SERVER_PRODUCTS.has(summaryName.toLowerCase())?"":summaryName,finalName=name||usableSummaryName;
    const state=finalName?(serviceIdentity?identityState(serviceIdentity.displayState||serviceIdentity.state,endpoint.identified===true?"established":"candidate"):(endpoint.identified===true?"established":"candidate")):"unknown";
    return {name:finalName,version:finalName?(text(endpoint.version)||text(serviceIdentity?.version)||"Unknown"):"",identityState:state,sourceType:sourceType(endpoint.source||endpoint.sourceOwner||endpoint.serviceMethod)};
  }
  function recordedState(status={}){
    const value=object(status),disposition=text(value.disposition,40).toLowerCase();
    if(disposition)return disposition;
    return ({todo:"not-started",active:"in-progress",done:"complete",na:"not-applicable"})[text(value.state,40).toLowerCase()]||"not-started";
  }
  function outcomeCounts(operations=[]){
    const output={positive:0,zero:0,open:0,failed:0,partial:0,conflicting:0,stale:0,deferred:0,unknown:0};
    values(operations).forEach(row=>{const state=text(row?.state,40).toLowerCase()||"unknown";if(state in output)output[state]++;if(OPEN_OUTCOME_STATES.has(state))output.open++;});
    return output;
  }
  function sourceCards(host,originId,endpointId,options={}){
    if(typeof reconApi.evidenceReview!=="function")return [];
    const reviewOptions={engagementId:text(options.engagementId),logicalScanImports:values(options.logicalScanImports)},catalog=reconApi.evidenceReview(host,reviewOptions),kindOrder={nmap:0,technology:1,web:2};
    return values(catalog?.results).filter(row=>row.kind==="nmap"?values(row.endpointIds).includes(endpointId):values(row.originIds).includes(originId)).slice(0,MAX_SOURCE_CARDS).map(row=>{
      const artifact=values(row.artifacts).find(item=>item.available)||values(row.artifacts)[0]||{},artifactId=text(artifact.artifactId||values(row.artifactIds)[0]),revision=Math.max(1,number(artifact.currentRevision)||1),selected=reconApi.evidenceReview(host,{...reviewOptions,selection:{logicalResultId:row.logicalResultId,artifactId,revision}})?.selected,operations=selected?.structured?.collections?.operations?.rows||[],sourceOperations=values(operations).filter(item=>item?.scope==="source");
      return {
        logicalResultId:text(row.logicalResultId),routeId:text(row.routeId),kind:text(row.kind),label:text(row.label),artifactId,revision,
        sourceFilename:text(selected?.sourceFilename),reviewState:text(selected?.reviewState),currentStatus:selected&&selected.selectedRevision!==selected.currentRevision?"legacy":"current",
        observedAt:text(row.observedAt),operationState:text(selected?.operationState||row.operationState),resultCount:number(row.resultCount),outcomes:outcomeCounts(sourceOperations.length?sourceOperations:operations),
        views:["structured-results","raw-output","artifact-history"],download:selected?.download||null
      };
    }).filter(row=>row.logicalResultId&&row.routeId&&row.artifactId).sort((left,right)=>(kindOrder[left.kind]??9)-(kindOrder[right.kind]??9)||left.logicalResultId.localeCompare(right.logicalResultId));
  }
  function methodRows(sources,review){
    return METHOD_DEFINITIONS.map(method=>({
      ...method,
      state:method.id==="manual"?(review?"saved":"not-saved"):sources.some(row=>method.id==="nmap"?row.kind==="nmap":row.kind==="technology")?"available":"not-imported"
    }));
  }
  function projectOrigin(host={},options={}){
    const originId=text(options.originId),endpointId=text(options.endpointId);
    if(!originId||!endpointId)return {ok:false,reason:"Select one exact web origin and endpoint. No neighboring origin was selected."};
    const originMatches=exactOrigins(host).filter(row=>originIdentity(row)===originId);
    if(originMatches.length!==1)return {ok:false,reason:"The exact web origin is missing or stale. No neighboring origin was selected."};
    const origin=originMatches[0],linkedEndpointId=text(origin.endpointId||origin.serviceEndpointId);
    if(!linkedEndpointId||linkedEndpointId!==endpointId)return {ok:false,reason:"The exact web origin belongs to a different endpoint."};
    const endpointMatches=values(host.serviceInventory).filter(row=>endpointIdentity(row)===endpointId);
    if(endpointMatches.length!==1)return {ok:false,reason:"The exact endpoint is missing or stale. No neighboring endpoint was selected."};
    const originUrl=exactOriginUrl(origin);
    if(!originUrl)return {ok:false,reason:"The exact web origin URL is invalid or unsupported."};
    const projection=typeof reconApi.projectHost==="function"?reconApi.projectHost(host,{logicalScanImports:values(options.logicalScanImports)}):{};
    const technology=values(projection?.technologies?.byOrigin).find(row=>text(row?.originId)===originId)||{originId,endpointId,url:originUrl,observations:[],sourceOutcomes:[],totalObservationCount:0,totalSourceOutcomeCount:0};
    const endpoint=endpointMatches[0],sources=sourceCards(host,originId,endpointId,options),review=origin.fingerprintReview&&object(origin.fingerprintReview).owner==="manual"?origin.fingerprintReview:null,operational=operationalProjection(host,origin,originId,endpointId,review),context={originId,endpointId,originUrl,serviceKey:endpoint.service,service:endpoint.service,protocol:endpoint.protocol,port:endpoint.port,methodOutcomeCount:values(options.methodologyStatus?.methodOutcomes).length};
    const summary=typeof reconApi.technologyObjectiveEvidenceSummary==="function"?reconApi.technologyObjectiveEvidenceSummary(technology,context):null;
    const proposal={server:serverProposal(endpoint,summary),application:applicationProposal(technology,summary),http:httpProposal(host,endpointId,originId)};
    return {
      ok:true,hostId:text(host.id),originId,originUrl,endpointId,endpoint:{targetAddress:text(endpoint.targetAddress||host.ip),protocol:text(endpoint.protocol)||"tcp",port:number(endpoint.port),service:text(endpoint.service)},
      evidenceState:summary?.evidenceState||"none",evidenceLabel:summary?.evidenceLabel||"No retained evidence",recordedState:recordedState(options.methodologyStatus),
      metrics:{retainedObservations:number(summary?.retainedObservationCount),displayedIdentities:number(summary?.displayedIdentityCount),retainedSourceOutcomes:number(summary?.retainedSourceOutcomeCount),retainedMethodOutcomes:number(summary?.retainedMethodOutcomeCount),importedSources:sources.length,discoveredPages:operational.pageStats.total,mappedInputs:operational.inputStats.parameters,apiRoutes:operational.routes.filter(row=>row.kind==="api").length},
      known:values(summary?.known),unknown:values(summary?.unknown),suggestedNextSteps:values(summary?.suggestedNextSteps),definitionOfDone:text(summary?.definitionOfDone),reason:text(summary?.reason),
      proposal,manualReview:review,manualConflict:review?manualConflicts(review,proposal):false,methods:methodRows(sources,review),sources,...operational
    };
  }
  function teamProjection(host={}){
    return exactOrigins(host).map(origin=>{
      const review=object(origin.fingerprintReview);
      if(review.owner!=="manual")return null;
      return {originId:originIdentity(origin),originUrl:exactOriginUrl(origin),endpointId:text(origin.endpointId||origin.serviceEndpointId),review};
    }).filter(Boolean).slice(0,MAX_LIST_ITEMS);
  }
  function teamWorkspaceProjection(host={}){
    return exactOrigins(host).map(origin=>{const review=object(origin.webReview);if(review.owner!=="manual")return null;return {originId:originIdentity(origin),originUrl:exactOriginUrl(origin),endpointId:text(origin.endpointId||origin.serviceEndpointId),review};}).filter(Boolean).slice(0,MAX_LIST_ITEMS);
  }

  return Object.freeze({VERSION,WORKSPACE_VERSION,MAX_STRING,MAX_OBSERVATION,MAX_SOURCE_CARDS,MAX_CAPTURE_BYTES,STAGES,ATTACK_CLASSES,INPUT_ATTACK_CLASSES,METHOD_DEFINITIONS,classifyDiscoveredPageEvidence,rankDiscoveredPageEvidence,discoveredPageRecommendations,completedExactOriginDiscoverySources,projectOrigin,previewWorkspaceReview,analyzeCapturedDocument,initializeDraft,refreshDraft,mergeProposal,saveFingerprintReview,clearFingerprintReview,saveWorkspaceReview,clearWorkspaceReview,manualConflicts,teamProjection,teamWorkspaceProjection});
});
