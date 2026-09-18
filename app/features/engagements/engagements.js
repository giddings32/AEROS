(function(root,factory){
  const api=factory();
  if(typeof module==="object"&&module.exports)module.exports=api;
  if(root)root.AEROSEngagements=api;
})(typeof window!=="undefined"?window:globalThis,function(){
  "use strict";

  function requireDependencies(dependencies){
    const required=[
      "getState","byId","createOption","saveState","persistState","engagementState",
      "applicationState","replaceEngagementState","normalizeLoadedState","preserveSystemInfoOnLoad","resetEngagementState",
      "removeReservedHostEntries","render","saveActiveProfilePreferences","fetch","alertUser"
    ];
    const missing=required.filter(name=>typeof dependencies?.[name]!=="function");
    if(missing.length)throw new Error(`AEROS engagement dependencies are unavailable: ${missing.join(", ")}`);
  }

  async function responseJson(response){
    const data=await response.json();
    if(!response.ok||!data?.ok){
      const error=new Error(data?.error||"Unknown error");
      error.code=String(data?.code||"");
      error.status=Number(response?.status)||0;
      throw error;
    }
    return data;
  }

  const TARGET_SCHEMA_VERSION=1;
  const TARGET_KINDS=Object.freeze(["ipv4","ipv6","hostname","url","cidr","range","wildcard"]);

  function cleanText(value){return String(value??"").trim();}
  function normalizeIpv4(value){
    const raw=cleanText(value);
    if(!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(raw))return "";
    const parts=raw.split(".");
    if(parts.some(part=>Number(part)>255||(part.length>1&&part.startsWith("0"))))return "";
    return parts.map(part=>String(Number(part))).join(".");
  }
  function ipv4Number(value){
    const normalized=normalizeIpv4(value);
    if(!normalized)return -1;
    return normalized.split(".").reduce((total,part)=>total*256+Number(part),0);
  }
  function normalizeIpv6(value){
    const raw=cleanText(value).replace(/^\[|\]$/g,"").toLowerCase();
    if(!raw.includes(":")||raw.includes("%")||/[\s/]/.test(raw))return "";
    try{
      const parsed=new URL(`http://[${raw}]/`);
      const host=parsed.hostname.replace(/^\[|\]$/g,"").toLowerCase();
      return host.includes(":")?host:"";
    }catch{return "";}
  }
  function normalizeHostname(value){
    const raw=cleanText(value).replace(/\.$/,"").toLowerCase();
    if(!raw||raw.length>253||/^\d+(?:\.\d+)+$/.test(raw)||raw.includes(":"))return "";
    const labels=raw.split(".");
    if(labels.some(label=>!label||label.length>63||!/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label)))return "";
    return raw;
  }
  function validLabel(value){
    const label=cleanText(value);
    return !label||(
      label.length<=80
      && !/[\u0000-\u001f\u007f<>\"'`\\\/]/.test(label)
      && !/\s{3,}/.test(label)
    );
  }
  function targetIdentityFromHost(host){
    if(!host||typeof host!=="object")return "";
    const candidates=[host.scopeTarget?.identity,host.ip,host.hostname];
    for(const candidate of candidates){
      const raw=cleanText(candidate);
      const normalized=normalizeIpv4(raw)||normalizeIpv6(raw)||normalizeHostname(raw);
      if(normalized)return normalized;
    }
    return "";
  }
  function targetKey(row){
    const kind=cleanText(row?.kind).toLowerCase();
    const rawValue=kind==="url"?(row?.value||row?.identity):(row?.identity||row?.value);
    const value=kind==="url"?cleanText(rawValue):cleanText(rawValue).toLowerCase();
    return `${kind}|${value}`;
  }
  function stableTargetId(row,index=0){
    const source=`${targetKey(row)}|${cleanText(row?.disposition)||"in-scope"}`;
    let hash=2166136261;
    for(let i=0;i<source.length;i++){hash^=source.charCodeAt(i);hash=Math.imul(hash,16777619);}
    return `scope-target-${(hash>>>0).toString(36)}-${index+1}`;
  }
  function splitDelimitedTargetLine(line){
    const parts=[];
    let start=0;
    for(let index=0;index<line.length;index++){
      if(line[index]!==","&&line[index]!==";")continue;
      const current=line.slice(start,index).trim();
      const remainderRaw=line.slice(index+1);
      const remainder=remainderRaw.trimStart();
      if(!current||!remainder)continue;
      const nextToken=cleanText(remainder.split(/[;,]/,1)[0]).split(/\s+/)[0];
      const nextRow=parseTargetRecord(nextToken);
      const nextIsExplicitTarget=nextRow.valid&&(nextRow.kind!=="hostname"||nextRow.identity.includes("."));
      if(!nextIsExplicitTarget)continue;
      const currentTarget=cleanText(current.split("|",1)[0]);
      const currentIsUrl=/^https?:\/\//i.test(currentTarget);
      const separatorHasWhitespace=/^\s/.test(remainderRaw);
      if(currentIsUrl&&!separatorHasWhitespace&&!/^https?:\/\//i.test(remainder))continue;
      parts.push(current);
      start=index+1;
    }
    const tail=line.slice(start).trim();
    if(tail)parts.push(tail);
    return parts;
  }
  function splitTargetRecords(value){
    const records=[];
    cleanText(value).split(/\r?\n/).forEach(line=>{
      splitDelimitedTargetLine(line).forEach(part=>{
        if(part.includes("|")||/^https?:\/\//i.test(part)){records.push(part);return;}
        const tokens=part.split(/\s+/).filter(Boolean);
        if(tokens.length<=1){records.push(part);return;}
        const everyTarget=tokens.every(token=>{
          const row=parseTargetRecord(token);
          return row.valid&&(row.kind!=="hostname"||row.identity.includes("."));
        });
        if(everyTarget)records.push(...tokens);
        else records.push(part);
      });
    });
    return records;
  }
  function parseTargetRecord(record,options={}){
    const raw=cleanText(record);
    const disposition=options.disposition==="out-of-scope"?"out-of-scope":"in-scope";
    const order=Math.max(1,Number(options.reportOrder)||1);
    const base={id:"",raw,value:"",identity:"",kind:"unknown",label:"",disposition,groupType:"standalone",adRole:"",objectiveNote:"",reportOrder:order,createHost:false,valid:false,status:"invalid",errors:[],warnings:[],existingHostId:"",duplicateOf:"",resolution:""};
    if(!raw){base.errors.push("Target is empty.");return base;}
    const pipeParts=raw.split("|");
    if(pipeParts.length>2){base.errors.push("Use only one | between a target and its optional label.");return base;}
    const target=cleanText(pipeParts[0]),label=cleanText(pipeParts[1]);
    base.raw=raw;base.label=label;
    if(pipeParts.length===2&&!target){base.errors.push("Enter a target before the label.");return base;}
    if(!validLabel(label)){base.errors.push("Label contains unsafe characters, repeated spacing, or exceeds 80 characters.");return base;}
    if(/\s/.test(target)){base.errors.push("Ambiguous target text. Separate targets with a newline or comma, or use target | label.");return base;}

    if(/^https?:\/\//i.test(target)){
      try{
        const parsed=new URL(target);
        if(!["http:","https:"].includes(parsed.protocol)||parsed.username||parsed.password)throw new Error();
        const host=normalizeIpv4(parsed.hostname)||normalizeIpv6(parsed.hostname)||normalizeHostname(parsed.hostname);
        if(!host)throw new Error();
        base.kind="url";base.identity=host;base.value=parsed.href;base.createHost=true;
      }catch{base.errors.push("URL must be an HTTP(S) origin or path with a valid host and no embedded credentials.");return base;}
    }else if(target.startsWith("*.")){
      const host=normalizeHostname(target.slice(2));
      if(!host){base.errors.push("Wildcard target must use a valid domain such as *.example.com.");return base;}
      base.kind="wildcard";base.identity=`*.${host}`;base.value=base.identity;
    }else if(target.includes("/")){
      const slash=target.lastIndexOf("/"),address=target.slice(0,slash),prefixText=target.slice(slash+1);
      const ipv4=normalizeIpv4(address),ipv6=normalizeIpv6(address),prefix=Number(prefixText);
      const max=ipv4?32:ipv6?128:-1;
      if(max<0||!/^\d{1,3}$/.test(prefixText)||prefix<0||prefix>max){base.errors.push("CIDR must contain a valid IPv4/IPv6 address and prefix length.");return base;}
      base.kind="cidr";base.identity=`${ipv4||ipv6}/${prefix}`;base.value=base.identity;
      base.warnings.push("CIDR is retained as scope only and is not expanded into hosts.");
    }else{
      const rangeMatch=target.match(/^(\d{1,3}(?:\.\d{1,3}){3})-(\d{1,3}(?:\.\d{1,3}){3}|\d{1,3})$/);
      if(rangeMatch){
        const start=normalizeIpv4(rangeMatch[1]);
        const end=rangeMatch[2].includes(".")?normalizeIpv4(rangeMatch[2]):normalizeIpv4(`${rangeMatch[1].split(".").slice(0,3).join(".")}.${rangeMatch[2]}`);
        if(!start||!end){base.errors.push("IPv4 range must contain valid start and end addresses.");return base;}
        if(ipv4Number(end)<ipv4Number(start)){base.errors.push("IPv4 range end must not precede the start address.");return base;}
        base.kind="range";base.identity=`${start}-${end}`;base.value=base.identity;
        base.warnings.push("Range is retained as scope only and is not expanded into hosts.");
      }else{
        const ipv4=normalizeIpv4(target),ipv6=normalizeIpv6(target),hostname=normalizeHostname(target);
        if(ipv4){base.kind="ipv4";base.identity=ipv4;base.value=ipv4;base.createHost=true;}
        else if(ipv6){base.kind="ipv6";base.identity=ipv6;base.value=ipv6;base.createHost=true;}
        else if(hostname){base.kind="hostname";base.identity=hostname;base.value=hostname;base.createHost=true;}
        else{base.errors.push("Use a valid IPv4 address, IPv6 address, hostname, HTTP(S) URL, CIDR, range, or wildcard domain.");return base;}
      }
    }
    base.valid=true;base.status="ready";base.id=stableTargetId(base,Number(options.index)||0);
    return base;
  }
  function analyzeTargetRows(inputRows,options={}){
    const analysisWarning=/^(Duplicate of preview row|Preview row \d+ places|Existing host label is|Existing host will be linked)/;
    const rows=(Array.isArray(inputRows)?inputRows:[]).map((row,index)=>({...row,errors:[...new Set(row.errors||[])],warnings:[...new Set((row.warnings||[]).filter(message=>!analysisWarning.test(message)))],reportOrder:Math.max(1,Number(row.reportOrder)||index+1),status:row.valid?"ready":"invalid",existingHostId:"",duplicateOf:"",resolution:cleanText(row.resolution)}));
    const existingHosts=Array.isArray(options.existingHosts)?options.existingHosts:[];
    const hostByIdentity=new Map();
    existingHosts.forEach(host=>{const identity=targetIdentityFromHost(host);if(identity&&!hostByIdentity.has(identity))hostByIdentity.set(identity,host);});
    const seen=new Map();
    rows.forEach((row,index)=>{
      if(!row.valid)return;
      const key=targetKey(row);
      if(seen.has(key)){
        const first=seen.get(key);
        row.duplicateOf=first.id;
        if(first.disposition!==row.disposition){
          row.status="conflict";
          row.warnings.push(`Preview row ${first.previewIndex} places the same target ${first.disposition}. Choose one scope disposition.`);
          if(!["keep-in-scope","keep-out-of-scope"].includes(row.resolution))row.resolution="";
        }else{
          row.status="duplicate";
          row.warnings.push(`Duplicate of preview row ${first.previewIndex}. The same canonical record will be used.`);
          row.resolution="use-first";
        }
        return;
      }
      seen.set(key,{id:row.id,previewIndex:index+1,disposition:row.disposition});
      if(!row.createHost)return;
      const host=hostByIdentity.get(row.identity);
      if(!host)return;
      row.existingHostId=cleanText(host.id);
      const existingLabel=cleanText(host.displayLabel);
      if(row.label&&existingLabel&&row.label.toLowerCase()!==existingLabel.toLowerCase()){
        row.status="conflict";
        row.warnings.push(`Existing host label is "${existingLabel}". Choose which label to retain.`);
        if(!["preserve-existing","update-existing"].includes(row.resolution))row.resolution="";
      }else{
        row.status="existing";
        row.resolution="use-existing";
        row.warnings.push("Existing host will be linked; no duplicate host will be created.");
      }
    });
    return rows;
  }
  function parseTargetInput(value,options={}){
    const records=splitTargetRecords(value);
    const rows=records.map((record,index)=>parseTargetRecord(record,{disposition:options.disposition,reportOrder:(Number(options.startOrder)||1)+index,index}));
    return analyzeTargetRows(rows,options);
  }
  function targetRowsReady(rows){
    const list=Array.isArray(rows)?rows:[];
    return !!list.length&&list.every(row=>row.valid&&row.status!=="invalid"&&(row.status!=="conflict"||["preserve-existing","update-existing","keep-in-scope","keep-out-of-scope"].includes(row.resolution)));
  }

  function createEngagements(dependencies){
    requireDependencies(dependencies);
    let loadedName="",loadedRevision=null,refreshGeneration=0,identityGeneration=0,pendingPresentation=null;
    let saveQueue=Promise.resolve();
    let saveWorker=null,saveRequested=0,saveCompleted=0;
    let pendingSaveSilent=true,pendingSaveOptions={allowEmptyHosts:false,createOnly:false};
    let saveWaiters=[];
    const state=()=>dependencies.getState();

    function loadedLabName(){return loadedName;}
    function loadedLabRevision(){return loadedRevision;}
    function setLoadedLabName(value){
      const next=String(value||"").trim();
      if(next.toLocaleLowerCase()!==loadedName.toLocaleLowerCase()){
        loadedRevision=next?0:null;
        identityGeneration++;
      }
      loadedName=next;
      return loadedName;
    }
    function selectedLabName(){
      const selected=String(dependencies.byId("labSelect")?.value||"").trim();
      return selected&&selected!=="__new__"?selected:"";
    }
    function activeLabName(){
      const selected=selectedLabName(),selectValue=String(dependencies.byId("labSelect")?.value||"").trim();
      const creatingNew=selectValue==="__new__"&&loadedName&&String(dependencies.byId("projectName")?.value||state().projectName||"").trim()===loadedName;
      return loadedName&&(selected===loadedName||creatingNew)?loadedName:"";
    }
    function exactNameIsUnambiguous(name){
      const target=String(name||"").trim().toLocaleLowerCase();
      if(!target)return false;
      return (state().labs||[]).filter(value=>String(value||"").trim().toLocaleLowerCase()===target).length===1;
    }
    function presentationIdentityMatches(candidateId,candidateName,incomingId,incomingName,requestedName){
      const expectedId=String(candidateId||"").trim(),loadedId=String(incomingId||"").trim();
      if(expectedId&&loadedId)return expectedId===loadedId;
      const expectedName=String(candidateName||"").trim(),loadedNameValue=String(incomingName||"").trim();
      return exactNameIsUnambiguous(requestedName)&&expectedName===requestedName&&loadedNameValue===requestedName;
    }

    function clearLoadedView(options={}){
      const currentProjectId=String(state().projectId||"").trim(),currentProjectName=String(state().projectName||loadedName||"").trim();
      pendingPresentation=options.preservePresentation===true&&currentProjectId&&currentProjectName&&state().navigation&&typeof state().navigation==="object"
        ?{projectId:currentProjectId,projectName:currentProjectName,navigation:state().navigation}
        :null;
      loadedName="";loadedRevision=null;identityGeneration++;
      dependencies.resetEngagementState(state());
      dependencies.persistState();
    }

    function renderSelect(){
      const select=dependencies.byId("labSelect");if(!select)return;
      const current=loadedName||(select.value==="__new__"?"__new__":"");
      select.innerHTML='<option value="">Select engagement...</option><option value="__new__">＋ Start New Engagement…</option>';
      (state().labs||[]).forEach(name=>{
        const option=dependencies.createOption();option.value=name;option.textContent=name;
        if(name===current)option.selected=true;select.appendChild(option);
      });
      if(current==="__new__")select.value="__new__";
      dependencies.byId("newEngagementFields")?.classList.toggle("hidden",select.value!=="__new__");
    }

    async function refresh(){
      dependencies.saveState();
      if(!state().serverAvailable){dependencies.alertUser("Run python server.py first.");return [];}
      const generation=++refreshGeneration;
      try{
        const response=await dependencies.fetch(`/api/list-labs?_=${Date.now()}`,{cache:"no-store"});
        const data=await responseJson(response);
        if(generation!==refreshGeneration)return Array.isArray(data.labs)?data.labs:[];
        const labs=[...new Set((Array.isArray(data.labs)?data.labs:[]).map(value=>String(value||"").trim()).filter(Boolean))]
          .sort((a,b)=>a.localeCompare(b,undefined,{sensitivity:"base"}));
        if(loadedName&&!labs.some(name=>name.toLowerCase()===loadedName.toLowerCase()))labs.push(loadedName);
        state().labs=labs;renderSelect();return labs;
      }catch(error){
        if(generation!==refreshGeneration)return [];
        dependencies.alertUser(`Could not refresh labs: ${error.message}`);return [];
      }
    }

    async function loadSelected(labOverride=""){
      await saveQueue.catch(()=>{});
      dependencies.saveState();
      if(!state().serverAvailable){dependencies.alertUser("Run python server.py first.");return false;}
      const lab=String(labOverride||dependencies.byId("labSelect")?.value||"").trim();
      if(!lab||lab==="__new__")return false;
      try{
        const response=await dependencies.fetch(`/api/load-project?labName=${encodeURIComponent(lab)}&_=${Date.now()}`,{cache:"no-store"});
        const data=await responseJson(response);
        let normalization=null;
        if(data.state){
          const application=dependencies.applicationState();
          const localProjectId=String(state().projectId||"").trim();
          const incomingProjectId=String(data.state.projectId||"").trim();
          const localProjectName=String(state().projectName||loadedName||"").trim();
          const incomingProjectName=String(data.state.projectName||lab||"").trim();
          const directIdentityMatches=presentationIdentityMatches(localProjectId,localProjectName,incomingProjectId,incomingProjectName,lab);
          const resumedIdentityMatches=pendingPresentation&&presentationIdentityMatches(
            pendingPresentation.projectId,pendingPresentation.projectName,incomingProjectId,incomingProjectName,lab
          );
          const directNavigation=directIdentityMatches?state().navigation:null;
          const resumedNavigation=resumedIdentityMatches
            ?pendingPresentation.navigation
            :null;
          const sameEngagementNavigation=directNavigation||resumedNavigation;
          pendingPresentation=null;
          if(directIdentityMatches||resumedIdentityMatches)dependencies.preserveSystemInfoOnLoad(data.state);
          dependencies.replaceEngagementState(data.state);
          Object.assign(state(),application);
          if(sameEngagementNavigation&&typeof sameEngagementNavigation==="object")state().navigation=sameEngagementNavigation;
          normalization=dependencies.normalizeLoadedState(state());
        }
        pendingPresentation=null;loadedName=lab;
        loadedRevision=Number.isInteger(Number(data.revision))?Number(data.revision):0;
        identityGeneration++;state().projectName=lab;
        dependencies.removeReservedHostEntries();
        state().activeHost=state().activeHost||Object.keys(state().hosts||{})[0]||null;
        dependencies.persistState();dependencies.render();
        const projectName=dependencies.byId("projectName");if(projectName)projectName.value=lab;
        dependencies.saveActiveProfilePreferences();
        if(normalization?.requiresCanonicalSave===true)await saveNow(true,{allowEmptyHosts:true});
        return true;
      }catch(error){dependencies.alertUser(`Could not load lab: ${error.message}`);return false;}
    }

    async function saveNow(silent=false,options={}){
      dependencies.saveState();dependencies.removeReservedHostEntries();
      const selected=selectedLabName(),selectValue=String(dependencies.byId("labSelect")?.value||"").trim();
      const creatingNew=selectValue==="__new__"&&loadedName&&String(dependencies.byId("projectName")?.value||state().projectName||"").trim()===loadedName;
      const lab=activeLabName();
      if(!state().serverAvailable){if(!silent)dependencies.alertUser("Run python server.py first.");return false;}
      if(!loadedName||!lab||(!creatingNew&&selected!==loadedName)){
        const message="Save blocked: select and successfully load the engagement before saving. The visible engagement must match the loaded engagement.";
        if(!silent)dependencies.alertUser(message);throw new Error(message);
      }
      state().projectName=lab;dependencies.persistState();
      const saveIdentityGeneration=identityGeneration;
      const expectedRevision=Number.isInteger(loadedRevision)?loadedRevision:0;
      const payload={...dependencies.engagementState(),_saveGuard:{expectedLabName:loadedName,expectedRevision,allowEmptyHosts:!!options.allowEmptyHosts,createOnly:!!options.createOnly}};
      try{
        const response=await dependencies.fetch("/api/save-project",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)});
        const data=await responseJson(response);
        if(saveIdentityGeneration!==identityGeneration||loadedName.toLocaleLowerCase()!==lab.toLocaleLowerCase())return true;
        state().projectId=data.engagementId||state().projectId||"";
        state().schemaVersion=data.schemaVersion||1;state().applicationVersion="V1";
        if(Number.isInteger(Number(data.revision)))loadedRevision=Number(data.revision);
        for(const change of data.pathRewrites||[]){
          const previous=change.from.replaceAll("\\","/").replace(/\/$/,"");
          const next=change.to.replaceAll("\\","/").replace(/\/$/,"");
          const rewrite=(value,field="")=>{
            if(["storedPath","screenshotAbsPath","absolutePath","artifactPath","storedPaths"].includes(field)&&typeof value==="string"&&value.replaceAll("\\","/").startsWith(previous+"/"))return next+value.replaceAll("\\","/").slice(previous.length);
            if(Array.isArray(value))return value.map(item=>rewrite(item,field));
            if(value&&typeof value==="object")Object.keys(value).forEach(key=>{value[key]=rewrite(value[key],key);});
            return value;
          };
          rewrite(state());
        }
        if(data.storage){state().engagementConfig.storage=data.storage;state().engagementConfig.commandPaths={...(state().engagementConfig.commandPaths||{}),kaliOutputRoot:data.storage.directory.replaceAll("\\","/")};}
        dependencies.persistState();
        if(!silent)dependencies.alertUser(`Saved engagement to files:\n${data.path}${data.backupPath?`\nBackup: ${data.backupPath}`:""}`);
        return true;
      }catch(error){if(!silent)dependencies.alertUser(`Could not save lab state: ${error.message}`);throw error;}
    }

    function settleSaveWaiters(target,result,error){
      const pending=[];
      saveWaiters.forEach(waiter=>{
        if(waiter.generation>target){pending.push(waiter);return;}
        if(error)waiter.reject(error);else waiter.resolve(result);
      });
      saveWaiters=pending;
    }

    async function runSaveWorker(){
      while(saveCompleted<saveRequested){
        const target=saveRequested;
        const silent=pendingSaveSilent;
        const options={...pendingSaveOptions};
        pendingSaveSilent=true;
        pendingSaveOptions={allowEmptyHosts:false,createOnly:false};
        try{
          const result=await saveNow(silent,options);
          saveCompleted=target;
          settleSaveWaiters(target,result,null);
        }catch(error){
          saveCompleted=target;
          settleSaveWaiters(target,null,error);
        }
      }
    }

    function ensureSaveWorker(){
      if(saveWorker)return;
      saveWorker=runSaveWorker().finally(()=>{
        saveWorker=null;
        if(saveCompleted<saveRequested)ensureSaveWorker();
      });
      saveQueue=saveWorker;
    }

    function save(silent=false,options={}){
      const generation=++saveRequested;
      pendingSaveSilent=pendingSaveSilent&&silent===true;
      pendingSaveOptions.allowEmptyHosts=pendingSaveOptions.allowEmptyHosts||options.allowEmptyHosts===true;
      pendingSaveOptions.createOnly=pendingSaveOptions.createOnly||options.createOnly===true;
      const task=new Promise((resolve,reject)=>saveWaiters.push({generation,resolve,reject}));
      ensureSaveWorker();
      return task;
    }

    async function waitForPendingSaves(){await saveQueue;}

    async function deleteSelected(confirmDelete){
      const lab=String(dependencies.byId("labSelect")?.value||"").trim();
      if(!lab){dependencies.alertUser("Select an engagement to delete first.");return false;}
      if(!(await confirmDelete(lab)))return false;
      try{
        const payload={labName:lab};
        if(loadedName.toLocaleLowerCase()===lab.toLocaleLowerCase()&&Number.isInteger(loadedRevision))payload.expectedRevision=loadedRevision;
        const response=await dependencies.fetch("/api/delete-project",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)});
        await responseJson(response);
        if(loadedName===lab||String(state().projectName||"").trim()===lab){clearLoadedView();dependencies.render();}
        await refresh();dependencies.alertUser(`Deleted engagement: ${lab}`);return true;
      }catch(error){dependencies.alertUser(`Could not delete engagement: ${error.message}`);return false;}
    }

    return Object.freeze({loadedLabName,loadedLabRevision,setLoadedLabName,selectedLabName,activeLabName,clearLoadedView,renderSelect,refresh,loadSelected,save,waitForPendingSaves,deleteSelected});
  }

  return Object.freeze({
    create:createEngagements,
    TARGET_SCHEMA_VERSION,
    TARGET_KINDS,
    normalizeIpv4,
    normalizeIpv6,
    normalizeHostname,
    validLabel,
    targetIdentityFromHost,
    targetKey,
    stableTargetId,
    parseTargetRecord,
    parseTargetInput,
    analyzeTargetRows,
    targetRowsReady
  });
});
