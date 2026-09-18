/* AEROS Access Contexts feature V1 */
(function initializeAccessContextsFeature(root,factory){
  const api=factory();
  if(typeof module==="object"&&module.exports)module.exports=api;
  if(root)root.AEROSAccessContexts=api;
})(typeof globalThis!=="undefined"?globalThis:this,function(){
  "use strict";

  const SIGNAL_KEYS=Object.freeze([
    "windowsSystemInfo","linuxSystemInfo","linuxUserInfo","linuxPackageInfo",
    "linuxProcessInfo","linuxServiceInfo","linuxAppInfo"
  ]);
  const SIGNAL_KEY_SET=new Set(SIGNAL_KEYS);
  const SOURCE_LABELS=Object.freeze({
    provided:"Provided",
    credential:"Working Credential",
    movement:"Movement",
    evidence:"Evidence",
    implicit:"Recorded Shell",
    collector:"AEROS Collector",
    peas:"PEAS Output",
    manual:"Manual"
  });
  const REQUIRED_DEPENDENCIES=Object.freeze([
    "activeHost","ensureHostIntel","ensureHostMethodologyContextState","contextFoundation",
    "startingAccessEntries","startingAccessEntryMatchesHost","startingAccessLabel",
    "startingAccessMethod","startingAccessPrivilege","formValue","setFormValue",
    "commandPathsModel","byId","escapeHtml","escapeAttr","saveState","persistState",
    "renderAll","renderRecommended","methodologySummary","serverAvailable","activeLabName",
    "saveLabState","showToast","alertUser","formatContextLabel","afterSave","notifyOrigin"
  ]);

  function clean(value){return String(value??"").trim();}
  function list(value){return Array.isArray(value)?value:[];}
  function object(value){return value&&typeof value==="object"&&!Array.isArray(value)?value:{};}
  function unique(values){return [...new Set(list(values).map(value=>clean(value)).filter(Boolean))];}

  function validateDependencies(dependencies){
    const missing=REQUIRED_DEPENDENCIES.filter(name=>typeof dependencies?.[name]!=="function");
    if(missing.length)throw new Error(`Access Contexts feature is missing required dependencies: ${missing.join(", ")}`);
  }

  function activeForHost(host,{includeInactive=false}={}){
    return list(host?.accessContexts).filter(context=>includeInactive||context?.active!==false);
  }

  function currentForHost(host,contexts=activeForHost(host)){
    const preferred=clean(host?.currentAccessContextId||host?.notesContextSelection?.contextId);
    return list(contexts).find(context=>clean(context?.id)===preferred)||list(contexts).find(context=>context?.active!==false)||null;
  }

  function signalRecord(host,contextId){
    if(!host||typeof host!=="object")return null;
    if(!host.accessContextSignals||typeof host.accessContextSignals!=="object"||Array.isArray(host.accessContextSignals))host.accessContextSignals={};
    const id=clean(contextId);
    if(!id)return null;
    if(!host.accessContextSignals[id]||typeof host.accessContextSignals[id]!=="object"||Array.isArray(host.accessContextSignals[id]))host.accessContextSignals[id]={};
    return host.accessContextSignals[id];
  }

  function systemInfoFingerprints(host){
    const system=object(host?.systemInfo),linux=object(system.linux),raw=object(system.raw),osnet=object(system.osnet),apps=object(system.appsproc);
    const compact=value=>String(value??"").replace(/\r\n?/g,"\n").trim();
    const combine=values=>values.map(compact).filter(Boolean).join("\n\u241f\n");
    const structuredUsers=list(system.users).map(user=>({
      username:compact(user?.username),domain:compact(user?.domain),enabled:compact(user?.enabled),
      groups:compact(user?.groups),privileges:compact(user?.privileges),access:user?.access||{},notes:compact(user?.notes)
    }));
    return {
      windowsSystemInfo:combine([osnet.osName,osnet.version,osnet.arch,osnet.hotfixes,osnet.adapters,osnet.routes,osnet.listeningPorts]),
      linuxSystemInfo:combine([linux.osKernel,linux.network,linux.routes,linux.firewall,linux.listeningPorts]),
      linuxUserInfo:combine([linux.users,linux.groups,linux.sudoers,raw.users,raw.groups,raw.groupMembers,structuredUsers.length?JSON.stringify(structuredUsers):""]),
      linuxPackageInfo:combine([linux.packages,apps.installedAppsX64,apps.installedAppsX86]),
      linuxProcessInfo:combine([linux.processes,apps.processes,apps.interestingProcesses]),
      linuxServiceInfo:combine([linux.services,apps.runningServices])
    };
  }

  function systemInfoSnapshot(host){
    const fingerprints=systemInfoFingerprints(host),snapshot={};
    Object.entries(fingerprints).forEach(([key,value])=>{snapshot[key]=Boolean(value);});
    snapshot.linuxAppInfo=Boolean(snapshot.linuxPackageInfo||snapshot.linuxProcessInfo||snapshot.linuxServiceInfo);
    return snapshot;
  }

  function markSignalKeys(host,contextId,keys=[],options={}){
    if(!host)return null;
    const contexts=list(options.contexts||activeForHost(host));
    const context=contexts.find(item=>clean(item?.id)===clean(contextId))||(!clean(contextId)?currentForHost(host,contexts):null);
    if(!context)return null;
    const record=signalRecord(host,context.id);
    const selected=unique(keys).filter(key=>SIGNAL_KEY_SET.has(key));
    if(!selected.length)return record;
    selected.forEach(key=>{record[key]=true;});
    if(selected.some(key=>["linuxPackageInfo","linuxProcessInfo","linuxServiceInfo"].includes(key)))record.linuxAppInfo=true;
    record.updatedAt=clean(options.now)||new Date().toISOString();
    host.currentAccessContextId=context.id;
    return record;
  }

  function markSignalsFromSystemInfo(host,contextId="",onlyKeys=null,options={}){
    if(!host)return null;
    const snapshot=systemInfoSnapshot(host);
    const keys=(Array.isArray(onlyKeys)?onlyKeys:Object.keys(snapshot)).filter(key=>snapshot[key]);
    return markSignalKeys(host,contextId,keys,options);
  }

  function sourceLabel(source){
    const value=clean(source);
    return SOURCE_LABELS[value.toLowerCase()]||value.replace(/-/g," ")||"Manual";
  }

  function sourceSummary(context){
    const raw=[...list(context?.sources),context?.source];
    const supporting=list(context?.supportingMethods);
    if(supporting.some(method=>/collector/i.test(clean(method))))raw.push("collector");
    let sources=unique(raw.map(value=>clean(value).toLowerCase()));
    if(sources.includes("collector")||sources.includes("provided"))sources=sources.filter(source=>source!=="manual");
    return sources.map(sourceLabel).join(" + ")||"Manual";
  }

  function referenceValue(context){
    if(context?.sourceStartingAccessId)return `starting:${context.sourceStartingAccessId}`;
    if(context?.sourceCredentialId)return `credential:${context.sourceCredentialId}`;
    return "";
  }

  function createAccessContextsFeature(dependencies){
    validateDependencies(dependencies);
    let modalOrigin="";

    function active(host,{includeInactive=false}={}){
      dependencies.ensureHostMethodologyContextState(host);
      return activeForHost(host,{includeInactive});
    }

    function current(host){return currentForHost(host,active(host));}

    function markKeys(host,contextId="",keys=[]){
      return markSignalKeys(host,contextId,keys,{contexts:active(host)});
    }

    function markFromSystemInfo(host,contextId="",onlyKeys=null){
      const snapshot=systemInfoSnapshot(host);
      const keys=(Array.isArray(onlyKeys)?onlyKeys:Object.keys(snapshot)).filter(key=>snapshot[key]);
      return markKeys(host,contextId,keys);
    }

    function preserveLegacySignalsBeforeAdding(host){
      const contexts=active(host);
      if(contexts.length===1&&!host?.accessContextSignals?.[contexts[0].id])markFromSystemInfo(host,contexts[0].id);
    }

    function referenceRows(host){
      const rows=[];
      list(host?.credentials).filter(credential=>credential?.username||credential?.secret).forEach(credential=>rows.push({
        value:`credential:${credential.id}`,kind:"credential",record:credential,
        label:`Saved credential · ${[credential.domain,credential.username].filter(Boolean).join("\\")||"Credential"} · ${credential.status||"unknown"}`
      }));
      list(dependencies.startingAccessEntries()).filter(entry=>(entry?.username||entry?.secret)&&dependencies.startingAccessEntryMatchesHost(entry,host)).forEach(entry=>rows.push({
        value:`starting:${entry.id}`,kind:"starting",record:entry,
        label:`Starting access · ${entry.username||entry.name||dependencies.startingAccessLabel(entry.type)} · ${dependencies.startingAccessLabel(entry.type)}`
      }));
      return rows;
    }

    function populateReferenceOptions(host,selected=""){
      const select=dependencies.byId("accessContextCredential");
      if(!select)return;
      const rows=referenceRows(host);
      select.innerHTML='<option value="">Not linked to starting access or a saved credential</option>'+rows.map(row=>`<option value="${dependencies.escapeAttr(row.value)}">${dependencies.escapeHtml(row.label)}</option>`).join("");
      select.value=rows.some(row=>row.value===selected)?selected:"";
    }

    function selectedReference(host){
      const value=dependencies.formValue("accessContextCredential");
      return referenceRows(host).find(item=>item.value===value)||null;
    }

    function applyReferenceDefaults(){
      const host=dependencies.activeHost(),reference=selectedReference(host);
      if(!host||!reference)return;
      if(reference.kind==="starting"){
        const entry=reference.record;
        if(!dependencies.formValue("accessContextPrincipal").trim()&&entry.username)dependencies.setFormValue("accessContextPrincipal",entry.username);
        const method=dependencies.startingAccessMethod(entry);if(method)dependencies.setFormValue("accessContextMethod",method);
        dependencies.setFormValue("accessContextPrivilege",dependencies.startingAccessPrivilege(entry));
      }else{
        const credential=reference.record,principal=[credential.domain,credential.username].filter(Boolean).join("\\")||credential.username||"";
        if(!dependencies.formValue("accessContextPrincipal").trim()&&principal)dependencies.setFormValue("accessContextPrincipal",principal);
        const method=dependencies.contextFoundation()?.directAccessMethod?.(`${credential.services||""} ${credential.type||""} ${credential.notes||""}`);
        if(method)dependencies.setFormValue("accessContextMethod",method);
      }
    }

    function interactiveAccess(context){
      if(typeof dependencies.interactiveAccess==="function")return dependencies.interactiveAccess(context)===true;
      return context?.active!==false;
    }

    function syncHostAccessTruth(host){
      if(typeof dependencies.syncAccessTruth==="function"){
        dependencies.syncAccessTruth(host);
        return;
      }
      const interactive=list(host?.accessContexts).filter(interactiveAccess);
      host.hasShell=interactive.length>0;
      host.isRootAdmin=interactive.some(context=>["root-admin","root","system","administrator","admin"].includes(clean(context?.privilege).toLowerCase()));
    }

    function closeModal(){
      const modal=dependencies.byId("accessContextModal");
      if(modal)modal.classList.add("hidden");
    }

    function setModalOpen(open,contextId="",options={}){
      const modal=dependencies.byId("accessContextModal"),host=dependencies.activeHost();
      if(!modal)return;
      if(!open){modal.classList.add("hidden");modalOrigin="";return;}
      if(!host)return dependencies.alertUser("Select a host first.");
      modalOrigin=clean(options?.origin);
      dependencies.ensureHostIntel(host);dependencies.ensureHostMethodologyContextState(host);
      const context=list(host.accessContexts).find(item=>item?.id===contextId)||null;
      dependencies.setFormValue("accessContextId",context?.id||"");
      dependencies.setFormValue("accessContextPrincipal",context?.principal||"");
      dependencies.setFormValue("accessContextMethod",context?.method||"SSH");
      dependencies.setFormValue("accessContextPrivilege",context?.privilege||"user");
      dependencies.setFormValue("accessContextLinuxWorkdir",context?.commandPaths?.linuxTargetWorkdir||"");
      dependencies.setFormValue("accessContextWindowsWorkdir",context?.commandPaths?.windowsTargetWorkdir||"");
      dependencies.setFormValue("accessContextNotes",context?.notes||"");
      populateReferenceOptions(host,referenceValue(context));
      const title=dependencies.byId("accessContextModalTitle"),button=dependencies.byId("saveAccessContextBtn");
      if(title)title.textContent=context?"Edit Access Context":"Add Access Context";
      if(button)button.textContent=context?"Update Access Context":"Save Access Context";
      modal.classList.remove("hidden");
      const schedule=typeof dependencies.requestFrame==="function"?dependencies.requestFrame:callback=>callback();
      schedule(()=>dependencies.byId("accessContextPrincipal")?.focus());
    }

    async function saveFromModal(){
      const host=dependencies.activeHost(),button=dependencies.byId("saveAccessContextBtn");if(!host)return null;
      const origin=modalOrigin;
      try{
        if(button)button.disabled=true;
        dependencies.ensureHostIntel(host);dependencies.ensureHostMethodologyContextState(host);preserveLegacySignalsBeforeAdding(host);
        const principal=dependencies.formValue("accessContextPrincipal").trim();
        if(!principal)throw new Error("Username / Principal is required.");
        const id=dependencies.formValue("accessContextId"),method=dependencies.formValue("accessContextMethod")||"SSH",privilege=dependencies.formValue("accessContextPrivilege")||"user",notes=dependencies.formValue("accessContextNotes"),reference=selectedReference(host);
        const interactive=interactiveAccess({active:true,type:"access",contextType:"access",method,accessMethod:method});
        const rawPaths={linuxTargetWorkdir:dependencies.formValue("accessContextLinuxWorkdir"),windowsTargetWorkdir:dependencies.formValue("accessContextWindowsWorkdir")};
        const pathsModel=dependencies.commandPathsModel();
        const commandPaths=pathsModel?.normalizeSettings?pathsModel.normalizeSettings(rawPaths):rawPaths;
        const credential=reference?.kind==="credential"?reference.record:null,startingEntry=reference?.kind==="starting"?reference.record:null;
        const foundation=dependencies.contextFoundation();
        const context=foundation?.recordAccessContext?.(host,{id,principal,method,privilege,notes,commandPaths,interactiveConfirmed:interactive,accessType:interactive?"interactive-shell":"authenticated-session",source:credential?"credential":"manual",sources:startingEntry?["provided","manual"]:undefined,sourceCredentialId:credential?.id||"",sourceStartingAccessId:startingEntry?.id||"",matchKey:id?undefined:(credential?`credential:${credential.id}:${method.toLowerCase()}`:startingEntry?`provided:${startingEntry.id}:${method.toLowerCase()}`:`manual:${host.id}:${principal.toLowerCase()}:${method.toLowerCase()}:${privilege}`)});
        if(!context)throw new Error("Access-context support is unavailable.");
        host.currentAccessContextId=context.id;host.notesContextSelection={type:"access",contextId:context.id};syncHostAccessTruth(host);
        if(credential&&credential.status!=="works")credential.status="works";
        modalOrigin="";closeModal();dependencies.saveState();dependencies.renderAll();dependencies.afterSave(context,origin);
        if(dependencies.serverAvailable()&&dependencies.activeLabName())await dependencies.saveLabState(true);
        const message=`Access context saved: ${dependencies.formatContextLabel(context)}.`;
        dependencies.notifyOrigin(origin,message,"success");dependencies.showToast(message,"success");
        return context;
      }catch(error){
        const message=error?.message||"The access context could not be saved.";
        dependencies.notifyOrigin(origin,message,"error");dependencies.showToast(message,"error");
        return null;
      }finally{if(button)button.disabled=false;}
    }

    async function setActivity(host,contextId,isActive){
      const context=dependencies.contextFoundation()?.setAccessContextActive?.(host,contextId,isActive);if(!context)return null;
      if(!isActive&&host.currentAccessContextId===contextId)host.currentAccessContextId="";
      syncHostAccessTruth(host);
      dependencies.saveState();dependencies.renderRecommended(host);
      if(dependencies.serverAvailable()&&dependencies.activeLabName())await dependencies.saveLabState(true).catch(()=>{});
      return context;
    }

    function focus(host,contextId){
      const context=list(host?.accessContexts).find(item=>item?.id===contextId);if(!context)return null;
      host.currentAccessContextId=context.id;host.notesContextSelection={type:"access",contextId:context.id};
      dependencies.persistState();dependencies.renderRecommended(host);return context;
    }

    function renderWorkspace(host,items=[],contexts=[]){
      const rootElement=dependencies.byId("accessContextWorkspace"),container=dependencies.byId("accessContextList");
      if(!rootElement||!container||!host)return;
      const rows=list(host.accessContexts).filter(context=>context.active!==false||context.source==="manual").sort((a,b)=>(a.active===false?1:0)-(b.active===false?1:0)||clean(a.principal||a.label).localeCompare(clean(b.principal||b.label)));
      rootElement.classList.remove("hidden");
      if(!rows.length){container.innerHTML='<div class="access-context-empty">No working login or shell has been recorded yet. Working SSH/RDP/WinRM credentials, successful movement, collector imports, and manually added access will create user-specific contexts here.</div>';return;}
      const currentId=host.currentAccessContextId||host.notesContextSelection?.contextId||"";
      container.innerHTML=rows.map(context=>{
        const contextItems=list(items).filter(item=>item?.contextId===context.id),summary=dependencies.methodologySummary(contextItems)||{addressed:0,total:contextItems.length,open:contextItems.length};
        const isInteractive=interactiveAccess(context),elevated=isInteractive&&["root-admin","root","system","administrator","admin"].includes(clean(context.privilege).toLowerCase());
        const editable=["manual","peas"].includes(context.source)&&!dependencies.contextFoundation()?.isCollectorAccessContext?.(context);
        return `<article class="access-context-card${context.id===currentId?" is-current":""}${context.active===false?" is-inactive":""}" data-access-context-card="${dependencies.escapeAttr(context.id)}"><div class="access-context-card-head"><div><strong>${dependencies.escapeHtml(context.principal||"Unspecified user")}</strong><small>${dependencies.escapeHtml(context.method||"Access")} · ${dependencies.escapeHtml(sourceSummary(context))}</small></div><div class="access-context-badges"><span class="access-context-badge ${elevated?"elevated":"working"}">${isInteractive?(elevated?"Elevated":"Non-elevated"):"Authenticated service session"}</span>${context.id===currentId?'<span class="access-context-badge working">Current</span>':""}</div></div><div class="access-context-progress"><div><strong>${summary.addressed}</strong><span>Addressed</span></div><div><strong>${summary.open}</strong><span>Open</span></div><div><strong>${summary.total}</strong><span>Tasks</span></div></div>${context.notes?`<div class="access-context-notes">${dependencies.escapeHtml(context.notes)}</div>`:""}<div class="access-context-actions"><button class="primary-btn small" data-access-focus="${dependencies.escapeAttr(context.id)}" type="button">Focus Workflow</button>${editable?`<button class="secondary-btn small" data-access-edit="${dependencies.escapeAttr(context.id)}" type="button">Edit</button><button class="secondary-btn small" data-access-toggle="${dependencies.escapeAttr(context.id)}" data-active="${context.active===false?"true":"false"}" type="button">${context.active===false?"Reactivate":"Deactivate"}</button>`:""}</div></article>`;
      }).join("");
      container.querySelectorAll("[data-access-focus]").forEach(button=>button.onclick=()=>focus(host,button.dataset.accessFocus));
      container.querySelectorAll("[data-access-edit]").forEach(button=>button.onclick=()=>setModalOpen(true,button.dataset.accessEdit));
      container.querySelectorAll("[data-access-toggle]").forEach(button=>button.onclick=()=>setActivity(host,button.dataset.accessToggle,button.dataset.active==="true"));
    }

    return Object.freeze({
      active,current,signalRecord:(host,contextId)=>signalRecord(host,contextId),systemInfoFingerprints,
      systemInfoSnapshot,markSignalKeys:markKeys,markSignalsFromSystemInfo:markFromSystemInfo,
      preserveLegacySignalsBeforeAdding,sourceLabel,sourceSummary,referenceRows,referenceValue,
      populateReferenceOptions,selectedReference,applyReferenceDefaults,setModalOpen,saveFromModal,
      closeModal,setActivity,focus,renderWorkspace
    });
  }

  return Object.freeze({
    SIGNAL_KEYS,SOURCE_LABELS,activeForHost,currentForHost,signalRecord,systemInfoFingerprints,
    systemInfoSnapshot,markSignalKeys,markSignalsFromSystemInfo,sourceLabel,sourceSummary,
    referenceValue,create:createAccessContextsFeature
  });
});
