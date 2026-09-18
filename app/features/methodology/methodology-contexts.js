(function(root,factory){
  const api=factory();
  if(typeof module==="object"&&module.exports)module.exports=api;
  if(root)root.AEROSMethodologyContexts=api;
})(typeof window!=="undefined"?window:globalThis,function(){
  "use strict";

  function requireDependencies(dependencies){
    const required=[
      "getState","ensureAssetGroups","migrateLegacyHostState","providedAssessmentAccessForHost",
      "hostProfileModel","contextFoundation","syncHostStageAwareness","stageAwareness","saveState",
      "activeLabName","saveLabState","showToast"
    ];
    const missing=required.filter(name=>typeof dependencies?.[name]!=="function");
    if(missing.length)throw new Error(`AEROS methodology-context dependencies are unavailable: ${missing.join(", ")}`);
  }

  function clone(value){return JSON.parse(JSON.stringify(value));}

  function createMethodologyContexts(dependencies){
    requireDependencies(dependencies);
    const state=()=>dependencies.getState();

    function ensureHost(host){
      if(!host)return host;
      try{dependencies.migrateLegacyHostState(host);}catch(error){}
      if(!Array.isArray(host.attackPathSteps))host.attackPathSteps=[];
      dependencies.providedAssessmentAccessForHost(host);
      const profile=dependencies.hostProfileModel(),groups=state().assetGroups||[];
      profile?.syncLegacyHostFields?.(host,{assetGroups:groups,preserveLegacyAccess:true,syncStatus:false});
      const foundation=dependencies.contextFoundation();
      if(foundation?.ensureHostFoundation){
        foundation.ensureHostFoundation(host,{
          hostId:host.id,
          engagementId:state().projectId||state().projectName||"",
          serviceCatalog:dependencies.defaultServices||[],
          assetGroups:groups
        });
        if(foundation.mergePlaceholderAccessContexts&&Array.isArray(host.accessContexts))host.accessContexts=foundation.mergePlaceholderAccessContexts(host,host.accessContexts);
      }else{
        if(!host.noteStatus||typeof host.noteStatus!=="object"||Array.isArray(host.noteStatus))host.noteStatus={};
        if(!Array.isArray(host.serviceContexts))host.serviceContexts=[];
        if(!Array.isArray(host.accessContexts))host.accessContexts=[];
        if(!host.notesContextSelection||typeof host.notesContextSelection!=="object")host.notesContextSelection={type:"all",contextId:""};
      }
      profile?.syncLegacyHostFields?.(host,{assetGroups:groups,preserveLegacyAccess:false,syncStatus:false});
      dependencies.syncHostStageAwareness(host);
      profile?.syncLegacyHostFields?.(host,{assetGroups:groups,preserveLegacyAccess:false,syncStatus:true});
      return host;
    }

    function ensureState({ensureGroups=true}={}){
      if(ensureGroups)dependencies.ensureAssetGroups();
      const foundation=dependencies.contextFoundation();
      if(foundation?.ensureAssetGroupFoundation)(state().assetGroups||[]).forEach(group=>foundation.ensureAssetGroupFoundation(group));
      Object.entries(state().hosts||{}).forEach(([hostId,host])=>{if(host&&!host.id)host.id=hostId;ensureHost(host);});
      return state();
    }

    function contextsForHost(hostOrId,{includeInactive=false}={}){
      const host=typeof hostOrId==="string"?state().hosts?.[hostOrId]:hostOrId;if(!host)return [];
      ensureState();
      const foundation=dependencies.contextFoundation();
      const contexts=foundation?.contextsForHost?foundation.contextsForHost(host,state().assetGroups,{includeInactive}):[];
      const namedAccess=contexts.filter(context=>context?.type==="access"&&context?.active!==false&&!foundation?.isPlaceholderPrincipal?.(context?.principal));
      if(!namedAccess.length)return contexts;
      return contexts.filter(context=>{
        if(context?.type!=="access"||context?.active===false)return true;
        if(foundation?.isPlaceholderPrincipal?.(context?.principal)!==true)return true;
        const source=String(context?.source||"").toLowerCase(),label=String(context?.label||"").toLowerCase();
        return !(source==="implicit"||source==="provided"||label==="standard user"||label.startsWith("standard user ·"));
      });
    }

    function statusOwner(host,contextId){
      const foundation=dependencies.contextFoundation();
      return foundation?.ownerForContext?foundation.ownerForContext(host,state().assetGroups,contextId):host;
    }
    function noteStatus(host,noteId,contextId){
      const foundation=dependencies.contextFoundation(),owner=statusOwner(host,contextId);
      return foundation?.getNoteStatus?foundation.getNoteStatus(owner,noteId,contextId):null;
    }
    async function setNoteStatus(host,noteId,contextId,status,reason=""){
      if(!host)throw new Error("Select a host first.");ensureState();
      const foundation=dependencies.contextFoundation();if(!foundation?.setNoteStatus)throw new Error("Methodology context support is unavailable.");
      const record=foundation.setNoteStatus(statusOwner(host,contextId),noteId,contextId,status,reason);
      dependencies.saveState();
      if(state().serverAvailable&&dependencies.activeLabName())await dependencies.saveLabState(true).catch(error=>dependencies.showToast(`Methodology status saved locally, but SQLite save failed: ${error.message}`,"error"));
      return record;
    }
    async function registerAccess(host,input={}){
      if(!host)throw new Error("Select a host first.");ensureState();
      const foundation=dependencies.contextFoundation();if(!foundation?.recordAccessContext)throw new Error("Methodology context support is unavailable.");
      const context=foundation.recordAccessContext(host,input);ensureHost(host);dependencies.saveState();
      if(state().serverAvailable&&dependencies.activeLabName())await dependencies.saveLabState(true).catch(error=>dependencies.showToast(`Access context saved locally, but SQLite save failed: ${error.message}`,"error"));
      return clone(context);
    }

    const contextsApi=Object.freeze({
      sync:()=>{ensureState();return true;},
      listForHost:(hostId,options={})=>clone(contextsForHost(hostId,options)),
      registerAccess:(hostId,input={})=>registerAccess(state().hosts?.[hostId],input),
      getStatus:(hostId,noteId,contextId)=>noteStatus(state().hosts?.[hostId],noteId,contextId),
      setStatus:(hostId,noteId,contextId,status,reason="")=>setNoteStatus(state().hosts?.[hostId],noteId,contextId,status,reason)
    });
    const stagesApi=Object.freeze({
      sync:(hostId="")=>{if(hostId&&state().hosts?.[hostId])return clone(dependencies.syncHostStageAwareness(state().hosts[hostId]));ensureState();return true;},
      evaluate:hostId=>{const host=state().hosts?.[hostId],stage=dependencies.stageAwareness();return host&&stage?.evaluateHostStage?clone(stage.evaluateHostStage(host,{movements:state().movements||[]})):null;},
      get:hostId=>{const host=state().hosts?.[hostId];return host?clone({inferredStage:host.inferredStage||"recon",focusStage:host.focusStage||null,reachedStages:host.reachedStages||["recon"],stageInference:host.stageInference||{},stageHistory:host.stageHistory||{}}):null;}
    });

    return Object.freeze({ensureHost,ensureState,contextsForHost,statusOwner,noteStatus,setNoteStatus,registerAccess,contextsApi,stagesApi});
  }

  return Object.freeze({create:createMethodologyContexts});
});
