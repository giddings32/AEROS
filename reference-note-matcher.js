(function(root,factory){
  const api=factory();
  if(typeof module==="object"&&module.exports)module.exports=api;
  if(root)root.AerosReferenceMatcher=api;
})(typeof globalThis!=="undefined"?globalThis:this,function(){
  "use strict";

  const CANONICAL_STAGES=["recon","enumeration","exploitation","foothold","privesc","lateral","looting","reporting"];
  const MODULES=["general","oscp","web","active-directory"];
  const SCOPES=["engagement","asset-group","host","service","access","reporting","library-only"];
  const TRIGGER_MODES=["always","asset-group-type","service","port","host-os","access","credential","domain","event","manual"];
  const DISCOVERY_OBJECTIVE_ALIASES=Object.freeze({
    "tcp-port-discovery":"tcp-port-discovery",
    "tcp-service-discovery":"service-version-enumeration",
    "service-version-enumeration":"service-version-enumeration",
    "udp-port-discovery":"udp-port-discovery",
    "udp-service-discovery":"udp-service-discovery"
  });
  const TCP_PORT_METHODS=new Set(["nmap-tcp-port-discovery","autorecon","threader3000","netcat"]);

  function normalizedToken(value){
    return String(value||"").trim().toLowerCase();
  }

  function uniqueTokens(values,normalizer=normalizedToken){
    const out=[];
    (Array.isArray(values)?values:[]).forEach(value=>{
      const token=normalizer(value);
      if(token&&!out.includes(token))out.push(token);
    });
    return out;
  }

  function normalizeServiceName(value){
    const raw=normalizedToken(value).replace(/[_\s]+/g,"-");
    const aliases={
      "postgres":"postgresql",
      "postgre":"postgresql",
      "psql":"postgresql",
      "ms-sql":"mssql",
      "microsoft-sql":"mssql",
      "microsoft-ds":"smb",
      "netbios":"smb",
      "netbios-ssn":"smb",
      "web":"http",
      "www":"http"
    };
    return aliases[raw]||raw;
  }

  function normalizeHostOs(value){
    const raw=normalizedToken(value);
    if(raw==="both")return "both";
    if(raw.includes("windows"))return "windows";
    if(raw.includes("linux")||raw.includes("ubuntu")||raw.includes("debian")||raw.includes("kali"))return "linux";
    return raw==="windows"||raw==="linux"?raw:"unknown";
  }

  function hasNormalizedMetadata(note){
    if(!note||typeof note!=="object")return false;
    return CANONICAL_STAGES.includes(normalizedToken(note.stage)) &&
      MODULES.some(module=>uniqueTokens(note.modules).includes(module)) &&
      SCOPES.includes(normalizedToken(note.scope)) &&
      TRIGGER_MODES.includes(normalizedToken(note.triggerMode)) &&
      Array.isArray(note.services) && Array.isArray(note.ports) &&
      Array.isArray(note.activationEvents);
  }

  function moduleMatches(note,moduleName){
    const selected=normalizedToken(moduleName)||"general";
    if(selected==="all")return true;
    const modules=uniqueTokens(note?.modules);
    if(!modules.length)return selected==="general";
    return modules.includes(selected);
  }

  function stageMatches(note,stageName){
    const selected=normalizedToken(stageName)||"all";
    if(selected==="all")return true;
    return normalizedToken(note?.stage)===selected;
  }

  function buildContext(raw={}){
    const services=uniqueTokens(raw.detectedServices,normalizeServiceName);
    const ports=[];
    (Array.isArray(raw.openPorts)?raw.openPorts:[]).forEach(value=>{
      const port=Number(value);
      if(Number.isInteger(port)&&port>=1&&port<=65535&&!ports.includes(port))ports.push(port);
    });
    return {
      hostOs:normalizeHostOs(raw.hostOs),
      detectedServices:services,
      openPorts:ports,
      hasShell:!!raw.hasShell,
      hasCreds:!!raw.hasCreds,
      hasDomain:!!raw.hasDomain,
      isRootAdmin:!!raw.isRootAdmin,
      activeEvents:uniqueTokens(raw.activeEvents),
      assetGroupTypes:uniqueTokens(raw.assetGroupTypes)
    };
  }

  function matchNormalizedNote(note,rawContext={}){
    if(!hasNormalizedMetadata(note)){
      return {matched:false,metadataComplete:false,reason:"legacy-metadata"};
    }

    const context=buildContext(rawContext);
    const scope=normalizedToken(note.scope);
    const triggerMode=normalizedToken(note.triggerMode);
    const noteOs=normalizeHostOs(note.os||"both");
    const noteServices=uniqueTokens(note.services,normalizeServiceName);
    const notePorts=(note.ports||[]).map(Number).filter(port=>Number.isInteger(port)&&port>=1&&port<=65535);
    const noteAssetGroupTypes=uniqueTokens(note.assetGroupTypes);
    const assetGroupMatch=noteAssetGroupTypes.some(type=>context.assetGroupTypes.includes(type));
    const serviceMatch=noteServices.some(service=>context.detectedServices.includes(service));
    const portMatch=notePorts.some(port=>context.openPorts.includes(port));
    const technicalMatch=serviceMatch||portMatch;

    if(scope==="library-only")return {matched:false,metadataComplete:true,reason:"library-only"};
    if(scope==="reporting")return {matched:false,metadataComplete:true,reason:"reporting-scope"};

    if(noteOs!=="unknown"&&noteOs!=="both"){
      if(context.hostOs!=="unknown"&&context.hostOs!==noteOs){
        return {matched:false,metadataComplete:true,reason:"os-mismatch"};
      }
      if(context.hostOs==="unknown"&&!technicalMatch&&!(triggerMode==="domain"&&context.hasDomain)){
        return {matched:false,metadataComplete:true,reason:"os-unknown"};
      }
    }

    if(note.requiresShell&&!context.hasShell)return {matched:false,metadataComplete:true,reason:"shell-required"};
    if(note.requiresCreds&&!context.hasCreds)return {matched:false,metadataComplete:true,reason:"credentials-required"};
    if(note.requiresDomain&&!context.hasDomain)return {matched:false,metadataComplete:true,reason:"domain-required"};

    // Scope is an applicability boundary. A credential-triggered SMB note still
    // requires SMB to be present, and an access note still requires host access.
    if(scope==="asset-group"&&!context.assetGroupTypes.length){
      return {matched:false,metadataComplete:true,reason:"asset-group-not-present"};
    }
    if(scope==="service"&&!technicalMatch){
      return {matched:false,metadataComplete:true,reason:"service-not-present"};
    }
    if(scope==="access"&&!context.hasShell){
      return {matched:false,metadataComplete:true,reason:"access-not-present"};
    }

    let matched=false;
    switch(triggerMode){
      case "always":
        matched=true;
        break;
      case "asset-group-type":
        matched=assetGroupMatch;
        break;
      case "service":
        matched=technicalMatch;
        break;
      case "port":
        matched=portMatch;
        break;
      case "host-os":
        matched=context.hostOs!=="unknown"&&(noteOs==="both"||noteOs===context.hostOs);
        break;
      case "access":
        matched=context.hasShell;
        break;
      case "credential":
        matched=context.hasCreds;
        break;
      case "domain":
        matched=context.hasDomain;
        break;
      case "event": {
        const events=uniqueTokens(note.activationEvents);
        matched=events.some(event=>context.activeEvents.includes(event));
        break;
      }
      case "manual":
      default:
        matched=false;
        break;
    }

    return {
      matched,
      metadataComplete:true,
      reason:matched?"metadata-match":"trigger-not-satisfied",
      serviceMatch,
      portMatch,
      assetGroupMatch
    };
  }

  function normalizedObjective(value){
    const id=normalizedToken(value).replace(/[_\s]+/g,"-");
    return DISCOVERY_OBJECTIVE_ALIASES[id]||id;
  }
  function noteIdentity(note){
    return normalizedToken(note?.title).replace(/[^a-z0-9]+/g,"-").replace(/^-+|-+$/g,"");
  }
  function contextualPolicyAllows(note,context){
    const profile=normalizedToken(context.profileId||"general")||"general",modules=uniqueTokens(note?.modules);
    if(profile==="oscp"){
      if(!modules.includes("oscp"))return false;
      if(normalizedToken(note?.taskRole)==="exclude")return false;
    }else if(profile==="general"&&modules.length&&!modules.includes("general"))return false;
    else if(!["general","oscp"].includes(profile)&&modules.length&&!modules.includes(profile))return false;
    return true;
  }
  function contextualPrerequisitesAllow(note,context){
    const noteOs=normalizeHostOs(note?.os||"both"),hostOs=normalizeHostOs(context.hostOs);
    if(noteOs!=="both"&&noteOs!=="unknown"&&hostOs!==noteOs)return false;
    if(note?.requiresShell&&!context.hasShell)return false;
    if(note?.requiresCreds&&!context.hasCreds)return false;
    if(note?.requiresDomain&&!context.hasDomain)return false;
    if(context.requiresConfirmedWebOrigin===true&&uniqueTokens(note?.modules).includes("web")){
      if(context.exactOriginConfirmed!==true||!normalizedToken(context.originId))return false;
    }
    const services=uniqueTokens(note?.services,normalizeServiceName);
    if(services.length){
      const confirmed=uniqueTokens(context.confirmedServices,normalizeServiceName);
      if(!services.some(service=>confirmed.includes(service)))return false;
    }
    return true;
  }
  function objectiveMatches(note,rawObjective){
    const objective=normalizedObjective(rawObjective),task=normalizedObjective(note?.taskId);
    if(!objective||!task)return false;
    if(objective==="udp-port-discovery")return task==="udp-service-discovery";
    return task===objective;
  }
  function discoveryMethodAllowed(note,objective){
    const normalized=normalizedObjective(objective);
    if(normalized==="tcp-port-discovery")return TCP_PORT_METHODS.has(noteIdentity(note));
    if(normalized==="service-version-enumeration")return noteIdentity(note)==="nmap-service-version-enumeration"||noteIdentity(note)==="autorecon"||noteIdentity(note)==="threader3000";
    if(["udp-port-discovery","udp-service-discovery"].includes(normalized))return noteIdentity(note)==="nmap-udp-discovery-service-enumeration"||noteIdentity(note)==="autorecon";
    return true;
  }
  function matchContextualNote(note,rawContext={}){
    if(!hasNormalizedMetadata(note))return {matched:false,tier:"",reason:"legacy-metadata"};
    const context={...buildContext(rawContext),...rawContext};
    const objective=normalizedObjective(context.objectiveId);
    if(!objective)return {matched:false,tier:"",reason:"objective-required"};
    if(!contextualPolicyAllows(note,context))return {matched:false,tier:"",reason:"policy-excluded"};
    if(!objectiveMatches(note,objective))return {matched:false,tier:"",reason:"objective-mismatch"};
    if(!discoveryMethodAllowed(note,objective))return {matched:false,tier:"",reason:"objective-capability-mismatch"};
    if(!contextualPrerequisitesAllow(note,context))return {matched:false,tier:"",reason:"context-prerequisite"};
    return {matched:true,tier:"exact",reason:"exact-objective-context"};
  }
  function selectContextualNotes(notes,rawContext={},limit=12){
    const exact=[],strong=[];
    (Array.isArray(notes)?notes:[]).forEach(note=>{
      const match=matchContextualNote(note,rawContext);
      if(!match.matched)return;
      (match.tier==="strong"?strong:exact).push(note);
    });
    const sort=(a,b)=>String(a?.title||"").localeCompare(String(b?.title||""),undefined,{numeric:true,sensitivity:"base"});
    return {exact:exact.sort(sort).slice(0,limit),strong:strong.sort(sort).slice(0,Math.max(0,limit-exact.length))};
  }

  return {
    CANONICAL_STAGES,
    MODULES,
    SCOPES,
    TRIGGER_MODES,
    normalizeServiceName,
    normalizeHostOs,
    hasNormalizedMetadata,
    moduleMatches,
    stageMatches,
    buildContext,
    matchNormalizedNote,
    normalizedObjective,
    matchContextualNote,
    selectContextualNotes
  };
});
