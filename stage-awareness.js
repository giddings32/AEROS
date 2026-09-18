(function(root,factory){
  const api=factory();
  if(typeof module==="object"&&module.exports)module.exports=api;
  if(root)root.AerosStageAwareness=api;
})(typeof globalThis!=="undefined"?globalThis:this,function(){
  "use strict";

  const STAGES=["recon","enumeration","exploitation","foothold","privesc","lateral","looting","reporting"];
  const PRIMARY_PROGRESS_STAGES=["recon","enumeration","exploitation","foothold","privesc","lateral"];
  const CROSS_CUTTING_STAGES=new Set(["looting","reporting"]);
  const STAGE_INFERENCE_VERSION=2;
  const STAGE_HISTORY_VERSION=1;
  const DIRECT_STARTING_ACCESS_TYPES=new Set(["ssh","rdp","internal-foothold"]);
  const CREDENTIAL_STARTING_ACCESS_TYPES=new Set(["standard-credentials","privileged-credentials","domain-account","local-account","privileged-account","ssh","rdp","web-account"]);

  function clean(value){return String(value??"").trim();}
  function token(value){return clean(value).toLowerCase().replace(/[\s_]+/g,"-");}
  function safeArray(value){return Array.isArray(value)?value:[];}
  function safeObject(value){return value&&typeof value==="object"&&!Array.isArray(value)?value:{};}
  function unique(values){return [...new Set(safeArray(values).map(clean).filter(Boolean))];}
  function nowIso(options={}){return clean(options.now)||new Date().toISOString();}
  function normalizedStage(value){const stage=token(value);return STAGES.includes(stage)?stage:"recon";}
  function primaryStageIndex(value){return PRIMARY_PROGRESS_STAGES.indexOf(normalizedStage(value));}
  function stageIndex(value){return STAGES.indexOf(normalizedStage(value));}

  function hasText(value){return clean(value).length>0;}
  function hasMeaningfulValue(value,depth=0){
    if(depth>4)return false;
    if(value===true)return true;
    if(typeof value==="string")return hasText(value);
    if(typeof value==="number")return Number.isFinite(value)&&value!==0;
    if(Array.isArray(value))return value.some(item=>hasMeaningfulValue(item,depth+1));
    if(value&&typeof value==="object")return Object.values(value).some(item=>hasMeaningfulValue(item,depth+1));
    return false;
  }

  function hostAliases(host){
    return unique([host?.id,host?.ip,host?.hostname]).map(value=>value.toLowerCase());
  }
  function movementTouchesHost(movement,host){
    const aliases=hostAliases(host);
    if(!aliases.length)return false;
    const source=clean(movement?.sourceHost).toLowerCase();
    const target=clean(movement?.targetHost).toLowerCase();
    return aliases.some(alias=>alias&&(source===alias||target===alias||source.includes(alias)||target.includes(alias)));
  }
  function successfulMovementForHost(host,movements=[]){
    return safeArray(movements).some(movement=>movementTouchesHost(movement,host)&&["success","partial"].includes(token(movement?.result)));
  }

  function evidenceOfType(host,...types){
    const wanted=new Set(types.map(token));
    return safeArray(host?.evidence).filter(item=>item&&item.active!==false&&wanted.has(token(item?.type)));
  }
  function checkedServiceCount(host){
    return Object.values(safeObject(host?.services)).filter(service=>safeObject(service).checked).length;
  }
  function activeAccessContexts(host){return safeArray(host?.accessContexts).filter(context=>context&&context.active!==false);}
  function activeProvidedStartingAccess(host){return safeArray(host?.providedStartingAccess).filter(context=>context&&context.active!==false);}
  function hasRootAccessContext(host){
    return activeAccessContexts(host).some(context=>["root-admin","root","system","administrator","admin"].includes(token(context?.privilege)));
  }
  function hostIdentityValues(host){
    return unique([host?.id,host?.ip,host?.hostname]).map(value=>value.toLowerCase());
  }
  function targetHostValue(value){
    const raw=clean(value).toLowerCase();
    if(!raw)return "";
    try{
      const parsed=new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)?raw:`aeros://${raw}`);
      return clean(parsed.hostname).toLowerCase().replace(/^\[|\]$/g,"");
    }catch(error){
      return raw.replace(/^\[|\]$/g,"");
    }
  }
  function startingAccessEntryTargetsHost(entry,host){
    const row=safeObject(entry),hostId=clean(host?.id);
    if(clean(row.hostId))return clean(row.hostId)===hostId;
    const target=clean(row.target);
    if(!target)return false;
    const identities=new Set(hostIdentityValues(host));
    return target.split(/[,;\r\n]+/).map(targetHostValue).some(value=>identities.has(value));
  }
  function defaultStartingAccessMethod(entry){
    const type=token(entry?.type);
    if(type==="ssh")return "SSH";
    if(type==="rdp")return "RDP";
    if(type==="internal-foothold")return "Shell";
    return "";
  }
  function defaultStartingAccessPrivilege(entry){
    return /root|system|administrator|admin|privileged/i.test(`${entry?.type||""} ${entry?.privilege||""}`)?"root-admin":"user";
  }
  function defaultStartingAccessLabel(type){
    return token(type).replace(/-/g," ").replace(/\b\w/g,letter=>letter.toUpperCase())||"Starting access";
  }
  function deriveStartingAccessTruth(config,host,options={}){
    const starting=safeObject(config?.startingAccess);
    const types=unique(safeArray(starting.types).map(token));
    const entries=safeArray(starting.entries).filter(entry=>entry&&entry.active!==false);
    const matchingEntries=entries.filter(entry=>startingAccessEntryTargetsHost(entry,host));
    const methodForEntry=typeof options.methodForEntry==="function"?options.methodForEntry:defaultStartingAccessMethod;
    const privilegeForEntry=typeof options.privilegeForEntry==="function"?options.privilegeForEntry:defaultStartingAccessPrivilege;
    const labelForType=typeof options.labelForType==="function"?options.labelForType:defaultStartingAccessLabel;
    const directCandidates=matchingEntries.filter(entry=>DIRECT_STARTING_ACCESS_TYPES.has(token(entry?.type))).map((entry,index)=>{
      const type=token(entry?.type),method=clean(methodForEntry(entry))||defaultStartingAccessMethod(entry);
      const sourceId=clean(entry?.id),identity=sourceId||`${type}:${targetHostValue(entry?.target)||clean(host?.id)||index}`;
      return {
        matchKey:`provided:${identity}:${token(method)||"access"}`,
        source:"provided",
        sourceStartingAccessId:sourceId,
        principal:clean(entry?.username),
        privilege:clean(privilegeForEntry(entry))||defaultStartingAccessPrivilege(entry),
        method,
        displayName:clean(entry?.name),
        label:clean(entry?.name)||`${clean(labelForType(type))} (provided)`,
        active:true,
        acquiredAt:clean(entry?.createdAt),
        notes:clean(entry?.notes)
      };
    });
    const providedCredentials=types.some(type=>CREDENTIAL_STARTING_ACCESS_TYPES.has(type))||entries.some(entry=>
      clean(entry?.username)||clean(entry?.secret)||CREDENTIAL_STARTING_ACCESS_TYPES.has(token(entry?.type))
    );
    return {
      knowledgeLevel:token(config?.assessment?.knowledgeLevel),
      providedCredentials,
      directCandidates,
      hasDirectAccess:directCandidates.length>0,
      unresolvedDirectTypes:types.filter(type=>DIRECT_STARTING_ACCESS_TYPES.has(type))
    };
  }
  function hasEnumerationData(host){
    const scans=safeObject(host?.scans);
    const recon=safeObject(host?.recon);
    const systemInfo=safeObject(host?.systemInfo);
    const collectedSystemInfo={users:systemInfo.users,raw:systemInfo.raw,osnet:systemInfo.osnet,appsproc:systemInfo.appsproc,boxes:systemInfo.boxes,linux:systemInfo.linux,ad:systemInfo.ad,dynamicBoxes:systemInfo.dynamicBoxes,findings:systemInfo.findings};
    return hasText(scans.port)||hasText(scans.tcp)||hasText(scans.udp)||checkedServiceCount(host)>0||hasMeaningfulValue(recon)||hasMeaningfulValue(collectedSystemInfo)||host?.isDomain===true||host?.isDc===true;
  }
  function hasDocumentedFinding(host){
    return hasText(host?.findingTitle)&&(hasText(host?.attackPath)||hasText(host?.vulnExplanation)||hasText(host?.vulnFix));
  }
  function hasReportWork(host){
    const core=[host?.findingTitle,host?.vulnExplanation,host?.vulnFix,host?.attackPath].filter(hasText).length;
    const proof=hasText(host?.localProof)||hasText(host?.proofTxt)||safeArray(host?.evidence).some(item=>item&&item.active!==false);
    return core>=3&&proof&&(hasText(host?.reportNotes)||core===4);
  }

  function addSignal(signals,stage,key,reason){
    const normalized=normalizedStage(stage);const cleanKey=clean(key);const cleanReason=clean(reason);
    if(!cleanKey||!cleanReason)return;
    if(signals.some(item=>item.stage===normalized&&item.key===cleanKey))return;
    signals.push({stage:normalized,key:cleanKey,reason:cleanReason});
  }

  function collectStageSignals(host,options={}){
    const h=safeObject(host);const signals=[];
    addSignal(signals,"recon","host-record","Host is present in the engagement scope.");

    if(hasEnumerationData(h))addSignal(signals,"enumeration","enumeration-data","Scan, service, recon, or system-enumeration data is recorded.");

    if(evidenceOfType(h,"initial_access").length)addSignal(signals,"exploitation","initial-access-evidence","Active initial-access evidence is recorded.");
    if(hasDocumentedFinding(h))addSignal(signals,"exploitation","documented-exploit-path","A finding and exploit path are documented.");

    const footholdEvidence=evidenceOfType(h,"local","proof","lateral_movement");
    const structuredAccessModel=Array.isArray(h.accessContexts);
    if(!structuredAccessModel&&h.hasShell===true)addSignal(signals,"foothold","legacy-shell-recorded","A legacy working-shell record is present.");
    if(activeAccessContexts(h).length)addSignal(signals,"foothold","access-context","At least one active access context is recorded.");
    if(activeProvidedStartingAccess(h).length)addSignal(signals,"foothold","provided-direct-access","Host-linked direct starting access is recorded.");
    if(footholdEvidence.length)addSignal(signals,"foothold","foothold-evidence","Active foothold or proof evidence is recorded.");
    if(!structuredAccessModel&&["foothold","privesc","owned"].includes(token(h.status)))addSignal(signals,"foothold","legacy-host-status","A legacy host status records a foothold or later access.");

    if(!structuredAccessModel&&h.isRootAdmin===true)addSignal(signals,"privesc","legacy-elevated-access-flag","A legacy root, SYSTEM, or administrator access record is present.");
    if(hasRootAccessContext(h))addSignal(signals,"privesc","elevated-access-context","An elevated access context is recorded.");
    if(evidenceOfType(h,"proof","privilege_escalation").length)addSignal(signals,"privesc","privilege-evidence","Active privilege-escalation or elevated proof evidence is recorded.");
    if(hasText(h.privescTitle)&&(activeAccessContexts(h).length||(!structuredAccessModel&&h.hasShell===true)))addSignal(signals,"privesc","documented-privesc","A privilege-escalation path is documented for a host with active access.");
    if(!structuredAccessModel&&["privesc","owned"].includes(token(h.status)))addSignal(signals,"privesc","legacy-privileged-host-status","A legacy host status records privilege escalation or ownership.");

    if(evidenceOfType(h,"lateral_movement").length)addSignal(signals,"lateral","lateral-evidence","Lateral-movement evidence is recorded.");
    if(successfulMovementForHost(h,options.movements))addSignal(signals,"lateral","successful-movement","A successful or partial movement path involves this host.");

    if(evidenceOfType(h,"credential_dump").length)addSignal(signals,"looting","credential-dump","Credential-harvesting evidence is recorded.");
    if(evidenceOfType(h,"post_exploitation").some(item=>hasText(item?.lootPath)||hasText(item?.credentials)))addSignal(signals,"looting","post-exploitation-loot","Post-exploitation evidence contains loot or credentials.");

    if(hasReportWork(h))addSignal(signals,"reporting","report-work","The finding write-up contains report-ready technical detail and proof.");

    return signals;
  }

  function highestPrimarySignalStage(signals){
    let best="recon",bestIndex=0;
    safeArray(signals).forEach(signal=>{
      const index=primaryStageIndex(signal?.stage);
      if(index>bestIndex){best=normalizedStage(signal.stage);bestIndex=index;}
    });
    return best;
  }
  function reachedStagesFor(inferredStage,signals){
    const reached=[];const primaryIndex=primaryStageIndex(inferredStage);
    PRIMARY_PROGRESS_STAGES.forEach((stage,index)=>{if(index<=Math.max(0,primaryIndex))reached.push(stage);});
    CROSS_CUTTING_STAGES.forEach(stage=>{if(safeArray(signals).some(signal=>normalizedStage(signal?.stage)===stage))reached.push(stage);});
    return unique(reached);
  }
  function reasonForStage(signals,stage){
    const normalized=normalizedStage(stage);const matches=safeArray(signals).filter(signal=>normalizedStage(signal?.stage)===normalized);
    return clean(matches[matches.length-1]?.reason);
  }

  function evaluateHostStage(host,options={}){
    const signals=collectStageSignals(host,options);
    const candidate=highestPrimarySignalStage(signals);
    const inferredStage=candidate;
    const reachedStages=reachedStagesFor(inferredStage,signals);
    return {
      version:STAGE_INFERENCE_VERSION,
      inferredStage,
      candidateStage:candidate,
      reachedStages,
      reason:reasonForStage(signals,inferredStage),
      signals
    };
  }

  function stableSnapshot(result){
    return JSON.stringify({
      version:Number(result?.version)||STAGE_INFERENCE_VERSION,
      inferredStage:normalizedStage(result?.inferredStage),
      candidateStage:normalizedStage(result?.candidateStage),
      reachedStages:unique(result?.reachedStages),
      reason:clean(result?.reason),
      signals:safeArray(result?.signals).map(item=>({stage:normalizedStage(item?.stage),key:clean(item?.key),reason:clean(item?.reason)}))
    });
  }

  function applyHostStageInference(host,options={}){
    if(!host||typeof host!=="object")return null;
    const result=evaluateHostStage(host,options);
    const previous=safeObject(host.stageInference);
    const historical=safeObject(host.stageHistory);
    const historicalSignalMap=new Map();
    [...safeArray(historical.signals),...safeArray(previous.signals),...safeArray(result.signals)].forEach(item=>{
      const stage=normalizedStage(item?.stage),key=clean(item?.key),reason=clean(item?.reason);
      if(key&&reason)historicalSignalMap.set(`${stage}|${key}`,{stage,key,reason});
    });
    const historicalReachedStages=unique([
      ...safeArray(historical.reachedStages),
      ...safeArray(host.reachedStages),
      ...safeArray(previous.reachedStages),
      ...safeArray(result.reachedStages)
    ]).map(normalizedStage);
    const highestPrimaryStage=historicalReachedStages.reduce((best,stage)=>
      primaryStageIndex(stage)>primaryStageIndex(best)?stage:best,"recon");
    const finalResult={...result,reachedStages:result.reachedStages,reason:result.reason,signals:result.signals};
    const changed=stableSnapshot(previous)!==stableSnapshot(finalResult);
    host.inferredStage=finalResult.inferredStage;
    host.reachedStages=finalResult.reachedStages;
    host.stageInference={...finalResult,updatedAt:changed?nowIso(options):clean(previous.updatedAt)||nowIso(options)};
    host.stageHistory={
      version:STAGE_HISTORY_VERSION,
      highestPrimaryStage,
      reachedStages:historicalReachedStages,
      signals:[...historicalSignalMap.values()],
      updatedAt:changed?nowIso(options):clean(historical.updatedAt)||nowIso(options)
    };
    // The user's selected working focus is presentation state and must never be overwritten by inference.
    const focus=token(host.focusStage);host.focusStage=STAGES.includes(focus)?focus:null;
    return host.stageInference;
  }

  function stageRelation(stage,hostOrInference={}){
    const normalized=normalizedStage(stage);
    const inferred=normalizedStage(hostOrInference?.inferredStage||hostOrInference?.stageInference?.inferredStage);
    const reached=new Set(unique(hostOrInference?.reachedStages||hostOrInference?.stageInference?.reachedStages).map(normalizedStage));
    if(normalized===inferred)return "current";
    if(reached.has(normalized))return "reached";
    return "future";
  }

  return {
    STAGES,PRIMARY_PROGRESS_STAGES,CROSS_CUTTING_STAGES,STAGE_INFERENCE_VERSION,STAGE_HISTORY_VERSION,
    normalizedStage,stageIndex,primaryStageIndex,collectStageSignals,evaluateHostStage,
    applyHostStageInference,stageRelation,reasonForStage,movementTouchesHost,successfulMovementForHost,
    startingAccessEntryTargetsHost,deriveStartingAccessTruth
  };
});
