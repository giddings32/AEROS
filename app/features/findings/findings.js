(function(root,factory){
  const api=factory();
  if(typeof module==="object"&&module.exports)module.exports=api;
  if(root)root.AEROSFindings=api;
})(typeof window!=="undefined"?window:globalThis,function(){
  "use strict";

  const REPORT_STAGES=Object.freeze(["initial-access","privilege-escalation","lateral-movement","other"]);
  const REPORT_STAGE_LABELS=Object.freeze({
    "initial-access":"Initial Access",
    "privilege-escalation":"Privilege Escalation",
    "lateral-movement":"Lateral Movement",
    other:"Other / Supporting"
  });
  const REPORT_ROLES=Object.freeze(["primary","additional","supporting"]);
  const REPORT_ROLE_LABELS=Object.freeze({
    primary:"Primary",
    additional:"Additional",
    supporting:"Supporting"
  });
  const FINDING_STATUSES=Object.freeze([
    "draft","needs-evidence","report-ready","not-reported","ready-for-review",
    "changes-requested","approved","published"
  ]);
  const SOLO_EDITABLE_STATUSES=Object.freeze(["draft","needs-evidence","report-ready","not-reported"]);
  const FINDING_STATUS_LABELS=Object.freeze({
    draft:"Draft",
    "needs-evidence":"Needs Evidence",
    "report-ready":"Report Ready",
    "not-reported":"Not Reported",
    "ready-for-review":"Ready for Review",
    "changes-requested":"Changes Requested",
    approved:"Approved",
    published:"Published"
  });
  const SEVERITIES=Object.freeze(["not-assessed","informational","low","medium","high","critical"]);

  function clean(value){return String(value??"").trim();}
  function token(value){return clean(value).toLowerCase().replace(/[_\s]+/g,"-");}
  function list(value){return Array.isArray(value)?value:[];}
  function object(value){return value&&typeof value==="object"&&!Array.isArray(value)?value:{};}
  function unique(values){return [...new Set(list(values).map(clean).filter(Boolean))];}
  function nowIso(options={}){return clean(options.now)||new Date().toISOString();}
  function newId(prefix,options={}){
    if(typeof options.idFactory==="function")return clean(options.idFactory(prefix));
    return `${prefix}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
  }
  function findingDeleted(finding){return !!clean(finding?.deletedAt)||clean(finding?.status).toLowerCase()==="deleted";}
  function findingIncluded(finding){return !findingDeleted(finding)&&clean(finding?.status).toLowerCase()!=="not-reported";}
  function hostAssetIds(state){
    const ids=new Set();
    Object.entries(object(state?.hosts)).forEach(([key,host])=>{
      if(clean(key))ids.add(clean(key));
      if(clean(host?.id))ids.add(clean(host.id));
    });
    return ids;
  }
  function hostForAsset(state,assetId){
    const requested=clean(assetId);
    return Object.entries(object(state?.hosts)).find(([key,host])=>clean(key)===requested||clean(host?.id)===requested)?.[1]||null;
  }
  function normalizeScopedRef(value={},kind="activity"){
    const raw=object(value);
    const ref={
      assetId:clean(raw.assetId||raw.hostId),
      attemptId:clean(raw.attemptId||raw.investigationId)
    };
    if(kind==="result")ref.resultId=clean(raw.resultId);
    if(kind==="activity")ref.runId=clean(raw.runId||raw.activityId);
    if(kind==="evidence")ref.evidenceId=clean(raw.evidenceId);
    if(kind==="attack-path")ref.stepId=clean(raw.stepId||raw.attackPathStepId);
    return ref;
  }
  function normalizeReproductionRef(value={},index=0){
    const raw=object(value);
    return {
      ...normalizeScopedRef(raw,"activity"),
      included:raw.included!==false,
      order:Number.isInteger(Number(raw.order))&&Number(raw.order)>=0?Number(raw.order):index,
      reportAddendum:clean(raw.reportAddendum)
    };
  }
  function scopedKey(ref,kind){
    const row=object(ref);
    const tail=kind==="result"?row.resultId:kind==="evidence"?row.evidenceId:
      kind==="attack-path"?row.stepId:row.runId;
    return [clean(row.assetId),clean(row.attemptId),clean(tail)].join("\u0000");
  }
  function evidenceRefMatches(refValue,candidateValue){
    const ref=normalizeScopedRef(refValue,"evidence"),candidate=normalizeScopedRef(candidateValue,"evidence");
    if(!ref.evidenceId||ref.evidenceId!==candidate.evidenceId)return false;
    if(ref.assetId&&candidate.assetId&&ref.assetId!==candidate.assetId)return false;
    return !ref.attemptId||!candidate.attemptId||ref.attemptId===candidate.attemptId;
  }
  function normalizeScopedRefs(values,kind){
    const seen=new Set();
    return list(values).map((value,index)=>kind==="reproduction"?
      normalizeReproductionRef(value,index):normalizeScopedRef(value,kind)
    ).filter(ref=>{
      const key=scopedKey(ref,kind==="reproduction"?"activity":kind);
      if(!key.replace(/\u0000/g,"")||seen.has(key))return false;
      seen.add(key);return true;
    });
  }
  function placementId(findingId,index,placement){
    return clean(placement?.id)||`placement-${clean(findingId)||"finding"}-${index+1}`;
  }
  function normalizedOrder(value){
    const number=Number(value);
    return Number.isInteger(number)&&number>=0?number:value;
  }
  function normalizePlacement(value={},options={}){
    const raw=object(value);
    return {
      id:clean(raw.id)||newId("placement",options),
      assetId:clean(raw.assetId||raw.hostId),
      stage:clean(raw.stage).toLowerCase(),
      role:clean(raw.role).toLowerCase(),
      order:normalizedOrder(raw.order),
      createdAt:clean(raw.createdAt)||nowIso(options),
      updatedAt:clean(raw.updatedAt)||nowIso(options)
    };
  }
  function normalizeFinding(value={},options={}){
    const raw=object(value),createdAt=clean(raw.createdAt)||nowIso(options);
    const rawStatus=clean(raw.status).toLowerCase();
    const status=rawStatus==="deleted"?"deleted":FINDING_STATUSES.includes(rawStatus)?rawStatus:"draft";
    const severity=SEVERITIES.includes(clean(raw.severity).toLowerCase())?clean(raw.severity).toLowerCase():"not-assessed";
    const placements=list(raw.reportPlacements).map((placement,index)=>normalizePlacement(
      {...placement,id:placementId(raw.id,index,placement)},
      {...options,idFactory:undefined}
    ));
    const assetIds=unique([
      ...list(raw.assetIds||raw.affectedAssetIds),
      ...placements.map(placement=>placement.assetId)
    ]);
    const sourceInvestigationRefs=normalizeScopedRefs(raw.sourceInvestigationRefs,"activity")
      .map(ref=>({assetId:ref.assetId,attemptId:ref.attemptId}));
    const legacyEvidenceIds=unique(raw.evidenceIds);
    const rawEvidenceRefs=normalizeScopedRefs(raw.evidenceRefs,"evidence");
    const hasEvidenceSelectionVersion=Object.prototype.hasOwnProperty.call(raw,"evidenceSelectionVersion");
    const suppliedEvidenceRefs=Array.isArray(raw.evidenceRefs);
    const requestedEvidenceSelectionVersion=Math.max(0,Number(raw.evidenceSelectionVersion)||0);
    let scopedEvidenceSelection=requestedEvidenceSelectionVersion>=1||
      (!hasEvidenceSelectionVersion&&suppliedEvidenceRefs);
    let evidenceRefs=rawEvidenceRefs;
    if(!scopedEvidenceSelection&&legacyEvidenceIds.length){
      const candidateAssets=unique([...assetIds,...evidenceRefs.map(ref=>ref.assetId)]);
      if(candidateAssets.length===1){
        evidenceRefs=normalizeScopedRefs(legacyEvidenceIds.map(evidenceId=>({
          assetId:candidateAssets[0],attemptId:"",evidenceId
        })),"evidence");
        scopedEvidenceSelection=true;
      }
    }
    const evidenceSelectionVersion=scopedEvidenceSelection?1:0;
    const evidenceIds=evidenceSelectionVersion>=1?
      unique(evidenceRefs.map(ref=>ref.evidenceId)):legacyEvidenceIds;
    return {
      ...raw,
      id:clean(raw.id)||newId("finding",options),
      title:clean(raw.title),
      severity,
      status,
      summary:clean(raw.summary),
      rootCause:clean(raw.rootCause),
      description:clean(raw.description),
      impact:clean(raw.impact),
      reproduction:clean(raw.reproduction||raw.steps),
      remediation:clean(raw.remediation||raw.fix),
      references:clean(raw.references),
      cve:clean(raw.cve),
      cwe:clean(raw.cwe||raw.cweId),
      endpoint:object(raw.endpoint),
      assetIds,
      sourceInvestigationRefs,
      sourceResultRefs:normalizeScopedRefs(raw.sourceResultRefs,"result"),
      sourceActivityRefs:normalizeScopedRefs(raw.sourceActivityRefs,"activity"),
      reproductionRefs:normalizeScopedRefs(raw.reproductionRefs,"reproduction"),
      evidenceRefs,
      evidenceSelectionVersion,
      attackPathRefs:normalizeScopedRefs(raw.attackPathRefs,"attack-path"),
      sourceInvestigationIds:unique(raw.sourceInvestigationIds),
      sourceResultIds:unique(raw.sourceResultIds),
      activityIds:unique(raw.activityIds),
      evidenceIds,
      legacySnapshot:object(raw.legacySnapshot),
      legacyReviewConfirmed:raw.legacyReviewConfirmed===true,
      reportPlacements:placements,
      visibility:clean(raw.visibility)||"internal",
      revision:Math.max(1,Number(raw.revision)||1),
      createdAt,
      updatedAt:clean(raw.updatedAt)||createdAt
    };
  }
  function ensureState(state,options={}){
    if(!state||typeof state!=="object")return [];
    state.findings=list(state.findings).map(row=>normalizeFinding(row,options));
    return state.findings;
  }
  function placementRows(state,{includeDeleted=false}={}){
    const rows=[];
    list(state?.findings).forEach((finding,findingIndex)=>{
      if(!finding||typeof finding!=="object"||(!includeDeleted&&findingDeleted(finding)))return;
      list(finding.reportPlacements).forEach((placement,index)=>rows.push({
        finding,
        findingIndex,
        placement:object(placement),
        placementId:placementId(finding.id,index,placement),
        included:findingIncluded(finding)
      }));
    });
    return rows;
  }
  function issue(code,message,row={},extra={}){
    return {
      code,
      message,
      assetId:clean(row.placement?.assetId||row.placement?.hostId),
      stage:clean(row.placement?.stage).toLowerCase(),
      findingIds:unique(extra.findingIds||[row.finding?.id]),
      placementIds:unique(extra.placementIds||[row.placementId])
    };
  }
  function validateReportPlacements(stateValue={},options={}){
    const state=object(stateValue),assets=hostAssetIds(state),rows=placementRows(state);
    const issues=[],validRows=[],seenFindingStage=new Map();
    const rowsToValidate=rows.filter(row=>row.included||options.includeNotReported===true);
    const requiredPrimary=new Set(list(options.requiredPrimary).map(row=>{
      const value=object(row);
      return `${clean(value.assetId)}\u0000${clean(value.stage).toLowerCase()}`;
    }).filter(key=>!key.startsWith("\u0000")&&!key.endsWith("\u0000")));
    rowsToValidate.forEach(row=>{
      const placement=row.placement,assetId=clean(placement.assetId||placement.hostId);
      const stage=clean(placement.stage).toLowerCase(),role=clean(placement.role).toLowerCase();
      const order=placement.order;
      let structurallyValid=true;
      if(!REPORT_STAGES.includes(stage)){
        issues.push(issue("invalid-stage","Report placement has an invalid stage.",row));
        structurallyValid=false;
      }
      if(!REPORT_ROLES.includes(role)){
        issues.push(issue("invalid-role","Report placement has an invalid role.",row));
        structurallyValid=false;
      }
      if(!assetId||!assets.has(assetId)){
        issues.push(issue("missing-asset","Report placement references a missing asset.",row));
        structurallyValid=false;
      }
      if(typeof order!=="number"||!Number.isInteger(order)||order<0){
        issues.push(issue("invalid-order","Report placement order must be a non-negative integer.",row));
        structurallyValid=false;
      }
      const duplicateKey=`${clean(row.finding?.id)}\u0000${assetId}\u0000${stage}`;
      if(seenFindingStage.has(duplicateKey)){
        const prior=seenFindingStage.get(duplicateKey);
        issues.push(issue("duplicate-placement","A Finding has more than one placement for the same asset and stage.",row,{
          findingIds:[row.finding?.id],
          placementIds:[prior.placementId,row.placementId]
        }));
        structurallyValid=false;
      }else seenFindingStage.set(duplicateKey,row);
      if(structurallyValid)validRows.push({...row,assetId,stage,role,order});
    });

    const groups=new Map();
    validRows.forEach(row=>{
      const key=`${row.assetId}\u0000${row.stage}`;
      if(!groups.has(key))groups.set(key,[]);
      groups.get(key).push(row);
    });
    groups.forEach(group=>{
      const included=group.filter(row=>row.included);
      const primaries=included.filter(row=>row.role==="primary");
      if(primaries.length>1){
        issues.push(issue("multiple-primary","More than one active primary Finding exists for the same asset and stage.",primaries[0],{
          findingIds:primaries.map(row=>row.finding?.id),
          placementIds:primaries.map(row=>row.placementId)
        }));
      }
      const includedPrimary=included.filter(row=>row.role==="primary");
      if(included.some(row=>row.role==="additional")&&!includedPrimary.length){
        issues.push(issue("missing-primary","Additional Findings require one active primary Finding for the asset and stage.",included[0],{
          findingIds:included.map(row=>row.finding?.id),
          placementIds:included.map(row=>row.placementId)
        }));
      }
      const groupKey=`${group[0].assetId}\u0000${group[0].stage}`;
      if(requiredPrimary.has(groupKey)&&!includedPrimary.length&&
        !issues.some(row=>row.code==="missing-primary"&&`${row.assetId}\u0000${row.stage}`===groupKey)){
        issues.push(issue("missing-primary","Report readiness requires one included primary Finding for the asset and stage.",group[0],{
          findingIds:group.map(row=>row.finding?.id),
          placementIds:group.map(row=>row.placementId)
        }));
      }
      const orderGroups=new Map();
      included.filter(row=>row.role!=="primary").forEach(row=>{
        const key=`${row.role}\u0000${row.order}`;
        if(!orderGroups.has(key))orderGroups.set(key,[]);
        orderGroups.get(key).push(row);
      });
      orderGroups.forEach(rowsAtOrder=>{
        if(rowsAtOrder.length<2)return;
        issues.push(issue("unstable-order","Findings in the same role cannot share a display order.",rowsAtOrder[0],{
          findingIds:rowsAtOrder.map(row=>row.finding?.id),
          placementIds:rowsAtOrder.map(row=>row.placementId)
        }));
      });
    });
    requiredPrimary.forEach(key=>{
      if(groups.has(key))return;
      const [assetId,stage]=key.split("\u0000");
      if(!assets.has(assetId)||!REPORT_STAGES.includes(stage))return;
      issues.push(issue("missing-primary","Report readiness requires one included primary Finding for the asset and stage.",{
        finding:{},placement:{assetId,stage},placementId:""
      },{findingIds:[],placementIds:[]}));
    });
    issues.sort((a,b)=>[
      a.assetId,a.stage,a.code,a.findingIds.join(","),a.placementIds.join(",")
    ].join("\u0000").localeCompare([
      b.assetId,b.stage,b.code,b.findingIds.join(","),b.placementIds.join(",")
    ].join("\u0000")));
    return {
      valid:issues.length===0,
      blocking:issues.length>0,
      legacyOnly:rows.length===0,
      canonical:rows.length>0,
      issues,
      placementCount:rows.length
    };
  }
  function attemptForRef(state,ref){
    const host=hostForAsset(state,ref?.assetId);
    if(!host)return {host:null,attempt:null};
    const attempt=list(host.exploitAttempts).find(row=>clean(row?.id)===clean(ref?.attemptId))||null;
    return {host,attempt};
  }
  function activityForRef(state,ref){
    const resolved=attemptForRef(state,ref);
    return {...resolved,activity:list(resolved.attempt?.runs).find(row=>clean(row?.id)===clean(ref?.runId))||null};
  }
  function evidenceForRef(state,ref){
    const host=hostForAsset(state,ref?.assetId);
    return {host,evidence:list(host?.evidence).find(row=>clean(row?.id)===clean(ref?.evidenceId))||null};
  }
  function attackPathForRef(state,ref){
    const host=hostForAsset(state,ref?.assetId);
    return {host,step:list(host?.attackPathSteps).find(row=>clean(row?.id)===clean(ref?.stepId))||null};
  }
  function resultForRef(state,ref){
    const resolved=attemptForRef(state,ref);
    const result=resolved.attempt?.success&&typeof resolved.attempt.success==="object"?resolved.attempt.success:null;
    return {...resolved,result:result&&resultId(resolved.attempt)===clean(ref?.resultId)?result:null};
  }
  function referenceIssue(code,message,finding,ref,kind){
    return {
      code,message,kind,
      findingIds:unique([finding?.id]),
      assetId:clean(ref?.assetId),
      attemptId:clean(ref?.attemptId),
      reference:{...object(ref)}
    };
  }
  function validateFindingReferences(stateValue={},options={}){
    const state=object(stateValue),issues=[],requireReportContent=options.requireReportContent!==false;
    list(state.findings).forEach(rawFinding=>{
      const finding=normalizeFinding(rawFinding,{now:clean(rawFinding?.updatedAt)||new Date(0).toISOString()});
      if(findingDeleted(finding)||(!findingIncluded(finding)&&options.includeNotReported!==true))return;
      const placementAsset=clean(finding.reportPlacements?.[0]?.assetId);
      if(requireReportContent&&!finding.title)issues.push(referenceIssue("missing-finding-title","Canonical Finding title is required.",finding,{assetId:placementAsset},"finding"));
      if(requireReportContent&&Object.keys(finding.legacySnapshot).length&&finding.legacyReviewConfirmed!==true)
        issues.push(referenceIssue("legacy-review-required","Legacy report values must be reviewed before canonical ownership is reportable.",finding,{assetId:placementAsset},"finding"));
      if(requireReportContent&&!resolveFindingReproduction(state,finding).some(row=>clean(row.body)))
        issues.push(referenceIssue("missing-reproduction","Canonical Finding must include at least one valid reproduction activity.",finding,{assetId:placementAsset},"activity"));
      finding.sourceInvestigationRefs.forEach(ref=>{
        const resolved=attemptForRef(state,ref);
        if(!resolved.host)issues.push(referenceIssue("missing-source-asset","Finding source investigation references a missing asset.",finding,ref,"investigation"));
        else if(!resolved.attempt)issues.push(referenceIssue("missing-source-investigation","Finding source investigation no longer exists on the referenced asset.",finding,ref,"investigation"));
      });
      finding.sourceResultRefs.forEach(ref=>{
        const resolved=resultForRef(state,ref);
        if(!resolved.host)issues.push(referenceIssue("missing-source-asset","Finding source result references a missing asset.",finding,ref,"result"));
        else if(!resolved.attempt)issues.push(referenceIssue("missing-source-investigation","Finding source result references a missing investigation.",finding,ref,"result"));
        else if(!resolved.result)issues.push(referenceIssue("missing-source-result","Finding source result no longer matches the referenced investigation.",finding,ref,"result"));
        else if(resolved.result.confirmed!==true||clean(resolved.result.revokedAt)||clean(resolved.attempt.revokedAt))
          issues.push(referenceIssue("revoked-source-result","Finding source result is not currently confirmed.",finding,ref,"result"));
      });
      finding.sourceActivityRefs.forEach(ref=>{
        const resolved=activityForRef(state,ref);
        if(!resolved.host)issues.push(referenceIssue("missing-source-asset","Finding activity references a missing asset.",finding,ref,"activity"));
        else if(!resolved.attempt)issues.push(referenceIssue("missing-source-investigation","Finding activity references a missing investigation.",finding,ref,"activity"));
        else if(!resolved.activity)issues.push(referenceIssue("missing-source-activity","Finding activity no longer exists in the referenced investigation.",finding,ref,"activity"));
        else if(clean(resolved.attempt?.success?.sourceActivityId)!==clean(ref.runId))
          issues.push(referenceIssue("source-activity-result-mismatch","Finding source activity no longer matches the confirmed result.",finding,ref,"activity"));
      });
      finding.reproductionRefs.forEach(ref=>{
        const resolved=activityForRef(state,ref);
        if(!resolved.host)issues.push(referenceIssue("missing-source-asset","Finding activity references a missing asset.",finding,ref,"activity"));
        else if(!resolved.attempt)issues.push(referenceIssue("missing-source-investigation","Finding activity references a missing investigation.",finding,ref,"activity"));
        else if(!resolved.activity)issues.push(referenceIssue("missing-source-activity","Finding activity no longer exists in the referenced investigation.",finding,ref,"activity"));
      });
      const seenOrders=new Map();
      finding.reproductionRefs.filter(ref=>ref.included!==false).forEach(ref=>{
        if(seenOrders.has(ref.order))issues.push(referenceIssue(
          "duplicate-reproduction-order",
          "Included reproduction activities must have unique display orders.",
          finding,ref,"activity"
        ));
        else seenOrders.set(ref.order,ref);
      });
      finding.evidenceRefs.forEach(ref=>{
        const resolved=evidenceForRef(state,ref);
        if(!resolved.host)issues.push(referenceIssue("missing-evidence-asset","Finding evidence references a missing asset.",finding,ref,"evidence"));
        else if(!resolved.evidence||clean(resolved.evidence.deletedAt)||resolved.evidence.active===false)
          issues.push(referenceIssue("missing-evidence","Finding evidence is missing or inactive.",finding,ref,"evidence"));
        else if(clean(ref.attemptId)&&!list(resolved.evidence.attemptIds).map(clean).includes(clean(ref.attemptId))&&
          clean(resolved.evidence.attemptId)!==clean(ref.attemptId)&&
          clean(resolved.evidence.sourceExploitAttemptId||resolved.evidence.relatedExploitAttemptId)!==clean(ref.attemptId))
          issues.push(referenceIssue("evidence-investigation-mismatch","Finding evidence is not associated with the referenced investigation.",finding,ref,"evidence"));
      });
      finding.attackPathRefs.forEach(ref=>{
        const resolved=attackPathForRef(state,ref);
        if(!resolved.host)issues.push(referenceIssue("missing-attack-path-asset","Finding attack-path reference uses a missing asset.",finding,ref,"attack-path"));
        else if(!resolved.step||clean(resolved.step.deletedAt)||resolved.step.active===false)
          issues.push(referenceIssue("missing-attack-path-step","Finding attack-path step is missing or inactive.",finding,ref,"attack-path"));
        else if(clean(ref.attemptId)&&clean(resolved.step.sourceExploitAttemptId||resolved.step.attemptId)!==clean(ref.attemptId))
          issues.push(referenceIssue("attack-path-investigation-mismatch","Finding attack-path step belongs to a different investigation.",finding,ref,"attack-path"));
      });
    });
    issues.sort((a,b)=>[a.assetId,a.findingIds.join(","),a.kind,a.code].join("\u0000")
      .localeCompare([b.assetId,b.findingIds.join(","),b.kind,b.code].join("\u0000")));
    return {valid:issues.length===0,blocking:issues.length>0,issues};
  }
  function validateCanonicalFindings(stateValue={},options={}){
    const resolvedOptions={...options};
    if(!Array.isArray(resolvedOptions.requiredPrimary))resolvedOptions.requiredPrimary=requiredPrimaryPlacements(stateValue);
    const placements=validateReportPlacements(stateValue,resolvedOptions);
    const references=validateFindingReferences(stateValue,resolvedOptions);
    return {
      valid:placements.valid&&references.valid,
      blocking:placements.blocking||references.blocking,
      canonical:placements.canonical,
      legacyOnly:placements.legacyOnly,
      placementCount:placements.placementCount,
      issues:[...placements.issues,...references.issues],
      placements,references
    };
  }
  function resolveFindingReproduction(state,findingValue,{includeLegacy=true}={}){
    const finding=normalizeFinding(findingValue,{now:clean(findingValue?.updatedAt)||new Date(0).toISOString()});
    const rows=finding.reproductionRefs.filter(ref=>ref.included!==false)
      .sort((a,b)=>a.order-b.order||scopedKey(a,"activity").localeCompare(scopedKey(b,"activity")))
      .map(ref=>{
        const resolved=activityForRef(state,ref);
        return resolved.activity?{
          ref,
          activity:resolved.activity,
          attempt:resolved.attempt,
          host:resolved.host,
          body:activityBody(resolved.activity),
          reportAddendum:clean(ref.reportAddendum)
        }:null;
      }).filter(Boolean);
    if(rows.length||!includeLegacy||finding.reproductionRefs.length)return rows;
    const legacy=clean(finding.reproduction||finding.steps);
    return legacy?[{ref:null,activity:null,attempt:null,host:null,body:legacy,reportAddendum:"",legacy:true}]:[];
  }
  function resolveFindingEvidence(state,findingValue){
    const finding=normalizeFinding(findingValue,{now:clean(findingValue?.updatedAt)||new Date(0).toISOString()});
    return finding.evidenceRefs.map(ref=>{
      const resolved=evidenceForRef(state,ref);
      return resolved.evidence?{ref,...resolved}:null;
    }).filter(Boolean);
  }
  function canonicalStageManaged(state,assetId,stage){
    const wantedAsset=clean(assetId),wantedStage=clean(stage).toLowerCase();
    return placementRows(state).some(row=>
      clean(row.placement.assetId||row.placement.hostId)===wantedAsset&&
      clean(row.placement.stage).toLowerCase()===wantedStage
    );
  }
  function activeAccessContexts(host){return list(host?.accessContexts).filter(row=>row&&row.active!==false);}
  function elevatedPrivilege(value){return ["root-admin","root","administrator","admin","system"].includes(token(value));}
  function attemptStage(attempt){
    const stage=token(attempt?.success?.report?.stage);
    return REPORT_STAGES.includes(stage)?stage:"";
  }
  function confirmedAttempt(attempt){
    return !!attempt&&attempt?.success?.confirmed===true&&!clean(attempt?.success?.revokedAt)&&!clean(attempt?.revokedAt);
  }
  function activeStageEvidence(host,stage){
    const expected={"initial-access":"initial-access","privilege-escalation":"privilege-escalation","lateral-movement":"lateral-movement"}[stage];
    return expected&&list(host?.evidence).some(row=>row&&row.active!==false&&!clean(row.deletedAt)&&token(row.type)===expected);
  }
  function activeStageStep(host,stage){
    return list(host?.attackPathSteps).some(row=>row&&row.active!==false&&!clean(row.deletedAt)&&token(row.stage||row.reportStage)===stage);
  }
  function hostRequiresStageFinding(host,stage){
    const wanted=token(stage),contexts=activeAccessContexts(host);
    const attempts=list(host?.exploitAttempts).filter(confirmedAttempt);
    if(attempts.some(row=>attemptStage(row)===wanted)||activeStageEvidence(host,wanted)||activeStageStep(host,wanted))return true;
    if(wanted==="initial-access"){
      return contexts.length>0||attempts.some(row=>["interactive-shell","command-execution","authenticated-session"].includes(token(row?.success?.resultType))&&row?.success?.accessConfirmed===true)||
        host?.hasShell===true||clean(host?.localProof)!=="";
    }
    if(wanted==="privilege-escalation"){
      if(clean(host?.privescTitle))return true;
      const elevated=contexts.some(row=>elevatedPrivilege(row?.privilege))||attempts.some(row=>
        row?.success?.accessConfirmed===true&&elevatedPrivilege(row?.success?.privilege)
      );
      const lower=contexts.some(row=>{
        const privilege=token(row?.privilege);
        return !!privilege&&privilege!=="unknown"&&!elevatedPrivilege(privilege);
      })||attempts.some(row=>{
        const privilege=token(row?.success?.privilege);
        return row?.success?.accessConfirmed===true&&!!privilege&&privilege!=="unknown"&&!elevatedPrivilege(privilege);
      });
      const explicitDirectElevated=elevated&&!lower&&(
        contexts.some(row=>elevatedPrivilege(row?.privilege))||attempts.some(row=>
          row?.success?.accessConfirmed===true&&elevatedPrivilege(row?.success?.privilege)&&attemptStage(row)==="initial-access"
        )
      );
      if(clean(host?.proofTxt)&&!explicitDirectElevated)return true;
      return elevated&&lower;
    }
    if(wanted==="lateral-movement")return false;
    return false;
  }
  function requiredPrimaryPlacements(stateValue={}){
    const state=object(stateValue),required=[],seen=new Set();
    Object.entries(object(state.hosts)).forEach(([key,host])=>{
      if(!host||typeof host!=="object")return;
      const assetId=clean(host.id||key);
      const managed=REPORT_STAGES.some(stage=>canonicalStageManaged(state,assetId,stage));
      if(!assetId||!managed)return;
      REPORT_STAGES.filter(stage=>stage!=="other").forEach(stage=>{
        if(!hostRequiresStageFinding(host,stage))return;
        const id=`${assetId}\u0000${stage}`;
        if(!seen.has(id)){seen.add(id);required.push({assetId,stage});}
      });
    });
    return required;
  }
  function orderedForAssetStage(state,assetId,stage,{includeNotReported=false}={}){
    const wantedAsset=clean(assetId),wantedStage=clean(stage).toLowerCase();
    const roleWeight={primary:0,additional:1,supporting:2};
    return placementRows(state).filter(row=>{
      const placement=row.placement;
      return clean(placement.assetId||placement.hostId)===wantedAsset&&
        clean(placement.stage).toLowerCase()===wantedStage&&
        REPORT_ROLES.includes(clean(placement.role).toLowerCase())&&
        (includeNotReported||row.included);
    }).map(row=>({
      finding:row.finding,
      placement:{
        ...row.placement,
        id:row.placementId,
        assetId:wantedAsset,
        stage:wantedStage,
        role:clean(row.placement.role).toLowerCase(),
        order:Number(row.placement.order)
      }
    })).sort((a,b)=>
      roleWeight[a.placement.role]-roleWeight[b.placement.role]||
      a.placement.order-b.placement.order||
      a.placement.id.localeCompare(b.placement.id)
    );
  }
  function resultId(attempt){
    return clean(attempt?.success?.id)||`result-${clean(attempt?.id)||"investigation"}`;
  }
  function activityBody(run){
    if(clean(run?.body))return clean(run.body);
    return [
      clean(run?.requestOrCommand),
      clean(run?.changedValues)?`Changed values / payload:\n${clean(run.changedValues)}`:"",
      clean(run?.output)?`Output / response:\n${clean(run.output)}`:"",
      clean(run?.resultSummary)
    ].filter(Boolean).join("\n\n");
  }
  function nextPlacementOrder(state,assetId,stage,role){
    const rows=orderedForAssetStage(state,assetId,stage)
      .filter(row=>row.placement.role===role);
    return rows.length?Math.max(...rows.map(row=>Number(row.placement.order)||0))+1:0;
  }
  function stageEvidence(host,stage,attemptId=""){
    const type={
      "initial-access":"initial-access",
      "privilege-escalation":"privilege-escalation",
      "lateral-movement":"lateral-movement"
    }[clean(stage).toLowerCase()];
    if(!type)return null;
    const rows=list(host?.evidence).filter(row=>row&&row.active!==false&&!clean(row.deletedAt)&&token(row.type)===type);
    const wantedAttempt=clean(attemptId);
    const linked=rows.filter(row=>wantedAttempt&&(
      clean(row.attemptId)===wantedAttempt||
      clean(row.sourceExploitAttemptId||row.relatedExploitAttemptId)===wantedAttempt||
      list(row.attemptIds).map(clean).includes(wantedAttempt)
    ));
    const candidates=linked.length?linked:rows;
    return candidates.slice().sort((a,b)=>clean(b.updatedAt||b.createdAt).localeCompare(clean(a.updatedAt||a.createdAt)))[0]||null;
  }
  function legacySnapshotFor(state,host,attempt,stage,assetId){
    const normalizedStage=clean(stage).toLowerCase();
    if(canonicalStageManaged(state,assetId||host?.id,normalizedStage))return {};
    const report=object(attempt?.success?.report);
    const evidence=object(stageEvidence(host,normalizedStage,attempt?.id));
    let snapshot={resultReportTitle:clean(report.title),resultAttackPathStep:clean(report.attackPathStep)};
    if(normalizedStage==="initial-access")snapshot={...snapshot,
      findingTitle:clean(host?.findingTitle||evidence.title),
      vulnExplanation:clean(host?.vulnExplanation||evidence.explanation),
      vulnFix:clean(host?.vulnFix||evidence.fix),
      attackPath:clean(host?.attackPath||evidence.notes),
      severity:clean(host?.severity||evidence.severity)
    };
    else if(normalizedStage==="privilege-escalation")snapshot={...snapshot,
      privescTitle:clean(host?.privescTitle||evidence.title),
      privescExplanation:clean(evidence.explanation),
      privescFix:clean(evidence.fix),
      privescNotes:clean(evidence.notes),
      privescSeverity:clean(evidence.severity)
    };
    else if(normalizedStage==="lateral-movement")snapshot={...snapshot,
      lateralTitle:clean(evidence.title),
      lateralExplanation:clean(evidence.explanation),
      lateralNotes:clean(evidence.notes),
      lateralMethod:clean(evidence.method),
      lateralPath:[clean(evidence.sourceHost),clean(evidence.targetHost)].filter(Boolean).join(" -> ")
    };
    return Object.values(snapshot).some(Boolean)?snapshot:{};
  }
  function findingDraftFromResult(state,host,attempt,options={}){
    const success=object(attempt?.success),sourceResultId=resultId(attempt);
    const assetId=clean(options.assetId||host?.id),attemptId=clean(attempt?.id);
    const existing=list(state?.findings).find(row=>{
      const normalized=normalizeFinding(row,{now:clean(row?.updatedAt)||new Date(0).toISOString()});
      if(findingDeleted(normalized))return false;
      if(normalized.sourceResultRefs.some(ref=>ref.assetId===assetId&&ref.attemptId===attemptId&&ref.resultId===sourceResultId))return true;
      return normalized.sourceResultRefs.length===0&&normalized.assetIds.length===1&&normalized.assetIds[0]===assetId&&
        normalized.sourceInvestigationIds.length===1&&normalized.sourceInvestigationIds[0]===attemptId&&
        normalized.sourceResultIds.includes(sourceResultId);
    });
    if(existing)return normalizeFinding(existing,options);
    const sourceRun=list(attempt?.runs).find(row=>clean(row?.id)===clean(success.sourceActivityId))||null;
    const stage=REPORT_STAGES.includes(clean(options.stage||success.report?.stage).toLowerCase())?
      clean(options.stage||success.report?.stage).toLowerCase():"initial-access";
    const legacySnapshot=legacySnapshotFor(state,host,attempt,stage,assetId);
    const legacyTitle=clean(legacySnapshot.findingTitle||legacySnapshot.privescTitle||legacySnapshot.lateralTitle||legacySnapshot.resultReportTitle);
    const legacyDescription=clean(legacySnapshot.vulnExplanation||legacySnapshot.privescExplanation||legacySnapshot.lateralExplanation);
    const legacyRemediation=clean(legacySnapshot.vulnFix||legacySnapshot.privescFix);
    const legacySeverity=clean(legacySnapshot.severity||legacySnapshot.privescSeverity).toLowerCase();
    const evidenceIds=unique([success.proof?.evidenceId,success.report?.evidenceId]);
    const attackPathStepId=clean(success.report?.attackPathStepId);
    return normalizeFinding({
      id:`finding-${assetId}-${attemptId}-${sourceResultId}`.replace(/[^a-zA-Z0-9._-]+/g,"-"),
      title:clean(options.title||legacyTitle||
        attempt?.leadSnapshot?.title||attempt?.title),
      status:"draft",
      severity:SEVERITIES.includes(legacySeverity)?legacySeverity:"not-assessed",
      summary:clean(success.summary),
      description:clean(legacyDescription||attempt?.leadSnapshot?.description||attempt?.applicability?.notes),
      remediation:legacyRemediation,
      reproduction:"",
      cve:clean(attempt?.leadSnapshot?.cve),
      cwe:clean(attempt?.leadSnapshot?.cwe),
      identifier:clean(attempt?.leadSnapshot?.identifier),
      endpoint:{...object(attempt?.endpoint),...object(attempt?.webLocation)},
      assetIds:[assetId],
      sourceInvestigationRefs:[{assetId,attemptId}],
      sourceResultRefs:[{assetId,attemptId,resultId:sourceResultId}],
      sourceActivityRefs:sourceRun?[{assetId,attemptId,runId:sourceRun.id}]:[],
      reproductionRefs:sourceRun?[{assetId,attemptId,runId:sourceRun.id,included:true,order:0,reportAddendum:""}]:[],
      evidenceRefs:evidenceIds.map(evidenceId=>({assetId,attemptId,evidenceId})),
      evidenceSelectionVersion:1,
      attackPathRefs:attackPathStepId?[{assetId,attemptId,stepId:attackPathStepId}]:[],
      sourceInvestigationIds:[attemptId],
      sourceResultIds:[sourceResultId],
      activityIds:sourceRun?[sourceRun.id]:[],
      evidenceIds,
      legacySnapshot,
      legacyReviewConfirmed:Object.keys(legacySnapshot).length===0,
      reportPlacements:[{
        id:`placement-${sourceResultId}-${assetId}-${stage}`,
        assetId,
        stage,
        role:clean(options.role),
        order:options.order
      }]
    },options);
  }
  function saveFinding(state,input={},options={}){
    const rows=ensureState(state,options),incoming=normalizeFinding(input,{...options,now:nowIso(options)});
    const index=rows.findIndex(row=>row.id===incoming.id);
    if(index>=0){
      incoming.createdAt=rows[index].createdAt;
      incoming.revision=Math.max(1,Number(rows[index].revision)||1)+1;
      rows[index]=incoming;
    }else rows.push(incoming);
    return incoming;
  }

  function requireDependencies(dependencies){
    const required=[
      "getState","byId","activeHost","saveState","saveLabState","render",
      "alertUser","escapeHtml","escapeAttr","newId","formValue","setFormValue","clearFormValue"
    ];
    const missing=required.filter(name=>typeof dependencies?.[name]!=="function");
    if(missing.length)throw new Error(`AEROS findings dependencies are unavailable: ${missing.join(", ")}`);
  }
  function createFindings(dependencies){
    requireDependencies(dependencies);
    let editingId="",sourceAttemptId="",draftFinding=null;
    const state=()=>dependencies.getState();
    const host=()=>dependencies.activeHost();
    const byId=id=>dependencies.byId(id);
    const field=id=>clean(dependencies.formValue(id));
    const clone=value=>JSON.parse(JSON.stringify(value));

    function showForm(show=true){
      byId("reportFindingForm")?.classList?.toggle("hidden",!show);
      if(show)setTimeout(()=>byId("reportFindingTitle")?.focus(),0);
    }
    function syncStatusControl(status){
      const select=byId("reportFindingStatus");if(!select)return;
      select.querySelectorAll?.("[data-team-controlled-status]").forEach(option=>option.remove?.());
      const normalized=clean(status).toLowerCase();
      const teamControlled=normalized&&FINDING_STATUSES.includes(normalized)&&!SOLO_EDITABLE_STATUSES.includes(normalized);
      select.disabled=!!teamControlled;
      if(teamControlled){
        const option=select.ownerDocument?.createElement?.("option");
        if(option){
          option.value=normalized;
          option.textContent=`${FINDING_STATUS_LABELS[normalized]||normalized} · team-controlled`;
          option.dataset.teamControlledStatus="true";
          select.appendChild(option);
          select.value=normalized;
        }
      }
    }
    function clearForm(){
      editingId="";sourceAttemptId="";draftFinding=null;
      ["reportFindingTitle","reportFindingSummary","reportFindingRootCause","reportFindingDescription",
        "reportFindingImpact","reportFindingReproduction","reportFindingRemediation","reportFindingReferences",
        "reportFindingCve","reportFindingCwe"].forEach(dependencies.clearFormValue);
      dependencies.setFormValue("reportFindingStatus","draft");
      dependencies.setFormValue("reportFindingSeverity","not-assessed");
      dependencies.setFormValue("reportFindingStage","initial-access");
      dependencies.setFormValue("reportFindingRole","primary");
      dependencies.setFormValue("reportFindingOrder","0");
      syncStatusControl("draft");
      showForm(false);
    }
    function activityCandidates(activeHost){
      return list(activeHost?.exploitAttempts).flatMap(attempt=>list(attempt?.runs).map(run=>({
        assetId:clean(activeHost.id),attemptId:clean(attempt.id),runId:clean(run.id),attempt,run
      }))).filter(row=>row.assetId&&row.attemptId&&row.runId);
    }
    function renderReferenceSelectors(finding){
      const active=host(),activityRoot=byId("reportFindingActivityChoices"),evidenceRoot=byId("reportFindingEvidenceChoices");
      if(!active)return;
      const refs=list(finding?.reproductionRefs),activityRows=activityCandidates(active);
      if(activityRoot){
        activityRoot.innerHTML=activityRows.length?activityRows.map(row=>{
          const key=scopedKey(row,"activity"),existing=refs.find(ref=>scopedKey(ref,"activity")===key);
          const label=clean(row.run.body||row.run.requestOrCommand||row.run.resultSummary)||`Activity ${Number(row.run.sequence)||1}`;
          return `<article class="report-finding-card" data-finding-activity-row data-asset-id="${dependencies.escapeAttr(row.assetId)}" data-attempt-id="${dependencies.escapeAttr(row.attemptId)}" data-run-id="${dependencies.escapeAttr(row.runId)}" data-existing="${existing?"true":"false"}"><div class="report-finding-head"><label><input data-finding-activity-include type="checkbox" ${existing&&existing.included!==false?"checked":""}/> Include ${dependencies.escapeHtml(clean(row.attempt.title)||"Investigation")} · Activity ${dependencies.escapeHtml(Number(row.run.sequence)||1)}</label><button class="secondary-btn small" data-open-finding-activity="${dependencies.escapeAttr(row.attemptId)}" type="button">Open Activity</button></div><p>${dependencies.escapeHtml(label)}</p><div class="form-grid"><label>Order<input data-finding-activity-order min="0" step="1" type="number" value="${dependencies.escapeAttr(existing?.order??refs.filter(ref=>ref.included!==false).length)}"/></label><label>Optional transition note<input data-finding-activity-addendum type="text" value="${dependencies.escapeAttr(existing?.reportAddendum||"")}"/></label></div></article>`;
        }).join(""):'<div class="host-meta">No investigation activities are available for this asset.</div>';
        activityRoot.querySelectorAll("[data-open-finding-activity]").forEach(button=>button.onclick=()=>{
          if(typeof dependencies.openAttempt==="function")dependencies.openAttempt(button.dataset.openFindingActivity);
        });
      }
      if(evidenceRoot){
        const selected=list(finding?.evidenceRefs).map(ref=>normalizeScopedRef(ref,"evidence"));
        const rows=list(active.evidence).filter(row=>row&&row.active!==false&&!clean(row.deletedAt));
        evidenceRoot.innerHTML=rows.length?rows.map(evidence=>{
          const attemptId=clean(evidence.sourceExploitAttemptId||evidence.relatedExploitAttemptId);
          const ref={assetId:active.id,attemptId,evidenceId:evidence.id};
          return `<label class="report-finding-card"><input data-finding-evidence type="checkbox" data-asset-id="${dependencies.escapeAttr(active.id)}" data-attempt-id="${dependencies.escapeAttr(attemptId)}" data-evidence-id="${dependencies.escapeAttr(evidence.id)}" ${selected.some(selectedRef=>evidenceRefMatches(selectedRef,ref))?"checked":""}/> <strong>${dependencies.escapeHtml(evidence.title||evidence.proofFile||"Evidence")}</strong>${evidence.proofValue?` · ${dependencies.escapeHtml(evidence.proofValue)}`:""}</label>`;
        }).join(""):'<div class="host-meta">No active evidence is available for this asset.</div>';
      }
      const legacy=object(finding?.legacySnapshot),panel=byId("reportFindingLegacyPanel");
      if(panel){
        const entries=Object.entries(legacy).filter(([,value])=>clean(value));
        panel.classList.toggle("hidden",entries.length===0);
        panel.innerHTML=entries.length?`<div class="subsection-divider"></div><h4>Legacy report fields to review</h4><p class="hint">These values were copied into the draft where applicable. The original host fields remain unchanged.</p>${entries.map(([name,value])=>`<article class="report-finding-card"><strong>${dependencies.escapeHtml(name)}</strong><p>${dependencies.escapeHtml(value)}</p></article>`).join("")}<label class="exploit-success-check"><input id="reportFindingLegacyReviewed" type="checkbox" ${finding?.legacyReviewConfirmed===true?"checked":""}/> I reviewed the legacy values before assigning canonical ownership</label>`:"";
      }
    }
    function writeForm(finding,placement,attemptId=""){
      draftFinding=normalizeFinding(finding);
      editingId=clean(draftFinding.id);
      sourceAttemptId=clean(attemptId||draftFinding.sourceInvestigationRefs?.[0]?.attemptId||draftFinding.sourceInvestigationIds?.[0]);
      syncStatusControl(draftFinding.status);
      const values={
        reportFindingTitle:draftFinding.title,reportFindingStatus:draftFinding.status,
        reportFindingSeverity:draftFinding.severity,reportFindingStage:placement?.stage,
        reportFindingRole:placement?.role,reportFindingOrder:placement?.order,
        reportFindingSummary:draftFinding.summary,reportFindingRootCause:draftFinding.rootCause,
        reportFindingDescription:draftFinding.description,reportFindingImpact:draftFinding.impact,
        reportFindingReproduction:draftFinding.reportNarrative,reportFindingRemediation:draftFinding.remediation,
        reportFindingReferences:draftFinding.references,reportFindingCve:draftFinding.cve,reportFindingCwe:draftFinding.cwe
      };
      Object.entries(values).forEach(([id,value])=>dependencies.setFormValue(id,value??""));
      renderReferenceSelectors(draftFinding);
      showForm(true);
      byId("reportFindingForm")?.scrollIntoView?.({behavior:"smooth",block:"start"});
    }
    function openManual(){
      const active=host();if(!active)return dependencies.alertUser("Select a host first.");
      clearForm();
      const stage="initial-access",role=orderedForAssetStage(state(),active.id,stage)
        .some(row=>row.placement.role==="primary")?"additional":"primary";
      const draft=normalizeFinding({
        id:dependencies.newId("finding"),title:"",assetIds:[active.id],
        reportPlacements:[{id:dependencies.newId("placement"),assetId:active.id,stage,role,order:nextPlacementOrder(state(),active.id,stage,role)}]
      });
      writeForm(draft,draft.reportPlacements[0]);
    }
    function openForResult(attempt){
      const active=host();if(!active)return dependencies.alertUser("Select a host first.");
      if(attempt?.success?.confirmed!==true)return dependencies.alertUser("Confirm the technical result before promoting it to a Finding.");
      const sourceActivityId=clean(attempt?.success?.sourceActivityId);
      if(!sourceActivityId||!list(attempt?.runs).some(row=>clean(row?.id)===sourceActivityId))
        return dependencies.alertUser("Select the exact supporting activity on the confirmed result before promoting it.");
      const stage=clean(attempt?.success?.report?.stage)||"initial-access";
      const existingPrimary=orderedForAssetStage(state(),active.id,stage)
        .some(row=>row.placement.role==="primary");
      const role=existingPrimary?"additional":"primary",order=nextPlacementOrder(state(),active.id,stage,role);
      const draft=findingDraftFromResult(state(),active,attempt,{role,order,stage,idFactory:dependencies.newId});
      writeForm(draft,draft.reportPlacements.find(row=>row.assetId===active.id&&row.stage===stage)||draft.reportPlacements[0],attempt.id);
    }
    function editFinding(id){
      const active=host(),finding=list(state().findings).find(row=>clean(row?.id)===clean(id));if(!active||!finding)return;
      const placement=list(finding.reportPlacements).find(row=>clean(row?.assetId||row?.hostId)===clean(active.id))||finding.reportPlacements?.[0];
      writeForm(finding,placement,finding.sourceInvestigationIds?.[0]);
    }
    async function save(){
      const active=host();if(!active)return false;
      const title=field("reportFindingTitle"),stage=field("reportFindingStage"),role=field("reportFindingRole");
      const order=Number(field("reportFindingOrder"));
      if(!title)return dependencies.alertUser("Finding Title is required."),false;
      if(!REPORT_STAGES.includes(stage))return dependencies.alertUser("Choose a valid report stage."),false;
      if(!REPORT_ROLES.includes(role))return dependencies.alertUser("Choose a valid report role."),false;
      if(!Number.isInteger(order)||order<0)return dependencies.alertUser("Display Order must be a non-negative whole number."),false;
      if(Object.keys(object(draftFinding?.legacySnapshot)).length&&byId("reportFindingLegacyReviewed")?.checked!==true)
        return dependencies.alertUser("Review and confirm the legacy report values before saving this canonical Finding."),false;
      const activityRefs=[...(byId("reportFindingActivityChoices")?.querySelectorAll?.("[data-finding-activity-row]")||[])].map(row=>{
        const included=row.querySelector("[data-finding-activity-include]")?.checked===true;
        const existed=row.dataset.existing==="true";
        if(!included&&!existed)return null;
        return normalizeReproductionRef({
          assetId:row.dataset.assetId,attemptId:row.dataset.attemptId,runId:row.dataset.runId,
          included,order:Number(row.querySelector("[data-finding-activity-order]")?.value),
          reportAddendum:row.querySelector("[data-finding-activity-addendum]")?.value
        });
      }).filter(Boolean);
      const includedOrders=activityRefs.filter(ref=>ref.included!==false).map(ref=>ref.order);
      if(new Set(includedOrders).size!==includedOrders.length)
        return dependencies.alertUser("Included reproduction activities must use unique display orders."),false;
      const evidenceRefs=[...(byId("reportFindingEvidenceChoices")?.querySelectorAll?.("[data-finding-evidence]:checked")||[])]
        .map(input=>normalizeScopedRef({
          assetId:input.dataset.assetId,attemptId:input.dataset.attemptId,evidenceId:input.dataset.evidenceId
        },"evidence"));
      const existing=list(state().findings).find(row=>clean(row?.id)===editingId);
      const attempt=list(active.exploitAttempts).find(row=>clean(row?.id)===sourceAttemptId);
      const draft=existing?normalizeFinding(existing):draftFinding?normalizeFinding(draftFinding):attempt?
        findingDraftFromResult(state(),active,attempt,{stage,role,order,idFactory:dependencies.newId}):
        normalizeFinding({id:editingId||dependencies.newId("finding"),assetIds:[active.id]});
      const otherPlacements=list(draft.reportPlacements).filter(row=>clean(row.assetId)!==clean(active.id));
      const previousPlacement=list(draft.reportPlacements).find(row=>clean(row.assetId)===clean(active.id));
      const requestedStatus=field("reportFindingStatus").toLowerCase();
      const status=SOLO_EDITABLE_STATUSES.includes(requestedStatus)?requestedStatus:
        existing&&FINDING_STATUSES.includes(clean(existing.status).toLowerCase())?clean(existing.status).toLowerCase():"draft";
      const record={
        ...draft,
        title,
        status,
        severity:field("reportFindingSeverity"),
        summary:field("reportFindingSummary"),
        rootCause:field("reportFindingRootCause"),
        description:field("reportFindingDescription"),
        impact:field("reportFindingImpact"),
        reportNarrative:field("reportFindingReproduction"),
        remediation:field("reportFindingRemediation"),
        references:field("reportFindingReferences"),
        cve:field("reportFindingCve"),
        cwe:field("reportFindingCwe"),
        reproductionRefs:activityRefs,
        evidenceRefs,
        evidenceSelectionVersion:1,
        evidenceIds:unique(evidenceRefs.map(ref=>ref.evidenceId)),
        legacyReviewConfirmed:Object.keys(object(draft.legacySnapshot)).length?
          byId("reportFindingLegacyReviewed")?.checked===true:true,
        assetIds:unique([...draft.assetIds,active.id]),
        reportPlacements:[...otherPlacements,{
          ...previousPlacement,
          id:clean(previousPlacement?.id)||dependencies.newId("placement"),
          assetId:active.id,stage,role,order,updatedAt:new Date().toISOString()
        }],
        updatedAt:new Date().toISOString()
      };
      const snapshot=clone(list(state().findings));
      saveFinding(state(),record,{idFactory:dependencies.newId});
      const validation=validateCanonicalFindings(state());
      if(["report-ready","ready-for-review","approved","published"].includes(record.status)&&!validation.valid){
        state().findings=snapshot;
        dependencies.alertUser(`This Finding cannot be saved as ${FINDING_STATUS_LABELS[record.status]||record.status} until the report placement and source references are valid:\n${validation.issues.map(row=>row.message).join("\n")}`);
        return false;
      }
      dependencies.saveState();
      try{await dependencies.saveLabState(true);}catch(error){
        state().findings=snapshot;
        dependencies.saveState();
        dependencies.alertUser(`SQLite save failed, so the Finding change was rolled back: ${error.message}`);
        return false;
      }
      clearForm();dependencies.render();
      if(!validation.valid)dependencies.alertUser(`Finding saved as a draft, but report export remains blocked until these items are corrected:\n${validation.issues.map(row=>row.message).join("\n")}`);
      return true;
    }
    async function removeFinding(id){
      const finding=list(state().findings).find(row=>clean(row?.id)===clean(id));
      if(!finding)return false;
      const confirmed=typeof dependencies.confirmDelete==="function"?
        await dependencies.confirmDelete(`Delete "${clean(finding.title)||"this Finding"}"? Its source investigations and evidence will remain intact.`,{title:"Delete Finding",confirmText:"Delete Finding",danger:true}):
        (typeof window==="undefined"||window.confirm(`Delete "${clean(finding.title)||"this Finding"}"?`));
      if(!confirmed)return false;
      const snapshot=clone(list(state().findings)),row=list(state().findings).find(item=>clean(item?.id)===clean(id));
      row.status="deleted";row.deletedAt=new Date().toISOString();row.updatedAt=row.deletedAt;
      const validation=validateCanonicalFindings(state());
      dependencies.saveState();
      try{await dependencies.saveLabState(true);}
      catch(error){
        state().findings=snapshot;dependencies.saveState();
        dependencies.alertUser(`SQLite save failed, so the Finding deletion was rolled back: ${error.message}`);
        return false;
      }
      if(editingId===id)clearForm();
      dependencies.render();
      if(!validation.valid)dependencies.alertUser(`Finding deleted. The remaining report placement now needs correction before export:\n${validation.issues.map(item=>item.message).join("\n")}`);
      return true;
    }
    function render(activeHost){
      ensureState(state());
      const root=byId("reportFindingList"),summary=byId("reportFindingSummaryBar");if(!root||!activeHost)return;
      const rows=list(state().findings).filter(finding=>!findingDeleted(finding)&&list(finding.reportPlacements)
        .some(placement=>clean(placement.assetId||placement.hostId)===clean(activeHost.id)));
      if(summary){
        const included=rows.filter(findingIncluded).length;
        summary.innerHTML=`<article><span>Canonical Findings</span><strong>${rows.length}</strong></article><article><span>Included</span><strong>${included}</strong></article><article><span>Not Reported</span><strong>${rows.length-included}</strong></article>`;
      }
      if(!rows.length){
        root.innerHTML='<div class="host-meta">No canonical Findings own this asset yet. Promote a confirmed result or create a Finding manually.</div>';
        return;
      }
      root.innerHTML=rows.map(finding=>{
        const placements=list(finding.reportPlacements).filter(row=>clean(row.assetId||row.hostId)===clean(activeHost.id));
        return `<article class="report-finding-card"><div class="report-finding-head"><div><span>${dependencies.escapeHtml(FINDING_STATUS_LABELS[finding.status]||finding.status)}</span><h4>${dependencies.escapeHtml(finding.title||"Title required")}</h4></div><strong>${dependencies.escapeHtml(finding.severity)}</strong></div><div class="report-finding-placements">${placements.map(placement=>`<span>${dependencies.escapeHtml(REPORT_STAGE_LABELS[placement.stage]||placement.stage)} · ${dependencies.escapeHtml(REPORT_ROLE_LABELS[placement.role]||placement.role)} · order ${dependencies.escapeHtml(placement.order)}</span>`).join("")}</div>${finding.description?`<p>${dependencies.escapeHtml(finding.description)}</p>`:""}<div class="row-actions"><button class="secondary-btn small" data-edit-report-finding="${dependencies.escapeAttr(finding.id)}" type="button">Edit Finding</button><button class="danger-btn small" data-delete-report-finding="${dependencies.escapeAttr(finding.id)}" type="button">Delete Finding</button></div></article>`;
      }).join("");
      root.querySelectorAll("[data-edit-report-finding]").forEach(button=>button.onclick=()=>editFinding(button.dataset.editReportFinding));
      root.querySelectorAll("[data-delete-report-finding]").forEach(button=>button.onclick=()=>removeFinding(button.dataset.deleteReportFinding));
    }
    return Object.freeze({render,openManual,openForResult,editFinding,save,removeFinding,clearForm,showForm});
  }

  return Object.freeze({
    REPORT_STAGES,REPORT_STAGE_LABELS,REPORT_ROLES,REPORT_ROLE_LABELS,
    FINDING_STATUSES,FINDING_STATUS_LABELS,SOLO_EDITABLE_STATUSES,SEVERITIES,
    findingDeleted,findingIncluded,normalizePlacement,normalizeFinding,ensureState,
    placementRows,validateReportPlacements,validateFindingReferences,validateCanonicalFindings,
    normalizeScopedRef,normalizeReproductionRef,scopedKey,evidenceRefMatches,attemptForRef,activityForRef,
    evidenceForRef,attackPathForRef,resultForRef,resolveFindingReproduction,resolveFindingEvidence,
    canonicalStageManaged,orderedForAssetStage,hostRequiresStageFinding,requiredPrimaryPlacements,
    resultId,activityBody,nextPlacementOrder,stageEvidence,legacySnapshotFor,findingDraftFromResult,saveFinding,hostForAsset,
    create:createFindings
  });
});
