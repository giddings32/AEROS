(function(root,factory){
  const profileApi=(typeof module==="object"&&module.exports)
    ?require("../../../host-profile.js")
    :(root&&root.AerosHostProfile);
  const api=factory(profileApi||{});
  if(typeof module==="object"&&module.exports)module.exports=api;
  if(root)root.AEROSReadiness=api;
})(typeof globalThis!=="undefined"?globalThis:this,function(profileApi){
  "use strict";

  const PLACEHOLDER=/^\s*(tbd|todo|tba|xxx|placeholder|fill ?in|n\/a|\.\.\.|untitled finding)\s*$/i;
  const SEVERITIES=Object.freeze(["blocking","warning"]);
  const CATEGORY_LABELS=Object.freeze({
    target:"Target Identity",enumeration:"Enumeration",access:"Access",proof:"Proof Capture",reporting:"Reporting",engagement:"Engagement"
  });

  function clean(value){return String(value??"").trim();}
  function token(value){return clean(value).toLowerCase().replace(/[_\s]+/g,"-");}
  function list(value){return Array.isArray(value)?value:[];}
  function object(value){return value&&typeof value==="object"&&!Array.isArray(value)?value:{};}
  function hasText(value){return clean(value).length>0;}
  function placeholder(value){return PLACEHOLDER.test(clean(value));}
  function meaningfulEndpointFact(value,assignedLabel=""){
    const text=clean(value).replace(/\s+/g," "),lower=text.toLowerCase();
    if(!text||["-","/","unknown","n/a","na","none","null","nil","not available","not applicable","undefined"].includes(lower))return "";
    if(/^[^a-z0-9]+$/i.test(text)||assignedLabel&&lower===clean(assignedLabel).toLowerCase())return "";
    return text;
  }
  function slug(value){return clean(value).toLowerCase().replace(/[^a-z0-9]+/g,"-").replace(/^-|-$/g,"")||"item";}
  function hostLabel(host){return clean(host?.hostname)||clean(host?.ip)||"Unnamed host";}
  function profileChecks(options={}){return object(options.profile?.checks);}
  function exploitApi(options={}){return options.exploitAttemptsApi||null;}
  function findingsApi(options={}){return options.findingsApi||null;}

  function issue({id,severity="warning",scope="host",category="reporting",hostId="",pathId="",title="",detail="",tab="review",anchor="",attemptId=""}={}){
    return {
      id:clean(id)||`${scope}-${slug(title)}`,
      severity:SEVERITIES.includes(severity)?severity:"warning",
      scope,category,hostId:clean(hostId),pathId:clean(pathId),title:clean(title),detail:clean(detail),
      action:{tab:clean(tab)||"review",anchor:clean(anchor),attemptId:clean(attemptId)}
    };
  }
  function criterion({id,label,category="reporting",applicable=true,complete=false,severity="blocking",issueData=null}={}){
    return {id:clean(id),label:clean(label),category,applicable:applicable!==false,complete:complete===true,severity:SEVERITIES.includes(severity)?severity:"blocking",issue:issueData?issue(issueData):null};
  }
  function summarizeCriteria(criteria=[]){
    const applicable=criteria.filter(row=>row.applicable!==false);
    const complete=applicable.filter(row=>row.complete).length;
    const score=applicable.length?Math.round((complete/applicable.length)*100):0;
    return {complete,total:applicable.length,score};
  }
  function serviceEndpoints(host){
    const rows=list(host?.serviceInventory).filter(row=>row&&token(row.state||"open")!=="closed");
    const seen=new Set();
    return rows.filter(row=>{const key=`${token(row.protocol||"tcp")}:${Number(row.port)||0}`;if(seen.has(key))return false;seen.add(key);return Number(row.port)>0;});
  }
  function discoveredTcpPorts(host){
    const ports=new Set();
    list(host?.scanEvidence?.port?.ports).forEach(value=>{const port=Number(value);if(port>0&&port<=65535)ports.add(port);});
    serviceEndpoints(host).filter(row=>token(row.protocol||"tcp")==="tcp").forEach(row=>ports.add(Number(row.port)));
    return [...ports].sort((a,b)=>a-b);
  }
  function activeAccess(host){return list(host?.accessContexts).filter(row=>row&&row.active!==false);}
  function elevated(context){return ["root-admin","root","administrator","admin","system"].includes(token(context?.privilege));}
  function interactiveAccess(context){
    if(typeof profileApi.interactiveAccess==="function")return profileApi.interactiveAccess(context);
    if(!context||context.active===false||context.revoked===true)return false;
    if(context.interactiveShell===false||context.shell===false)return false;
    if(context.interactiveShell===true||context.shell===true)return true;
    const description=[context.method,context.accessMethod,context.sessionType,context.resultType,context.label].map(clean).join(" ").toLowerCase();
    if(/\b(database|mysql|postgres(?:ql)?|mssql|oracle|smb|ftp|http|api|web session|authenticated session|credential)\b/.test(description))return false;
    return /\b(ssh|shell|winrm|evil-winrm|rdp|telnet|console|tty|reverse|bind|meterpreter|collector|peas)\b/.test(description);
  }
  function interactiveAttempt(attempt){
    const success=object(attempt?.success);
    return attempt?.active!==false&&success.accessConfirmed===true&&(
      success.interactiveShell===true||token(success.resultType)==="interactive-shell"
    );
  }
  function proofApplicability(host,type="local.txt"){
    const contexts=activeAccess(host).filter(interactiveAccess),attempts=activeAttempts(host).filter(interactiveAttempt);
    const user=contexts.some(row=>!elevated(row))||attempts.some(row=>!elevated(row.success));
    const privileged=contexts.some(elevated)||attempts.some(row=>elevated(row.success));
    const proofType=token(type)==="proof.txt"?"proof.txt":"local.txt";
    const applicable=proofType==="proof.txt"?privileged:user;
    return {
      type:proofType,
      applicable,
      userAccess:user,
      elevatedAccess:privileged,
      reason:applicable
        ?proofType==="proof.txt"?"Valid elevated interactive access makes proof.txt applicable.":"Valid user interactive access makes local.txt applicable."
        :proofType==="proof.txt"?"Not applicable until elevated interactive access.":"Not applicable until user interactive access."
    };
  }
  function activeAttempts(host){return list(host?.exploitAttempts).filter(row=>row&&["successful","partial"].includes(token(row.status))&&(row?.success?.confirmed===true||row?.success?.confirmed===undefined));}
  function activeSteps(host){return list(host?.attackPathSteps).filter(row=>row&&row.active!==false);}
  function reportStage(value){return token(value);}
  function privilegeEscalationRequired(host){
    const contexts=activeAccess(host).filter(interactiveAccess),attempts=activeAttempts(host),steps=activeSteps(host);
    const hasElevatedContext=contexts.some(elevated),hasLowerContext=contexts.some(row=>{
      const privilege=token(row?.privilege);
      return !!privilege&&privilege!=="unknown"&&!elevated(row);
    });
    const explicitAttempt=attempts.some(row=>reportStage(row?.success?.report?.stage)==="privilege-escalation");
    const explicitStep=steps.some(row=>reportStage(row?.stage||row?.reportStage)==="privilege-escalation");
    const explicitEvidence=list(host?.evidence).some(row=>row&&row.active!==false&&!hasText(row.deletedAt)&&token(row.type)==="privilege-escalation");
    const elevatedAttempt=attempts.some(row=>row?.success?.accessConfirmed===true&&elevated(row?.success));
    const lowerAttempt=attempts.some(row=>{
      const privilege=token(row?.success?.privilege);
      return row?.success?.accessConfirmed===true&&!!privilege&&privilege!=="unknown"&&!elevated(row?.success);
    });
    const explicitDirectElevated=(hasElevatedContext||elevatedAttempt)&&!(hasLowerContext||lowerAttempt)&&(
      hasElevatedContext||attempts.some(row=>reportStage(row?.success?.report?.stage)==="initial-access"&&row?.success?.accessConfirmed===true&&elevated(row?.success))
    );
    const legacyStage=hasText(host?.privescTitle)||(hasText(host?.proofTxt)&&!explicitDirectElevated);
    return explicitAttempt||explicitStep||explicitEvidence||legacyStage||((hasElevatedContext||elevatedAttempt)&&(hasLowerContext||lowerAttempt));
  }
  function evidenceImage(item){return hasText(item?.imageDataUrl||item?.screenshotAbsPath||item?.screenshotRelPath);}
  function proofEvidence(host,type){return list(host?.evidence).filter(row=>row&&row.active!==false&&token(row.type)===token(type));}
  function reportable(host,options={}){
    const findingApi=findingsApi(options),state=options.state||{},assetId=clean(options.assetId||host?.id);
    const canonical=findingApi?.REPORT_STAGES?.some(stage=>findingApi.orderedForAssetStage(state,assetId,stage).length)||false;
    return activeAccess(host).length>0||activeAttempts(host).length>0||activeSteps(host).length>0||
      canonical||
      hasText(host?.localProof)||hasText(host?.proofTxt)||hasText(host?.findingTitle)||hasText(host?.vulnExplanation)||hasText(host?.attackPath)||
      list(host?.evidence).some(row=>row&&row.active!==false&&["local","proof","initial-access","initial_access","privilege-escalation","privilege_escalation","custom"].includes(token(row.type)));
  }
  function proofAttempts(host,type){
    return activeAttempts(host).filter(row=>token(row?.success?.proof?.type)===token(type));
  }
  function proofAttempt(host,type,options={}){
    const rows=proofAttempts(host,type),api=exploitApi(options);
    if(!rows.length)return null;
    if(!api?.proofReadiness)return rows[0];
    return rows.slice().sort((a,b)=>list(api.proofReadiness(a).missing).length-list(api.proofReadiness(b).missing).length)[0];
  }
  function proofComplete(host,type,options={}){
    const rows=proofAttempts(host,type),api=exploitApi(options);
    if(rows.length&&api?.proofReadiness&&rows.some(row=>api.proofReadiness(row).complete===true))return true;
    const legacyValue=type==="local.txt"?host?.localProof:host?.proofTxt;
    const evidence=proofEvidence(host,type==="local.txt"?"local":"proof");
    return hasText(legacyValue)&&evidence.some(evidenceImage);
  }
  function proofMissing(host,type,options={}){
    const attempt=proofAttempt(host,type,options),api=exploitApi(options);
    if(attempt&&api?.proofReadiness)return list(api.proofReadiness(attempt).missing);
    const missing=[],legacyValue=type==="local.txt"?host?.localProof:host?.proofTxt;
    const evidence=proofEvidence(host,type==="local.txt"?"local":"proof");
    if(!hasText(legacyValue)&&!evidence.some(row=>hasText(row.proofValue)))missing.push(`record the ${type} value`);
    if(!evidence.some(evidenceImage))missing.push("attach the proof screenshot");
    if(evidence.length&&!evidence.some(row=>/\b(cat|type)\b/i.test(clean(row.notes))))missing.push("record the exact cat/type command and original path");
    return missing;
  }

  function assessPath(host,step,options={}){
    const hostId=clean(host?.id),pathId=clean(step?.id)||`path-${slug(step?.summary)}`;
    const attempt=list(host?.exploitAttempts).find(row=>clean(row?.id)===clean(step?.sourceExploitAttemptId))||null;
    const criteria=[];
    const add=(row)=>criteria.push(criterion(row));
    add({id:"path-summary",label:"Reproducible attack-path narrative",complete:hasText(step?.summary),issueData:{id:`${pathId}-summary`,severity:"blocking",scope:"path",category:"reporting",hostId,pathId,title:"Attack-path narrative is missing",detail:"Record the exact sequence needed for a technically competent reader to reproduce this step.",tab:"evidence",anchor:"exploitAttemptsSection",attemptId:attempt?.id}});
    add({id:"path-source",label:"Structured source attempt",complete:!!attempt,severity:"warning",issueData:{id:`${pathId}-source`,severity:"warning",scope:"path",category:"reporting",hostId,pathId,title:"Attack-path step is not linked to an exploit attempt",detail:"Link the step to the attempt, command, result, and supporting evidence that produced it.",tab:"evidence",anchor:"exploitAttemptsSection"}});
    if(attempt){
      const sourceActivity=list(attempt?.runs).find(row=>clean(row?.id)===clean(attempt?.success?.sourceActivityId));
      add({id:"path-command",label:"Exact execution command or activity",complete:hasText(sourceActivity?.body||sourceActivity?.requestOrCommand||attempt?.provenance?.executeCommand),issueData:{id:`${pathId}-command`,severity:"blocking",scope:"path",category:"reporting",hostId,pathId,title:"Exact execution activity is missing",detail:`${clean(attempt.title)||"The source investigation"} does not record the activity that produced the result.`,tab:"evidence",anchor:"exploitAttemptsSection",attemptId:attempt.id}});
      const accessResult=["interactive-shell","command-execution","authenticated-session"].includes(token(attempt?.success?.resultType));
      add({id:"path-result",label:accessResult?"Obtained result and identity":"Confirmed technical result",complete:accessResult?
        attempt?.success?.accessConfirmed===true&&hasText(attempt?.success?.principal)&&hasText(attempt?.success?.method)&&token(attempt?.success?.privilege)!=="unknown":
        attempt?.success?.confirmed===true&&!!sourceActivity,
        issueData:{id:`${pathId}-result`,severity:"blocking",category:accessResult?"access":"reporting",hostId,pathId,
          title:accessResult?"Obtained access is not fully identified":"Technical result is not fully supported",
          detail:accessResult?"Confirm the principal, access method, and privilege that resulted from this step.":"Confirm the technical result and select the exact activity that demonstrated it.",
          tab:"evidence",anchor:"exploitAttemptsSection",attemptId:attempt.id}});
      add({id:"path-stage",label:"Report stage",complete:hasText(attempt?.success?.report?.stage),severity:"warning",issueData:{id:`${pathId}-stage`,severity:"warning",scope:"path",category:"reporting",hostId,pathId,title:"Report stage is missing",detail:"Classify this step as initial access, privilege escalation, lateral movement, or supporting activity.",tab:"evidence",anchor:"exploitAttemptsSection",attemptId:attempt.id}});
    }
    const issues=criteria.filter(row=>row.applicable&&!row.complete&&row.issue).map(row=>row.issue);
    const summary=summarizeCriteria(criteria);
    return {id:pathId,hostId,label:clean(step?.title)||clean(attempt?.title)||"Attack-path step",active:step?.active!==false,attemptId:clean(attempt?.id),criteria,issues,...summary,state:issues.some(row=>row.severity==="blocking")?"blocked":issues.length?"review":"ready"};
  }

  function assessHost(host,options={}){
    const hostId=clean(options.assetId||host?.id),label=hostLabel(host),criteria=[];
    const add=(row)=>criteria.push(criterion(row));
    const reportHost=reportable(host,options),tcpPorts=discoveredTcpPorts(host),endpoints=serviceEndpoints(host),contexts=activeAccess(host),attempts=activeAttempts(host),paths=activeSteps(host);
    const scanEvidence=object(host?.scanEvidence),portEntry=object(scanEvidence.port),tcpEntry=object(scanEvidence.tcp),udpEntry=object(scanEvidence.udp);

    add({id:"target-ip",label:"Target IP",complete:hasText(host?.ip),issueData:{id:`${hostId}-target-ip`,severity:"blocking",category:"target",hostId,title:"Target IP is missing",detail:"Record the target address before relying on any scan, proof, or report evidence.",tab:"profile",anchor:"hostProfileEditor"}});
    add({id:"target-os",label:"Operating-system family",complete:token(host?.os)!=="unknown"&&hasText(host?.os),severity:"warning",issueData:{id:`${hostId}-target-os`,severity:"warning",category:"target",hostId,title:"Operating-system family is unknown",detail:"Confirm whether the host is Linux, Windows, or another platform so methodology and report language are accurate.",tab:"profile",anchor:"hostProfileEditor"}});
    add({id:"tcp-discovery",label:"Full TCP discovery evidence",complete:portEntry.confirmed===true,issueData:{id:`${hostId}-tcp-discovery`,severity:"blocking",category:"enumeration",hostId,title:"Full TCP discovery evidence is missing",detail:"Import or confirm the full TCP discovery result instead of relying only on a partial or targeted scan.",tab:"recon",anchor:"scanPanelPort"}});
    add({id:"service-coverage",label:"Service enumeration for discovered TCP ports",applicable:tcpPorts.length>0,complete:tcpEntry.confirmed===true&&list(tcpEntry.uncoveredPorts).length===0,issueData:{id:`${hostId}-service-coverage`,severity:"blocking",category:"enumeration",hostId,title:"Discovered TCP services are not fully enumerated",detail:list(tcpEntry.uncoveredPorts).length?`Missing service coverage for: ${list(tcpEntry.uncoveredPorts).join(", ")}.`:"Import or confirm version/default-script enumeration for every discovered TCP port.",tab:"recon",anchor:"scanPanelTcp"}});
    add({id:"udp-review",label:"Targeted UDP review",complete:udpEntry.confirmed===true,severity:"warning",issueData:{id:`${hostId}-udp-review`,severity:"warning",category:"enumeration",hostId,title:"UDP review is not confirmed",detail:"Record targeted UDP discovery, including a confirmed negative result when no open UDP services are found.",tab:"recon",anchor:"scanPanelUdp"}});
    const unversioned=endpoints.filter(row=>{const assigned=clean(row.serviceHint||row.serviceRaw);return !meaningfulEndpointFact(row.product,assigned)&&!meaningfulEndpointFact(row.version,assigned);}).map(row=>`${Number(row.port)}/${token(row.protocol||"tcp")}`);
    add({id:"endpoint-detail",label:"Product or version detail for identified endpoints",applicable:endpoints.length>0,complete:unversioned.length===0,severity:"warning",issueData:{id:`${hostId}-endpoint-detail`,severity:"warning",category:"enumeration",hostId,title:"Some endpoints have no product or version detail",detail:`Review: ${unversioned.join(", ")}. A service can remain unknown, but the gap should be intentional and visible.`,tab:"recon",anchor:"serviceInventory"}});

    contexts.forEach((context,index)=>{
      const contextLabel=clean(context.principal)||clean(context.label)||`Access context ${index+1}`;
      add({id:`access-${index}-identity`,label:`${contextLabel}: identity, method, and privilege`,complete:hasText(context.principal)&&hasText(context.method)&&hasText(context.privilege)&&token(context.privilege)!=="unknown",issueData:{id:`${hostId}-access-${index}`,severity:"blocking",category:"access",hostId,title:`${contextLabel} access context is incomplete`,detail:"Record the principal, access method, and confirmed privilege so the compromise is attributable and reproducible.",tab:"notes",anchor:"accessContextWorkspace"}});
    });
    attempts.forEach((attempt,index)=>{
      const api=exploitApi(options),readiness=api?.proofReadiness?api.proofReadiness(attempt):null;
      add({id:`attempt-${index}-capture`,label:`${clean(attempt.title)||`Attempt ${index+1}`}: access/proof capture`,complete:readiness?readiness.complete:true,issueData:{id:`${hostId}-attempt-${clean(attempt.id)||index}`,severity:"blocking",category:"proof",hostId,title:`${clean(attempt.title)||"Successful attempt"} is not fully captured`,detail:readiness?.missing?.length?readiness.missing.join("; "):"Finish the access result and proof-capture record.",tab:"evidence",anchor:"exploitAttemptsSection",attemptId:attempt.id}});
    });

    const localApplicability=proofApplicability(host,"local.txt"),privilegedApplicability=proofApplicability(host,"proof.txt");
    const hasElevated=privilegedApplicability.applicable,hasUser=localApplicability.applicable;
    const checks=profileChecks(options),examProof=options.profile?.exam===true||checks.requireLocalProof===true;
    if(examProof&&hasUser){
      const requiredType="local.txt";
      const missing=proofMissing(host,requiredType,options);
      add({id:"required-proof",label:`Complete ${requiredType} capture`,complete:proofComplete(host,requiredType,options),issueData:{id:`${hostId}-required-proof`,severity:"blocking",category:"proof",hostId,title:`${requiredType} capture is incomplete`,detail:missing.length?missing.join("; "):`Record ${requiredType} from its original location with the required screenshot and target identity.`,tab:"evidence",anchor:"exploitAttemptsSection",attemptId:proofAttempt(host,requiredType,options)?.id}});
    }
    if(examProof&&hasElevated){
      const requiredType="proof.txt",missing=proofMissing(host,requiredType,options);
      add({id:"required-privileged-proof",label:`Complete ${requiredType} capture`,complete:proofComplete(host,requiredType,options),issueData:{id:`${hostId}-required-privileged-proof`,severity:"blocking",category:"proof",hostId,title:`${requiredType} capture is incomplete`,detail:missing.length?missing.join("; "):`Record ${requiredType} from its original location with the required screenshot and target identity.`,tab:"evidence",anchor:"exploitAttemptsSection",attemptId:proofAttempt(host,requiredType,options)?.id}});
    }

    const findingApi=findingsApi(options),findingState=options.state||{};
    const canonicalRows=findingApi?.REPORT_STAGES?.flatMap(stage=>findingApi.orderedForAssetStage(findingState,hostId,stage))||[];
    const initialManaged=findingApi?.canonicalStageManaged?.(findingState,hostId,"initial-access")||false;
    const privilegeManaged=findingApi?.canonicalStageManaged?.(findingState,hostId,"privilege-escalation")||false;
    const canonicalManaged=findingApi?.REPORT_STAGES?.some(stage=>findingApi.canonicalStageManaged(findingState,hostId,stage))||false;
    if(canonicalManaged){
      const requiredStages=list(findingApi?.requiredPrimaryPlacements?.(findingState)).filter(row=>clean(row?.assetId)===hostId);
      requiredStages.forEach(({stage})=>{
        const primary=findingApi.orderedForAssetStage(findingState,hostId,stage).some(row=>row.placement?.role==="primary");
        const stageLabel=findingApi.REPORT_STAGE_LABELS?.[stage]||stage;
        add({id:`finding-primary-${stage}`,label:`Primary ${stageLabel} Finding`,complete:primary,issueData:{id:`${hostId}-finding-primary-${stage}`,severity:"blocking",category:"reporting",hostId,title:`Primary ${stageLabel} Finding is missing`,detail:`This asset has confirmed ${stageLabel.toLowerCase()} activity, but no included primary Finding owns that report stage.`,tab:"evidence",anchor:"reportFindingsSection"}});
      });
    }
    if(canonicalRows.length){
      canonicalRows.forEach((row,index)=>{
        const finding=row.finding,labelText=clean(finding.title)||`Finding ${index+1}`;
        add({id:`finding-${index}-title`,label:`${labelText}: title`,complete:hasText(finding.title)&&!placeholder(finding.title),issueData:{id:`${hostId}-finding-${clean(finding.id)||index}-title`,severity:"blocking",category:"reporting",hostId,title:"Canonical Finding title is missing",detail:"Complete the Finding title before report export.",tab:"evidence",anchor:"reportFindingsSection"}});
        add({id:`finding-${index}-description`,label:`${labelText}: technical description`,complete:hasText(finding.description||finding.summary)&&!placeholder(finding.description||finding.summary),issueData:{id:`${hostId}-finding-${clean(finding.id)||index}-description`,severity:"blocking",category:"reporting",hostId,title:"Canonical Finding description is missing",detail:"Complete the technical description or summary.",tab:"evidence",anchor:"reportFindingsSection"}});
        const reproduction=findingApi.resolveFindingReproduction?.(findingState,finding)||[];
        add({id:`finding-${index}-steps`,label:`${labelText}: reproduction`,complete:reproduction.some(item=>hasText(item.body)&&!placeholder(item.body)),issueData:{id:`${hostId}-finding-${clean(finding.id)||index}-steps`,severity:"blocking",category:"reporting",hostId,title:"Canonical Finding reproduction is missing",detail:"Select at least one valid reproducible activity for this Finding.",tab:"evidence",anchor:"reportFindingsSection"}});
        add({id:`finding-${index}-remediation`,label:`${labelText}: remediation`,complete:hasText(finding.remediation||finding.fix)&&!placeholder(finding.remediation||finding.fix),severity:"warning",issueData:{id:`${hostId}-finding-${clean(finding.id)||index}-remediation`,severity:"warning",category:"reporting",hostId,title:"Canonical Finding remediation is missing",detail:"Record a practical fix or mitigation.",tab:"evidence",anchor:"reportFindingsSection"}});
        add({id:`finding-${index}-severity`,label:`${labelText}: severity`,complete:token(finding.severity)!=="not-assessed",severity:"warning",issueData:{id:`${hostId}-finding-${clean(finding.id)||index}-severity`,severity:"warning",category:"reporting",hostId,title:"Canonical Finding severity is not assessed",detail:"Assess the severity or intentionally mark the Finding as not reported.",tab:"evidence",anchor:"reportFindingsSection"}});
        add({id:`finding-${index}-legacy-review`,label:`${labelText}: legacy review`,applicable:Object.keys(object(finding.legacySnapshot)).length>0,complete:finding.legacyReviewConfirmed===true,issueData:{id:`${hostId}-finding-${clean(finding.id)||index}-legacy-review`,severity:"blocking",category:"reporting",hostId,title:"Legacy report values require review",detail:"Review the preserved legacy snapshot before relying on this canonical Finding.",tab:"evidence",anchor:"reportFindingsSection"}});
      });
    }
    if(!initialManaged){
      add({id:"report-title",label:"Finding title",applicable:reportHost,complete:hasText(host?.findingTitle)&&!placeholder(host?.findingTitle),issueData:{id:`${hostId}-report-title`,severity:"blocking",category:"reporting",hostId,title:"Finding title is missing or still a placeholder",detail:"Give the compromise a report-ready title that states the weakness and impact.",tab:"evidence",anchor:"reportFields"}});
      add({id:"report-explanation",label:"Vulnerability explanation",applicable:reportHost,complete:hasText(host?.vulnExplanation)&&!placeholder(host?.vulnExplanation),issueData:{id:`${hostId}-report-explanation`,severity:"blocking",category:"reporting",hostId,title:"Vulnerability explanation is missing or still a placeholder",detail:"Explain why the weakness existed and how it enabled the compromise.",tab:"evidence",anchor:"reportFields"}});
      add({id:"report-steps",label:"Reproducible steps",applicable:reportHost,complete:(hasText(host?.attackPath)&&!placeholder(host?.attackPath))||paths.some(row=>hasText(row.summary)),issueData:{id:`${hostId}-report-steps`,severity:"blocking",category:"reporting",hostId,title:"Reproducible attack steps are missing",detail:"Record every material command, result, and transition needed to reproduce the compromise.",tab:"evidence",anchor:"reportFields"}});
      add({id:"report-remediation",label:"Remediation",applicable:reportHost,complete:hasText(host?.vulnFix)&&!placeholder(host?.vulnFix),severity:"warning",issueData:{id:`${hostId}-report-remediation`,severity:"warning",category:"reporting",hostId,title:"Remediation is missing",detail:"Record a practical fix or mitigation for the identified weakness.",tab:"evidence",anchor:"reportFields"}});
      add({id:"report-severity",label:"Severity",applicable:reportHost,complete:hasText(host?.severity),severity:"warning",issueData:{id:`${hostId}-report-severity`,severity:"warning",category:"reporting",hostId,title:"Severity is not set",detail:"Assign a severity so the finding is prioritized consistently in the final report.",tab:"evidence",anchor:"reportFields"}});
    }
    const peRequired=findingApi?.hostRequiresStageFinding?.(host,"privilege-escalation")??privilegeEscalationRequired(host);
    if(peRequired&&!privilegeManaged&&!canonicalManaged){
      const peAttempts=attempts.filter(row=>reportStage(row?.success?.report?.stage)==="privilege-escalation");
      const peAttemptIds=new Set(peAttempts.map(row=>clean(row?.id)).filter(Boolean));
      const peSteps=paths.filter(row=>
        reportStage(row?.stage||row?.reportStage)==="privilege-escalation"||
        peAttemptIds.has(clean(row?.sourceExploitAttemptId||row?.attemptId))
      );
      const peEvidence=list(host?.evidence).filter(row=>row&&row.active!==false&&!hasText(row.deletedAt)&&token(row.type)==="privilege-escalation");
      const peReproduction=peAttempts.some(row=>{
        const source=list(row?.runs).find(run=>clean(run?.id)===clean(row?.success?.sourceActivityId));
        return hasText(source?.body||source?.requestOrCommand||row?.provenance?.executeCommand);
      })||peSteps.some(row=>hasText(row?.summary))||peEvidence.some(row=>hasText(row?.notes||row?.explanation));
      add({id:"report-privesc-title",label:"Privilege Escalation finding title",complete:hasText(host?.privescTitle)&&!placeholder(host?.privescTitle),issueData:{id:`${hostId}-report-privesc-title`,severity:"blocking",category:"reporting",hostId,title:"Privilege Escalation finding title is missing or still a placeholder",detail:"Give the privilege-escalation stage a report-ready title.",tab:"evidence",anchor:"reportFields"}});
      add({id:"report-privesc-steps",label:"Privilege Escalation reproducible steps",complete:peReproduction,issueData:{id:`${hostId}-report-privesc-steps`,severity:"blocking",category:"reporting",hostId,title:"Privilege Escalation reproduction is missing",detail:"Record the exact activity, evidence, or attack-path transition that produced elevated access.",tab:"evidence",anchor:"reportFields"}});
    }
    const unexplained=list(host?.evidence).filter(row=>row&&row.active!==false&&!hasText(row.explanation)&&!hasText(row.notes));
    add({id:"evidence-context",label:"Explanation for active evidence",applicable:!canonicalManaged&&reportHost&&list(host?.evidence).length>0,complete:unexplained.length===0,severity:"warning",issueData:{id:`${hostId}-evidence-context`,severity:"warning",category:"reporting",hostId,title:"Some evidence has no explanation",detail:`${unexplained.length} active evidence item${unexplained.length===1?"":"s"} lack context describing what the evidence proves.`,tab:"evidence",anchor:"evidenceList"}});

    const pathAssessments=paths.map(step=>assessPath(host,step,options));
    const issues=criteria.filter(row=>row.applicable&&!row.complete&&row.issue).map(row=>row.issue).concat(pathAssessments.flatMap(row=>row.issues));
    const summary=summarizeCriteria(criteria.concat(pathAssessments.flatMap(row=>row.criteria)));
    const blockers=issues.filter(row=>row.severity==="blocking").length,warnings=issues.length-blockers;
    let state="ready",stateLabel="Report ready";
    if(!reportHost){state="in-progress";stateLabel=portEntry.confirmed?"Enumeration in progress":"Enumeration incomplete";}
    else if(blockers){state="blocked";stateLabel=examProof&&((hasUser&&!proofComplete(host,"local.txt",options))||(hasElevated&&!proofComplete(host,"proof.txt",options)))?"Access obtained — proof or documentation missing":"Report blockers remain";}
    else if(warnings){state="review";stateLabel="Ready with review warnings";}
    return {id:hostId,label,host,reportable:reportHost,state,stateLabel,criteria,issues,pathAssessments,blockers,warnings,proofApplicability:{local:localApplicability,privileged:privilegedApplicability},...summary,categories:Object.keys(CATEGORY_LABELS).reduce((out,key)=>{out[key]=issues.filter(row=>row.category===key);return out;},{})};
  }

  function assessEngagement(stateValue={},options={}){
    const state=object(stateValue),hostEntries=Object.entries(object(state.hosts));
    const hosts=hostEntries.map(([,host])=>host);
    const hostAssessments=hostEntries.map(([key,host])=>assessHost(host,{...options,state,assetId:clean(host?.id||key),profile:options.profile||{}}));
    const criteria=[],issues=[];
    const add=(row)=>criteria.push(criterion(row));
    const checks=profileChecks(options);
    const findingModel=findingsApi(options);
    const requiredPrimary=[
      ...list(findingModel?.requiredPrimaryPlacements?.(state)),
      ...list(options.requiredPrimaryPlacements)
    ].filter((row,index,rows)=>row&&rows.findIndex(other=>clean(other?.assetId)===clean(row?.assetId)&&token(other?.stage)===token(row?.stage))===index);
    const canonicalValidation=(findingModel?.validateCanonicalFindings||findingModel?.validateReportPlacements)?.(state,{requiredPrimary});
    if(canonicalValidation&&!canonicalValidation.valid){
      canonicalValidation.issues.forEach((findingIssue,index)=>issues.push(issue({
        id:`canonical-${index}-${findingIssue.code}`,severity:"blocking",scope:"engagement",category:"reporting",
        hostId:findingIssue.assetId,title:findingIssue.kind?"Canonical Finding reference conflict":"Canonical Finding placement conflict",
        detail:`${findingIssue.message}${findingIssue.stage?` Stage: ${findingIssue.stage}.`:""}`,
        tab:"evidence",anchor:"reportFindingsSection"
      })));
    }
    add({id:"project-name",label:"Project name",complete:hasText(state.projectName),issueData:{id:"engagement-project-name",severity:"blocking",scope:"engagement",category:"engagement",title:"Project name is missing",detail:"Set the engagement name so report titles and saved records are attributable.",tab:"options",anchor:"reportingOptions"}});
    add({id:"tester-name",label:"Tester name",complete:hasText(state.testerName),severity:"warning",issueData:{id:"engagement-tester-name",severity:"warning",scope:"engagement",category:"engagement",title:"Tester name is missing",detail:"Record the tester name used in the report.",tab:"options",anchor:"profileOptions"}});
    add({id:"tester-email",label:"Tester email",complete:hasText(state.studentEmail),severity:"warning",issueData:{id:"engagement-tester-email",severity:"warning",scope:"engagement",category:"engagement",title:"Tester email is missing",detail:"Record the report contact or student email.",tab:"options",anchor:"profileOptions"}});
    add({id:"osid",label:"OSID",applicable:checks.requireOsid===true,complete:hasText(state.osid),severity:"warning",issueData:{id:"engagement-osid",severity:"warning",scope:"engagement",category:"engagement",title:"OSID is missing",detail:"Add the OSID required by the active exam profile.",tab:"options",anchor:"profileOptions"}});
    add({id:"hosts",label:"At least one target host",complete:hosts.length>0,issueData:{id:"engagement-hosts",severity:"blocking",scope:"engagement",category:"engagement",title:"No target hosts exist",detail:"Add or import at least one target before generating a report.",tab:"profile"}});
    add({id:"reportable-host",label:"At least one reportable compromise",applicable:options.profile?.exam===true,complete:hostAssessments.some(row=>row.reportable),issueData:{id:"engagement-reportable-host",severity:"blocking",scope:"engagement",category:"engagement",title:"No reportable compromise is recorded",detail:"Document a successful or partial attack path, obtained access, proof, or a report finding before submission.",tab:"review"}});
    const ips={};hosts.forEach(host=>{const ip=clean(host?.ip);if(ip)ips[ip]=(ips[ip]||0)+1;});
    Object.entries(ips).filter(([,count])=>count>1).forEach(([ip,count])=>issues.push(issue({id:`duplicate-ip-${slug(ip)}`,severity:"warning",scope:"engagement",category:"engagement",title:`Duplicate target IP: ${ip}`,detail:`${count} host records use this address. Confirm they are not accidental duplicates.`,tab:"profile"})));
    issues.push(...criteria.filter(row=>row.applicable&&!row.complete&&row.issue).map(row=>row.issue));
    const reportableHosts=hostAssessments.filter(row=>row.reportable),hostIssues=reportableHosts.flatMap(row=>row.issues);
    const combinedCriteria=criteria.concat(reportableHosts.flatMap(row=>row.criteria),reportableHosts.flatMap(row=>row.pathAssessments.flatMap(path=>path.criteria)));
    const summary=summarizeCriteria(combinedCriteria),allIssues=issues.concat(hostIssues);
    const blockers=allIssues.filter(row=>row.severity==="blocking").length,warnings=allIssues.length-blockers;
    const ready=blockers===0&&hostAssessments.some(row=>row.reportable);
    return {
      state:ready?(warnings?"review":"ready"):"blocked",stateLabel:ready?(warnings?"Ready with warnings":"Submission ready"):(hostAssessments.some(row=>row.reportable)?"Submission blockers remain":"No reportable compromise"),
      criteria,issues:allIssues,engagementIssues:issues,hosts:hostAssessments,reportableHosts:reportableHosts.length,totalHosts:hostAssessments.length,readyHosts:reportableHosts.filter(row=>row.blockers===0).length,blockers,warnings,...summary
    };
  }

  return {CATEGORY_LABELS,SEVERITIES,issue,criterion,reportable,privilegeEscalationRequired,interactiveAccess,proofApplicability,assessPath,assessHost,assessEngagement};
});
