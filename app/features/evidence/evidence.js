(function(root,factory){
  const api=factory();
  if(typeof module==="object"&&module.exports)module.exports=api;
  if(root)root.AEROSEvidence=api;
})(typeof window!=="undefined"?window:globalThis,function(){
  "use strict";

  const FIELD_IDS=[
    "evidenceName","evidenceSeverity","evidenceProofValue","evidenceImage",
    "evidenceLootPath","evidenceCredentials","evidenceCredentialContext",
    "evidenceSourceHost","evidenceTargetHost","evidenceMethod",
    "evidenceCredentialUsed","evidenceExplanation","evidenceFix","evidenceNotes",
    "evidenceRelatedAttempt","evidenceDistinctSupporting"
  ];
  const FIELD_PROFILES={
    local:["evidenceProofValue","evidenceImage","evidenceNotes"],
    proof:["evidenceProofValue","evidenceImage","evidenceNotes"],
    initial_access:["evidenceName","evidenceSeverity","evidenceImage","evidenceExplanation","evidenceFix","evidenceNotes","evidenceRelatedAttempt","evidenceDistinctSupporting"],
    privilege_escalation:["evidenceName","evidenceSeverity","evidenceImage","evidenceExplanation","evidenceFix","evidenceNotes","evidenceRelatedAttempt","evidenceDistinctSupporting"],
    post_exploitation:["evidenceName","evidenceImage","evidenceLootPath","evidenceCredentials","evidenceCredentialContext","evidenceNotes"],
    credential_dump:["evidenceName","evidenceImage","evidenceLootPath","evidenceCredentials","evidenceCredentialContext","evidenceNotes"],
    lateral_movement:["evidenceName","evidenceImage","evidenceSourceHost","evidenceTargetHost","evidenceMethod","evidenceCredentialUsed","evidenceCredentialContext","evidenceNotes","evidenceRelatedAttempt","evidenceDistinctSupporting"],
    service:["evidenceName","evidenceSeverity","evidenceProofValue","evidenceImage","evidenceExplanation","evidenceNotes"],
    custom:["evidenceName","evidenceSeverity","evidenceProofValue","evidenceImage","evidenceLootPath","evidenceCredentials","evidenceCredentialContext","evidenceSourceHost","evidenceTargetHost","evidenceMethod","evidenceCredentialUsed","evidenceExplanation","evidenceFix","evidenceNotes"]
  };

  function requireDependencies(dependencies){
    const required=[
      "getState","byId","activeHost","ensureLabName","saveState","persistState","render",
      "saveLabState","confirmDelete","alertUser","fetch","createFormData","createElement",
      "setFormValue","formValue","clearFormValue","escapeHtml","escapeAttr",
      "renderBacktickGlow","newId","importOutcomeLabel","scrollToTop"
    ];
    const missing=required.filter(name=>typeof dependencies?.[name]!=="function");
    if(missing.length)throw new Error(`AEROS evidence dependencies are unavailable: ${missing.join(", ")}`);
  }

  function profileFor(type){
    return [...(FIELD_PROFILES[String(type||"custom")]||FIELD_PROFILES.custom)];
  }
  function imageSource(evidence){
    if(!evidence)return "";
    if(evidence.imageDataUrl)return evidence.imageDataUrl;
    if(evidence.screenshotAbsPath)return `/api/serve-file?path=${encodeURIComponent(evidence.screenshotAbsPath)}`;
    return "";
  }
  function reportStageForEvidence(type){
    if(type==="initial_access")return "initial-access";
    if(type==="privilege_escalation")return "privilege-escalation";
    if(type==="lateral_movement")return "lateral-movement";
    return "";
  }
  function canonicalManaged(host,evidence,options={}){
    const stage=reportStageForEvidence(evidence?.type);
    return !!stage&&options.findingsApi?.canonicalStageManaged?.(options.state||{},host?.id,stage)===true;
  }
  function applyToHost(host,evidence,options={}){
    if(!host||!evidence)return host;
    if(evidence.type==="local"){host.hasShell=true;if(evidence.proofValue)host.localProof=evidence.proofValue;}
    if(evidence.type==="proof"){host.hasShell=true;host.isRootAdmin=true;if(evidence.proofValue)host.proofTxt=evidence.proofValue;}
    if(evidence.type==="credential_dump")host.hasCreds=true;
    if(evidence.type==="lateral_movement"){host.hasShell=true;if(evidence.credentialUsed||evidence.credentials)host.hasCreds=true;}
    if(evidence.type==="initial_access"&&!canonicalManaged(host,evidence,options)){
      if(evidence.title&&!host.findingTitle)host.findingTitle=evidence.title;
      if(evidence.explanation&&!host.vulnExplanation)host.vulnExplanation=evidence.explanation;
      if(evidence.fix&&!host.vulnFix)host.vulnFix=evidence.fix;
    }
    if(evidence.type==="privilege_escalation"&&!canonicalManaged(host,evidence,options)&&evidence.title&&!host.privescTitle)host.privescTitle=evidence.title;
    return host;
  }

  function createEvidence(dependencies){
    requireDependencies(dependencies);
    let editingId=null;
    const state=()=>dependencies.getState();
    const value=id=>String(dependencies.byId(id)?.value||"").trim();

    function setFieldVisible(id,visible){
      const element=dependencies.byId(id);if(!element)return;
      const holder=element.closest?.("label")||element.parentElement;
      holder?.classList?.toggle("hidden",!visible);
    }
    function stageEvidenceType(type){return ["initial_access","privilege_escalation","lateral_movement"].includes(String(type||""));}
    function generatedEvidenceFor(host,attemptId){
      return (host?.evidence||[]).find(row=>row?.active!==false&&row?.sourceExploitAttemptId===attemptId&&row?.sourceRole==="report-step")||null;
    }
    function updateRelatedInvestigation(){
      const host=dependencies.activeHost(),select=dependencies.byId("evidenceRelatedAttempt"),status=dependencies.byId("evidenceRelatedAttemptStatus"),type=dependencies.byId("evidenceType")?.value||"custom";
      const visible=stageEvidenceType(type);setFieldVisible("evidenceRelatedAttempt",visible);setFieldVisible("evidenceDistinctSupporting",visible);
      if(!select||!status)return null;
      const selected=select.value;select.innerHTML='<option value="">None / standalone evidence</option>';
      (host?.exploitAttempts||[]).forEach(attempt=>{const option=dependencies.createElement("option");option.value=attempt.id;option.textContent=`${attempt.title||"Investigation"} · ${attempt.status||"lead"}`;select.appendChild(option);});
      select.value=[...select.options].some(option=>option.value===selected)?selected:"";
      const generated=select.value?generatedEvidenceFor(host,select.value):null;
      status.className=`evidence-related-status${generated?" warning":" hidden"}`;
      status.innerHTML=generated?`Generated evidence already exists: <strong>${dependencies.escapeHtml(generated.title||"Linked evidence")}</strong>. <button class="secondary-btn small" type="button" data-open-related-attempt="${dependencies.escapeAttr(select.value)}">Open Investigation</button>`:"";
      status.querySelector?.("[data-open-related-attempt]")?.addEventListener("click",()=>dependencies.openAttempt?.(select.value));
      return generated;
    }
    function updateFormVisibility(){
      const type=dependencies.byId("evidenceType")?.value,visible=new Set(profileFor(type));
      if(canonicalManaged(dependencies.activeHost(),{type},{state:state(),findingsApi:dependencies.findingsApi})){
        ["evidenceSeverity","evidenceExplanation","evidenceFix"].forEach(id=>visible.delete(id));
      }
      FIELD_IDS.forEach(id=>setFieldVisible(id,visible.has(id)));
      updateRelatedInvestigation();
      return visible;
    }
    function updateGuidance(){
      const host=dependencies.activeHost(),guidance=dependencies.byId("evidenceGuidance");if(!host||!guidance)return;
      const type=dependencies.byId("evidenceType")?.value||"custom",os=host.os;
      const proofFile=type==="proof"?"proof.txt":"local.txt";
      let command="",need="";
      if(type==="local"||type==="proof"){
        if(os==="windows")command=`whoami && ipconfig && type ${proofFile}`;
        else if(os==="linux")command=`whoami && ifconfig && cat ${proofFile}\n# If ifconfig is missing: whoami && ip a && cat ${proofFile}`;
        else command=`Windows: whoami && ipconfig && type ${proofFile}\nLinux: whoami && ifconfig && cat ${proofFile}`;
        need=`Screenshot should clearly show:\n- current user / privilege context\n- IP configuration\n- ${proofFile} value\n- enough terminal context to prove the host`;
      }else if(type==="initial_access"){
        need="Screenshot should show the exploit path or vulnerability proof: vulnerable page/share/service, command output, successful login, shell callback, or RCE proof. Evidence Name is required.";
        command="Examples:\n- SMB share listing + sensitive file\n- web login as discovered user\n- reverse shell callback\n- command output proving RCE";
      }else if(type==="privilege_escalation"){
        need="Screenshot should show the privilege escalation finding and/or the elevated shell. Evidence Name is required.";
        command="Examples:\nWindows: whoami /priv, whoami, ipconfig, type proof.txt\nLinux: id, sudo -l, whoami, ifconfig, cat proof.txt";
      }else if(type==="service"){
        need="Screenshot should show the service result you want in the report: web page, ffuf result, smb share listing, SQL output, etc. Evidence Name is required.";
        command="Include target IP/URL/port in the screenshot when possible.";
      }else{
        need="Screenshot should prove the specific item you want inserted into the report. Evidence Name is required.";
        command="Add context in Evidence Notes so the report section makes sense later.";
      }
      guidance.innerHTML=`<strong>Upload reminder</strong><br>${dependencies.escapeHtml(need).replaceAll("\n","<br>")}<code>${dependencies.escapeHtml(command)}</code>`;
    }
    function showForm(show=true){
      dependencies.byId("evidenceForm")?.classList?.toggle("hidden",!show);
      if(show){updateFormVisibility();updateGuidance();}
    }

    function renderList(host){
      const list=dependencies.byId("evidenceList");if(!list)return;
      const items=host?.evidence||[];
      if(!items.length){list.innerHTML='<div class="host-meta">No posted evidence yet. Click + Add Evidence to post proof, findings, screenshots, loot, credentials, or movement evidence.</div>';return;}
      list.innerHTML="";
      items.slice().reverse().forEach(evidence=>{
        const card=dependencies.createElement("div");
        card.className="evidence-item sys-entry-card";
        const detailId=`evidenceDetails_${dependencies.escapeAttr(evidence.id||dependencies.newId("ev"))}`;
        const title=evidence.title||evidence.type||"Evidence",type=evidence.type||"custom",src=imageSource(evidence);
        const summary=[];
        if(evidence.proofFile||evidence.proofValue)summary.push(`${evidence.proofFile||""}${evidence.proofValue?" · "+evidence.proofValue:""}`);
        if(evidence.screenshotRelPath)summary.push(`Screenshot: ${evidence.screenshotRelPath}`);
        if(evidence.screenshotImportOutcome)summary.push(`${dependencies.importOutcomeLabel({importOutcome:evidence.screenshotImportOutcome})} · revision ${Number(evidence.screenshotCurrentRevision)||1} of ${Math.max(1,Number(evidence.screenshotRevisionCount)||1)}`);
        if(evidence.noteTargets?.length)summary.push(`Updated: ${evidence.noteTargets.join(", ")}`);
        const details=[];
        const add=(label,content,code=false)=>{if(content)details.push(`<div><strong>${label}</strong>${code?`<code>${dependencies.escapeHtml(content)}</code>`:`<span>${dependencies.escapeHtml(content)}</span>`}</div>`);};
        add("Severity",evidence.severity);add("Proof File",evidence.proofFile);add("Proof Value / Result",evidence.proofValue);
        add("Credential/File Path",evidence.lootPath);add("Source Host",evidence.sourceHost);add("Target Host",evidence.targetHost);
        add("Method / Protocol",evidence.method);add("Credential Used",evidence.credentialUsed);add("Screenshot Path",evidence.screenshotRelPath);
        add("Screenshot SHA-256",evidence.screenshotSha256,true);
        if(evidence.screenshotRevisionCount)add("Screenshot Revisions",`${Number(evidence.screenshotCurrentRevision)||1} of ${Math.max(1,Number(evidence.screenshotRevisionCount)||1)}`);
        if(evidence.noteTargets?.length)add("Updated Files",evidence.noteTargets.join("\n"));
        const section=(label,content)=>String(content||"").trim()?`<div class="cred-expanded-section"><strong>${label}</strong><div class="sys-note-block">${dependencies.renderBacktickGlow(String(content).trim())}</div></div>`:"";
        card.innerHTML=`<div class="entry-head evidence-entry-head"><strong>${dependencies.escapeHtml(title)}</strong><span>${dependencies.escapeHtml(type)}</span></div>
          ${summary.length?`<div class="host-meta evidence-summary">${dependencies.escapeHtml(summary.join(" | "))}</div>`:""}
          <div id="${detailId}" class="hidden evidence-expanded">
            ${src?`<div class="cred-expanded-section"><strong>Screenshot / Image</strong><div class="cred-image-wrap evidence-image-wrap"><img src="${dependencies.escapeAttr(src)}" alt="${dependencies.escapeAttr(title)} screenshot"></div></div>`:""}
            ${details.length?`<div class="cred-detail-grid evidence-detail-grid">${details.join("")}</div>`:""}
            ${section("Credentials Found",evidence.credentials)}
            ${section("Credential Context / Reuse Notes",evidence.credentialContext)}
            ${section("Vulnerability Explanation",evidence.explanation)}
            ${section("Vulnerability Fix",evidence.fix)}
            ${section("Steps / Evidence Notes",evidence.notes)}
          </div>
          <div class="row-actions evidence-card-actions">
            <button class="secondary-btn small" data-toggle-evidence="${detailId}">Expand Full Evidence</button>
            <button class="secondary-btn small edit-evidence-btn" data-evidence-id="${dependencies.escapeAttr(evidence.id||"")}">Edit</button>
            <button class="danger-btn small" data-delete-evidence="${dependencies.escapeAttr(evidence.id||"")}">Delete</button>
          </div>`;
        list.appendChild(card);
      });
      list.querySelectorAll("[data-toggle-evidence]").forEach(button=>button.onclick=()=>{
        const target=dependencies.byId(button.dataset.toggleEvidence);if(!target)return;
        target.classList.toggle("hidden");button.textContent=target.classList.contains("hidden")?"Expand Full Evidence":"Collapse Full Evidence";
      });
      list.querySelectorAll(".edit-evidence-btn").forEach(button=>button.onclick=()=>edit(button.dataset.evidenceId));
      list.querySelectorAll("[data-delete-evidence]").forEach(button=>button.onclick=()=>remove(button.dataset.deleteEvidence));
    }

    async function remove(id){
      const host=dependencies.activeHost();if(!host)return false;
      const evidence=(host.evidence||[]).find(item=>item.id===id);if(!evidence)return false;
      const owners=(state().findings||[]).filter(finding=>!dependencies.findingsApi?.findingDeleted?.(finding)&&
        ((finding.evidenceRefs||[]).some(ref=>ref.assetId===host.id&&ref.evidenceId===id)||
          (!(finding.evidenceRefs||[]).length&&(finding.assetIds||[]).length===1&&
            finding.assetIds[0]===host.id&&(finding.evidenceIds||[]).includes(id))));
      if(owners.length){
        dependencies.alertUser(`Evidence cannot be deleted because it is referenced by Finding: ${owners.map(row=>row.title||row.id).join(", ")}. Unlink it from the Finding first.`);
        return false;
      }
      const title=evidence.title||evidence.type||"this evidence";
      if(!(await dependencies.confirmDelete(`Delete evidence entry "${title}" from the app state?\n\nGenerated note files or screenshot files already written to disk will not be deleted.`,{title:"Delete Evidence",confirmText:"Delete",danger:true})))return false;
      const snapshot=JSON.parse(JSON.stringify(host.evidence||[]));
      host.evidence=(host.evidence||[]).filter(item=>item.id!==id);
      if(editingId===id)clearForm();
      dependencies.saveState();renderList(host);
      try{await dependencies.saveLabState(true);}catch(error){
        host.evidence=snapshot;dependencies.saveState();renderList(host);
        dependencies.alertUser(`SQLite save failed, so the evidence deletion was rolled back: ${error.message}`);
        return false;
      }
      return true;
    }
    function edit(id){
      const host=dependencies.activeHost(),evidence=(host?.evidence||[]).find(item=>item.id===id);if(!evidence)return false;
      editingId=id;
      const direct={evidenceType:evidence.type||"custom",evidenceName:evidence.title||"",evidenceSeverity:evidence.severity||"",evidenceProofValue:evidence.proofValue||"",evidenceExplanation:evidence.explanation||"",evidenceFix:evidence.fix||"",evidenceNotes:evidence.notes||""};
      Object.entries(direct).forEach(([field,content])=>{const element=dependencies.byId(field);if(element)element.value=content;});
      [["evidenceLootPath","lootPath"],["evidenceCredentials","credentials"],["evidenceCredentialContext","credentialContext"],["evidenceSourceHost","sourceHost"],["evidenceTargetHost","targetHost"],["evidenceMethod","method"],["evidenceCredentialUsed","credentialUsed"]].forEach(([field,key])=>dependencies.setFormValue(field,evidence[key]||""));
      dependencies.setFormValue("evidenceRelatedAttempt",evidence.relatedExploitAttemptId||"");if(dependencies.byId("evidenceDistinctSupporting"))dependencies.byId("evidenceDistinctSupporting").checked=evidence.supportingEvidence===true;
      const image=dependencies.byId("evidenceImage");if(image)image.value="";
      const button=dependencies.byId("postEvidenceBtn");if(button)button.textContent="Update Evidence";
      showForm(true);dependencies.scrollToTop();return true;
    }
    function draft(host,type,existing={}){
      let title=value("evidenceName");
      if(type==="local")title=title||"local.txt proof";
      if(type==="proof")title=title||"proof.txt proof";
      if(type==="credential_dump")title=title||"Credentials Found";
      if(type==="lateral_movement")title=title||"Lateral Movement";
      return {...existing,type,title,proofValue:value("evidenceProofValue"),severity:dependencies.byId("evidenceSeverity")?.value||"",explanation:value("evidenceExplanation"),fix:value("evidenceFix"),notes:value("evidenceNotes"),lootPath:dependencies.formValue("evidenceLootPath"),credentials:dependencies.formValue("evidenceCredentials"),credentialContext:dependencies.formValue("evidenceCredentialContext"),sourceHost:dependencies.formValue("evidenceSourceHost"),targetHost:dependencies.formValue("evidenceTargetHost"),method:dependencies.formValue("evidenceMethod"),credentialUsed:dependencies.formValue("evidenceCredentialUsed"),relatedExploitAttemptId:stageEvidenceType(type)?dependencies.formValue("evidenceRelatedAttempt"):"",supportingEvidence:dependencies.byId("evidenceDistinctSupporting")?.checked===true,proofFile:type==="local"?"local.txt":type==="proof"?"proof.txt":""};
    }
    async function post(){
      dependencies.saveState();
      const lab=dependencies.ensureLabName(),host=dependencies.activeHost();
      if(!host){dependencies.alertUser("Select a host first.");return false;}
      if(!state().serverAvailable){dependencies.alertUser("Run python server.py first.");return false;}
      if(!lab){dependencies.alertUser("Enter or load a Lab / Engagement Name first.");return false;}
      state().projectName=lab;dependencies.persistState();
      const type=dependencies.byId("evidenceType")?.value||"custom";
      const requiresName=["initial_access","privilege_escalation","post_exploitation","service","custom"].includes(type);
      const existing=editingId?(host.evidence||[]).find(item=>item.id===editingId):null;
      const evidence=draft(host,type,existing||{});evidence.id=evidence.id||editingId;
      if(requiresName&&!evidence.title){dependencies.alertUser("Finding Title / Evidence Name is required for this evidence type.");return false;}
      const generated=evidence.relatedExploitAttemptId?generatedEvidenceFor(host,evidence.relatedExploitAttemptId):null;
      if(!editingId&&generated&&!evidence.supportingEvidence){dependencies.alertUser("This investigation already has generated stage evidence. Open the linked investigation/evidence, or explicitly mark this as distinct supporting evidence.");updateRelatedInvestigation();return false;}
      const file=dependencies.byId("evidenceImage")?.files?.[0]||null,wasEditing=!!editingId;
      if(editingId&&!file){
        evidence.updatedAt=new Date().toISOString();
        const index=(host.evidence||[]).findIndex(item=>item.id===editingId);if(index>=0)host.evidence[index]=evidence;
        applyToHost(host,evidence,{state:state(),findingsApi:dependencies.findingsApi});dependencies.saveState();dependencies.render();clearForm();
        try{await dependencies.saveLabState(true);}catch(error){}
        dependencies.alertUser("Evidence updated in saved state and Word report data.");return true;
      }
      const form=dependencies.createFormData();
      form.append("labName",state().projectName);form.append("host",JSON.stringify(host));form.append("evidence",JSON.stringify(evidence));if(file)form.append("screenshot",file);
      try{
        const response=await dependencies.fetch("/api/post-evidence",{method:"POST",body:form}),data=await response.json();
        if(!response.ok||!data.ok)throw new Error(data.error||"Unknown error");
        if(!host.evidence)host.evidence=[];
        const index=editingId?host.evidence.findIndex(item=>item.id===editingId):-1;
        if(index>=0)host.evidence[index]=data.evidence;else host.evidence.push(data.evidence);
        applyToHost(host,data.evidence,{state:state(),findingsApi:dependencies.findingsApi});dependencies.saveState();dependencies.render();clearForm();
        try{await dependencies.saveLabState(true);}catch(error){}
        dependencies.alertUser(`${wasEditing?"Evidence updated":"Evidence saved"} internally.${data.evidence?.screenshotImportOutcome?` ${dependencies.importOutcomeLabel({importOutcome:data.evidence.screenshotImportOutcome})}.`:""}`);
        return true;
      }catch(error){dependencies.alertUser(`Evidence post failed: ${error.message}`);return false;}
    }
    function clearForm(){
      editingId=null;
      const button=dependencies.byId("postEvidenceBtn");if(button)button.textContent="Post Evidence";
      ["evidenceName","evidenceSeverity","evidenceProofValue","evidenceExplanation","evidenceFix","evidenceNotes","evidenceImage"].forEach(id=>{const element=dependencies.byId(id);if(element)element.value="";});
      ["evidenceLootPath","evidenceCredentials","evidenceCredentialContext","evidenceSourceHost","evidenceTargetHost","evidenceMethod","evidenceCredentialUsed","evidenceRelatedAttempt"].forEach(dependencies.clearFormValue);
      if(dependencies.byId("evidenceDistinctSupporting"))dependencies.byId("evidenceDistinctSupporting").checked=false;
      updateFormVisibility();updateGuidance();showForm(false);
    }

    return Object.freeze({profileFor,imageSource,applyToHost,stageEvidenceType,generatedEvidenceFor,editingId:()=>editingId,showForm,setFieldVisible,updateFormVisibility,updateRelatedInvestigation,updateGuidance,renderList,remove,edit,post,clearForm});
  }

  return Object.freeze({FIELD_IDS:Object.freeze([...FIELD_IDS]),FIELD_PROFILES:Object.freeze({...FIELD_PROFILES}),profileFor,imageSource,reportStageForEvidence,canonicalManaged,applyToHost,create:createEvidence});
});
