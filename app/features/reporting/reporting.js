(function(root,factory){
  const api=factory();
  if(typeof module==="object"&&module.exports)module.exports=api;
  if(root)root.AEROSReporting=api;
})(typeof window!=="undefined"?window:globalThis,function(){
  "use strict";

  function requireDependencies(dependencies){
    const required=[
      "getState","byId","createOption","ensureEngagementConfig","persistState","saveState",
      "ensureLabName","activeLabName","safeFile","escapeHtml","escapeAttr","nl2br",
      "versionedRecordBadge","importOutcomeLabel","showToast","confirmDelete","alertUser",
      "fetch","createFormData","createBlob","downloadBlob","renderStartingAccess"
    ];
    const missing=required.filter(name=>typeof dependencies?.[name]!=="function");
    if(missing.length)throw new Error(`AEROS reporting dependencies are unavailable: ${missing.join(", ")}`);
  }

  function attackPathText(host){
    const manual=String(host?.attackPath||"").trim();
    const generated=(host?.attackPathSteps||[]).filter(step=>step&&step.active!==false)
      .sort((a,b)=>String(a.createdAt||"").localeCompare(String(b.createdAt||"")))
      .map(step=>String(step.summary||"").trim()).filter(Boolean);
    return [manual,...generated].filter(Boolean).join("\n\n");
  }
  function osReportFacts(host){
    const resolution=host?.osResolution&&typeof host.osResolution==="object"?host.osResolution:{};
    const status=String(resolution.status||"").trim().toLowerCase();
    const family=String(resolution.family||host?.os||"unknown").trim().toLowerCase()||"unknown";
    const label=status==="conflict"?"Conflict":family==="unknown"?"Unknown":family.replace(/\b\w/g,char=>char.toUpperCase());
    const confidence=String(resolution.confidence||((family==="unknown")?"Unknown":"Recorded")).trim();
    const sources=Array.isArray(resolution.sourceLabels)?resolution.sourceLabels.map(value=>String(value||"").trim()).filter(Boolean):[];
    return {label,confidence,sources,status};
  }
  function hostAssetId(key,host){return String(host?.id||key||"").trim();}
  function urlPathLabel(url,path){
    const address=String(url||"").trim(),suffix=String(path||"").trim();
    if(!address)return suffix;
    if(!suffix)return address;
    try{if(new URL(address,"http://aeros.invalid").pathname===suffix)return address;}catch{}
    return address.endsWith(suffix)?address:`${address} ${suffix}`;
  }
  function placementError(validation){
    const first=validation?.issues?.[0]||{};
    const scope=[first.assetId?`asset ${first.assetId}`:"",first.stage?`stage ${first.stage}`:""].filter(Boolean).join(", ");
    return `Canonical Finding is invalid${scope?` for ${scope}`:""}: ${first.message||"review the Finding references and placements"}`;
  }
  function validateForRender(state,findingsApi,requiredPrimaryResolver){
    const hasPlacements=(state?.findings||[]).some(finding=>(finding?.reportPlacements||[]).length);
    if(!hasPlacements)return {valid:true,legacyOnly:true,issues:[]};
    const validator=findingsApi?.validateCanonicalFindings||findingsApi?.validateReportPlacements;
    if(!validator)throw new Error("Canonical Finding validator is unavailable.");
    const validation=typeof requiredPrimaryResolver==="function"?
      validator(state,{requiredPrimary:requiredPrimaryResolver(state)}):validator(state);
    if(!validation.valid)throw new Error(placementError(validation));
    return validation;
  }
  function findingBodyHtml(state,finding,placement,helpers){
    const {escapeHtml,nl2br,findingsApi}=helpers;
    const detail=(label,value)=>String(value||"").trim()?`<h5>${escapeHtml(label)}</h5><p>${nl2br(escapeHtml(value))}</p>`:"";
    const endpoint=finding.endpoint||{},host=findingsApi?.hostForAsset?.(state,placement.assetId)||{};
    const affected=[
      ["Asset",[host.ip,host.hostname].filter(Boolean).join(" / ")||placement.assetId],
      ["Port / Service",[endpoint.port?`${endpoint.port}/${String(endpoint.protocol||"tcp").toUpperCase()}`:"",endpoint.service].filter(Boolean).join(" · ")],
      ["URL / Path",urlPathLabel(endpoint.url,endpoint.path)],
      ["Method",endpoint.httpMethod],["Parameter / Input",endpoint.parameter],
      ["Product / Version",[endpoint.product,endpoint.version].filter(Boolean).join(" ")],
      ["Identifiers",[finding.cve,finding.cwe,finding.identifier].filter(Boolean).join(" · ")]
    ].filter(([,value])=>String(value||"").trim());
    const affectedHtml=affected.length?`<h5>Affected Location</h5><dl>${affected.map(([label,value])=>`<dt>${escapeHtml(label)}</dt><dd>${escapeHtml(value)}</dd>`).join("")}</dl>`:"";
    const reproduction=findingsApi?.resolveFindingReproduction?.(state,finding)||[];
    const reproductionHtml=reproduction.length?`<h5>Steps to Reproduce</h5>${reproduction.map((row,index)=>`<section class="reproduction-activity"><strong>Activity ${index+1}</strong><pre><code>${escapeHtml(row.body)}</code></pre>${row.reportAddendum?`<p>${nl2br(escapeHtml(row.reportAddendum))}</p>`:""}</section>`).join("")}`:"";
    const evidence=findingsApi?.resolveFindingEvidence?.(state,finding)||[];
    const evidenceHtml=evidence.length?`<h5>Supporting Evidence</h5><ul>${evidence.map(row=>`<li>${escapeHtml(row.evidence.title||row.evidence.proofFile||row.evidence.id)}${row.evidence.proofValue?` — ${escapeHtml(row.evidence.proofValue)}`:""}</li>`).join("")}</ul>`:"";
    return `<article class="finding finding-${escapeHtml(placement.role)}"><h4>${escapeHtml(finding.title)}</h4><p><span class="pill">${escapeHtml(finding.severity||"not-assessed")}</span><span class="pill">${escapeHtml(placement.role)}</span></p>${affectedHtml}${detail("Summary",finding.summary)}${detail("Root Cause",finding.rootCause)}${detail("Technical Description",finding.description)}${detail("Impact",finding.impact)}${detail("Report Note",finding.reportNarrative)}${reproductionHtml}${evidenceHtml}${detail("Remediation",finding.remediation||finding.fix)}${detail("References",finding.references)}</article>`;
  }
  function legacyInitialHtml(host,helpers){
    const {escapeHtml,nl2br}=helpers;
    return `<h3>${escapeHtml(host.findingTitle||"Finding TBD")}</h3><p>${nl2br(escapeHtml(host.vulnExplanation||"TBD"))}</p><h3>Steps to Reproduce</h3><p>${nl2br(escapeHtml(attackPathText(host)||"TBD"))}</p>`;
  }
  function buildHtml(state,helpers={}){
    const escapeHtml=helpers.escapeHtml||function(value){return String(value??"").replace(/[&<>"']/g,char=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[char]));};
    const nl2br=helpers.nl2br||function(value){return String(value||"").replace(/\n/g,"<br>");};
    const css=String(helpers.reportCss||""),hosts=Object.entries(state?.hosts||{});
    const findingsApi=helpers.findingsApi||(typeof globalThis!=="undefined"?globalThis.AEROSFindings:null);
    validateForRender(state,findingsApi,helpers.requiredPrimaryPlacements);
    const stageLabels=findingsApi?.REPORT_STAGE_LABELS||{};
    const stageOrder=findingsApi?.REPORT_STAGES||["initial-access","privilege-escalation","lateral-movement","other"];
    const hostSections=hosts.map(([key,host])=>{
      const assetId=hostAssetId(key,host),canonicalStages=stageOrder.filter(stage=>findingsApi?.canonicalStageManaged?.(state,assetId,stage));
      const canonical=canonicalStages.length>0;
      const os=osReportFacts(host);
      const findingsHtml=stageOrder.map(stage=>{
        if(!findingsApi?.canonicalStageManaged?.(state,assetId,stage)){
          return stage==="initial-access"?legacyInitialHtml(host,{escapeHtml,nl2br}):"";
        }
        const rows=findingsApi.orderedForAssetStage(state,assetId,stage);
        const main=rows.filter(row=>row.placement.role!=="supporting");
        const supporting=rows.filter(row=>row.placement.role==="supporting");
        if(!main.length&&!supporting.length)return "";
        const findingHelpers={escapeHtml,nl2br,findingsApi};
        return `<section class="finding-stage"><h3>${escapeHtml(stageLabels[stage]||stage)}</h3>${main.map(row=>findingBodyHtml(state,row.finding,row.placement,findingHelpers)).join("")}${supporting.length?`<aside class="supporting-findings"><h4>Supporting Findings</h4>${supporting.map(row=>findingBodyHtml(state,row.finding,row.placement,findingHelpers)).join("")}</aside>`:""}</section>`;
      }).join("");
      return `<section class="host"><h2>${escapeHtml(host.ip)} ${host.hostname?`- ${escapeHtml(host.hostname)}`:""}</h2><p><span class="pill">OS: ${escapeHtml(os.label)}</span><span class="pill">OS confidence: ${escapeHtml(os.confidence)}</span><span class="pill">Status: ${escapeHtml(host.status)}</span>${canonical?"":`<span class="pill">Severity: ${escapeHtml(host.severity||"TBD")}</span>`}</p>${os.sources.length?`<p><strong>OS sources:</strong> ${escapeHtml(os.sources.join(" · "))}</p>`:""}${findingsHtml}<h3>Post-Exploitation / Proof</h3><p><strong>local.txt:</strong> ${escapeHtml(host.localProof||"TBD")}<br><strong>proof.txt:</strong> ${escapeHtml(host.proofTxt||"TBD")}</p><p>${nl2br(escapeHtml(host.reportNotes||"TBD"))}</p></section>`;
    }).join("");
    return `<!DOCTYPE html><html><head><title>${escapeHtml(state?.projectName||"Report")}</title><style>${css}</style></head><body><main class="report"><button class="no-print" onclick="window.print()" style="position:fixed;right:24px;top:20px;padding:10px 14px">Print / Save PDF</button><h1>${escapeHtml(state?.projectName||"OSCP Report")}</h1><div class="meta"><div><strong>Tester:</strong> ${escapeHtml(state?.testerName||"")}</div><div><strong>Email:</strong> ${escapeHtml(state?.studentEmail||"")}</div><div><strong>OSID:</strong> ${escapeHtml(state?.osid||"")}</div><div><strong>Hosts:</strong> ${hosts.length}</div></div><h2>High-Level Summary</h2><p>TBD</p><h2>Methodology</h2><p>Information gathering, service enumeration, exploitation, privilege escalation, post-exploitation, and cleanup.</p><h2>Targets</h2>${hostSections}</main></body></html>`;
  }

  function createReporting(dependencies){
    requireDependencies(dependencies);
    let templates={templates:[],defaultTemplateId:"",storagePath:""};
    const state=()=>dependencies.getState();
    const templateName=id=>templates.templates.find(template=>template.id===id)?.displayName||"";

    function fillTemplateSelect(select,includeDefault=true){
      if(!select)return;
      const previous=select.value;select.innerHTML="";
      if(includeDefault){const option=dependencies.createOption();option.value="";option.textContent="Use Global Default";select.appendChild(option);}
      templates.templates.forEach(template=>{const option=dependencies.createOption();option.value=template.id;option.textContent=template.displayName;select.appendChild(option);});
      if([...select.options].some(option=>option.value===previous))select.value=previous;
    }
    function fillWizardTemplates(){
      const select=dependencies.byId("wizardReportTemplate");if(!select)return;
      const previous=select.value;select.innerHTML='<option value="default">Use Global Default</option>';
      templates.templates.forEach(template=>{const option=dependencies.createOption();option.value=`template:${template.id}`;option.textContent=template.displayName;select.appendChild(option);});
      const later=dependencies.createOption();later.value="later";later.textContent="Configure Later";select.appendChild(later);
      select.value=[...select.options].some(option=>option.value===previous)?previous:"default";
    }
    function renderTemplates(){
      fillTemplateSelect(dependencies.byId("optionReportTemplateSelect"),true);
      fillTemplateSelect(dependencies.byId("defaultReportTemplateSelect"),false);
      fillWizardTemplates();
      const config=dependencies.ensureEngagementConfig();
      if(dependencies.byId("optionReportTemplateSelect"))dependencies.byId("optionReportTemplateSelect").value=config.reporting.templateId||"";
      if(dependencies.byId("optionStartingAccessNotes"))dependencies.byId("optionStartingAccessNotes").value=config.startingAccess.notes||"";
      dependencies.renderStartingAccess();
      if(dependencies.byId("defaultReportTemplateSelect"))dependencies.byId("defaultReportTemplateSelect").value=templates.defaultTemplateId||"";
      const list=dependencies.byId("reportTemplateList");if(!list)return;
      if(!templates.templates.length){list.innerHTML='<div class="archive-empty">No report templates stored.</div>';return;}
      list.innerHTML=templates.templates.map(template=>`<article class="report-template-item"><div><h4>${dependencies.escapeHtml(template.displayName)}</h4><p>${dependencies.escapeHtml(template.originalFilename||template.filename)} · ${Math.max(1,Math.round((template.size||0)/1024))} KB</p><div class="report-template-badges">${template.id===templates.defaultTemplateId?'<span class="report-template-badge">Global Default</span>':""}${template.id===config.reporting.templateId?'<span class="report-template-badge">This Engagement</span>':""}${template.builtIn?'<span class="report-template-badge">Built In</span>':dependencies.versionedRecordBadge(template)}</div></div><div class="report-template-actions"><button class="ghost-btn" data-template-action="use" data-template-id="${dependencies.escapeAttr(template.id)}" type="button">Use</button><button class="ghost-btn" data-template-action="default" data-template-id="${dependencies.escapeAttr(template.id)}" type="button">Set Default</button><button class="ghost-btn" data-template-action="download" data-template-id="${dependencies.escapeAttr(template.id)}" type="button">Download</button>${template.builtIn?"":`<button class="danger-btn" data-template-action="delete" data-template-id="${dependencies.escapeAttr(template.id)}" type="button">Delete</button>`}</div></article>`).join("");
    }
    async function refreshTemplates(silent=false){
      if(!state().serverAvailable){if(!silent)dependencies.alertUser("Run python server.py first.");return false;}
      try{
        const response=await dependencies.fetch("/api/report-templates"),data=await response.json();
        if(!response.ok||!data.ok)throw new Error(data.error||"Could not load templates");
        templates={templates:data.templates||[],defaultTemplateId:data.defaultTemplateId||"",storagePath:data.storagePath||""};
        renderTemplates();
        if(dependencies.byId("reportTemplateStatus"))dependencies.byId("reportTemplateStatus").textContent=`Stored internally: ${templates.storagePath}`;
        return true;
      }catch(error){
        if(dependencies.byId("reportTemplateStatus"))dependencies.byId("reportTemplateStatus").textContent=`Template manager error: ${error.message}`;
        if(!silent)dependencies.alertUser(error.message);return false;
      }
    }
    async function uploadTemplate(){
      const file=dependencies.byId("reportTemplateFile")?.files?.[0];if(!file){dependencies.alertUser("Choose a DOCX template first.");return false;}
      const form=dependencies.createFormData();form.append("displayName",String(dependencies.byId("reportTemplateDisplayName")?.value||"").trim());form.append("template",file);
      try{
        const response=await dependencies.fetch("/api/upload-report-template",{method:"POST",body:form}),data=await response.json();
        if(!response.ok||!data.ok)throw new Error(data.error||"Upload failed");
        dependencies.byId("reportTemplateFile").value="";dependencies.byId("reportTemplateDisplayName").value="";
        if(dependencies.byId("reportTemplateFileName"))dependencies.byId("reportTemplateFileName").textContent="No file selected.";
        await refreshTemplates(true);dependencies.showToast(`${dependencies.importOutcomeLabel(data.template)} · ${data.template.originalFilename}`,"success");return true;
      }catch(error){dependencies.alertUser(`Could not upload template: ${error.message}`);return false;}
    }
    async function setDefaultTemplate(id){
      try{
        const response=await dependencies.fetch("/api/set-default-report-template",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({templateId:id})}),data=await response.json();
        if(!response.ok||!data.ok)throw new Error(data.error||"Could not set default");
        await refreshTemplates(true);return true;
      }catch(error){dependencies.alertUser(error.message);return false;}
    }
    async function deleteTemplate(id){
      const name=templateName(id);
      if(!(await dependencies.confirmDelete(`Delete report template "${name}"? Existing generated reports are not affected.`,{title:"Delete Report Template",confirmText:"Delete",danger:true})))return false;
      try{
        const response=await dependencies.fetch("/api/delete-report-template",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({templateId:id})}),data=await response.json();
        if(!response.ok||!data.ok)throw new Error(data.error||"Delete failed");
        const config=dependencies.ensureEngagementConfig();
        if(config.reporting.templateId===id){config.reporting.templateId="";config.reporting.templateMode="default";dependencies.persistState();}
        await refreshTemplates(true);return true;
      }catch(error){dependencies.alertUser(error.message);return false;}
    }
    async function downloadTemplate(id){
      try{
        const response=await dependencies.fetch(`/api/download-report-template?templateId=${encodeURIComponent(id)}`);
        if(!response.ok){const data=await response.json().catch(()=>({}));throw new Error(data.error||"Download failed");}
        dependencies.downloadBlob(await response.blob(),`${templateName(id)||"report-template"}.docx`,1000);return true;
      }catch(error){dependencies.alertUser(error.message);return false;}
    }
    async function handleTemplateAction(event){
      const button=event.target.closest("[data-template-action]");if(!button)return false;
      const id=button.dataset.templateId,action=button.dataset.templateAction;
      if(action==="use"){const config=dependencies.ensureEngagementConfig();config.reporting.templateId=id;config.reporting.templateMode="selected";dependencies.persistState();renderTemplates();return true;}
      if(action==="default")return setDefaultTemplate(id);
      if(action==="download")return downloadTemplate(id);
      if(action==="delete")return deleteTemplate(id);
      return false;
    }
    function guardCanonicalExport(){
      const current=state(),hasPlacements=(current?.findings||[]).some(finding=>(finding?.reportPlacements||[]).length);
      if(!hasPlacements)return true;
      const validator=dependencies.findingsApi?.validateCanonicalFindings||dependencies.validateReportPlacements;
      if(typeof validator!=="function"){
        dependencies.alertUser("Canonical Finding validation is unavailable. Report export was blocked.");
        return false;
      }
      const validation=typeof dependencies.requiredPrimaryPlacements==="function"?
        validator(current,{requiredPrimary:dependencies.requiredPrimaryPlacements(current)}):validator(current);
      if(validation.valid)return true;
      const first=validation.issues?.[0]||{};
      dependencies.alertUser(placementError(validation));
      dependencies.openPlacementIssue?.(first);
      return false;
    }
    async function wordReport(){
      dependencies.saveState();
      const lab=dependencies.ensureLabName();
      if(!state().serverAvailable){dependencies.alertUser("Run python server.py first.");return false;}
      if(!lab){dependencies.alertUser("Enter or load a Lab / Engagement Name first.");return false;}
      if(!guardCanonicalExport())return false;
      state().projectName=lab;dependencies.persistState();
      try{
        const response=await dependencies.fetch("/api/report-docx",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(state())});
        if(!response.ok){const data=await response.json().catch(()=>({error:"Unknown error"}));throw new Error(data.error);}
        dependencies.downloadBlob(await response.blob(),"OSCP-Exam-Report.docx",0);return true;
      }catch(error){dependencies.alertUser(`Word export failed: ${error.message}`);return false;}
    }
    function reportHtml(){return buildHtml(state(),{escapeHtml:dependencies.escapeHtml,nl2br:dependencies.nl2br,reportCss:dependencies.reportCss||"",findingsApi:dependencies.findingsApi});}
    function openHtmlReport(){
      dependencies.saveState();if(!guardCanonicalExport())return false;
      const frame=dependencies.byId("reportPreviewFrame"),modal=dependencies.byId("reportPreviewModal");
      try{if(frame)frame.srcdoc=reportHtml();modal?.classList?.remove("hidden");return true;}
      catch(error){dependencies.alertUser(error.message);return false;}
    }
    function closeHtmlReport(){dependencies.byId("reportPreviewModal")?.classList?.add("hidden");const frame=dependencies.byId("reportPreviewFrame");if(frame)frame.srcdoc="";}
    async function downloadHtmlReport(){
      if(!guardCanonicalExport())return false;
      const filename=`${dependencies.safeFile(dependencies.activeLabName()||state().projectName||"engagement")}-report.html`;
      let html;try{html=reportHtml();}catch(error){dependencies.alertUser(error.message);return false;}
      try{
        const response=await dependencies.fetch("/api/report-html",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({labName:dependencies.activeLabName(),html})});
        const result=await response.json();if(!response.ok||!result.ok)throw new Error(result.error||"Report save failed");
      }catch(error){dependencies.alertUser(`Could not save HTML report: ${error.message}`);return false;}
      dependencies.downloadBlob(dependencies.createBlob([html],{type:"text/html;charset=utf-8"}),filename,1000);
      dependencies.showToast("HTML report saved in the engagement reports folder and downloaded.","success");
      return true;
    }

    return Object.freeze({templateStore:()=>JSON.parse(JSON.stringify(templates)),templateName,fillTemplateSelect,fillWizardTemplates,renderTemplates,refreshTemplates,uploadTemplate,setDefaultTemplate,deleteTemplate,downloadTemplate,handleTemplateAction,guardCanonicalExport,wordReport,reportHtml,openHtmlReport,closeHtmlReport,downloadHtmlReport,attackPathText});
  }

  return Object.freeze({attackPathText,placementError,validateForRender,buildHtml,create:createReporting});
});
