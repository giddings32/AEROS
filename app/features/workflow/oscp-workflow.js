(function(root,factory){
  const api=factory();
  if(typeof module==="object"&&module.exports)module.exports=api;
  if(root)root.AerosOscpWorkflow=api;
})(typeof globalThis!=="undefined"?globalThis:this,function(){
  "use strict";

  const PROFILE_ID="oscp";
  const GENERAL_PROFILE_ID="generic";
  const NAVIGATOR_ROUTE="oscp-navigator";
  const DEFAULT_GENERAL_LANDING_ROUTE="host-profile";
  const STARTUP_ENGAGEMENT_LIMIT=200;
  const PREFS_VERSION=2;
  const OSCP_POLICY=Object.freeze({
    id:"offsec-oscp",
    version:"2026.1",
    source:"shipped-offline"
  });
  const OSCP_STARTING_ACCESS_TYPES=Object.freeze([
    "vpn","standard-credentials","privileged-credentials","ssh","rdp","web-account","internal-foothold"
  ]);
  const GENERAL_STARTING_ACCESS_TYPES=Object.freeze([
    ...OSCP_STARTING_ACCESS_TYPES,"source-code","architecture","asset-inventory"
  ]);
  const GENERAL_LANDING_ROUTES=Object.freeze(["host-profile","recon","exploitation-path","notes"]);
  const PREFLIGHT_ORDER=["server","persistence","template","referencePack","operatorOutput","staging","renderer","backup"];
  const BLOCKING_KEYS=new Set(["server","persistence"]);

  function clean(value){return String(value??"").trim();}
  function safeObject(value){return value&&typeof value==="object"&&!Array.isArray(value)?value:{};}
  function safeArray(value){return Array.isArray(value)?value:[];}
  function workflowProfileForAssessment(assessment={},options={}){
    const normalized=safeObject(assessment);
    const category=clean(normalized.category).toLowerCase();
    const type=clean(normalized.type).toLowerCase();
    if(type){
      return category==="certification-lab"&&type==="oscp"?PROFILE_ID:GENERAL_PROFILE_ID;
    }
    return clean(options.legacyEngagementType).toLowerCase()==="oscp"||
      clean(options.legacyProfileId).toLowerCase()===PROFILE_ID
      ?PROFILE_ID
      :GENERAL_PROFILE_ID;
  }
  function isOscpConfig(config={},options={}){
    const assessment=safeObject(config.assessment),workflow=safeObject(config.workflow);
    return workflowProfileForAssessment(assessment,{
      legacyEngagementType:options.legacyEngagementType,
      legacyProfileId:workflow.profileId
    })===PROFILE_ID;
  }
  function normalizeEngagementConfig(input={},options={}){
    const config={...safeObject(input)};
    const assessment={...safeObject(config.assessment)};
    const workflow={...safeObject(config.workflow)};
    const hasCanonicalAssessment=!!clean(assessment.type);
    const profileId=workflowProfileForAssessment(assessment,{
      legacyEngagementType:options.legacyEngagementType,
      legacyProfileId:workflow.profileId
    });
    if(profileId===PROFILE_ID){
      if(!hasCanonicalAssessment){
        assessment.category="certification-lab";
        assessment.type="oscp";
      }
      workflow.profileId=PROFILE_ID;
      workflow.landingPage=NAVIGATOR_ROUTE;
      workflow.startupPreflight=true;
      workflow.policy={...OSCP_POLICY};
      workflow.ownerProfile=clean(workflow.ownerProfile||options.profileName);
      workflow.dataRootFingerprint=clean(workflow.dataRootFingerprint||options.dataRootFingerprint);
    }else if(hasCanonicalAssessment){
      workflow.profileId=GENERAL_PROFILE_ID;
      workflow.startupPreflight=false;
    }
    config.assessment=assessment;
    config.workflow=workflow;
    return config;
  }
  function normalizeUserProfile(input={}){
    const profile={...safeObject(input)};
    const preferences={...safeObject(profile.workflowPreferences)};
    const legacyOscp={...safeObject(preferences.oscp)};
    const last={...safeObject(preferences.lastEngagement)};
    const migratedId=clean(last.engagementId||legacyOscp.engagementId);
    const migratedName=clean(last.engagementName||legacyOscp.engagementName||profile.lastProjectName);
    const migratedProfileId=clean(last.profileId||(legacyOscp.engagementId||legacyOscp.engagementName?"oscp":""));
    const {
      engagementId:_legacyEngagementId,
      engagementName:_legacyEngagementName,
      activeHostId:_legacyActiveHostId,
      dataRootFingerprint:_legacyDataRootFingerprint,
      updatedAt:_legacyUpdatedAt,
      ...oscpCompatibility
    }=legacyOscp;
    profile.workflowPreferences={
      ...preferences,
      version:PREFS_VERSION,
      lastEngagement:{
        engagementId:migratedId,
        engagementName:migratedName,
        profileId:migratedProfileId,
        assessmentType:clean(last.assessmentType),
        ownerProfile:clean(last.ownerProfile),
        activeHostId:clean(last.activeHostId||legacyOscp.activeHostId||profile.lastActiveHost),
        dataRootFingerprint:clean(last.dataRootFingerprint||legacyOscp.dataRootFingerprint),
        importStagingRoot:clean(last.importStagingRoot||legacyOscp.importStagingRoot),
        updatedAt:clean(last.updatedAt||legacyOscp.updatedAt)
      },
      oscp:{
        ...oscpCompatibility,
        importStagingRoot:clean(legacyOscp.importStagingRoot)
      }
    };
    return profile;
  }
  function engagementSummary(state={},fallbackName=""){
    const config=normalizeEngagementConfig(state.engagementConfig||{},{
      legacyEngagementType:state.engagementType
    });
    return {
      id:clean(state.projectId),
      name:clean(state.projectName||fallbackName),
      status:clean(config.identity?.status||state.status||"active").toLowerCase(),
      profileId:isOscpConfig(config)?PROFILE_ID:"generic",
      assessmentCategory:clean(config.assessment?.category),
      assessmentType:clean(config.assessment?.type),
      ownerProfile:clean(config.workflow?.ownerProfile),
      dataRootFingerprint:clean(config.workflow?.dataRootFingerprint),
      activeHostId:clean(state.activeHost),
      updatedAt:clean(state.updatedAt||state.updated_at)
    };
  }
  function profileLabel(summary={}){
    if(clean(summary.profileId).toLowerCase()===PROFILE_ID)return "OSCP";
    const assessmentType=clean(summary.assessmentType);
    if(!assessmentType||assessmentType.toLowerCase()==="general")return "General";
    return assessmentType.replace(/-/g," ").replace(/\b\w/g,letter=>letter.toUpperCase());
  }
  function normalizeSummary(summary={}){
    const row={...safeObject(summary)};
    row.id=clean(row.id);
    row.name=clean(row.name);
    row.status=clean(row.status||"active").toLowerCase();
    row.profileId=clean(row.profileId).toLowerCase()===PROFILE_ID?PROFILE_ID:GENERAL_PROFILE_ID;
    row.assessmentCategory=clean(row.assessmentCategory);
    row.assessmentType=clean(row.assessmentType);
    row.ownerProfile=clean(row.ownerProfile);
    row.dataRootFingerprint=clean(row.dataRootFingerprint);
    row.activeHostId=clean(row.activeHostId);
    row.updatedAt=clean(row.updatedAt);
    row.profileLabel=profileLabel(row);
    return row;
  }
  function selectLastValidEngagement({profileName="",dataRootFingerprint="",remembered={},summaries=[]}={}){
    const owner=clean(profileName),rootFingerprint=clean(dataRootFingerprint);
    const reference=safeObject(remembered);
    const rememberedId=clean(reference.engagementId);
    const rememberedName=clean(reference.engagementName);
    if(!rememberedId&&!rememberedName)return {engagement:null,reason:"no-remembered-engagement"};
    if(reference.dataRootFingerprint&&rootFingerprint&&clean(reference.dataRootFingerprint)!==rootFingerprint){
      return {engagement:null,reason:"data-root-mismatch"};
    }
    if(reference.ownerProfile&&owner&&clean(reference.ownerProfile)!==owner){
      return {engagement:null,reason:"profile-owner-mismatch"};
    }
    const selected=safeArray(summaries).map(normalizeSummary).find(row=>{
      if(row.status==="archived"||row.available===false)return false;
      if(rememberedId?row.id!==rememberedId:row.name.toLowerCase()!==rememberedName.toLowerCase())return false;
      if(reference.profileId&&row.profileId!==clean(reference.profileId).toLowerCase())return false;
      if(row.profileId===PROFILE_ID){
        if(owner&&row.ownerProfile&&row.ownerProfile!==owner)return false;
        if(rootFingerprint&&row.dataRootFingerprint&&row.dataRootFingerprint!==rootFingerprint)return false;
      }
      return true;
    });
    return selected?{engagement:selected,reason:"remembered"}:{engagement:null,reason:"stale-remembered-engagement"};
  }
  function startupEngagements(summaries=[]){
    return safeArray(summaries).map(normalizeSummary)
      .filter(row=>row.id&&row.name&&row.status!=="archived")
      .sort((a,b)=>clean(b.updatedAt).localeCompare(clean(a.updatedAt))||
        clean(a.name).localeCompare(clean(b.name)))
      .slice(0,STARTUP_ENGAGEMENT_LIMIT);
  }
  function rememberEngagement(profileInput={},summaryInput={},context={}){
    const profile=normalizeUserProfile(profileInput);
    const summary=normalizeSummary(summaryInput);
    profile.workflowPreferences.lastEngagement={
      engagementId:summary.id,
      engagementName:summary.name,
      profileId:summary.profileId,
      assessmentType:summary.assessmentType,
      ownerProfile:clean(context.profileName||summary.ownerProfile),
      activeHostId:clean(context.activeHostId||summary.activeHostId),
      dataRootFingerprint:clean(context.dataRootFingerprint||summary.dataRootFingerprint),
      importStagingRoot:clean(context.importStagingRoot),
      updatedAt:clean(context.updatedAt)||new Date().toISOString()
    };
    return profile;
  }
  function startingAccessTypesForAssessment(assessment={}){
    return workflowProfileForAssessment(assessment)===PROFILE_ID
      ?[...OSCP_STARTING_ACCESS_TYPES]
      :[...GENERAL_STARTING_ACCESS_TYPES];
  }
  function reconcileStartingAccessTypes(selected=[],assessment={}){
    const allowed=startingAccessTypesForAssessment(assessment),allowedSet=new Set(allowed);
    const unique=[...new Set(safeArray(selected).map(clean).filter(Boolean))];
    return {
      allowed,
      applicable:unique.filter(value=>allowedSet.has(value)),
      inapplicable:unique.filter(value=>!allowedSet.has(value))
    };
  }
  function landingRoutesForAssessment(assessment={}){
    return workflowProfileForAssessment(assessment)===PROFILE_ID
      ?[NAVIGATOR_ROUTE]
      :[...GENERAL_LANDING_ROUTES];
  }
  function parseCandidateCredentialLines(value){
    return clean(value).split(/\r?\n/).map((line,index)=>{
      if(!line.trim())return null;
      const fields=line.split("|").map(clean);
      if(fields.length<4||!fields[0]||!fields[1]||!fields[2]||!fields[3]){
        return {valid:false,line:index+1,error:"Use username | secret | exact source | intended scope | method."};
      }
      return {
        valid:true,
        line:index+1,
        entry:{
          id:"",
          type:"candidate-credential",
          classification:"candidate",
          name:`Candidate credential: ${fields[0]}`,
          username:fields[0],
          secret:fields[1],
          source:fields[2],
          intendedScope:fields[3],
          intendedMethod:fields[4]||"",
          target:"",
          hostId:"",
          privilege:"",
          active:true,
          verified:false,
          notes:"Candidate supplied during OSCP setup; verify before creating access context."
        }
      };
    }).filter(Boolean);
  }
  function rowState(fact,key){
    if(fact?.ready===true)return "Ready";
    return BLOCKING_KEYS.has(key)?"Blocking":"Warning";
  }
  function evaluatePreflight(raw={},options={}){
    const facts=safeObject(raw.checks),checkedAt=clean(raw.checkedAt||options.checkedAt)||new Date().toISOString();
    const labels={
      server:"Application and server identity",
      persistence:"SQLite persistence",
      template:"OSCP report template",
      referencePack:"Canonical Reference Pack",
      operatorOutput:"Operator Output Root",
      staging:"AEROS Import Staging Root",
      renderer:"Report renderer",
      backup:"Backup/checkpoint destination"
    };
    const rows=PREFLIGHT_ORDER.map(key=>{
      const fact=safeObject(facts[key]),state=rowState(fact,key);
      return {
        key,label:labels[key],state,
        currentValue:clean(fact.currentValue)||"Not available",
        reason:clean(fact.reason)||(state==="Ready"?"Validated locally.":"Local prerequisite is unavailable."),
        consequence:clean(fact.consequence)||(state==="Ready"
          ?"No local blocker was detected for this prerequisite."
          :state==="Blocking"
            ?"AEROS cannot safely open or persist this OSCP engagement."
            :"This workflow may fail later or require manual recovery."),
        correctiveAction:clean(fact.correctiveAction)||(state==="Ready"
          ?"No corrective action is required."
          :"Review local configuration and check again."),
        actionTarget:state==="Ready"?"":clean(fact.actionTarget),
        lastChecked:checkedAt
      };
    });
    const blocking=rows.filter(row=>row.state==="Blocking");
    const warnings=rows.filter(row=>row.state==="Warning");
    return {
      checkedAt,
      rows,
      blocking,
      warnings,
      canContinue:blocking.length===0,
      requiresWarningConfirmation:blocking.length===0&&warnings.length>0
    };
  }

  return {
    PROFILE_ID,GENERAL_PROFILE_ID,NAVIGATOR_ROUTE,DEFAULT_GENERAL_LANDING_ROUTE,
    STARTUP_ENGAGEMENT_LIMIT,
    PREFLIGHT_ORDER,OSCP_POLICY,OSCP_STARTING_ACCESS_TYPES,GENERAL_STARTING_ACCESS_TYPES,
    GENERAL_LANDING_ROUTES,workflowProfileForAssessment,isOscpConfig,
    normalizeEngagementConfig,normalizeUserProfile,engagementSummary,profileLabel,
    normalizeSummary,selectLastValidEngagement,startupEngagements,rememberEngagement,
    startingAccessTypesForAssessment,reconcileStartingAccessTypes,landingRoutesForAssessment,
    parseCandidateCredentialLines,evaluatePreflight
  };
});
