(function(root,factory){
  const api=factory(
    typeof module==="object"&&module.exports?require("./navigator-core.js"):root?.AEROSNavigatorCore
  );
  if(typeof module==="object"&&module.exports)module.exports=api;
  if(root)root.AEROSOscpNavigator=api;
})(typeof globalThis!=="undefined"?globalThis:this,function(core){
  "use strict";

  if(!core)throw new Error("The profile-neutral Navigator core is required.");

  const POLICY=Object.freeze({
    id:"offsec-oscp",
    version:"2026.1",
    source:"shipped-offline",
    editable:false,
    runtimeRefresh:false,
    profileId:"oscp",
    title:"OSCP Navigator",
    backLabel:"Back to Navigator",
    endpointContextLabel:"Relevant Notes",
    dimensionLabels:Object.freeze({
      scope:"Scope / target",
      os:"OS state",
      port:"TCP discovery",
      tcp:"TCP identification",
      udp:"UDP discovery",
      udpService:"UDP identification",
      endpoints:"Endpoint identity",
      origins:"Web-origin coverage",
      access:"Verified access contexts",
      leads:"Open / stale Leads",
      credentials:"Credential revisit",
      postAccess:"Post-access by context",
      pe:"Privilege escalation by context",
      proof:"OSCP proof",
      report:"Evidence / report readiness",
      save:"Current save state"
    }),
    priorityOrder:Object.freeze([
      "integrity","foundation","reopened","endpoint-gaps","leads","post-access",
      "privilege-escalation","proof","report"
    ]),
    excludedAdministration:Object.freeze([
      "commercial-roe-authoring","client-contacts","statement-of-work","business-severity-approval",
      "remediation-ownership","retest-scheduling","stakeholder-approval","deliverable-approval","team-assignment"
    ])
  });

  const GLOBAL_ACTIONS=Object.freeze([
    {id:"import",label:"Import",destination:"import",subview:"services"},
    {id:"record-outcome",label:"Record Outcome",destination:"record-outcome"},
    {id:"coverage",label:"Reassess",destination:"coverage"},
    {id:"proof",label:"Proof",destination:"proof"},
    {id:"report",label:"Report",destination:"report"},
    {id:"notes",label:"Notes / Reference",destination:"reference-note",subview:"next-actions"}
  ]);

  function policyDescriptor(){
    return Object.freeze({
      id:POLICY.id,version:POLICY.version,source:POLICY.source,
      editable:POLICY.editable,runtimeRefresh:POLICY.runtimeRefresh
    });
  }
  function appliesTo(config={}){
    const assessment=config&&typeof config==="object"?config.assessment||{}:{};
    return String(assessment.category||"").trim().toLowerCase()==="certification-lab"
      &&String(assessment.type||"").trim().toLowerCase()==="oscp";
  }
  function project(state={},options={}){
    if(!appliesTo(state.engagementConfig||{}))return null;
    return core.projectEngagement(state,POLICY,options);
  }
  function globalRoutes(state={},hostId=""){
    const owner={engagementId:String(state.projectId||"").trim(),engagementName:String(state.projectName||"").trim(),hostId:String(hostId||"").trim()};
    return GLOBAL_ACTIONS.map(action=>Object.freeze({
      ...action,
      route:core.normalizeRoute({...owner,destination:action.destination,subview:action.subview||""}).route
    }));
  }

  return Object.freeze({POLICY,GLOBAL_ACTIONS,policyDescriptor,appliesTo,project,globalRoutes});
});
