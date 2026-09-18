(function(global){
  "use strict";

  const SCHEMA_VERSION=1;
  const clean=value=>String(value??"").trim();
  const unique=values=>{const seen=new Set(),rows=[];for(const value of values||[]){const text=clean(value);if(!text)continue;const key=text.toLowerCase();if(seen.has(key))continue;seen.add(key);rows.push(text);}return rows;};
  function normalizePath(value,fallback="artifact"){
    const parts=clean(value||fallback).replace(/\\/g,"/").split("/").filter(part=>part&&part!=="."&&part!=="..");
    return parts.join("/")||fallback;
  }
  function normalizeRevision(raw={},fallback=1){
    const revision=Math.max(1,Number.parseInt(raw.revision,10)||fallback);
    return {
      revision,
      sha256:clean(raw.sha256).toLowerCase(),
      storedFilename:clean(raw.storedFilename),
      originalFilename:clean(raw.originalFilename),
      logicalPath:normalizePath(raw.logicalPath||raw.originalFilename||"artifact"),
      size:Number(raw.size)||0,
      mimeType:clean(raw.mimeType)||"application/octet-stream",
      source:clean(raw.source)||"Imported artifact",
      objective:clean(raw.objective),
      importedAt:clean(raw.importedAt||raw.uploadedAt||raw.observedAt)
    };
  }
  function normalizeArtifact(raw={}){
    const original=clean(raw.originalFilename)||"artifact";
    const revisions=(Array.isArray(raw.revisions)?raw.revisions:[]).map((row,index)=>normalizeRevision(row,index+1)).sort((a,b)=>a.revision-b.revision);
    const currentRevision=Math.max(1,Number.parseInt(raw.currentRevision,10)||revisions.at(-1)?.revision||1);
    const current=[...revisions].reverse().find(row=>row.revision===currentRevision)||revisions.at(-1)||null;
    const logicalPath=normalizePath(raw.logicalPath||current?.logicalPath||original,original);
    return {
      ...raw,
      artifactIdentitySchemaVersion:SCHEMA_VERSION,
      id:clean(raw.id)||`artifact_${Date.now()}_${Math.random().toString(16).slice(2)}`,
      kind:clean(raw.kind)||"scan-artifact",
      originalFilename:current?.originalFilename||original,
      logicalPath,
      artifactType:clean(raw.artifactType)||"scan-file",
      source:clean(raw.source)||"Imported scan",
      importer:clean(raw.importer||raw.source)||"Imported scan",
      objective:clean(raw.objective),
      storedFilename:current?.storedFilename||clean(raw.storedFilename),
      sha256:(current?.sha256||clean(raw.sha256)).toLowerCase(),
      currentRevision,
      revisionCount:Math.max(revisions.length,currentRevision,1),
      revisions,
      aliases:unique([...(Array.isArray(raw.aliases)?raw.aliases:[]),original,...revisions.map(row=>row.originalFilename)]),
      importHistory:(Array.isArray(raw.importHistory)?raw.importHistory:[]).filter(row=>row&&typeof row==="object"),
      firstSeenAt:clean(raw.firstSeenAt||raw.uploadedAt||raw.createdAt),
      lastSeenAt:clean(raw.lastSeenAt||raw.updatedAt||raw.uploadedAt),
      lastImportStatus:clean(raw.lastImportStatus)
    };
  }
  function mergeArtifact(records,raw){
    const artifact=normalizeArtifact(raw);
    const rows=Array.isArray(records)?records:[];
    let index=rows.findIndex(row=>clean(row?.id)===artifact.id);
    if(index<0&&artifact.sha256)index=rows.findIndex(row=>{
      const normalized=normalizeArtifact(row);
      return normalized.sha256===artifact.sha256||normalized.revisions.some(revision=>revision.sha256===artifact.sha256);
    });
    if(index>=0)rows.splice(index,1,artifact);else rows.push(artifact);
    return artifact;
  }
  function normalizeArtifacts(records){
    const output=[];
    for(const raw of Array.isArray(records)?records:[]){
      const item=normalizeArtifact(raw);
      const existing=output.find(row=>row.id===item.id||(item.sha256&&(row.sha256===item.sha256||row.revisions.some(revision=>revision.sha256===item.sha256))));
      if(existing){
        existing.aliases=unique([...existing.aliases,...item.aliases]);
        existing.importHistory=[...existing.importHistory,...item.importHistory];
        if(item.lastSeenAt>existing.lastSeenAt)Object.assign(existing,item,{aliases:existing.aliases,importHistory:existing.importHistory});
      }else output.push(item);
    }
    return output;
  }

  function sameLogicalIdentity(left,right){
    const a=normalizeArtifact(left),b=normalizeArtifact(right);
    return normalizePath(a.logicalPath).toLowerCase()===normalizePath(b.logicalPath).toLowerCase()
      &&clean(a.source).toLowerCase()===clean(b.source).toLowerCase()
      &&clean(a.objective).toLowerCase()===clean(b.objective).toLowerCase()
      &&clean(a.artifactType).toLowerCase()===clean(b.artifactType).toLowerCase();
  }
  function observeMetadata(records,raw){
    const rows=Array.isArray(records)?records:[];
    const now=clean(raw.observedAt||raw.uploadedAt)||new Date().toISOString();
    const incoming=normalizeArtifact({...raw,firstSeenAt:raw.firstSeenAt||now,lastSeenAt:now,uploadedAt:raw.uploadedAt||now});
    let existing=incoming.sha256?rows.find(row=>{const item=normalizeArtifact(row);return item.sha256===incoming.sha256||item.revisions.some(revision=>revision.sha256===incoming.sha256);}):null;
    let outcome=existing?"unchanged":"new";
    if(!existing){existing=rows.find(row=>sameLogicalIdentity(row,incoming));if(existing)outcome="updated";}
    if(!existing){
      incoming.currentRevision=1;incoming.revisionCount=1;incoming.lastImportStatus="new";
      incoming.revisions=[normalizeRevision({...incoming,revision:1,importedAt:now})];
      incoming.importHistory=[{observedAt:now,outcome:"new",revision:1,sha256:incoming.sha256,originalFilename:incoming.originalFilename,logicalPath:incoming.logicalPath,source:incoming.source,objective:incoming.objective}];
      rows.push(incoming);return {artifact:incoming,outcome:"new"};
    }
    const item=normalizeArtifact(existing);
    if(outcome==="updated"){
      const revision=Math.max(item.currentRevision,...item.revisions.map(row=>row.revision))+1;
      item.revisions.push(normalizeRevision({...incoming,revision,importedAt:now}));item.currentRevision=revision;item.revisionCount=item.revisions.length;
      item.originalFilename=incoming.originalFilename;item.logicalPath=incoming.logicalPath;item.sha256=incoming.sha256;item.size=incoming.size;item.mimeType=incoming.mimeType;item.storedFilename="";
    }
    const eventRevision=outcome==="updated"?item.currentRevision:(item.revisions.find(row=>row.sha256===incoming.sha256)?.revision||item.currentRevision);
    item.aliases=unique([...item.aliases,incoming.originalFilename,incoming.logicalPath]);
    item.importHistory=[...item.importHistory,{observedAt:now,outcome,revision:eventRevision,sha256:incoming.sha256,originalFilename:incoming.originalFilename,logicalPath:incoming.logicalPath,source:incoming.source,objective:incoming.objective}];
    item.lastSeenAt=now;item.updatedAt=now;item.lastImportStatus=outcome;
    const index=rows.indexOf(existing);rows.splice(index,1,item);return {artifact:item,outcome};
  }
  function importSummary(records){
    const rows=normalizeArtifacts(records);
    return {
      artifacts:rows.length,
      revisions:rows.reduce((total,row)=>total+Math.max(1,row.revisions.length||row.revisionCount||1),0),
      observations:rows.reduce((total,row)=>total+Math.max(1,row.importHistory.length),0)
    };
  }
  global.AEROSArtifactIdentity={SCHEMA_VERSION,normalizePath,normalizeRevision,normalizeArtifact,normalizeArtifacts,mergeArtifact,sameLogicalIdentity,observeMetadata,importSummary};
})(window);
