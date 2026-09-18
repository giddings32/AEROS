(function(root,factory){
  const api=factory();
  if(typeof module==="object"&&module.exports)module.exports=api;
  if(root)root.AEROSReconImport=api;
})(typeof window!=="undefined"?window:globalThis,function(){
  "use strict";

  const SUPPORTED_SCHEMAS=Object.freeze(["aeros-recon","aeros-collector","product-recon"]);
  const API_CAPABILITY="reconImport";
  const supportsSchema=value=>SUPPORTED_SCHEMAS.includes(String(value||"").trim().toLowerCase());

  function validate(data){
    if(!data||typeof data!=="object"||Array.isArray(data))throw new Error("The selected file is not a JSON object.");
    const schemaName=String(data.schema?.name||"").trim();
    if(!supportsSchema(schemaName))throw new Error(`Unsupported schema.name: ${schemaName||"missing"}. Expected aeros-recon.`);
    const schemaVersion=String(data.schema?.version||"").trim();
    if(!schemaVersion||schemaVersion.split(".")[0]!=="1")throw new Error(`Unsupported ${schemaName} schema version: ${schemaVersion||"missing"}`);
    if(String(data.collector?.platform||"").toLowerCase()!=="linux")throw new Error("This importer currently supports Linux AEROS recon data only.");
    if(!data.collection||typeof data.collection!=="object")throw new Error("The JSON does not contain a collection object.");
    if(!data.target||typeof data.target!=="object")throw new Error("The JSON does not contain a target object.");
    if(!data.sections||typeof data.sections!=="object"||Array.isArray(data.sections))throw new Error("The JSON does not contain a sections object.");
    return true;
  }

  function normalizeRouteTitle(value){return String(value||"").toLowerCase().replace(/[^a-z0-9]+/g,"").trim();}
  function resolveMapping(sectionKey,section,mappings=[]){
    const direct=mappings.find(item=>item.section===sectionKey);if(direct)return direct;
    const title=normalizeRouteTitle(section?.label||sectionKey);
    return mappings.find(item=>normalizeRouteTitle(item.label)===title||normalizeRouteTitle(item.section)===title)||null;
  }
  function cleanText(value){
    const cleaned=[];let previousBlank=false;
    String(value||"").replace(/\r\n?/g,"\n").split("\n").forEach(line=>{const blank=!line.trim();if(blank&&previousBlank)return;cleaned.push(line.replace(/\s+$/,""));previousBlank=blank;});
    return cleaned.join("\n").trim();
  }
  function sectionValue(sectionKey,section,mapping){
    let value=cleanText(section?.raw||"");
    if(sectionKey==="os"||mapping?.fieldId==="sysLinuxOsKernel")value=value.split("\n").map(line=>/^(?:\s*)(?:Operating System:|Kernel:|Architecture:)/.test(line)?line.trimStart():line).join("\n");
    return value;
  }
  function username(item){return String(item?.data?.collection?.executedAs?.username||"unknown").trim()||"unknown";}
  function signalKey(mapping){
    const section=String(mapping?.section||"");
    if(["os","network","routes","firewall","listeningPorts"].includes(section))return "linuxSystemInfo";
    if(["users","groups","sudoers","userGroups","privilegePolicy"].includes(section))return "linuxUserInfo";
    if(section==="packages")return "linuxPackageInfo";if(section==="processes")return "linuxProcessInfo";if(section==="services")return "linuxServiceInfo";return "";
  }
  function mappingDestination(item,mapping){
    if(mapping?.dynamicKind){const user=username(item);return {type:"dynamic",key:`${mapping.dynamicKind}::${user}`,label:`${mapping.label} - ${user}`};}
    return {type:"static",store:mapping.store,key:mapping.key,label:mapping.label};
  }
  function destinationId(destination){return destination.type==="dynamic"?`dynamic:${destination.key}`:`static:${destination.store}:${destination.key}`;}
  function importedFieldKey(item,mapping){return mapping?.dynamicKind?`dynamic::${mapping.dynamicKind}::${username(item)}`:(mapping?.fieldId?`static::${mapping.fieldId}`:"");}
  function routes(item,mappings=[]){
    const grouped=new Map();
    Object.entries(item?.data?.sections||{}).forEach(([sectionKey,section])=>{
      const mapping=resolveMapping(sectionKey,section,mappings),value=mapping?sectionValue(sectionKey,section,mapping):"";if(!mapping||!value)return;
      const destination=mappingDestination(item,mapping),id=destinationId(destination);
      if(!grouped.has(id))grouped.set(id,{sectionKey,section,sections:[{sectionKey,section}],mapping,destination,value});
      else{const route=grouped.get(id);route.sections.push({sectionKey,section});route.value=`${route.value.trim()}\n\n${value.trim()}`;}
    });
    return Array.from(grouped.values());
  }
  function collectionIdentity(data){
    const rawSchema=String(data?.schema?.name||"").trim().toLowerCase(),schema=supportsSchema(rawSchema)?"aeros-recon":rawSchema;
    const collection=data?.collection||{},target=data?.target||{},collectionId=String(collection.id||"").trim();
    if(collectionId)return `${schema}::${collectionId}`;
    return [schema,target.hostname,target.primaryAddress,collection.scope,collection.executedAs?.username,collection.collectedAt].map(value=>String(value||"").trim().toLowerCase()).join("::");
  }
  function normalizedTarget(payloads=[]){
    const hostnames=new Set(),addresses=new Set();
    payloads.forEach(entry=>{const target=entry?.data?.target||{},hostname=String(target.hostname||"").trim().toLowerCase().replace(/\.$/,""),address=String(target.primaryAddress||"").trim().toLowerCase();if(hostname)hostnames.add(hostname);if(address)addresses.add(address);});
    if(hostnames.size>1||addresses.size>1)throw new Error("The selected files describe more than one target host. Import one host at a time.");
    return {hostname:[...hostnames][0]||"",primaryAddress:[...addresses][0]||""};
  }
  function targetMismatch(host,target){
    const addresses=[host?.ip,...(Array.isArray(host?.networkAddresses)?host.networkAddresses.filter(row=>row?.active!==false).map(row=>row?.address):[]),...(Array.isArray(host?.addresses)?host.addresses:[])]
      .map(value=>String(value||"").trim().toLowerCase()).filter(Boolean);
    const names=[host?.hostname,...(Array.isArray(host?.hostnames)?host.hostnames:[]),...(Array.isArray(host?.aliases)?host.aliases:[])]
      .map(value=>String(value||"").trim().toLowerCase().replace(/\.$/,"")).filter(Boolean);
    const targetIp=String(target?.primaryAddress||"").trim().toLowerCase(),targetName=String(target?.hostname||"").trim().toLowerCase().replace(/\.$/,"");
    return Boolean((targetIp&&addresses.length&&!addresses.includes(targetIp))||(targetName&&names.length&&!names.includes(targetName)));
  }
  async function detectUploadType(file){
    const filename=String(file?.name||"").toLowerCase();let signature=[];
    try{signature=Array.from(new Uint8Array(await file.slice(0,4).arrayBuffer()));}catch(error){}
    const zipMagic=signature.length>=4&&signature[0]===0x50&&signature[1]===0x4b&&((signature[2]===0x03&&signature[3]===0x04)||(signature[2]===0x05&&signature[3]===0x06)||(signature[2]===0x07&&signature[3]===0x08));
    if(zipMagic||filename.endsWith(".zip"))return "zip";if(filename.endsWith(".json"))return "json";return "unknown";
  }
  function serverError(detail=""){
    const extra=detail?` ${detail}`:"";
    return new Error(`The Imported Recon page cannot reach the current AEROS recon-import API.${extra} Close every AEROS window, run "Stop AEROS V1 Server.cmd", then reopen this build.`);
  }
  async function readUpload(file,{fetchImpl,FormDataCtor}={}){
    const filename=String(file?.name||"recon-upload"),uploadType=await detectUploadType(file);
    if(uploadType==="unknown")throw new Error("Supported recon upload types are ZIP archives and JSON files.");
    if(typeof fetchImpl!=="function")throw new Error("Recon import network support is unavailable.");
    if(typeof FormDataCtor!=="function")throw new Error("Recon import form-data support is unavailable.");
    const form=new FormDataCtor();form.append("collection",file,filename);let response;
    try{response=await fetchImpl("/api/import-recon",{method:"POST",body:form});}
    catch(networkError){
      if(uploadType==="zip")throw serverError(`A ZIP archive was detected; it cannot be processed by the offline JSON fallback. (${networkError.message})`);
      let data;try{data=JSON.parse(await file.text());validate(data);}catch(localError){throw new Error(localError.message);}
      return {sourceType:"json",sourceName:filename,payloads:[{filename,data}],legacySchemas:data.schema?.name==="aeros-recon"?[]:[data.schema?.name]};
    }
    const responseText=await response.text();let result;
    try{result=JSON.parse(responseText);}catch(parseError){if(response.status===404)throw serverError("The running server does not have /api/import-recon.");throw serverError(`The server returned a non-JSON response (HTTP ${response.status}).`);}
    if(response.status===404)throw serverError("The running server is older than this Imported Recon page.");
    if(!response.ok||!result.ok)throw new Error(result.error||"The AEROS server rejected the collection.");
    if(!Array.isArray(result.payloads)||!result.payloads.length)throw new Error("The upload did not contain any recon payloads.");
    result.payloads.forEach(entry=>validate(entry.data));return result;
  }

  const WEB_SCHEMES=Object.freeze(["http:","https:"]);
  const MAX_WEB_IMPORT_BYTES=25*1024*1024;
  const MAX_WEB_SOURCE_OBSERVATIONS=50;
  const WEB_IMPORT_PROJECTION_SCHEMA_VERSION=1;
  const TECHNOLOGY_IMPORT_PROJECTION_SCHEMA_VERSION=1;
  const WEB_BASELINE_PROJECTION_SCHEMA_VERSION=1;
  const MAX_WHATWEB_RECORDS=5000;
  const MAX_WHATWEB_TECHNOLOGIES_PER_RECORD=250;
  const WEB_PATH_ONLY_ORIGIN="path-only";
  const boundedText=(value,limit=2048)=>String(value??"").replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g,"").trim().slice(0,limit);
  const finiteInteger=(value,{min=0,max=Number.MAX_SAFE_INTEGER}={})=>{const number=Number(value);return Number.isInteger(number)&&number>=min&&number<=max?number:null;};
  function normalizedDomain(value){
    let text=boundedText(value,512).toLowerCase().replace(/\.$/,"");
    if(text.startsWith("[")&&text.endsWith("]"))text=text.slice(1,-1);
    if(!text||text.length>253||/[\s/?#@]/.test(text))return "";
    if(text.includes(":"))return /^[0-9a-f:.]+$/i.test(text)&&text.includes(":")?text:"";
    const labels=text.split(".");
    if(labels.some(label=>!label||label.length>63||!/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label)))return "";
    return text;
  }
  function normalizedWebUrl(value){
    const text=boundedText(value,8192);if(!text)return null;let parsed;
    try{parsed=new URL(text);}catch(error){return null;}
    if(!WEB_SCHEMES.includes(parsed.protocol)||parsed.username||parsed.password)return null;
    const host=normalizedDomain(parsed.hostname);if(!host)return null;
    parsed.hostname=host;parsed.hash="";
    const scheme=parsed.protocol.slice(0,-1),defaultPort=scheme==="https"?443:80,port=finiteInteger(parsed.port||defaultPort,{min:1,max:65535});
    if(!port)return null;
    if(port===defaultPort)parsed.port="";
    const path=parsed.pathname||"/",query=parsed.search||"",url=parsed.toString();
    return {key:`url:${scheme}://${host}:${port}${path}${query}`,kind:"url",value:url,url,origin:parsed.origin,scheme,host,port,path,query};
  }
  function normalizedWebOrigin(value){
    const normalized=normalizedWebUrl(value);if(!normalized)return "";
    try{return new URL(normalized.url).origin;}catch(_error){return "";}
  }
  function webServiceBaseUrl({host="",port=0,serviceKey="",contextLabel="",noteServices=[]}={}){
    const rawHost=boundedText(host,512).trim()||"<rhost>";
    const numericPort=finiteInteger(port,{min:1,max:65535})||0;
    const service=boundedText(serviceKey,64).toLowerCase();
    const label=boundedText(contextLabel,1024);
    const services=(Array.isArray(noteServices)?noteServices:[]).map(value=>boundedText(value,64).toLowerCase()).filter(Boolean);
    const httpsContext=service==="https"||/\b(?:https|ssl|tls)\b/i.test(label);
    const httpsOnly=services.includes("https")&&!services.includes("http");
    const scheme=httpsContext||httpsOnly||[443,8443].includes(numericPort)?"https":"http";
    const displayHost=rawHost.includes(":")&&!rawHost.startsWith("[")?`[${rawHost}]`:rawHost;
    const includePort=numericPort&&!((scheme==="http"&&numericPort===80)||(scheme==="https"&&numericPort===443));
    return {scheme,host:rawHost,port:numericPort,baseUrl:`${scheme}://${displayHost}${includePort?`:${numericPort}`:""}`};
  }
  function webRecord(candidate,metadata={}){
    const text=boundedText(candidate,8192);if(!text)return null;
    const direct=normalizedWebUrl(text);
    let baseResolved=null;
    if(!direct&&text.startsWith("/")&&metadata.baseUrl){
      try{baseResolved=normalizedWebUrl(new URL(text,metadata.baseUrl).toString());}catch(error){}
    }
    const normalized=direct||baseResolved;
    const metrics={
      status:finiteInteger(metadata.status,{min:100,max:599}),
      length:finiteInteger(metadata.length),
      words:finiteInteger(metadata.words),
      lines:finiteInteger(metadata.lines),
      contentType:boundedText(metadata.contentType,256),
      redirect:boundedText(metadata.redirect,4096),
      method:boundedText(metadata.method||"GET",24).toUpperCase()||"GET"
    };
    if(normalized)return {...normalized,...metrics,unresolved:false};
    if(text.startsWith("/")&&!/[\s\u0000]/.test(text)){
      const path=text.split("#",1)[0].slice(0,8192);
      return {key:`path:${path}`,kind:"path",value:path,url:"",scheme:"",host:"",port:null,path,query:"",...metrics,unresolved:true};
    }
    const domain=normalizedDomain(text);
    if(domain)return {key:`domain:${domain}`,kind:metadata.kind==="vhost"?"vhost":"domain",value:domain,url:"",scheme:"",host:domain,port:null,path:"",query:"",...metrics,unresolved:false};
    return null;
  }
  function dedupeWebRecords(records=[]){
    const rows=[],byKey=new Map();
    for(const raw of records){
      if(!raw?.key)continue;
      const existing=byKey.get(raw.key);
      if(!existing){const row={...raw};byKey.set(raw.key,row);rows.push(row);continue;}
      for(const key of ["status","length","words","lines","contentType","redirect","method"]){
        if((existing[key]===null||existing[key]===""||existing[key]===undefined)&&raw[key]!==null&&raw[key]!==""&&raw[key]!==undefined)existing[key]=raw[key];
      }
      if(existing.kind==="domain"&&raw.kind==="vhost")existing.kind="vhost";
    }
    return rows;
  }
  function ffufCandidate(result,data){
    const direct=boundedText(result?.url,8192);if(direct)return direct;
    const template=boundedText(data?.config?.url||data?.commandline,8192);
    const input=result?.input&&typeof result.input==="object"?Object.values(result.input).map(value=>boundedText(value,4096)).find(Boolean):"";
    if(input&&template.includes("FUZZ")){
      const match=template.match(/https?:\/\/[^\s'"`]+/i),urlTemplate=match?.[0]||template;
      return urlTemplate.replace("FUZZ",input);
    }
    return input||"";
  }
  function parseFfufJson(data,{filename=""}={}){
    if(!data||typeof data!=="object"||Array.isArray(data)||!Array.isArray(data.results))throw new Error("This JSON is not an ffuf results file.");
    const records=[],skipped=[];const baseUrl=boundedText(data?.config?.url,8192).replace(/FUZZ.*$/,"");
    data.results.forEach((result,index)=>{
      const candidate=ffufCandidate(result,data);
      const record=webRecord(candidate,{baseUrl,status:result?.status,length:result?.length,words:result?.words,lines:result?.lines,contentType:result?.["content-type"]||result?.content_type,redirect:result?.redirectlocation||result?.redirect_location,method:result?.method||data?.config?.method});
      if(record)records.push(record);else skipped.push(`Result ${index+1} did not contain a supported HTTP(S) URL, domain, or path.`);
    });
    const normalizedBase=normalizedWebUrl(baseUrl)?.url||"",command=boundedText(data?.commandline||data?.config?.command||"",4096);
    const providerWordlists=Array.isArray(data?.config?.inputproviders)?data.config.inputproviders.map(provider=>boundedText(provider?.value,2048)).filter(Boolean):[];
    const wordlist=boundedText(data?.config?.wordlist||providerWordlists.join(", "),2048);
    return {format:"ffuf-json",tool:"FFUF",filename:boundedText(filename,512),baseUrl:normalizedBase,command,wordlist,operationState:"completed",records:dedupeWebRecords(records),skipped,totalInput:data.results.length};
  }
  function gobusterBaseUrl(lines){
    for(const line of lines){
      const match=line.match(/^\s*\[\+\]\s*(?:url|target url)\s*:\s*(https?:\/\/\S+)/i);
      if(match){const normalized=normalizedWebUrl(match[1]);if(normalized)return normalized.url;}
    }
    return "";
  }
  function parseGobusterText(text,{filename="",baseUrl=""}={}){
    const normalizedText=String(text??"").replace(/\r\n?/g,"\n");
    const lines=normalizedText.split("\n"),detectedBase=gobusterBaseUrl(lines)||normalizedWebUrl(baseUrl)?.url||"";
    const records=[],skipped=[];let candidates=0;
    for(const sourceLine of lines){
      const line=sourceLine.trim();if(!line)continue;
      let match=line.match(/^(\/\S*?)\s+\(Status:\s*(\d{3})\)\s+\[Size:\s*(\d+)\](?:\s+\[-->\s*(.*?)\])?\s*$/i);
      if(match){
        candidates++;const record=webRecord(match[1],{baseUrl:detectedBase,status:match[2],length:match[3],redirect:match[4]});
        if(record)records.push(record);else skipped.push(line.slice(0,160));continue;
      }
      match=line.match(/^Found:\s*(\S+?)(?:\s+(?:\(Status:\s*|Status:\s*)(\d{3})\)?(?:\s+\[Size:\s*(\d+)\])?)?\s*$/i);
      if(match){
        candidates++;const token=match[1],kind=!/^https?:\/\//i.test(token)&&!token.startsWith("/")?"vhost":undefined;
        const record=webRecord(token,{baseUrl:detectedBase,status:match[2],length:match[3],kind});
        if(record)records.push(record);else skipped.push(line.slice(0,160));
      }
    }
    if(!candidates&&!/gobuster/i.test(normalizedText))throw new Error("This text does not contain recognizable Gobuster results.");
    const failed=/^\s*(?:error|fatal|\[!\])\b|connection refused|could not connect|context deadline exceeded/im.test(normalizedText);
    const completed=/^\s*finished\s*$/im.test(normalizedText)||/^\s*end time\s*:/im.test(normalizedText);
    const operationState=failed?(candidates?"partial":"failed"):(completed?"completed":candidates?"partial":"partial");
    const command=boundedText((/^\s*\[\+\]\s*Command\s*:\s*(.+)$/im.exec(normalizedText)||[])[1],4096);
    const wordlist=boundedText((/^\s*\[\+\]\s*Wordlist\s*:\s*(.+)$/im.exec(normalizedText)||[])[1],2048);
    return {format:"gobuster-text",tool:"Gobuster",filename:boundedText(filename,512),baseUrl:detectedBase,command,wordlist,operationState,records:dedupeWebRecords(records),skipped,totalInput:candidates};
  }
  function dirbBaseUrl(lines){
    for(const line of lines){
      const match=line.match(/^\s*(?:URL_BASE\s*:|----\s*Scanning URL\s*:)\s*(https?:\/\/\S+?)(?:\s+----)?\s*$/i);
      if(match){const normalized=normalizedWebUrl(match[1]);if(normalized)return normalized.url;}
    }
    return "";
  }
  function parseDirbText(text,{filename="",baseUrl=""}={}){
    const normalizedText=String(text??"").replace(/\r\n?/g,"\n"),lines=normalizedText.split("\n");
    const structural=/^\s*DIRB\s+v?\d/i.test(normalizedText)||/^\s*(?:URL_BASE|START_TIME|END_TIME|DOWNLOADED)\s*:/im.test(normalizedText);
    if(!structural)throw new Error("This text does not contain recognizable DIRB output.");
    const detectedBase=dirbBaseUrl(lines)||normalizedWebUrl(baseUrl)?.url||"";
    const records=[],skipped=[];let candidates=0;
    for(const sourceLine of lines){
      const line=sourceLine.trim();if(!line)continue;
      let match=line.match(/^\+\s+(\S+)\s+\(CODE:(\d{3})\|SIZE:(\d+)(?:\|LOCATION:([^)]*))?\)\s*$/i);
      if(match){
        candidates++;
        const record=webRecord(match[1],{baseUrl:detectedBase,status:match[2],length:match[3],redirect:match[4]});
        if(record)records.push(record);else skipped.push(line.slice(0,160));
        continue;
      }
      match=line.match(/^==>\s*DIRECTORY:\s*(\S+)\s*$/i);
      if(match){
        candidates++;
        const record=webRecord(match[1],{baseUrl:detectedBase,status:200});
        if(record)records.push(record);else skipped.push(line.slice(0,160));
      }
    }
    const failed=/couldn['’]?t resolve|connection refused|error connecting|fatal error|unable to connect/i.test(normalizedText);
    const completed=/^\s*END_TIME\s*:/im.test(normalizedText)||/^\s*DOWNLOADED\s*:/im.test(normalizedText);
    const operationState=failed?(candidates?"partial":"failed"):(completed?"completed":candidates?"partial":"partial");
    const wordlist=boundedText((/^\s*WORDLIST_FILES\s*:\s*(.+)$/im.exec(normalizedText)||[])[1],2048);
    return {format:"dirb-text",tool:"DIRB",filename:boundedText(filename,512),baseUrl:detectedBase,command:"",wordlist,operationState,records:dedupeWebRecords(records),skipped,totalInput:candidates};
  }
  function parseDirbusterText(text,{filename="",baseUrl=""}={}){
    const normalizedText=String(text??"").replace(/\r\n?/g,"\n"),structural=/\bDirBuster\b/i.test(normalizedText)||/^\s*(?:Dir|File) found\s*:/im.test(normalizedText);
    if(!structural)throw new Error("This text does not contain recognizable DirBuster output.");
    const targetMatch=/^\s*(?:Target(?: URL)?|URL)\s*:\s*(https?:\/\/\S+)/im.exec(normalizedText),detectedBase=normalizedWebUrl(targetMatch?.[1])?.url||normalizedWebUrl(baseUrl)?.url||"";
    const records=[],skipped=[];let candidates=0;
    for(const sourceLine of normalizedText.split("\n")){
      const line=sourceLine.trim();if(!line)continue;
      const match=line.match(/^(?:Dir|File) found\s*:\s*(\S+?)\s+-\s+(\d{3})(?:\s+-\s+(\d+))?\s*$/i);if(!match)continue;
      candidates++;const record=webRecord(match[1],{baseUrl:detectedBase,status:match[2],length:match[3],method:"GET"});if(record)records.push(record);else skipped.push(line.slice(0,160));
    }
    const failed=/connection refused|could not connect|unable to connect|fatal error/i.test(normalizedText),completed=/scan complete|scan completed|finished/i.test(normalizedText),operationState=failed?(candidates?"partial":"failed"):(completed?"completed":candidates?"partial":"partial");
    return {format:"dirbuster-text",tool:"DirBuster",filename:boundedText(filename,512),baseUrl:detectedBase,command:"",wordlist:"",operationState,records:dedupeWebRecords(records),skipped,totalInput:candidates};
  }
  function parseFeroxbusterJson(data,{filename=""}={}){
    const rawRows=Array.isArray(data)?data:Array.isArray(data?.results)?data.results:[data],records=[],skipped=[],metadata=[];let candidates=0;
    rawRows.forEach((row,index)=>{
      if(!row||typeof row!=="object"||Array.isArray(row))return;
      const type=String(row.type||"").toLowerCase();
      if(type&&type!=="response"){metadata.push(row);return;}
      if(!row.url&&!row.target_url)return;
      candidates++;
      const record=webRecord(row.url||row.target_url,{status:row.status||row.status_code,length:row.content_length??row.size,words:row.word_count??row.words,lines:row.line_count??row.lines,contentType:row.content_type,redirect:row.redirect||row.location,method:row.method||"GET"});
      if(record)records.push(record);else skipped.push(`Result ${index+1} did not contain a supported HTTP(S) URL.`);
    });
    const recognizedMetadata=metadata.some(row=>["statistics","stats","configuration","config","summary","error"].includes(String(row.type||"").toLowerCase())||row.total_requests!==undefined||row.requests!==undefined||row.errors!==undefined||row.command!==undefined||row.wordlist!==undefined);
    if(!candidates&&!recognizedMetadata)throw new Error("This JSON is not a Feroxbuster response export.");
    const allRows=rawRows.filter(row=>row&&typeof row==="object"&&!Array.isArray(row)),first=value=>allRows.map(row=>row?.[value]).find(item=>item!==undefined&&item!==null&&String(item).trim()!=="");
    const failed=allRows.some(row=>String(row?.type||"").toLowerCase()==="error"||row?.error===true||/fatal|connection refused|could not connect|unable to connect/i.test(String(row?.error||row?.message||"")));
    const completed=allRows.some(row=>["statistics","stats","summary"].includes(String(row?.type||"").toLowerCase())||row?.completed===true||row?.scan_complete===true)||candidates>0;
    const baseUrl=normalizedWebUrl(first("target_url")||first("target")||first("base_url"))?.url||"";
    return {format:"feroxbuster-json",tool:"Feroxbuster",filename:boundedText(filename,512),baseUrl,command:boundedText(first("command")||first("commandline"),4096),wordlist:boundedText(first("wordlist")||first("wordlist_path"),2048),operationState:failed?(records.length?"partial":"failed"):(completed?"completed":"partial"),records:dedupeWebRecords(records),skipped,totalInput:candidates};
  }
  function feroxbusterTextStructure(text="",filename=""){
    const raw=String(text??""),named=/ferox(?:buster)?/i.test(String(filename||"")),toolMarker=/\bferoxbuster(?:\/\d+(?:[.]\d+){1,3})?\b/i.test(raw),legacy=/^\s*\[\+\]\s*Target Url\s*:/im.test(raw);
    const config=/^\s*Configuration\s*\{/im.test(raw)&&/^\s*kind\s*:\s*"configuration"\s*,?\s*$/im.test(raw)&&/^\s*target_url\s*:\s*"https?:\/\/[^"\r\n]+"\s*,?\s*$/im.test(raw);
    const result=/^\s*\d{3}\s+[A-Z]+\s+\d+l\s+\d+w\s+\d+c\s+(?:https?:\/\/|\/)\S+/im.test(raw);
    return toolMarker||legacy||result&&(named||config)||config&&named;
  }
  function parseFeroxbusterText(text,{filename="",baseUrl=""}={}){
    const normalizedText=String(text??"").replace(/\r\n?/g,"\n"),lines=normalizedText.split("\n");
    const structural=feroxbusterTextStructure(normalizedText,filename);
    if(!structural)throw new Error("This text does not contain recognizable Feroxbuster output.");
    const targetMatch=/^\s*\[\+\]\s*Target Url\s*:\s*(https?:\/\/\S+)/im.exec(normalizedText),configTarget=/^\s*target_url\s*:\s*"([^"\r\n]+)"\s*,?\s*$/im.exec(normalizedText);
    const detectedBase=normalizedWebUrl(targetMatch?.[1]||configTarget?.[1])?.url||normalizedWebUrl(baseUrl)?.url||"";
    const records=[],skipped=[];let candidates=0;
    for(let index=0;index<lines.length;index++){
      const sourceLine=lines[index];
      const line=sourceLine.replace(/\x1b\[[0-9;]*m/g,"").trim();if(!line)continue;
      const match=line.match(/^(\d{3})\s+([A-Z]+)\s+(\d+)l\s+(\d+)w\s+(\d+)c\s+(https?:\/\/\S+?|\/\S+?)(?:\s+(?:=>|->)\s+(\S+))?\s*$/i);
      if(!match)continue;
      let redirect=match[7]||"";
      if(!redirect&&index+1<lines.length){
        const next=lines[index+1].replace(/\x1b\[[0-9;]*m/g,"");
        const continuation=/^\s+(?:=>|->)\s+(\S+)\s*$/.exec(next);if(continuation){redirect=continuation[1];index++;}
      }
      candidates++;
      const record=webRecord(match[6],{baseUrl:detectedBase,status:match[1],method:match[2],lines:match[3],words:match[4],length:match[5],redirect});
      if(record)records.push(record);else skipped.push(line.slice(0,160));
    }
    const failed=/\b(?:fatal|error)\b.*(?:connect|resolve|timeout)|connection refused|could not connect/i.test(normalizedText);
    const completed=/^\s*(?:Finished|Scan complete|Scan completed)\s*$/im.test(normalizedText);
    const operationState=failed?(candidates?"partial":"failed"):(completed?"completed":candidates?"partial":"partial");
    const command=boundedText((/^\s*\[\+\]\s*Command\s*:\s*(.+)$/im.exec(normalizedText)||[])[1],4096);
    const wordlist=boundedText((/^\s*\[\+\]\s*Wordlist\s*:\s*(.+)$/im.exec(normalizedText)||[])[1]||(/^\s*wordlist\s*:\s*"([^"\r\n]+)"\s*,?\s*$/im.exec(normalizedText)||[])[1],2048);
    return {format:"feroxbuster-text",tool:"Feroxbuster",filename:boundedText(filename,512),baseUrl:detectedBase,command,wordlist,operationState,records:dedupeWebRecords(records),skipped,totalInput:candidates};
  }
  function parsedByteSize(value){
    const match=String(value??"").trim().match(/^(\d+(?:\.\d+)?)\s*([kmgt]?b)?$/i);if(!match)return null;
    const multiplier=({kb:1024,mb:1024**2,gb:1024**3,tb:1024**4})[String(match[2]||"b").toLowerCase()]||1;
    return Math.max(0,Math.round(Number(match[1])*multiplier));
  }
  function parseDirsearchText(text,{filename="",baseUrl=""}={}){
    const normalizedText=String(text??"").replace(/\r\n?/g,"\n"),lines=normalizedText.split("\n");
    const structural=/dirsearch/i.test(normalizedText)||/^\s*\[[^\]]+\]\s*Starting\s*:\s*https?:\/\//im.test(normalizedText);
    if(!structural)throw new Error("This text does not contain recognizable dirsearch output.");
    const targetMatch=/^\s*(?:\[[^\]]+\]\s*)?Starting\s*:\s*(https?:\/\/\S+)/im.exec(normalizedText);
    const detectedBase=normalizedWebUrl(targetMatch?.[1])?.url||normalizedWebUrl(baseUrl)?.url||"";
    const records=[],skipped=[];let candidates=0;
    for(const sourceLine of lines){
      const line=sourceLine.replace(/\x1b\[[0-9;]*m/g,"").trim();if(!line)continue;
      const match=line.match(/^(?:\[[^\]]+\]\s*)?(\d{3})\s+(?:-\s*)?(\d+(?:\.\d+)?\s*[KMGT]?B|\d+)(?:\s*-\s*|\s+)(https?:\/\/\S+?|\/\S+?)(?:\s+(?:->|=>)\s+(\S+))?\s*$/i);
      if(!match)continue;
      candidates++;
      const record=webRecord(match[3],{baseUrl:detectedBase,status:match[1],length:parsedByteSize(match[2]),redirect:match[4],method:"GET"});
      if(record)records.push(record);else skipped.push(line.slice(0,160));
    }
    const failed=/\b(?:fatal|error)\b.*(?:connect|resolve|timeout)|connection refused|could not connect/i.test(normalizedText);
    const completed=/^\s*(?:Task Completed|Scan complete|Scan completed)\s*$/im.test(normalizedText);
    const operationState=failed?(candidates?"partial":"failed"):(completed?"completed":candidates?"partial":"partial");
    const wordlist=boundedText((/^\s*(?:Wordlist|Extensions)\s*:\s*(.+)$/im.exec(normalizedText)||[])[1],2048);
    return {format:"dirsearch-text",tool:"dirsearch",filename:boundedText(filename,512),baseUrl:detectedBase,command:"",wordlist,operationState,records:dedupeWebRecords(records),skipped,totalInput:candidates};
  }
  function parseWebTargetList(text,{filename="",baseUrl=""}={}){
    const records=[],skipped=[];let candidates=0;
    String(text??"").replace(/\r\n?/g,"\n").split("\n").forEach(sourceLine=>{
      const line=sourceLine.trim();if(!line||line.startsWith("#"))return;candidates++;
      const record=webRecord(line,{baseUrl});
      if(record)records.push(record);else skipped.push(line.slice(0,160));
    });
    if(!candidates)throw new Error("The selected file does not contain any URL or domain entries.");
    if(!records.length)throw new Error("No supported HTTP(S) URLs, domains, or absolute paths were found.");
    return {format:"target-list",tool:"URL list",filename:boundedText(filename,512),baseUrl:normalizedWebUrl(baseUrl)?.url||"",command:"",operationState:"facts-only",records:dedupeWebRecords(records),skipped,totalInput:candidates};
  }
  function parseJsonObjectStream(text,{label="JSON object stream"}={}){
    const raw=String(text??""),rows=[];let index=0;
    while(index<raw.length){
      while(index<raw.length&&/\s/.test(raw[index]))index++;
      if(index>=raw.length)break;
      if(raw[index]!=="{")throw new Error(`${label} contains unexpected data before JSON object ${rows.length+1}.`);
      const start=index;let depth=0,inString=false,escaped=false,closed=false;
      for(;index<raw.length;index++){
        const char=raw[index];
        if(inString){
          if(escaped)escaped=false;
          else if(char==="\\")escaped=true;
          else if(char==='"')inString=false;
          continue;
        }
        if(char==='"'){inString=true;continue;}
        if(char==="{"){depth++;continue;}
        if(char==="}"){
          depth--;
          if(depth<0)throw new Error(`${label} contains an unmatched closing brace.`);
          if(depth===0){index++;closed=true;break;}
        }
      }
      if(!closed)throw new Error(`${label} ends with an incomplete JSON object.`);
      const fragment=raw.slice(start,index);
      try{rows.push(JSON.parse(fragment));}catch(error){throw new Error(`${label} object ${rows.length+1} is invalid: ${error.message}`);}
    }
    return rows;
  }
  function parseWebDiscovery(text,{filename="",baseUrl=""}={}){
    const raw=String(text??"");if(!raw.trim())throw new Error("The selected file is empty.");
    const lower=String(filename||"").toLowerCase(),feroxType=row=>["response","statistics","stats","configuration","config","summary","error"].includes(String(row?.type||"").toLowerCase());
    const feroxJsonLineHint=/(?:^|\r?\n)\s*\{[^\r\n]*"type"\s*:\s*"(?:response|statistics|stats|configuration|config|summary|error)"/i.test(raw);
    if((lower.includes("ferox")||feroxJsonLineHint)&&/^\s*\{/.test(raw)){
      try{
        const rows=parseJsonObjectStream(raw,{label:"Feroxbuster JSON stream"});
        if(rows.length&&rows.some(feroxType))return parseFeroxbusterJson(rows,{filename});
      }catch(error){
        if(raw.trim().split(/\r?\n/).length>1)throw error;
      }
    }
    if(lower.endsWith(".json")||/^\s*\{/.test(raw)||/^\s*\[\s*(?:\{|\])/.test(raw)){
      let data;try{data=JSON.parse(raw);}catch(error){throw new Error(`The selected JSON is invalid: ${error.message}`);}
      const rows=Array.isArray(data)?data:Array.isArray(data?.results)?data.results:[data],ferox=lower.includes("ferox")||rows.some(row=>feroxType(row)||row?.content_length!==undefined&&row?.type!==undefined);
      if(ferox)return parseFeroxbusterJson(data,{filename});
      return parseFfufJson(data,{filename});
    }
    if(feroxbusterTextStructure(raw,filename))return parseFeroxbusterText(raw,{filename,baseUrl});
    if(/dirsearch/i.test(raw)||/^\s*\[[^\]]+\]\s*Starting\s*:\s*https?:\/\//im.test(raw))return parseDirsearchText(raw,{filename,baseUrl});
    if(/\bDirBuster\b/i.test(raw)||/^\s*(?:Dir|File) found\s*:/im.test(raw))return parseDirbusterText(raw,{filename,baseUrl});
    if(/gobuster/i.test(raw)||/^\s*(?:\/\S+\s+\(Status:|Found:\s*)/im.test(raw))return parseGobusterText(raw,{filename,baseUrl});
    if(/^\s*DIRB\s+v?\d/im.test(raw)||/^\s*(?:URL_BASE|START_TIME|END_TIME|DOWNLOADED)\s*:/im.test(raw))return parseDirbText(raw,{filename,baseUrl});
    return parseWebTargetList(raw,{filename,baseUrl});
  }
  function webDiscoveryOrigins(parsed={}){
    const origins=[];
    const add=value=>{const origin=normalizedWebOrigin(value);if(origin&&!origins.includes(origin))origins.push(origin);};
    add(parsed.baseUrl);
    (parsed.records||[]).forEach(record=>add(record.origin||record.url));
    return origins;
  }
  function detectWebDiscovery(text,{filename="",baseUrl=""}={}){
    try{
      const parsed=parseWebDiscovery(text,{filename,baseUrl});
      const origins=webDiscoveryOrigins(parsed),pathOnly=(parsed.records||[]).some(row=>row.unresolved===true);
      return {
        matched:true,
        parser:parsed.format,
        tool:parsed.tool,
        origins,
        pathOnly,
        operationState:parsed.operationState||"partial",
        command:parsed.command||"",
        totalInput:Number(parsed.totalInput)||0,
        resultCount:(parsed.records||[]).length
      };
    }catch(error){
      return {matched:false,reason:error.message,parser:"",tool:"",origins:[],pathOnly:false,operationState:"invalid",totalInput:0,resultCount:0};
    }
  }
  function webBaselineSampleShape(path=""){
    const value=boundedText(path,2048)||"/";
    if(value.endsWith("/"))return "directory";
    const leaf=value.split("/").filter(Boolean).at(-1)||"";
    return /[.][a-z0-9][a-z0-9._-]*$/i.test(leaf)?"extension":"bare";
  }
  function webBaselineRedirectPattern(redirect="",path=""){
    let value=boundedText(redirect,4096);if(!value)return "";
    const cleanPath=boundedText(path,2048),variants=[cleanPath];
    try{variants.push(encodeURI(cleanPath),encodeURIComponent(cleanPath));}catch(_error){}
    const token=cleanPath.replace(/^\/+|\/+$/g,"").split("/").at(-1)||"";
    if(token.length>=4){variants.push(token);try{variants.push(encodeURIComponent(token));}catch(_error){}}
    [...new Set(variants.filter(Boolean))].sort((a,b)=>b.length-a.length).forEach(candidate=>{value=value.split(candidate).join("<requested-path>");});
    return value;
  }
  function webBaselineSignature(sample={}){
    return [sample.status,sample.bytes,sample.words,sample.lines,String(sample.contentType||"").toLowerCase(),sample.redirectPattern||""].join("|");
  }
  function webBaselineShapeSummary(shape,samples=[]){
    const values=key=>[...new Set(samples.map(row=>String(row[key]??"")))];
    const statuses=values("status").map(Number),bytes=values("bytes").map(Number),words=values("words").map(Number),lines=values("lines").map(Number),contentTypes=values("contentType").filter(Boolean),redirectPatterns=values("redirectPattern").filter(Boolean);
    const stable=[statuses,bytes,words,lines,values("contentType"),values("redirectPattern")].every(group=>group.length<=1);
    return {shape,count:samples.length,stable,statuses,bytes,words,lines,contentTypes,redirectPatterns,signatureCount:new Set(samples.map(webBaselineSignature)).size};
  }
  function webBaselineOptions(classification,shapes,samples){
    const allStable=shapes.every(row=>row.stable),allBytes=[...new Set(samples.map(row=>row.bytes))],allWords=[...new Set(samples.map(row=>row.words))],allLines=[...new Set(samples.map(row=>row.lines))];
    let ffuf='-ac',ferox='--auto-tune',guidance=[];
    if(classification==="normal-not-found"){
      ferox='--auto-tune -C 404';
      guidance.push("Invalid paths consistently return 404; the Feroxbuster command can exclude 404 responses.");
    }else if(classification==="soft-404"&&allStable){
      if(allWords.length===1&&Number(allWords[0])>0){ffuf=`-fw ${allWords[0]}`;ferox=`--auto-tune -W ${allWords[0]}`;}
      else if(allBytes.length===1&&Number(allBytes[0])>0){ffuf=`-fs ${allBytes[0]}`;ferox=`--auto-tune -S ${allBytes[0]}`;}
      else if(allLines.length===1&&Number(allLines[0])>0){ffuf=`-fl ${allLines[0]}`;ferox=`--auto-tune -N ${allLines[0]}`;}
      else ffuf='-ac -ach -acc "aeros-baseline-route" -acc "aeros-baseline-directory/" -acc "aeros-baseline-file.txt"';
      guidance.push("The origin returns a successful catch-all response; use the retained response metric as an explicit filter and verify any zero-result scan.");
    }else if(["wildcard-authentication-redirect","wildcard-redirect","shape-dependent-invalid-response","dynamic-invalid-response","mixed-invalid-response"].includes(classification)){
      ffuf='-ac -ach -acc "aeros-baseline-route" -acc "aeros-baseline-directory/" -acc "aeros-baseline-file.txt"';
      guidance.push("Invalid-path behavior is redirecting, dynamic, or shape-dependent; use per-host custom calibration for all three path shapes.");
      if(samples.every(row=>row.bytes===0))guidance.push("No zero-byte size filter was generated because it could hide legitimate bodyless endpoints.");
      guidance.push("Feroxbuster keeps automatic tuning without an unsafe blanket status or zero-byte filter; compare retained redirects manually.");
    }else if(classification==="wildcard-access-denied"){
      ffuf='-ac -ach -acc "aeros-baseline-route" -acc "aeros-baseline-directory/" -acc "aeros-baseline-file.txt"';
      guidance.push("Invalid paths return access-control responses; do not discard every 401 or 403 because real protected resources can look identical.");
    }
    guidance.push("AEROS compares imported FFUF and Feroxbuster results with the matching path-shape signature, labels baseline-like rows, keeps them visible, and prevents them from automatically activating evidence-led follow-up tasks.");
    return {ffufOptions:ffuf,feroxOptions:ferox,guidance};
  }
  function parseWebBaseline(text,{filename=""}={}){
    const raw=String(text??"").replace(/\r\n?/g,"\n");if(!raw.trim())throw new Error("The selected baseline file is empty.");
    const records=[],origins=[];let round=0,recognized=0;
    const linePattern=/^\s*(\/\S+)\s+status=(\d{3})\s+bytes=(\d+)\s+type=(.*?)\s+redirect=(.*?)\s+words=(\d+)\s+lines=(\d+)\s*$/;
    raw.split("\n").forEach(sourceLine=>{
      const roundMatch=/^\s*Round\s+(\d+)\s*$/i.exec(sourceLine);if(roundMatch){round=Number(roundMatch[1])||0;return;}
      const match=linePattern.exec(sourceLine);if(!match)return;recognized++;
      const path=boundedText(match[1],2048),redirect=boundedText(match[5],4096),origin=normalizedWebOrigin(redirect);
      if(origin&&!origins.includes(origin))origins.push(origin);
      records.push({
        key:`baseline:${round}:${path}`,
        round,
        path,
        shape:webBaselineSampleShape(path),
        status:Number(match[2]),
        bytes:Number(match[3]),
        contentType:boundedText(match[4],512),
        redirect,
        redirectPattern:webBaselineRedirectPattern(redirect,path),
        words:Number(match[6]),
        lines:Number(match[7])
      });
    });
    if(!recognized)throw new Error("The text does not contain recognizable AEROS invalid-path baseline measurements.");
    const shapeOrder=["bare","directory","extension"],shapes=shapeOrder.map(shape=>webBaselineShapeSummary(shape,records.filter(row=>row.shape===shape)));
    const complete=shapes.every(row=>row.count>=2),allStatuses=records.map(row=>row.status),allRedirects=records.map(row=>row.redirect).filter(Boolean),allStable=shapes.every(row=>row.count&&row.stable);
    let classification="mixed-invalid-response";
    if(allStatuses.every(code=>code===404))classification="normal-not-found";
    else if(allStatuses.every(code=>code===200))classification="soft-404";
    else if(allStatuses.every(code=>code===401||code===403))classification="wildcard-access-denied";
    else if(allStatuses.every(code=>code>=300&&code<400)&&allRedirects.length===records.length){
      classification=allRedirects.every(value=>/(?:login|signin|sign-in|auth|permissionviolation)/i.test(value))?"wildcard-authentication-redirect":"wildcard-redirect";
    }else if(shapes.some(row=>row.count&&!row.stable))classification="dynamic-invalid-response";
    else if(allStable&&new Set(shapes.map(row=>row.count?webBaselineSignature(records.find(sample=>sample.shape===row.shape)):"")).size>1)classification="shape-dependent-invalid-response";
    const labels={
      "normal-not-found":"Normal 404 response",
      "soft-404":"Soft 404 / successful catch-all",
      "wildcard-access-denied":"Wildcard access-control response",
      "wildcard-authentication-redirect":"Wildcard authentication redirect",
      "wildcard-redirect":"Wildcard redirect",
      "dynamic-invalid-response":"Dynamic invalid-path response",
      "shape-dependent-invalid-response":"Shape-dependent invalid-path response",
      "mixed-invalid-response":"Mixed invalid-path response"
    };
    const confidence=complete&&allStable?"high":shapes.every(row=>row.count)?"medium":"low";
    const options=webBaselineOptions(classification,shapes,records);
    const summary=`${records.length} sample${records.length===1?"":"s"}; ${shapes.map(row=>`${row.shape} ${row.count}/${row.stable?"stable":"variable"}`).join(", ")}.`;
    return {
      format:"aeros-web-baseline-text",
      tool:"curl baseline",
      filename:boundedText(filename,512),
      operationState:complete?"completed":"partial",
      classification,
      classificationLabel:labels[classification]||classification,
      confidence,
      summary,
      origins,
      sampleCount:records.length,
      shapes,
      records,
      ffufOptions:options.ffufOptions,
      feroxOptions:options.feroxOptions,
      guidance:options.guidance,
      warnings:complete?[]:["All three path shapes need at least two samples before the baseline can complete the objective."]
    };
  }
  function detectWebBaseline(text,{filename=""}={}){
    try{
      const parsed=parseWebBaseline(text,{filename});
      return {matched:true,parser:parsed.format,tool:parsed.tool,origins:parsed.origins,operationState:parsed.operationState,classification:parsed.classification,classificationLabel:parsed.classificationLabel,confidence:parsed.confidence,sampleCount:parsed.sampleCount};
    }catch(error){return {matched:false,reason:error.message,parser:"",tool:"",origins:[],operationState:"invalid",classification:"",classificationLabel:"",confidence:"none",sampleCount:0};}
  }

  const WHATWEB_NON_IDENTITY_PLUGINS=new Set([
    "country","email","httpstatus","ip","redirectlocation","redirect","title","uncommonheaders",
    "cookies","cookie","httponly","html5","indexof","opensearch","passwordfield","script",
    "xframeoptions","xuacompatible","xxssprotection","xcontenttypeoptions","contentsecuritypolicy",
    "xaccelbuffering"
  ]);
  function whatWebPluginKey(name=""){return boundedText(name,160).toLowerCase().replace(/[^a-z0-9]/g,"");}
  function technologyCategory(name="",raw={}){
    const explicit=boundedText(raw?.category||raw?.type,40).toLowerCase();
    if(["application","cms","framework","language","library","platform","server","technology"].includes(explicit))return explicit;
    const value=boundedText(name,160).toLowerCase();
    if(/(?:wordpress|drupal|joomla|confluence|sharepoint|ghost|typo3)/.test(value))return "cms";
    if(/(?:tomcat|apache|nginx|iis|jetty|caddy|httpserver|webserver)/.test(value))return "server";
    if(/(?:php|java|python|ruby|perl|asp[.]?net|node[.]?js)/.test(value))return "language";
    if(/(?:jquery|bootstrap|react|angular|vue|prototype|mootools)/.test(value))return "library";
    if(/(?:spring|django|rails|laravel|express)/.test(value))return "framework";
    if(/(?:linux|windows|ubuntu|debian|centos|freebsd)/.test(value))return "platform";
    return "technology";
  }
  function whatWebTechnology(name,raw={}){
    const label=boundedText(name,160);if(!label)return null;
    const pluginKey=whatWebPluginKey(label);if(WHATWEB_NON_IDENTITY_PLUGINS.has(pluginKey))return null;
    const values=value=>(Array.isArray(value)?value:[value]).map(item=>boundedText(item,512)).filter(Boolean);
    const versions=values(raw&&typeof raw==="object"?raw.version:"");
    const strings=values(raw&&typeof raw==="object"?raw.string:typeof raw==="string"?raw:"");
    const explicitState=boundedText(raw&&typeof raw==="object"?(raw.state||raw.identityState):"",32).toLowerCase();
    const state=["positive","candidate","clue-only","conflicting"].includes(explicitState)?explicitState:(pluginKey==="java"&&!versions.length&&!strings.length?"clue-only":"positive");
    return {name:label,version:versions[0]||"",category:technologyCategory(label,raw),state,details:strings.slice(0,12)};
  }
  function whatWebPluginDetails(plugins={},names=[]){
    if(!plugins||typeof plugins!=="object"||Array.isArray(plugins))return [];
    const wanted=new Set(names.map(name=>String(name||"").toLowerCase().replace(/[^a-z0-9]/g,""))),output=[];
    Object.entries(plugins).forEach(([name,raw])=>{
      if(!wanted.has(String(name||"").toLowerCase().replace(/[^a-z0-9]/g,"")))return;
      const value=raw&&typeof raw==="object"&&!Array.isArray(raw)?raw:{};
      for(const candidate of [...(Array.isArray(value.string)?value.string:[value.string]),...(Array.isArray(value.version)?value.version:[value.version])]){
        const detail=boundedText(candidate,2048);if(detail&&!output.includes(detail))output.push(detail);
      }
    });
    return output.slice(0,32);
  }
  function whatWebHasPlugin(plugins={},name=""){
    const wanted=whatWebPluginKey(name);return Object.keys(plugins&&typeof plugins==="object"&&!Array.isArray(plugins)?plugins:{}).some(key=>whatWebPluginKey(key)===wanted);
  }
  function whatWebObservedHeaders(plugins={}){
    const output=[];
    whatWebPluginDetails(plugins,["uncommonheaders"]).forEach(value=>String(value).split(",").forEach(name=>{const item=boundedText(name,160);if(item&&!output.includes(item))output.push(item);}));
    [["xframeoptions","X-Frame-Options"],["xxssprotection","X-XSS-Protection"],["xcontenttypeoptions","X-Content-Type-Options"],["contentsecuritypolicy","Content-Security-Policy"],["xuacompatible","X-UA-Compatible"],["xaccelbuffering","X-Accel-Buffering"]].forEach(([plugin,label])=>{if(whatWebHasPlugin(plugins,plugin)&&!output.some(value=>value.toLowerCase()===label.toLowerCase()))output.push(label);});
    return output.slice(0,32);
  }
  function whatWebSecurityHeaders(plugins={}){
    return [["xframeoptions","X-Frame-Options"],["xxssprotection","X-XSS-Protection"],["xcontenttypeoptions","X-Content-Type-Options"],["contentsecuritypolicy","Content-Security-Policy"],["xuacompatible","X-UA-Compatible"],["xaccelbuffering","X-Accel-Buffering"]].flatMap(([plugin,label])=>{
      const details=whatWebPluginDetails(plugins,[plugin]);return details.length?details.map(value=>({name:label,value})):whatWebHasPlugin(plugins,plugin)?[{name:label,value:"Observed"}]:[];
    }).slice(0,32);
  }
  function whatWebPageCharacteristics(plugins={}){
    const output=[];
    if(whatWebHasPlugin(plugins,"html5"))output.push("HTML5 document");
    const scripts=whatWebPluginDetails(plugins,["script"]);if(scripts.length)output.push(`Script types: ${scripts.join(", ")}`);
    return output.slice(0,16);
  }
  function whatWebWeakClues(plugins={}){
    const output=[];if(whatWebHasPlugin(plugins,"indexof"))output.push("Possible directory-listing pattern; manual confirmation required.");return output;
  }
  function whatWebDiscoveredRoutes(plugins={},origin=""){
    const output=[],seen=new Set();
    whatWebPluginDetails(plugins,["opensearch"]).forEach(candidate=>{
      try{const parsed=new URL(candidate,origin);if(parsed.origin!==origin)return;const url=parsed.toString(),key=`GET|${url}`;if(seen.has(key))return;seen.add(key);output.push({url,path:parsed.pathname||"/",method:"GET",kind:"opensearch",status:null,notes:"Discovered by the WhatWeb OpenSearch plugin; this route was not independently requested."});}catch{}
    });
    return output.slice(0,32);
  }
  function whatWebInputs(plugins={},targetUrl=""){
    return whatWebPluginDetails(plugins,["passwordfield"]).slice(0,32).map(name=>({name,type:"password",location:"body",pageUrl:targetUrl,reviewState:"mapped",coverageEligible:false,notes:"WhatWeb observed a password field name. The form method and action remain unconfirmed."}));
  }
  function dedupeWhatWebTechnologies(rows=[]){
    const seen=new Set(),output=[];
    for(const row of rows){
      if(!row?.name)continue;
      const key=[row.name.toLowerCase(),boundedText(row.version,160).toLowerCase(),boundedText(row.category,40).toLowerCase(),boundedText(row.state,32).toLowerCase()].join("|");
      if(seen.has(key))continue;seen.add(key);output.push({...row,state:boundedText(row.state,32)||"positive",details:(row.details||[]).slice(0,12)});
      if(output.length>=MAX_WHATWEB_TECHNOLOGIES_PER_RECORD)break;
    }
    return output.sort((left,right)=>left.name.localeCompare(right.name)||left.version.localeCompare(right.version));
  }
  function explicitWhatWebOperationState(data={}){
    const status=boundedText(data?.operationState||data?.operation_status||(typeof data?.status==="string"?data.status:""),40).toLowerCase();
    const error=boundedText(data?.error||data?.failure,2048);
    if(["error","failed","failure"].includes(status))return "failed";
    if(data?.partial===true||["partial","incomplete"].includes(status))return "partial";
    if(error)return "failed";
    if(data?.completed===false||data?.complete===false)return "partial";
    if(["conflict","conflicting"].includes(status))return "conflicting";
    if(status==="deferred")return "deferred";
    if(data?.completed===true||data?.complete===true||["complete","completed","success","successful"].includes(status))return "completed";
    return "";
  }
  function normalizedWhatWebReviewState(value="",fallback="current"){
    const state=boundedText(value,32).toLowerCase();
    return ["current","reviewed","stale","conflicting","deferred"].includes(state)?state:fallback;
  }
  function whatWebRecord(raw={},index=0){
    if(!raw||typeof raw!=="object"||Array.isArray(raw))throw new Error(`WhatWeb JSON result ${index+1} is malformed.`);
    const normalized=normalizedWebUrl(raw.target||raw.url);if(!normalized)throw new Error(`WhatWeb JSON result ${index+1} has no supported exact HTTP(S) target URL.`);
    const plugins=raw.plugins;
    if(!plugins||typeof plugins!=="object"||Array.isArray(plugins))throw new Error(`WhatWeb JSON result ${index+1} has no plugin object.`);
    const technologies=dedupeWhatWebTechnologies(Object.entries(plugins).map(([name,value])=>whatWebTechnology(name,value)).filter(Boolean));
    const title=whatWebPluginDetails(plugins,["title"])[0]||"",redirect=whatWebPluginDetails(plugins,["redirectlocation","redirect"])[0]||"",serverHeader=whatWebPluginDetails(plugins,["httpserver","server"])[0]||"";
    const cookieNames=whatWebPluginDetails(plugins,["cookies","cookie"]),httpOnlyNames=new Set(whatWebPluginDetails(plugins,["httponly"]).map(value=>value.toLowerCase()));
    const cookies=[...new Set(cookieNames.map(name=>httpOnlyNames.has(name.toLowerCase())?`${name} (HttpOnly)`:name))].slice(0,32);
    const operationState=explicitWhatWebOperationState(raw)||"completed",reviewState=normalizedWhatWebReviewState(raw.reviewState);
    return {
      key:`whatweb:${normalized.key}`,targetUrl:normalized.url,origin:normalized.origin,scheme:normalized.scheme,host:normalized.host,port:normalized.port,path:normalized.path,
      sourceOrigin:normalized.origin,status:finiteInteger(raw.http_status??raw.status,{min:100,max:599}),operationState,operationExplicit:Boolean(explicitWhatWebOperationState(raw)),reviewState,
      resultCount:technologies.length,error:boundedText(raw.error||raw.failure,2048),duplicateCount:1,title,redirect,serverHeader,cookies,
      observedHeaders:whatWebObservedHeaders(plugins),securityHeaders:whatWebSecurityHeaders(plugins),pageCharacteristics:whatWebPageCharacteristics(plugins),weakClues:whatWebWeakClues(plugins),
      discoveredRoutes:whatWebDiscoveredRoutes(plugins,normalized.origin),inputs:whatWebInputs(plugins,normalized.url),technologies
    };
  }
  function whatWebOperationState(data,records=[]){
    const explicit=explicitWhatWebOperationState(data);if(explicit&&explicit!=="completed")return explicit;
    if(records.some(row=>row?.operationState==="conflicting"))return "conflicting";
    if(records.some(row=>row?.operationState==="failed"))return "failed";
    if(records.some(row=>row?.operationState==="partial"))return "partial";
    if(records.some(row=>row?.operationState==="deferred"))return "deferred";
    return "completed";
  }
  function whatWebRecordSignature(row={}){
    const technologies=dedupeWhatWebTechnologies(row.technologies||[]).map(item=>[item.name.toLowerCase(),boundedText(item.version,160).toLowerCase(),boundedText(item.category,40).toLowerCase(),(item.details||[]).map(value=>boundedText(value,512)).sort()].join("~")).sort();
    const metadata=[row.observedHeaders,row.securityHeaders,row.pageCharacteristics,row.weakClues,row.discoveredRoutes,row.inputs].map(value=>JSON.stringify(value||[])).join("||");
    return [boundedText(row.targetUrl||row.url,2048).toLowerCase(),boundedText(row.operationState,32).toLowerCase(),boundedText(row.reviewState,32).toLowerCase(),String(row.status??""),boundedText(row.error,2048),boundedText(row.title,2048),boundedText(row.redirect,2048),boundedText(row.serverHeader,2048),(row.cookies||[]).map(value=>boundedText(value,256)).sort().join("~"),metadata,technologies.join("||")].join("|");
  }
  function dedupeWhatWebRecords(rows=[]){
    const byKey=new Map(),output=[];
    for(const raw of rows){
      if(!raw?.targetUrl)continue;
      const row={...raw,technologies:dedupeWhatWebTechnologies(raw.technologies||[]),duplicateCount:Math.max(1,Number(raw.duplicateCount)||1)};
      const key=whatWebRecordSignature(row),existing=byKey.get(key);
      if(existing){existing.duplicateCount+=row.duplicateCount;continue;}
      byKey.set(key,row);output.push(row);
      if(output.length>=MAX_WHATWEB_RECORDS)break;
    }
    return output;
  }
  function whatWebVerbosePositionalRecord(value){
    return Array.isArray(value)&&value.length>=3&&typeof value[0]==="string"&&Boolean(normalizedWebUrl(value[0]))&&finiteInteger(value[1],{min:100,max:599})!==null&&Array.isArray(value[2]);
  }
  function whatWebVerboseJsonPayload(value){
    return whatWebVerbosePositionalRecord(value)||(Array.isArray(value)&&value.length>0&&value.every(whatWebVerbosePositionalRecord));
  }
  function parseWhatWebJson(raw,{filename=""}={}){
    let data;
    try{data=JSON.parse(raw);}
    catch(error){
      const lines=String(raw).replace(/\r\n?/g,"\n").split("\n").map(line=>line.trim()).filter(Boolean);
      let parsedLines=[];
      if(lines.length>=2&&lines.length<=MAX_WHATWEB_RECORDS){try{parsedLines=lines.map(line=>JSON.parse(line));}catch(_lineError){parsedLines=[];}}
      if(parsedLines.length&&parsedLines.every(whatWebVerbosePositionalRecord))throw new Error("WhatWeb verbose JSON is not supported. Generate standard output with --log-json.");
      if(!parsedLines.length||!parsedLines.every(line=>line&&typeof line==="object"&&!Array.isArray(line)))throw new Error("The WhatWeb JSON is invalid or malformed.");
      data=parsedLines;
    }
    if(whatWebVerboseJsonPayload(data))throw new Error("WhatWeb verbose JSON is not supported. Generate standard output with --log-json.");
    let rows=[];
    if(Array.isArray(data))rows=data;
    else if(data&&typeof data==="object"&&Array.isArray(data.results)&&/whatweb/i.test([data.tool,data.scanner,data.generator,data.command,data.commandline].join(" ")))rows=data.results;
    else if(data&&typeof data==="object"&&data.target&&data.plugins&&typeof data.plugins==="object")rows=[data];
    else throw new Error("This JSON does not contain supported WhatWeb target/plugin structure.");
    if(!rows.length)throw new Error("WhatWeb JSON contains no exact HTTP(S) target record.");
    if(rows.length>MAX_WHATWEB_RECORDS)throw new Error(`WhatWeb JSON exceeds the ${MAX_WHATWEB_RECORDS}-record limit.`);
    const sourceExplicit=explicitWhatWebOperationState(data),records=dedupeWhatWebRecords(rows.map(whatWebRecord).map(row=>sourceExplicit&&sourceExplicit!=="completed"&&!row.operationExplicit?{...row,operationState:sourceExplicit,error:row.error||boundedText(data?.error||data?.failure,2048)}:row)),operationState=whatWebOperationState(data,records);
    const resultCount=records.reduce((total,row)=>total+row.technologies.length,0);
    return {format:"whatweb-json",tool:"WhatWeb",filename:boundedText(filename,512),operationState,records,resultCount,totalInput:rows.length,error:boundedText(data?.error||data?.failure,2048)};
  }
  function splitWhatWebTokens(value=""){
    const rows=[];let current="",depth=0;
    for(const character of String(value)){
      if(character==="[")depth++;
      if(character==="]"&&depth>0)depth--;
      if(character===","&&depth===0){if(current.trim())rows.push(current.trim());current="";continue;}
      current+=character;
    }
    if(current.trim())rows.push(current.trim());return rows;
  }
  function whatWebTextToken(token=""){
    const plugin=/^([^\[\]]{1,160})(?:\[([^\]]*)\])?$/.exec(String(token||"").trim());if(!plugin)return null;
    const detail=boundedText(plugin[2],512),version=/^(?:v(?:ersion)?\s*)?([0-9]+(?:[.][0-9A-Za-z_-]+)*)$/i.exec(detail)?.[1]||"";
    return {name:boundedText(plugin[1],160),detail,technology:whatWebTechnology(plugin[1],{version:version?[version]:[],string:detail?[detail]:[]})};
  }
  function parseWhatWebVerboseText(raw,{filename=""}={}){
    const normalizedText=String(raw).replace(/\r\n?/g,"\n").replace(/\x1b\[[0-9;]*m/g,""),lines=normalizedText.split("\n"),starts=[];
    lines.forEach((line,index)=>{if(/^\s*WhatWeb report for\s+https?:\/\/\S+/i.test(line))starts.push(index);});
    if(!starts.length)throw new Error("This text does not contain a recognizable WhatWeb verbose report.");
    if(starts.length>MAX_WHATWEB_RECORDS)throw new Error(`WhatWeb verbose text exceeds the ${MAX_WHATWEB_RECORDS}-report limit.`);
    starts.push(lines.length);const records=[];
    for(let blockIndex=0;blockIndex<starts.length-1;blockIndex++){
      const block=lines.slice(starts[blockIndex],starts[blockIndex+1]),header=/^\s*WhatWeb report for\s+(https?:\/\/\S+)\s*$/i.exec(block[0]),normalized=normalizedWebUrl(header?.[1]);
      if(!normalized)throw new Error(`WhatWeb verbose report ${blockIndex+1} has no supported exact HTTP(S) target URL.`);
      const field=name=>{const pattern=new RegExp(`^\\s*${name}\\s*:\\s*(.*?)\\s*$`,"i");for(const line of block){const match=pattern.exec(line);if(match)return boundedText(match[1],2048);}return "";};
      const status=finiteInteger((/^\s*(\d{3})\b/.exec(field("Status"))||[])[1],{min:100,max:599}),summary=field("Summary"),tokens=splitWhatWebTokens(summary).map(whatWebTextToken).filter(Boolean),pluginRows=[];
      let current=null,insidePlugins=false;
      const flush=()=>{if(current){pluginRows.push(whatWebTechnology(current.name,{version:current.versions,string:current.strings}));current=null;}};
      for(const line of block){
        if(/^\s*Detected Plugins\s*:/i.test(line)){insidePlugins=true;continue;}if(!insidePlugins)continue;
        const heading=/^\s*\[\s*([^\]]{1,160})\s*\]\s*$/.exec(line);if(heading){flush();current={name:heading[1],versions:[],strings:[]};continue;}
        const property=/^\s*(Version|String)\s*:\s*(.*?)\s*$/i.exec(line);if(!property||!current)continue;
        const value=boundedText(property[2],512);if(!value)continue;if(property[1].toLowerCase()==="version")current.versions.push(value);else current.strings.push(value);
      }
      flush();
      const technologies=dedupeWhatWebTechnologies([...tokens.map(row=>row.technology),...pluginRows].filter(Boolean)),errorLine=block.map(line=>line.trim()).find(line=>/^(?:error|fatal)\s*:|connection\s+(?:refused|reset|failed)|timed?\s*out|unable\s+to\s+connect/i.test(line))||"",operationState=errorLine?(status?"partial":"failed"):(status?"completed":"partial");
      const tokenDetail=name=>tokens.find(row=>row.name.toLowerCase().replace(/[^a-z0-9]/g,"")===name)?.detail||"";
      records.push({key:`whatweb:${normalized.key}`,targetUrl:normalized.url,origin:normalized.origin,sourceOrigin:normalized.origin,scheme:normalized.scheme,host:normalized.host,port:normalized.port,path:normalized.path,status,operationState,operationExplicit:true,reviewState:"current",resultCount:technologies.length,error:boundedText(errorLine,2048),duplicateCount:1,title:field("Title")||tokenDetail("title"),redirect:field("RedirectLocation")||field("Redirect")||tokenDetail("redirectlocation"),serverHeader:field("HTTPServer")||field("Server")||tokenDetail("httpserver"),cookies:tokens.filter(row=>["cookie","cookies"].includes(row.name.toLowerCase().replace(/[^a-z0-9]/g,""))).map(row=>row.detail).filter(Boolean).slice(0,32),technologies});
    }
    const deduped=dedupeWhatWebRecords(records),operationState=whatWebOperationState({},deduped),resultCount=deduped.reduce((total,row)=>total+row.technologies.length,0),error=boundedText([...new Set(deduped.map(row=>row.error).filter(Boolean))].join(" | "),2048);
    return {format:"whatweb-verbose-text",tool:"WhatWeb",filename:boundedText(filename,512),operationState,records:deduped,resultCount,totalInput:records.length,error};
  }
  function parseWhatWebText(raw,{filename=""}={}){
    const lines=String(raw).replace(/\r\n?/g,"\n").split("\n").map(line=>line.trim()).filter(Boolean);
    if(!lines.length)throw new Error("The selected WhatWeb text is empty.");
    if(lines.length>MAX_WHATWEB_RECORDS)throw new Error(`WhatWeb text exceeds the ${MAX_WHATWEB_RECORDS}-line limit.`);
    const records=[],globalMarkers=[];
    lines.forEach((line,index)=>{
      const match=/^(https?:\/\/\S+)\s+\[(\d{3})(?:\s+[^\]]*)?\]\s*(.*)$/i.exec(line);
      if(!match){
        if(/^(?:error|fatal|whatweb\s+error)\b|connection\s+(?:refused|reset|failed)|timed?\s*out|timeout|unable\s+to\s+connect/i.test(line)){globalMarkers.push({state:"failed",error:boundedText(line,2048)});return;}
        if(/^(?:whatweb\b|partial\b|incomplete\b)/i.test(line)){globalMarkers.push({state:"partial",error:boundedText(line,2048)});return;}
        throw new Error(`WhatWeb text line ${index+1} is malformed or unsupported.`);
      }
      const normalized=normalizedWebUrl(match[1]);if(!normalized)throw new Error(`WhatWeb text line ${index+1} has an invalid target URL.`);
      const tokens=splitWhatWebTokens(match[3]).map(whatWebTextToken).filter(Boolean),technologies=dedupeWhatWebTechnologies(tokens.map(row=>row.technology).filter(Boolean)),tokenDetail=name=>tokens.find(row=>row.name.toLowerCase().replace(/[^a-z0-9]/g,"")===name)?.detail||"";
      records.push({key:`whatweb:${normalized.key}`,targetUrl:normalized.url,origin:normalized.origin,sourceOrigin:normalized.origin,scheme:normalized.scheme,host:normalized.host,port:normalized.port,path:normalized.path,status:Number(match[2]),operationState:"completed",operationExplicit:true,reviewState:"current",resultCount:technologies.length,error:"",duplicateCount:1,title:tokenDetail("title"),redirect:tokenDetail("redirectlocation"),serverHeader:tokenDetail("httpserver"),cookies:tokens.filter(row=>["cookie","cookies"].includes(row.name.toLowerCase().replace(/[^a-z0-9]/g,""))).map(row=>row.detail).filter(Boolean).slice(0,32),technologies});
    });
    const globalState=globalMarkers.some(row=>row.state==="failed")?"failed":globalMarkers.some(row=>row.state==="partial")?"partial":"",globalError=boundedText([...new Set(globalMarkers.map(row=>row.error).filter(Boolean))].join(" | "),2048);
    if(!records.length&&globalState==="failed")throw new Error("WhatWeb text records a failed run without one exact retained target.");
    if(!records.length)throw new Error("This text does not contain supported WhatWeb one-result-per-target structure.");
    const deduped=dedupeWhatWebRecords(records).map(row=>globalState?{...row,operationState:globalState,operationExplicit:false,error:row.error||globalError}:row),operationState=globalState||"completed",resultCount=deduped.reduce((total,row)=>total+row.technologies.length,0);
    return {format:"whatweb-text",tool:"WhatWeb",filename:boundedText(filename,512),operationState,records:deduped,resultCount,totalInput:records.length,error:globalError};
  }
  function parseWhatWeb(text,{filename=""}={}){
    const raw=String(text??"");if(!raw.trim())throw new Error("The selected WhatWeb output is empty.");
    if(new TextEncoder().encode(raw).length>MAX_WEB_IMPORT_BYTES)throw new Error("WhatWeb output exceeds the 25 MB retained-input limit.");
    if(/^\s*[\[{]/.test(raw))return parseWhatWebJson(raw,{filename});
    if(/^\s*WhatWeb report for\s+https?:\/\//im.test(raw))return parseWhatWebVerboseText(raw,{filename});
    return parseWhatWebText(raw,{filename});
  }
  function detectWhatWeb(text,{filename=""}={}){
    try{
      const parsed=parseWhatWeb(text,{filename}),origins=[...new Set(parsed.records.map(row=>row.origin).filter(Boolean))];
      return {matched:true,parser:parsed.format,tool:"WhatWeb",origins,operationState:parsed.operationState,resultCount:parsed.resultCount,totalInput:parsed.totalInput};
    }catch(error){const verboseJson=error.message==="WhatWeb verbose JSON is not supported. Generate standard output with --log-json.";return {matched:false,reason:error.message,parser:verboseJson?"whatweb-json-verbose":"",unsupportedFormat:verboseJson?"whatweb-json-verbose":"",tool:"WhatWeb",origins:[],operationState:"invalid",resultCount:0,totalInput:0};}
  }
  function webMethodDisposition(operationState="",resultCount=0,{changedRevision=false}={}){
    if(changedRevision)return "stale";
    const operation=boundedText(operationState,32).toLowerCase();
    if(operation==="completed")return Number(resultCount)>0?"complete":"negative";
    if(operation==="failed")return "failed";
    if(operation==="partial")return "partial";
    return "in-progress";
  }
  function webObservationKey(source={}){
    return [source.contributionKey,source.artifactId,source.revision,source.sha256,source.status,source.length,source.words,source.lines,source.redirect].map(value=>String(value??"")).join("|");
  }
  function mergeWebTargets(existing=[],incoming=[],{source={},observedAt="",idFactory}={}){
    const at=boundedText(observedAt,64)||new Date().toISOString(),rows=(Array.isArray(existing)?existing:[]).filter(row=>row&&typeof row==="object").map(row=>({...row,sources:Array.isArray(row.sources)?row.sources.slice(-MAX_WEB_SOURCE_OBSERVATIONS):[]}));
    const byKey=new Map(rows.map(row=>[String(row.key||""),row]));
    for(const raw of dedupeWebRecords(incoming)){
      let row=byKey.get(raw.key);
      const observation={
        contributionKey:boundedText(source.contributionKey,512),
        artifactId:boundedText(source.artifactId,256),
        revision:contributionRevision(source),
        sha256:boundedText(source.sha256,64).toLowerCase(),
        filename:boundedText(source.filename,512),
        tool:boundedText(source.tool||raw.tool,64),
        objectiveId:boundedText(source.objectiveId||raw.objectiveId,160),
        originId:boundedText(source.originId||raw.originId,256),
        endpointId:boundedText(source.endpointId||raw.endpointId,256),
        command:boundedText(source.command||raw.command,4096),
        wordlist:boundedText(source.wordlist||raw.wordlist,2048),
        observedAt:at,
        status:raw.status,
        length:raw.length,
        words:raw.words,
        lines:raw.lines,
        contentType:raw.contentType||"",
        redirect:raw.redirect||""
      };
      if(!row){
        row={...raw,id:typeof idFactory==="function"?idFactory(raw):stableWebTargetId(raw.key),firstSeenAt:at,lastSeenAt:at,sources:[observation]};
        rows.push(row);byKey.set(raw.key,row);continue;
      }
      const importedOverlay=raw.sourceOwner==="web-discovery-import"&&row.sourceOwner!=="web-discovery-import";
      if(!importedOverlay){
        row.lastSeenAt=at;row.kind=row.kind==="domain"&&raw.kind==="vhost"?"vhost":row.kind;
        for(const key of ["value","url","scheme","host","port","path","query","status","length","words","lines","contentType","redirect","method","unresolved"]){
          if(raw[key]!==null&&raw[key]!==""&&raw[key]!==undefined)row[key]=raw[key];
        }
      }
      const signature=webObservationKey(observation);
      if(!row.sources.some(item=>webObservationKey(item)===signature))row.sources=[...row.sources,observation].slice(-MAX_WEB_SOURCE_OBSERVATIONS);
    }
    return rows;
  }
  function stableWebTargetId(value=""){
    let hash=2166136261;
    for(const character of String(value)){hash^=character.charCodeAt(0);hash=Math.imul(hash,16777619);}
    return `web-target-${(hash>>>0).toString(36)}`;
  }
  function clone(value,fallback){
    try{return JSON.parse(JSON.stringify(value??fallback));}catch(_error){return fallback;}
  }
  function normalizedArtifactLifecycle(value,provisional=false){return provisional===true||boundedText(value,32).toLowerCase()==="provisional"?"provisional":"canonical";}
  function contributionRevision(source={}){
    return normalizedArtifactLifecycle(source.artifactLifecycle,source.provisional)==="provisional"?0:(finiteInteger(source.revision,{min:1})||1);
  }
  function ensureWebImportProjection(recon={}){
    if(!recon||typeof recon!=="object")throw new Error("A Recon owner is required.");
    const current=recon.webImportProjection;
    if(current&&Number(current.schemaVersion)===WEB_IMPORT_PROJECTION_SCHEMA_VERSION&&Array.isArray(current.sources))return current;
    recon.webImportProjection={
      schemaVersion:WEB_IMPORT_PROJECTION_SCHEMA_VERSION,
      migration:"Existing untracked web targets remain a non-separable baseline; subsequently tracked web-discovery sources are replaceable.",
      sources:[],
      migratedAt:new Date().toISOString()
    };
    return recon.webImportProjection;
  }
  function webImportContributionKey({artifactId="",objectiveId="",originIds=[]}={}){
    const origins=[...new Set((originIds||[]).map(value=>boundedText(value,256)).filter(Boolean))].sort();
    return `web-source:${boundedText(artifactId,256)}|${boundedText(objectiveId,160)}|${origins.join(",")}`;
  }
  function rebuildWebImportProjection(recon={}){
    const projection=ensureWebImportProjection(recon);
    let rows=(Array.isArray(recon.webTargets)?recon.webTargets:[])
      .filter(row=>row&&row.sourceOwner!=="web-discovery-import")
      .map(row=>({
        ...clone(row,{}),
        sources:(Array.isArray(row.sources)?row.sources:[]).filter(source=>!String(source?.contributionKey||"").startsWith("web-source:"))
      }));
    projection.sources.forEach(source=>{
      const sourceMetadata={
        contributionKey:source.key,
        artifactId:source.artifactId,
        revision:source.revision,
        sha256:source.sha256,
        filename:source.filename,
        logicalPath:source.logicalPath,
        physicalSourcePath:source.physicalSourcePath,
        tool:source.tool,
        objectiveId:source.objectiveId,
        command:source.command,
        wordlist:source.wordlist,
        artifactLifecycle:normalizedArtifactLifecycle(source.artifactLifecycle,source.provisional),provisional:source.provisional===true,immutable:source.provisional!==true
      };
      rows=mergeWebTargets(rows,(source.records||[]).map(record=>({
        ...clone(record,{}),
        id:record.id||stableWebTargetId(record.key),
        sourceOwner:"web-discovery-import",
        recordRole:"web-discovery",
        objectiveId:source.objectiveId,
        sourceContributionKey:source.key
      })),{source:sourceMetadata,observedAt:source.observedAt,idFactory:record=>record.id||stableWebTargetId(record.key)});
    });
    recon.webTargets=rows;
    projection.updatedAt=new Date().toISOString();
    return rows;
  }
  function upsertWebImportContribution(recon={},contribution={}){
    const projection=ensureWebImportProjection(recon),key=boundedText(contribution.key,512);
    if(!key)throw new Error("A source-owned web contribution key is required.");
    const normalized={
      key,
      artifactId:boundedText(contribution.artifactId,256),
      revision:contributionRevision(contribution),
      sha256:boundedText(contribution.sha256,64).toLowerCase(),
      filename:boundedText(contribution.filename,512),
      logicalPath:boundedText(contribution.logicalPath,4096).replace(/\\/g,"/"),
      physicalSourcePath:boundedText(contribution.physicalSourcePath,4096).replace(/\\/g,"/"),
      tool:boundedText(contribution.tool,64),
      objectiveId:boundedText(contribution.objectiveId,160),
      endpointId:boundedText(contribution.endpointId,256),
      originIds:[...new Set((contribution.originIds||[]).map(value=>boundedText(value,256)).filter(Boolean))],
      command:boundedText(contribution.command,4096),
      wordlist:boundedText(contribution.wordlist,2048),
      operationState:boundedText(contribution.operationState,32),
      artifactLifecycle:normalizedArtifactLifecycle(contribution.artifactLifecycle,contribution.provisional),
      provisional:contribution.provisional===true||normalizedArtifactLifecycle(contribution.artifactLifecycle)==="provisional",
      immutable:contribution.provisional!==true&&normalizedArtifactLifecycle(contribution.artifactLifecycle)!=="provisional",
      resultCount:Math.max(0,Number(contribution.resultCount)||0),
      observedAt:boundedText(contribution.observedAt,64)||new Date().toISOString(),
      records:dedupeWebRecords((contribution.records||[]).map(record=>({
        ...clone(record,{}),
        id:record.id||stableWebTargetId(record.key),
        originId:boundedText(record.originId,256),
        endpointId:boundedText(record.endpointId||contribution.endpointId,256),
        objectiveId:boundedText(record.objectiveId||contribution.objectiveId,160)
      })))
    };
    const index=projection.sources.findIndex(row=>row.key===key);
    if(index>=0)projection.sources[index]=normalized;else projection.sources.push(normalized);
    rebuildWebImportProjection(recon);
    return normalized;
  }
  function deleteWebImportContribution(recon={},key=""){
    const projection=ensureWebImportProjection(recon),index=projection.sources.findIndex(row=>row.key===boundedText(key,512));
    if(index<0)return {ok:false,reason:"The web-discovery source is missing, stale, or legacy non-separable."};
    const [removed]=projection.sources.splice(index,1);
    rebuildWebImportProjection(recon);
    return {ok:true,removed};
  }
  function logicalWebImportedResults(recon={}){
    const projection=ensureWebImportProjection(recon);
    return projection.sources.map(source=>({
      id:source.key,
      sourceOwned:true,
      kind:"web-discovery",
      artifactId:source.artifactId,
      filename:source.filename,
      tool:source.tool,
      objectiveId:source.objectiveId,
      endpointId:source.endpointId,
      originIds:source.originIds,
      revision:source.revision,
      resultCount:source.resultCount,
      operationState:source.operationState,
      artifactLifecycle:normalizedArtifactLifecycle(source.artifactLifecycle,source.provisional),
      provisional:source.provisional===true,
      command:source.command,
      wordlist:source.wordlist,
      updatedAt:source.observedAt
    }));
  }

  function ensureWebBaselineProjection(recon={}){
    if(!recon||typeof recon!=="object")throw new Error("A Recon owner is required.");
    const current=recon.webBaselineProjection;
    if(current&&Number(current.schemaVersion)===WEB_BASELINE_PROJECTION_SCHEMA_VERSION&&Array.isArray(current.sources))return current;
    recon.webBaselineProjection={schemaVersion:WEB_BASELINE_PROJECTION_SCHEMA_VERSION,sources:[],migratedAt:new Date().toISOString()};
    return recon.webBaselineProjection;
  }
  function webBaselineContributionKey({artifactId="",objectiveId="",originId=""}={}){
    return `web-baseline:${boundedText(artifactId,256)}|${boundedText(objectiveId,160)}|${boundedText(originId,256)}`;
  }
  function upsertWebBaselineContribution(recon={},contribution={}){
    const projection=ensureWebBaselineProjection(recon),key=boundedText(contribution.key,512);if(!key)throw new Error("A source-owned web baseline key is required.");
    const normalized={
      key,
      artifactId:boundedText(contribution.artifactId,256),
      revision:contributionRevision(contribution),
      sha256:boundedText(contribution.sha256,64).toLowerCase(),
      filename:boundedText(contribution.filename,512),
      tool:boundedText(contribution.tool,64)||"curl baseline",
      objectiveId:boundedText(contribution.objectiveId,160),
      endpointId:boundedText(contribution.endpointId,256),
      originId:boundedText(contribution.originId,256),
      originUrl:normalizedWebOrigin(contribution.originUrl)||"",
      operationState:boundedText(contribution.operationState,32),
      artifactLifecycle:normalizedArtifactLifecycle(contribution.artifactLifecycle,contribution.provisional),
      provisional:contribution.provisional===true||normalizedArtifactLifecycle(contribution.artifactLifecycle)==="provisional",
      immutable:contribution.provisional!==true&&normalizedArtifactLifecycle(contribution.artifactLifecycle)!=="provisional",
      classification:boundedText(contribution.classification,64),
      classificationLabel:boundedText(contribution.classificationLabel,160),
      confidence:boundedText(contribution.confidence,32),
      summary:boundedText(contribution.summary,2048),
      sampleCount:Math.max(0,Number(contribution.sampleCount)||0),
      shapes:clone(contribution.shapes,[]),
      records:clone(contribution.records,[]),
      ffufOptions:boundedText(contribution.ffufOptions,1024)||"-ac",
      feroxOptions:boundedText(contribution.feroxOptions,1024)||"--auto-tune",
      guidance:(contribution.guidance||[]).map(value=>boundedText(value,1024)).filter(Boolean),
      warnings:(contribution.warnings||[]).map(value=>boundedText(value,1024)).filter(Boolean),
      observedAt:boundedText(contribution.observedAt,64)||new Date().toISOString()
    };
    const index=projection.sources.findIndex(row=>row.key===key);if(index>=0)projection.sources[index]=normalized;else projection.sources.push(normalized);
    projection.updatedAt=new Date().toISOString();return normalized;
  }
  function webBaselineForOrigin(recon={},originId=""){
    const id=boundedText(originId,256),projection=recon&&typeof recon==="object"?recon.webBaselineProjection:null;
    if(!id||!projection||Number(projection.schemaVersion)!==WEB_BASELINE_PROJECTION_SCHEMA_VERSION||!Array.isArray(projection.sources))return null;
    const sources=projection.sources.filter(row=>row.originId===id);
    return sources.sort((a,b)=>String(a.observedAt||"").localeCompare(String(b.observedAt||""))||Number(a.revision||0)-Number(b.revision||0)).at(-1)||null;
  }
  function logicalWebBaselineResults(recon={}){
    return ensureWebBaselineProjection(recon).sources.map(source=>({id:source.key,sourceOwned:true,kind:"web-baseline",artifactId:source.artifactId,filename:source.filename,tool:source.tool,objectiveId:source.objectiveId,endpointId:source.endpointId,originIds:[source.originId],revision:source.revision,resultCount:source.sampleCount,operationState:source.operationState,artifactLifecycle:normalizedArtifactLifecycle(source.artifactLifecycle,source.provisional),provisional:source.provisional===true,classification:source.classification,updatedAt:source.observedAt}));
  }
  function compareWebRecordToBaseline(record={},baseline=null){
    const empty={state:"not-imported",label:"No baseline imported",reason:"No invalid-path baseline is retained for this exact origin.",shape:"",matchedFields:[],differentFields:[],cssClass:"",baselineClassification:"",baselineFilename:"",baselineRevision:0};
    if(!baseline||typeof baseline!=="object")return empty;
    const path=boundedText(record.path||(()=>{try{return new URL(record.url||record.targetUrl||"").pathname;}catch(_error){return "";}})(),2048)||"/",shape=webBaselineSampleShape(path),shapeSummary=(baseline.shapes||[]).find(row=>boundedText(row?.shape,32)===shape);
    const base={...empty,state:"unknown",label:"Baseline comparison unavailable",reason:`The imported baseline has no retained ${shape} signature for this record.`,shape,baselineClassification:boundedText(baseline.classification,64),baselineFilename:boundedText(baseline.filename,512),baselineRevision:contributionRevision(baseline)};
    if(!shapeSummary||!Number(shapeSummary.count))return base;
    const matched=[],different=[],compared=[];
    const compareNumber=(label,value,allowed)=>{const current=value===null||value===undefined||value===""?null:Number(value),expected=(allowed||[]).map(Number).filter(Number.isFinite);if(current===null||!Number.isFinite(current)||!expected.length)return;compared.push(label);(expected.includes(current)?matched:different).push(label);};
    const compareText=(label,value,allowed,normalizer=value=>boundedText(value,4096).toLowerCase())=>{const current=normalizer(value),expected=(allowed||[]).map(normalizer).filter(Boolean);if(!current||!expected.length)return;compared.push(label);(expected.includes(current)?matched:different).push(label);};
    compareNumber("status",record.status,shapeSummary.statuses);
    compareNumber("bytes",record.length??record.bytes,shapeSummary.bytes);
    compareNumber("words",record.words,shapeSummary.words);
    compareNumber("lines",record.lines,shapeSummary.lines);
    compareText("content type",record.contentType||record.content_type,shapeSummary.contentTypes,value=>boundedText(value,512).split(";",1)[0].trim().toLowerCase());
    const redirect=boundedText(record.redirect||record.location,4096),redirectPattern=webBaselineRedirectPattern(redirect,path);
    compareText("redirect",redirectPattern,shapeSummary.redirectPatterns,value=>boundedText(value,4096));
    if(different.length)return {...base,state:"distinct",label:"Distinct from baseline",reason:`Differs from the retained ${shape} invalid-path signature on ${different.join(", ")}.`,matchedFields:matched,differentFields:different,cssClass:"web-app-review-disco-baseline-distinct"};
    const statusMatched=matched.includes("status"),strongMatches=matched.filter(value=>value!=="status").length;
    if(shapeSummary.stable&&statusMatched&&strongMatches>=1)return {...base,state:"baseline-like",label:"Baseline-like",reason:`Matches the stable ${shape} invalid-path signature on ${matched.join(", ")}. Keep it visible until manually verified.`,matchedFields:matched,differentFields:different,cssClass:"web-app-review-disco-baseline-like"};
    if(statusMatched&&compared.length)return {...base,state:"possible-baseline-like",label:"Possibly baseline-like",reason:`Matches the ${shape} invalid-path status but lacks enough stable matching measurements for a definitive comparison.`,matchedFields:matched,differentFields:different,cssClass:"web-app-review-disco-baseline-possible"};
    return {...base,reason:`The retained ${shape} baseline exists, but this record lacks enough comparable response metadata.`,matchedFields:matched,differentFields:different};
  }

  function ensureTechnologyImportProjection(recon={}){
    if(!recon||typeof recon!=="object")throw new Error("A Recon owner is required.");
    const current=recon.technologyImportProjection;
    if(current&&Number(current.schemaVersion)===TECHNOLOGY_IMPORT_PROJECTION_SCHEMA_VERSION&&Array.isArray(current.sources)){normalizeTechnologyImportProjection(current);return current;}
    recon.technologyImportProjection={schemaVersion:TECHNOLOGY_IMPORT_PROJECTION_SCHEMA_VERSION,migration:"Existing untracked technology text remains Manual Recon Notes; subsequently tracked retained sources are replaceable.",sources:[],migratedAt:new Date().toISOString()};
    return recon.technologyImportProjection;
  }
  function technologyContributionIdentity({artifactId="",objectiveId=""}={}){
    const artifact=boundedText(artifactId,256),objective=boundedText(objectiveId,160);return artifact&&objective?`${artifact}|${objective}`:"";
  }
  function technologyImportContributionKey({artifactId="",objectiveId=""}={}){
    return `technology-source:${boundedText(artifactId,256)}|${boundedText(objectiveId,160)}`;
  }
  function technologySourceRank(row={}){
    const contentIdentity=boundedText(JSON.stringify({originIds:[...new Set((row.originIds||[]).map(value=>boundedText(value,256)).filter(Boolean))].sort(),endpointId:boundedText(row.endpointId,256),records:(row.records||[]).slice(0,100).map(record=>[boundedText(record.key,1024),boundedText(record.targetUrl,2048),boundedText(record.originId,256),boundedText(record.operationState,32),Number(record.resultCount)||0].join("|")).sort()}),8192);
    return [contributionRevision(row),boundedText(row.observedAt,64),boundedText(row.sha256,64),boundedText(row.key,512),contentIdentity];
  }
  function compareTechnologySourceRank(left={},right={}){
    const a=technologySourceRank(left),b=technologySourceRank(right);return a[0]-b[0]||a[1].localeCompare(b[1])||a[2].localeCompare(b[2])||a[3].localeCompare(b[3])||a[4].localeCompare(b[4]);
  }
  function technologyContributionSourceKeys(source={}){
    const canonical=technologyContributionIdentity(source)?technologyImportContributionKey(source):"";
    return [...new Set([canonical,source.key,...(Array.isArray(source.legacyKeys)?source.legacyKeys:[])].map(value=>boundedText(value,512)).filter(Boolean))];
  }
  function normalizeTechnologyImportProjection(projection={}){
    const sources=Array.isArray(projection.sources)?projection.sources:[],groups=new Map();
    sources.forEach((source,index)=>{const identity=technologyContributionIdentity(source);if(!identity)return;if(!groups.has(identity))groups.set(identity,[]);groups.get(identity).push({source,index});});
    const duplicateGroups=[...groups.entries()].filter(([,rows])=>rows.length>1).sort(([left],[right])=>left.localeCompare(right));
    for(const [,rows] of duplicateGroups){
      const currentRows=rows.map(row=>row.source).filter(source=>sources.includes(source));if(currentRows.length<2)continue;
      const winner=currentRows.slice().sort(compareTechnologySourceRank).at(-1),indices=currentRows.map(source=>sources.indexOf(source)).filter(index=>index>=0).sort((a,b)=>a-b),insertAt=indices[0];
      const legacyKeys=[...new Set(currentRows.flatMap(source=>technologyContributionSourceKeys(source)).map(value=>boundedText(value,512)).filter(value=>value&&value!==technologyImportContributionKey(winner)))].sort().slice(0,50);
      const normalized={...winner,key:technologyImportContributionKey(winner),legacyKeys};
      for(const index of indices.slice().sort((a,b)=>b-a))sources.splice(index,1);sources.splice(insertAt,0,normalized);
    }
    return projection;
  }
  function normalizedWhatWebRoute(raw={},origin=""){
    try{
      const candidate=raw?.url||new URL(String(raw?.path||""),origin).toString(),route=normalizedWebUrl(candidate);
      if(!route||route.origin!==origin)return null;
      return {url:route.url,path:route.path,method:boundedText(raw?.method||"GET",24).toUpperCase()||"GET",kind:boundedText(raw?.kind||"client-route",80),status:finiteInteger(raw?.status,{min:100,max:599}),notes:boundedText(raw?.notes,1024)};
    }catch{return null;}
  }
  function normalizeTechnologyRecord(raw={},contribution={}){
    const target=normalizedWebUrl(raw.targetUrl||raw.url);if(!target)throw new Error("A retained WhatWeb record requires its exact original HTTP(S) target URL.");
    const technologies=dedupeWhatWebTechnologies((raw.technologies||[]).map(row=>whatWebTechnology(row?.name,row)).filter(Boolean));
    const sourceReview=normalizedWhatWebReviewState(contribution.reviewState),rawReview=normalizedWhatWebReviewState(raw.reviewState,sourceReview);
    const reviewState=sourceReview==="stale"?"stale":rawReview==="current"&&sourceReview!=="current"?sourceReview:rawReview;
    const operationState=explicitWhatWebOperationState(raw)||boundedText(raw.operationState||contribution.operationState,32).toLowerCase()||"completed";
    return {
      key:boundedText(raw.key,1024)||`whatweb:${target.key}`,targetUrl:target.url,origin:target.origin,scheme:target.scheme,host:target.host,port:target.port,path:target.path,
      sourceOrigin:normalizedWebOrigin(raw.sourceOrigin||target.origin),status:finiteInteger(raw.status,{min:100,max:599}),originId:boundedText(raw.originId,256),endpointId:boundedText(raw.endpointId||contribution.endpointId,256),
      operationState,reviewState,resultCount:technologies.length,error:boundedText(raw.error,2048),duplicateCount:Math.max(1,Number(raw.duplicateCount)||1),title:boundedText(raw.title,2048),redirect:boundedText(raw.redirect,2048),serverHeader:boundedText(raw.serverHeader,2048),cookies:[...new Set((Array.isArray(raw.cookies)?raw.cookies:[]).map(value=>boundedText(value,256)).filter(Boolean))].slice(0,32),
      observedHeaders:[...new Set((Array.isArray(raw.observedHeaders)?raw.observedHeaders:[]).map(value=>boundedText(value,160)).filter(Boolean))].slice(0,32),
      securityHeaders:(Array.isArray(raw.securityHeaders)?raw.securityHeaders:[]).map(row=>({name:boundedText(row?.name,160),value:boundedText(row?.value,512)})).filter(row=>row.name).slice(0,32),
      pageCharacteristics:[...new Set((Array.isArray(raw.pageCharacteristics)?raw.pageCharacteristics:[]).map(value=>boundedText(value,512)).filter(Boolean))].slice(0,16),
      weakClues:[...new Set((Array.isArray(raw.weakClues)?raw.weakClues:[]).map(value=>boundedText(value,512)).filter(Boolean))].slice(0,16),
      discoveredRoutes:(Array.isArray(raw.discoveredRoutes)?raw.discoveredRoutes:[]).map(row=>normalizedWhatWebRoute(row,target.origin)).filter(Boolean).slice(0,32),
      inputs:(Array.isArray(raw.inputs)?raw.inputs:[]).map(row=>({name:boundedText(row?.name,160),type:boundedText(row?.type||"string",80),location:boundedText(row?.location||"body",32),pageUrl:normalizedWebUrl(row?.pageUrl||target.url)?.url||target.url,reviewState:boundedText(row?.reviewState||"mapped",32),coverageEligible:row?.coverageEligible===true,notes:boundedText(row?.notes,1024)})).filter(row=>row.name).slice(0,32),
      artifactId:boundedText(raw.artifactId||contribution.artifactId,256),revision:contributionRevision({...contribution,...raw,artifactLifecycle:raw.artifactLifecycle||contribution.artifactLifecycle,provisional:raw.provisional===true||contribution.provisional===true}),artifactLifecycle:normalizedArtifactLifecycle(raw.artifactLifecycle||contribution.artifactLifecycle,raw.provisional===true||contribution.provisional===true),provisional:raw.provisional===true||contribution.provisional===true,technologies
    };
  }
  function technologyRecordState(record={},source={}){
    const review=boundedText(record.reviewState||source.reviewState,32).toLowerCase(),operation=boundedText(record.operationState||source.operationState,32).toLowerCase();
    if(review==="stale")return "stale";
    if(review==="conflicting"||["conflict","conflicting"].includes(operation))return "conflicting";
    if(operation==="failed")return "failed";
    if(operation==="partial"||operation==="incomplete")return "partial";
    if(review==="deferred"||operation==="deferred")return "deferred";
    if(["complete","completed"].includes(operation))return Number(record.resultCount??(Array.isArray(record.technologies)?record.technologies.length:0))>0?"positive":"zero";
    return "unknown";
  }
  const TECHNOLOGY_OPEN_RECORD_STATES=new Set(["conflicting","stale","partial","failed","deferred","unknown"]);
  function technologyOutcomeSummary(records=[],source={}){
    const rows=Array.isArray(records)?records:[],recordStates=rows.map(record=>technologyRecordState(record,source)),count=state=>recordStates.filter(value=>value===state).length;
    const positiveRecordCount=count("positive"),completedZeroCount=count("zero"),failedCount=count("failed"),partialCount=count("partial"),conflictingCount=count("conflicting"),staleCount=count("stale"),deferredCount=count("deferred"),unknownCount=count("unknown"),openCount=recordStates.filter(state=>TECHNOLOGY_OPEN_RECORD_STATES.has(state)).length;
    const precedence=["conflicting","stale","partial","failed","deferred","unknown","positive","zero"],state=precedence.find(candidate=>recordStates.includes(candidate))||"unknown";
    const reviewStates=rows.map(record=>normalizedWhatWebReviewState(record.reviewState||source.reviewState)),reviewState=["stale","conflicting","deferred","reviewed","current"].find(candidate=>reviewStates.includes(candidate))||"current";
    const operationState=["positive","zero"].includes(state)?"completed":state==="stale"?boundedText(rows.find(record=>record.reviewState==="stale")?.operationState||rows[0]?.operationState||source.operationState,32):state;
    const resultCount=rows.reduce((total,record)=>total+Math.max(0,Number(record.resultCount??(Array.isArray(record.technologies)?record.technologies.length:0))||0),0),positiveObservationCount=rows.reduce((total,record,index)=>recordStates[index]==="positive"?total+Math.max(0,Number(record.resultCount??(Array.isArray(record.technologies)?record.technologies.length:0))||0):total,0);
    const outcomeKinds=[positiveRecordCount>0,completedZeroCount>0,openCount>0].filter(Boolean).length;
    return {state,operationState,reviewState,resultCount,positiveObservationCount,positiveRecordCount,recordCount:rows.length,completedZeroCount,failedCount,partialCount,conflictingCount,staleCount,deferredCount,unknownCount,openCount,hasOpenWork:openCount>0,mixed:outcomeKinds>1,recordStates};
  }
  function technologyOriginOutcomes(source={}){
    const groups=new Map();
    (Array.isArray(source.records)?source.records:[]).forEach(record=>{
      const originId=boundedText(record.originId,256);if(!originId)return;
      if(!groups.has(originId))groups.set(originId,[]);groups.get(originId).push(record);
    });
    return [...groups.entries()].map(([originId,records])=>{
      const summary=technologyOutcomeSummary(records,source);
      return {
        id:`${boundedText(source.key,512)}|${originId}`,sourceKey:boundedText(source.key,512),originId,endpointId:boundedText(records[0]?.endpointId||source.endpointId,256),
        artifactId:boundedText(source.artifactId,256),revision:contributionRevision(source),tool:boundedText(source.tool||"WhatWeb",64),...summary,
        targetUrls:[...new Set(records.map(record=>boundedText(record.targetUrl,2048)).filter(Boolean))],sourceOrigins:[...new Set(records.map(record=>boundedText(record.sourceOrigin,2048)).filter(Boolean))],errors:[...new Set(records.map(record=>boundedText(record.error,2048)).filter(Boolean))],records
      };
    }).sort((left,right)=>left.originId.localeCompare(right.originId));
  }
  function methodologyDispositionFromOutcomes(outcomes=[]){
    const values=(Array.isArray(outcomes)?outcomes:[]).map(row=>boundedText(row?.outcome,32).toLowerCase());
    if(values.includes("complete"))return "complete";
    if(values.includes("negative"))return "negative";
    if(values.includes("partial"))return "partial";
    if(values.includes("failed"))return "failed";
    if(values.includes("stale"))return "stale";
    if(values.includes("deferred"))return "deferred";
    return "in-progress";
  }
  function methodologyStateForDisposition(disposition="in-progress"){
    return ({complete:"done",negative:"done","not-applicable":"na",deferred:"todo","not-started":"todo"})[boundedText(disposition,32)]||"active";
  }
  function methodOutcomeRank(row={}){return [finiteInteger(row.revision,{min:0})||0,boundedText(row.observedAt||row.updatedAt,64),boundedText(row.sha256,64),boundedText(row.sourceKey||row.id,512)];}
  function compareMethodOutcomeRank(left={},right={}){const a=methodOutcomeRank(left),b=methodOutcomeRank(right);return a[0]-b[0]||a[1].localeCompare(b[1])||a[2].localeCompare(b[2])||a[3].localeCompare(b[3]);}
  function reconcileTechnologyMethodOutcomes(noteStatus={},sources=[],options={}){
    const statuses=noteStatus&&typeof noteStatus==="object"&&!Array.isArray(noteStatus)?noteStatus:{},current=Array.isArray(sources)?sources:[],removed=Array.isArray(options.removedContributions)?options.removedContributions:[];
    const referencedKeys=new Set(Object.values(statuses).flatMap(status=>Array.isArray(status?.methodOutcomes)?status.methodOutcomes:[]).map(row=>boundedText(row?.sourceKey||row?.id,512)).filter(Boolean));
    current.forEach(source=>{
      const identity=technologyContributionIdentity(source),currentKey=boundedText(source?.key,512),canonical=identity?technologyImportContributionKey(source):"";if(!identity||!currentKey||currentKey===canonical)return;
      if(!technologyContributionSourceKeys(source).some(key=>referencedKeys.has(key)))return;
      source.legacyKeys=[...new Set([currentKey,...(Array.isArray(source.legacyKeys)?source.legacyKeys:[])].map(value=>boundedText(value,512)).filter(value=>value&&value!==canonical))].sort().slice(0,50);source.key=canonical;
    });
    const currentByKey=new Map(),currentByIdentity=new Map(),removedByKey=new Map(),removedByIdentity=new Map();
    current.forEach(source=>{const identity=technologyContributionIdentity(source);if(identity)currentByIdentity.set(identity,source);technologyContributionSourceKeys(source).forEach(key=>currentByKey.set(key,source));});
    removed.forEach(source=>{const identity=technologyContributionIdentity(source);if(identity&&!currentByIdentity.has(identity))removedByIdentity.set(identity,source);technologyContributionSourceKeys(source).forEach(key=>{if(!currentByKey.has(key))removedByKey.set(key,source);});});
    let changed=false,statusesChanged=0,removedOutcomes=0,canonicalizedOutcomes=0;
    Object.values(statuses).forEach(status=>{
      if(!status||typeof status!=="object"||!Array.isArray(status.methodOutcomes))return;
      const retained=[],canonicalRows=new Map();let statusChanged=false,statusRemovedOutcomes=0;
      status.methodOutcomes.forEach(raw=>{
        const row=raw&&typeof raw==="object"?{...raw}:{},key=boundedText(row.sourceKey||row.id,512),identity=technologyContributionIdentity(row),source=currentByKey.get(key)||currentByIdentity.get(identity),removedSource=removedByKey.get(key)||removedByIdentity.get(identity);
        if(source){
          const originId=boundedText(row.originId,256),ownedOrigins=[...new Set((source.originIds||[]).map(value=>boundedText(value,256)).filter(Boolean))];
          if(originId&&ownedOrigins.length&&!ownedOrigins.includes(originId)){statusChanged=true;removedOutcomes++;statusRemovedOutcomes++;return;}
          const canonical=technologyImportContributionKey(source),normalized={...row,id:canonical,sourceKey:canonical,artifactId:boundedText(source.artifactId,256)||boundedText(row.artifactId,256),objectiveId:boundedText(source.objectiveId,160)||boundedText(row.objectiveId,160)};
          if(key!==canonical)statusChanged=true,canonicalizedOutcomes++;
          const prior=canonicalRows.get(canonical);if(!prior||compareMethodOutcomeRank(prior,normalized)<0)canonicalRows.set(canonical,normalized);else statusChanged=true;
          return;
        }
        if(removedSource){statusChanged=true;removedOutcomes++;statusRemovedOutcomes++;return;}
        retained.push(row);
      });
      const next=[...retained,...canonicalRows.values()].slice(-100);
      if(statusChanged||JSON.stringify(next)!==JSON.stringify(status.methodOutcomes)){
        const disposition=methodologyDispositionFromOutcomes(next);status.methodOutcomes=next;status.disposition=disposition;status.state=methodologyStateForDisposition(disposition);
        if(!next.length&&statusRemovedOutcomes)status.reason=boundedText(options.emptyReason,1024)||"Source-owned Technology evidence no longer owns this exact origin; review the objective again.";
        status.updatedAt=boundedText(options.now,64)||new Date().toISOString();changed=true;statusesChanged++;
      }
    });
    return {changed,statusesChanged,removedOutcomes,canonicalizedOutcomes};
  }
  function upsertTechnologyImportContribution(recon={},contribution={}){
    const projection=ensureTechnologyImportProjection(recon),identity=technologyContributionIdentity(contribution);if(!identity)throw new Error("A retained artifact and methodology objective are required for a source-owned Technology contribution.");
    const key=technologyImportContributionKey(contribution),requestedKey=boundedText(contribution.key,512),matchingIndices=projection.sources.map((row,index)=>technologyContributionIdentity(row)===identity||row.key===key||requestedKey&&(row.key===requestedKey||Array.isArray(row.legacyKeys)&&row.legacyKeys.includes(requestedKey))?index:-1).filter(index=>index>=0),existingRows=matchingIndices.map(index=>projection.sources[index]),existing=existingRows.slice().sort(compareTechnologySourceRank).at(-1)||null;
    const revision=contributionRevision(contribution),sha256=boundedText(contribution.sha256,64).toLowerCase();
    const changed=!!existing&&(Number(existing.revision)!==revision||sha256&&existing.sha256&&existing.sha256!==sha256);
    const reviewState=boundedText(contribution.reviewState,32)||(changed?"stale":existing?.reviewState||"current"),recordOwner={...contribution,revision,reviewState};
    const records=dedupeWhatWebRecords((contribution.records||[]).slice(0,MAX_WHATWEB_RECORDS).map(row=>normalizeTechnologyRecord(row,recordOwner)));
    const normalized={
      key,artifactId:boundedText(contribution.artifactId,256),revision,sha256,filename:boundedText(contribution.filename,512),tool:boundedText(contribution.tool||"WhatWeb",64),objectiveId:boundedText(contribution.objectiveId,160),
      endpointId:boundedText(contribution.endpointId,256),originIds:[...new Set((contribution.originIds||[]).map(value=>boundedText(value,256)).filter(Boolean))],operationState:boundedText(contribution.operationState,32),artifactLifecycle:normalizedArtifactLifecycle(contribution.artifactLifecycle,contribution.provisional),provisional:contribution.provisional===true||normalizedArtifactLifecycle(contribution.artifactLifecycle)==="provisional",immutable:contribution.provisional!==true&&normalizedArtifactLifecycle(contribution.artifactLifecycle)!=="provisional",
      reviewState,resultCount:records.reduce((total,row)=>total+row.resultCount,0),observedAt:boundedText(contribution.observedAt,64)||new Date().toISOString(),records,
      legacyKeys:[...new Set(existingRows.flatMap(row=>[row.key,...(Array.isArray(row.legacyKeys)?row.legacyKeys:[])]).concat(requestedKey).map(value=>boundedText(value,512)).filter(value=>value&&value!==key))].sort().slice(0,50)
    };
    normalized.originOutcomes=technologyOriginOutcomes(normalized);
    const oldOriginIds=existingRows.flatMap(row=>Array.isArray(row.originIds)?row.originIds:[]).map(value=>boundedText(value,256)).filter(Boolean),affectedOriginIds=[...new Set([...oldOriginIds,...normalized.originIds])].sort();
    if(matchingIndices.length){const insertAt=Math.min(...matchingIndices);for(const index of matchingIndices.slice().sort((a,b)=>b-a))projection.sources.splice(index,1);projection.sources.splice(insertAt,0,normalized);}else projection.sources.push(normalized);
    projection.updatedAt=new Date().toISOString();return {...normalized,affectedOriginIds,replacedContributions:existingRows};
  }
  function deleteTechnologyImportContribution(recon={},key=""){
    const projection=ensureTechnologyImportProjection(recon),requested=boundedText(key,512),index=projection.sources.findIndex(row=>row.key===requested||technologyImportContributionKey(row)===requested||Array.isArray(row.legacyKeys)&&row.legacyKeys.includes(requested));
    if(index<0)return {ok:false,reason:"The Technology source is missing, stale, or legacy non-separable."};
    const selected=projection.sources[index],identity=technologyContributionIdentity(selected),removedRows=[];
    for(let sourceIndex=projection.sources.length-1;sourceIndex>=0;sourceIndex--){if(sourceIndex===index||identity&&technologyContributionIdentity(projection.sources[sourceIndex])===identity)removedRows.unshift(...projection.sources.splice(sourceIndex,1));}
    projection.updatedAt=new Date().toISOString();return {ok:true,removed:selected,removedContributions:removedRows};
  }
  function logicalTechnologyImportedResults(recon={}){
    return ensureTechnologyImportProjection(recon).sources.map(source=>({id:source.key,sourceOwned:true,kind:"web-technology",artifactId:source.artifactId,filename:source.filename,tool:source.tool,objectiveId:source.objectiveId,endpointId:source.endpointId,originIds:source.originIds,revision:source.revision,resultCount:source.resultCount,operationState:source.operationState,artifactLifecycle:normalizedArtifactLifecycle(source.artifactLifecycle,source.provisional),provisional:source.provisional===true,reviewState:source.reviewState,originOutcomes:technologyOriginOutcomes(source),updatedAt:source.observedAt}));
  }

  return Object.freeze({SUPPORTED_SCHEMAS,API_CAPABILITY,WEB_SCHEMES,MAX_WEB_IMPORT_BYTES,MAX_WEB_SOURCE_OBSERVATIONS,WEB_IMPORT_PROJECTION_SCHEMA_VERSION,TECHNOLOGY_IMPORT_PROJECTION_SCHEMA_VERSION,WEB_BASELINE_PROJECTION_SCHEMA_VERSION,WEB_PATH_ONLY_ORIGIN,validate,normalizeRouteTitle,resolveMapping,cleanText,sectionValue,username,signalKey,mappingDestination,destinationId,importedFieldKey,routes,collectionIdentity,normalizedTarget,targetMismatch,detectUploadType,serverError,readUpload,normalizedDomain,normalizedWebUrl,normalizedWebOrigin,webServiceBaseUrl,webRecord,dedupeWebRecords,parseFfufJson,parseGobusterText,parseDirbText,parseDirbusterText,parseFeroxbusterJson,parseFeroxbusterText,parseDirsearchText,parseWebTargetList,parseWebDiscovery,webDiscoveryOrigins,detectWebDiscovery,webBaselineSampleShape,webBaselineRedirectPattern,parseWebBaseline,detectWebBaseline,parseWhatWeb,detectWhatWeb,webMethodDisposition,normalizedArtifactLifecycle,contributionRevision,mergeWebTargets,stableWebTargetId,ensureWebImportProjection,webImportContributionKey,rebuildWebImportProjection,upsertWebImportContribution,deleteWebImportContribution,logicalWebImportedResults,ensureWebBaselineProjection,webBaselineContributionKey,upsertWebBaselineContribution,webBaselineForOrigin,logicalWebBaselineResults,compareWebRecordToBaseline,ensureTechnologyImportProjection,technologyImportContributionKey,technologyContributionSourceKeys,technologyRecordState,technologyOutcomeSummary,technologyOriginOutcomes,reconcileTechnologyMethodOutcomes,upsertTechnologyImportContribution,deleteTechnologyImportContribution,logicalTechnologyImportedResults});
});
