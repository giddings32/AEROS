(function(root,factory){
  const reconApi=(typeof module==="object"&&module.exports)
    ?(()=>{
      try{return require("./recon-import.js");}
      catch(error){
        if(error?.code!=="MODULE_NOT_FOUND")throw error;
        return require("./app/features/imports/recon-import.js");
      }
    })()
    :(root&&root.AEROSReconImport);
  const api=factory(reconApi||{});
  if(typeof module==="object"&&module.exports)module.exports=api;
  if(root)root.AEROSImportLifecycle=api;
})(typeof window!=="undefined"?window:globalThis,function(reconApi){
  "use strict";

  const SCHEMA_VERSION=1;
  const INTAKE_SCHEMA_VERSION=1;
  const MAX_HISTORY=250;
  const MIB=1024*1024;
  const INTAKE_LIMITS=Object.freeze({
    maximumArchiveBytes:48*MIB,
    maximumExpandedBytes:100*MIB,
    maximumMemberBytes:25*MIB,
    maximumContainedFiles:500,
    maximumCompressionRatio:200,
    maximumNestedArchiveDepth:0,
    previewBytesPerFile:256*1024
  });
  const IMPORT_TYPE_LABELS=Object.freeze({
    nmap:"Nmap results",
    "scan-support":"AutoRecon support file",
    peas:"PEAS output",
    "host-enumeration":"Structured Host Enumeration",
    "web-discovery":"Web discovery results",
    "web-baseline":"Invalid-path baseline",
    "web-technology":"WhatWeb technology results",
    document:"Engagement document",
    zip:"ZIP archive"
  });
  const clean=value=>String(value??"").trim();
  const nowIso=()=>new Date().toISOString();
  const safeObject=value=>value&&typeof value==="object"&&!Array.isArray(value)?value:{};
  const unique=values=>{const seen=new Set(),rows=[];for(const value of values||[]){const text=clean(value);if(!text)continue;const key=text.toLowerCase();if(seen.has(key))continue;seen.add(key);rows.push(text);}return rows;};
  const randomId=prefix=>`${prefix}_${Date.now()}_${Math.random().toString(16).slice(2)}`;
  const normalizePath=value=>clean(value).replace(/\\/g,"/").replace(/^\/+/,"").replace(/\/+/g,"/");
  const suffix=value=>{const match=normalizePath(value).toLowerCase().match(/([.][a-z0-9]+)$/);return match?.[1]||"";};

  function stableValue(value){
    if(Array.isArray(value))return value.map(stableValue);
    if(value&&typeof value==="object")return Object.keys(value).sort().reduce((out,key)=>{out[key]=stableValue(value[key]);return out;},{});
    return value;
  }
  function stableStringify(value){return JSON.stringify(stableValue(value));}
  async function sha256Text(value){
    const bytes=new TextEncoder().encode(String(value??""));
    if(globalThis.crypto?.subtle){
      const digest=await globalThis.crypto.subtle.digest("SHA-256",bytes);
      return Array.from(new Uint8Array(digest)).map(byte=>byte.toString(16).padStart(2,"0")).join("");
    }
    if(typeof require==="function")return require("crypto").createHash("sha256").update(Buffer.from(bytes)).digest("hex");
    throw new Error("SHA-256 is unavailable in this runtime");
  }
  function normalizeLogicalKey(value){return clean(value).toLowerCase().replace(/\\/g,"/").replace(/\/+/,"/");}
  function reconTargetSignature(data){
    const collection=data?.collection||{},target=data?.target||{};
    return [target.hostname,target.primaryAddress,collection.scope,collection.executedAs?.username]
      .map(normalizeLogicalKey).join("::");
  }
  function reconLogicalKey(data){
    const schema=clean(data?.schema?.name).toLowerCase();
    const collection=data?.collection||{},target=data?.target||{};
    const collectionId=clean(collection.id).toLowerCase();
    if(collectionId)return `collector:${schema}:${collectionId}`;
    return ["collector",schema,target.hostname,target.primaryAddress,collection.scope,collection.executedAs?.username]
      .map(normalizeLogicalKey).join("::");
  }
  function uniqueTargets(values){
    const seen=new Set(),rows=[];
    (values||[]).map(value=>clean(value).replace(/^\[|\]$/g,"").replace(/[.]$/,"")).filter(Boolean).forEach(value=>{
      const key=value.toLowerCase();if(seen.has(key))return;seen.add(key);rows.push(value);
    });
    return rows;
  }
  function detectedTargets(text="",structured=null){
    const raw=String(text||""),rows=[];let match;
    const reports=/^\s*Nmap scan report for\s+(.+?)\s*$/gim;
    while((match=reports.exec(raw))){
      const value=clean(match[1]),parenthesized=(/\(([^)]+)\)\s*$/.exec(value)||[])[1];
      rows.push(parenthesized||value.split(/\s+/).pop());
    }
    const grepable=/^\s*Host:\s+(\S+)(?:\s+\([^\r\n)]*\))?\s+(?:Status:\s+(?:Up|Down|Unknown)\b|Ports:\s*(?:\d{1,5}\/(?:open\|filtered|closed\|filtered|open|closed|filtered|unfiltered)\/(?:tcp|udp|sctp|ip)\/|Ignored State:\s*(?:open\|filtered|closed\|filtered|closed|filtered|unfiltered)\b))/gim;
    while((match=grepable.exec(raw)))rows.push(match[1]);
    const targetLines=/^\s*(?:Target(?:\s+(?:Host|IP|Address))?|Hostname|ComputerName|Host Name)\s*[:=]\s*(\S+)/gim;
    while((match=targetLines.exec(raw)))rows.push(match[1]);
    if(/<nmaprun\b/i.test(raw)){
      const xmlAddresses=[];
      const addressTags=/<address\b([^>]*)\/?\s*>/gi;
      while((match=addressTags.exec(raw))){
        const attrs=match[1]||"",address=(/\baddr\s*=\s*["']([^"']+)["']/i.exec(attrs)||[])[1]||"";
        const kind=((/\baddrtype\s*=\s*["']([^"']+)["']/i.exec(attrs)||[])[1]||"").toLowerCase();
        if(address&&(!kind||kind==="ipv4"||kind==="ipv6"))xmlAddresses.push(address);
      }
      if(xmlAddresses.length)rows.push(...xmlAddresses);
      else{
        const hostnameTags=/<hostname\b([^>]*)\/?\s*>/gi;
        while((match=hostnameTags.exec(raw))){
          const name=(/\bname\s*=\s*["']([^"']+)["']/i.exec(match[1]||"")||[])[1];
          if(name)rows.push(name);
        }
      }
    }
    if(structured&&typeof structured==="object"){
      const target=structured.target||{};
      rows.push(target.primaryAddress,target.ip,target.address,target.hostname);
    }
    return uniqueTargets(rows);
  }
  function zipSignature(signatureHex=""){
    const value=clean(signatureHex).toLowerCase();
    return value.startsWith("504b0304")||value.startsWith("504b0506")||value.startsWith("504b0708");
  }
  function pdfSignature(signatureHex="",text=""){return clean(signatureHex).toLowerCase().startsWith("25504446")||String(text||"").startsWith("%PDF-");}
  function structuredEnumeration(text=""){
    const raw=clean(text);if(!raw.startsWith("{"))return null;
    try{
      const data=JSON.parse(raw),schema=clean(data?.schema?.name).toLowerCase();
      if(["aeros-recon","aeros-collector","product-recon"].includes(schema)&&data.collection&&data.target&&data.sections)return {data,schema};
    }catch(_error){}
    return null;
  }
  function nmapRunCommand(text=""){
    const raw=String(text||"");
    const xmlAttrs=(/<nmaprun\b([^>]*)>/i.exec(raw)||[])[1]||"";
    const xmlCommand=(/\bargs\s*=\s*["']([^"']+)["']/i.exec(xmlAttrs)||[])[1]||"";
    if(xmlCommand)return clean(xmlCommand).replace(/&#x([0-9a-f]+);/gi,(_match,value)=>String.fromCodePoint(Number.parseInt(value,16))).replace(/&#(\d+);/g,(_match,value)=>String.fromCodePoint(Number(value))).replace(/&quot;/g,'"').replace(/&amp;/g,"&");
    const initiated=/^\s*#\s*Nmap\b[^\r\n]*?\s+as:\s*(.+?)\s*$/im.exec(raw);
    if(initiated)return clean(initiated[1]);
    const starting=/^\s*Starting Nmap\b[^\r\n]*$/im.exec(raw);
    return clean(starting?.[0]);
  }
  function nmapRunKey(text="",path=""){
    const command=nmapRunCommand(text).toLowerCase().replace(/\s+/g," ").trim();
    if(command)return command;
    return normalizePath(path).toLowerCase().replace(/[.](?:xml|nmap|gnmap)$/,"");
  }
  function nmapStructure(text="",path=""){
    const raw=String(text||"");
    const xmlRoot=/<nmaprun\b([^>]*)>/i.exec(raw),xmlScanner=xmlRoot&&/\bscanner\s*=\s*["']nmap["']/i.test(xmlRoot[1]||"");
    if(xmlRoot||xmlScanner){
      const structures=[/<scaninfo\b/i,/<verbose\b/i,/<debugging\b/i,/<host\b/i,/<status\b/i,/<address\b/i,/<ports\b/i,/<extraports\b/i,/<runstats\b/i,/<finished\b/i,/<hosts\b/i].filter(pattern=>pattern.test(raw)).length;
      const closed=/<\/nmaprun\s*>/i.test(raw),metadata=xmlScanner||/\b(?:args|start|startstr)\s*=/i.test(xmlRoot?.[1]||"")||structures>0;
      return {matched:true,parser:"nmap-xml",representation:"XML",signal:"Nmap XML run structure",complete:closed&&metadata,reason:closed&&metadata?"Nmap XML run structure detected.":"Nmap XML signature detected, but the bounded preview is incomplete, malformed, or truncated.",runKey:nmapRunKey(raw,path)};
    }
    const grepComment=/^\s*#\s*Nmap\b/im.test(raw),grepDone=/^\s*#\s*Nmap done at\b/im.test(raw),grepPortsScanned=/^\s*#\s*Ports scanned:/im.test(raw);
    const grepStatusLine=/^\s*Host:\s+\S+(?:\s+\([^\r\n)]*\))?\s+Status:\s+(?:Up|Down|Unknown)\b[^\r\n]*$/im.test(raw);
    const grepPortsLine=/^\s*Host:\s+\S+(?:\s+\([^\r\n)]*\))?\s+Ports:\s*(?:\d{1,5}\/(?:open\|filtered|closed\|filtered|open|closed|filtered|unfiltered)\/(?:tcp|udp|sctp|ip)\/|Ignored State:\s*(?:open\|filtered|closed\|filtered|closed|filtered|unfiltered)\b)[^\r\n]*$/im.test(raw);
    const grepIdentity=grepPortsLine||grepStatusLine&&(grepComment||grepDone||grepPortsScanned||suffix(path)===".gnmap")||grepComment&&grepPortsScanned||suffix(path)===".gnmap"&&grepComment&&grepDone;
    const grepComplete=grepDone||grepPortsLine||/\b(?:QUITTING|fatal|aborted|interrupted)\b/i.test(raw);
    if(grepIdentity){
      return {matched:true,parser:"nmap-grepable",representation:"Grepable",signal:"Nmap grepable run structure",complete:grepComplete,reason:grepComplete?"Nmap grepable run structure detected.":"Nmap grepable signature detected, but the bounded preview is incomplete or truncated.",runKey:nmapRunKey(raw,path)};
    }
    const normalSignals=[
      /^\s*Starting Nmap\b/im,
      /^\s*#\s*Nmap\b.*scan initiated\b/im,
      /^\s*Nmap scan report for\s+.+$/im,
      /^\s*Host (?:is up|seems down)\b/im,
      /\bAll\s+\d+\s+scanned ports?\b/i,
      /^\s*Not shown:\s*\d+\s+/im,
      /^\s*PORT\s+STATE\s+SERVICE\b/im,
      /^\s*#?\s*Nmap done\b/im
    ].filter(pattern=>pattern.test(raw)).length;
    const normalComplete=/^\s*#?\s*Nmap done\b/im.test(raw)||/\b(?:QUITTING|fatal|aborted|interrupted)\b/i.test(raw);
    if(normalSignals>=2||normalSignals>=1&&/^\s*(?:Starting Nmap|Nmap scan report for)\b/im.test(raw)){
      return {matched:true,parser:"nmap-normal",representation:"Normal",signal:"Nmap normal-output run structure",complete:normalComplete,reason:normalComplete?"Nmap normal-output run structure detected.":"Nmap normal-output signature detected, but the bounded preview is incomplete or truncated.",runKey:nmapRunKey(raw,path)};
    }
    return {matched:false,parser:"",representation:"",signal:"",complete:false,reason:"",runKey:""};
  }
  function deterministicDetection(input={}){
    const name=clean(input.name)||normalizePath(input.path).split("/").pop()||"selected input";
    const path=normalizePath(input.path||name),lower=path.toLowerCase(),text=String(input.text||"").slice(0,INTAKE_LIMITS.previewBytesPerFile);
    const fileSuffix=suffix(path),size=Number(input.size)||0,signatureHex=clean(input.signatureHex||input.signature);
    const candidates=[],signals=[];let parser="",confidence="strong",structured=null,containerHint="",detectedStatus="detected",detectedReason="",runKey="",representation="";
    const add=(type,signal)=>{if(!candidates.includes(type))candidates.push(type);if(signal)signals.push(signal);};
    if(size<=0)return {intakeSchemaVersion:INTAKE_SCHEMA_VERSION,name,path,size,type:"",parser:"",label:"Empty input",status:"invalid",reason:"The selected input is empty.",candidates:[],signals:[],targetCandidates:[]};
    if(size>INTAKE_LIMITS.maximumMemberBytes&&input.kind!=="archive")return {intakeSchemaVersion:INTAKE_SCHEMA_VERSION,name,path,size,type:"",parser:"",label:"Input too large",status:"invalid",reason:`The input exceeds the ${INTAKE_LIMITS.maximumMemberBytes/MIB} MiB per-file limit.`,candidates:[],signals:[],targetCandidates:[]};
    if((fileSuffix===".zip"||zipSignature(signatureHex))&&fileSuffix!==".docx"){
      if(size>INTAKE_LIMITS.maximumArchiveBytes)return {intakeSchemaVersion:INTAKE_SCHEMA_VERSION,name,path,size,type:"zip",parser:"zip",label:IMPORT_TYPE_LABELS.zip,status:"invalid",reason:`The archive exceeds the ${INTAKE_LIMITS.maximumArchiveBytes/MIB} MiB archive limit.`,candidates:["zip"],signals:["ZIP signature"],targetCandidates:[]};
      return {intakeSchemaVersion:INTAKE_SCHEMA_VERSION,name,path,size,type:"zip",parser:"zip",label:IMPORT_TYPE_LABELS.zip,status:"detected",reason:"ZIP signature detected; safe member inspection is required before commit.",candidates:["zip"],signals:["ZIP signature"],targetCandidates:[],containerHint:"ZIP"};
    }
    structured=structuredEnumeration(text);
    if(structured){add("host-enumeration",`Supported ${structured.schema} schema`);parser="aeros-recon";}
    const nmap=nmapStructure(text,path);
    if(nmap.matched){
      add("nmap",nmap.signal);
      parser=nmap.parser;detectedStatus=nmap.complete?"detected":"invalid";detectedReason=nmap.reason;runKey=nmap.runKey;representation=nmap.representation;
    }
    const autoSupport=/(?:^|\/)(?:scans\/)?_(?:commands|errors)[.]log$/i.test(lower);
    if(autoSupport){add("scan-support","AutoRecon command/error support path");parser="autorecon-support";containerHint="AutoRecon";}
    if(/(?:^|\/)(?:results?\/)?[^/]+\/scans\//i.test(lower)||/autorecon/i.test(lower))containerHint="AutoRecon";
    const peasLinux=/linpeas|linux privilege escalation awesome script|starting linpeas/i.test(`${name}\n${text.slice(0,12000)}`);
    const peasWindows=/winpeas|windows privilege escalation awesome script/i.test(`${name}\n${text.slice(0,12000)}`);
    if(peasLinux||peasWindows){add("peas",peasWindows?"winPEAS marker":"linPEAS marker");parser=peasWindows?"winpeas":"linpeas";}
    const baseline=typeof reconApi.detectWebBaseline==="function"?reconApi.detectWebBaseline(text,{filename:name}):null;
    if(baseline?.matched){
      add("web-baseline",`${baseline.tool} ${baseline.parser} structure`);parser=baseline.parser;
      detectedStatus="detected";
      detectedReason=baseline.operationState==="completed"
        ?`${baseline.classificationLabel} detected from ${baseline.sampleCount} invalid-path samples.`
        :`A partial invalid-path baseline was detected; it may be retained without completing the objective.`;
    }
    const feroxJsonLineHint=/(?:^|\r?\n)\s*\{[^\r\n]*"type"\s*:\s*"(?:response|statistics|stats|configuration|config|summary|error)"/i.test(text);
    const feroxNamed=/ferox(?:buster)?/i.test(name),feroxFilenameHint=feroxNamed&&fileSuffix===".json";
    const feroxToolMarker=/\bferoxbuster(?:\/\d+(?:[.]\d+){1,3})?\b/i.test(text);
    const feroxConfigHint=/^\s*Configuration\s*\{/im.test(text)&&/^\s*kind\s*:\s*"configuration"\s*,?\s*$/im.test(text)&&/^\s*target_url\s*:\s*"https?:\/\/[^"\r\n]+"\s*,?\s*$/im.test(text);
    const feroxResultHint=/^\s*\d{3}\s+[A-Z]+\s+\d+l\s+\d+w\s+\d+c\s+(?:https?:\/\/|\/)\S+/im.test(text);
    const feroxTextHint=feroxResultHint&&(feroxNamed||feroxToolMarker||feroxConfigHint)||feroxConfigHint&&(feroxNamed||feroxToolMarker);
    const webHint=(
      /^\s*\{[\s\S]*"results"\s*:\s*\[/i.test(text)||feroxJsonLineHint||feroxFilenameHint||feroxTextHint||
      /gobuster/i.test(text)||/^\s*(?:\/\S+\s+\(Status:|Found:\s*)/im.test(text)||
      /^\s*DIRB\s+v?\d/im.test(text)||/^\s*(?:URL_BASE|START_TIME|END_TIME|DOWNLOADED)\s*:/im.test(text)||
      /(?:url|urls|domain|domains|path|paths|target|targets|discovery|ffuf|gobuster|dirb)/i.test(name)&&
        text.split(/\r?\n/).map(line=>line.trim()).filter(line=>line&&!line.startsWith("#")).every(line=>/^(?:https?:\/\/|\/)\S+$/i.test(line))
    );
    let web=webHint&&typeof reconApi.detectWebDiscovery==="function"?reconApi.detectWebDiscovery(text,{filename:name}):null;
    if(webHint&&!web?.matched&&feroxJsonLineHint&&typeof reconApi.detectWebDiscovery==="function"){
      const previewBytes=new TextEncoder().encode(text).length;
      if(size>previewBytes){
        const lastNewline=Math.max(text.lastIndexOf("\n"),text.lastIndexOf("\r"));
        const completePreview=lastNewline>0?text.slice(0,lastNewline).trim():"";
        if(completePreview)web=reconApi.detectWebDiscovery(completePreview,{filename:name});
      }
    }
    if(web?.matched){
      add("web-discovery",`${web.tool} ${web.parser} structure`);
      parser=web.parser;
      detectedStatus="detected";
      detectedReason=web.operationState==="failed"
        ?`${web.tool} output records a failed run; it may be retained without completing the objective.`
        :`${web.tool} ${web.parser} structure detected.`;
    }
    const whatWeb=typeof reconApi.detectWhatWeb==="function"?reconApi.detectWhatWeb(text,{filename:name}):null;
    if(whatWeb?.matched){
      add("web-technology",`${whatWeb.tool} ${whatWeb.parser} structure`);parser=whatWeb.parser;
      detectedStatus="detected";
      detectedReason=whatWeb.operationState==="failed"
        ?"WhatWeb output records a failed exact-target run; it may be retained without completing Technology work."
        :whatWeb.operationState==="partial"
          ?"WhatWeb output is structurally valid but incomplete; it may be retained as open Technology work."
          :`WhatWeb ${whatWeb.parser} structure detected.`;
    }else if(whatWeb?.unsupportedFormat==="whatweb-json-verbose"){
      add("web-technology","WhatWeb verbose JSON positional structure");parser="whatweb-json-verbose";
      detectedStatus="invalid";detectedReason=whatWeb.reason;
    }
    const documentSuffix=[".pdf",".docx",".md",".txt"].includes(fileSuffix);
    const strongDocument=pdfSignature(signatureHex,text)||(fileSuffix===".docx"&&zipSignature(signatureHex))||(fileSuffix===".md"&&/^(?:#{1,6}\s+\S+|---\s*$)/m.test(text));
    if(strongDocument){add("document",pdfSignature(signatureHex,text)?"PDF signature":fileSuffix===".docx"?"DOCX ZIP signature":"Markdown structure");if(!parser)parser="engagement-document";}
    else if(documentSuffix&&!candidates.length){add("document",`${fileSuffix.slice(1).toUpperCase()} extension with no stronger content signature`);parser="engagement-document";confidence="weak";}
    const webOrigins=web?.origins||[],technologyOrigins=whatWeb?.origins||[],baselineOrigins=baseline?.origins||[];
    const webTargets=[...webOrigins,...technologyOrigins,...baselineOrigins].map(value=>{try{return new URL(value).hostname;}catch(_error){return "";}}).filter(Boolean);
    const targets=uniqueTargets([...detectedTargets(text,structured?.data),...webTargets]);
    if(candidates.length>1){
      return {intakeSchemaVersion:INTAKE_SCHEMA_VERSION,name,path,size,type:"",parser:"",label:"Ambiguous input",status:"ambiguous",reason:`The content matches more than one supported type: ${candidates.map(type=>IMPORT_TYPE_LABELS[type]).join(", ")}. Choose the intended parser.`,candidates,signals,targetCandidates:targets,webOrigins,technologyOrigins,baselineOrigins,baselineOperationState:baseline?.operationState||"",baselineClassification:baseline?.classification||"",baselineClassificationLabel:baseline?.classificationLabel||"",baselineSampleCount:Number(baseline?.sampleCount)||0,webPathOnly:web?.pathOnly===true,webOperationState:web?.operationState||"",whatWebOperationState:whatWeb?.operationState||"",technologyResultCount:Number(whatWeb?.resultCount)||0,containerHint,confidence};
    }
    if(!candidates.length)return {intakeSchemaVersion:INTAKE_SCHEMA_VERSION,name,path,size,type:"",parser:"",label:"Unsupported",status:"unsupported",reason:"No deterministic signature matched a currently supported importer.",candidates:[],signals:[],targetCandidates:targets,containerHint,confidence:"none"};
    const type=candidates[0],weak=confidence==="weak",tool=type==="nmap"?"Nmap":type==="web-discovery"?clean(web?.tool):type==="web-baseline"?clean(baseline?.tool):type==="web-technology"?clean(whatWeb?.tool):type==="scan-support"?"AutoRecon":type==="peas"?(parser==="winpeas"?"winPEAS":"linPEAS"):"";
    return {intakeSchemaVersion:INTAKE_SCHEMA_VERSION,name,path,size,type,tool,parser,label:IMPORT_TYPE_LABELS[type]||type,status:weak?"ambiguous":detectedStatus,reason:weak?"The extension is supported, but content does not provide a strong type signature. Confirm the document parser or remove the item.":detectedReason||`${signals[0]} detected.`,candidates,signals,targetCandidates:targets,webOrigins,technologyOrigins,baselineOrigins,baselineOperationState:baseline?.operationState||"",baselineClassification:baseline?.classification||"",baselineClassificationLabel:baseline?.classificationLabel||"",baselineSampleCount:Number(baseline?.sampleCount)||0,webPathOnly:web?.pathOnly===true,webOperationState:web?.operationState||"",whatWebOperationState:whatWeb?.operationState||"",technologyResultCount:Number(whatWeb?.resultCount)||0,containerHint,confidence,runKey,representation};
  }
  function applyDetectionOverride(detection,type){
    const selected=clean(type),row={...(detection||{})};
    if(row.status!=="ambiguous"||!row.candidates?.includes(selected))return {...row,status:"invalid",reason:"That parser is not a safe candidate for this input."};
    const parser=selected==="document"?"engagement-document":selected==="peas"?(row.signals||[]).some(value=>/winpeas/i.test(value))?"winpeas":"linpeas":selected==="nmap"?(row.signals||[]).some(value=>/xml/i.test(value))?"nmap-xml":(row.signals||[]).some(value=>/grepable/i.test(value))?"nmap-grepable":"nmap-normal":selected==="host-enumeration"?"aeros-recon":selected==="scan-support"?"autorecon-support":selected==="web-discovery"?(row.parser||"web-discovery"):selected==="web-baseline"?(row.parser||"aeros-web-baseline-text"):selected==="web-technology"?(row.parser||"whatweb-json"):"";
    return {...row,type:selected,parser,label:IMPORT_TYPE_LABELS[selected]||selected,status:"detected",reason:`${IMPORT_TYPE_LABELS[selected]||selected} was explicitly selected from the deterministic candidates.`,manualOverride:true};
  }
  function targetIdentity(host={}){
    const values=[host.id,host.ip,host.hostname];
    (Array.isArray(host.networkAddresses)?host.networkAddresses:[]).filter(row=>row?.active!==false).forEach(row=>values.push(row?.address));
    [host.aliases,host.targetAliases,host.addresses,host.hostnames].forEach(group=>{if(Array.isArray(group))values.push(...group);});
    return uniqueTargets(values);
  }
  function validateDetectionTarget(detection,host={}){
    const row={...(detection||{})};
    if(!["detected","ready"].includes(row.status))return row;
    const targets=uniqueTargets(row.targetCandidates||[]),allowed=new Set(targetIdentity(host).map(value=>value.toLowerCase()));
    if(!targets.length)return {...row,status:"ready",detectedTarget:"Not stated",intendedHostId:clean(host.id),targetValidation:"operator-bound",reason:`${row.reason} No target identity is present; explicit commit binds this item to the displayed host.`};
    const unmatched=targets.filter(value=>!allowed.has(value.toLowerCase()));
    if(!unmatched.length)return {...row,status:"ready",detectedTarget:targets.join(", "),intendedHostId:clean(host.id),targetValidation:"matched"};
    if(targets.length>1&&row.parser==="nmap-xml")return {...row,status:"mapping-required",detectedTarget:targets.join(", "),intendedHostId:clean(host.id),targetValidation:"mapping-required",reason:"The Nmap XML contains multiple targets. Map every admitted target to an exact host before commit."};
    return {...row,status:"target-mismatch",detectedTarget:targets.join(", "),intendedHostId:clean(host.id),targetValidation:"mismatch",reason:`Detected target ${unmatched.join(", ")} does not match the displayed host.`};
  }
  function validateMultiTargetMappings(detection,mappings={},hosts={}){
    const row={...(detection||{})},targets=uniqueTargets(row.targetCandidates||[]);
    if(row.parser!=="nmap-xml"||targets.length<2)return {ok:false,reason:"Only multi-target Nmap XML supports explicit per-target mapping."};
    const resolved=[];
    for(const target of targets){
      const hostId=clean(mappings[target]);
      if(!hostId)return {ok:false,reason:`Map or explicitly exclude ${target} before commit.`};
      if(hostId==="exclude"){resolved.push({target,excluded:true});continue;}
      const matches=Object.entries(safeObject(hosts)).filter(([key,host])=>host&&(clean(key)===hostId||clean(host.id||key)===hostId)).map(([,host])=>host);
      const uniqueMatches=matches.filter((host,index)=>matches.indexOf(host)===index);
      if(uniqueMatches.length!==1)return {ok:false,reason:uniqueMatches.length?`The mapped host for ${target} is ambiguous.`:`The mapped host for ${target} is missing or stale.`};
      const host=uniqueMatches[0];
      if(!targetIdentity(host).some(value=>value.toLowerCase()===target.toLowerCase()))return {ok:false,reason:`${target} is not an address or alias of the mapped host.`};
      resolved.push({target,hostId:clean(host.id)||hostId,excluded:false});
    }
    if(!resolved.some(item=>!item.excluded))return {ok:false,reason:"At least one target must be admitted."};
    return {ok:true,mappings:resolved};
  }
  function validateWebOriginMappings(detection,routedOrigin={},availableOrigins=[],mappings={}){
    const row={...(detection||{})};
    if(!["web-discovery","web-technology","web-baseline"].includes(row.type))return row;
    const normalize=value=>typeof reconApi.normalizedWebOrigin==="function"?reconApi.normalizedWebOrigin(value):clean(value);
    const routeUrl=normalize(routedOrigin.url||routedOrigin.value),routeId=clean(routedOrigin.id),routeEndpointId=clean(routedOrigin.endpointId);
    const originParts=value=>{try{const url=new URL(normalize(value));return {scheme:url.protocol.replace(":",""),host:url.hostname.toLowerCase(),port:Number(url.port)||(url.protocol==="https:"?443:80)};}catch(_error){return null;}};
    const available=(availableOrigins||[]).map(origin=>({id:clean(origin.id),url:normalize(origin.url||origin.value),endpointId:clean(origin.endpointId),aliases:unique(origin.aliases||[]).map(value=>value.toLowerCase())})).filter(origin=>origin.id&&origin.url);
    const routedMatches=available.filter(origin=>origin.id===routeId&&origin.url===routeUrl);
    if(!routeId||!routeUrl||routedMatches.length!==1){
      return {...row,status:"target-mismatch",reason:"The routed exact web origin is missing, stale, or ambiguous."};
    }
    if(row.type==="web-baseline"){
      const sourceOrigins=unique(row.baselineOrigins||[]).map(normalize).filter(Boolean);
      if(sourceOrigins.some(source=>source!==routeUrl))return {...row,status:"target-mismatch",originCandidates:sourceOrigins,reason:`The baseline was measured against ${sourceOrigins.join(", ")}, not the routed exact origin ${routeUrl}. Update the AEROS origin or rerun the baseline; baseline evidence cannot be remapped.`};
      const sourceOrigin=sourceOrigins[0]||reconApi.WEB_PATH_ONLY_ORIGIN||"path-only";
      return {...row,status:"ready",originCandidates:sourceOrigins,validatedOriginMappings:[{sourceOrigin,targetOriginId:routeId,targetOriginUrl:routeUrl,excluded:false}],reason:"The invalid-path baseline is bound to the routed exact origin."};
    }
    const ownerEndpointId=routeEndpointId||routedMatches[0].endpointId;
    const sourceOrigins=unique([...(row.type==="web-technology"?row.technologyOrigins||[]:row.webOrigins||[]),...(row.webPathOnly?[reconApi.WEB_PATH_ONLY_ORIGIN||"path-only"]:[])]);
    if(!sourceOrigins.length)return {...row,status:"invalid",reason:"The web output contains no trustworthy origin or path records."};
    const resolved=[];
    for(const sourceOrigin of sourceOrigins){
      let targetId=clean(mappings[sourceOrigin]);
      const normalizedSource=sourceOrigin===(reconApi.WEB_PATH_ONLY_ORIGIN||"path-only")?sourceOrigin:normalize(sourceOrigin);
      if(row.type==="web-technology"){
        const source=originParts(normalizedSource),sameOwnerBoundary=available.filter(target=>{
          const candidate=originParts(target.url);if(!source||!candidate)return false;
          return target.endpointId===ownerEndpointId&&source.scheme===candidate.scheme&&source.port===candidate.port;
        });
        const exact=source?sameOwnerBoundary.filter(target=>originParts(target.url)?.host===source.host):[];
        if(exact.length>1)return {...row,status:"mapping-required",originCandidates:sourceOrigins,reason:`${sourceOrigin} has multiple exact current-origin owners on the same endpoint and is ambiguous.`};
        if(exact.length===1){
          if(!targetId)targetId=exact[0].id;
          if(targetId!=="exclude"&&targetId!==exact[0].id)return {...row,status:"target-mismatch",originCandidates:sourceOrigins,reason:`${sourceOrigin} exactly belongs to ${exact[0].id}; an alias or routed origin cannot replace that owner.`};
        }else{
          const aliasCandidates=source?sameOwnerBoundary.filter(target=>target.aliases.includes(source.host)):[];
          if(aliasCandidates.length>1)return {...row,status:"mapping-required",originCandidates:sourceOrigins,reason:`${sourceOrigin} matches multiple retained aliases on the same endpoint and is ambiguous.`};
          if(!targetId&&aliasCandidates.length===1)targetId=aliasCandidates[0].id;
          if(targetId&&targetId!=="exclude"&&(aliasCandidates.length!==1||aliasCandidates[0].id!==targetId))return {...row,status:"target-mismatch",originCandidates:sourceOrigins,reason:`${sourceOrigin} is not the same exact scheme, effective port, endpoint, address, or unique retained host alias as the selected origin.`};
        }
      }else if(!targetId&&sourceOrigins.length===1&&normalizedSource===routeUrl)targetId=routeId;
      if(!targetId)return {...row,status:"mapping-required",originCandidates:sourceOrigins,reason:`Map or exclude ${sourceOrigin} before commit.`};
      if(targetId==="exclude"){resolved.push({sourceOrigin,excluded:true});continue;}
      const target=available.find(origin=>origin.id===targetId);
      if(!target)return {...row,status:"mapping-required",originCandidates:sourceOrigins,reason:`The selected origin owner for ${sourceOrigin} is missing or stale.`};
      resolved.push({sourceOrigin,targetOriginId:target.id,targetOriginUrl:target.url,excluded:false});
    }
    if(!resolved.some(item=>!item.excluded))return {...row,status:"mapping-required",originCandidates:sourceOrigins,reason:"At least one web origin must be admitted."};
    return {...row,status:"ready",originCandidates:sourceOrigins,validatedOriginMappings:resolved,reason:"Every admitted web result is bound to an explicit exact origin."};
  }
  function normalizeRevision(raw={},fallback=1){return {
    revision:Math.max(1,Number.parseInt(raw.revision,10)||fallback),
    sha256:clean(raw.sha256).toLowerCase(),
    filename:clean(raw.filename||raw.originalFilename),
    sourceArchive:clean(raw.sourceArchive),
    importedAt:clean(raw.importedAt||raw.observedAt),
    data:raw.data&&typeof raw.data==="object"?raw.data:null
  };}
  function normalizeImportRecord(raw={}){
    const revisions=(Array.isArray(raw.revisions)?raw.revisions:[]).filter(row=>row&&typeof row==="object").map((row,index)=>normalizeRevision(row,index+1)).sort((a,b)=>a.revision-b.revision);
    const currentRevision=Math.max(1,Number.parseInt(raw.currentRevision,10)||revisions.at(-1)?.revision||1);
    const current=[...revisions].reverse().find(row=>row.revision===currentRevision)||revisions.at(-1)||null;
    const data=(current?.data||raw.data||{});
    const filename=current?.filename||clean(raw.filename)||"Recon import";
    const logicalKey=clean(raw.logicalKey)||reconLogicalKey(data);
    const digest=(current?.sha256||clean(raw.sha256)).toLowerCase();
    return {
      ...raw,
      importLifecycleSchemaVersion:SCHEMA_VERSION,
      id:clean(raw.id)||randomId("recon-import"),
      filename,
      sourceArchive:current?.sourceArchive||clean(raw.sourceArchive),
      data,
      logicalKey,
      targetSignature:clean(raw.targetSignature)||reconTargetSignature(data),
      sha256:digest,
      currentRevision,
      revisionCount:Math.max(currentRevision,revisions.length,1),
      revisions,
      aliases:unique([...(Array.isArray(raw.aliases)?raw.aliases:[]),filename,clean(raw.sourceArchive)]),
      importHistory:(Array.isArray(raw.importHistory)?raw.importHistory:[]).filter(row=>row&&typeof row==="object").slice(-MAX_HISTORY),
      firstSeenAt:clean(raw.firstSeenAt||raw.importedAt),
      lastSeenAt:clean(raw.lastSeenAt||raw.updatedAt||raw.importedAt),
      lastImportStatus:clean(raw.lastImportStatus)
    };
  }
  function revisionHashes(item){return new Set([clean(item.sha256).toLowerCase(),...(item.revisions||[]).map(row=>clean(row.sha256).toLowerCase())].filter(Boolean));}
  function hydrateImportRecord(raw,sha256,{observedAt=""}={}){
    const at=clean(observedAt)||clean(raw?.importedAt)||nowIso();
    const item=normalizeImportRecord({...raw,sha256:clean(sha256).toLowerCase(),firstSeenAt:raw?.firstSeenAt||at,lastSeenAt:raw?.lastSeenAt||at});
    if(!item.revisions.length){item.currentRevision=1;item.revisionCount=1;item.revisions=[normalizeRevision({...item,revision:1,importedAt:at})];}
    if(!item.importHistory.length)item.importHistory=[{observedAt:at,outcome:"legacy-hydrated",revision:item.currentRevision,sha256:item.sha256,filename:item.filename,sourceArchive:item.sourceArchive}];
    return item;
  }
  function upsertImportRecord(records,incoming,{observedAt=""}={}){
    const rows=Array.isArray(records)?records:[];
    const at=clean(observedAt)||nowIso();
    const normalizedIncoming=normalizeImportRecord({...incoming,firstSeenAt:incoming.firstSeenAt||at,lastSeenAt:at});
    let existing=normalizedIncoming.sha256?rows.find(row=>revisionHashes(normalizeImportRecord(row)).has(normalizedIncoming.sha256)):null;
    let outcome=existing?"unchanged":"new";
    if(!existing){
      existing=rows.find(row=>normalizeImportRecord(row).logicalKey===normalizedIncoming.logicalKey);
      if(existing){
        const normalizedExisting=normalizeImportRecord(existing);
        if(normalizedExisting.targetSignature&&normalizedIncoming.targetSignature&&normalizedExisting.targetSignature!==normalizedIncoming.targetSignature){
          return {outcome:"conflicts",record:normalizedExisting,incoming:normalizedIncoming,reason:"The same collector identity describes a different target, scope, or execution user."};
        }
        outcome="updated";
      }
    }
    if(!existing){
      normalizedIncoming.currentRevision=1;normalizedIncoming.revisionCount=1;normalizedIncoming.lastImportStatus="new";
      normalizedIncoming.revisions=[normalizeRevision({...normalizedIncoming,revision:1,importedAt:at})];
      normalizedIncoming.importHistory=[{observedAt:at,outcome:"new",revision:1,sha256:normalizedIncoming.sha256,filename:normalizedIncoming.filename,sourceArchive:normalizedIncoming.sourceArchive}];
      rows.push(normalizedIncoming);return {outcome:"new",record:normalizedIncoming};
    }
    const item=normalizeImportRecord(existing);
    if(outcome==="updated"){
      const revision=Math.max(item.currentRevision,...item.revisions.map(row=>row.revision),0)+1;
      item.revisions.push(normalizeRevision({...normalizedIncoming,revision,importedAt:at}));
      item.currentRevision=revision;item.revisionCount=item.revisions.length;item.filename=normalizedIncoming.filename;item.sourceArchive=normalizedIncoming.sourceArchive;item.data=normalizedIncoming.data;item.sha256=normalizedIncoming.sha256;
    }
    const revision=outcome==="updated"?item.currentRevision:(item.revisions.find(row=>row.sha256===normalizedIncoming.sha256)?.revision||item.currentRevision);
    item.aliases=unique([...item.aliases,normalizedIncoming.filename,normalizedIncoming.sourceArchive]);
    item.importHistory=[...item.importHistory,{observedAt:at,outcome,revision,sha256:normalizedIncoming.sha256,filename:normalizedIncoming.filename,sourceArchive:normalizedIncoming.sourceArchive}].slice(-MAX_HISTORY);
    item.lastSeenAt=at;item.updatedAt=at;item.lastImportStatus=outcome;
    const index=rows.indexOf(existing);rows.splice(index,1,item);
    return {outcome,record:item};
  }
  function importSummary(outcomes=[]){
    const summary={new:0,updated:0,unchanged:0,skipped:0,conflicts:0};
    for(const value of outcomes){const key=clean(value?.outcome||value).toLowerCase();if(Object.prototype.hasOwnProperty.call(summary,key))summary[key]++;}
    return summary;
  }
  function formatImportSummary(summary={},noun="artifact"){
    const count=key=>Number(summary[key])||0;
    return `New ${noun}s: ${count("new")} · Updated revisions: ${count("updated")} · Unchanged duplicates: ${count("unchanged")} · Skipped: ${count("skipped")} · Conflicts: ${count("conflicts")}`;
  }
  function ensureHostEnumerationState(host){
    if(!host||typeof host!=="object")return {};
    host.systemInfo=host.systemInfo&&typeof host.systemInfo==="object"?host.systemInfo:{};
    const current=host.systemInfo.importedFieldState;
    if(!current||typeof current!=="object"||Array.isArray(current))host.systemInfo.importedFieldState={};
    return host.systemInfo.importedFieldState;
  }
  function markImportedField(host,fieldKey,metadata={}){
    const state=ensureHostEnumerationState(host),key=clean(fieldKey);if(!key)return null;
    const at=clean(metadata.importedAt)||nowIso(),previous=state[key]&&typeof state[key]==="object"?state[key]:{};
    state[key]={...previous,fieldKey:key,mode:"preview",editing:false,imported:true,sourceId:clean(metadata.sourceId||previous.sourceId),sourceName:clean(metadata.sourceName||previous.sourceName),sourceArchive:clean(metadata.sourceArchive||previous.sourceArchive),section:clean(metadata.section||previous.section),importedAt:at,lastUpdatedAt:at};
    return state[key];
  }
  function fieldMode(host,fieldKey,{hasValue=false,defaultMode=""}={}){
    const item=ensureHostEnumerationState(host)[clean(fieldKey)];
    if(item?.editing)return "edit";
    if(item?.imported&&hasValue)return "preview";
    return clean(defaultMode)||(hasValue?"preview":"edit");
  }
  function setFieldEditing(host,fieldKey,editing){
    const state=ensureHostEnumerationState(host),key=clean(fieldKey);if(!key)return null;
    const item=state[key]&&typeof state[key]==="object"?state[key]:{fieldKey:key,imported:false};
    item.editing=Boolean(editing);item.mode=item.editing?"edit":"preview";item.lastUpdatedAt=nowIso();state[key]=item;return item;
  }
  function fieldProvenance(host,fieldKey){return ensureHostEnumerationState(host)[clean(fieldKey)]||null;}

  return {SCHEMA_VERSION,INTAKE_SCHEMA_VERSION,INTAKE_LIMITS,IMPORT_TYPE_LABELS,stableStringify,sha256Text,reconLogicalKey,reconTargetSignature,normalizeImportRecord,hydrateImportRecord,upsertImportRecord,importSummary,formatImportSummary,nmapRunCommand,nmapRunKey,nmapStructure,deterministicDetection,applyDetectionOverride,targetIdentity,validateDetectionTarget,validateMultiTargetMappings,validateWebOriginMappings,ensureHostEnumerationState,markImportedField,fieldMode,setFieldEditing,fieldProvenance};
});
