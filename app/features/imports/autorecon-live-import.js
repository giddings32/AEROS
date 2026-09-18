(function(root,factory){
  const api=factory();
  if(typeof module==="object"&&module.exports)module.exports=api;
  if(root)root.AEROSAutoReconLiveImport=api;
})(typeof window!=="undefined"?window:globalThis,function(){
  "use strict";

  const MANIFEST_SCHEMA_VERSION=1;
  const MANIFEST_BASENAME="aeros-autorecon-run.json";
  const TERMINAL_RUN_STATUSES=new Set(["completed","failed","interrupted"]);
  const STRUCTURAL_DIRECTORIES=new Set(["scans","report","loot","exploit"]);
  const SIGNAL_FILES=new Set(["_commands.log","_manual_commands.txt","_errors.log","_patterns.log"]);
  const ACTIVE_EXTENSIONS=new Set(["html","htm","svg","xml","xhtml"]);
  const IMAGE_EXTENSIONS=new Set(["png","jpg","jpeg","gif","webp","bmp","svg","avif"]);
  const TEXT_EXTENSIONS=new Set(["txt","log","xml","html","htm","json","csv","md","markdown","yaml","yml","ini","conf","config","cfg","toml","py","sh","bash","zsh","ps1","bat","cmd","rb","pl","php","jsp","jspx","asp","aspx","ashx","asmx","js","css","sql","nmap","gnmap","ctd","out","lst","list","pem","crt","cer","key","pub","properties","service","env"]);
  const REVIEW_STATES=Object.freeze(["new","reviewed","follow-up-required","resolved"]);
  const OTHER_SERVICE_FAMILY="Other / Unclassified";
  const SERVICE_REVIEW_ORDER=Object.freeze([
    "WEB","SMB / NetBIOS","FTP","SNMP","DNS","LDAP","Kerberos","NFS","SMTP / Mail","Databases","RDP","WinRM","SSH"
  ]);
  const AUTORECON_REPORT_PLACEHOLDERS=new Set(["local.txt","proof.txt"]);
  const AUTORECON_NOTES_NAME="notes.txt";
  const AUTORECON_NOTES_HEADING=/^\s*\[\*\]\s+(.+?)\s+found\s+on\s+(tcp|udp)\s*\/\s*(\d{1,5})\s*\.?\s*$/i;
  const SENSITIVE_OPTION=/(?:^|[-_.])(?:api[-_.]?key|access[-_.]?key|private[-_.]?key|session[-_.]?key|auth[-_.]?token|client[-_.]?secret|password|passwd|pass|token|secret|credentials?|credential|cred|key)$/i;
  const REDACTED_ARGUMENT="[REDACTED]";
  const clean=value=>String(value??"").trim();
  const lower=value=>clean(value).toLowerCase();
  const unique=values=>[...new Set((values||[]).map(clean).filter(Boolean))];

  function normalizePath(value){
    const raw=clean(value).replace(/\\/g,"/").replace(/^\/+|\/+$/g,"");
    if(!raw)return "";
    const parts=raw.split("/");
    if(parts.some(part=>!part||part==="."||part===".."||part.length>255||/[\u0000-\u001f\u007f]/.test(part)))return "";
    return parts.join("/");
  }
  function pathParts(value){const normalized=normalizePath(value);return normalized?normalized.split("/"):[];}
  function basename(value){return pathParts(value).at(-1)||"";}
  function dirname(value){const parts=pathParts(value);parts.pop();return parts.join("/");}
  function extension(value){const match=basename(value).match(/\.([^.]+)$/);return match?lower(match[1]):"";}
  function stripRoot(value,rootName=""){
    const parts=pathParts(value);if(rootName&&lower(parts[0])===lower(rootName))parts.shift();return parts.join("/");
  }
  function pathWithin(path,root){const candidate=normalizePath(path),parent=normalizePath(root);return candidate===parent||candidate.startsWith(`${parent}/`);}
  function isManifestPath(value){return lower(basename(value))===MANIFEST_BASENAME;}
  function isTerminalRunStatus(value){return TERMINAL_RUN_STATUSES.has(lower(value));}
  function safePhysicalDirectory(value){
    const candidate=clean(value),stem=lower(candidate.split(".")[0]),reserved=/^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])$/;
    return !!candidate&&candidate.length<=255&&!/[<>:"/\\|?*\u0000-\u001f\u007f]/.test(candidate)&&!/[ .]$/.test(candidate)&&candidate!=="."&&candidate!==".."&&!reserved.test(stem);
  }
  function validIso(value,required=false){if(!clean(value))return !required;return Number.isFinite(new Date(value).getTime());}
  function validPort(value){const port=Number(value);return Number.isInteger(port)&&port>=1&&port<=65535;}
  function isIpv4(value){const parts=clean(value).split(".");return parts.length===4&&parts.every(part=>/^\d{1,3}$/.test(part)&&Number(part)>=0&&Number(part)<=255);}
  function isIpv6(value){const candidate=clean(value).replace(/^\[|\]$/g,"");if(!candidate.includes(":")||!/^[0-9a-f:.]+$/i.test(candidate))return false;try{return new URL(`http://[${candidate}]/`).hostname.replace(/^\[|\]$/g,"").includes(":");}catch(_error){return false;}}
  function normalizeIp(value){const candidate=clean(value).replace(/^\[|\]$/g,"");return isIpv4(candidate)||isIpv6(candidate)?candidate.toLowerCase():"";}
  function safeDiagnosticText(value,limit=4096){const text=clean(value);if(text.length>limit||/[\u0000]/.test(text))throw new Error("The AutoRecon manifest contains an invalid diagnostic field.");return text;}
  function redactManifestArgv(values=[]){
    const out=[];let redactNext=false;
    for(const raw of values){const value=String(raw);if(redactNext){out.push(REDACTED_ARGUMENT);redactNext=false;continue;}const separator=value.indexOf("="),option=separator>=0?value.slice(0,separator):value;if(value.startsWith("-")&&separator>=0&&SENSITIVE_OPTION.test(option.replace(/^-+/,""))){out.push(`${option}=${REDACTED_ARGUMENT}`);continue;}out.push(value);if(value.startsWith("-")&&SENSITIVE_OPTION.test(value.replace(/^-+/,"")))redactNext=true;}
    return out;
  }
  function manifestCommandDisplay(argv=[]){return argv.map(value=>/^[A-Za-z0-9_./:\\-]+$/.test(value)?value:`'${value.replace(/'/g,"'\\''")}'`).join(" ");}
  function normalizedTransport(raw,status,{requiresTerminalCopy=false,outputRoot="",stagingOutputRoot=""}={}){
    if(!raw||typeof raw!=="object"||Array.isArray(raw)){
      const mode=requiresTerminalCopy?"terminal-copy":"direct";
      return {mode,status:mode==="direct"?"complete":"absent",sourceRoot:outputRoot,finalRoot:stagingOutputRoot,recoveryRoot:"",incomingRoot:"",startedAt:"",completedAt:"",error:mode==="terminal-copy"?"The terminal-copy transport record is absent.":"",diagnostics:[],reason:mode==="terminal-copy"?"Encoded output cannot be finalized without a verified transport record.":"Legacy direct output requires no terminal copy.",present:false};
    }
    const mode=lower(raw.mode),transportStatus=lower(raw.status),sourceRoot=safeDiagnosticText(raw.sourceRoot),finalRoot=safeDiagnosticText(raw.finalRoot),recoveryRoot=safeDiagnosticText(raw.recoveryRoot),incomingRoot=safeDiagnosticText(raw.incomingRoot),startedAt=clean(raw.startedAt),completedAt=clean(raw.completedAt),error=safeDiagnosticText(raw.error,16384),reason=safeDiagnosticText(raw.reason,16384);
    if(!["direct","terminal-copy"].includes(mode))throw new Error("The AutoRecon manifest transport.mode is invalid.");
    if(!["pending","copying","complete","failed"].includes(transportStatus))throw new Error("The AutoRecon manifest transport.status is invalid.");
    if(mode==="direct"&&transportStatus!=="complete")throw new Error("Direct AutoRecon transport must be complete.");
    if(mode==="terminal-copy"&&transportStatus==="complete"&&(!finalRoot||!validIso(completedAt,true)))throw new Error("Completed terminal-copy transport requires a final root and completion timestamp.");
    if(mode==="terminal-copy"&&transportStatus==="failed"&&(!recoveryRoot||!error))throw new Error("Failed terminal-copy transport requires a recovery root and actionable error.");
    if(startedAt&&!validIso(startedAt)||completedAt&&!validIso(completedAt))throw new Error("The AutoRecon manifest transport timestamps are invalid.");
    const diagnostics=Array.isArray(raw.diagnostics)?raw.diagnostics.slice(0,1000).map(row=>{if(!row||typeof row!=="object"||Array.isArray(row))throw new Error("The AutoRecon manifest transport diagnostics are invalid.");return {path:safeDiagnosticText(row.path),kind:safeDiagnosticText(row.kind,200),message:safeDiagnosticText(row.message,4096)};}):[];
    return {mode,status:transportStatus,sourceRoot,finalRoot,recoveryRoot,incomingRoot,startedAt,completedAt,error,diagnostics,reason,present:true};
  }
  function transportReady(manifest={}){const transport=manifest.transport||{};return transport.mode==="direct"?transport.status==="complete":transport.mode==="terminal-copy"&&transport.status==="complete";}

  function normalizedManifestTarget(raw,index){
    const source=typeof raw==="string"?{originalTarget:raw}:raw&&typeof raw==="object"?raw:{};
    const originalTarget=clean(source.originalTarget||source.target),rawResolvedIp=clean(source.resolvedIp||source.resolvedIP),resolvedIp=normalizeIp(rawResolvedIp),physicalDirectory=clean(source.physicalDirectory||source.outputDirectory||originalTarget);
    if(!originalTarget)throw new Error(`AutoRecon manifest target ${index+1} is missing originalTarget.`);
    if(!safePhysicalDirectory(physicalDirectory))throw new Error(`AutoRecon manifest target ${index+1} has an unsafe physicalDirectory.`);
    if(rawResolvedIp&&!resolvedIp)throw new Error(`AutoRecon manifest target ${index+1} has an invalid resolvedIp.`);
    return {originalTarget,resolvedIp,physicalDirectory};
  }
  function parseRunManifest(text,{relativePath="",rootName=""}={}){
    let raw;try{raw=JSON.parse(String(text??""));}catch(_error){throw new Error("The AutoRecon run manifest is not valid JSON.");}
    if(!raw||typeof raw!=="object"||Array.isArray(raw))throw new Error("The AutoRecon run manifest must be a JSON object.");
    if(Number(raw.schemaVersion)!==MANIFEST_SCHEMA_VERSION)throw new Error(`Unsupported AutoRecon manifest schemaVersion ${raw.schemaVersion}.`);
    const runId=clean(raw.runId),tool=clean(raw.tool),autoReconVersion=clean(raw.autoReconVersion||raw.toolVersion),engagement=clean(raw.engagement),outputRoot=clean(raw.outputRoot),physicalEngagementDirectory=clean(raw.physicalEngagementDirectory),stagingOutputRoot=clean(raw.stagingOutputRoot),wrapperError=safeDiagnosticText(raw.wrapperError,16384),status=lower(raw.status),startedAt=clean(raw.startedAt||raw.startTime),completedAt=clean(raw.completedAt||raw.completionTime),exitCode=raw.exitCode===null||raw.exitCode===undefined?null:Number(raw.exitCode);
    if(!/^[A-Za-z0-9](?:[A-Za-z0-9._-]{6,158}[A-Za-z0-9_-])$/.test(runId))throw new Error("The AutoRecon run manifest has an invalid runId.");
    if(lower(tool)!=="autorecon")throw new Error("The run manifest tool must be AutoRecon.");
    if(!autoReconVersion||autoReconVersion.length>80)throw new Error("The AutoRecon run manifest is missing autoReconVersion.");
    if(!engagement||engagement.length>200||pathParts(engagement).length!==1)throw new Error("The AutoRecon run manifest is missing or has an unsafe engagement.");
    if(physicalEngagementDirectory&&!safePhysicalDirectory(physicalEngagementDirectory))throw new Error("The AutoRecon run manifest has an unsafe physicalEngagementDirectory.");
    if(stagingOutputRoot.length>4096||/[\u0000]/.test(stagingOutputRoot))throw new Error("The AutoRecon run manifest has an invalid stagingOutputRoot.");
    if(!outputRoot||outputRoot.length>4096)throw new Error("The AutoRecon run manifest is missing outputRoot.");
    if(!new Set(["running",...TERMINAL_RUN_STATUSES]).has(status))throw new Error("The AutoRecon run manifest status is invalid.");
    if(!validIso(startedAt,true)||!validIso(completedAt,isTerminalRunStatus(status)))throw new Error("The AutoRecon run manifest timestamps are invalid.");
    if(isTerminalRunStatus(status)&&(!Number.isInteger(exitCode)||exitCode<0||exitCode>255))throw new Error("A terminal AutoRecon run manifest requires an integer exitCode from 0 through 255.");
    if(status==="running"&&exitCode!==null)throw new Error("A running AutoRecon manifest cannot have an exitCode.");
    const layout=raw.layout&&typeof raw.layout==="object"?raw.layout:{};
    for(const key of ["singleTarget","onlyScansDir","noPortDirs"])if(typeof layout[key]!=="boolean")throw new Error(`The AutoRecon manifest layout.${key} flag must be boolean.`);
    const command=raw.command&&typeof raw.command==="object"?raw.command:{};
    if(!Array.isArray(command.argv)||!command.argv.length||command.argv.length>4096||command.argv.some(value=>typeof value!=="string"||value.length>8192||/[\u0000]/.test(value)))throw new Error("The AutoRecon manifest command.argv is invalid.");
    const targetInput=Array.isArray(raw.targets)&&raw.targets.length?raw.targets:[{originalTarget:raw.originalTarget,resolvedIp:raw.resolvedIp,physicalDirectory:raw.physicalDirectory}];
    if(!targetInput.length||targetInput.length>4096)throw new Error("The AutoRecon run manifest requires at least one target.");
    const targets=targetInput.map(normalizedManifestTarget),requiresTerminalCopy=targets.some(target=>target.physicalDirectory!==target.originalTarget),transport=normalizedTransport(raw.transport,status,{requiresTerminalCopy,outputRoot,stagingOutputRoot});
    if(layout.singleTarget&&targets.length!==1)throw new Error("singleTarget manifests must describe exactly one target.");
    const manifestPath=stripRoot(relativePath,rootName),relativeRoot=dirname(manifestPath);
    if(!manifestPath||!isManifestPath(manifestPath))throw new Error("The AutoRecon manifest path is not recognized.");
    const safeArgv=redactManifestArgv(command.argv),argvSha256=/^[0-9a-f]{64}$/i.test(clean(command.argvSha256))?lower(command.argvSha256):"",scannerStatus=lower(raw.scannerStatus||status),scannerExitCode=raw.scannerExitCode===null||raw.scannerExitCode===undefined?exitCode:Number(raw.scannerExitCode),wrapperExitCode=raw.wrapperExitCode===null||raw.wrapperExitCode===undefined?exitCode:Number(raw.wrapperExitCode);
    return {schemaVersion:MANIFEST_SCHEMA_VERSION,runId,tool:"AutoRecon",autoReconVersion,originalTarget:clean(raw.originalTarget||targets[0].originalTarget),resolvedIp:normalizeIp(raw.resolvedIp||targets[0].resolvedIp),engagement,physicalEngagementDirectory,outputRoot,stagingOutputRoot,startedAt,completedAt,status,exitCode,scannerStatus,scannerExitCode,wrapperExitCode,layout:{singleTarget:layout.singleTarget,onlyScansDir:layout.onlyScansDir,noPortDirs:layout.noPortDirs},command:{argv:safeArgv,display:manifestCommandDisplay(safeArgv),argvSha256,redacted:safeArgv.some((value,index)=>value!==command.argv[index])||command.redacted===true},targets,transport,wrapperError,manifestPath,relativeRoot,updatedAt:clean(raw.updatedAt)||completedAt||startedAt};
  }

  function manifestForArtifact(manifests,path,{rootName=""}={}){
    const candidate=stripRoot(path,rootName),rows=Array.isArray(manifests)?manifests:manifests instanceof Map?[...manifests.values()]:Object.values(manifests||{});
    return rows.filter(row=>row&&pathWithin(candidate,row.relativeRoot)).sort((a,b)=>b.relativeRoot.length-a.relativeRoot.length)[0]||null;
  }
  function aggregateReportPath(relative){
    const parts=pathParts(relative),first=lower(parts[0]);
    return first==="report.md"||first==="report.xml.ctd"||first==="report.ctd"||first==="autorecon-report.md";
  }
  function canonicalLogicalPath(route={}){
    const manifest=route.manifest||{},engagement=clean(route.engagement||manifest.engagement),artifactPath=normalizePath(route.artifactPath||route.filename),runId=clean(route.runId||manifest.runId);
    if(!engagement||!artifactPath)return "";
    if(route.status==="manifest"||isManifestPath(artifactPath))return normalizePath([engagement,"__engagement__","__runs__",runId||"unknown-run",artifactPath].join("/"));
    if(route.scope==="engagement")return normalizePath([engagement,"__engagement__",artifactPath].join("/"));
    const host=normalizeIp(route.hostAddress||route.host||route.target?.resolvedIp);return host?normalizePath([engagement,host,artifactPath].join("/")):"";
  }
  function targetForPhysicalDirectory(manifest,directory){
    const exact=lower(directory);return (manifest?.targets||[]).filter(row=>lower(row.physicalDirectory)===exact||lower(row.originalTarget)===exact);
  }
  function routeFromManifest(relativePath,manifest,{rootName=""}={}){
    const full=stripRoot(relativePath,rootName),root=normalizePath(manifest?.relativeRoot);
    if(!manifest||!pathWithin(full,root))return null;
    const local=full===root?"":full.slice(root.length+1),parts=pathParts(local);
    if(!parts.length)return {ok:false,status:"invalid-route",reason:"The manifest output root does not name an artifact.",relativePath:full,manifest};
    if(isManifestPath(local))return {ok:true,status:"manifest",scope:"engagement",engagement:manifest.engagement,artifactPath:local,filename:basename(local),relativePath:full,manifest};
    if(aggregateReportPath(local))return {ok:true,status:"routed",scope:"engagement",engagement:manifest.engagement,artifactPath:local,filename:basename(local),relativePath:full,manifest,reason:"AutoRecon multi-target aggregate reports remain engagement-level evidence."};
    let target=null,artifactParts=[];
    if(manifest.layout.singleTarget&&STRUCTURAL_DIRECTORIES.has(lower(parts[0]))){target=manifest.targets[0];artifactParts=parts;}
    else{
      const matches=targetForPhysicalDirectory(manifest,parts[0]);
      if(matches.length===1){target=matches[0];artifactParts=parts.slice(1);}
      else if(matches.length>1)return {ok:false,status:"ambiguous-host",retryable:true,reason:`Manifest physical directory ${parts[0]} maps to more than one target.`,relativePath:full,manifest};
    }
    if(!target)return {ok:true,status:"routed",scope:"engagement",engagement:manifest.engagement,artifactPath:local,filename:basename(local),relativePath:full,manifest,reason:"The artifact is at the AutoRecon output root and has no exact target directory owner."};
    const host=normalizeIp(target.resolvedIp)||normalizeIp(target.originalTarget);
    if(!host)return {ok:false,status:"host-unresolved",retryable:true,reason:`Manifest target ${target.originalTarget} has no authoritative resolved IP.`,relativePath:full,engagement:manifest.engagement,manifest,target};
    if(!artifactParts.length)return {ok:false,status:"invalid-route",reason:"The routed AutoRecon target path does not name an artifact.",relativePath:full,engagement:manifest.engagement,host,manifest,target};
    return {ok:true,status:"routed",scope:"host",relativePath:full,engagement:manifest.engagement,host,hostAddress:host,artifactPath:artifactParts.join("/"),filename:artifactParts.at(-1),manifest,target,runId:manifest.runId,runStatus:manifest.status};
  }

  function autoReconOwnership(path,{route={},classification={}}={}){
    const normalized=normalizePath(path),parts=pathParts(normalized),lowerParts=parts.map(lower);
    const manifestOwned=Boolean(route?.manifest),explicitRouteOwned=route?.autoReconOwned===true,classifiedOwned=classification?.autoReconOwned===true||lower(classification?.ownership)==="autorecon"||lower(classification?.source)==="autorecon"||lower(classification?.tool)==="autorecon";
    const canonicalOwned=lowerParts.some(part=>part.startsWith("autorecon-run-"))||/^(?:autorecon|aeros-autorecon|sample-autorecon)$/i.test(parts[0]||"");
    const owned=manifestOwned||explicitRouteOwned||classifiedOwned||canonicalOwned;
    return {owned,source:manifestOwned?"manifest-route":explicitRouteOwned?clean(route.autoReconOwnershipSource)||"explicit-route":classifiedOwned?"classified-record":canonicalOwned?"recognized-autorecon-path":"",manifestOwned,explicitRouteOwned,classifiedOwned,canonicalOwned};
  }
  function autoReconReportContext(path,{route={},classification={}}={}){
    const routed=normalizePath(route?.artifactPath),candidate=routed||normalizePath(path),parts=pathParts(candidate),lowerParts=parts.map(lower),reportIndex=lowerParts.lastIndexOf("report");
    if(reportIndex<0||reportIndex!==parts.length-2)return null;
    const filename=lower(parts.at(-1));
    if(!AUTORECON_REPORT_PLACEHOLDERS.has(filename)&&filename!==AUTORECON_NOTES_NAME)return null;
    const ownership=autoReconOwnership(routed?path:candidate,{route,classification});
    if(!ownership.owned)return null;
    return {path:candidate,relativePath:`report/${filename}`,filename,reportIndex,ownershipSource:ownership.source,...ownership};
  }
  function analyzeAutoReconNotes(value){
    const raw=String(value??"").replace(/\r\n?/g,"\n"),lines=raw.split("\n"),sections=[];let current=null,preamble=[];
    const finish=()=>{if(current){current.body=current.lines.join("\n").replace(/^\s+|\s+$/g,"");if(current.body)sections.push(current);current=null;}};
    for(const line of lines){
      const match=AUTORECON_NOTES_HEADING.exec(line);
      if(match&&validPort(match[3])){finish();current={service:clean(match[1]),protocol:lower(match[2]),port:Number(match[3]),heading:line.trim(),lines:[],body:""};continue;}
      if(current)current.lines.push(line);else preamble.push(line);
    }
    finish();
    const preambleText=preamble.join("\n").replace(/^\s+|\s+$/g,""),meaningful=[];
    if(preambleText)meaningful.push(preambleText);
    for(const section of sections)meaningful.push(`[${section.service} · ${section.protocol.toUpperCase()}/${section.port}]\n${section.body}`);
    const generatedHeadings=lines.filter(line=>AUTORECON_NOTES_HEADING.test(line)).length;
    return {raw,templateOnly:meaningful.length===0,meaningfulText:meaningful.join("\n\n").trim(),generatedHeadings,sections:sections.map(({service,protocol,port,body})=>({service,protocol,port,body}))};
  }
  function semanticDisposition(input={}){
    const context=autoReconReportContext(input.path||input.relativePath,{route:input.route||{},classification:input.classification||{}});
    if(!context)return {action:"retain",kind:"ordinary-artifact",reason:"The path is not a recognized AutoRecon report scaffold."};
    if(AUTORECON_REPORT_PLACEHOLDERS.has(context.filename))return {action:"ignore",kind:"autorecon-report-placeholder",context,reason:`Recognized AutoRecon ${context.relativePath} is generated report scaffolding, not evidence.`};
    const contentAvailable=input.contentAvailable===true||input.contentAvailable!==false&&(Object.prototype.hasOwnProperty.call(input,"text")||Object.prototype.hasOwnProperty.call(input,"snapshot"));
    if(!contentAvailable)return {action:"inspect",kind:"autorecon-notes",context,reason:"AutoRecon report/notes.txt requires content-aware recognition."};
    const text=Object.prototype.hasOwnProperty.call(input,"text")?input.text:input.snapshot?.text;
    const analysis=analyzeAutoReconNotes(text);
    if(analysis.templateOnly)return {action:"ignore",kind:"autorecon-notes-template",context,analysis,reason:"AutoRecon report/notes.txt contains only generated service headings and whitespace."};
    return {action:"retain",kind:"external-autorecon-notes",context,analysis,meaningfulText:analysis.meaningfulText,reason:"Operator-authored content beyond the AutoRecon notes template is retained as external notes."};
  }
  function applySemanticClassification(classification={},semantic={}){
    if(semantic.kind!=="external-autorecon-notes")return {...classification};
    return {...classification,category:"external-notes",routingLevel:"host",tool:"Operator-authored",autoReconOwned:true,semanticKind:semantic.kind,scannerEvidence:false,endpointEvidence:false,displayLabel:"External AutoRecon Notes"};
  }
  function reconcileSemanticInventory(records=[]){
    const rows=Array.isArray(records)?records:[],kept=[],removed=[],updated=[];
    for(const row of rows){
      if(!row||typeof row!=="object"){kept.push(row);continue;}
      const path=row.logicalPath||row.path||row.sourcePath,classification={...(row.classification||{})},hasCompleteText=row.binary!==true&&row.metadataOnly!==true&&row.previewTruncated!==true&&Object.prototype.hasOwnProperty.call(row,"preview");
      if(row.autoReconOwned===true||clean(row.runId))classification.autoReconOwned=true;
      const semantic=semanticDisposition({path,classification,text:hasCompleteText?row.preview:undefined,contentAvailable:hasCompleteText});
      if(semantic.action==="ignore"){removed.push({...row,semanticReason:semantic.reason});continue;}
      if(semantic.kind==="external-autorecon-notes"){
        const next={...row,classification:applySemanticClassification(classification,semantic),semanticPreview:semantic.meaningfulText,semanticKind:semantic.kind};
        if(JSON.stringify(row.classification||{})===JSON.stringify(next.classification)&&clean(row.semanticPreview)===clean(next.semanticPreview)&&clean(row.semanticKind)===next.semanticKind){kept.push(row);continue;}
        kept.push(next);updated.push(next);continue;
      }
      kept.push(row);
    }
    rows.splice(0,rows.length,...kept);return {records:rows,removed,updated};
  }

  const TOOL_RULES=Object.freeze([
    [/feroxbuster/i,"Feroxbuster"],[/gobuster/i,"Gobuster"],[/dirsearch/i,"Dirsearch"],[/ffuf/i,"FFUF"],[/dirbuster|(?:^|[_-])dirb(?:[_-]|\.)/i,"Directory discovery"],
    [/whatweb/i,"WhatWeb"],[/nikto/i,"Nikto"],[/wpscan/i,"WPScan"],[/curl/i,"Curl"],[/sslscan/i,"SSLScan"],[/enum4linux-ng/i,"Enum4Linux-NG"],[/enum4linux/i,"Enum4Linux"],
    [/smbmap/i,"SMBMap"],[/smbclient/i,"SMBClient"],[/nbtscan/i,"NBTScan"],[/snmpwalk|onesixtyone|snmp/i,"SNMP"],[/dnsrecon|(?:^|[_-])dig(?:[_-]|\.)|dns/i,"DNS"],[/nmap/i,"Nmap"]
  ]);
  function toolForPath(path){const name=basename(path);for(const [pattern,label] of TOOL_RULES)if(pattern.test(name))return label;return "Unparsed artifact";}
  function endpointFromPath(path){
    const normalized=normalizePath(path),directory=normalized.match(/(?:^|\/)scans\/(tcp|udp)(\d+)(?:\/|$)/i),named=basename(normalized).match(/^(tcp|udp)_?(\d+)(?:_|\.)/i),match=directory||named;
    if(!match||!validPort(match[2]))return null;return {protocol:lower(match[1]),port:Number(match[2]),source:directory?"per-port-directory":"explicit-output-name"};
  }
  function pathClassification(path,{manifest=null}={}){
    const normalized=normalizePath(path),name=lower(basename(normalized)),ext=extension(normalized),parts=pathParts(normalized),lowerParts=parts.map(lower),scansIndex=lowerParts.lastIndexOf("scans"),reportIndex=Math.max(lowerParts.lastIndexOf("report"),lowerParts.lastIndexOf("report.md")),lootIndex=lowerParts.lastIndexOf("loot"),exploitIndex=lowerParts.lastIndexOf("exploit"),endpointHint=endpointFromPath(normalized),tool=toolForPath(normalized);
    let category="unclassified",routingLevel="host";
    if(isManifestPath(normalized)){category="manifest";routingLevel="engagement";}
    else if(reportIndex>=0&&lowerParts[reportIndex+1]==="screenshots"){category="screenshot";routingLevel="host";}
    else if(reportIndex>=0){category="report";routingLevel="host";}
    else if(lootIndex>=0){category="loot";routingLevel="host";}
    else if(exploitIndex>=0){category="exploit";routingLevel="host";}
    else if(scansIndex>=0&&SIGNAL_FILES.has(name)){category=name==="_commands.log"?"commands":name==="_manual_commands.txt"?"manual-commands":name==="_errors.log"?"errors":"patterns";routingLevel="host";}
    else if(scansIndex>=0&&endpointHint){category="endpoint-artifact";routingLevel="endpoint-context";}
    else if(scansIndex>=0&&(lowerParts[scansIndex+1]==="xml"||name.startsWith("_")&&/nmap/.test(name))){category="port-scan";routingLevel="host";}
    else if(scansIndex>=0){category="scan-artifact";routingLevel="host";}
    if(manifest){const root=normalizePath(manifest.relativeRoot),local=root&&pathWithin(normalized,root)?normalized.slice(root.length).replace(/^\//,""):normalized;if(aggregateReportPath(local)){category="aggregate-report";routingLevel="engagement";}}
    return {path:normalized,filename:basename(normalized),extension:ext,category,routingLevel,tool,endpointHint,isText:TEXT_EXTENSIONS.has(ext)||!ext,isImage:IMAGE_EXTENSIONS.has(ext),activeContent:ACTIVE_EXTENSIONS.has(ext)};
  }
  const GENERIC_SMB_NAMES=new Set(["enum4linux.txt","enum4linux-ng.txt","nbtscan.txt","smbclient.txt","smbmap-share-permissions.txt","smbmap-list-contents.txt","smbmap-execute-command.txt"]);
  function endpointKey(row){const protocol=lower(row?.protocol||"tcp"),port=Number(row?.port);return validPort(port)?`${protocol}:${port}`:"";}
  function normalizedFamilyLabel(value){return clean(value).replace(/[\u0000-\u001f\u007f]/g," ").replace(/\s+/g," ").slice(0,80);}
  function meaningfulServiceName(value){const name=lower(value).replace(/[?]+$/g,"").trim();return name&&!/^(?:unknown|unidentified|tcpwrapped|no-response|none|null|n\/a|service)$/i.test(name)?name:"";}
  function dynamicServiceFamily(value){
    const name=meaningfulServiceName(value);if(!name)return "";
    const labels={postgresql:"PostgreSQL",postgres:"PostgreSQL",mysql:"MySQL",mariadb:"MariaDB","ms-sql-s":"Microsoft SQL Server",mssql:"Microsoft SQL Server",mongodb:"MongoDB",redis:"Redis",memcached:"Memcached",vnc:"VNC",telnet:"Telnet",xmpp:"XMPP",amqp:"AMQP",docker:"Docker",kubernetes:"Kubernetes",ipp:"IPP",cups:"CUPS"};
    if(labels[name])return labels[name];
    return name.split(/[\s_-]+/).filter(Boolean).map(part=>part.length<=4&&/^[a-z0-9]+$/.test(part)?part.toUpperCase():part.charAt(0).toUpperCase()+part.slice(1)).join(" ")||"";
  }
  function serviceFamilyForName(value){
    const original=meaningfulServiceName(value);if(!original)return "";
    const name=original.replace(/^ssl[\/_-]/,"").replace(/[\/_-]ssl$/,""),tokens=` ${name} `;
    if(/^(?:http|https|http-alt|http-proxy|http-mgmt|www|webcache)$/.test(name)||/(?:^|[\/_-])http(?:s)?(?:$|[\/_-])/.test(original))return "WEB";
    if(/^(?:microsoft-ds|netbios-ssn|netbios-ns|netbios-dgm|smb|samba)$/.test(name))return "SMB / NetBIOS";
    if(/^(?:ftp|ftp-data|ftps)$/.test(name))return "FTP";
    if(/^snmp(?:trap)?$/.test(name))return "SNMP";
    if(/^(?:domain|dns)$/.test(name))return "DNS";
    if(/^(?:ldap|ldaps)$/.test(name))return "LDAP";
    if(/^(?:kerberos|kerberos-sec|krb5)$/.test(name))return "Kerberos";
    if(/^(?:nfs|nfs-acl)$/.test(name))return "NFS";
    if(/^(?:smtp|smtps|submission|imap|imaps|pop3|pop3s)$/.test(name))return "SMTP / Mail";
    if(/^(?:ms-wbt-server|rdp)$/.test(name))return "RDP";
    if(/^(?:winrm|wsman)$/.test(name))return "WinRM";
    if(name==="ssh")return "SSH";
    if(/^(?:postgresql|postgres|mysql|mariadb|ms-sql-s|mssql|mongodb|redis|memcached|oracle|oracle-tns|cassandra)$/.test(name))return dynamicServiceFamily(name);
    return dynamicServiceFamily(tokens.trim());
  }
  function databaseFamily(value){return /^(?:PostgreSQL|MySQL|MariaDB|Microsoft SQL Server|MongoDB|Redis|Memcached|Oracle|Oracle Tns|Cassandra)$/i.test(clean(value));}
  function familyReviewRank(value){const family=clean(value),index=SERVICE_REVIEW_ORDER.indexOf(family);if(index>=0)return index;if(databaseFamily(family))return SERVICE_REVIEW_ORDER.indexOf("Databases");return family===OTHER_SERVICE_FAMILY?1000:900;}
  function strongEvidenceFamily(artifacts=[]){
    for(const artifact of Array.isArray(artifacts)?artifacts:[]){
      if(artifact?.scannerEvidence===false||artifact?.classification?.scannerEvidence===false||lower(artifact?.category||artifact?.classification?.category)==="external-notes")continue;
      const tool=lower(artifact?.tool||artifact?.classification?.tool),body=String(artifact?.semanticPreview??artifact?.preview??artifact?.raw??"").slice(0,131072);
      if(!body.trim())continue;
      if(!/sslscan/.test(tool)&&(/(?:^|\s)SSH-\d(?:\.\d)?-/im.test(body)||/\bssh (?:host key|banner|protocol)\b/i.test(body)))return {family:"SSH",reason:"An endpoint-owned artifact contains an explicit SSH protocol banner."};
      if(!/sslscan/.test(tool)&&(/\bSMB\d?\b|\bNetBIOS\b|\\\\[^\s]+\\[^\s]+/i.test(body))&&/(?:smb|enum4linux|netbios|samba|share)/i.test(`${tool} ${body}`))return {family:"SMB / NetBIOS",reason:"Endpoint-owned output explicitly records SMB or NetBIOS protocol behavior."};
      if(!/sslscan/.test(tool)&&(/\bHTTP\/\d(?:\.\d)?\s+\d{3}\b|https?:\/\/[^\s<>'"]+|\[(?:200|201|204|3\d\d|401|403|404)\s+(?:OK|Found|Unauthorized|Forbidden|Not Found)\]/i.test(body))&&/(?:whatweb|nikto|wpscan|ferox|gobuster|dirsearch|ffuf|dirb|curl|http|web)/i.test(`${tool} ${body}`))return {family:"WEB",reason:"Endpoint-owned output contains an explicit HTTP response or origin from an HTTP-aware tool."};
      if(/\b(?:status:\s*NOERROR|SERVER:\s*\S+#53|flags:\s*qr)\b/i.test(body))return {family:"DNS",reason:"Endpoint-owned output contains an explicit DNS response."};
      if(/\bLDAP Result Code\b|\bobjectClass:\s+/i.test(body))return {family:"LDAP",reason:"Endpoint-owned output contains an explicit LDAP response."};
    }
    return null;
  }
  function portHeuristicFamily(protocol,port){
    const key=`${lower(protocol||"tcp")}:${Number(port)}`,map={
      "tcp:21":"FTP","tcp:22":"SSH","tcp:53":"DNS","udp:53":"DNS","tcp:80":"WEB","tcp:81":"WEB","tcp:88":"Kerberos","udp:88":"Kerberos","tcp:110":"SMTP / Mail","tcp:135":"SMB / NetBIOS","tcp:139":"SMB / NetBIOS","tcp:143":"SMTP / Mail","tcp:389":"LDAP","udp:389":"LDAP","tcp:443":"WEB","tcp:445":"SMB / NetBIOS","udp:161":"SNMP","udp:162":"SNMP","tcp:465":"SMTP / Mail","tcp:587":"SMTP / Mail","tcp:636":"LDAP","tcp:993":"SMTP / Mail","tcp:995":"SMTP / Mail","tcp:2049":"NFS","udp:2049":"NFS","tcp:3306":"MySQL","tcp:3389":"RDP","tcp:5432":"PostgreSQL","tcp:5985":"WinRM","tcp:5986":"WinRM","tcp:8000":"WEB","tcp:8008":"WEB","tcp:8080":"WEB","tcp:8081":"WEB","tcp:8443":"WEB","tcp:8888":"WEB"
    };return map[key]||"";
  }
  function classifyServiceEndpoint(endpoint={},artifacts=[],options={}){
    const key=endpointKey(endpoint),manual=options.manualMappings&&typeof options.manualMappings==="object"?options.manualMappings[key]:null,manualFamily=normalizedFamilyLabel(typeof manual==="string"?manual:manual?.family);
    if(manualFamily)return {key,family:manualFamily,source:"Manual",automatic:false,reason:"The persisted operator assignment outranks automatic classification.",detectedAs:clean(endpoint.service||endpoint.serviceRaw||endpoint.serviceHint)||"unknown",reviewRank:familyReviewRank(manualFamily)};
    const established=meaningfulServiceName(endpoint.service),explicitFallback=(endpoint.identified===true||endpoint.serviceConfirmed===true||lower(endpoint.identificationState)==="identified"||lower(endpoint.serviceIdentity?.state)==="established"||lower(endpoint.serviceMethod)==="probed")?meaningfulServiceName(endpoint.serviceRaw||endpoint.serviceHint):"",detected=established||explicitFallback;
    if(detected){const family=serviceFamilyForName(detected);if(family)return {key,family,source:"Nmap",automatic:true,reason:`The accepted detected service identity “${clean(detected)}” determines the family regardless of port.`,detectedAs:clean(detected),reviewRank:familyReviewRank(family)};}
    const evidence=strongEvidenceFamily(artifacts);if(evidence)return {key,family:evidence.family,source:"Evidence-derived",automatic:true,reason:evidence.reason,detectedAs:clean(endpoint.serviceRaw||endpoint.serviceHint)||"unknown",reviewRank:familyReviewRank(evidence.family)};
    const heuristic=portHeuristicFamily(endpoint.protocol,endpoint.port);if(heuristic)return {key,family:heuristic,source:"Port heuristic",automatic:true,reason:`No stronger identity is retained; conventional ${lower(endpoint.protocol||"tcp").toUpperCase()}/${Number(endpoint.port)} usage supplies a fallback only.`,detectedAs:clean(endpoint.serviceRaw||endpoint.serviceHint)||"unknown",reviewRank:familyReviewRank(heuristic)};
    return {key,family:OTHER_SERVICE_FAMILY,source:"Automatic",automatic:true,reason:"No reliable service identity or strong endpoint-owned protocol evidence is retained.",detectedAs:clean(endpoint.serviceRaw||endpoint.serviceHint)||"unknown",reviewRank:familyReviewRank(OTHER_SERVICE_FAMILY)};
  }
  function endpointIsProvisional(row={}){return row.provisional===true&&!(row.sources||[]).some(source=>source?.provisional!==true);}
  function endpointAuthorityScore(row={}){return (endpointIsProvisional(row)?0:100)+(row.identified===true?10:0)+(lower(row.state)==="open"?2:0)+(clean(row.product)?1:0)+(clean(row.version)?1:0);}
  function authoritativeEndpointRows(host={}){
    const rows=new Map();
    for(const row of Array.isArray(host.serviceInventory)?host.serviceInventory:[]){
      const key=endpointKey(row),state=lower(row?.state||"open");if(!key||!["open","open|filtered"].includes(state))continue;
      const previous=rows.get(key);if(!previous||endpointAuthorityScore(row)>endpointAuthorityScore(previous))rows.set(key,row);
    }
    return [...rows.values()];
  }
  function smbCandidates(host={}){
    return authoritativeEndpointRows(host).filter(row=>{const service=lower([row.service,row.serviceRaw,row.serviceHint,row.product].filter(Boolean).join(" "));return lower(row.protocol||"tcp")!=="udp"&&/(?:smb|microsoft-ds|netbios-ssn|samba)/.test(service);});
  }
  function routeInventoryArtifact(path,{route={},host={},origins=[]}={}){
    const classification=pathClassification(path,{manifest:route.manifest});
    if(route.scope==="engagement"||classification.routingLevel==="engagement")return {classification,owner:{kind:"engagement",id:clean(route.engagement),confidence:"authoritative",reason:route.reason||"The AutoRecon run manifest owns this output-root artifact at engagement scope."}};
    const hint=classification.endpointHint;
    if(hint){
      const matches=authoritativeEndpointRows(host).filter(row=>lower(row.protocol||"tcp")===hint.protocol&&Number(row.port)===hint.port);
      if(matches.length===1){
        const endpoint=matches[0],endpointId=clean(endpoint.endpointId||endpoint.id)||`${hint.protocol}:${hint.port}`,webLike=/^(?:Curl|SSLScan|WhatWeb|Nikto|Feroxbuster|Gobuster|Dirsearch|FFUF|Directory discovery)$/.test(classification.tool)||classification.activeContent,schemeMatch=classification.filename.match(/(?:^|[_-])(https?)(?:[_-]|[.])/i),scheme=lower(schemeMatch?.[1]);
        const candidates=webLike?(origins||[]).filter(origin=>clean(origin.endpointId||origin.serviceEndpointId)===endpointId&&(!scheme||lower(origin.scheme||String(origin.url||origin.value).split(":")[0])===scheme)):[];
        if(candidates.length===1){const origin=candidates[0];return {classification,owner:{kind:"origin",id:clean(origin.id||origin.originId||origin.key),endpointId,protocol:hint.protocol,port:hint.port,url:clean(origin.url||origin.value),confidence:"authoritative-origin",reason:"The exact per-port path, web scheme, and one existing endpoint-owned origin establish one canonical origin home."}};}
        return {classification,owner:{kind:"endpoint",id:endpointId,protocol:hint.protocol,port:hint.port,confidence:hint.source==="per-port-directory"?"authoritative-context":"strong-context",reason:candidates.length>1?"The path identifies one endpoint, but more than one exact web origin remains possible; origin ownership was not guessed.":"The path identifies one exact protocol/port and the host already has that authoritative endpoint."}};
      }
      return {classification,owner:{kind:"unresolved",id:"",protocol:hint.protocol,port:hint.port,confidence:"context-only",reason:`The path suggests ${hint.protocol.toUpperCase()}/${hint.port}, but a directory or filename alone cannot establish an open endpoint.`}};
    }
    if(GENERIC_SMB_NAMES.has(lower(classification.filename))){
      const candidates=smbCandidates(host);
      if(candidates.length===1){const row=candidates[0];return {classification,owner:{kind:"endpoint",id:clean(row.endpointId||row.id)||endpointKey(row),protocol:lower(row.protocol||"tcp"),port:Number(row.port),confidence:"service-family",reason:"AutoRecon's generic SMB filename lost its port path, but exactly one already-authoritative SMB-family endpoint exists."}};}
      return {classification,owner:{kind:candidates.length>1?"unresolved":"host",id:candidates.length>1?"":clean(host.id||host.ip),confidence:"ambiguous",reason:candidates.length>1?"AutoRecon --no-port-dirs produced a generic SMB filename and more than one SMB-family endpoint is possible; exact ownership was not guessed.":"AutoRecon --no-port-dirs produced a generic SMB filename without an exact authoritative endpoint; it remains host/service-family evidence."}};
    }
    return {classification,owner:{kind:"host",id:clean(host.id||host.ip),confidence:"path-authoritative",reason:"The manifest or exact staging route owns this artifact at host scope; no exact endpoint owner is proven."}};
  }

  function parseManualCommands(text){
    const rows=[],lines=String(text??"").replace(/\r\n?/g,"\n").split("\n");let current=null;
    for(const line of lines){
      const heading=/^\[\*\]\s+(.+?)\s+on\s+(tcp|udp)\/(\d+)\s*$/i.exec(line.trim());
      if(heading&&validPort(heading[3])){current={service:clean(heading[1]),protocol:lower(heading[2]),port:Number(heading[3]),descriptions:[],commands:[]};rows.push(current);continue;}
      if(!current)continue;
      const description=/^\[-\]\s*(.+)$/.exec(line.trim());if(description){current.descriptions.push(description[1]);continue;}
      if(line.trim())current.commands.push(line);
    }
    return rows;
  }
  function parseCommandSignals(text){
    const out=[];for(const line of String(text??"").replace(/\r\n?/g,"\n").split("\n")){
      const matches=[...line.matchAll(/(?:^|[^\d])(\d{1,5})\/(tcp|udp)\b/gi),...line.matchAll(/(?:^|\s)-(?:p|port)\s*(\d{1,5})\b/gi)];
      for(const match of matches){const port=Number(match[1]);if(validPort(port))out.push({protocol:lower(match[2]||"tcp"),port,line});}
    }
    return out;
  }
  function inventoryRecordId(identity={},hash){
    if(typeof hash!=="function")throw new Error("A deterministic SHA-256 identity function is required for AutoRecon inventory records.");
    const runScope=identity.provisional===true?lower(identity.runId):"",value=[lower(identity.engagementId),lower(identity.hostId),runScope,lower(normalizePath(identity.logicalPath))].join("|");return `autorecon-artifact:${hash(value)}`;
  }
  function normalizeReviewState(value){const state=lower(value);return REVIEW_STATES.includes(state)?state:"new";}
  function normalizeInventoryRecord(raw={}){
    const provisional=raw.provisional===true||lower(raw.artifactLifecycle)==="provisional",revision=provisional?0:Math.max(1,Number(raw.revision)||1),path=normalizePath(raw.path||raw.logicalPath);
    const updatedAt=clean(raw.updatedAt)||new Date().toISOString(),observations=Array.isArray(raw.runObservations)?raw.runObservations.filter(row=>row&&typeof row==="object").slice(-250):[],observation=clean(raw.runId)?{runId:clean(raw.runId),runStatus:clean(raw.runStatus),physicalSourcePath:normalizePath(raw.physicalSourcePath||raw.sourceRelativePath),outcome:clean(raw.outcome),revision,observedAt:updatedAt}:null;
    if(observation&&!observations.some(row=>clean(row.runId)===observation.runId&&normalizePath(row.physicalSourcePath)===observation.physicalSourcePath&&clean(row.outcome)===observation.outcome&&Number(row.revision)===observation.revision))observations.push(observation);
    return {...raw,id:clean(raw.id),path,logicalPath:path,physicalSourcePath:normalizePath(raw.physicalSourcePath||raw.sourceRelativePath),filename:clean(raw.filename)||basename(path),size:Math.max(0,Number(raw.size)||0),lastModified:Math.max(0,Number(raw.lastModified)||0),artifactLifecycle:provisional?"provisional":"canonical",provisional,immutable:!provisional,revision,reviewState:normalizeReviewState(raw.reviewState),annotation:clean(raw.annotation),followUps:unique(raw.followUps).slice(0,100),preview:String(raw.preview??""),previewTruncated:raw.previewTruncated===true,metadataOnly:raw.metadataOnly===true,runObservations:observations.slice(-250),updatedAt};
  }
  function upsertInventory(records=[],raw={}){
    const normalized=normalizeInventoryRecord(raw),rows=Array.isArray(records)?records:[];let inherited=[];
    if(!normalized.provisional)for(let cursor=rows.length-1;cursor>=0;cursor--){const row=rows[cursor];if(row?.provisional===true&&normalizePath(row.logicalPath||row.path)===normalized.logicalPath&&lower(row.engagementId)===lower(normalized.engagementId)&&lower(row.hostId)===lower(normalized.hostId)){inherited.push(...(row.runObservations||[]));rows.splice(cursor,1);}}
    const index=rows.findIndex(row=>clean(row?.id)===normalized.id),existing=index>=0?rows[index]:null;
    if(existing){normalized.reviewState=normalizeReviewState(existing.reviewState);normalized.annotation=clean(existing.annotation);normalized.followUps=unique(existing.followUps);normalized.firstSeenAt=clean(existing.firstSeenAt)||clean(normalized.firstSeenAt)||normalized.updatedAt;inherited.push(...(existing.runObservations||[]));}
    const mergedObservations=[];for(const row of [...inherited,...normalized.runObservations]){const key=[clean(row.runId),normalizePath(row.physicalSourcePath),clean(row.outcome),Number(row.revision)].join("|");if(!mergedObservations.some(item=>item.key===key))mergedObservations.push({key,row});}normalized.runObservations=mergedObservations.slice(-250).map(item=>item.row);
    if(existing)rows.splice(index,1,normalized);else{normalized.firstSeenAt=clean(normalized.firstSeenAt)||normalized.updatedAt;rows.push(normalized);}
    return normalized;
  }
  function removeProvisionalInventory(records=[],identity={}){
    const rows=Array.isArray(records)?records:[],before=rows.length,path=normalizePath(identity.path||identity.logicalPath),artifactId=clean(identity.artifactId),id=clean(identity.id);
    for(let index=rows.length-1;index>=0;index--){const row=rows[index];if(row?.provisional!==true)continue;const matches=id?row.id===id:artifactId?row.artifactId===artifactId:path&&normalizePath(row.path)===path;if(matches)rows.splice(index,1);}
    return before-rows.length;
  }
  function recordsForEndpoint(records=[],endpoint={}){
    const id=clean(endpoint.endpointId||endpoint.id),protocol=lower(endpoint.protocol||"tcp"),port=Number(endpoint.port);
    return (records||[]).filter(row=>{
      const owner=row?.owner||{},ownerMatch=["endpoint","origin"].includes(owner.kind)&&(clean(owner.id)===id||clean(owner.endpointId)===id||lower(owner.protocol)===protocol&&Number(owner.port)===port),referenceMatch=(row?.endpointReferences||[]).some(reference=>clean(reference.endpointId)===id||lower(reference.protocol)===protocol&&Number(reference.port)===port);
      return ownerMatch||referenceMatch;
    });
  }
  function genericNextWork(endpoint={}){
    const protocol=lower(endpoint.protocol||"tcp"),state=lower(endpoint.state||"open"),service=lower(endpoint.service||endpoint.serviceRaw),rows=[];
    if(protocol==="udp")rows.push(state==="open|filtered"?"Retain open|filtered uncertainty; validate with service-appropriate UDP probes before describing the endpoint as confirmed open.":"Validate the UDP response and repeat a bounded service-appropriate probe when necessary.","Correlate ICMP/no-response behavior, command history, and scanner evidence.","Determine the protocol, authentication surface, and safe enumeration path; record operator observations separately.");
    else rows.push("Validate the open state with a bounded second observation when needed.","Gather a safe banner and test protocol negotiation without assuming the service from its assigned port.","Determine encryption and the exposed authentication surface.","Correlate command history, scanner evidence, and operator observations.");
    if(service&&!["unknown","unidentified"].includes(service))rows.push(`Continue with the existing ${service.toUpperCase()} service-specific methodology while retaining the generic evidence history.`);
    return rows;
  }
  function endpointAreas(host={},records=[],origins=[]){
    return authoritativeEndpointRows(host).map(row=>{
      const id=clean(row.endpointId||row.id)||endpointKey(row),owned=recordsForEndpoint(records,row),webOrigins=(origins||[]).filter(origin=>clean(origin.endpointId||origin.serviceEndpointId)===id).map(origin=>clean(origin.url||origin.value)).filter(Boolean),provisional=endpointIsProvisional(row),service=clean(row.service||row.serviceRaw),product=clean(row.product),version=clean(row.version),endpointState=clean(row.state||"open"),known=[provisional?`${lower(row.protocol||"tcp").toUpperCase()}/${Number(row.port)} has a safely parsed provisional ${endpointState} observation`:`${lower(row.protocol||"tcp").toUpperCase()}/${Number(row.port)} has authoritative state ${endpointState}`];
      if(row.identified===true&&service)known.push(`Service identity: ${service}`);if(product)known.push(`Product: ${product}`);if(version)known.push(`Version: ${version}`);if(webOrigins.length)known.push(...webOrigins.map(url=>`Exact web origin: ${url}`));
      const unknown=[];if(row.identified!==true)unknown.push("Service identity remains unconfirmed");if(!product)unknown.push("Product remains unknown");if(!version)unknown.push("Version remains unknown");if(lower(row.protocol)==="udp"&&lower(row.state)==="open|filtered")unknown.push("Whether the UDP endpoint is open or filtered remains unresolved");unknown.push("Encryption and authentication behavior remain operator-review facts until observed");
      const manualCommands=unique(owned.flatMap(record=>(record.manualCommands||[]).filter(command=>lower(command.protocol)===lower(row.protocol||"tcp")&&Number(command.port)===Number(row.port)).flatMap(command=>[...command.descriptions,...command.commands]))),signals=unique(owned.flatMap(record=>(record.commandSignals||[]).filter(signal=>lower(signal.protocol)===lower(row.protocol||"tcp")&&Number(signal.port)===Number(row.port)).map(signal=>signal.line)));
      return {id,protocol:lower(row.protocol||"tcp"),port:Number(row.port),state:clean(row.state||"open"),artifactLifecycle:provisional?"provisional":"canonical",provisional,service,product,version,identified:row.identified===true,confidence:clean(row.serviceIdentity?.state||row.identificationState||row.confidence||"unknown"),reviewState:normalizeReviewState(host?.recon?.endpointReviews?.[id]?.state),known:unique(known),unknown:unique(unknown),nextWork:genericNextWork(row),artifacts:owned,webOrigins,manualCommands,signals,toolingGap:owned.length?"":"No endpoint-specific AutoRecon plugin artifact is retained; the authoritative open endpoint still requires generic follow-up.",provenance:unique([row.source,row.sourceSlot,row.sourceArtifactId,...(row.sources||[]).map(source=>[source.tool,source.filename,source.artifactId,source.revision===0?"revision 0":source.revision?`revision ${source.revision}`:""].filter(Boolean).join(" · "))])};
    });
  }

  return Object.freeze({MANIFEST_SCHEMA_VERSION,MANIFEST_BASENAME,TERMINAL_RUN_STATUSES:Object.freeze([...TERMINAL_RUN_STATUSES]),SIGNAL_FILES,ACTIVE_EXTENSIONS,IMAGE_EXTENSIONS,TEXT_EXTENSIONS,REVIEW_STATES,GENERIC_SMB_NAMES,OTHER_SERVICE_FAMILY,SERVICE_REVIEW_ORDER,AUTORECON_REPORT_PLACEHOLDERS,normalizePath,basename,dirname,extension,stripRoot,isManifestPath,isTerminalRunStatus,isIpv4,isIpv6,normalizeIp,transportReady,parseRunManifest,manifestForArtifact,routeFromManifest,canonicalLogicalPath,aggregateReportPath,autoReconOwnership,autoReconReportContext,analyzeAutoReconNotes,semanticDisposition,applySemanticClassification,reconcileSemanticInventory,pathClassification,endpointFromPath,toolForPath,endpointKey,normalizedFamilyLabel,meaningfulServiceName,dynamicServiceFamily,serviceFamilyForName,databaseFamily,familyReviewRank,strongEvidenceFamily,portHeuristicFamily,classifyServiceEndpoint,endpointIsProvisional,authoritativeEndpointRows,routeInventoryArtifact,parseManualCommands,parseCommandSignals,inventoryRecordId,normalizeReviewState,normalizeInventoryRecord,upsertInventory,removeProvisionalInventory,recordsForEndpoint,genericNextWork,endpointAreas});
});
