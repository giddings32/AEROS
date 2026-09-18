(function(root,factory){
  const autorecon=(typeof module==="object"&&module.exports)
    ?(()=>{try{return require("./autorecon-live-import.js");}catch(error){if(error?.code!=="MODULE_NOT_FOUND")throw error;return require("./app/features/imports/autorecon-live-import.js");}})()
    :(root&&root.AEROSAutoReconLiveImport);
  const api=factory(autorecon||{});
  if(typeof module==="object"&&module.exports)module.exports=api;
  if(root)root.AEROSLiveImportCore=api;
})(typeof window!=="undefined"?window:globalThis,function(autorecon){
  "use strict";

  const SCHEMA_VERSION=1;
  const MAX_ARTIFACT_BYTES=25*1024*1024;
  const PROVISIONAL_ARTIFACT_PREFIX="live-provisional:";
  const DEFAULTS=Object.freeze({
    debounceMs:1800,
    maximumDebounceMs:12000,
    concurrency:3,
    retryBaseMs:5000,
    retryMaximumMs:60000,
    maximumAutomaticRetries:6,
    maximumLedgerEntries:10000
  });
  const PROCESSABLE_TYPES=new Set(["nmap","scan-support","scan-tool","web-discovery","web-baseline","web-technology"]);
  const PROCESSING_STATES=new Set(["discovered","receiving","processing","waiting"]);
  const clean=value=>String(value??"").trim();
  const lower=value=>clean(value).toLowerCase();
  const iso=value=>new Date(value).toISOString();

  const SHA256_INITIAL=Object.freeze([0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]);
  const SHA256_CONSTANTS=Object.freeze([0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]);
  function rotateRight(value,bits){return value>>>bits|value<<(32-bits);}
  function sha256Hex(value=""){
    const bytes=new TextEncoder().encode(String(value)),bitLength=bytes.length*8,paddedLength=Math.ceil((bytes.length+9)/64)*64,buffer=new Uint8Array(paddedLength);buffer.set(bytes);buffer[bytes.length]=0x80;
    const view=new DataView(buffer.buffer);view.setUint32(paddedLength-8,Math.floor(bitLength/0x100000000));view.setUint32(paddedLength-4,bitLength>>>0);
    const state=SHA256_INITIAL.slice(),words=new Uint32Array(64);
    for(let offset=0;offset<paddedLength;offset+=64){
      for(let index=0;index<16;index++)words[index]=view.getUint32(offset+index*4);
      for(let index=16;index<64;index++){const s0=rotateRight(words[index-15],7)^rotateRight(words[index-15],18)^words[index-15]>>>3,s1=rotateRight(words[index-2],17)^rotateRight(words[index-2],19)^words[index-2]>>>10;words[index]=(words[index-16]+s0+words[index-7]+s1)>>>0;}
      let [a,b,c,d,e,f,g,h]=state;
      for(let index=0;index<64;index++){const sum1=rotateRight(e,6)^rotateRight(e,11)^rotateRight(e,25),choice=e&f^~e&g,temp1=(h+sum1+choice+SHA256_CONSTANTS[index]+words[index])>>>0,sum0=rotateRight(a,2)^rotateRight(a,13)^rotateRight(a,22),majority=a&b^a&c^b&c,temp2=(sum0+majority)>>>0;h=g;g=f;f=e;e=(d+temp1)>>>0;d=c;c=b;b=a;a=(temp1+temp2)>>>0;}
      [a,b,c,d,e,f,g,h].forEach((word,index)=>{state[index]=(state[index]+word)>>>0;});
    }
    return state.map(word=>word.toString(16).padStart(8,"0")).join("");
  }
  function provisionalArtifactId({engagementId="",hostId="",logicalPath="",objective="",runId=""}={}){
    const identity=[clean(engagementId).toLowerCase(),clean(hostId).toLowerCase(),normalizeRelativePath(logicalPath).toLowerCase(),clean(objective).toLowerCase(),clean(runId).toLowerCase()].join("|");
    return `${PROVISIONAL_ARTIFACT_PREFIX}${sha256Hex(identity)}`;
  }
  function isProvisionalArtifactId(value){return lower(value).startsWith(PROVISIONAL_ARTIFACT_PREFIX);}

  function safePathSegments(value){
    const raw=clean(value).replace(/\\/g,"/").replace(/^\/+|\/+$/g,"");
    if(!raw)return [];
    const parts=raw.split("/");
    if(parts.some(part=>!part||part==="."||part===".."||part.length>255||/[\u0000-\u001f\u007f]/.test(part)))return [];
    return parts;
  }
  function normalizeRelativePath(value){return safePathSegments(value).join("/");}
  function errorDiagnostic(error,{phase="unknown",path=""}={}){
    const name=clean(error?.name)||"Error",message=clean(error?.message||error)||"Unknown Live Import failure",stack=String(error?.stack||"");
    return {name,message,stack,phase:clean(phase)||"unknown",path:String(path??""),at:new Date().toISOString()};
  }
  function isIpv4(value){
    const parts=clean(value).split(".");
    return parts.length===4&&parts.every(part=>/^\d{1,3}$/.test(part)&&Number(part)>=0&&Number(part)<=255);
  }
  function isIpv6(value){
    const candidate=clean(value).replace(/^\[|\]$/g,"");
    if(!candidate.includes(":")||!/^[0-9a-f:.]+$/i.test(candidate))return false;
    try{return new URL(`http://[${candidate}]/`).hostname.replace(/^\[|\]$/g,"").includes(":");}
    catch(_error){return false;}
  }
  function normalizeAddress(value){
    if(typeof autorecon.normalizeIp==="function")return autorecon.normalizeIp(value);
    const candidate=clean(value).replace(/^\[|\]$/g,"");return isIpv4(candidate)||isIpv6(candidate)?candidate.toLowerCase():"";
  }
  function canonicalEngagementName(value){
    return lower(value).normalize("NFKC").replace(/[^a-z0-9]+/g,"-").replace(/^-+|-+$/g,"");
  }
  function parseStagingRoute(relativePath,{rootName=""}={}){
    const original=normalizeRelativePath(relativePath),parts=safePathSegments(relativePath);
    if(!original||!parts.length)return {ok:false,status:"invalid-path",reason:"The artifact path is empty or unsafe.",relativePath:original};
    if(rootName&&lower(parts[0])===lower(rootName))parts.shift();
    if(parts.length<3)return {ok:false,status:"invalid-route",reason:"Expected engagement/host/artifact beneath the authorized staging root.",relativePath:original};
    const engagement=clean(parts[0]),host=normalizeAddress(parts[1]),artifactParts=parts.slice(2);
    if(!canonicalEngagementName(engagement))return {ok:false,status:"invalid-engagement",reason:"The engagement directory name is invalid.",relativePath:original};
    if(!host)return {ok:false,status:"invalid-host",reason:"The second path segment must be an exact IPv4 or IPv6 host directory.",relativePath:original,engagement};
    if(!artifactParts.length)return {ok:false,status:"invalid-route",reason:"The routed host path does not name an artifact.",relativePath:original,engagement,host};
    return {ok:true,status:"routed",relativePath:parts.join("/"),engagement,host,artifactPath:artifactParts.join("/"),filename:artifactParts.at(-1)};
  }
  function hostIdentityValues(host={}){
    const values=[host.ip,host.address,host.primaryAddress];
    for(const row of Array.isArray(host.networkAddresses)?host.networkAddresses:[]){if(row?.active!==false)values.push(row?.address);}
    for(const group of [host.addresses,host.aliases,host.targetAliases])if(Array.isArray(group))values.push(...group);
    return [...new Set(values.map(normalizeAddress).filter(Boolean))];
  }
  function workspaceHosts(workspace={}){
    const source=workspace.hosts&&typeof workspace.hosts==="object"?workspace.hosts:{};
    const rows=[];
    for(const [key,host] of Object.entries(source)){
      if(!host||typeof host!=="object")continue;
      if(!rows.some(row=>row.host===host))rows.push({key,id:clean(host.id||key),host});
    }
    return rows;
  }
  function resolveWorkspaceRoute(route,workspace={}){
    if(!route?.ok)return route||{ok:false,status:"invalid-route",reason:"The artifact route is invalid."};
    const engagementNames=[workspace.engagementName,workspace.projectName,workspace.loadedEngagementName,...(Array.isArray(workspace.engagementAliases)?workspace.engagementAliases:[])]
      .map(canonicalEngagementName).filter(Boolean);
    const routedEngagement=canonicalEngagementName(route.engagement);
    if(!routedEngagement||!engagementNames.includes(routedEngagement)){
      return {...route,ok:false,retryable:true,status:"engagement-unavailable",reason:`Open the exact engagement “${route.engagement}” to import this artifact.`};
    }
    const matches=workspaceHosts(workspace).filter(row=>hostIdentityValues(row.host).includes(route.host));
    if(matches.length!==1){
      return {...route,ok:false,retryable:true,status:matches.length?"ambiguous-host":"host-unresolved",reason:matches.length?`Host directory ${route.host} matches more than one current host.`:`Host directory ${route.host} is not an exact address of a current engagement host.`};
    }
    return {...route,ok:true,status:"ready",hostAddress:route.host,host:matches[0].host,hostKey:matches[0].key,hostId:matches[0].id};
  }
  function resolveWorkspaceArtifactRoute(route,workspace={}){
    if(!route?.ok)return route||{ok:false,status:"invalid-route",reason:"The artifact route is invalid."};
    if(route.scope!=="engagement")return resolveWorkspaceRoute(route,workspace);
    const names=[workspace.engagementName,workspace.projectName,workspace.loadedEngagementName,...(Array.isArray(workspace.engagementAliases)?workspace.engagementAliases:[])].map(canonicalEngagementName).filter(Boolean),routed=canonicalEngagementName(route.engagement);
    if(!routed||!names.includes(routed))return {...route,ok:false,retryable:true,status:"engagement-unavailable",reason:`Open the exact engagement “${route.engagement}” to import this artifact.`};
    return {...route,ok:true,status:"ready",engagementId:clean(workspace.engagementId||workspace.projectId||route.engagement)};
  }
  function engagementManifestRoute(relativePath,{rootName=""}={}){
    if(typeof autorecon.isManifestPath!=="function"||!autorecon.isManifestPath(relativePath))return null;
    const parts=safePathSegments(relativePath);if(rootName&&lower(parts[0])===lower(rootName))parts.shift();
    if(parts.length<2)return {ok:false,status:"invalid-route",reason:"Expected the AutoRecon manifest beneath an engagement output root.",relativePath:parts.join("/")};
    const engagement=clean(parts[0]);if(!canonicalEngagementName(engagement))return {ok:false,status:"invalid-engagement",reason:"The AutoRecon manifest engagement directory is invalid.",relativePath:parts.join("/")};
    return {ok:true,status:"manifest",scope:"engagement",engagement,artifactPath:parts.slice(1).join("/"),filename:parts.at(-1),relativePath:parts.join("/")};
  }
  function parseArtifactRoute(relativePath,{rootName="",manifests=[]}={}){
    const manifest=typeof autorecon.manifestForArtifact==="function"?autorecon.manifestForArtifact(manifests,relativePath,{rootName}):null;
    const routed=manifest&&typeof autorecon.routeFromManifest==="function"?autorecon.routeFromManifest(relativePath,manifest,{rootName}):null;
    return routed||engagementManifestRoute(relativePath,{rootName})||parseStagingRoute(relativePath,{rootName});
  }
  function isPotentialArtifactPath(value){
    const path=normalizeRelativePath(value).toLowerCase();
    if(!path)return false;
    if(path.split("/").some(part=>part.startsWith(".aeros-transport-")))return false;
    const name=path.split("/").at(-1)||"";
    return !/(?:^|[.])(?:tmp|part|crdownload|swp)$/.test(name)&&!name.startsWith("~$");
  }
  function artifactSourcePaths(route={},entryPath="",rootName=""){
    const relativePath=normalizeRelativePath(route.relativePath||entryPath),physicalSourcePath=normalizeRelativePath([rootName,relativePath].filter(Boolean).join("/")),canonicalLogicalPath=normalizeRelativePath(typeof autorecon.canonicalLogicalPath==="function"?autorecon.canonicalLogicalPath(route):"")||physicalSourcePath;
    return {physicalSourcePath,canonicalLogicalPath};
  }
  function promoteAuthoritativeScanTool(input={},detection={},authority={}){
    const current=detection&&typeof detection==="object"?{...detection}:{},type=lower(current.type),path=normalizeRelativePath(input.path||input.name),name=clean(input.name)||basename(path);
    const genericDocument=type==="document"&&lower(current.confidence)==="weak"&&lower(current.parser)==="engagement-document";
    const noDeterministicCandidate=!type&&(!Array.isArray(current.candidates)||current.candidates.length===0);
    if(!/[.](?:txt|log)$/i.test(path)||(!genericDocument&&!noDeterministicCandidate))return current;
    const candidate={name,size:Number(input.size)||0,aerosRelativePath:path};
    if(typeof authority.isCandidate!=="function"||!authority.isCandidate(candidate,true)||typeof authority.parseToolOutput!=="function")return current;
    let parsed=null;
    try{parsed=authority.parseToolOutput(String(input.text||""),{filename:path,command:clean(input.command)});}
    catch(_error){return current;}
    const tool=clean(parsed?.tool||parsed?.source);if(!tool)return current;
    return {...current,type:"scan-tool",parser:"scan-tool-router",status:"detected",label:`${tool} output`,tool,toolOperationStatus:clean(parsed.operationStatus||parsed.status),reason:`The existing authoritative scan-tool parser recognizes this artifact as ${tool} output.`};
  }
  function metadataSignature(metadata={}){
    const size=Math.max(0,Number(metadata.size)||0),modified=Math.max(0,Number(metadata.lastModified)||0);
    return `${size}:${modified}`;
  }
  function mutationKind(previous={},metadata={}){
    if(!previous||!previous.signature)return "new";
    const oldSize=Math.max(0,Number(previous.size)||0),size=Math.max(0,Number(metadata.size)||0);
    const oldModified=Math.max(0,Number(previous.lastModified)||0),modified=Math.max(0,Number(metadata.lastModified)||0);
    if(size<oldSize||modified<oldModified)return "rewritten";
    if(size===oldSize&&modified===oldModified)return "unchanged";
    return "updated";
  }
  function basename(value){return normalizeRelativePath(value).split("/").at(-1)||"artifact";}
  function extension(value){const match=basename(value).toLowerCase().match(/[.]([a-z0-9]+)$/);return match?.[1]||"";}
  function withoutIncompleteLastLine(text){
    const raw=String(text??"").replace(/\r\n?/g,"\n");
    if(!raw||raw.endsWith("\n"))return raw;
    const index=raw.lastIndexOf("\n");
    return index>=0?raw.slice(0,index+1):raw;
  }
  function parseJsonStream(text){
    const raw=String(text??"").replace(/\r\n?/g,"\n"),trimmed=raw.trim();
    if(!trimmed)return {valid:false,incomplete:true,parseText:"",stream:false,complete:false};
    try{
      const data=JSON.parse(trimmed);
      return {valid:true,incomplete:false,parseText:raw,stream:false,complete:true,data};
    }catch(_error){}
    const lines=raw.split("\n"),completeLineCount=raw.endsWith("\n")?lines.length:Math.max(0,lines.length-1),parsed=[];
    for(let index=0;index<completeLineCount;index++){
      const line=lines[index].trim();if(!line)continue;
      try{parsed.push(JSON.parse(line));}
      catch(_error){return {valid:false,incomplete:true,parseText:"",stream:false,complete:false};}
    }
    const final=raw.endsWith("\n")?"":lines.at(-1).trim();
    if(final){
      try{parsed.push(JSON.parse(final));}
      catch(_error){}
    }
    if(!parsed.length)return {valid:false,incomplete:true,parseText:"",stream:false,complete:false};
    const parseText=parsed.map(value=>JSON.stringify(value)).join("\n")+"\n";
    const summary=parsed.some(value=>value&&typeof value==="object"&&!Array.isArray(value)&&(
      ["statistics","stats","summary"].includes(lower(value.type))||value.completed===true||value.scan_complete===true
    ));
    return {valid:true,incomplete:Boolean(final)&&parsed.length<=completeLineCount,parseText,stream:true,complete:summary,data:parsed};
  }
  function partialNmapText(text,detection={}){
    const completeLines=withoutIncompleteLastLine(text),parser=lower(detection.parser);
    if(parser==="nmap-grepable"){
      const record=/^\s*Host:\s+\S+(?:\s+\([^)]*\))?\s+Ports:\s*[^\r\n]+$/im.test(completeLines);
      return record?completeLines:"";
    }
    const target=/^\s*Nmap scan report for\s+.+$/im.test(completeLines),port=/^\s*\d{1,5}\/(?:tcp|udp)\s+(?:open|closed|filtered|open\|filtered|closed\|filtered)\b[^\r\n]*$/im.test(completeLines);
    return target&&port?completeLines:"";
  }
  function explicitToolCompletion(path,text,detection={}){
    const value=String(text||""),route=lower(path),tool=lower(detection.tool),failed=lower(detection.toolOperationStatus)==="failed"&&/\b(?:fatal|aborted|interrupted|timed out|timeout|connection refused|unreachable)\b/i.test(value);
    if(failed)return true;
    if(tool==="nikto"||!tool&&/nikto/.test(route))return /^\s*\+\s*(?:End Time:|\d+\s+host\(s\)\s+tested)/im.test(value);
    if(tool==="wpscan"||!tool&&/wpscan/.test(route))return /^\s*\[\+\]\s*Finished:/im.test(value);
    if(["vulners","smb nse","nmap nse"].includes(tool)||!tool&&/(?:nse|vulners)/.test(route))return /^\s*#?\s*Nmap done\b/im.test(value);
    if(["snmp","dns"].includes(tool)||!tool&&/(?:snmp|dns|dig)/.test(route))return /^\s*(?:END|Finished|Completed)\b/im.test(value);
    return false;
  }
  function jsonPathHint(path){return /(?:ffuf|ferox|whatweb|gobuster|dirsearch|dirbuster|autorecon|nmap|scan)/i.test(path);}
  function artifactReadiness({path="",text="",detection={},size=0}={}){
    const raw=String(text??""),trimmed=raw.trim(),fileExtension=extension(path),parser=lower(detection.parser),type=lower(detection.type),status=lower(detection.status);
    if(Number(size)>MAX_ARTIFACT_BYTES)return {ready:false,state:"skipped",retryable:false,reason:"The artifact exceeds the existing 25 MiB per-file import limit.",completion:"none",parseText:""};
    if(!trimmed)return {ready:false,state:"receiving",retryable:true,reason:"The artifact is empty and may still be receiving data.",completion:"none",parseText:""};
    const nmapXml=parser==="nmap-xml"||fileExtension==="xml"&&/<nmaprun\b/i.test(raw);
    if(nmapXml){
      const closed=/<\/nmaprun\s*>/i.test(raw),finished=/<finished\b/i.test(raw);
      if(!closed||!finished)return {ready:false,state:"receiving",retryable:true,reason:"Nmap XML is still open; authoritative XML import waits for the finished run and closing root element.",completion:"none",parseText:""};
      if(!["detected","ready"].includes(status))return {ready:false,state:"receiving",retryable:true,reason:detection.reason||"The closed Nmap XML is not yet accepted by the authoritative detector.",completion:"none",parseText:""};
      return {ready:true,state:"ready",retryable:false,reason:"A finished, closed Nmap XML run is ready for import.",completion:"explicit",parseText:raw};
    }
    const maybeJson=fileExtension==="json"||/^[\[{]/.test(trimmed);
    if(maybeJson){
      const json=parseJsonStream(raw);
      const jsonLineStream=/(?:ferox|jsonl|json-lines)/i.test(`${path} ${parser}`)&&/^\s*\{/.test(raw)&&json.valid&&!json.stream;
      if(jsonLineStream){
        const value=json.data,summary=value&&typeof value==="object"&&!Array.isArray(value)&&(["statistics","stats","summary"].includes(lower(value.type))||value.completed===true||value.scan_complete===true);
        json.stream=true;json.complete=summary;json.parseText=`${JSON.stringify(value)}\n`;
      }
      if(!json.valid){
        if(jsonPathHint(path)||["web-discovery","web-baseline","web-technology"].includes(type))return {ready:false,state:"receiving",retryable:true,reason:"JSON is incomplete while the external tool is writing it.",completion:"none",parseText:""};
        return {ready:false,state:"skipped",retryable:false,reason:detection.reason||"The JSON does not match a supported live importer.",completion:"none",parseText:""};
      }
      if(!PROCESSABLE_TYPES.has(type))return {ready:false,state:"skipped",retryable:false,reason:detection.reason||"Valid JSON does not match a supported scan importer.",completion:"none",parseText:""};
      if(!["detected","ready"].includes(status))return {ready:false,state:"receiving",retryable:true,reason:detection.reason||"The structured artifact is not ready for the authoritative parser.",completion:"none",parseText:""};
      return {ready:true,state:"ready",retryable:false,reason:json.complete?"The structured artifact is complete and ready for import.":"Complete JSON records are ready; the object stream may continue growing.",completion:json.complete?"structured":"open",parseText:json.parseText};
    }
    if(type==="nmap"){
      const grepableTerminal=parser!=="nmap-grepable"||/^\s*#\s*Nmap done at\b/im.test(raw)||/\b(?:QUITTING|fatal|aborted|interrupted)\b/i.test(raw);
      if(["detected","ready"].includes(status)&&grepableTerminal)return {ready:true,state:"ready",retryable:false,reason:"The Nmap text contains an explicit completion indicator.",completion:"explicit",parseText:raw};
      const parseText=partialNmapText(raw,detection);
      if(parseText)return {ready:true,state:"ready",retryable:false,reason:"Complete Nmap text records are ready; scan completion remains open.",completion:"open",parseText};
      return {ready:false,state:"receiving",retryable:true,reason:detection.reason||"Nmap text has no complete result records yet.",completion:"none",parseText:""};
    }
    if(type==="scan-support")return {ready:true,state:"ready",retryable:false,reason:"AutoRecon support metadata can be retained without claiming scan completion.",completion:"open",parseText:withoutIncompleteLastLine(raw)||raw};
    if(type==="scan-tool"){
      if(!explicitToolCompletion(path,raw,detection))return {ready:false,state:"receiving",retryable:true,reason:"The tool output has no reliable completion marker yet, so it is not treated as completed evidence.",completion:"none",parseText:""};
      return {ready:true,state:"ready",retryable:false,reason:"The tool-specific completion marker is present.",completion:"explicit",parseText:raw};
    }
    if(["web-discovery","web-baseline","web-technology"].includes(type)){
      if(!["detected","ready"].includes(status))return {ready:false,state:"receiving",retryable:true,reason:detection.reason||"The web artifact remains incomplete.",completion:"none",parseText:""};
      const operation=lower(type==="web-technology"?detection.whatWebOperationState:type==="web-baseline"?detection.baselineOperationState:detection.webOperationState);
      const explicit=operation==="completed"&&/(?:finished|scan complete|scan completed|task completed|end time\s*:)/i.test(raw);
      return {ready:true,state:"ready",retryable:false,reason:explicit?"The web tool recorded explicit completion.":"Complete web result records are ready; overall file completion remains open.",completion:explicit?"explicit":"open",parseText:withoutIncompleteLastLine(raw)||raw};
    }
    return {ready:false,state:"skipped",retryable:false,reason:detection.reason||"No supported authoritative importer matched this artifact.",completion:"none",parseText:""};
  }

  class ArtifactLedger{
    constructor(entries=[],options={}){
      this.maximumEntries=Number(options.maximumEntries)||DEFAULTS.maximumLedgerEntries;
      this.now=typeof options.now==="function"?options.now:Date.now;
      this.rows=new Map();
      for(const raw of Array.isArray(entries)?entries:[]){
        if(!raw||typeof raw!=="object")continue;
        const relativePath=normalizeRelativePath(raw.relativePath);if(!relativePath)continue;
        const key=lower(raw.key||relativePath);this.rows.set(key,{...raw,key,relativePath});
      }
      this.prune();
    }
    key(path){return lower(normalizeRelativePath(path));}
    get(path){return this.rows.get(this.key(path))||null;}
    values(){return [...this.rows.values()];}
    observe(metadata={},route=null){
      const relativePath=normalizeRelativePath(metadata.relativePath),key=this.key(relativePath),previous=this.rows.get(key)||{};
      const signature=metadataSignature(metadata),changeKind=mutationKind(previous,metadata),at=iso(this.now());
      const entry={...previous,key,relativePath,size:Math.max(0,Number(metadata.size)||0),lastModified:Math.max(0,Number(metadata.lastModified)||0),signature,changeKind:changeKind==="unchanged"?(previous.changeKind||"unchanged"):changeKind,firstSeenAt:previous.firstSeenAt||at,lastSeenAt:at,updatedAt:changeKind==="unchanged"?(previous.updatedAt||at):at};
      if(route){entry.engagement=clean(route.engagement);entry.host=clean(route.host);entry.artifactPath=clean(route.artifactPath);entry.filename=clean(route.filename)||basename(relativePath);}
      if(changeKind!=="unchanged"){entry.retryCount=0;entry.nextRetryAt=0;entry.errorKey="";entry.errorCount=0;}
      this.rows.set(key,entry);this.prune();return {entry,previous,changeKind,unchanged:changeKind==="unchanged"};
    }
    update(path,patch={}){
      const key=this.key(path),previous=this.rows.get(key);if(!previous)return null;
      const entry={...previous,...patch,key,relativePath:previous.relativePath,updatedAt:patch.updatedAt||iso(this.now())};
      this.rows.set(key,entry);return entry;
    }
    remove(path){return this.rows.delete(this.key(path));}
    prune(){
      if(this.rows.size<=this.maximumEntries)return;
      const rows=this.values().sort((a,b)=>String(b.updatedAt||"").localeCompare(String(a.updatedAt||"")));
      this.rows=new Map(rows.slice(0,this.maximumEntries).map(row=>[row.key,row]));
    }
    summary(){
      const rows=this.values(),processed=rows.filter(row=>row.processedAt).length,updating=rows.filter(row=>PROCESSING_STATES.has(row.state)).length;
      const errors=rows.filter(row=>row.state==="error").length,skipped=rows.filter(row=>row.state==="skipped").length,complete=rows.filter(row=>row.state==="complete").length;
      const lastUpdate=rows.map(row=>row.processedAt||row.updatedAt||"").sort().at(-1)||"";
      return {total:rows.length,processed,updating,errors,skipped,complete,lastUpdate};
    }
  }

  class DebounceQueue{
    constructor(worker,options={}){
      if(typeof worker!=="function")throw new Error("A debounce worker is required.");
      this.worker=worker;this.debounceMs=Number(options.debounceMs)||DEFAULTS.debounceMs;this.maximumDebounceMs=Number(options.maximumDebounceMs)||DEFAULTS.maximumDebounceMs;this.concurrency=Math.max(1,Number(options.concurrency)||DEFAULTS.concurrency);
      const timerScope=options.timerScope||(typeof window!=="undefined"?window:globalThis),injectedSetTimer=typeof options.setTimer==="function"?options.setTimer:null,injectedClearTimer=typeof options.clearTimer==="function"?options.clearTimer:null;
      if(!injectedSetTimer&&typeof timerScope?.setTimeout!=="function")throw new Error("A native or injected setTimeout function is required.");
      if(!injectedClearTimer&&typeof timerScope?.clearTimeout!=="function")throw new Error("A native or injected clearTimeout function is required.");
      this.now=typeof options.now==="function"?options.now:Date.now;
      this.setTimer=injectedSetTimer?((callback,delay)=>injectedSetTimer(callback,delay)):timerScope.setTimeout.bind(timerScope);
      this.clearTimer=injectedClearTimer?(timer=>injectedClearTimer(timer)):timerScope.clearTimeout.bind(timerScope);
      this.onError=typeof options.onError==="function"?options.onError:null;
      this.pending=new Map();this.ready=[];this.active=0;this.idleWaiters=[];this.stopped=false;
    }
    reportError(error,context={}){if(!this.onError)return;try{Promise.resolve(this.onError(error,context)).catch(()=>{});}catch(_error){}}
    enqueue(key,payload){
      if(this.stopped)return false;
      const id=String(key),at=this.now(),current=this.pending.get(id),firstAt=current?.firstAt??at;
      try{
        if(current?.timer)this.clearTimer(current.timer);
        const wait=Math.max(0,Math.min(this.debounceMs,firstAt+this.maximumDebounceMs-at)),item={key:id,payload,firstAt,lastAt:at,timer:null};
        item.timer=this.setTimer(()=>this.release(id),wait);this.pending.set(id,item);return true;
      }catch(error){this.pending.delete(id);throw error;}
    }
    release(key){
      const item=this.pending.get(key);if(!item||this.stopped)return;
      this.pending.delete(key);this.ready.push(item);this.pump();
    }
    pump(){
      while(!this.stopped&&this.active<this.concurrency&&this.ready.length){
        const item=this.ready.shift();this.active++;
        Promise.resolve().then(()=>this.worker(item.payload)).catch(error=>this.reportError(error,{phase:"worker",key:item.key,payload:item.payload})).finally(()=>{this.active--;this.pump();this.resolveIdle();});
      }
      this.resolveIdle();
    }
    resolveIdle(){
      if(this.pending.size||this.ready.length||this.active)return;
      const waiters=this.idleWaiters.splice(0);waiters.forEach(resolve=>resolve());
    }
    whenIdle(){return !this.pending.size&&!this.ready.length&&!this.active?Promise.resolve():new Promise(resolve=>this.idleWaiters.push(resolve));}
    cancel(){
      this.stopped=true;for(const item of this.pending.values())if(item.timer)try{this.clearTimer(item.timer);}catch(error){this.reportError(error,{phase:"cancel",key:item.key,payload:item.payload});}
      this.pending.clear();this.ready=[];this.resolveIdle();
    }
  }

  class LiveImportCoordinator{
    constructor(dependencies={},options={}){
      for(const name of ["getWorkspace","classify","readArtifact","createImportFile","ingest"]){if(typeof dependencies[name]!=="function")throw new Error(`Live Import dependency is unavailable: ${name}`);}
      this.dependencies=dependencies;this.options={...DEFAULTS,...options};this.now=typeof options.now==="function"?options.now:Date.now;
      this.rootName=clean(options.rootName);this.ledger=new ArtifactLedger(options.entries||[],{maximumEntries:this.options.maximumLedgerEntries,now:this.now});this.manifests=new Map();
      for(const entry of this.ledger.values())if(entry.manifestData?.runId)this.manifests.set(clean(entry.manifestData.runId),entry.manifestData);
      this.enabled=options.enabled!==false;
      this.retryTimers=new Map();this.queue=new DebounceQueue(payload=>this.process(payload),{...this.options,now:this.now,onError:(error,context)=>this.handleQueueError(error,context)});this.setTimer=(callback,delay)=>this.queue.setTimer(callback,delay);this.clearTimer=timer=>this.queue.clearTimer(timer);this.emit();
    }
    setRootName(value){this.rootName=clean(value);}
    setEnabled(value){this.enabled=value===true;if(!this.enabled)this.clearRetries();this.emit();}
    async persist(entry){if(entry&&typeof this.dependencies.persistEntry==="function")await this.dependencies.persistEntry({...entry});}
    async removePersisted(entry){if(entry&&typeof this.dependencies.removeEntry==="function")await this.dependencies.removeEntry({...entry});}
    emit(){if(typeof this.dependencies.onUpdate==="function")this.dependencies.onUpdate({summary:this.ledger.summary(),entries:this.activity(),queueActive:this.queue.active,queuePending:this.queue.pending.size+this.queue.ready.length});}
    activity(limit=12){return this.ledger.values().sort((a,b)=>String(b.updatedAt||"").localeCompare(String(a.updatedAt||""))).slice(0,limit);}
    async mark(path,patch){
      const current=this.ledger.get(path);if(!current)return null;
      if(!Object.entries(patch).some(([key,value])=>current[key]!==value))return current;
      const entry=this.ledger.update(path,patch);if(entry)await this.persist(entry);this.emit();return entry;
    }
    async reportDiagnostic(error,phase,path){const diagnostic=error?.phase&&error?.message?{...error}:errorDiagnostic(error,{phase,path});if(typeof this.dependencies.onDiagnostic==="function")try{await this.dependencies.onDiagnostic({...diagnostic});}catch(_error){}return diagnostic;}
    async markEntryError(entry,error,phase){
      const diagnostic=await this.reportDiagnostic(error,phase,entry?.relativePath||""),current=entry&&this.ledger.get(entry.relativePath)||entry;if(!current)return diagnostic;
      const errorKey=`${current.signature||""}|${diagnostic.phase}|${diagnostic.name}|${diagnostic.message}`,same=current.errorKey===errorKey,errorCount=same?(Number(current.errorCount)||0)+1:1;
      await this.mark(current.relativePath,{state:"error",reason:`${diagnostic.name}: ${diagnostic.message}`,errorKey,errorCount,nextRetryAt:0,errorName:diagnostic.name,errorMessage:diagnostic.message,errorStack:diagnostic.stack,errorPhase:diagnostic.phase,errorPath:diagnostic.path,diagnostic});return diagnostic;
    }
    async enqueueEntry(entry,payload,phase="enqueue"){
      try{if(!this.queue.enqueue(entry.key,payload)){const error=new Error("The Live Import debounce queue is unavailable.");error.name="LiveImportQueueUnavailableError";throw error;}return true;}
      catch(error){await this.markEntryError(entry,error,phase);throw error;}
    }
    async handleQueueError(error,context={}){const path=context?.payload?.relativePath||"",entry=path?this.ledger.get(path):null;if(entry)await this.markEntryError(entry,error,`queue-${context.phase||"worker"}`);else await this.reportDiagnostic(error,`queue-${context.phase||"worker"}`,path);}
    async ignore(relativePath,semantic={},route=null){
      const entry=this.ledger.get(relativePath),key=entry?.key||lower(normalizeRelativePath(relativePath));
      if(this.retryTimers.has(key)){try{this.clearTimer(this.retryTimers.get(key));}catch(error){await this.reportDiagnostic(error,"semantic-ignore-retry-clear",relativePath);}this.retryTimers.delete(key);}
      if(entry){this.ledger.remove(relativePath);try{await this.removePersisted(entry);}catch(error){await this.reportDiagnostic(error,"semantic-ignore-ledger-remove",relativePath);}}
      if(typeof this.dependencies.onSemanticIgnore==="function")try{await this.dependencies.onSemanticIgnore({entry:entry||{relativePath:normalizeRelativePath(relativePath),key},semantic,route});}catch(error){await this.reportDiagnostic(error,"semantic-ignore-reconcile",relativePath);}
      this.emit();return {queued:false,reason:semantic.kind||"semantic-ignore",ignored:true};
    }
    async observe(metadata={},options={}){
      if(!this.enabled||!isPotentialArtifactPath(metadata.relativePath))return {queued:false,reason:"disabled-or-unsupported-path"};
      const route=parseArtifactRoute(metadata.relativePath,{rootName:this.rootName,manifests:this.manifests});
      let semantic=options.semantic;
      if(!semantic&&typeof this.dependencies.semanticDisposition==="function")semantic=await this.dependencies.semanticDisposition({path:metadata.relativePath,relativePath:metadata.relativePath,metadata,route,contentAvailable:false,phase:"recognition"});
      if(semantic?.action==="ignore")return this.ignore(metadata.relativePath,semantic,route);
      const observed=this.ledger.observe(metadata,route.ok?route:null),entry=observed.entry;
      if(!observed.unchanged||!observed.previous?.engagement&&route.ok)await this.persist(entry);
      if(!route.ok){await this.mark(entry.relativePath,{state:"skipped",reason:route.reason,routeStatus:route.status,processedSignature:entry.signature});return {queued:false,reason:route.status};}
      const resolution=resolveWorkspaceArtifactRoute(route,this.dependencies.getWorkspace()||{}),manifestEntry=autorecon.isManifestPath?.(entry.relativePath)===true;
      if(!resolution.ok&&!manifestEntry){await this.mark(entry.relativePath,{state:"waiting",reason:resolution.reason,routeStatus:resolution.status});return {queued:false,reason:resolution.status};}
      const stableBoundaryPending=options.stableFileBoundary===true&&entry.stableBoundaryAttemptSignature!==entry.signature&&(entry.provisional===true||entry.artifactLifecycle!=="canonical");
      if(!options.force&&!stableBoundaryPending&&entry.processedSignature===entry.signature){
        if(entry.artifactId&&typeof this.dependencies.isArtifactPresent==="function"){
          const present=await this.dependencies.isArtifactPresent(entry,resolution);
          if(!present){await this.enqueueEntry(entry,{relativePath:entry.relativePath,route,resolution,metadata,force:true},"workspace-reconciliation-enqueue");return {queued:true,reason:"workspace-reconciliation"};}
        }
        return {queued:false,reason:"unchanged"};
      }
      if(!options.force&&Number(entry.nextRetryAt)>this.now())return {queued:false,reason:"retry-backoff"};
      await this.mark(entry.relativePath,{state:"discovered",reason:observed.changeKind==="rewritten"?"A truncation or replacement was detected; waiting for a safe current representation.":"Artifact change coalesced for import.",routeStatus:"ready"});
      await this.enqueueEntry(entry,{relativePath:entry.relativePath,route,resolution,metadata,force:options.force===true,semantic,reconciliation:options.reconciliation===true,stableFileBoundary:options.stableFileBoundary===true},"observe-enqueue");return {queued:true,reason:stableBoundaryPending?"stable-file-boundary":observed.changeKind};
    }
    async workspaceChanged(){
      if(!this.enabled)return;
      for(const entry of this.ledger.values().filter(row=>row.state==="waiting"&&row.signature)){
        const route=parseArtifactRoute(entry.relativePath,{rootName:this.rootName,manifests:this.manifests}),resolution=resolveWorkspaceArtifactRoute(route,this.dependencies.getWorkspace()||{});
        if(resolution.ok||autorecon.isManifestPath?.(entry.relativePath)===true)await this.enqueueEntry(entry,{relativePath:entry.relativePath,route,resolution,metadata:{relativePath:entry.relativePath,size:entry.size,lastModified:entry.lastModified},force:true},"workspace-change-enqueue");
      }
    }
    retryDelay(entry){return Math.min(this.options.retryMaximumMs,this.options.retryBaseMs*(2**Math.max(0,Number(entry.retryCount)||0)));}
    scheduleRetry(entry){
      if(!this.enabled||Number(entry.retryCount)>=this.options.maximumAutomaticRetries)return;
      const key=entry.key;if(this.retryTimers.has(key))try{this.clearTimer(this.retryTimers.get(key));}catch(error){this.markEntryError(entry,error,"retry-clear-timer").catch(()=>{});}
      const delay=Math.max(0,Number(entry.nextRetryAt)-this.now());
      try{const timer=this.setTimer(()=>{this.retryTimers.delete(key);const current=this.ledger.get(entry.relativePath);if(current&&current.signature!==current.processedSignature)this.enqueueEntry(current,{relativePath:current.relativePath,metadata:{relativePath:current.relativePath,size:current.size,lastModified:current.lastModified},force:true},"retry-enqueue").catch(()=>{});},delay);this.retryTimers.set(key,timer);}
      catch(error){this.markEntryError(entry,error,"retry-set-timer").catch(()=>{});}
    }
    clearRetries(){for(const timer of this.retryTimers.values())try{this.clearTimer(timer);}catch(error){this.reportDiagnostic(error,"retry-clear-all","");}this.retryTimers.clear();}
    async defer(entry,readiness){
      const retryCount=(Number(entry.retryCount)||0)+1,exhausted=readiness.retryable===false||retryCount>=this.options.maximumAutomaticRetries,nextRetryAt=exhausted?0:this.now()+this.retryDelay(entry);
      const reason=exhausted?`${readiness.reason} Waiting for the next file change.`:readiness.reason;
      const updated=await this.mark(entry.relativePath,{state:"receiving",reason,retryCount,nextRetryAt,parserType:entry.parserType||"",completion:"open",processedSignature:exhausted?entry.signature:entry.processedSignature});
      if(!exhausted)this.scheduleRetry(updated);
    }
    async retainRaw(entry,snapshot,resolution,details={}){
      if(typeof this.dependencies.ingestRaw!=="function")return {ok:false,reason:details.reason||"No raw-artifact inventory bridge is available.",retryable:false};
      const paths=artifactSourcePaths(resolution,entry.relativePath,this.rootName),result=await this.dependencies.ingestRaw({entry,snapshot,route:resolution,logicalPath:paths.canonicalLogicalPath,...paths,...details});
      if(result?.ok===false)return result;
      const provisional=result?.provisional===true,processedAt=iso(this.now()),artifactRevision=provisional?0:(Number(result?.artifactRevision)||Number(entry.artifactRevision)||1);
      await this.mark(entry.relativePath,{state:provisional?"receiving":"complete",reason:result?.reason||details.reason||"The artifact is retained in the AutoRecon inventory.",processedAt,processedSignature:entry.signature,processedSize:entry.size,processedLastModified:entry.lastModified,artifactId:clean(result?.artifactId||entry.artifactId),inventoryId:clean(result?.inventoryId||entry.inventoryId),artifactRevision,outcome:clean(result?.outcome||"inventoried"),artifactLifecycle:provisional?"provisional":"canonical",provisional,completion:provisional?"open":clean(details.completion||"raw-final"),retryCount:0,nextRetryAt:0,errorKey:"",errorCount:0});
      return result;
    }
    async replayCompanionDependents(entry,detection){
      if(clean(detection?.type)!=="scan-support"||!/(?:^|\/)_(?:commands|errors)[.]log$/i.test(clean(entry?.relativePath)))return 0;
      const normalized=normalizeRelativePath(entry.relativePath),base=normalized.slice(0,normalized.lastIndexOf("/")+1),candidates=this.ledger.values().filter(candidate=>{
        if(candidate.key===entry.key||!candidate.signature||!candidate.processedSignature||!normalizeRelativePath(candidate.relativePath).startsWith(base))return false;
        if(/(?:^|\/)_(?:commands|errors)[.]log$/i.test(candidate.relativePath))return false;
        return ["nmap","scan-tool"].includes(clean(candidate.detectedType))||/nmap/i.test(clean(candidate.parserType));
      }).slice(0,250);
      for(const candidate of candidates)await this.enqueueEntry(candidate,{relativePath:candidate.relativePath,metadata:{relativePath:candidate.relativePath,size:candidate.size,lastModified:candidate.lastModified},force:true,companionReplay:true},"companion-replay-enqueue");
      return candidates.length;
    }
    async processManifest(entry,snapshot,resolution){
      if(typeof autorecon.parseRunManifest!=="function")throw new Error("AutoRecon manifest support is unavailable.");
      const manifest=autorecon.parseRunManifest(snapshot.text,{relativePath:entry.relativePath,rootName:this.rootName}),manifestResolution=resolveWorkspaceArtifactRoute({...resolution,ok:true,status:"manifest",scope:"engagement",engagement:manifest.engagement,artifactPath:manifest.manifestPath,filename:basename(manifest.manifestPath),relativePath:manifest.manifestPath},this.dependencies.getWorkspace()||{});
      if(!manifestResolution.ok){await this.mark(entry.relativePath,{state:"waiting",reason:manifestResolution.reason,routeStatus:manifestResolution.status});return {ok:false,...manifestResolution};}
      const previous=this.manifests.get(manifest.runId)||null;
      this.manifests.set(manifest.runId,manifest);
      const provisional=!autorecon.isTerminalRunStatus(manifest.status),manifestError=clean(manifest.wrapperError||manifest.transport?.error),terminalReason=manifestError?`The atomic AutoRecon run manifest records terminal scanner status ${manifest.status}; operator action is required: ${manifestError}`:`The atomic AutoRecon run manifest records terminal scanner status ${manifest.status} and transport ${manifest.transport?.status||"unknown"}.`,raw=await this.retainRaw(entry,snapshot,{...manifestResolution,manifest,runId:manifest.runId},{detection:{type:"autorecon-manifest",parser:"autorecon-run-manifest",status:"detected",tool:"AutoRecon"},manifest,provisional,metadataOnly:false,completion:provisional?"open":"manifest-terminal",reason:provisional?"The atomic AutoRecon run manifest is running; it remains a replaceable engagement-level inventory record.":terminalReason});
      await this.mark(entry.relativePath,{manifestData:manifest,runId:manifest.runId,runStatus:manifest.status,parserType:"autorecon-run-manifest",detectedType:"autorecon-manifest",tool:"AutoRecon"});
      if(typeof this.dependencies.onManifest==="function")await this.dependencies.onManifest({manifest,previous,entry,result:raw});
      const changed=!previous||previous.status!==manifest.status||previous.updatedAt!==manifest.updatedAt;
      if(changed){
        for(const candidate of this.ledger.values()){
          if(candidate.key===entry.key||!candidate.signature)continue;
          const owner=autorecon.manifestForArtifact?.([manifest],candidate.relativePath,{rootName:this.rootName});if(owner?.runId!==manifest.runId)continue;
          await this.enqueueEntry(candidate,{relativePath:candidate.relativePath,metadata:{relativePath:candidate.relativePath,size:candidate.size,lastModified:candidate.lastModified},force:true,manifestFinalization:autorecon.isTerminalRunStatus(manifest.status)&&autorecon.transportReady?.(manifest)===true},"manifest-finalization-enqueue");
        }
      }
      return raw;
    }
    async process(payload={}){
      if(!this.enabled)return;
      const route=parseArtifactRoute(payload.relativePath,{rootName:this.rootName,manifests:this.manifests}),resolution=resolveWorkspaceArtifactRoute(route,this.dependencies.getWorkspace()||{}),manifestEntry=autorecon.isManifestPath?.(payload.relativePath)===true;
      if(!resolution.ok&&!manifestEntry){await this.mark(payload.relativePath,{state:"waiting",reason:resolution.reason,routeStatus:resolution.status});return;}
      let entry=this.ledger.get(payload.relativePath);if(!entry)return;
      await this.mark(entry.relativePath,{state:"processing",reason:"Reading the latest coalesced file state."});
      try{
        const snapshot=await this.dependencies.readArtifact(entry.relativePath);
        if(!snapshot||!snapshot.file)throw new Error("The artifact disappeared before it could be read.");
        const metadata={relativePath:entry.relativePath,size:Number(snapshot.size??snapshot.file.size)||0,lastModified:Number(snapshot.lastModified??snapshot.file.lastModified)||0};
        if(metadataSignature(metadata)!==entry.signature){await this.observe(metadata,{force:true});return;}
        if(manifestEntry){await this.processManifest(entry,snapshot,resolution);return;}
        const manifest=route.manifest||autorecon.manifestForArtifact?.(this.manifests,entry.relativePath,{rootName:this.rootName})||null,scannerTerminal=manifest&&autorecon.isTerminalRunStatus?.(manifest.status),transportReady=!manifest||autorecon.transportReady?.(manifest)===true,runTerminal=scannerTerminal&&transportReady,transportBlocked=scannerTerminal&&!transportReady,runRunning=manifest?.status==="running";
        let semantic=payload.semantic;
        if((!semantic||semantic.action==="inspect")&&typeof this.dependencies.semanticDisposition==="function")semantic=await this.dependencies.semanticDisposition({path:entry.relativePath,relativePath:entry.relativePath,metadata,route:{...resolution,manifest},manifest,snapshot,text:snapshot.text,contentAvailable:true,phase:"content-recognition"});
        if(semantic?.action==="ignore"){await this.ignore(entry.relativePath,semantic,{...resolution,manifest});return;}
        const unsupportedMaterial=metadata.size>MAX_ARTIFACT_BYTES||snapshot.binary===true;
        const detection=unsupportedMaterial?{type:"",parser:"",status:"unsupported",reason:metadata.size>MAX_ARTIFACT_BYTES?"The artifact exceeds the automatic read and retention limit.":"The artifact contains binary bytes and has no structured text parser."}:await this.dependencies.classify({name:basename(entry.relativePath),path:entry.relativePath,size:metadata.size,text:snapshot.text,signatureHex:snapshot.signatureHex,file:snapshot.file});
        entry=await this.mark(entry.relativePath,{parserType:clean(detection?.parser||detection?.type||""),detectedType:clean(detection?.type||""),tool:clean(detection?.tool||""),runId:clean(manifest?.runId),runStatus:clean(manifest?.status),stableBoundaryAttemptSignature:payload.stableFileBoundary===true?entry.signature:entry.stableBoundaryAttemptSignature})||entry;
        let readiness=artifactReadiness({path:entry.relativePath,text:snapshot.text,detection,size:metadata.size});
        const selfTerminatingNmap=["nmap","scan-tool"].includes(clean(detection?.type))&&lower(detection?.tool||"Nmap")==="nmap"&&readiness.completion==="explicit";
        if(runRunning&&readiness.ready&&!selfTerminatingNmap)readiness={...readiness,completion:"open",reason:"The AutoRecon run manifest is still running; this non-self-terminating output remains a replaceable provisional projection."};
        if(transportBlocked&&readiness.ready)readiness={...readiness,completion:"open",reason:`The AutoRecon scanner is ${manifest.status}, but terminal-copy transport is ${manifest.transport?.status||"absent"}; this staging copy remains provisional. ${manifest.transport?.error||"Use the manifest recovery root and retry verified transport."}`};
        if(runTerminal&&readiness.ready&&readiness.completion==="open")readiness={...readiness,completion:"manifest-terminal",reason:`The ${manifest.status} AutoRecon manifest establishes the final file boundary; parser result semantics remain unchanged.`};
        if(!manifest&&payload.stableFileBoundary===true&&clean(detection?.type)==="web-discovery"&&clean(detection?.parser)==="feroxbuster-text"&&readiness.ready&&readiness.completion==="open")readiness={...readiness,completion:"stable-file",reason:"The pre-existing Feroxbuster text file remained unchanged beyond the bounded reconciliation stability interval; this establishes a file-level retention boundary without claiming scanner success."};
        if(runTerminal&&!readiness.ready&&detection?.type==="scan-tool"&&String(snapshot.text||"").trim())readiness={ready:true,state:"ready",retryable:false,reason:`The ${manifest.status} AutoRecon manifest establishes final bytes for this recognized tool output without claiming a positive result.`,completion:"manifest-terminal",parseText:String(snapshot.text||"")};
        if(!readiness.ready){
          const rawReason=transportBlocked?`Transport is ${manifest.transport?.status||"absent"}; copied partials cannot become canonical. ${manifest.transport?.error||"Recover the complete child output from the manifest recovery root."}`:metadata.size>MAX_ARTIFACT_BYTES?`Metadata only: the unchanged ${metadata.size}-byte artifact exceeds the ${MAX_ARTIFACT_BYTES}-byte automatic read/retention limit.`:snapshot.binary===true?"Unsupported binary artifact retained as exact bytes only when the run has a terminal manifest and verified transport; no parser claims are derived.":readiness.reason;
          const raw=await this.retainRaw(entry,snapshot,{...resolution,manifest},{detection,manifest,semantic,provisional:!runTerminal,metadataOnly:metadata.size>MAX_ARTIFACT_BYTES,completion:runTerminal?"manifest-terminal":"open",reason:semantic?.reason||rawReason,parserState:readiness.state});
          if(raw?.ok!==false)return;
          if(readiness.state==="skipped"){await this.mark(entry.relativePath,{state:"skipped",reason:raw.reason||readiness.reason,processedSignature:entry.signature,retryCount:0,nextRetryAt:0});return;}
          await this.defer(entry,readiness);return;
        }
        if(typeof this.dependencies.currentMetadata==="function"){
          const current=await this.dependencies.currentMetadata(entry.relativePath);
          if(current&&metadataSignature(current)!==entry.signature){await this.observe({...current,relativePath:entry.relativePath},{force:true});return;}
        }
        const resolvedRoute={...resolution,manifest,runId:manifest?.runId||"",runStatus:manifest?.status||""},paths=artifactSourcePaths(resolvedRoute,entry.relativePath,this.rootName),file=await this.dependencies.createImportFile(snapshot,paths.physicalSourcePath,readiness.parseText,paths.canonicalLogicalPath);
        const result=await this.dependencies.ingest({file,snapshot,detection,readiness,route:resolvedRoute,manifest,semantic,logicalPath:paths.canonicalLogicalPath,...paths,entry});
        if(result?.ok===false){
          if(typeof this.dependencies.ingestRaw==="function"){const raw=await this.retainRaw(entry,snapshot,{...resolution,manifest},{detection,manifest,semantic,provisional:!runTerminal,metadataOnly:false,completion:runTerminal?"manifest-terminal":"open",reason:semantic?.reason||`Structured parsing was not accepted (${result.reason||"unsupported result"}); exact raw evidence remains inventoried without derived claims.`,parserState:"unparsed"});if(raw?.ok!==false)return;}
          const error=new Error(result.reason||"The authoritative importer did not accept this artifact.");error.code=result.code||"";error.retryable=result.retryable;throw error;
        }
        if(readiness.completion==="open"&&result?.provisional!==true){const error=new Error("The Live Import bridge refused an open update because it was not modeled as provisional evidence.");error.code="LIVE_IMPORT_PROVISIONAL_REQUIRED";error.retryable=false;throw error;}
        const provisional=result?.provisional===true,completed=!provisional&&readiness.completion!=="open"&&result?.complete!==false,processedAt=iso(this.now()),artifactRevision=provisional?0:(Number(result?.artifactRevision)||Number(entry.artifactRevision)||0);
        const inventory=typeof this.dependencies.recordInventory==="function"?await this.dependencies.recordInventory({entry,snapshot,detection,readiness,route:resolvedRoute,manifest,semantic,result,logicalPath:paths.canonicalLogicalPath,...paths,provisional}):null;
        await this.mark(entry.relativePath,{state:completed?"complete":"receiving",reason:completed?(result?.reason||"Imported through the authoritative pipeline."):(result?.reason||"Current complete records were imported into a replaceable provisional projection; file completion remains open."),processedAt,processedSignature:entry.signature,processedSize:entry.size,processedLastModified:entry.lastModified,physicalSourcePath:paths.physicalSourcePath,canonicalLogicalPath:paths.canonicalLogicalPath,artifactId:clean(result?.artifactId||entry.artifactId),inventoryId:clean(inventory?.inventoryId||result?.inventoryId||entry.inventoryId),artifactRevision,outcome:clean(result?.outcome||"processed"),artifactLifecycle:provisional?"provisional":"canonical",provisional,completion:completed?readiness.completion:"open",retryCount:0,nextRetryAt:0,errorKey:"",errorCount:0});
        await this.replayCompanionDependents(entry,detection);
      }catch(error){
        const current=this.ledger.get(payload.relativePath)||entry,diagnostic=await this.reportDiagnostic(error,"process",current?.relativePath||payload.relativePath),errorMessage=diagnostic.message;
        if(error?.code==="LIVE_IMPORT_ROUTING_REQUIRED"){
          await this.mark(current.relativePath,{state:"waiting",reason:errorMessage,routeStatus:"mapping-required",nextRetryAt:0,errorName:diagnostic.name,errorMessage:diagnostic.message,errorStack:diagnostic.stack,errorPhase:diagnostic.phase,errorPath:diagnostic.path,diagnostic});return;
        }
        const errorKey=`${current.signature}|${diagnostic.phase}|${diagnostic.name}|${diagnostic.message}`,same=current.errorKey===errorKey,errorCount=same?(Number(current.errorCount)||0)+1:1,retryCount=(Number(current.retryCount)||0)+1;
        const exhausted=error?.retryable===false||retryCount>=this.options.maximumAutomaticRetries,nextRetryAt=exhausted?0:this.now()+this.retryDelay(current);
        const updated=await this.mark(current.relativePath,{state:"error",reason:errorMessage,errorKey,errorCount,retryCount,nextRetryAt,processedSignature:exhausted?current.signature:current.processedSignature,errorName:diagnostic.name,errorMessage:diagnostic.message,errorStack:diagnostic.stack,errorPhase:diagnostic.phase,errorPath:diagnostic.path,diagnostic});
        if(nextRetryAt)this.scheduleRetry(updated);
      }
    }
    async removeProvisional(entry,details={}){
      if(!entry||entry.provisional!==true)return {removed:false,canonicalRetained:!!entry};
      let result={removed:false};
      try{
        if(typeof this.dependencies.removeProvisional==="function")result=await this.dependencies.removeProvisional({...entry},details)||result;
        await this.mark(entry.relativePath,{provisionalRemovedAt:iso(this.now()),provisionalRemovalReason:clean(details.reason||"source-missing"),provisionalRemovalError:""});
      }catch(error){
        const diagnostic=await this.reportDiagnostic(error,"remove-provisional",entry.relativePath),message=diagnostic.message;
        result={removed:false,error:message};
        await this.mark(entry.relativePath,{provisionalRemovalReason:clean(details.reason||"source-missing"),provisionalRemovalError:message,provisionalRemovalDiagnostic:diagnostic});
      }
      return result;
    }
    async markMissing(relativePath,details={}){
      const entry=this.ledger.get(relativePath);if(!entry)return;
      const provisional=entry.provisional===true,removal=provisional?await this.removeProvisional(entry,{...details,reason:details.reason||"source-missing"}):null,removalFailed=!!removal?.error;
      const reason=provisional
        ?removalFailed
          ?`The provisional source disappeared, but its replaceable projection could not be removed: ${removal.error}`
          :details.movedTo?`The provisional source moved to ${details.movedTo}; the old replaceable projection was removed before the new path is processed.`:"The provisional source file disappeared, so its source-owned projection was removed."
        :"The canonical source file is no longer present. Previously retained historical evidence remains unchanged.";
      await this.mark(entry.relativePath,{state:details.movedTo?"moved":"missing",reason,missingAt:iso(this.now()),movedTo:clean(details.movedTo),nextRetryAt:0});
    }
    async move(previousPath,nextPath,metadata={},options={}){
      const previous=this.ledger.get(previousPath);if(previous)await this.markMissing(previous.relativePath,{movedTo:normalizeRelativePath(nextPath),reason:"source-moved"});
      return this.observe({...metadata,relativePath:normalizeRelativePath(nextPath)},{...options,force:true});
    }
    async markUnseenMissing(seenPaths=[]){
      const seen=new Set([...seenPaths].map(value=>this.ledger.key(value)));
      for(const entry of this.ledger.values())if(!seen.has(entry.key)&&(entry.state!=="missing"&&entry.state!=="moved"||entry.provisional===true&&!entry.provisionalRemovedAt))await this.markMissing(entry.relativePath,{reason:"reconciliation-missing"});
    }
    whenIdle(){return this.queue.whenIdle();}
    stop(){this.enabled=false;this.clearRetries();this.queue.cancel();this.emit();}
  }

  return Object.freeze({SCHEMA_VERSION,MAX_ARTIFACT_BYTES,PROVISIONAL_ARTIFACT_PREFIX,DEFAULTS,PROCESSABLE_TYPES,sha256Hex,normalizeRelativePath,errorDiagnostic,isIpv4,isIpv6,normalizeAddress,canonicalEngagementName,parseStagingRoute,resolveWorkspaceArtifactRoute,parseArtifactRoute,hostIdentityValues,resolveWorkspaceRoute,isPotentialArtifactPath,artifactSourcePaths,promoteAuthoritativeScanTool,provisionalArtifactId,isProvisionalArtifactId,metadataSignature,mutationKind,withoutIncompleteLastLine,parseJsonStream,artifactReadiness,ArtifactLedger,DebounceQueue,LiveImportCoordinator});
});
