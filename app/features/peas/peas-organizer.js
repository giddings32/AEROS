(function(root,factory){
  const api=factory();
  if(typeof module==="object"&&module.exports)module.exports=api;
  if(root)root.AEROSPeasOrganizer=api;
})(typeof globalThis!=="undefined"?globalThis:this,function(){
  "use strict";
  const VERSION=6;
  const STATE_ORDER=["observed","potential-lead","applicability-confirmed","attempted","exploited","dismissed"];
  const EMPHASIS_ORDER=["red-yellow","red","light-cyan","blue","light-magenta","green"];
  const EMPHASIS_LABELS={
    "red-yellow":"High-confidence privilege-escalation lead",
    red:"Operator review required",
    "light-cyan":"Console-enabled account",
    blue:"Non-interactive account or mounted device",
    green:"Baseline or expected system item",
    "light-magenta":"Executing account"
  };
  const EMPHASIS_RANK={"red-yellow":0,red:1,"light-cyan":3,blue:4,"light-magenta":5,green:6};
  const LINUX_CATEGORIES=[
    ["sudo",/\bsudo(?:ers)?\b|\bnopasswd\b|\bsudo -l\b/i],
    ["sgid",/\bsgid\b|\bsetgid\b/i],
    ["suid",/\bsuid\b|\bsetuid\b/i],
    ["capabilities",/\bcapabilit(?:y|ies)\b|\bgetcap\b|\bcap_[a-z0-9_]+\b/i],
    ["cron-timers",/\bcron(?:tab)?\b|\bsystemd timer\b|\btimers?\b|\bscheduled job\b/i],
    ["services",/\bservices?\b|\bsystemd\b|\binit\.d\b|\bdaemon\b/i],
    ["credentials-secrets",/\bpasswords?\b|\bcredentials?\b|\bsecrets?\b|\bprivate keys?\b|\bhistory files?\b|\bapi keys?\b|\btokens?\b/i],
    ["writable-paths",/\bwritable\b|\bwrite permissions?\b|\bworld[- ]writable\b|\bpermissions?\b/i],
    ["kernel-os",/\bkernel\b|\bdistro\b|\boperating system\b|\bexploit suggester\b/i],
    ["network",/\bnetwork\b|\broutes?\b|\binterfaces?\b|\blistening ports?\b|\bfirewall\b/i],
    ["containers",/\bdocker\b|\blxd\b|\blxc\b|\bcontainers?\b|\bkubernetes\b/i],
    ["identity",/\busers?\b|\bgroups?\b|\bcurrent user\b|\buid\b|\bgid\b/i],
    ["software",/\bsoftware\b|\bpackages?\b|\bapplications?\b|\bversions?\b/i],
    ["interesting-files",/\bfiles?\b|\bbackups?\b|\blogs?\b|\bhome folders?\b/i]
  ];
  const WINDOWS_CATEGORIES=[
    ["token-privileges",/\btoken privileges?\b|\bse[a-z0-9]+privilege\b|\bwhoami \/priv\b/i],
    ["services",/\bservices?\b|\bunquoted service\b|\bservice permissions?\b/i],
    ["scheduled-tasks",/\bscheduled tasks?\b|\btask scheduler\b|\bschtasks\b/i],
    ["registry",/\bregistry\b|\bhklm\\|\bhkcu\\|\balwaysinstallelevated\b/i],
    ["credentials-secrets",/\bpasswords?\b|\bcredentials?\b|\bsecrets?\b|\bautologon\b|\bcredential manager\b|\bsam\b|\blsa\b/i],
    ["writable-paths",/\bwritable\b|\bwrite permissions?\b|\bweak permissions?\b|\bmodifiable\b/i],
    ["av-edr",/\bantivirus\b|\bdefender\b|\bedr\b|\bsecurity products?\b/i],
    ["network",/\bnetwork\b|\broutes?\b|\badapters?\b|\blistening ports?\b|\bfirewall\b/i],
    ["powershell-history",/\bpowershell history\b|\bconsolehost_history\b|\bpsreadline\b/i],
    ["identity",/\busers?\b|\bgroups?\b|\bcurrent user\b|\bdomain\b|\bsid\b/i],
    ["software",/\bsoftware\b|\bapplications?\b|\binstalled programs?\b|\bhotfixes?\b/i],
    ["interesting-files",/\bfiles?\b|\bbackups?\b|\blogs?\b|\bdocuments?\b/i]
  ];
  const POTENTIAL_PATTERNS=[
    ["Credential or secret material",/(?:-----BEGIN [A-Z ]*PRIVATE KEY-----|\b(?:password|passwd|secret|api[_ -]?key|access[_ -]?token|auth[_ -]?token|autologon)\b\s*(?:=|:)\s*(?!\s*(?:none|null|not found|disabled|false)\b)\S+)/i],
    ["Writable or weakly protected path",/\b(?:writable|world[- ]writable|write permissions?|weak permissions?|modifiable)\b/i],
    ["Exploit or vulnerability reference",/\b(?:CVE-\d{4}-\d+|vulnerab(?:le|ility)|exploit(?:able|ation)?|privesc)\b/i],
    ["Privileged command or binary evidence",/\b(?:NOPASSWD|SUID|SGID|setuid|setgid|cap_[a-z0-9_]+)\b/i],
    ["Windows privilege-escalation condition",/\b(?:AlwaysInstallElevated|unquoted service path|SeImpersonatePrivilege|SeBackupPrivilege|SeRestorePrivilege|SeAssignPrimaryTokenPrivilege)\b/i],
    ["Potentially abusable scheduled execution",/\b(?:cron|scheduled task|systemd timer|service)\b.*\b(?:writable|permission|replace|hijack|modifiable)\b/i]
  ];
  const NEGATIVE_RE=/\b(?:not vulnerable|not exploitable|not writable|permission denied|access denied|no findings?|nothing found|not found|patched|disabled by policy|outside known affected ranges|not reachable on this kernel|not sniffable|no sniffable interfaces)\b/i;
  const STRUCTURED_NEGATIVE_RE=/(?:\?|\.{2,}|:|\s{2,})\s*(?:no|none|not found|not reachable|not sniffable|not detected|outside known affected ranges)\s*$/i;
  const PATH_RE=/(?:^|[\s:=,(])((?:\/[A-Za-z0-9_.+@%~\-]+)+(?:\/[A-Za-z0-9_.+@%~\-]+)*|[A-Za-z]:\\[^\s"'<>|]+)/;
  const BANNER_RE=/^(?:[\s═─━#*+\-=_.:|╔╗╚╝╠╣╦╩╬│]+)$/u;
  const NOISE_RE=[
    /^ADVISORY:/i,
    /^(?:RED\/YELLOW|RED|LightCyan|Blue|Green|LightMagenta):/i,
    /^(?:Starting LinPEAS|Caching directories|Do you like PEASS|Thank you!?)/i,
    /^(?:Linux Privesc Checklist|Best Linux PE & Hardening course|Learn and practice cloud hacking)/i,
    /^https?:\/\/(?:book\.hacktricks|hacktricks-training|training\.hacktricks|github\.com\/carlospolop)/i,
    /^╚\s*(?:https?:\/\/|Check\b|Any\b|You\b)/i,
    /^(?:-e|No related packages found via dpkg)$/i,
    /^#\)\s*/i
  ];
  const BASIC_COLORS={
    30:["black","#000000"],31:["red","#c0392b"],32:["green","#2ecc71"],33:["yellow","#d4ac0d"],34:["blue","#3498db"],35:["magenta","#9b59b6"],36:["cyan","#17a2b8"],37:["white","#dfe6e9"],
    90:["bright-black","#7f8c8d"],91:["bright-red","#ff5c57"],92:["bright-green","#5af78e"],93:["bright-yellow","#f3f99d"],94:["bright-blue","#57c7ff"],95:["bright-magenta","#ff6ac1"],96:["bright-cyan","#9aedfe"],97:["bright-white","#ffffff"]
  };
  const BG_TO_FG={40:30,41:31,42:32,43:33,44:34,45:35,46:36,47:37,100:90,101:91,102:92,103:93,104:94,105:95,106:96,107:97};

  const clean=value=>String(value??"").trim();
  const unique=values=>Array.from(new Set((values||[]).map(clean).filter(Boolean)));
  const slug=value=>clean(value).toLowerCase().replace(/[^a-z0-9]+/g,"-").replace(/^-+|-+$/g,"")||"section";
  function normalizeTerminalText(value){
    return String(value??"")
      .replace(/\x1B\][^\x07]*(?:\x07|\x1B\\)/g,"")
      .replace(/\r\n?/g,"\n")
      .replace(/[\x00-\x08\x0B\x0C\x0E-\x1A\x1C-\x1F\x7F]/g,"")
      // Some LinPEAS lines contain duplicated ESC introducers and a repeated
      // bare SGR tail (ESC ESC[0m[0m). Canonicalize that malformed stream so
      // both ANSI rendering and clean-text extraction treat it as one reset.
      .replace(/\x1B+(?=\[)/g,"\x1B")
      .replace(/(\x1B\[[0-?]*[ -/]*[@-~])(?:\[[0-?]*[ -/]*[@-~])+/g,"$1");
  }
  function stripAnsi(value){
    return normalizeTerminalText(value)
      // Consume CSI sequences before generic two-byte ESC commands. The old
      // alternation matched only ESC[ and leaked the remaining SGR payload
      // (for example, ESC[0m became a visible "0m").
      .replace(/\x1B\[[0-?]*[ -/]*[@-~]/g,"")
      .replace(/\x9B[0-?]*[ -/]*[@-~]/g,"")
      .replace(/\u241B\[[0-?]*[ -/]*[@-~]/g,"")
      .replace(/\x1B[@-_]/g,"")
      .replace(/\x1B/g,"");
  }
  function ansi256Color(index){
    const n=Math.max(0,Math.min(255,Number(index)||0));
    if(n<16){
      const map=["#000000","#800000","#008000","#808000","#000080","#800080","#008080","#c0c0c0","#808080","#ff0000","#00ff00","#ffff00","#0000ff","#ff00ff","#00ffff","#ffffff"];
      return map[n];
    }
    if(n>=232){const level=8+(n-232)*10;return `rgb(${level},${level},${level})`;}
    const offset=n-16,r=Math.floor(offset/36),g=Math.floor((offset%36)/6),b=offset%6,levels=[0,95,135,175,215,255];
    return `rgb(${levels[r]},${levels[g]},${levels[b]})`;
  }
  function defaultAnsiState(){return {fgName:"",fgCss:"",bgName:"",bgCss:"",bold:false,dim:false,underline:false,inverse:false};}
  function applySgr(state,rawParams){
    const params=(rawParams===""?[0]:rawParams.split(/[;:]/).map(value=>value===""?0:Number(value))).filter(Number.isFinite);
    for(let index=0;index<params.length;index++){
      const code=params[index];
      if(code===0){Object.assign(state,defaultAnsiState());continue;}
      if(code===1){state.bold=true;continue;}if(code===2){state.dim=true;continue;}if(code===4){state.underline=true;continue;}if(code===7){state.inverse=true;continue;}
      if(code===22){state.bold=false;state.dim=false;continue;}if(code===24){state.underline=false;continue;}if(code===27){state.inverse=false;continue;}
      if(code===39){state.fgName="";state.fgCss="";continue;}if(code===49){state.bgName="";state.bgCss="";continue;}
      if(BASIC_COLORS[code]){[state.fgName,state.fgCss]=BASIC_COLORS[code];continue;}
      if(BG_TO_FG[code]){[state.bgName,state.bgCss]=BASIC_COLORS[BG_TO_FG[code]];continue;}
      if(code===38||code===48){
        const target=code===38?"fg":"bg",mode=params[index+1];
        if(mode===2&&params.length>=index+5){
          const rgb=params.slice(index+2,index+5).map(value=>Math.max(0,Math.min(255,value)));
          state[`${target}Name`]="truecolor";state[`${target}Css`]=`rgb(${rgb.join(",")})`;index+=4;continue;
        }
        if(mode===5&&params.length>=index+3){state[`${target}Name`]="indexed";state[`${target}Css`]=ansi256Color(params[index+2]);index+=2;continue;}
      }
    }
  }
  function ansiSegments(value){
    const text=normalizeTerminalText(value),segments=[],state=defaultAnsiState();let cursor=0;
    const pattern=/\x1B\[([0-?]*)([ -/]*)([@-~])/g;let match;
    const push=end=>{if(end<=cursor)return;const part=text.slice(cursor,end);if(!part)return;let fgName=state.fgName,fgCss=state.fgCss,bgName=state.bgName,bgCss=state.bgCss;if(state.inverse){[fgName,bgName]=[bgName,fgName];[fgCss,bgCss]=[bgCss,fgCss];}segments.push({text:part,fgName,fgCss,bgName,bgCss,bold:state.bold,dim:state.dim,underline:state.underline});};
    while((match=pattern.exec(text))){push(match.index);cursor=pattern.lastIndex;if(match[3]==="m")applySgr(state,match[1]);}
    push(text.length);
    if(!segments.length){
      const visible=stripAnsi(text);
      if(visible)segments.push({text:visible,fgName:"",fgCss:"",bgName:"",bgCss:"",bold:false,dim:false,underline:false});
    }
    return segments;
  }
  function ansiLineMetadata(value){
    const signals=new Set(),signalCharacters={};let visibleCharacters=0;
    ansiSegments(value).forEach(segment=>{
      if(!segment.text||!segment.text.trim())return;const characters=segment.text.replace(/\s+/g,"").length;visibleCharacters+=characters;
      const fg=segment.fgName,bg=segment.bgName,red=fg==="red"||fg==="bright-red",yellowBg=bg==="yellow"||bg==="bright-yellow";
      const add=signal=>{signals.add(signal);signalCharacters[signal]=(signalCharacters[signal]||0)+characters;};
      if(red&&yellowBg)add("red-yellow");else if(red)add("red");
      if(fg==="bright-cyan")add("light-cyan");
      if(fg==="blue"||fg==="bright-blue")add("blue");
      if(fg==="green"||fg==="bright-green")add("green");
      if(fg==="bright-magenta")add("light-magenta");
    });
    const ordered=EMPHASIS_ORDER.filter(value=>signals.has(value)),primary=ordered[0]||"",coverage=primary&&visibleCharacters?Math.min(1,(signalCharacters[primary]||0)/visibleCharacters):0,reviewWorthy=primary==="red-yellow"||(primary==="red"&&coverage>=0.45);
    return {primary,signals:ordered,rank:primary?(EMPHASIS_RANK[primary]??9):9,label:primary?EMPHASIS_LABELS[primary]:"",coverage,reviewWorthy};
  }
  function detectTool(text,filename=""){
    const sample=`${filename}\n${String(text||"").slice(0,12000)}`.toLowerCase();
    if(/winpeas|windows privilege escalation awesome script/.test(sample))return "winpeas";
    if(/linpeas|linux privilege escalation awesome script/.test(sample))return "linpeas";
    if(/\\windows\\|hklm\\|whoami \/priv|seimpersonateprivilege/.test(sample))return "winpeas";
    if(/\/etc\/(?:passwd|shadow)|sudo -l|\buid=\d+\b|\bgetcap\b/.test(sample))return "linpeas";
    return "unknown";
  }
  function platformForTool(tool){return tool==="winpeas"?"windows":tool==="linpeas"?"linux":"unknown";}
  function detectExecutionIdentity(value,{tool="unknown"}={}){
    const text=stripAnsi(value),resolvedTool=tool&&tool!=="auto"?tool:detectTool(text),platform=platformForTool(resolvedTool);
    if(platform==="linux"){
      const match=text.match(/\buid=(\d+)\(([^)\r\n]+)\)/i);
      if(!match)return null;
      const principal=clean(match[2]);if(!principal)return null;
      const ssh=/^(?:SSH_CLIENT|SSH_CONNECTION|SSH_TTY)=/m.test(text);
      return {principal,privilege:match[1]==="0"?"root-admin":"user",method:ssh?"SSH":"Shell",platform,confidence:"high",evidence:clean(match[0])};
    }
    if(platform==="windows"){
      const patterns=[
        /^(?:Current User|Current user|User Name|Username)\s*[:=]\s*([^\r\n]+)/mi,
        /^(?:USERDOMAIN)\s*=\s*([^\r\n]+)[\s\S]{0,800}?^(?:USERNAME)\s*=\s*([^\r\n]+)/mi,
        /\b(NT AUTHORITY\\SYSTEM)\b/i
      ];
      let principal="",evidence="";
      const direct=text.match(patterns[0]);
      if(direct){principal=clean(direct[1]).replace(/^[-\s]+|[-\s]+$/g,"");evidence=clean(direct[0]);}
      if(!principal){const env=text.match(patterns[1]);if(env){principal=`${clean(env[1])}\\${clean(env[2])}`;evidence=clean(env[0]);}}
      if(!principal){const system=text.match(patterns[2]);if(system){principal=system[1];evidence=system[0];}}
      if(!principal)return null;
      const elevated=/^(?:NT AUTHORITY\\SYSTEM|SYSTEM|Administrator)$/i.test(principal)||/\\Administrator$/i.test(principal),rdp=/SESSIONNAME\s*=\s*RDP/i.test(text);
      return {principal,privilege:elevated?"root-admin":"user",method:rdp?"RDP":"Shell",platform,confidence:"medium",evidence};
    }
    return null;
  }
  function normalizeHeader(line){
    let value=stripAnsi(line).trim();
    if(!value||value.length>180)return "";
    const markerCount=(value.match(/╣/gu)||[]).length;if(markerCount>1)value=value.slice(value.lastIndexOf("╣")+1);
    value=value.replace(/^[\s╔╗╚╝╠╣╦╩╬═─━#*+\-=_.:|\[\]]+/u,"").replace(/[\s╔╗╚╝╠╣╦╩╬═─━#*+\-=_.:|\[\]]+$/u,"").replace(/\s+/g," ").trim();
    if(!value||value.length<3||BANNER_RE.test(value))return "";
    return value;
  }
  function isHeaderLine(line){
    const raw=String(line||""),title=normalizeHeader(raw);if(!title)return false;
    if(/[╔╠╚═]{2,}|^[#=*+\-]{2,}\s*\S|\S\s*[#=*+\-]{2,}$/u.test(raw.trim()))return true;
    if(raw.trim().endsWith(":" )&&title.split(/\s+/).length<=10)return true;
    return false;
  }
  function categoryFor(text,platform="unknown"){
    const source=clean(text);if(!source)return "other";
    const rules=platform==="windows"?WINDOWS_CATEGORIES:LINUX_CATEGORIES;
    return rules.find(([,pattern])=>pattern.test(source))?.[0]||"other";
  }
  function normalizeEvidence(value){return stripAnsi(value).toLowerCase().replace(/\b(?:https?:\/\/)?[a-f0-9]{32,64}\b/g,"<hash>").replace(/\s+/g," ").replace(/[|*_`]+/g,"").trim();}
  function findingKey(finding,{accessContextId=""}={}){return [clean(accessContextId).toLowerCase(),clean(finding.category).toLowerCase(),normalizeEvidence(finding.groupTitle),normalizeEvidence(finding.parentTitle),normalizeEvidence(finding.sectionTitle),normalizeEvidence(finding.sourceLine||finding.evidence)].join("::");}
  function extractReferenceLinks(value){
    const matches=String(value||"").match(/https?:\/\/[^\s<>"']+/gi)||[];
    return unique(matches.map(url=>url.replace(/[),.;:]+$/g,"")));
  }
  function evidenceWithoutReferenceLinks(value){
    return clean(String(value||"").replace(/https?:\/\/[^\s<>"']+/gi,"").replace(/^[\s╚└═─—|:;-]+/u,"").replace(/[\s|:;-]+$/u,"").replace(/\s{2,}/g," "));
  }
  function isReferenceOnlyLine(line){
    const value=clean(stripAnsi(line)),links=extractReferenceLinks(value);
    return Boolean(links.length&&!evidenceWithoutReferenceLinks(value));
  }
  function isSectionAnnotationLine(line){
    const value=clean(stripAnsi(line));
    return /^╚(?:\s|$)/u.test(value)||isReferenceOnlyLine(value);
  }
  function isNoiseLine(line){const value=clean(line);return NOISE_RE.some(pattern=>pattern.test(value));}
  function meaningfulLine(line){
    const value=clean(line);if(value.length<4||BANNER_RE.test(value)||isHeaderLine(value)||isSectionAnnotationLine(value)||isNoiseLine(value))return false;
    if(/(?:^|\/)linpeas(?:_host_checker_[^/\s]+|\.(?:sh|txt|log|out|ansi))\b/i.test(value))return false;
    if(/^\/var\/log\/(?:bootstrap|dpkg)\.log:.*\b(?:base-passwd|passwd)(?::amd64)?\b/i.test(value))return false;
    if(/\?\s*\.?$/u.test(value)&&!/[=:]\s*\S+/.test(value))return false;
    if(/^(?:true|false|yes|no|none|unknown|n\/a)$/i.test(value))return false;
    if(/^(?:https?:\/\/github\.com\/carlospolop|linpeas|winpeas)\b/i.test(value))return false;
    return /[A-Za-z0-9]/.test(value);
  }
  function classifyLine(line,category){
    const value=clean(line);
    if(NEGATIVE_RE.test(value)||STRUCTURED_NEGATIVE_RE.test(value)||/\b(?:writable|vulnerable|readable|present)\s+(?:no|not found)\s*$/i.test(value))return {state:"observed",reason:"Negative or non-applicable output retained as an observation.",negative:true};
    if(category==="writable-paths"&&/^\/(?:tmp|var\/tmp|run\/lock|home\/[^/\s]+)\/?$/i.test(value))return {state:"observed",reason:"Common writable location retained as baseline context."};
    const matched=POTENTIAL_PATTERNS.find(([,pattern])=>pattern.test(value));
    if(matched)return {state:"potential-lead",reason:matched[0]};
    if(PATH_RE.test(value)&&["sudo","suid","sgid","capabilities","writable-paths"].includes(category))return {state:"potential-lead",reason:"Concrete path or executable retained for applicability review."};
    return {state:"observed",reason:"Informational evidence; no exploitability claim was made."};
  }
  function isOpeningBoxBorder(line){
    return /^╔═+╗$/u.test(String(line||"").trim());
  }
  function isClosingBoxBorder(line){
    return /^╚═+╝$/u.test(String(line||"").trim());
  }
  function isMajorCategoryHeader(line){
    return /^═{8,}╣\s*\S(?:.*?\S)?\s*╠═{8,}$/u.test(stripAnsi(line).trim());
  }
  function sectionHasContent(section){
    return (section?.lines||[]).some(line=>{
      const value=String(line||"").trim();
      return Boolean(value)&&!isOpeningBoxBorder(value)&&!isClosingBoxBorder(value);
    });
  }
  function isPrimarySectionHeader(line){return /^╔/u.test(stripAnsi(line).trim())&&isHeaderLine(line);}
  function isNestedSectionHeader(line){return /^══+╣/u.test(stripAnsi(line).trim())&&isHeaderLine(line);}
  function primaryHeaderHasNestedChildren(lines,index){
    for(let cursor=index+1;cursor<lines.length;cursor++){
      const candidate=lines[cursor];
      if(isMajorCategoryHeader(candidate)||isPrimarySectionHeader(candidate))return false;
      if(isNestedSectionHeader(candidate))return true;
    }
    return false;
  }
  function parseSections(lines,platform){
    const sections=[];let activeGroup="",activeParent="",skipGroupClosing=false;
    const makeSection=(title="General Output",headerLineNumber=0,parentTitle=activeParent)=>{
      const ownCategory=categoryFor(title,platform),parentCategory=categoryFor(parentTitle,platform);
      return {title,groupTitle:activeGroup,parentTitle:parentTitle||"",category:ownCategory!=="other"?ownCategory:parentCategory,headerLineNumber,lines:[],lineNumbers:[]};
    };
    let current=makeSection();
    const push=()=>{
      if(!sectionHasContent(current))return;
      current.lineStart=current.lineNumbers[0]||current.headerLineNumber||1;current.lineEnd=current.lineNumbers.at(-1)||current.lineStart;current.id=`section-${sections.length+1}-${slug([current.parentTitle,current.title].filter(Boolean).join("-"))}`;current.lineCount=current.lines.length;sections.push(current);
    };
    lines.forEach((line,index)=>{
      if(isMajorCategoryHeader(line)){
        if(isOpeningBoxBorder(current.lines.at(-1))){current.lines.pop();current.lineNumbers.pop();}
        push();activeGroup=normalizeHeader(line);activeParent="";current=makeSection("Overview",index+1,"");skipGroupClosing=true;return;
      }
      if(skipGroupClosing&&isClosingBoxBorder(line)){skipGroupClosing=false;return;}
      if(isPrimarySectionHeader(line)&&primaryHeaderHasNestedChildren(lines,index)){
        push();activeParent=normalizeHeader(line);current=makeSection("Overview",index+1,activeParent);return;
      }
      if(isHeaderLine(line)){
        const nested=isNestedSectionHeader(line),title=normalizeHeader(line),openingLine=isOpeningBoxBorder(current.lines.at(-1))?current.lines.pop():"",openingLineNumber=openingLine?current.lineNumbers.pop():0;
        push();
        if(isPrimarySectionHeader(line))activeParent="";
        current=makeSection(title,index+1,nested?activeParent:"");
        if(openingLine){current.lines.push(openingLine);current.lineNumbers.push(openingLineNumber);}
        current.lines.push(line);current.lineNumbers.push(index+1);return;
      }
      current.lines.push(line);current.lineNumbers.push(index+1);
    });
    push();
    if(!sections.length){current=makeSection();current.lines=lines.slice();current.lineNumbers=lines.map((_,index)=>index+1);push();}
    return sections;
  }
  function parseStructuredOutput(value,{filename="",tool=""}={}){
    const rawText=normalizeTerminalText(value),cleanText=stripAnsi(rawText),resolvedTool=tool&&tool!=="auto"?tool:detectTool(cleanText,filename),platform=platformForTool(resolvedTool),rawLines=rawText.split("\n"),lines=cleanText.split("\n"),sections=parseSections(lines,platform);
    return {tool:resolvedTool,platform,filename:clean(filename),rawText,cleanText,lines:rawLines.length,sections:sections.map(section=>({
      id:section.id,title:section.title,groupTitle:section.groupTitle||"",parentTitle:section.parentTitle||"",category:section.category,headerLineNumber:section.headerLineNumber,headerRaw:section.headerLineNumber?rawLines[section.headerLineNumber-1]||"":"",lineStart:section.lineStart,lineEnd:section.lineEnd,lineCount:section.lineCount,
      lines:section.lines.map((text,index)=>{const lineNumber=section.lineNumbers[index]||section.lineStart+index,raw=rawLines[lineNumber-1]??text;return {lineNumber,text,raw,emphasis:resolvedTool==="linpeas"?ansiLineMetadata(raw):{primary:"",signals:[],rank:9,label:""}};})
    }))};
  }
  function parsePeasOutput(value,{filename="",tool=""}={}){
    const structured=parseStructuredOutput(value,{filename,tool}),{cleanText,tool:resolvedTool,platform}=structured,findings=[];
    structured.sections.forEach(section=>{
      const sectionLinks=unique((section.lines||[]).flatMap(line=>extractReferenceLinks(line.text)));
      section.lines.forEach(line=>{
        if(!meaningfulLine(line.text))return;
        const category=section.category!=="other"?section.category:categoryFor(line.text,platform);
        if(category==="other"&&!POTENTIAL_PATTERNS.some(([,pattern])=>pattern.test(line.text)))return;
        const classification=classifyLine(line.text,category),sourceLine=clean(line.text),linpeasEmphasis=resolvedTool==="linpeas"&&line.emphasis?.primary?line.emphasis:null,sourceLinks=unique([...sectionLinks,...extractReferenceLinks(sourceLine)]);
        findings.push({category,sectionId:section.id,sectionTitle:section.title,parentTitle:section.parentTitle||"",groupTitle:section.groupTitle||"",lineNumber:line.lineNumber,sourceLine,evidence:evidenceWithoutReferenceLinks(sourceLine)||sourceLine,sourceLinks,autoState:classification.state,state:classification.state,reason:classification.reason,negative:classification.negative===true,path:(sourceLine.match(PATH_RE)||[])[1]||"",linpeasEmphasis});
      });
    });
    const byKey=new Map(),deduped=[];
    findings.forEach(item=>{
      const key=[item.category,normalizeEvidence(item.groupTitle),normalizeEvidence(item.parentTitle),normalizeEvidence(item.sectionTitle),normalizeEvidence(item.sourceLine)].join("::"),prior=byKey.get(key);
      if(!prior){const stored={...item,key};byKey.set(key,stored);deduped.push(stored);return;}
      if((item.linpeasEmphasis?.rank??9)<(prior.linpeasEmphasis?.rank??9))prior.linpeasEmphasis=item.linpeasEmphasis;
      prior.sourceLinks=unique([...(prior.sourceLinks||[]),...(item.sourceLinks||[])]);
    });
    const categoryCounts={},emphasisCounts={};deduped.forEach(row=>{categoryCounts[row.category]=(categoryCounts[row.category]||0)+1;(row.linpeasEmphasis?.signals||[]).forEach(signal=>{emphasisCounts[signal]=(emphasisCounts[signal]||0)+1;});});
    return {schemaVersion:VERSION,tool:resolvedTool,platform,filename:clean(filename),cleanText,identity:detectExecutionIdentity(cleanText,{tool:resolvedTool}),sections:structured.sections.map(section=>({id:section.id,title:section.title,groupTitle:section.groupTitle||"",parentTitle:section.parentTitle||"",category:section.category,lineStart:section.lineStart,lineEnd:section.lineEnd,lineCount:section.lineCount})),findings:deduped,stats:{lines:structured.lines,sections:structured.sections.length,findings:deduped.length,potential:deduped.filter(row=>row.state==="potential-lead").length,observed:deduped.filter(row=>row.state==="observed").length,categoryCounts,emphasisCounts}};
  }
  function mergeFinding(existing,incoming,{source={}}={}){
    const prior=existing&&typeof existing==="object"?existing:null,sourceRow={importId:clean(source.importId),filename:clean(source.filename),revision:Number(source.revision)||1,sha256:clean(source.sha256),observedAt:clean(source.observedAt)};
    if(!prior)return {...incoming,id:incoming.id||`peas-finding-${Math.random().toString(16).slice(2)}`,sources:[sourceRow],observations:1,active:true,createdAt:sourceRow.observedAt||new Date().toISOString(),updatedAt:sourceRow.observedAt||new Date().toISOString()};
    const sources=Array.isArray(prior.sources)?prior.sources.slice():[];
    if(!sources.some(row=>row.importId===sourceRow.importId&&row.revision===sourceRow.revision&&row.sha256===sourceRow.sha256))sources.push(sourceRow);
    const manual=STATE_ORDER.indexOf(prior.state)>STATE_ORDER.indexOf("potential-lead")||prior.state==="dismissed";
    return {...prior,...incoming,id:prior.id,state:manual?prior.state:incoming.state,autoState:incoming.autoState,sources,observations:Math.max(Number(prior.observations)||1,sources.length),active:true,updatedAt:sourceRow.observedAt||new Date().toISOString()};
  }
  function importLogicalKey({tool="unknown",accessContextId=""}={}){return `peas:${clean(accessContextId).toLowerCase()||"unscoped"}:${clean(tool).toLowerCase()||"unknown"}`;}
  return {VERSION,STATE_ORDER,EMPHASIS_ORDER,EMPHASIS_LABELS,EMPHASIS_RANK,normalizeTerminalText,stripAnsi,ansiSegments,ansiLineMetadata,detectTool,platformForTool,detectExecutionIdentity,normalizeHeader,isHeaderLine,isOpeningBoxBorder,isClosingBoxBorder,isMajorCategoryHeader,isPrimarySectionHeader,isNestedSectionHeader,isReferenceOnlyLine,isSectionAnnotationLine,isNoiseLine,categoryFor,normalizeEvidence,extractReferenceLinks,evidenceWithoutReferenceLinks,findingKey,classifyLine,parseStructuredOutput,parsePeasOutput,mergeFinding,importLogicalKey};
});
