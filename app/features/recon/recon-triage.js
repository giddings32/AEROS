(function(root,factory){
  const api=factory();
  if(typeof module==="object"&&module.exports)module.exports=api;
  if(root)root.AEROSReconTriage=api;
})(typeof window!=="undefined"?window:globalThis,function(){
  'use strict';

  const BACKTICK_RE=/`([^`\n]+)`/g;
  const MAX_TICK_LENGTH=220;

  function norm(value){return String(value??'');}
  function stripTicks(value){return norm(value).replace(/`/g,'');}

  /* --------------------------------------------------------------------
     Safe highlighting.

     String.prototype.replace with a *string* replacement expands `$&`,
     "$`", `$'` and `$n`. Scanner output legitimately contains those
     sequences (URLs, headers, PHP paths, jQuery bundles), so using a
     string replacement silently rewrites the operator's evidence.

     Every highlight is therefore expressed as a [start,end) range over
     the original line and spliced in a single left-to-right pass. This
     also removes the "first occurrence anywhere on the line" hazard the
     token-by-token replace approach had.
     -------------------------------------------------------------------- */
  function tickRanges(line,ranges){
    const src=norm(line);
    const valid=(ranges||[])
      .filter(r=>Array.isArray(r)&&Number.isFinite(r[0])&&Number.isFinite(r[1])&&r[0]>=0&&r[1]>r[0]&&r[1]<=src.length)
      .sort((a,b)=>a[0]-b[0]||b[1]-a[1]);
    let out='',prev=0,last=0,started=false;
    for(const [s,e] of valid){
      if(started&&s<last)continue;                       // overlapping: first wins
      const value=src.slice(s,e);
      if(!value.trim()||value.includes('`')||value.length>MAX_TICK_LENGTH)continue;
      out+=src.slice(prev,s)+'`'+value+'`';
      prev=e;last=e;started=true;
    }
    return out+src.slice(prev);
  }

  // Each token is searched *after* the previous one, so a service name that
  // also occurs inside the version string cannot steal the earlier match.
  // A token may be {value,skip:true} to advance the cursor without being
  // highlighted — used for uncertain values that must stay normal context.
  function orderedRanges(line,tokens,from=0){
    const out=[];let cursor=Math.max(0,from);
    for(const token of tokens){
      const spec=(token&&typeof token==='object')?token:{value:token,skip:false};
      const value=norm(spec.value);
      if(!value)continue;
      const i=line.indexOf(value,cursor);
      if(i<0)continue;
      cursor=i+value.length;
      if(spec.skip)continue;
      out.push([i,i+value.length]);
    }
    return out;
  }
  // Nmap marks an unconfirmed service identification with a trailing "?".
  // Glow means "high-signal / actionable", so a guess stays normal context.
  function isUncertainService(value){return /\?\s*$/.test(norm(value));}

  // Range of capture group 1, derived from the match position rather than a
  // second search, then trimmed of surrounding whitespace.
  function groupRange(line,re,group=1){
    const m=line.match(re);
    if(!m||m[group]==null||m.index==null)return null;
    const raw=m[group];
    if(!raw)return null;
    const tail=m[0].lastIndexOf(raw);
    if(tail<0)return null;
    let start=m.index+tail,end=start+raw.length;
    while(start<end&&/\s/.test(line[start]))start++;
    while(end>start&&/\s/.test(line[end-1]))end--;
    return end>start?[start,end]:null;
  }

  // Upper-case tokens inside a comma/space separated list (HTTP methods, CORS).
  function listRanges(line,re){
    const span=groupRange(line,re);
    if(!span)return [];
    const [start,end]=span,list=line.slice(start,end),out=[];
    const tokenRe=/[A-Za-z][A-Za-z0-9_-]{1,15}/g;
    let m;
    while((m=tokenRe.exec(list))){
      const t=m[0];
      if(/^(?:and|or)$/i.test(t))continue;
      if(!/^[A-Z][A-Z0-9_-]*$/.test(t))continue;
      out.push([start+m.index,start+m.index+t.length]);
    }
    return out;
  }

  function identifierRanges(line){
    const out=[];
    for(const source of [/\bCVE-\d{4}-\d{4,}\b/gi,/\bEDB-ID:?\s*\d+\b/gi]){
      const re=new RegExp(source.source,source.flags);
      let m;
      while((m=re.exec(line))){
        out.push([m.index,m.index+m[0].length]);
        if(m.index===re.lastIndex)re.lastIndex++;
      }
    }
    return out;
  }

  /* ---- tool detection ------------------------------------------------- */
  function toolName(meta={}){return norm(meta.tool||meta.classification?.tool||meta.path||'');}
  function fileName(meta={}){const p=norm(meta.path).replace(/\\/g,'/');return p.split('/').pop()||'';}
  function matches(meta,re){return re.test(toolName(meta))||re.test(fileName(meta));}
  function isNmap(meta={}){return matches(meta,/nmap/i);}
  function isXml(meta={}){return /\.xml$/i.test(fileName(meta));}
  function isFerox(meta={}){return matches(meta,/ferox/i);}
  function isWhatWeb(meta={}){return matches(meta,/whatweb/i);}
  function isNikto(meta={}){return matches(meta,/nikto/i);}
  function isWebDiscovery(meta={}){return /ferox|ffuf|gobuster|dirsearch|dirbuster|\bdirb\b|directory busting/i.test(toolName(meta))||/ferox|ffuf|gobuster|dirsearch|dirbuster|\bdirb\b/i.test(fileName(meta));}
  function isCurl(meta={}){return matches(meta,/curl|robots|security\.txt/i);}

  /* ---- dim / normal classification ------------------------------------ */
  function classifyLine(line,meta={}){
    const text=stripTicks(line).trim();
    if(!text)return 'normal';

    if(isNmap(meta)){
      if(isXml(meta)){
        if(/^<\?xml|^<!DOCTYPE|^<\?xml-stylesheet|^<!--\s*Nmap|^<\/?nmaprun\b|^<\/?verbose\b|^<\/?debugging\b|^<\/?task(?:begin|end|progress)\b|^<\/?runstats\b|^<\/?finished\b|^<\/?hosts\b|^<\/?times\b|^<\/?tcpsequence\b|^<\/?ipidsequence\b|^<\/?tcptssequence\b|^<osfingerprint\b/i.test(text))return 'noise';
        if(/^<\/?ports>|^<\/?os>|^<\/?trace>|^<\/?host(?:\s|>)/i.test(text))return 'noise';
        return 'normal';
      }
      if(/^#\s*Nmap\b/i.test(text))return 'noise';
      if(/^adjust_timeouts2:/i.test(text))return 'noise';
      if(/^SF:/i.test(text)||/^OS:/i.test(text))return 'noise';
      if(/^Read data files from:/i.test(text))return 'noise';
      if(/^OS and Service detection performed\./i.test(text))return 'noise';
      if(/^Please report any incorrect results/i.test(text))return 'noise';
      if(/^#?\s*Nmap done at\b/i.test(text))return 'noise';
      if(/^Not shown:\s+\d+\s+(?:closed|filtered)/i.test(text))return 'noise';
      if(/^\|[_ ]?(?:ssh-rsa|ecdsa-sha2|ssh-ed25519)\s+[A-Za-z0-9+/=]{36,}/i.test(text))return 'noise';
      if(/^1 service unrecognized despite returning data\./i.test(text))return 'noise';
      if(/^\|\s+(?:Date|Connection|content-length):/i.test(text))return 'noise';
      if(/^\|\s+text is empty \(possibly HTTP\/0\.9\)/i.test(text))return 'noise';
    }

    if(isFerox(meta)){
      if(/^[_|╭╰├└─┬┴┼]+$/.test(text)||/^by Ben\b/i.test(text)||/^ver:\s*\d/i.test(text))return 'noise';
      if(/^\[[#=> -]+\]\s+-\s+\d/i.test(text))return 'noise';
      if(/^Configuration\s*\{$/i.test(text)||/^\}$/.test(text))return 'noise';
      if(/^[-\[\],0-9 ]+$/.test(text))return 'noise';
      if(/^[A-Za-z_][A-Za-z0-9_]*:\s*/.test(text) && !/^(?:target_url|wordlist|extensions|methods|depth|scan_limit|rate_limit|timeout):/i.test(text))return 'noise';
    }

    // Banner, separator and progress chrome shared by the other content
    // discovery tools AutoRecon can invoke. Result lines are never matched here.
    if(isWebDiscovery(meta)){
      if(/^[=*_-]{4,}$/.test(text))return 'noise';                                  // separators
      if(/^(?:Gobuster|DIRB|dirsearch|ffuf|feroxbuster)\s+v?[\d.]/i.test(text))return 'noise';
      if(/^by (?:OJ Reeves|The Dark Raver|Ben)\b/i.test(text)||/^By The Dark Raver/i.test(text))return 'noise';
      if(/^(?:Starting|Finished|Ending|Task Completed)\b/i.test(text))return 'noise';
      if(/^(?:::\s*)?Progress:/i.test(text))return 'noise';
      if(/^GENERATED WORDS:|^DOWNLOADED:|^Wordlist size:|^Output File:|^Error Log:/i.test(text))return 'noise';
      if(/^::\s*(?:Method|Wordlist|Follow redirects|Calibration|Timeout|Threads|Matcher|Filter|Header|Data|Extensions)\b/i.test(text))return 'noise';
      if(/^:{2,}\s*$/.test(text))return 'noise';
      if(/^[\\/|_'`.:v\s]+$/.test(text)&&/[\\/|_]/.test(text))return 'noise';        // ffuf ascii banner
      if(/^\[\+\]\s*(?:Threads|Wordlist|Status codes|User Agent|Timeout|Extensions|Negative Status codes|Expanded|No status|Verbose|Add Slash|Follow Redirect)\b/i.test(text))return 'noise';
    }

    if(/^\s*(?:DEBUG|TRACE)\b/i.test(text))return 'noise';
    return 'normal';
  }

  /* ---- per-tool highlight ranges -------------------------------------- */
  function nmapRanges(line){
    const svc=line.match(/^(\s*)(\d+\/(?:tcp|udp))\s+(open(?:\|filtered)?)\s+(\S+)(?:\s+(.*))?$/i);
    if(svc&&svc[3].toLowerCase()==='open'){
      const rest=svc[5]||'';
      const product=rest.replace(/^(?:syn-ack|udp-response)(?:\s+ttl\s+\d+)?\s*/i,'').trim();
      return orderedRanges(line,[
        svc[2],
        svc[3],
        {value:svc[4],skip:isUncertainService(svc[4])},
        product
      ],svc[1].length);
    }
    const out=[];
    const push=r=>{if(r)out.push(r);};
    push(groupRange(line,/(?:^|[|_ ]+)Server:\s*(.+)$/i));
    push(groupRange(line,/http-title:\s*(.+)$/i));
    push(groupRange(line,/Requested resource was\s+(.+)$/i));
    out.push(...listRanges(line,/Supported Methods:\s*(.+)$/i));
    out.push(...listRanges(line,/Access-Control-Allow-Methods:\s*(.+)$/i));
    push(groupRange(line,/Access-Control-Allow-Origin:\s*(.+)$/i));
    push(groupRange(line,/Unknown favicon MD5:\s*([A-Fa-f0-9]{16,})/));
    if(/Service Info:\s*OS:/i.test(line)){
      push(groupRange(line,/OS:\s*([^;]+);/i));
      push(groupRange(line,/CPE:\s*(\S+)/i));
    }else{
      push(groupRange(line,/\bCPE:\s*(cpe:\/\S+)/i));
    }
    out.push(...identifierRanges(line));
    return out;
  }

  const WEB_STATIC_RE=/\.(?:css|js|mjs|ico|svg|png|jpe?g|gif|webp|woff2?|ttf|otf|map)(?:[?#]|$)/i;
  const IMPORTANT_ENDPOINT_RE=/^(?:admin(?:istrators?)?|login|dologin|signin|auth(?:entication|orization)?|password|forgot(?:user)?password|reset|signup|register|setup|install|config(?:uration)?|server[-_]?(?:info|status)|debug|console|dashboard|manage(?:r|ment)?|webdav)(?:[._-]|$)/i;
  const USEFUL_ENDPOINT_RE=/^(?:api|upload|backups?|search|opensearch|users?|accounts?|internal|private|secrets?)(?:[._-]|$)/i;
  const MEDIUM_ENDPOINT_RE=/^(?:activity|status)(?:[._-]|$)/i;
  const FEROX_ROW_RE=/^(\s*)([1-5]\d\d)\s+(?:GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH|TRACE|CONNECT)\s+\d+l\s+\d+w\s+\d+c\s+(https?:\/\/[^\s"'<>\x60]+|\/[^\s"'<>\x60]+)/i;

  function webPath(target){
    const offset=(target.match(/^https?:\/\/[^/?#]+/i)||[''])[0].length;
    const path=target.slice(offset).split(/[?#]/,1)[0];
    return {offset,path,leaf:path.replace(/\/$/,'').split('/').pop()||''};
  }
  function endpointRanges(target,start=0,repeated=new Set()){
    if(WEB_STATIC_RE.test(target))return [];
    const {offset,path,leaf}=webPath(target),parts=path.split('/').filter(Boolean);
    const priority=parts.some(part=>IMPORTANT_ENDPOINT_RE.test(part))?'high':
      parts.some(part=>USEFUL_ENDPOINT_RE.test(part)||MEDIUM_ENDPOINT_RE.test(part))?'medium':'';
    if(!priority||!path.startsWith('/'))return [];
    const from=repeated.has(leaf.toLowerCase())&&parts.length>1?path.lastIndexOf(leaf):0;
    return [[start+offset+from,start+offset+path.length,priority]];
  }
  function feroxRanges(line,meta={}){
    const match=line.match(FEROX_ROW_RE);if(!match)return null;
    const status=Number(match[2]),out=[];
    if([401,403,500,301,302,307,308].includes(status))
      out.push([match[1].length,match[1].length+3,'high']);
    if(status===404)return out;
    const target=match[3],start=match[0].lastIndexOf(target);
    out.push(...endpointRanges(target,start,meta.repeatedEndpoints));
    const tail=line.slice(match[0].length),redirect=tail.match(/^\s*(?:=>|->)\s*(https?:\/\/[^\s"'<>]+|\/[^\s"'<>]+)/i);
    if(redirect)out.push(...endpointRanges(redirect[1],match[0].length+redirect[0].lastIndexOf(redirect[1])));
    return out;
  }

  const WHATWEB_NOISE=/^(?:Country|IP|HTML5?|Script|HttpOnly|Cookies?|UncommonHeaders|X-Frame-Options|X-XSS-Protection|X-Content-Type-Options|Content-Security-Policy|Content-Encoding|Transfer-Encoding|Connection|Cache-Control|Date|Content-Length)$/i;
  const WHATWEB_FIELDS=/^(?:HTTPServer|Server|Title|RedirectLocation|Location|OpenSearch|Frame|PasswordField|UsernameField|Login|Authentication|Authorization|Password|X-Powered-By|PoweredBy|X-AspNet-Version)$/i;
  const WHATWEB_AUTH=/^(?:PasswordField|UsernameField|Login|Authentication|Authorization|Password)$/i;
  const SESSION_RE=/\b(?:JSESSIONID|PHPSESSID|ASP\.NET_SessionId|connect\.sid)\b/gi;

  function whatWebSection(line){
    return line.match(/^\s*\[\s+([A-Za-z][A-Za-z0-9_. +\/-]*?)\s+\]\s*$/)?.[1]||'';
  }
  function semanticContext(lines,meta={}){
    const web=norm(meta.family).toUpperCase()==='WEB'||isWhatWeb(meta);
    const whatWeb=web&&(isWhatWeb(meta)||lines.some(line=>/^\s*WhatWeb report for\s+https?:\/\//i.test(line))||
      lines.some(line=>/^\s*Summary\s*:/i.test(line))&&lines.some(line=>/^\s*(?:Status|Title)\s*:/i.test(line)||whatWebSection(line))||
      lines.some(line=>/^\s*https?:\/\/\S+\s+\[\d{3}\b[^\]]*\]\s+[A-Za-z]/.test(line))||
      lines.some(line=>/^\s*(?:[A-Za-z][\w.+-]*\[[^\]]*\](?:\s*,\s*|\s*$))+$/.test(line))||
      meta.boxId==='technologies_headers'&&lines.some(line=>whatWebSection(line))||
      lines.some(line=>whatWebSection(line))&&lines.some(line=>/^\s*(?:Version|String|Module)\s*:/i.test(line)));
    const plugins=[];let plugin='';
    const endpoints=new Map();
    for(const line of lines){
      if(/^\s*(?:WhatWeb report for|HTTP Headers:|Summary\s*:)/i.test(line))plugin='';
      const section=whatWebSection(line);if(section)plugin=section;
      plugins.push(plugin);
      const row=line.match(FEROX_ROW_RE);
      if(row&&Number(row[2])!==404&&!WEB_STATIC_RE.test(row[3])){
        const path=webPath(row[3]),key=path.leaf.toLowerCase();
        if(!endpoints.has(key))endpoints.set(key,new Set());
        endpoints.get(key).add(path.path);
      }
    }
    return {whatWeb,plugins,repeatedEndpoints:new Set([...endpoints].filter(([,paths])=>paths.size>=3).map(([key])=>key))};
  }
  function whatWebRanges(line,meta={}){
    const out=[],section=whatWebSection(line),plugin=meta.whatWebPlugin||section;
    const add=(start,end,priority='high')=>{if(end>start)out.push([start,end,priority]);};
    const paths=(target,start)=>out.push(...endpointRanges(target,start).map(([s,e])=>[s,e,'high']));
    const value=(re,priority='high')=>{const span=groupRange(line,re);if(span)add(...span,priority);};
    const sessions=(source,offset=0)=>{
      for(const match of source.matchAll(SESSION_RE))add(offset+match.index,offset+match.index+match[0].length,'low');
    };
    if(section){
      if((!WHATWEB_NOISE.test(section)&&!WHATWEB_FIELDS.test(section))||WHATWEB_AUTH.test(section))
        add(line.indexOf(section),line.indexOf(section)+section.length);
      return out;
    }
    // Plugin descriptions and vendor Website URLs are documentation, not detections.
    const resultLine=WHATWEB_NOISE.test(line.match(/^\s*([A-Za-z][\w-]*)\s*:/)?.[1]||'')||
      /^\s*(?:Summary|Status|Title|Version|String|Module|Model|Account|Hostname|Domain|Server|HTTPServer|Location|RedirectLocation|X-Powered-By|X-AspNet-Version|Set-Cookie|Cookies?|WWW-Authenticate)\s*:/i.test(line)||
      /^\s*(?:https?:\/\/|HTTP\/\S+\s+\d{3}|WhatWeb report for)/i.test(line)||
      /^\s*(?:[A-Za-z][\w.+-]*\[[^\]]*\](?:,\s*|\s*$))/.test(line);
    if(!resultLine)return out;
    value(/^\s*(?:Status\s*:\s*|HTTP\/\S+\s+)((?:301|302|307|308|401|403|500)\b(?:[ \t]+[A-Za-z][A-Za-z ]*)?)/i);
    value(/^\s*https?:\/\/\S+\s+\[((?:301|302|307|308|401|403|500)\b[^\]]*)\]/i);
    value(/^\s*(?:Server|HTTPServer|X-Powered-By|X-AspNet-Version)\s*:\s*(.+)$/i);
    value(/^\s*(?:Location|RedirectLocation)\s*:\s*(.+)$/i);
    value(/^\s*(?:Title|WWW-Authenticate)\s*:\s*(.+)$/i);
    if(plugin&&!WHATWEB_NOISE.test(plugin)){
      if(/^\s*Version\s*:/i.test(line))value(/^\s*Version\s*:\s*(.+)$/i);
      if(/^\s*(?:String|Module|Model|Account)\s*:/i.test(line)){
        if(/^(?:HTTPServer|X-Powered-By|PoweredBy|X-AspNet-Version|Title|RedirectLocation)$/i.test(plugin)||WHATWEB_AUTH.test(plugin))
          value(/^\s*[^:]+:\s*(.+)$/);
        else if(!WHATWEB_FIELDS.test(plugin)&&!/[\/]/.test(line.split(':').slice(1).join(':')))
          value(/^\s*[^:]+:\s*(.+)$/);
      }
    }
    const bracketRanges=[];
    for(const match of line.matchAll(/\b([A-Za-z][\w.+-]*)\[([^\]]*)\]/g)){
      const name=match[1],inner=match[2],start=match.index+name.length+1;
      bracketRanges.push([match.index,match.index+match[0].length]);
      if(WHATWEB_AUTH.test(name)){
        add(match.index,match.index+name.length);add(start,start+inner.length);
      }else if(/^(?:HTTPServer|Server|Title|X-Powered-By|PoweredBy|X-AspNet-Version|RedirectLocation)$/i.test(name)){
        add(start,start+inner.length);
      }else if(/^(?:OpenSearch|Frame)$/i.test(name)){
        paths(inner,start);
      }else if(!WHATWEB_NOISE.test(name)){
        add(match.index,match.index+match[0].length);
      }
      if(/^(?:Cookies?|HttpOnly)$/i.test(name))sessions(inner,start);
    }
    // Summary entries may name previously unknown products. Avoid a brand allowlist.
    const summary=line.match(/^\s*Summary\s*:\s*/i)||line.match(/^\s*https?:\/\/\S+\s+\[\d{3}[^\]]*\]\s*/i);
    if(summary){
      const tail=line.slice(summary[0].length);
      for(const match of tail.matchAll(/(?:^|,\s*)(?:probably\s+)?([A-Za-z][\w.+-]*(?:[ \t]+[A-Za-z][\w.+-]*)?)(?=\s*(?:,|$|\[))/g)){
        const name=match[1],start=summary[0].length+match.index+match[0].lastIndexOf(name);
        if(!WHATWEB_NOISE.test(name)&&!WHATWEB_FIELDS.test(name)&&!bracketRanges.some(([s,e])=>start>=s&&start<e))
          add(start,start+name.length);
      }
    }
    // Inspect detected fields, not prose. Static filenames, product spellings
    // and repeated IPv4 targets are not discovered hostnames.
    for(const match of line.matchAll(/(?:https?:\/\/[^\s"'<>\x60]+|\/[A-Za-z0-9_.~-][^\s"'<>\x60\]]*)/gi))
      paths(match[0],match.index);
    for(const match of line.matchAll(/\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}\b/gi)){
      if(WEB_STATIC_RE.test(match[0])||/\.(?:action|php|jsp|html?|aspx?|txt|xml|json)$/i.test(match[0])||/^(?:ASP\.NET|connect\.sid)$/i.test(match[0]))continue;
      add(match.index,match.index+match[0].length);
    }
    if(/^\s*(?:Set-Cookie|Cookies?|String)\s*:/i.test(line))sessions(line);
    out.push(...identifierRanges(line));
    return out;
  }

  function niktoRanges(line){
    const out=[];
    const m=line.match(/^(\s*\+\s+)(\/[^\s:]+)/);
    if(m)out.push([m[1].length,m[1].length+m[2].length]);
    out.push(...identifierRanges(line));
    return out;
  }

  /* AutoRecon's dirbuster plugin runs whichever tool is installed, so the same
     logical result arrives in five different shapes. Each is matched to a
     status plus the discovered target; the promotion rules below are shared. */
  const DISCOVERY_FORMATS=[
    // feroxbuster: "200      GET       12l   30w   280c http://host/path"
    {name:'feroxbuster', re:/^\s*(\d{3})\s+[A-Z]{3,7}\s+.*?(https?:\/\/[^\s"'<>]+)/, status:1, target:2},
    // dirb result:    "+ http://host/path (CODE:301|SIZE:313)"
    {name:'dirb',       re:/^\s*\+\s*(https?:\/\/[^\s"'<>]+)\s*\(CODE:(\d{3})/, target:1, status:2},
    // dirb directory: "==> DIRECTORY: http://host/path/"
    {name:'dirb-dir',   re:/^\s*==>\s*DIRECTORY:\s*(https?:\/\/[^\s"'<>]+)/, target:1, status:null},
    // gobuster vhost: "Found: sub.example.com (Status: 200) [Size: 1234]"
    {name:'gobuster-vhost', re:/^\s*Found:\s*(\S+)\s+\(Status:\s*(\d{3})\)/, target:1, status:2},
    // gobuster dir:   "/admin                (Status: 301) [Size: 313]"
    {name:'gobuster',   re:/^\s*(\/\S*)\s+\(Status:\s*(\d{3})\)/, target:1, status:2},
    // dirsearch:      "[12:01:33] 200 -    1KB - /admin/"
    {name:'dirsearch',  re:/^\s*\[\d{2}:\d{2}:\d{2}\]\s*(\d{3})\s*-\s*\S+\s*-\s*(https?:\/\/\S+|\/\S*)/, status:1, target:2},
    // ffuf:           "admin    [Status: 200, Size: 4096, Words: 120, ...]"
    {name:'ffuf',       re:/^\s*(\S+)\s+\[Status:\s*(\d{3})[,\]]/, target:1, status:2},
    // generic:        a leading status code followed by a URL
    {name:'generic',    re:/^\s*(\d{3})\b.*?(https?:\/\/[^\s"'<>]+)/, status:1, target:2}
  ];
  const STATIC_ASSET_RE=/\.(?:ico|svg|png|jpe?g|gif|webp|css|woff2?|ttf|otf|map)(?:[?#]|$)/i;
  const LOGIN_BASELINE_RE=/\/login\.action\?os_destination=/i;

  function discoveryRanges(line,meta={}){
    const ferox=feroxRanges(line,meta);
    if(ferox)return ferox;
    const out=[];
    for(const fmt of DISCOVERY_FORMATS){
      const m=line.match(fmt.re);
      if(!m)continue;
      const target=m[fmt.target];
      if(!target)break;
      const status=fmt.status==null?200:Number(m[fmt.status]);
      const interesting=(status>=200&&status<=399)||[401,403,405,500,501,502,503].includes(status);
      if(interesting&&!STATIC_ASSET_RE.test(target)&&!LOGIN_BASELINE_RE.test(target)&&target.length<260){
        const range=groupRange(line,fmt.re,fmt.target);
        if(range)out.push(range);
      }
      break;   // first matching format wins; never highlight the same line twice
    }
    out.push(...identifierRanges(line));
    return out;
  }

  function headerRanges(line){
    const out=[];
    if(/^\s*(?:Server|Location|Allow|WWW-Authenticate|X-Powered-By|Access-Control-Allow-Origin|Access-Control-Allow-Methods):/i.test(line)){
      const r=groupRange(line,/^\s*[^:]+:\s*(.+)$/);
      if(r)out.push(r);
    }
    out.push(...identifierRanges(line));
    return out;
  }

  function genericRanges(line){
    const out=[...identifierRanges(line)];

    const kv=groupRange(line,/^\s*(?:target|user(?:name)?|account|share|domain|workgroup|hostname|product|version|product \/ version|endpoint|state|service|service identity|operating system clue|cpe|uptime guess|network distance|observed protocol|http title|requested resource|server header|supported methods|allowed methods|cors origin|favicon md5|password|passwd|credential|token|secret|api[_ -]?key)\s*[:=]\s*(.+)$/i,1);
    if(kv)return [...out,kv];

    const svc=line.match(/^(\s*-\s+)(\d+\/(?:tcp|udp))\s+(\S+)(?:\s+—\s+(.+))?$/i);
    if(svc)return [...out,...orderedRanges(line,[
      svc[2],
      {value:svc[3],skip:isUncertainService(svc[3])||/^unknown$/i.test(svc[3])},
      svc[4]||''
    ],svc[1].length)];

    const research=groupRange(line,/^\s*-\s+Research\s+(.+?)\s+for public exploits \/ CVEs/i);
    if(research)return [...out,research];

    const endpointRe=/\d+\/(?:tcp|udp)/gi;
    let m;
    while((m=endpointRe.exec(line)))out.push([m.index,m.index+m[0].length]);
    return out;
  }

  function rangesForLine(line,meta={}){
    if(isNmap(meta))return isXml(meta)?identifierRanges(line):nmapRanges(line);
    if(isWhatWeb(meta))return whatWebRanges(line,meta);
    if(isNikto(meta))return niktoRanges(line);
    if(isWebDiscovery(meta))return discoveryRanges(line,meta);
    if(isCurl(meta))return headerRanges(line);
    return genericRanges(line);
  }

  /* ---- public API ----------------------------------------------------- */

  function signalSegments(value){
    const source=norm(value),out=[];let cursor=0,match;
    const expression=new RegExp(BACKTICK_RE.source,"g");
    while((match=expression.exec(source))){
      if(match.index>cursor)out.push({text:source.slice(cursor,match.index),signal:false});
      out.push({text:match[1],signal:true});
      cursor=match.index+match[0].length;
    }
    if(cursor<source.length)out.push({text:source.slice(cursor),signal:false});
    return out.length?out:[{text:source,signal:false}];
  }

  function rangeSegments(value,ranges=[]){
    const source=norm(value),out=[];let cursor=0;
    for(const [start,end,priority] of priorityRanges(source,ranges)){
      if(start<cursor)continue;
      if(start>cursor)out.push({text:source.slice(cursor,start),signal:false});
      out.push({text:source.slice(start,end),signal:true,...(priority?{priority}: {})});cursor=end;
    }
    if(cursor<source.length)out.push({text:source.slice(cursor),signal:false});
    return out.length?out:[{text:source,signal:false}];
  }

  // Single pass: classification and highlighting for one line.
  function triageLine(line,meta={}){
    const raw=norm(line),kind=classifyLine(raw,meta);
    const segments=kind==='noise'?[{text:raw,signal:false}]:rangeSegments(raw,rangesForLine(raw,meta));
    return {kind,raw,text:raw,segments};
  }

  function annotateLine(line,meta={}){return triageLine(line,meta).text;}

  // Returns lossless rows and retains the exact original source out-of-band.
  function triage(text,meta={}){
    const source=norm(text),lines=source.split(/\r?\n/),context=semanticContext(lines,meta);
    const rows=lines.map((line,index)=>triageLine(line,{...meta,whatWebPlugin:context.plugins[index],repeatedEndpoints:context.repeatedEndpoints}));
    Object.defineProperty(rows,"rawSource",{value:source,enumerable:false,writable:false,configurable:false});
    return rows;
  }

  function annotateText(text,meta={}){
    return triage(text,meta).map(row=>row.text).join('\n');
  }

  function stats(text,meta={}){
    const rows=triage(text,meta);
    const terms=[],seen=new Set();
    for(const row of rows){
      for(const segment of row.segments||[]){
        if(!segment.signal)continue;
        const v=norm(segment.text).trim(),k=v.toLowerCase();
        if(v&&!seen.has(k)){seen.add(k);terms.push(v);}
      }
    }
    return {lines:rows.length,noiseLines:rows.filter(r=>r.kind==='noise').length,signalTerms:terms.length,terms};
  }

  function validRanges(line,ranges=[]){
    const source=norm(line);
    return (ranges||[]).filter(range=>Array.isArray(range)&&Number.isFinite(range[0])&&Number.isFinite(range[1])&&range[0]>=0&&range[1]>range[0]&&range[1]<=source.length).sort((a,b)=>a[0]-b[0]||b[1]-a[1]);
  }
  function priorityRanges(line,ranges=[]){
    const rank=value=>({high:3,medium:2,low:1})[value]||3,accepted=[];
    for(const range of validRanges(line,ranges).sort((a,b)=>rank(b[2])-rank(a[2])||a[0]-b[0]||b[1]-a[1])){
      if(!accepted.some(([start,end])=>range[0]<end&&range[1]>start))accepted.push(range);
    }
    return accepted.sort((a,b)=>a[0]-b[0]);
  }
  function rawFromTriage(rows=[]){
    return typeof rows?.rawSource==="string"?rows.rawSource:(rows||[]).map(row=>norm(row?.raw)).join("\n");
  }
  function manualFollowUps(annotation){
    const rows=[],seen=new Set();
    for(const match of norm(annotation).matchAll(BACKTICK_RE)){
      const value=match[1].trim(),key=value.toLowerCase();
      if(!value||value.length>MAX_TICK_LENGTH||seen.has(key))continue;
      seen.add(key);rows.push(value);if(rows.length>=100)break;
    }
    return rows;
  }

  // Paste previews share the scanner rules, with additional service-specific
  // entities. These ranges never change the operator's saved source text.
  function pasteRanges(line,meta={}){
    const family=norm(meta.family).toUpperCase(),box=norm(meta.boxId),out=[];
    const add=re=>{for(const match of line.matchAll(re))out.push([match.index,match.index+match[0].length]);};
    const capture=re=>{const range=groupRange(line,re);if(range)out.push(range);};
    if(/^\s*\d+\/(?:tcp|udp)\s+(?:open|closed|filtered|unfiltered)/i.test(line))return nmapRanges(line);
    if(meta.whatWebDetected)return whatWebRanges(line,meta);
    if(family==='WEB'){
      const ferox=feroxRanges(line,meta);
      if(ferox)return ferox;
    }
    if(meta.scan)out.push(...nmapRanges(line));
    const discovery=family==='WEB'&&DISCOVERY_FORMATS.some(format=>format.re.test(line));
    if(family==='WEB'){
      out.push(...headerRanges(line));
      if(box==='directory_discovery'||box==='virtual_hosts'||box==='interesting_pages'||/\b(?:Status|Size|Words|Lines):/.test(line))out.push(...discoveryRanges(line));
      capture(/^HTTP\/\S+\s+((?:[123]\d\d|401|403)\b.*)/i);
    }
    out.push(...genericRanges(line));
    if(!discovery){add(/\b(?:https?|ftp):\/\/[^\s<>`"']+/gi);add(/(?:^|(?<=[\s("'=]))(?:\/(?!\/)[A-Za-z0-9_.~-][^\s<>`"']*|[A-Za-z]:\\[^\s<>`"']+)/g);}
    if(!discovery)add(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g);
    if(family==='SMB'){
      capture(/\buser:\[([^\]]+)\]/i);capture(/\bgroup:\[([^\]]+)\]/i);
      capture(/^\s*(\S+)\s+(?:Disk|IPC|Printer)\b/i);
      capture(/^\s*(\S+)\s+(?:READ(?:,?\s*WRITE)?|WRITE|NO ACCESS)\b/i);
      add(/\b(?:READ(?:,?\s*WRITE)?|WRITE|SMBv1|signing:(?:True|False)|Pwn3d!)\b/gi);
    }
    if(family==='SSH'){
      add(/\bSSH-\d\.\d-[^\s<>`]+/g);add(/\bSHA256:[A-Za-z0-9+/=]+/g);
      capture(/Authentications that can continue:\s*(.+)$/i);
      capture(/(?:Authentication succeeded|Authenticated to)\s*(.+)$/i);
    }
    if(family==='FTP'){
      capture(/^(?:220|230|257)\s+(.+)$/);
      capture(/^[d-][rwxstST-]{9}\s+.*?\s\d\d?:\d\d\s+(.+)$/);
    }
    if(family==='DNS'){
      const record=line.match(/^(\S+)\s+(?:\d+\s+)?(?:IN\s+)?(A|AAAA|CNAME|MX|NS|TXT|SOA|PTR|SRV)\s+(.+)$/i);
      if(record)out.push(...orderedRanges(line,[record[1],record[2],record[3]]));
    }
    if(family==='LDAP')capture(/^\s*(?:dn|namingContexts|defaultNamingContext|sAMAccountName|memberOf|userPrincipalName|description|userAccountControl|servicePrincipalName):\s*(.+)$/i);
    if(family==='SNMP')capture(/=\s*(?:STRING|OID|IpAddress|INTEGER|Timeticks):\s*(.+)$/i);
    if(family==='NFS')capture(/^\s*(\/\S+\s+.+)$/);
    if(family==='MAIL'){
      capture(/^(?:220|235|250[- ]|\+OK|\* OK|\* CAPABILITY)\s*(.+)$/i);
      capture(/\b(?:AUTH|AUTHENTICATE)\s+((?:LOGIN|PLAIN|NTLM|GSSAPI|CRAM-MD5)(?:\s+\S+)*)/i);
    }
    if(['RDP','WINRM','VNC'].includes(family)){
      capture(/(?:NetBIOS_Computer_Name|NetBIOS_Domain_Name|DNS_Computer_Name|DNS_Domain_Name|Product_Version|Security types|Protocol version):\s*(.+)$/i);
      out.push(...headerRanges(line));
    }
    if(family==='KERBEROS'){
      add(/\b[A-Za-z0-9_.-]+@[A-Za-z0-9_.-]+\b/g);add(/\$(?:krb5asrep|krb5tgs)\$[^\s`]+/g);
    }
    if(['MYSQL','MSSQL','POSTGRESQL','REDIS','MONGODB'].includes(family)){
      capture(/^\s*(?:redis_version|mysql_version|version|Database|database|datname|rolname|current_user|USER|USERNAME|schema|table|role|user|db):\s*(.+)$/i);
      capture(/^\s*(GRANT\s+.+)$/i);
    }
    return out;
  }
  function pasteTriage(source,meta={}){
    const rawSource=norm(source),lines=rawSource.split(/\r?\n/);
    const displays=lines.map(raw=>raw.replace(/\x1b\[[0-?]*[ -/]*[@-~]/g,''));
    const context=semanticContext(displays,meta);
    const rows=lines.map((raw,index)=>{
      const display=displays[index],manual=[...display.matchAll(/\x60([^\x60\r\n]+)\x60/g)].map(match=>({start:match.index,end:match.index+match[0].length,text:match[1],manual:true,priority:'high'}));
      const ranges=meta.autoHighlight===false?[]:pasteRanges(display,{...meta,whatWebDetected:context.whatWeb,whatWebPlugin:context.plugins[index],repeatedEndpoints:context.repeatedEndpoints});
      const automatic=priorityRanges(display,ranges.filter(([start,end])=>!manual.some(span=>start<span.end&&end>span.start))).map(([start,end,priority])=>({start,end,text:display.slice(start,end),priority:priority||'high',manual:false}));
      const spans=[...automatic,...manual].sort((a,b)=>a.start-b.start||b.end-a.end),segments=[];let cursor=0;
      for(const span of spans){
        if(span.start<cursor)continue;
        if(span.start>cursor)segments.push({text:display.slice(cursor,span.start),signal:false});
        segments.push({text:span.text,signal:true,priority:span.priority,manual:span.manual});cursor=span.end;
      }
      if(cursor<display.length)segments.push({text:display.slice(cursor),signal:false});
      return {raw,segments:segments.length?segments:[{text:display,signal:false}]};
    });
    Object.defineProperty(rows,'rawSource',{value:rawSource,enumerable:false});return rows;
  }

  return Object.freeze({
    MAX_SIGNAL_LENGTH:MAX_TICK_LENGTH,MAX_FOLLOW_UPS:100,stripTicks,validRanges,
    classifyLine,rangesForLine,signalSegments,rangeSegments,annotateLine,annotateText,triage,
    triageLine,stats,tickRanges,rawFromTriage,manualFollowUps,pasteTriage
  });
});
