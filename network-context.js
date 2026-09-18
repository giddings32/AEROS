/* Pure, offline interpretations of operator-pasted Linux network output.
 * Observations are derived from source text; they never establish reachability. */
(function(root,factory){
  const api=factory();
  if(typeof module==='object'&&module.exports)module.exports=api;
  if(root)root.AEROSNetworkContext=api;
})(typeof globalThis!=='undefined'?globalThis:this,function(){
  'use strict';
  const clean=value=>String(value??'').trim();
  const escape=value=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const stripAnsi=value=>String(value??'').replace(/\x1b\[[0-?]*[ -/]*[@-~]/g,'');
  function lineText(raw){
    const source=stripAnsi(raw),manual=[];let text='',cursor=0;
    for(const m of source.matchAll(/`([^`]+)`/g)){
      text+=source.slice(cursor,m.index);manual.push({start:text.length,end:text.length+m[1].length,reason:'Manual highlight',priority:'high',manual:true});
      text+=m[1];cursor=m.index+m[0].length;
    }
    return {text:text+source.slice(cursor),manual};
  }
  const sourceLines=value=>String(value??'').split(/\r\n|\n|\r/).map(lineText);
  function v4(value){
    const p=value.split('.');
    return p.length===4&&p.every(x=>/^\d{1,3}$/.test(x)&&Number(x)<256)?p.map(Number):null;
  }
  function v6(value){
    let text=value.toLowerCase();
    if(text.includes('.')){
      const i=text.lastIndexOf(':'),p=v4(text.slice(i+1));if(!p)return null;
      text=text.slice(0,i+1)+((p[0]<<8)|p[1]).toString(16)+':'+((p[2]<<8)|p[3]).toString(16);
    }
    if(!/^[a-f0-9:]+$/.test(text)||text.split('::').length>2)return null;
    const halves=text.split('::'),left=halves[0]?halves[0].split(':'):[],right=halves[1]?halves[1].split(':'):[];
    if([...left,...right].some(x=>!x||x.length>4))return null;
    const gap=8-left.length-right.length;
    if((halves.length===1&&gap!==0)||(halves.length===2&&gap<1))return null;
    return [...left,...Array(halves.length===2?gap:0).fill('0'),...right].map(x=>parseInt(x,16));
  }
  function format6(words){
    let start=-1,length=0;
    for(let i=0;i<8;){if(words[i]){i++;continue;}let j=i;while(j<8&&!words[j])j++;if(j-i>length){start=i;length=j-i;}i=j;}
    if(length<2)return words.map(x=>x.toString(16)).join(':');
    return words.slice(0,start).map(x=>x.toString(16)).join(':')+'::'+words.slice(start+length).map(x=>x.toString(16)).join(':');
  }
  function address(value){
    const raw=clean(value).replace(/^\[|\]$/g,''),withoutZone=raw.split('%')[0],four=v4(withoutZone);
    if(four)return {address:four.join('.'),family:4,bits:four.reduce((n,x)=>(n<<8n)|BigInt(x),0n)};
    const six=v6(withoutZone);if(!six)return null;
    if(six.slice(0,5).every(x=>x===0)&&six[5]===65535)return address([six[6]>>8,six[6]&255,six[7]>>8,six[7]&255].join('.'));
    return {address:format6(six),family:6,bits:six.reduce((n,x)=>(n<<16n)|BigInt(x),0n)};
  }
  const normalized=value=>address(value)?.address||'';
  function scope(value){
    const a=address(value);if(!a)return value==='*'?'wildcard':'unknown';
    if(a.bits===0n)return 'wildcard';
    if(a.family===4){
      const n=Number(a.bits)>>>0;
      if((n>>>24)===127)return 'loopback';
      if((n>>>16)===0xa9fe)return 'link-local';
      if((n>>>28)>=14)return 'multicast';
    }else{
      if(a.bits===1n)return 'loopback';
      if((a.bits>>118n)===0x3fan)return 'link-local';
      if((a.bits>>120n)===255n)return 'multicast';
    }
    return 'address';
  }
  function cidr(value){
    const parts=clean(value).split('/'),a=address(parts[0]);
    if(!a||parts.length!==2||!/^\d+$/.test(parts[1]))return null;
    let prefix=Number(parts[1]);
    if(a.family===4&&parts[0].includes(':'))prefix-=96;
    const width=a.family===4?32:128;if(prefix<0||prefix>width)return null;
    const shift=BigInt(width-prefix),network=(a.bits>>shift)<<shift;
    const base=a.family===4?[24,16,8,0].map(n=>Number((network>>BigInt(n))&255n)).join('.'):
      format6(Array.from({length:8},(_,i)=>Number((network>>BigInt((7-i)*16))&65535n)));
    return {address:a.address,family:a.family,prefix,subnet:base+'/'+prefix};
  }
  function contains(network,value){
    const n=cidr(network),a=address(value);if(!n||!a||a.family!==n.family)return false;
    const shift=BigInt((a.family===4?32:128)-n.prefix);
    return (address(n.address).bits>>shift)===(a.bits>>shift);
  }
  function netmaskPrefix(mask){
    const a=address(mask);if(!a||a.family!==4)return null;
    const bits=a.bits.toString(2).padStart(32,'0');return /^1*0*$/.test(bits)?bits.replace(/0/g,'').length:null;
  }
  function parseInterfaces(raw){
    const lines=sourceLines(raw),interfaces=[];let current=null;
    const start=(name,state,index,flags='')=>{
      current={name:name.replace(/:$/,''),state,virtual:/^(docker|br-|veth|virbr|tun\d|tap\d|wg\d|tailscale)/i.test(name),loopback:/LOOPBACK/.test(flags)||name==='lo',line:index,addresses:[]};
      interfaces.push(current);
    };
    lines.forEach(({text},index)=>{
      let m=text.match(/^\s*\d+:\s+([^: ]+):\s*(.*)$/);
      if(m){start(m[1],m[2].match(/\bstate\s+(\w+)/)?.[1]||(/\bUP\b/.test(m[2])?'UP':'UNKNOWN'),index,m[2]);}
      else if((m=text.match(/^([^\s:]+):?\s+(?:flags=\S+|Link encap:)(.*)$/))){start(m[1],/\bUP\b/.test(text)?'UP':'UNKNOWN',index,text);}
      else if((m=text.match(/^\s*([^\s:]+)\s+(UP|DOWN|UNKNOWN)\s+(.+)$/))){start(m[1],m[2],index);}
      if(!current)return;
      for(const match of text.matchAll(/(?:\binet6?\s+(?:addr:)?|\s)([a-fA-F0-9:.]+\/\d{1,3})(?=\s|$)/g)){
        const a=cidr(match[1]);if(a&&!current.addresses.some(x=>x.address===a.address&&x.prefix===a.prefix))current.addresses.push({...a,line:index,token:match[1],scope:scope(a.address)});
      }
      const old=text.match(/\binet\s+(?:addr:)?([\d.]+)\s+(?:netmask\s+|.*?Mask:)([\d.]+)/);
      if(old){const prefix=netmaskPrefix(old[2]),a=prefix===null?null:cidr(old[1]+'/'+prefix);if(a)current.addresses.push({...a,line:index,token:old[1],scope:scope(a.address)});}
      if(/^\s*(?:UP|flags=).*\bUP\b/.test(text))current.state='UP';
    });
    return {lines,interfaces};
  }
  function parseRoutes(raw){
    const lines=sourceLines(raw),routes=[];
    lines.forEach(({text},line)=>{
      const m=text.match(/^\s*(?:unicast\s+)?([\da-fA-F:.]+(?:\/\d+)?)\s+(.+)$/),dev=text.match(/\bdev\s+(\S+)/);
      if(!m||!dev)return;
      const c=cidr(m[1])||cidr(m[1]+'/'+(address(m[1])?.family===6?128:32));
      if(c&&c.prefix>0&&scope(c.address)==='address')routes.push({...c,interfaceName:dev[1],via:text.match(/\bvia\s+(\S+)/)?.[1]||'',line,token:m[1],down:/\blinkdown\b/.test(text)});
    });return {lines,routes};
  }
  function endpoint(token){
    const m=token.match(/^(?:\[([^\]]+)\]|(.+)):(\d+|\*)$/);if(!m)return null;
    const rawAddress=m[1]||m[2],ip=normalized(rawAddress);
    if(!ip&&rawAddress!=='*')return null;
    const port=m[3]==='*'?null:Number(m[3]);if(port!==null&&(port<1||port>65535))return null;
    return {address:ip||'*',port,scope:scope(rawAddress),token};
  }
  function parseSockets(raw){
    const lines=sourceLines(raw),sockets=[];
    lines.forEach(({text},line)=>{
      const t=text.trim().split(/\s+/);let protocol='',state='',localToken='',peerToken='';
      if(/^(tcp|udp)[46]?$/.test(t[0])){
        protocol=t[0].slice(0,3);
        if(/^\d+$/.test(t[1])&&/^\d+$/.test(t[2])){ // netstat
          localToken=t[3];peerToken=t[4];state=protocol==='udp'?'UNCONN':t[5];
        }else if(/^\d+$/.test(t[2])&&/^\d+$/.test(t[3])){state=t[1];localToken=t[4];peerToken=t[5];}
      }else if(/^(LISTEN|ESTAB|CLOSE-WAIT|SYN-SENT|TIME-WAIT)$/.test(t[0])&&/^\d+$/.test(t[1])&&/^\d+$/.test(t[2])){
        protocol='tcp';state=t[0];localToken=t[3];peerToken=t[4];
      }
      const local=endpoint(localToken||''),peer=endpoint(peerToken||'');if(!local||!peer||!protocol)return;
      state=String(state||'').replace(/_/g,'-').replace('ESTABLISHED','ESTAB');
      const processes=[...new Set([...text.matchAll(/"([^"\n]+)",pid=\d+/g)].map(m=>m[1]).concat(text.match(/\b\d+\/([^\s]+)/)?.[1]||[]))];
      sockets.push({protocol,state,local,peer,processes,line,
        listener:(protocol==='tcp'&&state==='LISTEN')||(protocol==='udp'&&state==='UNCONN'&&peer.port===null),
        established:state==='ESTAB'});
    });return {lines,sockets};
  }
  function addMark(marks,line,token,reason,priority='high'){
    if(!token)return;if(!marks[line])marks[line]=[];marks[line].push({token,reason,priority});
  }
  function analyze(host={}){
    const linux=host.systemInfo?.linux||{},prefs=host.networkContext||{},network=parseInterfaces(linux.network),routeData=parseRoutes(linux.routes),socketData=parseSockets(linux.listeningPorts);
    const primary=normalized(host.ip),override=clean(prefs.workingInterface),matches=network.interfaces.filter(i=>i.addresses.some(a=>a.address===primary));
    const working=override?network.interfaces.find(i=>i.name===override):(matches.length===1?matches[0]:null);
    const workingSubnets=new Set((working?.addresses||[]).filter(a=>override||a.address===primary).map(a=>a.subnet));
    const marks={network:{},routes:{},listeningPorts:{}},networks=[],listeners=[],peers=[];
    for(const iface of network.interfaces){
      for(const a of iface.addresses){
        if(iface.loopback||a.scope!=='address')continue;
        const extra=working?(!workingSubnets.has(a.subnet)):a.address!==primary;
        const differentInterface=working&&iface!==working;
        if(!extra&&!differentInterface)continue;
        const low=iface.virtual||iface.state==='DOWN';
        const label=!working?'Working interface unknown':extra?'Additional network':'Additional interface on working subnet';
        networks.push({...a,interfaceName:iface.name,state:iface.state,virtual:iface.virtual,label,additional:!!working&&extra});
        addMark(marks.network,iface.line,iface.name,label,low?'low':extra?'high':'medium');
        addMark(marks.network,a.line,a.token,label,low?'low':extra?'high':'medium');
      }
    }
    const routes=routeData.routes.filter(r=>!workingSubnets.has(r.subnet)&&!networks.some(n=>n.subnet===r.subnet&&n.interfaceName===r.interfaceName));
    routes.forEach(r=>addMark(marks.routes,r.line,r.token,'Route observed; reachability unverified',r.down?'low':'medium'));
    const locals=new Set([primary,...network.interfaces.flatMap(i=>i.addresses.map(a=>a.address)),...(host.networkAddresses||[]).map(a=>normalized(a.address))]);
    const listenerMap=new Map(),peerMap=new Map();
    for(const socket of socketData.sockets){
      const {local,peer,line,protocol}=socket;
      if(socket.listener){
        const resolver=local.scope==='loopback'&&local.port===53;
        const label=local.scope==='loopback'?'Loopback-only listener':local.scope==='wildcard'?'All-interface listener':'Address-bound listener';
        if(!['link-local','multicast'].includes(local.scope))addMark(marks.listeningPorts,line,local.token,label,resolver?'low':local.scope==='loopback'?'high':'medium');
        const key=protocol+'|'+local.address+'|'+local.port;
        if(!listenerMap.has(key)){const row={...socket,label,resolver,count:0};listenerMap.set(key,row);listeners.push(row);}
        listenerMap.get(key).count++;
      }else if(socket.established&&peer.scope==='address'&&!locals.has(peer.address)){
        const via=network.interfaces.find(i=>i.addresses.some(a=>a.address===local.address));
        const secondary=!!via&&!!working&&(!workingSubnets.size||!Array.from(workingSubnets).some(n=>contains(n,local.address)));
        addMark(marks.listeningPorts,line,peer.token,'Established peer observed from this host',secondary?'high':'medium');
        if(secondary)addMark(marks.listeningPorts,line,local.token,'Connection using additional network');
        const key=protocol+'|'+local.address+'|'+peer.address+'|'+peer.port;
        if(!peerMap.has(key)){const row={...socket,count:0,interfaceName:via?.name||'',secondary};peerMap.set(key,row);peers.push(row);}
        const row=peerMap.get(key);row.count++;row.processes=[...new Set([...row.processes,...socket.processes])];
      }
    }
    return {primary,working:working?.name||'',overrideMissing:!!override&&!working,network,routeData,socketData,networks,routes,listeners,peers,marks};
  }
  function renderLines(lines,marks={},auto=true){
    return lines.map(({text,manual},index)=>{
      const candidates=[...manual];
      if(auto)for(const mark of marks[index]||[]){
        let start=0;while((start=text.indexOf(mark.token,start))!==-1){const end=start+mark.token.length;if(!manual.some(m=>start<m.end&&end>m.start))candidates.push({...mark,start,end});start=end;}
      }
      candidates.sort((a,b)=>a.start-b.start||Number(!!b.manual)-Number(!!a.manual)||b.end-a.end);
      let result='',end=0;
      for(const range of candidates){if(range.start<end)continue;result+=escape(text.slice(end,range.start));result+='<span class="inline-glow network-signal" data-highlight-source="'+(range.manual?'manual':'auto')+'" data-highlight-priority="'+range.priority+'" title="'+escape(range.reason)+'">'+escape(text.slice(range.start,range.end))+'</span>';end=range.end;}
      return result+escape(text.slice(end));
    }).join('<br>');
  }
  function preview(host,key,analysis=analyze(host)){
    const raw=host.systemInfo?.linux?.[key]||'';
    if(!raw.trim())return '<div class="host-meta">Nothing pasted yet.</div>';
    const lines=key==='network'?analysis.network.lines:key==='routes'?analysis.routeData.lines:analysis.socketData.lines;
    return renderLines(lines,analysis.marks[key],host.networkContext?.autoHighlightDisabled?.[key]!==true);
  }
  const quote=value=>"'"+String(value).replace(/'/g,"'\\''")+"'";
  function commandPlan(values={}){
    // Validate typed values before interpolation. Unset values stay explicit placeholders.
    const ip=(key,fallback)=>normalized(values[key])||fallback;
    const port=(key,fallback)=>/^\d+$/.test(clean(values[key]))&&Number(values[key])>0&&Number(values[key])<=65535?String(Number(values[key])):fallback;
    const target=ip('target','<TARGET_IP>'),kali=ip('kali','<KALI_IP>'),dest=ip('destination','<DESTINATION_IP>');
    const dp=port('destinationPort','<DESTINATION_PORT>'),lp=port('localPort','<LOCAL_PORT>'),listen=port('listenerPort','<LISTENER_PORT>');
    const user=/^[a-zA-Z0-9_][a-zA-Z0-9_.-]*$/.test(clean(values.user))?clean(values.user):'<SSH_USER>';
    const subnet=cidr(values.subnet)?.subnet||'<SUBNET/CIDR>',bracket=value=>value.includes(':')?'['+value+']':value;
    const tool=values.tool||'ssh';let intro='',groups=[],routeSubnet=subnet,routeDestination=dest;
    if(tool==='ssh'){
      intro='Requires SSH access to the target and forwarding permitted by its SSH server. Local forwarding exposes one TCP endpoint on Kali loopback; SOCKS supports proxy-aware TCP clients.';
      groups=[{label:'Run on Kali — choose local forwarding OR SOCKS',commands:[
        'ssh -N -o ExitOnForwardFailure=yes -L '+quote('127.0.0.1:'+lp+':'+bracket(dest)+':'+dp)+' -l '+quote(user)+' '+quote(target),
        'ssh -N -o ExitOnForwardFailure=yes -D '+quote('127.0.0.1:'+lp)+' -l '+quote(user)+' '+quote(target)
      ]}];
    }else if(tool==='chisel'){
      intro='Requires Chisel on both machines and target-to-Kali connectivity. Use the server fingerprint printed on Kali in the client command. This reverse forward carries one TCP endpoint back to Kali loopback.';
      groups=[{label:'Run on Kali',commands:['chisel server --host '+quote(kali)+' --port '+listen+' --reverse']},
        {label:'Run on target',commands:['chisel client --fingerprint '+quote('<SERVER_FINGERPRINT>')+' '+quote('http://'+bracket(kali)+':'+listen)+' '+quote('R:127.0.0.1:'+lp+':'+bracket(dest)+':'+dp)]}];
    }else{
      if(scope(dest)==='loopback'){
        if(dest!=='127.0.0.1')return {intro:'For this loopback address, choose SSH or Chisel to forward the exact listener. Ligolo-ng\'s special IPv4 loopback mapping targets 127.0.0.1.',groups:[]};
        routeSubnet='240.0.0.1/32';routeDestination='240.0.0.1';
      }
      intro='Requires Ligolo-ng proxy on Kali, agent on the target and permission to create a TUN interface/route on Kali. The target connects to Kali. Check existing routes first; interface/session names must be unique. Commands below use the Ligolo-ng console interface_create workflow.';
      if(routeDestination==='240.0.0.1')intro+=' Ligolo maps 240.0.0.1 to the agent host\'s 127.0.0.1. After starting the tunnel, connect from Kali to 240.0.0.1:'+dp+'. The route below uses this mapping instead of the network field.';
      groups=[{label:'Run on Kali',commands:['ip route get '+quote(routeDestination),'sudo ligolo-proxy -selfcert -laddr '+quote(bracket(kali)+':'+listen)]},
        {label:'In the Ligolo-ng proxy console — get the certificate fingerprint',commands:['certificate_fingerprint']},
        {label:'Run on target',commands:['ligolo-agent -connect '+quote(bracket(kali)+':'+listen)+' -accept-fingerprint '+quote('<CERTIFICATE_FINGERPRINT>')]},
        {label:'In the proxy console — select the connected target session',commands:['interface_create --name <TUN_INTERFACE>','session','tunnel_start --tun <TUN_INTERFACE>']},
        {label:'Run on Kali — route only the intended network',commands:['sudo ip route add '+quote(routeSubnet)+' dev <TUN_INTERFACE>']}];
    }
    groups.push({label:'Verify on Kali',commands:tool==='ligolo'?['ip route get '+quote(routeDestination)]:['ss -lntp '+quote('sport = :'+lp)]});
    if(tool==='ligolo')groups.push({label:'Cleanup — run on Kali',commands:['sudo ip route del '+quote(routeSubnet)+' dev <TUN_INTERFACE>']},{label:'Cleanup — in the selected proxy session',commands:['tunnel_stop','interface_delete --name <TUN_INTERFACE>']});
    else intro+=' Stop the foreground client with Ctrl+C when finished.';
    return {intro,groups};
  }
  return {normalized,scope,cidr,contains,parseInterfaces,parseRoutes,parseSockets,analyze,preview,renderLines,commandPlan,escape};
});
