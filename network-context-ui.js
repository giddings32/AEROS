/* Host Enumeration view/controller. Parsed facts stay derived from ordinary files. */
(function(root){
  'use strict';
  const fields={network:'sysLinuxNetwork',routes:'sysLinuxRoutes',listeningPorts:'sysLinuxListeningPorts'};
  const model=()=>root.AEROSNetworkContext;
  let dependencies=null,modalHost='',returnFocus=null;
  const el=id=>document.getElementById(id);
  const prefs=host=>host.networkContext||(host.networkContext={});
  const h=value=>model().escape(value);
  function bind(deps){dependencies=deps;}
  function current(host){return dependencies?.getHost()?.id===host.id;}
  function summaryRow(title,detail){return '<li><strong>'+h(title)+'</strong><span>'+h(detail)+'</span></li>';}
  function rowsHtml(rows){return '<ul class="network-context-list">'+rows.slice(0,30).join('')+'</ul>'+(rows.length>30?'<p class="host-meta">Showing 30 of '+rows.length+' observations. Full output remains above.</p>':'');}
  function render(host){
    if(!dependencies||!host)return;
    if(modalHost&&modalHost!==host.id)close(false);
    const analysis=model().analyze(host);
    for(const [key,id] of Object.entries(fields)){
      const field=el(id),preview=el('sysPreview_'+id),card=field?.closest('.sys-paste-card');if(!card||!preview)continue;
      card.classList.add('network-context-card');preview.innerHTML=model().preview(host,key,analysis);
      let actions=card.querySelector('.sys-paste-actions');
      if(!actions){actions=document.createElement('div');actions.className='sys-paste-actions';card.querySelector('.sys-paste-title').appendChild(actions);}
      let toggle=actions.querySelector('[data-network-auto]');
      if(!toggle){
        toggle=document.createElement('button');toggle.type='button';toggle.className='secondary-btn small';toggle.dataset.networkAuto=key;actions.appendChild(toggle);
        toggle.onclick=()=>{const selected=dependencies.getHost();if(!selected)return;const p=prefs(selected);p.autoHighlightDisabled||={};if(p.autoHighlightDisabled[key])delete p.autoHighlightDisabled[key];else p.autoHighlightDisabled[key]=true;render(selected);dependencies.save();toggle.focus();};
      }
      const disabled=host.networkContext?.autoHighlightDisabled?.[key]===true;
      toggle.textContent=(disabled?'Restore':'Remove')+' Auto Highlighting';toggle.setAttribute('aria-pressed',String(disabled));
      let notes=actions.querySelector('[data-network-notes]');
      if(!notes){notes=document.createElement('button');notes.type='button';notes.className='secondary-btn small';notes.dataset.networkNotes=key;notes.textContent='Tunneling Notes';notes.onclick=()=>open(notes);actions.appendChild(notes);}
      let summary=card.querySelector('.network-context-summary');
      if(!summary){summary=document.createElement('div');summary.className='network-context-summary';summary.dataset.networkSummary=key;card.appendChild(summary);}
      if(key==='network'){
        // Keep the select node stable so typing and keyboard focus survive live parsing.
        let select=summary.querySelector('select');
        if(!select){summary.innerHTML='<label class="network-working-label">Working interface <select id="networkWorkingInterface" aria-label="Working interface"></select></label><p class="host-meta" data-working-status></p><div data-network-observations></div>';select=summary.querySelector('select');
          select.onchange=()=>{const selected=dependencies.getHost();if(!selected)return;prefs(selected).workingInterface=select.value;render(selected);dependencies.save();};}
        const names=[...new Set(analysis.network.interfaces.filter(i=>!i.loopback).map(i=>i.name))],override=host.networkContext?.workingInterface||'';
        if(override&&!names.includes(override))names.push(override);
        const options='<option value="">Auto — match host IP</option>'+names.map(name=>'<option value="'+h(name)+'">'+h(name)+(analysis.overrideMissing&&name===override?' (not in output)':'')+'</option>').join('');
        if(select.innerHTML!==options)select.innerHTML=options;select.value=override;
        summary.querySelector('[data-working-status]').textContent=analysis.working?(override?'Selected working interface: ':'Matches host IP: ')+analysis.working+' · Interface addresses do not confirm a connection path.':analysis.overrideMissing?'Selected interface is no longer in the output. Choose another interface or Auto.':'Working interface unknown. Select it if the host IP is translated or absent.';
        summary.querySelector('[data-network-observations]').innerHTML=rowsHtml(analysis.networks.map(n=>summaryRow(n.label+': '+n.subnet,n.interfaceName+' · '+n.address+'/'+n.prefix+' · '+n.state+(n.virtual?' · virtual/VPN interface':''))));
        summary.classList.toggle('hidden',!String(host.systemInfo?.linux?.network||'').trim()&&!override);
      }else if(key==='routes'){
        summary.innerHTML=rowsHtml(analysis.routes.map(r=>summaryRow('Route observed: '+r.subnet,r.interfaceName+(r.via?' via '+r.via:'')+(r.down?' · link down':'')+' · Reachability unverified')));
        summary.classList.toggle('hidden',!analysis.routes.length);
      }else{
        const listeners=analysis.listeners.map(s=>summaryRow(s.label+': '+s.local.token,s.protocol.toUpperCase()+(s.processes.length?' · '+s.processes.join(', '):'')+(s.resolver?' · local DNS resolver':'')+' · Remote reachability unverified'));
        const peers=analysis.peers.map(s=>summaryRow('Established peer: '+s.peer.token,s.count+' connection'+(s.count===1?'':'s')+' from '+s.local.address+(s.interfaceName?' ('+s.interfaceName+')':'')+(s.processes.length?' · '+s.processes.join(', '):'')));
        summary.innerHTML=rowsHtml([...listeners,...peers]);summary.classList.toggle('hidden',!listeners.length&&!peers.length);
      }
    }
  }
  function close(restore=true){
    el('networkNotesModal')?.classList.add('hidden');modalHost='';
    if(restore&&returnFocus?.isConnected)returnFocus.focus();returnFocus=null;
  }
  const inputSpecs=[['target','SSH / target address'],['kali','Kali address reachable from target'],['user','SSH username'],['destination','Destination address (from target)'],['destinationPort','Destination TCP port'],['localPort','Kali local / SOCKS port'],['listenerPort','Kali tunnel listener port'],['subnet','Network to route (CIDR)']];
  function ensureModal(){
    let modal=el('networkNotesModal');if(modal)return modal;
    modal=document.createElement('div');modal.id='networkNotesModal';modal.className='app-modal-backdrop hidden';modal.setAttribute('role','dialog');modal.setAttribute('aria-modal','true');modal.setAttribute('aria-labelledby','networkNotesTitle');
    modal.innerHTML='<section class="app-modal network-notes-modal"><header class="app-modal-header"><div><div class="app-modal-kicker">Host Enumeration</div><h2 id="networkNotesTitle">Tunneling Notes</h2></div><button type="button" class="app-modal-close" data-network-close aria-label="Close Tunneling Notes"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="m6 6 12 12M18 6 6 18"></path></svg></button></header><div class="network-notes-body"><p class="host-meta">Use observed networks and endpoints to prepare forwarding commands. Replace any remaining angle-bracket placeholders before running a command.</p><label>Tool <select id="networkNotesTool"><option value="ssh">SSH — local forwarding / SOCKS</option><option value="chisel">Chisel — reverse TCP forwarding</option><option value="ligolo">Ligolo-ng — routed tunnel</option></select></label><label>Use an observation <select id="networkNotesObservation" aria-label="Use a network observation"></select></label><div class="network-notes-inputs">'+inputSpecs.map(([key,label])=>'<label>'+h(label)+'<input id="networkNote_'+key+'" data-network-value="'+key+'" autocomplete="off" spellcheck="false" maxlength="160"></label>').join('')+'</div><p id="networkNotesIntro" class="host-meta"></p><div id="networkNotesCommands"></div></div><footer class="app-confirm-footer"><button type="button" class="secondary-btn" data-network-close>Close</button></footer></section>';
    document.body.appendChild(modal);
    modal.querySelectorAll('[data-network-close]').forEach(button=>button.onclick=()=>close());
    modal.onclick=event=>{if(event.target===modal)close();};
    modal.addEventListener('keydown',event=>{
      if(event.key==='Escape'){event.preventDefault();event.stopPropagation();close();}
      if(event.key==='Tab'){
        const nodes=[...modal.querySelectorAll('button,input,select')].filter(n=>!n.disabled&&n.getClientRects().length),first=nodes[0],last=nodes[nodes.length-1];
        if(event.shiftKey&&document.activeElement===first){event.preventDefault();last.focus();}else if(!event.shiftKey&&document.activeElement===last){event.preventDefault();first.focus();}
      }
    });
    return modal;
  }
  function open(button){
    const host=dependencies?.getHost();if(!host)return;
    const analysis=model().analyze(host),modal=ensureModal();returnFocus=button;modalHost=host.id;
    const saved=host.networkContext?.notes||{},values={...saved,target:saved.target||analysis.primary,kali:saved.kali||dependencies.getCallbackHost?.()||''};
    inputSpecs.forEach(([key])=>{el('networkNote_'+key).value=values[key]||'';});el('networkNotesTool').value=saved.tool||'ssh';
    const observations=[{label:'Choose a network, local listener or established peer',values:{}}];
    analysis.networks.filter(n=>n.state!=='DOWN').forEach(n=>observations.push({label:n.subnet+' via '+n.interfaceName,values:{subnet:n.subnet,destination:'',destinationPort:''}}));
    analysis.routes.filter(n=>!n.down).forEach(n=>observations.push({label:n.subnet+' via '+n.interfaceName+' (route)',values:{subnet:n.subnet,destination:'',destinationPort:''}}));
    analysis.listeners.filter(s=>s.protocol==='tcp'&&['address','loopback','wildcard'].includes(s.local.scope)).forEach(s=>{
      let destination=s.local.address;
      if(s.local.scope==='wildcard')destination=s.local.address==='::'?'::1':s.local.address==='0.0.0.0'?'127.0.0.1':analysis.network.interfaces.some(i=>i.addresses.some(a=>a.address===analysis.primary))?analysis.primary:'';
      observations.push({label:s.label+': '+s.local.token,values:{destination,destinationPort:String(s.local.port)}});
    });
    analysis.peers.filter(s=>s.protocol==='tcp').forEach(s=>observations.push({label:'Established peer: '+s.peer.token,values:{destination:s.peer.address,destinationPort:String(s.peer.port)}}));
    el('networkNotesObservation').innerHTML=observations.map((o,i)=>'<option value="'+i+'">'+h(o.label)+'</option>').join('');
    const update=(save=true)=>{
      if(!current(host)){close(false);return;}
      const value=Object.fromEntries(inputSpecs.map(([key])=>[key,el('networkNote_'+key).value]));value.tool=el('networkNotesTool').value;
      const relevant={ssh:['target','user','destination','destinationPort','localPort'],chisel:['kali','destination','destinationPort','localPort','listenerPort'],ligolo:['kali','destination','destinationPort','listenerPort','subnet']}[value.tool];
      inputSpecs.forEach(([key])=>{el('networkNote_'+key).closest('label').hidden=!relevant.includes(key);});
      const plan=model().commandPlan(value);el('networkNotesIntro').textContent=plan.intro;el('networkNotesCommands').innerHTML=dependencies.commandGroups(plan.groups);
      if(save){prefs(host).notes=value;dependencies.save();}
    };
    modal.querySelectorAll('[data-network-value]').forEach(input=>input.oninput=()=>update());el('networkNotesTool').onchange=()=>update();
    el('networkNotesObservation').onchange=()=>{const selected=observations[Number(el('networkNotesObservation').value)];Object.entries(selected?.values||{}).forEach(([key,value])=>{el('networkNote_'+key).value=value;});update();};
    update(false);modal.classList.remove('hidden');modal.querySelector('[data-network-close]').focus();
  }
  root.AEROSNetworkContextUI={bind,render,open,close,fields};
})(typeof globalThis!=='undefined'?globalThis:this);
