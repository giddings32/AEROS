/* Host-owned group editing, available directly from My Workspace. */
(() => {
  'use strict';
  const byId=id=>document.getElementById(id);
  const api=()=>window.AerosAssetGroups;
  const groups=()=>api()?.list?.()||[];
  const close=()=>{byId('assetGroupModal')?.classList.add('hidden');document.body.classList.remove('host-modal-open');};
  const domainField=()=>byId('assetGroupDomainField')?.classList.toggle('hidden',byId('assetGroupType')?.value!=='active-directory');
  function open(groupId='',hostId='',defaults={}){
    byId('saveAssetGroupBtn').disabled=false;
    const group=groups().find(row=>row.id===groupId)||defaults;
    for(const [id,key] of Object.entries({assetGroupId:'id',assetGroupName:'name',assetGroupType:'type',assetGroupDomainName:'domainName',assetGroupNotes:'notes'}))byId(id).value=group[key]||(key==='type'?'custom':'');
    const members=new Set([...(group.memberHostIds||[]),hostId]);
    const root=byId('assetGroupMemberList');root.replaceChildren();
    const state=window.getAerosState?.()||{};
    Object.entries(state.hosts||{}).forEach(([key,host])=>{
      const label=document.createElement('label');label.className='asset-group-member-option';
      const input=document.createElement('input');input.className='asset-group-member-checkbox';input.type='checkbox';input.value=host.id||key;input.checked=members.has(input.value);
      const text=document.createElement('span');text.className='asset-group-member-identity';text.textContent=[host.ip||key,host.hostname].filter(Boolean).join(' · ');
      label.append(input,text);root.append(label);
    });
    byId('assetGroupModalTitle').textContent=group.id?'Edit Asset Group':'Create Asset Group';
    byId('assetGroupError')?.classList.add('hidden');domainField();
    byId('assetGroupModal')?.classList.remove('hidden');document.body.classList.add('host-modal-open');byId('assetGroupName')?.focus();
  }
  window.openAerosAssetGroupManager=(hostId,{createAd=false}={})=>{
    const matches=groups().filter(group=>createAd?group.type==='active-directory':(group.memberHostIds||[]).includes(hostId));
    if(matches.length>1){
      byId('saveAssetGroupBtn').disabled=true;
      const root=byId('assetGroupMemberList');root.replaceChildren();
      byId('assetGroupModalTitle').textContent='Choose an Asset Group';
      matches.forEach(group=>{const button=document.createElement('button');button.type='button';button.textContent=group.name;button.onclick=()=>open(group.id,hostId);root.append(button);});
      byId('assetGroupModal')?.classList.remove('hidden');document.body.classList.add('host-modal-open');
      return;
    }
    open(matches[0]?.id||'',hostId,createAd?{type:'active-directory',name:'Active Directory Environment'}:{});
  };
  byId('saveAssetGroupBtn')?.addEventListener('click',async()=>{
    try{
      await api().save({id:byId('assetGroupId').value,name:byId('assetGroupName').value,type:byId('assetGroupType').value,domainName:byId('assetGroupDomainName').value,notes:byId('assetGroupNotes').value,memberHostIds:[...document.querySelectorAll('#assetGroupMemberList input:checked')].map(input=>input.value)});close();
    }catch(error){byId('assetGroupError').textContent=error.message;byId('assetGroupError').classList.remove('hidden');}
  });
  byId('closeAssetGroupBtn')?.addEventListener('click',close);
  byId('cancelAssetGroupBtn')?.addEventListener('click',close);
  byId('assetGroupType')?.addEventListener('change',domainField);
  byId('selectAllAssetGroupHostsBtn')?.addEventListener('click',()=>{const inputs=[...document.querySelectorAll('#assetGroupMemberList input')],checked=inputs.some(input=>!input.checked);inputs.forEach(input=>input.checked=checked);});
  byId('assetGroupModal')?.addEventListener('mousedown',event=>{if(event.target===byId('assetGroupModal'))close();});
})();
