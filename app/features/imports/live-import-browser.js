(function(root,factory){
  const core=(typeof module==="object"&&module.exports)
    ?(()=>{try{return require("./live-import-core.js");}catch(error){if(error?.code!=="MODULE_NOT_FOUND")throw error;return require("./app/features/imports/live-import-core.js");}})()
    :(root&&root.AEROSLiveImportCore);
  const api=factory(core||{});
  if(typeof module==="object"&&module.exports)module.exports=api;
  if(root)root.AEROSLiveImportBrowser=api;
})(typeof window!=="undefined"?window:globalThis,function(core){
  "use strict";

  const DB_NAME="aeros-live-import-v1";
  const DB_VERSION=1;
  const SETTINGS_ID="staging-root";
  const FALLBACK_VISIBLE_MS=45000;
  const FALLBACK_HIDDEN_MS=120000;
  const OBSERVER_RECONCILE_MS=300000;
  const STABLE_FILE_BOUNDARY_MS=OBSERVER_RECONCILE_MS;
  const FOCUS_RECONCILE_MIN_MS=10000;
  const WALK_BATCH_SIZE=250;
  const BINARY_EXTENSIONS=new Set(["7z","avif","bin","bmp","bz2","db","dll","dmp","exe","gif","gz","ico","jar","jpeg","jpg","o","obj","otf","pcap","pcapng","pdf","png","rar","so","sqlite","sqlite3","tar","tif","tiff","ttf","wasm","webp","woff","woff2","xz","zip"]);
  const clean=value=>String(value??"").trim();
  const nowIso=()=>new Date().toISOString();
  const permissionError=error=>["NotAllowedError","SecurityError"].includes(String(error?.name||""));
  const missingSourceError=error=>String(error?.name||"")==="NotFoundError";
  function stableFileBoundary(metadata={},now=Date.now(),minimumAge=STABLE_FILE_BOUNDARY_MS){
    const modified=Number(metadata.lastModified),current=Number(now),age=Math.max(0,Number(minimumAge)||0);
    return modified>0&&Number.isFinite(current)&&current>=modified&&current-modified>=age;
  }
  function createTimerApi(scope=globalThis,{setTimer,clearTimer}={}){
    const setScope=typeof scope?.setTimeout==="function"?scope:globalThis,clearScope=typeof scope?.clearTimeout==="function"?scope:globalThis;
    const injectedSetTimer=typeof setTimer==="function"?setTimer:null,injectedClearTimer=typeof clearTimer==="function"?clearTimer:null;
    if(!injectedSetTimer&&typeof setScope?.setTimeout!=="function")throw new Error("A native or injected setTimeout function is required.");
    if(!injectedClearTimer&&typeof clearScope?.clearTimeout!=="function")throw new Error("A native or injected clearTimeout function is required.");
    const schedule=injectedSetTimer?((callback,delay)=>injectedSetTimer(callback,delay)):setScope.setTimeout.bind(setScope);
    const cancel=injectedClearTimer?(timer=>injectedClearTimer(timer)):clearScope.clearTimeout.bind(clearScope);
    return Object.freeze({set(callback,delay){const timer=schedule(callback,delay);timer?.unref?.();return timer;},clear(timer){return cancel(timer);}});
  }

  function capabilities(scope=globalThis){
    return Object.freeze({
      supportsDirectoryAccess:typeof scope?.showDirectoryPicker==="function"&&scope?.isSecureContext!==false,
      supportsObserver:typeof scope?.FileSystemObserver==="function",
      supportsPersistentHandle:Boolean(scope?.indexedDB)
    });
  }
  function randomId(scope=globalThis){
    return scope?.crypto?.randomUUID?.()||`live-root-${Date.now()}-${Math.random().toString(16).slice(2)}`;
  }
  function isLikelyBinaryArtifact(prefix,{name="",type=""}={}){
    const bytes=prefix instanceof Uint8Array?prefix:new Uint8Array(prefix||[]),extension=clean(name).toLowerCase().match(/\.([^.]+)$/)?.[1]||"";
    if(BINARY_EXTENSIONS.has(extension))return true;
    const starts=(...values)=>values.every((value,index)=>bytes[index]===value),ascii=value=>[...value].every((char,index)=>bytes[index]===char.charCodeAt(0));
    if(starts(0x89,0x50,0x4e,0x47)||starts(0xff,0xd8,0xff)||ascii("GIF8")||starts(0x50,0x4b,0x03,0x04)||starts(0x50,0x4b,0x05,0x06)||starts(0x50,0x4b,0x07,0x08)||starts(0x1f,0x8b)||starts(0x37,0x7a,0xbc,0xaf)||ascii("Rar!")||ascii("%PDF")||ascii("\x7fELF")||starts(0x4d,0x5a)||ascii("SQLite format 3"))return true;
    if(bytes.some(byte=>byte===0))return true;
    let controls=0;for(const byte of bytes)if(byte<32&&![8,9,10,12,13,27].includes(byte))controls++;
    if(bytes.length>=16&&controls/bytes.length>0.08)return true;
    return /^application\/(?:octet-stream|pdf|zip|gzip|x-7z-compressed)$/i.test(clean(type));
  }
  function requestPromise(request){return new Promise((resolve,reject)=>{request.onsuccess=()=>resolve(request.result);request.onerror=()=>reject(request.error||new Error("IndexedDB request failed."));});}
  function transactionPromise(transaction){return new Promise((resolve,reject)=>{transaction.oncomplete=()=>resolve();transaction.onerror=()=>reject(transaction.error||new Error("IndexedDB transaction failed."));transaction.onabort=()=>reject(transaction.error||new Error("IndexedDB transaction was aborted."));});}

  class MemoryLiveImportStore{
    constructor(seed={}){this.settings=seed.settings||null;this.ledger=new Map((seed.ledger||[]).map(row=>[row.storageKey||`${row.rootId}|${row.key}`,{...row}]));}
    async loadSettings(){return this.settings?{...this.settings}:null;}
    async saveSettings(value){this.settings={...value};return this.settings;}
    async loadLedger(rootId){return [...this.ledger.values()].filter(row=>row.rootId===rootId).map(row=>({...row}));}
    async saveLedger(value){this.ledger.set(value.storageKey,{...value});return value;}
    async deleteLedger(rootId,key){const storageKey=String(key||"").includes("|")?String(key):`${rootId}|${String(key||"").toLowerCase()}`;return this.ledger.delete(storageKey);}
  }

  class IndexedDbLiveImportStore{
    constructor(indexedDb,{databaseName=DB_NAME}={}){this.indexedDb=indexedDb;this.databaseName=databaseName;this.databasePromise=null;}
    open(){
      if(this.databasePromise)return this.databasePromise;
      this.databasePromise=new Promise((resolve,reject)=>{
        const request=this.indexedDb.open(this.databaseName,DB_VERSION);
        request.onupgradeneeded=()=>{
          const database=request.result;
          if(!database.objectStoreNames.contains("settings"))database.createObjectStore("settings",{keyPath:"id"});
          if(!database.objectStoreNames.contains("ledger")){const store=database.createObjectStore("ledger",{keyPath:"storageKey"});store.createIndex("rootId","rootId",{unique:false});}
        };
        request.onsuccess=()=>resolve(request.result);request.onerror=()=>reject(request.error||new Error("Live Import storage could not be opened."));
      });
      return this.databasePromise;
    }
    async loadSettings(){const db=await this.open(),transaction=db.transaction("settings","readonly");return (await requestPromise(transaction.objectStore("settings").get(SETTINGS_ID)))||null;}
    async saveSettings(value){const db=await this.open(),transaction=db.transaction("settings","readwrite");transaction.objectStore("settings").put({...value,id:SETTINGS_ID});await transactionPromise(transaction);return value;}
    async loadLedger(rootId){
      const db=await this.open(),transaction=db.transaction("ledger","readonly"),store=transaction.objectStore("ledger"),index=store.index("rootId");
      if(typeof IDBKeyRange!=="undefined")return await requestPromise(index.getAll(IDBKeyRange.only(rootId)));
      const rows=await requestPromise(store.getAll());return rows.filter(row=>row.rootId===rootId);
    }
    async saveLedger(value){const db=await this.open(),transaction=db.transaction("ledger","readwrite");transaction.objectStore("ledger").put(value);await transactionPromise(transaction);return value;}
    async deleteLedger(rootId,key){const storageKey=String(key||"").includes("|")?String(key):`${rootId}|${String(key||"").toLowerCase()}`,db=await this.open(),transaction=db.transaction("ledger","readwrite");transaction.objectStore("ledger").delete(storageKey);await transactionPromise(transaction);return true;}
  }

  function createStore(scope=globalThis){return scope?.indexedDB?new IndexedDbLiveImportStore(scope.indexedDB):new MemoryLiveImportStore();}

  class BrowserDirectoryAdapter{
    constructor(handle,{scope=globalThis,setTimer,clearTimer}={}){this.handle=handle;this.scope=scope;this.timers=createTimerApi(scope,{setTimer,clearTimer});this.observer=null;this.cancelled=false;}
    async queryPermission(){
      if(typeof this.handle?.queryPermission!=="function")return "prompt";
      try{return await this.handle.queryPermission({mode:"read"});}catch(_error){return "prompt";}
    }
    async requestPermission(){
      if(typeof this.handle?.requestPermission!=="function")return "denied";
      try{return await this.handle.requestPermission({mode:"read"});}catch(_error){return "denied";}
    }
    pathParts(relativePath){
      const normalized=core.normalizeRelativePath(relativePath),parts=normalized.split("/").filter(Boolean);
      if(!normalized||parts.some(part=>part==="."||part===".."))throw new DOMException("Unsafe staging path.","SecurityError");
      return parts;
    }
    async fileHandle(relativePath){
      const parts=this.pathParts(relativePath);let directory=this.handle;
      for(const segment of parts.slice(0,-1))directory=await directory.getDirectoryHandle(segment);
      return directory.getFileHandle(parts.at(-1));
    }
    async stat(relativePath){const handle=await this.fileHandle(relativePath),file=await handle.getFile();return {relativePath:core.normalizeRelativePath(relativePath),size:Number(file.size)||0,lastModified:Number(file.lastModified)||0,handle};}
    async readArtifact(relativePath){
      const handle=await this.fileHandle(relativePath),file=await handle.getFile();
      if(Number(file.size)>core.MAX_ARTIFACT_BYTES)return {file,size:file.size,lastModified:file.lastModified,text:"",signatureHex:"",metadataOnly:true,binary:false};
      const prefix=new Uint8Array(await file.slice(0,4096).arrayBuffer());
      const signatureHex=[...prefix.slice(0,4)].map(byte=>byte.toString(16).padStart(2,"0")).join("");
      const binary=isLikelyBinaryArtifact(prefix,{name:file.name,type:file.type});
      return {file,size:Number(file.size)||0,lastModified:Number(file.lastModified)||0,text:binary?"":await file.text(),signatureHex,binary};
    }
    async createImportFile(snapshot,physicalSourcePath,parseText,canonicalLogicalPath=""){
      const FileCtor=this.scope?.File||globalThis.File;if(typeof FileCtor!=="function")throw new Error("The browser File API is unavailable.");
      const sameText=String(parseText??"")===String(snapshot.text??""),parts=sameText?[snapshot.file]:[String(parseText??"")];
      const file=new FileCtor(parts,snapshot.file.name,{type:snapshot.file.type||"text/plain",lastModified:Number(snapshot.file.lastModified)||Date.now()});
      const physical=core.normalizeRelativePath(physicalSourcePath),canonical=core.normalizeRelativePath(canonicalLogicalPath)||physical;
      try{Object.defineProperty(file,"webkitRelativePath",{value:physical,configurable:true});}
      catch(_error){file.aerosRelativePath=physical;}
      try{Object.defineProperties(file,{aerosPhysicalSourcePath:{value:physical,configurable:true},aerosCanonicalLogicalPath:{value:canonical,configurable:true}});}
      catch(_error){file.aerosPhysicalSourcePath=physical;file.aerosCanonicalLogicalPath=canonical;}
      return file;
    }
    async companionFiles(route,rootName){
      const current=core.normalizeRelativePath(route?.relativePath),parts=current.split("/"),scansIndex=parts.map(part=>part.toLowerCase()).lastIndexOf("scans");
      if(scansIndex<0)return [];
      const base=parts.slice(0,scansIndex+1).join("/"),paths=[`${base}/_commands.log`,`${base}/_errors.log`],files=[];
      for(const path of paths){
        if(core.normalizeRelativePath(path)===current)continue;
        try{
          const snapshot=await this.readArtifact(path),physicalSourcePath=[rootName,path].filter(Boolean).join("/"),currentArtifactPath=core.normalizeRelativePath(route?.artifactPath),prefix=currentArtifactPath&&current.endsWith(currentArtifactPath)?current.slice(0,current.length-currentArtifactPath.length):"",artifactPath=prefix&&path.startsWith(prefix)?path.slice(prefix.length):path,companionRoute={...route,relativePath:path,artifactPath};
          const canonicalLogicalPath=core.artifactSourcePaths?.(companionRoute,path,rootName)?.canonicalLogicalPath||physicalSourcePath;files.push(await this.createImportFile(snapshot,physicalSourcePath,snapshot.text,canonicalLogicalPath));
        }
        catch(error){if(permissionError(error))throw error;}
      }
      return files;
    }
    async walk(onFile,{batchSize=WALK_BATCH_SIZE,maxDepth=32}={}){
      this.cancelled=false;let visited=0;
      const visit=async(directory,prefix,depth)=>{
        if(this.cancelled)return;if(depth>maxDepth)throw new Error("The staging directory is nested too deeply.");
        for await(const [name,handle] of directory.entries()){
          if(this.cancelled)return;
          const path=core.normalizeRelativePath([prefix,name].filter(Boolean).join("/"));if(!path)continue;
          if(handle.kind==="directory"){if(name.toLowerCase().startsWith(".aeros-transport-"))continue;await visit(handle,path,depth+1);}
          else if(handle.kind==="file"){
            const file=await handle.getFile();await onFile({relativePath:path,size:Number(file.size)||0,lastModified:Number(file.lastModified)||0,handle});
            visited++;if(visited%batchSize===0)await new Promise(resolve=>this.timers.set(resolve,0));
          }
        }
      };
      await visit(this.handle,"",0);return visited;
    }
    observerPath(record){
      const components=Array.isArray(record?.relativePathComponents)?record.relativePathComponents:[];
      if(components.length)return core.normalizeRelativePath(components.join("/"));
      if(typeof record?.relativePath==="string")return core.normalizeRelativePath(record.relativePath);
      if(Array.isArray(record?.path))return core.normalizeRelativePath(record.path.join("/"));
      return "";
    }
    async observe(callback){
      const Observer=this.scope?.FileSystemObserver;if(typeof Observer!=="function")return false;
      const observer=new Observer(records=>{
        const normalized=[];
        for(const record of Array.isArray(records)?records:[]){normalized.push({type:clean(record?.type||"changed").toLowerCase(),relativePath:this.observerPath(record),movedFromRelativePath:core.normalizeRelativePath(Array.isArray(record?.relativePathMovedFrom)?record.relativePathMovedFrom.join("/"):record?.relativePathMovedFrom||"")});}
        callback(normalized);
      });
      await observer.observe(this.handle,{recursive:true});this.cancelled=false;this.observer=observer;return true;
    }
    stop(){this.cancelled=true;try{this.observer?.disconnect?.();}catch(_error){}this.observer=null;}
  }

  const STATE_LABELS=Object.freeze({unsupported:"Unsupported",off:"Off","permission-required":"Permission required",watching:"Watching",processing:"Processing",degraded:"Watching / degraded",error:"Paused / error"});
  const ACTIVITY_LABELS=Object.freeze({discovered:"Discovered",receiving:"Receiving",processing:"Processing",waiting:"Waiting",complete:"Complete",processed:"Processed",error:"Error",skipped:"Skipped",missing:"Source missing",moved:"Source moved"});

  class LiveImportBrowserController{
    constructor(dependencies={},options={}){
      if(!core?.LiveImportCoordinator)throw new Error("Live Import core is unavailable.");
      for(const name of ["getWorkspace","classify","ingest"]){if(typeof dependencies[name]!=="function")throw new Error(`Live Import browser dependency is unavailable: ${name}`);}
      this.dependencies=dependencies;this.scope=options.scope||globalThis;this.document=options.document||this.scope?.document||null;this.store=options.store||createStore(this.scope);this.timers=createTimerApi(this.scope,{setTimer:options.setTimer,clearTimer:options.clearTimer});this.adapterFactory=options.adapterFactory||((handle)=>new BrowserDirectoryAdapter(handle,{scope:this.scope,setTimer:options.setTimer,clearTimer:options.clearTimer}));this.options=options;this.now=typeof options.now==="function"?options.now:Date.now;const configuredBoundary=Number(options.stableFileBoundaryMs);this.stableFileBoundaryMs=Number.isFinite(configuredBoundary)&&configuredBoundary>=0?configuredBoundary:STABLE_FILE_BOUNDARY_MS;
      this.capability=capabilities(this.scope);this.settings=null;this.adapter=null;this.coordinator=null;this.state=this.capability.supportsDirectoryAccess?"off":"unsupported";this.permission="prompt";this.observationMode="none";this.enabled=false;this.persistenceWarning="";this.snapshot={summary:{total:0,processed:0,updating:0,errors:0,skipped:0,complete:0,lastUpdate:""},entries:[],queueActive:0,queuePending:0};
      this.reconcileTimer=null;this.fallbackTimer=null;this.lastReconcileAt=0;this.reconcilePromise=null;this.workspaceSignature="";this.reconciliationError=null;this.reconciliationWarning="";this.reconciliationErrorCount=0;this.currentReconcilePath="";this.diagnostics=[];this.boundVisibility=()=>this.onVisibility();
    }
    recordDiagnostic(error,{phase="browser",path=""}={}){
      const diagnostic=error?.phase&&error?.message?{...error}:typeof core.errorDiagnostic==="function"?core.errorDiagnostic(error,{phase,path}):{name:clean(error?.name)||"Error",message:clean(error?.message||error)||"Unknown Live Import failure",stack:String(error?.stack||""),phase:clean(phase)||"browser",path:String(path??""),at:nowIso()};
      this.diagnostics.push({...diagnostic});if(this.diagnostics.length>100)this.diagnostics.splice(0,this.diagnostics.length-100);
      if(typeof this.dependencies.onDiagnostic==="function")try{Promise.resolve(this.dependencies.onDiagnostic({...diagnostic})).catch(()=>{});}catch(_error){}
      try{const logger=this.scope?.console;if(typeof logger?.error==="function")logger.error.call(logger,"AEROS Live Import diagnostic",diagnostic);}catch(_error){}
      return diagnostic;
    }
    displaySummary(){const summary={...(this.snapshot.summary||{})},artifactErrors=Number(summary.errors)||0;return {...summary,artifactErrors,reconciliationErrors:this.reconciliationErrorCount,errors:artifactErrors+(this.reconciliationError?1:0)};}
    runtimeState(){return this.reconciliationError?"degraded":this.snapshot.queueActive||this.snapshot.queuePending?"processing":"watching";}
    async initialize(){
      this.bindUi();
      if(!this.capability.supportsDirectoryAccess){this.render();return this.getStatus();}
      try{this.settings=await this.store.loadSettings();}catch(error){this.persistenceWarning=`Live Import settings could not be restored: ${error.message}`;}
      if(!this.settings?.handle){this.state="off";this.render();return this.getStatus();}
      this.adapter=this.adapterFactory(this.settings.handle);this.permission=await this.adapter.queryPermission();
      if(this.settings.enabled!==true){this.state="off";this.render();return this.getStatus();}
      if(this.permission!=="granted"){this.state="permission-required";this.render();return this.getStatus();}
      await this.startMonitoring();return this.getStatus();
    }
    bindUi(){
      this.document?.getElementById("liveImportChooseBtn")?.addEventListener("click",()=>this.chooseDirectory());
      this.document?.getElementById("liveImportToggleBtn")?.addEventListener("click",()=>this.toggle());
      this.scope?.addEventListener?.("focus",this.boundVisibility);
      this.document?.addEventListener?.("visibilitychange",this.boundVisibility);
    }
    async saveSettings(){
      if(!this.settings)return;
      try{await this.store.saveSettings({...this.settings,id:SETTINGS_ID,updatedAt:nowIso()});this.persistenceWarning="";}
      catch(error){this.persistenceWarning="This browser could not persist the directory handle; access may need to be selected again after reload.";}
    }
    async chooseDirectory(){
      if(!this.capability.supportsDirectoryAccess)return;
      try{
        let handle;
        try{handle=await this.scope.showDirectoryPicker({id:"aeros-live-import-staging",mode:"read",startIn:"documents"});}
        catch(error){if(error?.name!=="TypeError")throw error;handle=await this.scope.showDirectoryPicker({mode:"read"});}
        let same=false;if(this.settings?.handle&&typeof this.settings.handle.isSameEntry==="function")try{same=await this.settings.handle.isSameEntry(handle);}catch(_error){}
        this.settings={id:SETTINGS_ID,handle,rootName:clean(handle.name)||"AEROS_Import_Staging",rootId:same&&this.settings?.rootId?this.settings.rootId:randomId(this.scope),enabled:true,updatedAt:nowIso()};
        this.adapter?.stop();this.adapter=this.adapterFactory(handle);this.permission=await this.adapter.queryPermission();if(this.permission!=="granted")this.permission=await this.adapter.requestPermission();
        await this.saveSettings();if(this.permission==="granted")await this.startMonitoring();else{this.state="permission-required";this.render();}
      }catch(error){if(error?.name!=="AbortError"){this.state="error";this.persistenceWarning=error.message||"The staging directory could not be selected.";this.render();}}
    }
    async toggle(){
      if(this.enabled){await this.pause();return;}
      if(!this.settings?.handle){await this.chooseDirectory();return;}
      this.adapter=this.adapter||this.adapterFactory(this.settings.handle);this.permission=await this.adapter.queryPermission();
      if(this.permission!=="granted")this.permission=await this.adapter.requestPermission();
      if(this.permission!=="granted"){this.state="permission-required";this.render();return;}
      this.settings.enabled=true;await this.saveSettings();await this.startMonitoring();
    }
    async pause(){
      this.enabled=false;this.settings={...this.settings,enabled:false};await this.saveSettings();this.stopRuntime();this.state="off";this.render();
    }
    async buildCoordinator(){
      const rootId=this.settings.rootId,storedRows=await this.store.loadLedger(rootId).catch(()=>[]),rows=[];
      for(const row of storedRows){
        try{
          const semantic=await this.semanticForMetadata(row);
          if(semantic?.action==="ignore"){
            await this.store.deleteLedger?.(rootId,row.storageKey||row.key);
            if(typeof this.dependencies.onSemanticIgnore==="function")await this.dependencies.onSemanticIgnore({entry:{...row},semantic,route:null,phase:"ledger-preflight"});
            continue;
          }
        }catch(error){
          if(missingSourceError(error)){
            try{await this.store.deleteLedger?.(rootId,row.storageKey||row.key);}
            catch(cleanupError){this.recordDiagnostic(cleanupError,{phase:"stale-ledger-cleanup",path:row.relativePath||""});rows.push(row);}
            continue;
          }
          this.recordDiagnostic(error,{phase:"semantic-ledger-preflight",path:row.relativePath||""});
        }
        rows.push(row);
      }
      const coordinatorOptions=this.options.coordinatorOptions||{};
      this.coordinator=new core.LiveImportCoordinator({
        getWorkspace:this.dependencies.getWorkspace,
        classify:this.dependencies.classify,
        readArtifact:async path=>{try{return await this.adapter.readArtifact(path);}catch(error){if(permissionError(error))this.permissionLost();throw error;}},
        currentMetadata:async path=>{try{return await this.adapter.stat(path);}catch(error){if(permissionError(error))this.permissionLost();return null;}},
        createImportFile:(snapshot,physicalSourcePath,parseText,canonicalLogicalPath)=>this.adapter.createImportFile(snapshot,physicalSourcePath,parseText,canonicalLogicalPath),
        ingest:async payload=>{
          if(["nmap","scan-support","scan-tool"].includes(payload.detection?.type))payload.companionFiles=await this.adapter.companionFiles(payload.route,this.settings.rootName);
          const result=await this.dependencies.ingest(payload);
          if(result?.ok!==false)Promise.resolve().then(()=>this.coordinator?.workspaceChanged());
          return result;
        },
        ingestRaw:this.dependencies.ingestRaw,
        recordInventory:this.dependencies.recordInventory,
        removeProvisional:this.dependencies.removeProvisional,
        onManifest:this.dependencies.onManifest,
        isArtifactPresent:this.dependencies.isArtifactPresent,
        persistEntry:entry=>this.store.saveLedger({...entry,rootId,storageKey:`${rootId}|${entry.key}`}),
        removeEntry:entry=>this.store.deleteLedger?.(rootId,entry.storageKey||entry.key),
        semanticDisposition:this.dependencies.semanticDisposition,
        onSemanticIgnore:this.dependencies.onSemanticIgnore,
        onUpdate:snapshot=>this.onCoordinatorUpdate(snapshot),
        onDiagnostic:diagnostic=>this.recordDiagnostic(diagnostic)
      },{rootName:this.settings.rootName,entries:rows,enabled:true,setTimer:(callback,delay)=>this.timers.set(callback,delay),clearTimer:timer=>this.timers.clear(timer),...coordinatorOptions});
    }
    async startMonitoring(){
      this.stopRuntime();this.enabled=true;this.state="watching";this.observationMode="fallback";
      if(!this.coordinator||this.coordinator.queue?.stopped)await this.buildCoordinator();else{this.coordinator.setRootName(this.settings.rootName);this.coordinator.setEnabled(true);}
      if(this.capability.supportsObserver){
        try{if(await this.adapter.observe(records=>this.onObserverRecords(records)))this.observationMode="observer";}
        catch(error){const diagnostic=this.recordDiagnostic(error,{phase:"native-observer-start",path:this.settings?.rootName||""});this.observationMode="fallback";this.persistenceWarning=`Native observation failed; bounded reconciliation is active. ${diagnostic.name}: ${diagnostic.message}`;}
      }
      this.render();await this.reconcile();this.scheduleFallback();
    }
    stopRuntime(){
      this.adapter?.stop();if(this.reconcileTimer)try{this.timers.clear(this.reconcileTimer);}catch(error){this.recordDiagnostic(error,{phase:"reconcile-timer-clear",path:this.currentReconcilePath});}if(this.fallbackTimer)try{this.timers.clear(this.fallbackTimer);}catch(error){this.recordDiagnostic(error,{phase:"fallback-timer-clear",path:this.currentReconcilePath});}this.reconcileTimer=null;this.fallbackTimer=null;
      if(this.coordinator){this.coordinator.stop();}
    }
    permissionLost(){
      if(this.state==="permission-required")return;
      this.enabled=false;this.permission="denied";this.stopRuntime();this.state="permission-required";this.render();
    }
    async semanticForMetadata(metadata={}){
      if(typeof this.dependencies.semanticDisposition!=="function")return {action:"retain",kind:"ordinary-artifact"};
      let semantic=await this.dependencies.semanticDisposition({path:metadata.relativePath,relativePath:metadata.relativePath,metadata,contentAvailable:false,phase:"browser-recognition"});
      if(semantic?.action!=="inspect")return semantic;
      const snapshot=await this.adapter.readArtifact(metadata.relativePath);
      semantic=await this.dependencies.semanticDisposition({path:metadata.relativePath,relativePath:metadata.relativePath,metadata,snapshot,text:snapshot.text,contentAvailable:true,phase:"browser-content-recognition"});
      return semantic;
    }
    watchedRelativePath(reference={}){
      const candidate=typeof reference==="string"?reference:reference?.sourceRelativePath||reference?.physicalSourcePath||reference?.path||"";
      let path=core.normalizeRelativePath(candidate),rootName=core.normalizeRelativePath(this.settings?.rootName||"");
      if(rootName&&path.toLowerCase()===rootName.toLowerCase())path="";
      else if(rootName&&path.toLowerCase().startsWith(rootName.toLowerCase()+"/"))path=path.slice(rootName.length+1);
      if(!path)throw new DOMException("The watched artifact path is unavailable.","NotFoundError");
      return path;
    }
    async readCurrentSource(reference={}){
      if(!this.adapter||typeof this.adapter.readArtifact!=="function")throw new Error("The watched filesystem reader is unavailable in this browser session.");
      const relativePath=this.watchedRelativePath(reference);
      try{
        const snapshot=await this.adapter.readArtifact(relativePath);
        if(snapshot?.binary===true)throw new Error("The current watched source is binary and cannot be rendered as text.");
        if(snapshot?.metadataOnly===true)throw new Error("The current watched source exceeds the bounded automatic text-read limit.");
        if(typeof snapshot?.text!=="string")throw new Error("The current watched source did not return text.");
        if(Number(snapshot.size)>0&&!snapshot.text.length)throw new Error("The current watched source returned no text for a nonempty artifact.");
        return {text:snapshot.text,size:Number(snapshot.size)||0,lastModified:Number(snapshot.lastModified)||0,signatureHex:String(snapshot.signatureHex||""),relativePath,sourceKind:"provisional-current"};
      }catch(error){if(permissionError(error))this.permissionLost();throw error;}
    }
    async observeMetadata(metadata={},options={}){
      const semantic=options.semantic||await this.semanticForMetadata(metadata);
      return this.coordinator.observe(metadata,{...options,semantic});
    }
    async onObserverRecords(records=[]){
      if(!this.enabled)return;let unknown=false;
      for(const record of records){
        try{
          const path=core.normalizeRelativePath(record.relativePath);if(!path){unknown=true;continue;}
          if(["disappeared","deleted"].includes(record.type)){await this.coordinator.markMissing(path);continue;}
          const metadata=await this.adapter.stat(path);
          if(record.type==="moved"){
            const previous=core.normalizeRelativePath(record.movedFromRelativePath);
            if(previous){
              if(typeof this.coordinator.move==="function"){const semantic=await this.semanticForMetadata(metadata);await this.coordinator.move(previous,path,metadata,{semantic});}
              else{
                await this.coordinator.markMissing(previous,{movedTo:path,reason:"source-moved"});
                await this.observeMetadata(metadata);
              }
              continue;
            }
          }
          await this.observeMetadata(metadata,{force:["changed","modified","replaced"].includes(record.type),explicitEvent:record.type});
        }catch(error){
          if(permissionError(error)){this.permissionLost();return;}
          const path=core.normalizeRelativePath(record.relativePath);
          if(error?.name==="NotFoundError"&&path)await this.coordinator.markMissing(path);else{unknown=true;this.recordDiagnostic(error,{phase:"native-observer-record",path});}
        }
      }
      if(unknown)this.scheduleReconcile(1200);
    }
    scheduleReconcile(delay=1200){
      if(!this.enabled)return;if(this.reconcileTimer)this.timers.clear(this.reconcileTimer);
      this.reconcileTimer=this.timers.set(()=>{this.reconcileTimer=null;this.reconcile();},delay);
    }
    scheduleFallback(){
      if(!this.enabled)return;if(this.fallbackTimer)this.timers.clear(this.fallbackTimer);
      const hidden=this.document?.visibilityState==="hidden",delay=this.observationMode==="observer"?OBSERVER_RECONCILE_MS:(hidden?FALLBACK_HIDDEN_MS:FALLBACK_VISIBLE_MS);
      this.fallbackTimer=this.timers.set(()=>{this.fallbackTimer=null;this.reconcile().finally(()=>this.scheduleFallback());},delay);
    }
    async reconcile(){
      if(!this.enabled||this.reconcilePromise)return this.reconcilePromise;
      this.state="processing";this.render();
      this.reconcilePromise=(async()=>{
        const seen=new Set();let phase="reconcile-walk";
        try{
          await this.adapter.walk(async metadata=>{
            if(!core.isPotentialArtifactPath(metadata.relativePath))return;
            this.currentReconcilePath=core.normalizeRelativePath(metadata.relativePath);phase="reconcile-observe";const observed=await this.observeMetadata(metadata,{reconciliation:true,stableFileBoundary:stableFileBoundary(metadata,this.now(),this.stableFileBoundaryMs)});if(!observed?.ignored)seen.add(this.currentReconcilePath.toLowerCase());this.currentReconcilePath="";phase="reconcile-walk";
          },{batchSize:WALK_BATCH_SIZE});
          phase="reconcile-mark-unseen";await this.coordinator.markUnseenMissing(seen);this.lastReconcileAt=Date.now();this.currentReconcilePath="";this.reconciliationError=null;this.reconciliationWarning="";
        }catch(error){if(permissionError(error)){this.permissionLost();return;}const diagnostic=this.recordDiagnostic(error,{phase,path:this.currentReconcilePath});this.reconciliationError=diagnostic;this.reconciliationErrorCount++;this.reconciliationWarning=`Directory reconciliation degraded after an error: ${diagnostic.name}: ${diagnostic.message}${diagnostic.path?` (${diagnostic.path})`:""}`;}
      })().finally(()=>{this.reconcilePromise=null;if(this.enabled){this.state=this.runtimeState();this.render();}});
      return this.reconcilePromise;
    }
    onCoordinatorUpdate(snapshot){
      this.snapshot=snapshot||this.snapshot;if(this.enabled)this.state=this.runtimeState();this.render();
    }
    onVisibility(){
      if(!this.enabled)return;const visible=this.document?.visibilityState!=="hidden";
      if(visible&&Date.now()-this.lastReconcileAt>=FOCUS_RECONCILE_MIN_MS)this.scheduleReconcile(350);
      this.scheduleFallback();
    }
    workspaceChanged(){
      if(!this.enabled||!this.coordinator)return;
      const workspace=this.dependencies.getWorkspace()||{},hosts=Object.values(workspace.hosts||{}).map(host=>clean(host?.id||host?.ip)).sort(),signature=[clean(workspace.engagementName||workspace.projectName),...hosts].join("|");
      if(signature===this.workspaceSignature)return;this.workspaceSignature=signature;Promise.resolve(this.coordinator.workspaceChanged()).catch(error=>this.recordDiagnostic(error,{phase:"workspace-change",path:""}));this.scheduleReconcile(600);
    }
    relativeTime(value){
      const at=new Date(value).getTime();if(!Number.isFinite(at))return "Never";const seconds=Math.max(0,Math.round((Date.now()-at)/1000));
      if(seconds<5)return "just now";if(seconds<60)return `${seconds}s ago`;const minutes=Math.round(seconds/60);if(minutes<60)return `${minutes}m ago`;return new Date(at).toLocaleString();
    }
    render(){
      if(!this.document)return;
      const control=this.document.getElementById("liveImportControl"),stateNode=this.document.getElementById("liveImportState"),folder=this.document.getElementById("liveImportFolder"),metrics=this.document.getElementById("liveImportMetrics"),last=this.document.getElementById("liveImportLastUpdate"),activity=this.document.getElementById("liveImportActivity"),choose=this.document.getElementById("liveImportChooseBtn"),toggle=this.document.getElementById("liveImportToggleBtn"),notice=this.document.getElementById("liveImportNotice");
      if(!control)return;const summary=this.displaySummary(),label=STATE_LABELS[this.state]||"Off",operational=["watching","processing","degraded"].includes(this.state);control.dataset.state=this.state;
      if(stateNode)stateNode.textContent=operational?`${label} · ${summary.updating||0} updating · ${summary.processed||0} processed`:label;
      if(folder)folder.textContent=this.settings?.rootName?`${operational?"Watching":"Selected"}: ${this.settings.rootName}`:"Choose the AEROS_Import_Staging root to begin.";
      if(metrics)metrics.textContent=`${summary.updating||0} updating · ${summary.processed||0} processed · ${summary.errors||0} errors`;
      if(last)last.textContent=`Last update: ${summary.lastUpdate?this.relativeTime(summary.lastUpdate):"never"} · ${this.observationMode==="observer"?"Native observation":"Bounded reconciliation"}`;
      if(notice){notice.textContent=this.reconciliationWarning||this.persistenceWarning||"Only the explicitly authorized directory is monitored. Existing evidence is retained when Live Import is paused or a source disappears.";notice.classList.toggle("is-warning",Boolean(this.reconciliationWarning||this.persistenceWarning));}
      if(choose){choose.disabled=!this.capability.supportsDirectoryAccess;choose.textContent=this.settings?.handle?"Change folder":"Choose folder";}
      if(toggle){toggle.disabled=this.state==="unsupported"||!this.settings?.handle;toggle.textContent=this.enabled?"Pause":this.state==="permission-required"?"Grant access":"Resume";}
      if(activity){
        activity.replaceChildren();const rows=(this.snapshot.entries||[]).slice(0,10);
        if(!rows.length){const empty=this.document.createElement("div");empty.className="live-import-empty";empty.textContent="No staging artifacts have been observed.";activity.appendChild(empty);}
        for(const row of rows){
          const item=this.document.createElement("article");item.className="live-import-activity-row";
          const main=this.document.createElement("div"),title=this.document.createElement("strong"),meta=this.document.createElement("small"),badge=this.document.createElement("span"),reason=this.document.createElement("p");
          title.textContent=row.filename||row.relativePath||"Artifact";meta.textContent=[row.host,row.parserType||row.detectedType,row.relativePath].filter(Boolean).join(" · ");main.append(title,meta);
          badge.className=`live-import-activity-state state-${String(row.state||"waiting").replace(/[^a-z-]/g,"")}`;badge.textContent=ACTIVITY_LABELS[row.state]||row.state||"Waiting";
          reason.textContent=row.reason||"Waiting for a stable artifact state.";item.append(main,badge,reason);activity.appendChild(item);
        }
      }
    }
    getStatus(){return {state:this.state,permission:this.permission,enabled:this.enabled,observationMode:this.observationMode,capabilities:this.capability,rootName:this.settings?.rootName||"",summary:this.displaySummary(),persistenceWarning:this.reconciliationWarning||this.persistenceWarning,reconciliationError:this.reconciliationError?{...this.reconciliationError}:null,diagnostics:this.diagnostics.map(row=>({...row}))};}
    destroy(){this.enabled=false;this.stopRuntime();this.scope?.removeEventListener?.("focus",this.boundVisibility);this.document?.removeEventListener?.("visibilitychange",this.boundVisibility);}
  }

  return Object.freeze({DB_NAME,DB_VERSION,SETTINGS_ID,FALLBACK_VISIBLE_MS,FALLBACK_HIDDEN_MS,OBSERVER_RECONCILE_MS,STABLE_FILE_BOUNDARY_MS,WALK_BATCH_SIZE,BINARY_EXTENSIONS,isLikelyBinaryArtifact,stableFileBoundary,capabilities,createTimerApi,MemoryLiveImportStore,IndexedDbLiveImportStore,BrowserDirectoryAdapter,LiveImportBrowserController,create:(dependencies,options)=>new LiveImportBrowserController(dependencies,options)});
});
