(function(root,factory){
  const api=factory();
  if(typeof module==="object"&&module.exports)module.exports=api;
  if(root)root.AEROSPersistence=api;
})(typeof window!=="undefined"?window:globalThis,function(){
  "use strict";

  const APPLICATION_STATE_KEYS=Object.freeze([
    "labs","profiles","commandPaths","serverAvailable","dynamicNotes","dynamicNoteRoot",
    "dynamicNoteCount","dynamicNoteError"
  ]);
  const FORBIDDEN_JSON_KEYS=new Set(["__proto__","prototype","constructor"]);
  const MAX_IMPORT_DEPTH=64;
  const MAX_IMPORT_NODES=250000;
  const LOCAL_STORAGE_OMITTED_KEYS=new Set(["secret","password","secretValue","imageDataUrl","dataUrl"]);

  function isPlainObject(value){
    if(!value||typeof value!=="object"||Array.isArray(value))return false;
    const prototype=Object.getPrototypeOf(value);
    return prototype===Object.prototype||prototype===null;
  }

  function sanitizeImportedValue(value,context={nodes:0},depth=0){
    context.nodes++;
    if(context.nodes>MAX_IMPORT_NODES)throw new Error("Imported JSON contains too many values.");
    if(depth>MAX_IMPORT_DEPTH)throw new Error("Imported JSON is nested too deeply.");
    if(value===null||typeof value==="boolean"||typeof value==="number"||typeof value==="string")return value;
    if(Array.isArray(value))return value.map(item=>sanitizeImportedValue(item,context,depth+1));
    if(!isPlainObject(value))throw new Error("Imported JSON contains an unsupported value.");
    const clean={};
    Object.keys(value).forEach(key=>{
      if(FORBIDDEN_JSON_KEYS.has(key))throw new Error(`Imported JSON contains a forbidden key: ${key}`);
      clean[key]=sanitizeImportedValue(value[key],context,depth+1);
    });
    return clean;
  }

  function validateImportedState(value){
    if(!isPlainObject(value))throw new Error("Imported JSON must contain one engagement object.");
    const clean=sanitizeImportedValue(value);
    const name=String(clean.projectName||clean.labName||"").trim();
    if(!name||name.length>160||/[\u0000-\u001f\u007f]/.test(name))throw new Error("Imported engagement name is missing or invalid.");
    if(!isPlainObject(clean.hosts))throw new Error("Imported engagement hosts must be an object.");
    if(Object.keys(clean.hosts).length>10000)throw new Error("Imported engagement contains too many hosts.");
    for(const field of ["observations","findings","movements","tunnels","assetGroups"]){
      if(field in clean&&!Array.isArray(clean[field]))throw new Error(`Imported engagement ${field} must be an array.`);
    }
    if("engagementConfig" in clean&&!isPlainObject(clean.engagementConfig))throw new Error("Imported engagement configuration must be an object.");
    clean.projectName=name;
    delete clean.labName;
    return clean;
  }

  function requireDependencies(dependencies){
    const required=["getState","storage","sanitizeState","normalizeLoadedState"];
    const missing=required.filter(name=>typeof dependencies?.[name]!=="function"&&name!=="storage");
    if(!dependencies?.storage||typeof dependencies.storage.getItem!=="function"||typeof dependencies.storage.setItem!=="function")missing.push("storage");
    if(missing.length)throw new Error(`AEROS persistence dependencies are unavailable: ${[...new Set(missing)].join(", ")}`);
  }

  function createPersistence(dependencies){
    requireDependencies(dependencies);
    const storageKey=String(dependencies.storageKey||"aeros-state-v1");
    const legacyKeys=Array.isArray(dependencies.legacyStorageKeys)?dependencies.legacyStorageKeys:[];
    let lastSerialized="";

    function persist(){
      const state=dependencies.getState();
      dependencies.sanitizeState(state);
      const serialized=JSON.stringify(state,(key,value)=>LOCAL_STORAGE_OMITTED_KEYS.has(key)?undefined:value);
      if(serialized!==lastSerialized){
        dependencies.storage.setItem(storageKey,serialized);
        lastSerialized=serialized;
      }
      return state;
    }

    function replaceState(incoming,{preserveApplication=false}={}){
      const state=dependencies.getState();
      const application=preserveApplication?applicationState():null;
      Object.keys(state).forEach(key=>delete state[key]);
      Object.assign(state,incoming||{});
      if(application)Object.assign(state,application);
      return state;
    }

    function load(){
      let raw=dependencies.storage.getItem(storageKey),legacyKey="";
      if(!raw){
        for(const key of legacyKeys){
          raw=dependencies.storage.getItem(key);
          if(raw){legacyKey=key;break;}
        }
      }
      if(!raw){dependencies.normalizeLoadedState(dependencies.getState());return false;}
      try{
        const parsed=sanitizeImportedValue(JSON.parse(raw));
        if(!parsed||typeof parsed!=="object"||Array.isArray(parsed))return false;
        replaceState(parsed);
        dependencies.normalizeLoadedState(dependencies.getState());
        persist();
        if(legacyKey&&typeof dependencies.storage.removeItem==="function"){
          try{dependencies.storage.removeItem(legacyKey);}catch(error){}
        }
        return true;
      }catch(error){
        return false;
      }
    }

    function applicationState(){
      const state=dependencies.getState(),snapshot={};
      APPLICATION_STATE_KEYS.forEach(key=>{
        const value=state[key];
        if(Array.isArray(value))snapshot[key]=value.slice();
        else if(value&&typeof value==="object")snapshot[key]={...value};
        else snapshot[key]=value;
      });
      return snapshot;
    }

    function engagementState(){
      const state=dependencies.getState(),snapshot={};
      Object.keys(state).forEach(key=>{if(!APPLICATION_STATE_KEYS.includes(key))snapshot[key]=state[key];});
      return snapshot;
    }

    function replaceEngagementState(incoming){
      return replaceState(validateImportedState(incoming),{preserveApplication:true});
    }

    return Object.freeze({persist,load,applicationState,engagementState,replaceEngagementState});
  }

  return Object.freeze({APPLICATION_STATE_KEYS,validateImportedState,create:createPersistence});
});
