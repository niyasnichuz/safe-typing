const $=id=>document.getElementById(id);
const enc=new TextEncoder(), dec=new TextDecoder();
let key=null, notes=[], editing=null;
const DB="safeTypingVaultV1";
function show(id){["setup","login","app"].forEach(x=>$(x).classList.toggle("hidden",x!==id));}
function b64(buf){return btoa(String.fromCharCode(...new Uint8Array(buf)));}
function un64(s){return Uint8Array.from(atob(s),c=>c.charCodeAt(0));}
async function derive(password,salt){const material=await crypto.subtle.importKey("raw",enc.encode(password),"PBKDF2",false,["deriveKey"]);return crypto.subtle.deriveKey({name:"PBKDF2",salt,iterations:310000,hash:"SHA-256"},material,{name:"AES-GCM",length:256},false,["encrypt","decrypt"]);}
async function encrypt(data,k=key){const iv=crypto.getRandomValues(new Uint8Array(12));const ct=await crypto.subtle.encrypt({name:"AES-GCM",iv},k,enc.encode(JSON.stringify(data)));return {iv:b64(iv),data:b64(ct)};}
async function decrypt(blob,k=key){const plain=await crypto.subtle.decrypt({name:"AES-GCM",iv:un64(blob.iv)},k,un64(blob.data));return JSON.parse(dec.decode(plain));}
function readVault(){try{return JSON.parse(localStorage.getItem(DB));}catch{return null;}}
async function saveVault(){const vault=readVault();vault.payload=await encrypt(notes);localStorage.setItem(DB,JSON.stringify(vault));}
async function create(){const p=$("newPass").value,c=$("confirmPass").value;if(p.length<10){$("setupStatus").textContent="Use at least 10 characters.";return;}if(p!==c){$("setupStatus").textContent="Passwords do not match.";return;}const salt=crypto.getRandomValues(new Uint8Array(16));key=await derive(p,salt);notes=[];localStorage.setItem(DB,JSON.stringify({salt:b64(salt),payload:await encrypt(notes)}));$("newPass").value=$("confirmPass").value="";show("app");render();}
async function unlock(){try{const v=readVault();key=await derive($("pass").value,un64(v.salt));notes=await decrypt(v.payload);$("pass").value="";$("loginStatus").textContent="";show("app");render();}catch{$("loginStatus").textContent="Password incorrect, or vault data could not be read.";key=null;}}
function render(){const root=$("notes");root.innerHTML="";if(!notes.length){root.innerHTML='<p class="hint">No notes yet. Tap “New note” to create one.</p>';return;}notes.slice().sort((a,b)=>b.updated-a.updated).forEach(n=>{const d=document.createElement("div");d.className="note";const t=document.createElement("strong");t.textContent=n.title||"Untitled";const s=document.createElement("small");s.textContent=new Date(n.updated).toLocaleString();d.append(t,s);d.onclick=()=>edit(n.id);root.append(d);});}
function edit(id=null){editing=id;const n=notes.find(x=>x.id===id);$("editor").classList.remove("hidden");$("editorTitle").textContent=id?"Edit note":"New note";$("title").value=n?.title||"";$("body").value=n?.body||"";$("deleteBtn").classList.toggle("hidden",!id);$("title").focus();}
async function save(){const title=$("title").value.trim(),body=$("body").value;if(!title&&!body){$("appStatus").textContent="Write a title or some note text first.";return;}if(editing){const n=notes.find(x=>x.id===editing);n.title=title;n.body=body;n.updated=Date.now();}else notes.push({id:crypto.randomUUID(),title,body,updated:Date.now()});await saveVault();$("editor").classList.add("hidden");$("appStatus").textContent="Saved securely on this device.";render();}
$("createBtn").onclick=create;$("unlockBtn").onclick=unlock;$("newBtn").onclick=()=>edit();$("saveBtn").onclick=save;$("cancelBtn").onclick=()=>$("editor").classList.add("hidden");
$("deleteBtn").onclick=async()=>{if(!editing||!confirm("Delete this note permanently?"))return;notes=notes.filter(n=>n.id!==editing);await saveVault();$("editor").classList.add("hidden");render();};
$("lockBtn").onclick=()=>{key=null;notes=[];$("editor").classList.add("hidden");show("login");};
$("backupBtn").onclick=()=>{const blob=new Blob([JSON.stringify(readVault())],{type:"application/json"});const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download="safe-typing-encrypted-backup.json";a.click();URL.revokeObjectURL(a.href);$("appStatus").textContent="Encrypted backup exported. Store it safely.";};
$("restoreBtn").onclick=()=>$("backupFile").click();
$("backupFile").onchange=async e=>{const f=e.target.files[0];if(!f)return;try{const v=JSON.parse(await f.text());if(!v.salt||!v.payload)throw Error();if(!confirm("Importing replaces all notes in this vault. Continue?"))return;const p=prompt("Enter the password used for this backup:");if(p===null)return;const k=await derive(p,un64(v.salt));const imported=await decrypt(v.payload,k);if(!Array.isArray(imported))throw Error();localStorage.setItem(DB,JSON.stringify(v));key=k;notes=imported;render();$("appStatus").textContent="Backup restored."; }catch{$("appStatus").textContent="Could not restore. Check the backup file and password.";}e.target.value="";};
if(!window.crypto?.subtle){alert("This browser does not support secure encryption. Please use a modern browser over HTTPS.");}
if(!readVault())show("setup");else show("login");
if("serviceWorker" in navigator)navigator.serviceWorker.register("sw.js").catch(()=>{});
