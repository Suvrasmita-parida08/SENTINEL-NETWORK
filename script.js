/* ~350 lines — main logic for auth, biometric camera, device register/scan/block/unblock, persistence, UI rendering */

/* -----------------------
   Utility / storage helpers
   ----------------------- */
function loadUsers() { return JSON.parse(localStorage.getItem('sentinel_users') || '{}'); }
function saveUsers(users) { localStorage.setItem('sentinel_users', JSON.stringify(users)); }
function getCurrentUser() { return sessionStorage.getItem('sentinel_current') || null; }
function setCurrentUser(u) { if(u) sessionStorage.setItem('sentinel_current', u); else sessionStorage.removeItem('sentinel_current'); }

/* per-user keys: users[username] = { passwordHash, bio: {faceEnrolled:bool, webauthnId?}, devices:[], blocked:[], log:[] } */

/* simple SHA-256 based hash for demo (not for production) */
async function simpleHash(text){
  const enc = new TextEncoder().encode(text);
  const d = await crypto.subtle.digest('SHA-256', enc);
  return bufferToBase64Url(d);
}
function bufferToBase64Url(buffer) {
  const bytes = new Uint8Array(buffer);
  let str = '';
  for (const b of bytes) str += String.fromCharCode(b);
  return btoa(str).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}
function base64UrlToBuffer(base64url) {
  const b64 = base64url.replace(/-/g,'+').replace(/_/g,'/');
  const pad = b64.length % 4 === 0 ? '' : '='.repeat(4 - (b64.length % 4));
  const bin = atob(b64 + pad);
  const arr = new Uint8Array(bin.length);
  for (let i=0;i<bin.length;i++) arr[i] = bin.charCodeAt(i);
  return arr.buffer;
}

/* -----------------------
   Demo auth flows: register/login
   ----------------------- */
async function demoRegisterUser(username, password, meta={}){
  if(!username || !password) throw new Error('username & password required');
  const users = loadUsers();
  if(users[username]) throw new Error('username exists');
  const ph = await simpleHash(password);
  users[username] = { passwordHash: ph, bio: { faceEnrolled:false, webauthnId:null }, devices: [], blocked: [], log: [] , meta: meta || {} };
  saveUsers(users);
  return true;
}

async function demoLoginWithPassword(username,password){
  if(!username || !password) throw new Error('Enter username & password');
  const users = loadUsers();
  const u = users[username];
  if(!u) throw new Error('User not found');
  const h = await simpleHash(password);
  if(h !== u.passwordHash) throw new Error('Invalid credentials');
  setCurrentUser(username);
  return true;
}

async function demoLogout(){
  setCurrentUser(null);
}

/* -----------------------
   WebAuthn demo helpers (create/get) - optional
   ----------------------- */
async function createWebAuthnForUser(username){
  if(!window.PublicKeyCredential) throw new Error('WebAuthn not available in this browser');
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const userId = new TextEncoder().encode(username);
  const publicKey = {
    challenge,
    rp: { name: 'Sentinel Demo' },
    user: { id: userId, name: username, displayName: username },
    pubKeyCredParams: [{ type:'public-key', alg: -7 }, { type:'public-key', alg: -257 }],
    timeout: 60000,
    attestation: 'none'
  };
  const cred = await navigator.credentials.create({ publicKey });
  if(!cred) throw new Error('Credential creation failed');
  const id = bufferToBase64Url(cred.rawId);
  const users = loadUsers();
  users[username] = users[username] || { passwordHash:null, bio:{}, devices:[], blocked:[], log:[] };
  users[username].bio = users[username].bio || {};
  users[username].bio.webauthnId = id;
  saveUsers(users);
  return true;
}

async function loginWithWebAuthn(){
  const username = document.getElementById('auth-username')?.value?.trim();
  if(!username) throw new Error('Enter username for WebAuthn login');
  const users = loadUsers();
  const u = users[username];
  if(!u || !u.bio || !u.bio.webauthnId) throw new Error('No WebAuthn credential for this user');
  const allowedId = base64UrlToBuffer(u.bio.webauthnId);
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const publicKey = { challenge, timeout:60000, allowCredentials: [{ id: allowedId, type: 'public-key' }], userVerification: 'preferred' };
  const assertion = await navigator.credentials.get({ publicKey });
  if(!assertion) throw new Error('Authentication failed');
  setCurrentUser(username);
  return true;
}

/* -----------------------
   Face camera demo: open camera, simulate verification
   ----------------------- */
let cameraStreamRef = null;
async function openFaceCamera(videoElId){
  const vid = document.getElementById(videoElId);
  if(!vid) throw new Error('Video element not found');
  try {
    const stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode:'user' }});
    vid.srcObject = stream;
    cameraStreamRef = stream;
    vid.classList.remove('hidden');
    return true;
  } catch(err){
    throw new Error('Camera access denied: ' + err.message);
  }
}
function stopFaceCamera(videoElId){
  const vid = document.getElementById(videoElId);
  if(vid && vid.srcObject){
    vid.srcObject.getTracks().forEach(t => t.stop());
    vid.srcObject = null;
  }
  cameraStreamRef = null;
  if(vid) vid.classList.add('hidden');
}

/* demoFaceAuth: purpose = 'enroll' or 'login'. If enroll, store faceEnrolled:true for that username.
   If login, attempts to locate any user with enrolled face (or uses provided username) and sets session.
   The "verification" is simulated by waiting a few seconds and checking video brightness / movement optionally.
*/
async function demoFaceAuth({ purpose='login', username=null } = {}){
  // show camera, simulate detection
  const vidIdLogin = document.getElementById('login-face-video') ? 'login-face-video' : null;
  const vidIdSignup = document.getElementById('signup-face-video') ? 'signup-face-video' : null;
  // choose visible video element
  let videoElId = vidIdLogin || vidIdSignup || 'face-video';
  await openFaceCamera(videoElId);
  // basic auto-check: sample one frame to ensure there is some brightness (very rough)
  const ok = await _waitForFaceSample(videoElId, 3500);
  stopFaceCamera(videoElId);
  if(!ok) throw new Error('Face not detected. Try again with camera facing you.');
  // enroll or login
  const users = loadUsers();
  if(purpose === 'enroll'){
    if(!username) throw new Error('username required for enroll');
    users[username] = users[username] || { passwordHash:null, devices:[], blocked:[], bio:{} , log:[] };
    users[username].bio = users[username].bio || {};
    users[username].bio.faceEnrolled = true;
    saveUsers(users);
    return true;
  } else { // login
    // if username provided, prefer that but require faceEnrolled true
    if(username){
      const u = users[username];
      if(!u || !u.bio || !u.bio.faceEnrolled) throw new Error('No face enrolled for this username');
      setCurrentUser(username);
      return true;
    }
    // else, try to find any user with faceEnrolled true (demo convenience)
    const keys = Object.keys(users);
    for(const k of keys){
      if(users[k].bio && users[k].bio.faceEnrolled){
        setCurrentUser(k);
        return true;
      }
    }
    throw new Error('No enrolled face found for any user');
  }
}

/* internal: sample video frame brightness to fake-check for a face presence */
function _waitForFaceSample(videoElId, timeout=3000){
  return new Promise((resolve)=>{
    const video = document.getElementById(videoElId);
    if(!video) return resolve(false);
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    let elapsed = 0;
    const interval = 300;
    const t = setInterval(()=>{
      elapsed += interval;
      try {
        canvas.width = video.videoWidth || 320;
        canvas.height = video.videoHeight || 240;
        ctx.drawImage(video,0,0,canvas.width,canvas.height);
        const data = ctx.getImageData(0,0,canvas.width,canvas.height).data;
        // compute average brightness
        let sum=0, count=0;
        for(let i=0;i<data.length;i+=4){ sum += data[i] + data[i+1] + data[i+2]; count++; }
        const avg = (sum / (count*3));
        // if average brightness higher than a threshold, we assume some face/presence (very rough)
        if(avg > 50){ clearInterval(t); resolve(true); }
      } catch(e){
        // ignore drawing errors
      }
      if(elapsed >= timeout){ clearInterval(t); resolve(false); }
    }, interval);
  });
}

/* -----------------------
   Per-user device data helpers
   ----------------------- */
function getUserObject(){
  const cur = getCurrentUser();
  if(!cur) return null;
  const users = loadUsers();
  users[cur] = users[cur] || { passwordHash:null, bio:{}, devices:[], blocked:[], log:[] };
  return users[cur];
}
function persistUserObject(uObj){
  const cur = getCurrentUser(); if(!cur) return;
  const users = loadUsers();
  users[cur] = uObj;
  saveUsers(users);
}

/* -----------------------
   Device register / UI / persistence
   ----------------------- */
function renderAllLists(filter=''){
  const u = getUserObject();
  const devices = (u && u.devices) ? u.devices : [];
  const blocked = (u && u.blocked) ? u.blocked : [];
  const detected = window._detectedDevices || [];
  renderRegisteredList(devices, filter);
  renderBlockedList(blocked, filter);
  renderDetectedList(detected, filter);
  renderRadar(detected);
}

function renderRegisteredList(devices, filter=''){
  const el = document.getElementById('registered-list');
  if(!el) return;
  if(devices.length === 0) { el.innerHTML = '<div class="muted">No registered devices.</div>'; return; }
  const f = filter.toLowerCase();
  el.innerHTML = devices.filter(d => {
    if(!f) return true;
    return (d.name||'').toLowerCase().includes(f) || (d.mac||'').toLowerCase().includes(f) || (d.ip||'').toLowerCase().includes(f);
  }).map((d,idx)=>`
    <div class="item">
      <div>
        <div style="font-weight:700">${escapeHtml(d.name)}</div>
        <div class="muted small">${escapeHtml(d.ip||'N/A')} • ${escapeHtml(d.mac)}</div>
        <div style="margin-top:6px"><span class="device-chip ${d.status==='Threat'?'threat': 'clean'}">${d.status}</span></div>
      </div>
      <div style="display:flex;flex-direction:column;gap:6px;align-items:flex-end">
        <button class="btn outline small" onclick="manualScanRegistered(${idx})">Scan</button>
        ${d.status==='Threat' ? `<button class="btn" style="background:#ef4444;color:#fff;border-radius:8px;padding:8px" onclick="blockRegistered(${idx})">Block</button>` : `<span class="muted small">Safe</span>`}
      </div>
    </div>
  `).join('');
}

function renderBlockedList(blocked, filter=''){
  const el = document.getElementById('blocked-list');
  if(!el) return;
  if(blocked.length === 0) { el.innerHTML = '<div class="muted">No blocked devices</div>'; return; }
  const f = filter.toLowerCase();
  el.innerHTML = blocked.filter(d=> {
    if(!f) return true;
    return (d.name||'').toLowerCase().includes(f) || (d.mac||'').toLowerCase().includes(f);
  }).map((d,idx)=>`
    <div class="item">
      <div>
        <div style="font-weight:700">${escapeHtml(d.name)}</div>
        <div class="muted small">${escapeHtml(d.ip||'N/A')} • ${escapeHtml(d.mac)}</div>
        <div style="margin-top:6px"><span class="device-chip blocked">Blocked</span></div>
      </div>
      <div>
        <button class="btn outline small" onclick="unblock(${idx})">Unblock</button>
      </div>
    </div>
  `).join('');
}

function renderDetectedList(detected, filter=''){
  const el = document.getElementById('detected-list');
  if(!el) return;
  if(detected.length === 0) { el.innerHTML = '<div class="muted">No devices detected. Start a scan.</div>'; return; }
  const f = filter.toLowerCase();
  el.innerHTML = detected.filter(d=>{
    if(!f) return true;
    return (d.name||'').toLowerCase().includes(f) || (d.mac||'').toLowerCase().includes(f) || (d.ip||'').toLowerCase().includes(f);
  }).map((d,idx)=>`
    <div class="item">
      <div>
        <div style="font-weight:700">${escapeHtml(d.name)}</div>
        <div class="muted small">${escapeHtml(d.ip||'N/A')} • ${escapeHtml(d.mac)} ${d.registered ? '<span class="muted small">• registered</span>':''}</div>
        <div style="margin-top:6px"><span class="device-chip ${d.status==='Threat'?'threat':'clean'}">${d.status}</span></div>
      </div>
      <div style="display:flex;flex-direction:column;gap:6px;align-items:flex-end">
        ${d.status === 'Threat' ? `<button class="btn" style="background:#ef4444;color:#fff;padding:8px;border-radius:8px" onclick="blockDetected(${idx})">Block</button>` : `<button class="btn outline small" onclick="registerFromDetected(${idx})">Register</button>`}
      </div>
    </div>
  `).join('');
}

/* -----------------------
   Device actions: register, block, unblock, scan
   ----------------------- */
async function registerDeviceWithFace(){
  // read inputs
  const name = document.getElementById('device-name').value.trim();
  const ip = document.getElementById('device-ip').value.trim() || 'N/A';
  const mac = document.getElementById('device-mac').value.trim();
  if(!name) throw new Error('Device name required');
  if(!mac) throw new Error('MAC address is mandatory');
  // open camera and enroll (simulate)
  await showCameraOverlay('Enroll device face');
  try {
    const current = getCurrentUser();
    if(!current) throw new Error('Not authenticated');
    // simulate face check (open camera, then succeed)
    await openFaceCamera('face-video');
    const ok = await _waitForFaceSample('face-video', 2500);
    stopFaceCamera('face-video');
    if(!ok) throw new Error('Face verification failed');
    // save device to user
    const users = loadUsers();
    users[current] = users[current] || { passwordHash:null, bio:{}, devices:[], blocked:[], log:[] };
    users[current].devices.push({ name, ip, mac, type: document.getElementById('device-type').value || 'Unknown', status: 'Clean', registeredAt: Date.now() });
    saveUsers(users);
    addLog(`Registered device ${name} (${mac}) with face verification`);
    loadUserDataAndRender();
    hideCameraOverlay();
    alert('Device registered with face verification');
  } catch(err){
    hideCameraOverlay();
    throw err;
  }
}

async function registerDeviceWithoutFace(){
  const name = document.getElementById('device-name').value.trim();
  const ip = document.getElementById('device-ip').value.trim() || 'N/A';
  const mac = document.getElementById('device-mac').value.trim();
  if(!name) throw new Error('Device name required');
  if(!mac) throw new Error('MAC address is mandatory');
  const current = getCurrentUser();
  if(!current) throw new Error('Not authenticated');
  const users = loadUsers();
  users[current] = users[current] || { passwordHash:null, bio:{}, devices:[], blocked:[], log:[] };
  users[current].devices.push({ name, ip, mac, type: document.getElementById('device-type').value || 'Unknown', status: 'Clean', registeredAt: Date.now() });
  saveUsers(users);
  addLog(`Registered device ${name} (${mac}) without face`);
  loadUserDataAndRender();
  alert('Device registered (no face)');
}

function registerFromDetected(idx){
  const detected = window._detectedDevices || [];
  if(!detected[idx]) return;
  const d = Object.assign({}, detected[idx]); d.registered=true;
  const cur = getCurrentUser();
  if(!cur) return alert('Not signed in');
  const users = loadUsers();
  users[cur] = users[cur] || { devices:[], blocked:[], log:[] };
  // required: ensure mac present
  if(!d.mac){ return alert('Detected device has no MAC — cannot register'); }
  users[cur].devices.push({ name:d.name, ip:d.ip||'N/A', mac:d.mac, type:'Unknown', status:'Clean', registeredAt:Date.now() });
  saveUsers(users);
  // remove from detected list
  detected.splice(idx,1);
  window._detectedDevices = detected;
  addLog(`Registered detected device ${d.name} (${d.mac})`);
  loadUserDataAndRender();
}

function manualScanRegistered(idx){
  const u = getUserObject();
  if(!u) return;
  const dev = u.devices[idx];
  if(!dev) return;
  // simulate a "deep scan" with some randomness
  const isThreat = Math.random() > 0.88; // low chance
  if(isThreat){
    dev.status = 'Threat';
    addLog(`Threat detected on registered device ${dev.name} (${dev.mac})`);
    // auto-block if auto-disconnect set high => optionally block Wi-Fi (demonstration)
    const ad = document.getElementById('auto-disconnect')?.value || 'off';
    if(ad === 'high'){
      // optionally auto-block or show alert
      alert('Auto-disconnect triggered by high threat (demo).');
    }
  } else {
    dev.status = 'Clean';
    addLog(`Registered device ${dev.name} scanned clean`);
  }
  persistUserObject(u);
  renderAllLists(document.getElementById('global-search')?.value || '');
}

function blockRegistered(idx){
  const u = getUserObject();
  if(!u) return;
  const dev = u.devices[idx];
  if(!dev) return;
  // move to blocked
  u.devices.splice(idx,1);
  u.blocked.unshift(Object.assign({}, dev, { blockedAt:Date.now() }));
  addLog(`Blocked registered device ${dev.name} (${dev.mac})`);
  persistUserObject(u);
  renderAllLists();
}

function unblock(idx){
  const u = getUserObject();
  if(!u) return;
  const b = u.blocked.splice(idx,1)[0];
  if(b){
    u.devices.unshift(Object.assign({}, b, { status:'Clean' }));
    addLog(`Unblocked device ${b.name} (${b.mac})`);
  }
  persistUserObject(u);
  renderAllLists();
}

/* detected list actions */
function blockDetected(idx){
  const detected = window._detectedDevices || [];
  const d = detected.splice(idx,1)[0];
  if(!d) return;
  const u = getUserObject();
  if(!u) return alert('Not signed in');
  u.blocked.unshift({ name:d.name, ip:d.ip||'N/A', mac:d.mac, blockedAt:Date.now() });
  addLog(`Blocked detected device ${d.name} (${d.mac})`);
  persistUserObject(u);
  window._detectedDevices = detected;
  renderAllLists();
}

/* -----------------------
   Scanning loop and generator
   ----------------------- */
let _scanLoopHandle = null;
function startScanLoop(){
  if(_scanLoopHandle) return;
  const interval = parseInt(document.getElementById('scan-interval')?.value || 2000,10);
  function tick(){
    doScanOnce();
    _scanLoopHandle = setTimeout(tick, parseInt(document.getElementById('scan-interval').value,10));
  }
  tick();
}

function stopScanLoop(){
  if(_scanLoopHandle) { clearTimeout(_scanLoopHandle); _scanLoopHandle = null; }
}

function doScanOnce(){
  // produce mix of devices: some registered (randomly flagged), some new devices
  const u = getUserObject();
  const regMacs = new Set((u && u.devices || []).map(d=>d.mac));
  const blkMacs = new Set((u && u.blocked || []).map(d=>d.mac));
  // simulated environment pool
  const pool = [
    { name:'Drone-Alpha', ip:'192.168.10.5', mac:'AA:11:22:33:44:55' },
    { name:'Rogue-Router', ip:'N/A', mac:'FF:FF:FF:FF:FF:00' },
    { name:'Visitor-Phone', ip:'192.168.10.20', mac:'BB:22:33:44:55:66' },
    { name:'Camera-Ext', ip:'192.168.10.44', mac:'CC:33:44:55:66:77' },
    { name:'Unknown-Device', ip:'192.168.10.99', mac:'00:11:22:AA:BB:CC' }
  ];
  // combine with a copy of registered devices to check them
  const detections = [];
  // check registered devices for random threat
  if(u && u.devices){
    u.devices.forEach(d=>{
      const maybeThreat = (Math.random() > 0.92); // 8% chance
      detections.push({ name:d.name, ip:d.ip||'N/A', mac:d.mac, registered:true, status: maybeThreat ? 'Threat' : 'Unregistered' });
      if(maybeThreat){ d.status = 'Threat'; addLog(`Threat flagged on registered device ${d.name} (${d.mac})`); }
    });
  }
  // add some random nearby devices that aren't registered or blocked
  const shuffled = pool.sort(()=>0.5 - Math.random()).slice(0,3);
  shuffled.forEach(p=>{
    if(regMacs.has(p.mac) || blkMacs.has(p.mac)) return;
    const isThreat = Math.random() > 0.7; // 30% chance
    detections.push({ name:p.name, ip:p.ip, mac:p.mac, registered:false, status: isThreat ? 'Threat' : 'Unregistered' });
    if(isThreat) addLog(`Threat detected nearby: ${p.name} (${p.mac})`);
  });
  window._detectedDevices = detections;
  persistUserObject(u);
  renderAllLists(document.getElementById('global-search')?.value || '');
}

/* -----------------------
   Radar drawing
   ----------------------- */
function renderRadar(detected){
  const svg = document.getElementById('radar-svg');
  if(!svg) return;
  const w = svg.clientWidth || 240, h = svg.clientHeight || 240;
  svg.setAttribute('width', w); svg.setAttribute('height', h);
  // center
  const cx = w/2, cy = h/2;
  svg.innerHTML = '';
  // concentric rings
  for(let r = 35; r <= Math.min(cx,cy); r += 35){
    svg.innerHTML += `<circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="rgba(0,0,0,0.04)"></circle>`;
  }
  if(!detected || detected.length===0) return;
  detected.forEach((d,i)=>{
    const angle = (2*Math.PI) * (i / detected.length);
    const radius = 20 + (i * 30) % (Math.min(cx,cy)-30);
    const x = cx + Math.cos(angle) * radius;
    const y = cy + Math.sin(angle) * radius;
    const color = d.status === 'Threat' ? '#ef4444' : '#f59e0b';
    svg.innerHTML += `<g>
      <circle cx="${x}" cy="${y}" r="6" fill="${color}" stroke="#fff" stroke-width="1"></circle>
      <text x="${x+8}" y="${y+4}" font-size="10" fill="#111">${escapeHtml(d.name)}</text>
    </g>`;
  });
}

/* -----------------------
   Threat log (per-user)
   ----------------------- */
function addLog(message){
  const u = getUserObject();
  if(!u) return;
  u.log = u.log || [];
  u.log.unshift({ ts: Date.now(), msg: message });
  if(u.log.length > 200) u.log.length = 200;
  persistUserObject(u);
  renderThreatLog();
}
function renderThreatLog(){
  const u = getUserObject();
  const el = document.getElementById('threat-log');
  if(!el) return;
  const logs = (u && u.log) ? u.log : [];
  if(logs.length === 0) { el.innerHTML = '<div class="muted">No events yet</div>'; return; }
  el.innerHTML = logs.slice(0,40).map(l => `<div class="muted small">${new Date(l.ts).toLocaleString()} — ${escapeHtml(l.msg)}</div>`).join('');
}
function exportThreatLog(){
  const u = getUserObject(); if(!u) return alert('No user data');
  const text = (u.log || []).map(l=>`${new Date(l.ts).toISOString()} - ${l.msg}`).join('\n');
  const blob = new Blob([text], { type:'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href = url; a.download = `sentinel-log-${getCurrentUser()}.txt`; a.click();
  URL.revokeObjectURL(url);
}

/* -----------------------
   Clear blocked devices
   ----------------------- */
function clearBlockedDevices(){
  const u = getUserObject(); if(!u) return;
  u.blocked = [];
  persistUserObject(u);
  addLog('Cleared all blocked devices');
  renderAllLists();
}

/* -----------------------
   Load user data & initial render
   ----------------------- */
function loadUserDataAndRender(){
  const u = getUserObject();
  if(!u) return;
  // ensure arrays
  u.devices = u.devices || []; u.blocked = u.blocked || []; u.log = u.log || [];
  persistUserObject(u);
  // initial render
  window._detectedDevices = window._detectedDevices || [];
  renderAllLists();
  renderThreatLog();
}

/* -----------------------
   Helper: escapeHtml
   ----------------------- */
function escapeHtml(s){ if(!s && s!==0) return ''; return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

/* -----------------------
   Camera overlay UI (used on dashboard register)
   ----------------------- */
function showCameraOverlay(title){
  return new Promise((resolve)=>{
    const overlay = document.getElementById('cam-overlay');
    const titleEl = document.getElementById('cam-purpose');
    titleEl.textContent = title || 'Face verification';
    overlay.classList.remove('hidden');
    // bind accept/cancel
    const accept = document.getElementById('cam-accept');
    const cancel = document.getElementById('cam-cancel');
    function cleanup(){ accept.removeEventListener('click', onAccept); cancel.removeEventListener('click', onCancel); overlay.classList.add('hidden'); }
    function onAccept(){ cleanup(); resolve(true); }
    function onCancel(){ cleanup(); resolve(false); }
    accept.addEventListener('click', onAccept);
    cancel.addEventListener('click', onCancel);
  });
}
function hideCameraOverlay(){ const overlay = document.getElementById('cam-overlay'); overlay.classList.add('hidden'); }

/* camera overlay actual open/close plus video element functions used earlier:
   openFaceCamera('face-video') and stopFaceCamera('face-video') */

/* -----------------------
   Persist helpers for user object
   ----------------------- */
function persistUserObject(uObj){
  const cur = getCurrentUser(); if(!cur) return;
  const users = loadUsers(); users[cur] = uObj; saveUsers(users);
}

/* -----------------------
   Helper: load users on page-level forms
   ----------------------- */
window.loadUsers = loadUsers;
window.demoRegisterUser = demoRegisterUser;
window.demoLoginWithPassword = demoLoginWithPassword;
window.demoFaceAuth = demoFaceAuth;
window.createWebAuthnForUser = createWebAuthnForUser;
window.loginWithWebAuthn = loginWithWebAuthn;
window.demoLogout = demoLogout;

/* expose device actions globally for inline onclick handlers in markup */
window.registerFromDetected = function(idx){ registerFromDetected(idx); };
window.blockDetected = function(idx){ blockDetected(idx); };
window.unblock = function(idx){ unblock(idx); };
window.manualScanRegistered = function(idx){ manualScanRegistered(idx); };
window.blockRegistered = function(idx){ blockRegistered(idx); };

/* utility functions to unblock via index for inline calls */
window.unblock = unblock;

/* initialize: when used in login/signup pages, forms call above functions directly */
