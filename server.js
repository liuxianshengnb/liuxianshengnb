
const express = require("express");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const multer = require("multer");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
require("dotenv").config();

const app = express();
const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || "change_this_secret";
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "luoshanjinb";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "123456";
const MAX_FILE_SIZE_MB = Number(process.env.MAX_FILE_SIZE_MB || 200);

// Railway: set DATA_DIR=/data and mount a Volume at /data
const DATA_DIR = process.env.DATA_DIR || __dirname;
const UPLOAD_DIR = path.join(DATA_DIR, "uploads");
const DB_FILE = path.join(DATA_DIR, "files.json");

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(UPLOAD_DIR, { recursive: true });
if (!fs.existsSync(DB_FILE)) fs.writeFileSync(DB_FILE, "[]", "utf-8");

app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(cors());
app.use(express.json({ limit: "1mb" }));

const loginLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 12,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "登录请求太频繁，请稍后再试。" }
});

function readDb() {
  try { return JSON.parse(fs.readFileSync(DB_FILE, "utf-8")); }
  catch { return []; }
}

function writeDb(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2), "utf-8");
}

function safeName(name) {
  return String(name || "file")
    .replace(/[<>:"/\\|?*\x00-\x1F]/g, "_")
    .replace(/\s+/g, " ")
    .slice(0, 180);
}

function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!token) return res.status(401).json({ error: "未登录。" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "登录已过期，请重新登录。" });
  }
}

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname || "");
    cb(null, crypto.randomUUID() + ext);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: MAX_FILE_SIZE_MB * 1024 * 1024, files: 20 }
});

app.post("/api/login", loginLimiter, (req, res) => {
  const { username, password } = req.body || {};
  if (username !== ADMIN_USERNAME || password !== ADMIN_PASSWORD) {
    return res.status(401).json({ error: "账号或密码错误。" });
  }
  const token = jwt.sign({ username: ADMIN_USERNAME }, JWT_SECRET, { expiresIn: "7d" });
  res.json({ token, username: ADMIN_USERNAME });
});

app.get("/api/me", auth, (req, res) => res.json({ username: req.user.username }));

app.get("/api/files", auth, (_req, res) => {
  const files = readDb()
    .filter(item => fs.existsSync(path.join(UPLOAD_DIR, item.storedName)))
    .sort((a, b) => new Date(b.uploadedAt) - new Date(a.uploadedAt));
  res.json({ files });
});

app.post("/api/upload", auth, upload.array("files", 20), (req, res) => {
  const uploaded = (req.files || []).map(file => ({
    id: crypto.randomUUID(),
    originalName: safeName(file.originalname),
    storedName: file.filename,
    mimeType: file.mimetype || "application/octet-stream",
    size: file.size,
    uploadedAt: new Date().toISOString()
  }));
  const db = readDb();
  db.push(...uploaded);
  writeDb(db);
  res.json({ files: uploaded });
});

app.get("/api/download/:id", auth, (req, res) => {
  const item = readDb().find(file => file.id === req.params.id);
  if (!item) return res.status(404).json({ error: "文件不存在。" });
  const filePath = path.join(UPLOAD_DIR, item.storedName);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: "服务器文件已丢失。" });
  res.download(filePath, item.originalName);
});

app.delete("/api/files/:id", auth, (req, res) => {
  const db = readDb();
  const item = db.find(file => file.id === req.params.id);
  if (!item) return res.status(404).json({ error: "文件不存在。" });
  const filePath = path.join(UPLOAD_DIR, item.storedName);
  if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
  writeDb(db.filter(file => file.id !== req.params.id));
  res.json({ ok: true });
});

const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Cyber Cloud Storage</title>
<style>
:root{--bg:#020617;--cyan:#22d3ee;--blue:#3b82f6;--purple:#a855f7;--pink:#ec4899;--text:#e5f7ff;--muted:#8ea5b8;--panel:rgba(7,18,38,.72);--line:rgba(125,211,252,.22);--shadow:0 25px 100px rgba(0,0,0,.55)}
*{box-sizing:border-box}html,body{margin:0;min-height:100%;font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;color:var(--text);background:#020617;overflow-x:hidden}
body{min-height:100vh;background:radial-gradient(circle at 15% 18%,rgba(34,211,238,.22),transparent 28%),radial-gradient(circle at 80% 12%,rgba(168,85,247,.24),transparent 30%),radial-gradient(circle at 50% 85%,rgba(59,130,246,.18),transparent 32%),#020617}
body:before{content:"";position:fixed;inset:0;pointer-events:none;background-image:linear-gradient(rgba(125,211,252,.05) 1px,transparent 1px),linear-gradient(90deg,rgba(125,211,252,.05) 1px,transparent 1px);background-size:42px 42px;z-index:0}
.loader{position:fixed;inset:0;display:grid;place-items:center;background:radial-gradient(circle at center,rgba(34,211,238,.16),transparent 42%),#020617;z-index:50;transition:.7s}
.loader.hide{opacity:0;visibility:hidden}.loaderbox{width:min(680px,calc(100% - 36px));padding:34px;border:1px solid var(--line);border-radius:30px;background:rgba(2,6,23,.78);box-shadow:var(--shadow);backdrop-filter:blur(18px)}
.track{height:18px;border-radius:999px;overflow:hidden;border:1px solid rgba(125,211,252,.35);background:rgba(15,23,42,.9)}.bar{height:100%;border-radius:999px;background:linear-gradient(90deg,var(--cyan),var(--blue),var(--purple),var(--pink));animation:load 2.4s forwards;box-shadow:0 0 30px rgba(34,211,238,.8)}
@keyframes load{0%{width:0}30%{width:38%}60%{width:72%}100%{width:100%}}.percent{text-align:center;margin-top:18px;color:#bae6fd;letter-spacing:.18em;font-size:13px}
.app{position:relative;z-index:2;min-height:100vh;display:grid;place-items:center;padding:28px}.panel{border:1px solid var(--line);background:linear-gradient(145deg,rgba(255,255,255,.12),rgba(255,255,255,.04)),var(--panel);box-shadow:var(--shadow),inset 0 0 60px rgba(34,211,238,.05);border-radius:34px;backdrop-filter:blur(22px)}
.login{position:relative;width:min(430px,100%);padding:28px;min-height:500px;overflow:hidden;transform-style:preserve-3d;transition:transform .08s ease-out;will-change:transform;backface-visibility:hidden}
.login:before{content:"";position:absolute;inset:-1px;background:radial-gradient(circle at var(--mx,50%) var(--my,50%),rgba(34,211,238,.26),transparent 26%),linear-gradient(135deg,rgba(34,211,238,.16),transparent 38%,rgba(168,85,247,.18));pointer-events:none}.inner{position:relative;z-index:2;transform:translateZ(42px)}
.head{display:flex;justify-content:space-between;align-items:center;margin-bottom:24px}.icon{width:54px;height:54px;display:grid;place-items:center;border-radius:20px;background:linear-gradient(135deg,var(--cyan),var(--purple));font-weight:900;font-size:24px}.chip{padding:8px 11px;border-radius:999px;border:1px solid rgba(34,211,238,.28);background:rgba(34,211,238,.08);color:#a5f3fc;font-size:12px;letter-spacing:.08em}
h2{margin:0 0 28px;font-size:34px;letter-spacing:-.05em}.field{margin-bottom:16px}.field label{display:block;margin-bottom:8px;color:#cbeafe;font-size:13px}input{width:100%;height:54px;padding:0 16px;color:#fff;background:rgba(2,6,23,.58);border:1px solid rgba(125,211,252,.22);border-radius:18px;outline:none;font-size:16px}input:focus{border-color:rgba(34,211,238,.78);box-shadow:0 0 0 5px rgba(34,211,238,.12)}
button{border:0;cursor:pointer}.mainbtn,.gyro{width:100%;height:54px;margin-top:6px;border-radius:18px;color:#03111b;background:linear-gradient(90deg,var(--cyan),#93c5fd,var(--purple));font-weight:900;letter-spacing:.04em}.gyro{display:none;margin-top:14px;color:#e0f2fe;background:rgba(34,211,238,.1);border:1px solid rgba(34,211,238,.28)}.error{min-height:22px;margin-top:14px;color:#fecdd3;font-size:14px}
.dashboard{display:none;width:min(1180px,100%);animation:appear .55s both}.dashboard.show{display:block}@keyframes appear{from{opacity:0;transform:translateY(18px) scale(.985)}to{opacity:1;transform:none}}
.top{display:flex;justify-content:flex-end;margin-bottom:18px}.logout,.download,.remove,.tool{height:40px;padding:0 14px;border-radius:13px;color:#04111c;background:#a5f3fc;font-weight:850}.logout,.remove{color:#fecdd3;background:rgba(251,113,133,.1);border:1px solid rgba(251,113,133,.22)}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:22px}.card{padding:24px;min-height:440px}.card h3{margin:0 0 20px;font-size:25px}.drop{position:relative;min-height:300px;display:grid;place-items:center;text-align:center;border:1px dashed rgba(125,211,252,.42);border-radius:26px;background:radial-gradient(circle at center,rgba(34,211,238,.12),transparent 46%),rgba(2,6,23,.38);overflow:hidden}.drop.drag{border-color:var(--cyan);box-shadow:0 0 40px rgba(34,211,238,.18)}.drop input{position:absolute;inset:0;opacity:0;cursor:pointer}.symbol{width:72px;height:72px;display:grid;place-items:center;margin:0 auto 16px;border-radius:26px;background:rgba(34,211,238,.12);border:1px solid rgba(34,211,238,.28);font-size:34px}
.tools{display:flex;gap:10px;flex-wrap:wrap;margin-top:16px}.tool{color:#dff8ff;border:1px solid rgba(125,211,252,.2);background:rgba(255,255,255,.06)}.list{display:grid;gap:12px;max-height:360px;overflow:auto}.file{display:grid;grid-template-columns:1fr auto;gap:12px;align-items:center;padding:14px;border:1px solid rgba(125,211,252,.16);border-radius:18px;background:rgba(2,6,23,.46)}.fname{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-weight:750}.meta{margin-top:4px;color:var(--muted);font-size:12px}.empty{padding:28px;color:#64748b;text-align:center;border:1px solid rgba(125,211,252,.12);border-radius:22px;background:rgba(2,6,23,.28)}
@media(max-width:900px){.grid{grid-template-columns:1fr}}@media(max-width:560px){.app{padding:16px}.login,.card{padding:18px;border-radius:26px}.file{grid-template-columns:1fr}.drop{min-height:240px}}
</style>
</head>
<body>
<div class="loader" id="loader"><div class="loaderbox"><div class="track"><div class="bar"></div></div><div class="percent" id="percent">0%</div></div></div>
<main class="app">
<form class="login panel" id="loginCard">
<div class="inner"><div class="head"><div class="icon">⌁</div><div class="chip">LOGIN</div></div><h2>系统登录</h2>
<div class="field"><label>账号</label><input id="username" autocomplete="username"></div>
<div class="field"><label>密码</label><input id="password" type="password" autocomplete="current-password"></div>
<button class="mainbtn" type="submit">登录</button><button class="gyro" type="button" id="gyroBtn">开启悬浮陀螺仪</button><div class="error" id="loginError"></div></div>
</form>
<section class="dashboard" id="dashboard"><div class="top"><button class="logout" id="logout">退出登录</button></div><div class="grid">
<section class="card panel"><h3>上传文件</h3><div class="drop" id="drop"><input type="file" id="fileInput" multiple><div><div class="symbol">⇪</div><strong>点击或拖拽上传</strong></div></div><div class="tools"><button class="tool" id="refresh" type="button">刷新列表</button><button class="tool" id="downloadAll" type="button">下载全部</button></div><div class="error" id="status"></div></section>
<section class="card panel"><h3>下载文件</h3><div class="list" id="fileList"><div class="empty">暂无文件</div></div></section>
</div></section>
</main>
<script>
const loader=document.getElementById("loader"),percent=document.getElementById("percent"),loginCard=document.getElementById("loginCard"),dashboard=document.getElementById("dashboard"),username=document.getElementById("username"),password=document.getElementById("password"),loginError=document.getElementById("loginError"),gyroBtn=document.getElementById("gyroBtn"),logout=document.getElementById("logout"),drop=document.getElementById("drop"),fileInput=document.getElementById("fileInput"),fileList=document.getElementById("fileList"),refresh=document.getElementById("refresh"),downloadAll=document.getElementById("downloadAll"),statusBox=document.getElementById("status");
let files=[],lv=0;
function token(){return localStorage.getItem("cloud_token")||""}function setToken(t){localStorage.setItem("cloud_token",t)}function clearToken(){localStorage.removeItem("cloud_token")}
async function api(url,opt={}){const headers=opt.headers||{};if(token())headers.Authorization="Bearer "+token();const r=await fetch(url,{...opt,headers});const ct=r.headers.get("content-type")||"";const d=ct.includes("application/json")?await r.json():null;if(!r.ok)throw new Error(d&&d.error?d.error:"请求失败");return d}
const lt=setInterval(()=>{lv+=Math.ceil(Math.random()*7);if(lv>=100){lv=100;clearInterval(lt);setTimeout(async()=>{loader.classList.add("hide");if(token()){try{await api("/api/me");showDash()}catch{clearToken();username.focus()}}else username.focus()},420)}percent.textContent=lv+"%"},110);
function clamp(n,a,b){return Math.min(Math.max(n,a),b)}
const motion={gyro:false,ticking:false,tx:0,ty:0,cx:0,cy:0};function renderTilt(){motion.ticking=false;motion.cx+=(motion.tx-motion.cx)*.22;motion.cy+=(motion.ty-motion.cy)*.22;const rx=clamp(-motion.cy,-14,14),ry=clamp(motion.cx,-14,14);loginCard.style.transform="perspective(1000px) translateZ(0) rotateX("+rx+"deg) rotateY("+ry+"deg)";loginCard.style.setProperty("--mx",(50+ry*2.2)+"%");loginCard.style.setProperty("--my",(50-rx*2.2)+"%");if(Math.abs(motion.tx-motion.cx)>.05||Math.abs(motion.ty-motion.cy)>.05){motion.ticking=true;requestAnimationFrame(renderTilt)}}function setTilt(x,y){motion.tx=clamp(x,-14,14);motion.ty=clamp(y,-14,14);if(!motion.ticking){motion.ticking=true;requestAnimationFrame(renderTilt)}}
loginCard.addEventListener("mousemove",e=>{if(dashboard.classList.contains("show")||motion.gyro)return;const r=loginCard.getBoundingClientRect();setTilt(((e.clientX-r.left)/r.width-.5)*24,((e.clientY-r.top)/r.height-.5)*24)});loginCard.addEventListener("mouseleave",()=>{if(!motion.gyro)setTilt(0,0)});
const canGyro=typeof DeviceOrientationEvent!=="undefined";if(canGyro)gyroBtn.style.display="block";let bb=null,bg=null,last=0;function orient(e){if(dashboard.classList.contains("show"))return;const now=performance.now();if(now-last<16)return;last=now;const b=Number(e.beta||0),g=Number(e.gamma||0);if(bb===null||bg===null){bb=b;bg=g}setTilt(clamp((g-bg)*.85,-14,14),clamp((b-bb)*.85,-14,14))}
async function enableGyro(){if(!canGyro){gyroBtn.textContent="当前设备不支持陀螺仪";return}try{if(typeof DeviceOrientationEvent.requestPermission==="function"){const p=await DeviceOrientationEvent.requestPermission();if(p!=="granted"){gyroBtn.textContent="未获得陀螺仪权限";return}}motion.gyro=true;bb=null;bg=null;window.removeEventListener("deviceorientation",orient);window.addEventListener("deviceorientation",orient,{passive:true});gyroBtn.textContent="悬浮陀螺仪已开启";gyroBtn.disabled=true}catch{gyroBtn.textContent="开启失败"}}
gyroBtn.onclick=enableGyro;window.addEventListener("touchstart",()=>{if(!motion.gyro&&canGyro&&typeof DeviceOrientationEvent.requestPermission!=="function")enableGyro()},{once:true,passive:true});
loginCard.addEventListener("submit",async e=>{e.preventDefault();loginError.textContent="";try{const d=await api("/api/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username:username.value.trim(),password:password.value})});setToken(d.token);showDash()}catch(err){loginError.textContent=err.message;loginCard.animate([{transform:"translateX(0)"},{transform:"translateX(-8px)"},{transform:"translateX(8px)"},{transform:"translateX(0)"}],{duration:260})}});
async function showDash(){loginCard.style.display="none";dashboard.classList.add("show");await loadFiles()}logout.onclick=()=>{clearToken();dashboard.classList.remove("show");loginCard.style.display="block";password.value="";username.focus()};
function esc(s){return String(s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;","\\"":"&quot;","'":"&#039;"}[c]))}function size(b){if(b<1024)return b+" B";if(b<1048576)return(b/1024).toFixed(1)+" KB";if(b<1073741824)return(b/1048576).toFixed(1)+" MB";return(b/1073741824).toFixed(1)+" GB"}
async function loadFiles(){fileList.innerHTML='<div class="empty">加载中...</div>';try{const d=await api("/api/files");files=d.files||[];renderFiles()}catch(e){fileList.innerHTML='<div class="empty">'+esc(e.message)+'</div>'}}
function renderFiles(){if(!files.length){fileList.innerHTML='<div class="empty">暂无文件</div>';return}fileList.innerHTML="";files.forEach(it=>{const row=document.createElement("div");row.className="file";const info=document.createElement("div");info.innerHTML='<div class="fname" title="'+esc(it.originalName)+'">'+esc(it.originalName)+'</div><div class="meta">'+size(it.size)+' · '+new Date(it.uploadedAt).toLocaleString()+'</div>';const actions=document.createElement("div");actions.style.display="flex";actions.style.gap="8px";actions.style.flexWrap="wrap";const down=document.createElement("button");down.className="download";down.textContent="下载";down.onclick=()=>downloadFile(it.id);const del=document.createElement("button");del.className="remove";del.textContent="删除";del.onclick=()=>deleteFile(it.id);actions.append(down,del);row.append(info,actions);fileList.appendChild(row)})}
async function uploadFiles(list){const selected=Array.from(list);if(!selected.length)return;statusBox.textContent="上传中...";try{const form=new FormData();selected.forEach(f=>form.append("files",f));await api("/api/upload",{method:"POST",body:form});statusBox.textContent="上传完成";await loadFiles()}catch(e){statusBox.textContent=e.message}}
function downloadFile(id){fetch("/api/download/"+encodeURIComponent(id),{headers:{Authorization:"Bearer "+token()}}).then(async r=>{if(!r.ok)throw new Error("下载失败");const blob=await r.blob();const f=files.find(x=>x.id===id);const url=URL.createObjectURL(blob);const a=document.createElement("a");a.href=url;a.download=f?f.originalName:"download";document.body.appendChild(a);a.click();a.remove();URL.revokeObjectURL(url)}).catch(e=>statusBox.textContent=e.message)}
async function deleteFile(id){try{await api("/api/files/"+encodeURIComponent(id),{method:"DELETE"});await loadFiles()}catch(e){statusBox.textContent=e.message}}
fileInput.onchange=async e=>{await uploadFiles(e.target.files);fileInput.value=""};["dragenter","dragover"].forEach(n=>drop.addEventListener(n,e=>{e.preventDefault();drop.classList.add("drag")}));["dragleave","drop"].forEach(n=>drop.addEventListener(n,e=>{e.preventDefault();drop.classList.remove("drag")}));drop.addEventListener("drop",e=>uploadFiles(e.dataTransfer.files));refresh.onclick=loadFiles;downloadAll.onclick=()=>files.forEach((it,i)=>setTimeout(()=>downloadFile(it.id),i*350));
</script>
</body>
</html>`;

app.get("/", (_req, res) => {
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(html);
});

app.get("*", (_req, res) => res.redirect("/"));

app.use((err, _req, res, _next) => {
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ error: `上传失败：${err.message}` });
  }
  console.error(err);
  res.status(500).json({ error: "服务器错误。" });
});

app.listen(PORT, () => {
  console.log("Cyber Cloud Storage running on port " + PORT);
  console.log("DATA_DIR: " + DATA_DIR);
  console.log("UPLOAD_DIR: " + UPLOAD_DIR);
});
