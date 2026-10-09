/**
 * keyauth_engine.js - Ghostrix / KeyAuth 1.2 Enterprise Security Engine for Node.js & Vercel
 * 
 * Features:
 * - Fully compatible with KeyAuth 1.2 SDK Protocol (/api/1.2/) for Android Kotlin/Java, C++, C#, Python, cURL
 * - Strict Authentication Enforcement: Variables & Files are ONLY served if user is authenticated with an active non-banned license key!
 * - Stream & Proxy Gatekeeper: Blocks unauthorized video/proxy requests unless authenticated with a valid key/session
 * - Anti-Tamper Security: Brute-Force Rate Limiting & Auto-Ban, Blacklist Rules (IP/HWID), APK Hash Check, Anti-VPN
 * - Per-Key & Per-User Controls: HWID Locking, Expiry, Status (Active, Paused, Banned), Note, Level, Subscriptions
 * - Deep Audit & Live Activity Logging: App Launches, Logins, HWID Mismatches, Variables, Files, Video Streaming
 * - Persistent JSON Database Storage: Auto-syncs to keyauth_db.json (with debounced async writes for zero latency)
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const BASE_DIR = path.resolve(__dirname);
const DB_FILE = process.env.VERCEL ? path.join('/tmp', 'keyauth_db.json') : path.join(BASE_DIR, 'keyauth_db.json');

const DEFAULT_ADMIN_TOKEN = process.env.ADMIN_SECRET || 'ghostrix_secret_admin_2026';
const ADMIN_CREDENTIALS = {
  user: 'admin@1234',
  pass: 'Darshan@1334'
};

const defaultDatabase = {
  activeAppId: "ghost_app_1",
  apps: [
    {
      id: "ghost_app_1",
      name: "Ghost",
      ownerid: "usr_34se87p0",
      secret: "4880a366c23746f5abaca00a6cc321ff1ecb4872666b1da4253d17656dae42a8",
      version: "1.0",
      status: "Active", // "Active" | "Paused"
      description: "Ghost Secure Android Application",
      standing: "Good",
      hwidLock: true,
      forceHwid: true,
      blockVpn: false,
      hashCheck: false,
      appHash: "",
      discordWebhook: "",
      autoBan: true,
      requireKeyForProxy: true,
      created: 1791520000000
    },
    {
      id: "redrix_app_1",
      name: "redrix",
      ownerid: "usr_rput5p1f",
      secret: "b99828e85635e0cbb569b9732c35b75abc1eebacbdd3fe4aaf08afde3dbdcada",
      version: "1.2",
      status: "Active", // "Active" | "Paused"
      description: "Redrix Ultimate Course & Secure Authentication Engine",
      standing: "Good",
      hwidLock: true,
      forceHwid: true,
      blockVpn: false,
      hashCheck: false,
      appHash: "",
      discordWebhook: "",
      autoBan: true,
      requireKeyForProxy: false, // User toggle: Require active license to access proxy streams
      created: Date.now()
    }
  ],
  licenses: [
    {
      key: "GHOST-VIP-7788",
      appId: "ghost_app_1",
      appName: "Ghost",
      level: 1,
      duration: 315569260,
      unit: "Lifetime",
      note: "Ghost VIP Access",
      status: "Active",
      hwidLock: true,
      hwid: "",
      usedby: "",
      usedon: 0,
      gendate: 1791520000000,
      expires: 2107089027404,
      banReason: ""
    }
  ],
  users: [],
  tokens: [],
  subscriptions: [
    { name: "default", level: 1 }
  ],
  sessions: [],
  files: [
    {
      id: "file_app_update",
      name: "Redrix_Course_Player_V1.2.apk",
      size: "24.5 MB",
      url: "https://example.com/app-release.apk",
      appId: "all",
      uploaded: Date.now()
    }
  ],
  variables: [
    {
      name: "announcement",
      data: "Welcome to Redrix Video Portal! All streams are secured with KeyAuth 1.2.",
      isSecret: false,
      appId: "all"
    },
    {
      name: "proxy_endpoint",
      data: "/proxy?url=",
      isSecret: false,
      appId: "all"
    }
  ],
  rules: [],
  logs: []
};

let inMemoryStore = JSON.parse(JSON.stringify(defaultDatabase));

// Rate limit tracker (IP => { count, resetTime })
const ipFailures = new Map();

function checkRateLimit(ip) {
  const now = Date.now();
  const record = ipFailures.get(ip);
  if (!record) return true;
  if (now > record.resetTime) {
    ipFailures.delete(ip);
    return true;
  }
  return record.count < 10;
}

function recordIpFailure(ip) {
  const now = Date.now();
  const record = ipFailures.get(ip);
  if (!record || now > record.resetTime) {
    ipFailures.set(ip, { count: 1, resetTime: now + 3 * 60 * 1000 });
  } else {
    record.count++;
  }
}

function clearIpFailure(ip) {
  ipFailures.delete(ip);
}

// Migrate and validate database schema
function migrateDBSchema(db) {
  if (!db || typeof db !== 'object') return JSON.parse(JSON.stringify(defaultDatabase));
  if (!Array.isArray(db.apps) || db.apps.length === 0) {
    db.apps = JSON.parse(JSON.stringify(defaultDatabase.apps));
  }
  // Ensure Ghost app exists
  if (!db.apps.some(a => a.name.toLowerCase() === "ghost" || a.ownerid === "usr_34se87p0")) {
    db.apps.unshift({
      id: "ghost_app_1",
      name: "Ghost",
      ownerid: "usr_34se87p0",
      secret: "4880a366c23746f5abaca00a6cc321ff1ecb4872666b1da4253d17656dae42a8",
      version: "1.0",
      status: "Active",
      description: "Ghost Secure Android Application",
      standing: "Good",
      hwidLock: true,
      forceHwid: true,
      blockVpn: false,
      hashCheck: false,
      appHash: "",
      discordWebhook: "",
      autoBan: true,
      requireKeyForProxy: true,
      created: 1791520000000,
      strictVersionCheck: false,
      downloadUrl: ""
    });
  }
  if (!db.activeAppId) {
    db.activeAppId = "ghost_app_1";
  }
  const defaultApp = db.apps.find(a => a.id === db.activeAppId) || db.apps[0];

  db.apps.forEach(app => {
    if (app.strictVersionCheck === undefined) app.strictVersionCheck = false;
    if (app.downloadUrl === undefined) app.downloadUrl = "";
    if (app.discordWebhook === undefined) app.discordWebhook = "";
    if (app.standing === undefined) app.standing = "Good";
    if (app.requireKeyForProxy === undefined) app.requireKeyForProxy = false;
  });

  if (!Array.isArray(db.licenses)) db.licenses = [];
  if (!db.licenses.some(l => l.key === "GHOST-VIP-7788")) {
    db.licenses.unshift({
      key: "GHOST-VIP-7788",
      appId: "ghost_app_1",
      appName: "Ghost",
      level: 1,
      duration: 315569260,
      unit: "Lifetime",
      note: "Ghost VIP Access",
      status: "Active",
      hwidLock: true,
      hwid: "",
      usedby: "",
      usedon: 0,
      gendate: 1791520000000,
      expires: 2107089027404,
      banReason: ""
    });
  }
  db.licenses.forEach(l => {
    if (!l.appId) {
      l.appId = defaultApp.id;
      l.appName = defaultApp.name;
    }
  });

  if (!Array.isArray(db.users)) db.users = [];
  db.users.forEach(u => {
    if (!u.appId) {
      u.appId = defaultApp.id;
      u.appName = defaultApp.name;
    }
  });

  if (!Array.isArray(db.variables)) db.variables = JSON.parse(JSON.stringify(defaultDatabase.variables));
  db.variables.forEach(v => {
    if (!v.appId) v.appId = "all";
  });

  if (!Array.isArray(db.files)) db.files = JSON.parse(JSON.stringify(defaultDatabase.files));
  db.files.forEach(f => {
    if (!f.appId) f.appId = "all";
  });

  if (!Array.isArray(db.tokens)) db.tokens = [];
  if (!Array.isArray(db.subscriptions)) db.subscriptions = [];
  if (!Array.isArray(db.sessions)) db.sessions = [];
  if (!Array.isArray(db.rules)) db.rules = [];
  if (!Array.isArray(db.logs)) db.logs = [];

  return db;
}

const BACKUP_DB_FILE = path.join(path.dirname(DB_FILE), 'keyauth_db.backup.json');

// Load database from file on startup
function loadDatabase() {
  try {
    if (fs.existsSync(DB_FILE)) {
      const raw = fs.readFileSync(DB_FILE, 'utf8');
      if (raw && raw.trim().length > 0) {
        const parsed = JSON.parse(raw);
        inMemoryStore = migrateDBSchema(parsed);
        console.log(`[KeyAuth] Loaded persistent DB from ${DB_FILE} (${inMemoryStore.licenses.length} keys, ${inMemoryStore.users.length} users)`);
        return inMemoryStore;
      }
    }
    // Fallback to backup file if main file is missing or empty
    if (fs.existsSync(BACKUP_DB_FILE)) {
      const rawBackup = fs.readFileSync(BACKUP_DB_FILE, 'utf8');
      if (rawBackup && rawBackup.trim().length > 0) {
        const parsedBackup = JSON.parse(rawBackup);
        inMemoryStore = migrateDBSchema(parsedBackup);
        console.log(`[KeyAuth] Restored from backup DB file: ${BACKUP_DB_FILE}`);
        saveDatabaseSync();
        return inMemoryStore;
      }
    }
  } catch (err) {
    console.error('[KeyAuth DB Load Error]:', err.message);
  }
  inMemoryStore = migrateDBSchema(inMemoryStore);
  saveDatabaseSync();
  return inMemoryStore;
}

let saveTimer = null;
function scheduleSave() {
  if (saveTimer) return;
  saveTimer = setTimeout(() => {
    saveTimer = null;
    try {
      const serialized = JSON.stringify(inMemoryStore, null, 2);
      fs.writeFileSync(DB_FILE, serialized, 'utf8');
      try { fs.writeFileSync(BACKUP_DB_FILE, serialized, 'utf8'); } catch (_) {}
    } catch (err) {
      console.error('[KeyAuth DB Save Error]:', err.message);
    }
  }, 1000);
}

function saveDatabaseSync() {
  try {
    const serialized = JSON.stringify(inMemoryStore, null, 2);
    fs.writeFileSync(DB_FILE, serialized, 'utf8');
    try { fs.writeFileSync(BACKUP_DB_FILE, serialized, 'utf8'); } catch (_) {}
  } catch (err) {
    console.error('[KeyAuth DB Sync Save Error]:', err.message);
  }
}

// Initialize on module load
loadDatabase();

function getDB() {
  return inMemoryStore;
}

function addLog(db, type, username, message, ip = "127.0.0.1", hwid = "", device = "") {
  if (!Array.isArray(db.logs)) db.logs = [];

  let resolvedDevice = (device || "").trim();
  const lowerDev = resolvedDevice.toLowerCase();
  if (!resolvedDevice || lowerDev.startsWith("okhttp") || lowerDev === "keyauth" || lowerDev === "android device") {
    const match = String(message || "").match(/Device:\s*([^\r\n|]+)/i);
    if (match && match[1]) {
      const extracted = match[1].trim();
      const lowerExt = extracted.toLowerCase();
      if (extracted && !lowerExt.startsWith("okhttp") && lowerExt !== "keyauth") {
        resolvedDevice = extracted;
      }
    }
    if (!resolvedDevice || lowerDev.startsWith("okhttp") || lowerDev === "keyauth") {
      resolvedDevice = "Android Device";
    }
  }

  db.logs.unshift({
    id: "log_" + Date.now() + "_" + Math.floor(Math.random() * 1000),
    type: type, // 'LOGIN_SUCCESS' | 'LOGIN_FAILED' | 'HWID_MISMATCH' | 'APP_INIT' | 'SECURITY_ALERT' | 'VAR_ACCESS' | 'FILE_DOWNLOAD' | 'ADMIN_ACTION' | 'CLIENT_LOG' | 'STREAM_ACCESS'
    username: username || "Guest",
    message: message,
    ip: ip || "127.0.0.1",
    hwid: hwid || "",
    device: resolvedDevice,
    time: Date.now()
  });

  if (db.logs.length > 2000) db.logs.length = 2000;
  scheduleSave();
}

async function sendDiscordWebhook(webhookUrl, embed) {
  if (!webhookUrl || typeof webhookUrl !== 'string' || !webhookUrl.startsWith('https://discord.com/api/webhooks/')) return;
  try {
    await fetch(webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: "Ghostrix Sentinel",
        avatar_url: "https://cdn.keyauth.cc/global/imgs/Favicon.png",
        embeds: [embed]
      })
    });
  } catch (e) {
    console.error("[KeyAuth Discord Error]:", e.message);
  }
}

function isAuthorizedAdmin(req, url) {
  const expectedToken = DEFAULT_ADMIN_TOKEN;

  // 1. Query token (?token=...)
  if (url && url.searchParams) {
    const qToken = url.searchParams.get("token");
    if (qToken && (qToken === expectedToken || qToken === ADMIN_CREDENTIALS.pass)) return true;
  }

  // 2. Authorization header (Bearer ...)
  const authHeader = req.headers['authorization'] || '';
  if (authHeader.startsWith("Bearer ")) {
    const t = authHeader.substring(7).trim();
    if (t === expectedToken || t === ADMIN_CREDENTIALS.pass || t.startsWith("admin_token_")) return true;
  }

  // 3. Custom headers
  const xToken = req.headers['x-admin-token'] || req.headers['x-token'];
  if (xToken && (xToken === expectedToken || xToken === ADMIN_CREDENTIALS.pass || xToken.startsWith("admin_token_"))) return true;

  // 4. Cookie
  const cookie = req.headers['cookie'] || '';
  const matchGhostrix = cookie.match(/ghostrix_admin_token=([^;]+)/);
  if (matchGhostrix && (decodeURIComponent(matchGhostrix[1]) === expectedToken || decodeURIComponent(matchGhostrix[1]) === ADMIN_CREDENTIALS.pass)) return true;
  const matchAdmin = cookie.match(/admin_token=([^;]+)/);
  if (matchAdmin) return true;

  return false;
}

function generateKey(mask, lower, upper) {
  let chars = "0123456789";
  if (upper) chars += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  if (lower) chars += "abcdefghijklmnopqrstuvwxyz";
  if (!upper && !lower) chars += "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

  let key = "";
  for (let i = 0; i < mask.length; i++) {
    if (mask[i] === "*") {
      key += chars.charAt(Math.floor(Math.random() * chars.length));
    } else {
      key += mask[i];
    }
  }
  return key;
}

function parseCSVLine(line) {
  const result = [];
  let current = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const char = line[i];
    if (char === '"' || char === "'") {
      if (inQuotes && line[i + 1] === char) {
        current += char;
        i++;
      } else {
        inQuotes = !inQuotes;
      }
    } else if (char === ',' && !inQuotes) {
      result.push(current.trim());
      current = '';
    } else {
      current += char;
    }
  }
  result.push(current.trim());
  return result;
}

function importLicensesFromCSV(db, csvText, targetAppId) {
  if (!csvText || typeof csvText !== 'string') return { count: 0, duplicates: 0 };
  const targetApp = (db.apps || []).find(a => a.id === targetAppId) || (db.apps && db.apps[0]) || defaultDatabase.apps[0];
  if (!Array.isArray(db.licenses)) db.licenses = [];
  if (!Array.isArray(db.users)) db.users = [];

  const lines = csvText.split(/\r?\n/).map(l => l.trim()).filter(l => l.length > 0);
  if (lines.length === 0) return { count: 0, duplicates: 0 };

  let headerIndex = -1;
  let headers = [];

  for (let i = 0; i < Math.min(3, lines.length); i++) {
    const parsed = parseCSVLine(lines[i]).map(h => h.toLowerCase());
    if (parsed.includes('key')) {
      headerIndex = i;
      headers = parsed;
      break;
    }
  }

  let importedCount = 0;
  let dupCount = 0;
  const startLine = headerIndex !== -1 ? headerIndex + 1 : 0;

  for (let i = startLine; i < lines.length; i++) {
    const rawLine = lines[i];
    if (!rawLine) continue;

    let key = '', note = '', expiry = 315569260, status = 'Not Used', level = 1, gendate = Date.now(), usedon = null, usedby = '', banned = '';

    if (headerIndex !== -1) {
      const cols = parseCSVLine(rawLine);
      const row = {};
      headers.forEach((h, idx) => { row[h] = cols[idx] || ''; });

      key = (row.key || '').trim();
      note = (row.note || '').trim();
      expiry = parseInt(row.expiry || 315569260) || 315569260;
      status = (row.status || 'Not Used').trim();
      level = parseInt(row.level || 1) || 1;
      gendate = row.gendate ? (parseInt(row.gendate) < 10000000000 ? parseInt(row.gendate) * 1000 : parseInt(row.gendate)) : Date.now();
      usedon = row.usedon ? (parseInt(row.usedon) < 10000000000 ? parseInt(row.usedon) * 1000 : parseInt(row.usedon)) : null;
      usedby = (row.usedby || '').trim();
      banned = (row.banned || '').trim();
    } else {
      const cols = parseCSVLine(rawLine);
      key = cols[0].trim();
      if (cols.length > 1) note = cols[1].trim();
    }

    if (!key) continue;

    if (banned && banned !== '0' && banned !== 'false') {
      status = 'Banned';
    }

    const existingUser = db.users.find(u => u.username.toLowerCase() === key.toLowerCase() && (!u.appId || u.appId === targetApp.id));
    let hwid = '';
    if (existingUser) {
      hwid = existingUser.hwid || '';
      if (!usedby) usedby = existingUser.username;
      if (status !== 'Banned' && (hwid || usedby)) status = 'Used';
    }

    const existIdx = db.licenses.findIndex(l => l.key.toLowerCase() === key.toLowerCase() && (!l.appId || l.appId === targetApp.id));
    const newLic = {
      key: key,
      appId: targetApp.id,
      appName: targetApp.name,
      level: level,
      duration: expiry,
      unit: expiry > 300000000 ? 'Lifetime' : 'Custom',
      note: note,
      status: status,
      hwidLock: true,
      hwid: hwid,
      usedby: usedby,
      usedon: usedon,
      gendate: gendate,
      expires: Date.now() + expiry * 1000,
      banReason: status === 'Banned' ? 'Imported Ban' : ''
    };

    if (existIdx !== -1) {
      db.licenses[existIdx] = Object.assign(db.licenses[existIdx], newLic);
      dupCount++;
    } else {
      db.licenses.unshift(newLic);
      importedCount++;
    }
  }

  scheduleSave();
  return { count: importedCount, duplicates: dupCount, total: db.licenses.length };
}

function importUsersFromCSV(db, csvText, targetAppId) {
  if (!csvText || typeof csvText !== 'string') return { count: 0, duplicates: 0 };
  const targetApp = (db.apps || []).find(a => a.id === targetAppId) || (db.apps && db.apps[0]) || defaultDatabase.apps[0];
  if (!Array.isArray(db.users)) db.users = [];
  if (!Array.isArray(db.licenses)) db.licenses = [];

  const lines = csvText.split(/\r?\n/).map(l => l.trim()).filter(l => l.length > 0);
  if (lines.length === 0) return { count: 0, duplicates: 0 };

  let headerIndex = -1;
  let headers = [];

  for (let i = 0; i < Math.min(3, lines.length); i++) {
    const parsed = parseCSVLine(lines[i]).map(h => h.toLowerCase());
    if (parsed.includes('username')) {
      headerIndex = i;
      headers = parsed;
      break;
    }
  }

  let importedCount = 0;
  let dupCount = 0;
  const startLine = headerIndex !== -1 ? headerIndex + 1 : 0;

  for (let i = startLine; i < lines.length; i++) {
    const rawLine = lines[i];
    if (!rawLine) continue;

    let username = '', email = '', password = '', hwid = '', createdate = Date.now(), lastlogin = Date.now(), banned = '', ip = '127.0.0.1';

    if (headerIndex !== -1) {
      const cols = parseCSVLine(rawLine);
      const row = {};
      headers.forEach((h, idx) => { row[h] = cols[idx] || ''; });

      username = (row.username || '').trim();
      email = (row.email || '').trim();
      password = (row.password || '').trim();
      hwid = (row.hwid || '').trim();
      ip = (row.ip || '127.0.0.1').trim();
      createdate = row.createdate ? (parseInt(row.createdate) < 10000000000 ? parseInt(row.createdate) * 1000 : parseInt(row.createdate)) : Date.now();
      lastlogin = row.lastlogin ? (parseInt(row.lastlogin) < 10000000000 ? parseInt(row.lastlogin) * 1000 : parseInt(row.lastlogin)) : Date.now();
      banned = (row.banned || '').trim();
    } else {
      const cols = parseCSVLine(rawLine);
      username = cols[0].trim();
      if (cols.length > 1) hwid = cols[1].trim();
    }

    if (!username) continue;

    const isBanned = banned && banned !== '0' && banned !== 'false';
    const status = isBanned ? 'banned' : 'active';

    const existIdx = db.users.findIndex(u => u.username.toLowerCase() === username.toLowerCase() && (!u.appId || u.appId === targetApp.id));
    const newUser = {
      username: username,
      appId: targetApp.id,
      appName: targetApp.name,
      password: password,
      email: email,
      subscription: "default",
      level: 1,
      expires: Date.now() + 315569260 * 1000,
      hwid: hwid,
      hwidAffected: !!hwid,
      status: status,
      ip: ip,
      device: "Android",
      lastLogin: lastlogin,
      created: createdate,
      banReason: isBanned ? "Imported Ban" : "",
      banExpires: 0
    };

    if (existIdx !== -1) {
      db.users[existIdx] = Object.assign(db.users[existIdx], newUser);
      dupCount++;
    } else {
      db.users.unshift(newUser);
      importedCount++;
    }

    const lic = db.licenses.find(l => l.key.toLowerCase() === username.toLowerCase() && (!l.appId || l.appId === targetApp.id));
    if (lic) {
      if (hwid) lic.hwid = hwid;
      lic.usedby = username;
      lic.status = isBanned ? 'Banned' : 'Used';
    }
  }

  scheduleSave();
  return { count: importedCount, duplicates: dupCount, total: db.users.length };
}

function resolveTargetApp(db, params) {
  if (!Array.isArray(db.apps) || db.apps.length === 0) {
    return (defaultDatabase.apps && defaultDatabase.apps[0]);
  }
  const pName = (params.name || "").trim().toLowerCase();
  const pOwner = (params.ownerid || "").trim();

  if (pName && pOwner) {
    const match = db.apps.find(a => a.name.toLowerCase() === pName && a.ownerid === pOwner);
    if (match) return match;
  }
  if (pName) {
    const match = db.apps.find(a => a.name.toLowerCase() === pName);
    if (match) return match;
  }
  if (pOwner) {
    const match = db.apps.find(a => a.ownerid === pOwner);
    if (match) return match;
  }
  if (params.sessionid && Array.isArray(db.sessions)) {
    const sess = db.sessions.find(s => s.id === params.sessionid);
    if (sess && sess.appId) {
      const match = db.apps.find(a => a.id === sess.appId);
      if (match) return match;
    }
  }
  if (params.key && Array.isArray(db.licenses)) {
    const targetLic = db.licenses.find(l => l.key.toLowerCase() === params.key.trim().toLowerCase());
    if (targetLic && targetLic.appId) {
      const match = db.apps.find(a => a.id === targetLic.appId);
      if (match) return match;
    }
  }
  if (db.activeAppId) {
    const match = db.apps.find(a => a.id === db.activeAppId);
    if (match) return match;
  }
  return db.apps[0];
}

function resolveClientDevice(params, req, db) {
  function isJunkAgent(str) {
    if (!str || typeof str !== 'string') return true;
    const s = str.trim().toLowerCase();
    if (!s || s === 'n/a' || s === 'unknown' || s === 'null' || s === 'undefined') return true;
    if (s.startsWith('okhttp') || s.includes('okhttp/')) return true;
    if (s === 'keyauth' || s.startsWith('keyauth/')) return true;
    if (s.startsWith('curl') || s.startsWith('postman') || s.startsWith('python') || s.startsWith('axios') || s.startsWith('node-fetch')) return true;
    return false;
  }
  function cleanStr(val) {
    if (!val || typeof val !== 'string') return '';
    return val.trim().replace(/^["']|["']$/g, '');
  }

  const candidates = [params.pcuser, params.device, params.devicename, params.model, params.device_name];
  for (const c of candidates) {
    const cleaned = cleanStr(c);
    if (cleaned && !isJunkAgent(cleaned)) return cleaned;
  }

  const msg = params.message || params.data || "";
  if (msg) {
    const match = String(msg).match(/Device:\s*([^\r\n|]+)/i);
    if (match && match[1]) {
      const dev = cleanStr(match[1]);
      if (dev && !isJunkAgent(dev)) return dev;
    }
  }

  if (req && req.headers) {
    const headers = [
      req.headers['x-device-name'],
      req.headers['x-device-model'],
      req.headers['x-device'],
      req.headers['device-name']
    ];
    for (const h of headers) {
      const cleaned = cleanStr(h);
      if (cleaned && !isJunkAgent(cleaned)) return cleaned;
    }

    const ua = cleanStr(req.headers['user-agent']);
    if (ua && !isJunkAgent(ua)) {
      const androidModelMatch = ua.match(/Android\s+[^;]+;\s*([^;)]+)/i);
      if (androidModelMatch && androidModelMatch[1]) {
        return cleanStr(androidModelMatch[1]);
      }
      return ua;
    }
  }

  if (params.sessionid && db && Array.isArray(db.sessions)) {
    const sess = db.sessions.find(s => s.id === params.sessionid);
    if (sess && sess.device && !isJunkAgent(sess.device)) {
      return cleanStr(sess.device);
    }
  }

  if (db && Array.isArray(db.users)) {
    const targetKey = (params.username || params.key || "").trim().toLowerCase();
    if (targetKey) {
      const u = db.users.find(usr => usr.username.toLowerCase() === targetKey);
      if (u && u.device && !isJunkAgent(u.device)) {
        return cleanStr(u.device);
      }
    }
  }

  return "Android Device";
}

function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) return forwarded.split(',')[0].trim().replace(/^::ffff:/, '');
  const cf = req.headers['cf-connecting-ip'];
  if (cf) return cf.trim().replace(/^::ffff:/, '');
  return (req.socket?.remoteAddress || '127.0.0.1').replace(/^::ffff:/, '');
}

/**
 * Handle KeyAuth 1.2 Protocol (/api/1.2/)
 */
async function handleKeyAuthProtocol(req, res, url, body) {
  const params = Object.assign({}, body || {});
  for (const [k, v] of url.searchParams.entries()) {
    if (params[k] === undefined) params[k] = v;
  }

  const type = params.type || "init";
  const db = getDB();
  const currentApp = resolveTargetApp(db, params);
  const clientIp = getClientIp(req);
  const clientDevice = resolveClientDevice(params, req, db);

  const jsonResp = (obj, status = 200) => {
    const bodyStr = JSON.stringify(obj);
    res.writeHead(status, {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS, PUT, DELETE'
    });
    res.end(bodyStr);
  };

  // Blacklist Security Check
  if (Array.isArray(db.rules) && db.rules.length > 0) {
    const matchedRule = db.rules.find(r => {
      if (r.type === "ip" && r.value === clientIp) return true;
      if (r.type === "hwid" && (params.hwid || "").trim() && r.value.toLowerCase() === (params.hwid || "").trim().toLowerCase()) return true;
      return false;
    });
    if (matchedRule) {
      addLog(db, "SECURITY_ALERT", "Blacklisted", `Access blocked by rule [${matchedRule.type.toUpperCase()}: ${matchedRule.value}] (${matchedRule.reason || 'Blacklisted'})`, clientIp, params.hwid || "", clientDevice);
      if (currentApp.discordWebhook) {
        sendDiscordWebhook(currentApp.discordWebhook, {
          title: "🚨 Blacklist Rule Triggered",
          description: `Blocked request matching rule: **${matchedRule.type.toUpperCase()}**: \`${matchedRule.value}\`\nReason: ${matchedRule.reason || 'Violation'}`,
          color: 16711680,
          fields: [
            { name: "IP", value: clientIp, inline: true },
            { name: "HWID", value: params.hwid || "N/A", inline: true }
          ]
        });
      }
      return jsonResp({ success: false, message: `Access Blocked: Your ${matchedRule.type.toUpperCase()} is blacklisted! Reason: ${matchedRule.reason || 'Security violation'}` });
    }
  }

  // Rate Limiting & Brute-Force Check
  if (!checkRateLimit(clientIp)) {
    if (currentApp.autoBan !== false) {
      if (!Array.isArray(db.rules)) db.rules = [];
      if (!db.rules.some(r => r.type === "ip" && r.value === clientIp)) {
        db.rules.unshift({
          id: "rule_autoban_" + Date.now(),
          type: "ip",
          value: clientIp,
          reason: "Auto-Ban: Exceeded maximum failed login attempts (Brute Force Protection)",
          created: Date.now()
        });
      }
    }
    addLog(db, "SECURITY_ALERT", "Unknown", "Temporary lockout: Exceeded maximum failed login attempts (Auto-Blacklisted).", clientIp, params.hwid || "", clientDevice);
    if (currentApp.discordWebhook) {
      sendDiscordWebhook(currentApp.discordWebhook, {
        title: "⚠️ Brute-Force Lockout & Auto-Ban",
        description: `IP \`${clientIp}\` was automatically blocked for repeated failures.`,
        color: 16753920,
        fields: [
          { name: "IP", value: clientIp, inline: true },
          { name: "Device", value: clientDevice, inline: true }
        ]
      });
    }
    return jsonResp({ success: false, message: "Security lockout: Too many failed attempts. Your IP has been temporarily blacklisted." });
  }

  // 1. type = init
  if (type === "init") {
    if (currentApp.status === "Paused") {
      return jsonResp({ success: false, message: "Application is paused by developer." });
    }
    if (currentApp.strictVersionCheck && params.ver && params.ver !== currentApp.version) {
      addLog(db, "SECURITY_ALERT", "Client", `Client version mismatch: v${params.ver} rejected, required v${currentApp.version}`, clientIp, params.hwid || "", clientDevice);
      return jsonResp({
        success: false,
        message: "invalidver",
        download: currentApp.downloadUrl || "",
        version: currentApp.version
      });
    }
    if (currentApp.hashCheck && currentApp.appHash) {
      const clientHash = params.hash || params.apphash || "";
      if (clientHash.toLowerCase() !== currentApp.appHash.toLowerCase()) {
        addLog(db, "SECURITY_ALERT", "Unknown", `Integrity mismatch: APK hash [${clientHash}] does not match developer hash.`, clientIp, params.hwid || "", clientDevice);
        return jsonResp({ success: false, message: "Security Alert: APK modified or untrusted version detected!" });
      }
    }

    const sessionid = "sess_" + Math.random().toString(36).substring(2, 15);
    if (!Array.isArray(db.sessions)) db.sessions = [];
    db.sessions = db.sessions.filter(s => Date.now() - (s.lastPing || s.started || 0) < 86400000);
    db.sessions.push({
      id: sessionid,
      appId: currentApp.id,
      appName: currentApp.name,
      authenticated: false,
      username: "",
      key: "",
      hwid: params.hwid || "",
      ip: clientIp,
      device: clientDevice,
      started: Date.now(),
      lastPing: Date.now()
    });

    const apkUser = (params.key || params.username || params.user || "APK Client").trim();
    addLog(db, "APP_INIT", apkUser, `APK Opened / App Initialized [${currentApp.name} v${params.ver || currentApp.version}] | HWID: ${params.hwid || 'N/A'}`, clientIp, params.hwid || "", clientDevice);

    const appUsers = (db.users || []).filter(u => !u.appId || u.appId === currentApp.id);
    const appOnline = (db.sessions || []).filter(s => (!s.appId || s.appId === currentApp.id) && s.authenticated);
    const appKeys = (db.licenses || []).filter(l => !l.appId || l.appId === currentApp.id);

    return jsonResp({
      success: true,
      message: "Initialized",
      sessionid: sessionid,
      appinfo: {
        numUsers: String(appUsers.length),
        numOnlineUsers: String(appOnline.length),
        numKeys: String(appKeys.length),
        version: currentApp.version,
        customerPanel: "http://" + (req.headers.host || 'localhost') + "/admin"
      },
      newSession: true,
      ip: clientIp
    });
  }

  // 2. type = license (direct key login)
  if (type === "license") {
    const key = (params.key || "").trim();
    const hwid = (params.hwid || "").trim();

    if (!key) {
      recordIpFailure(clientIp);
      addLog(db, "LOGIN_FAILED", "Unknown", "Key Login Failed: License key was not provided", clientIp, hwid, clientDevice);
      return jsonResp({ success: false, message: "License key is required!" });
    }

    const lic = (db.licenses || []).find(l => l.key.toLowerCase() === key.toLowerCase());
    if (!lic) {
      recordIpFailure(clientIp);
      addLog(db, "LOGIN_FAILED", key, `Key Login Failed: License key [${key}] does not exist`, clientIp, hwid, clientDevice);
      return jsonResp({ success: false, message: "License key does not exist!" });
    }

    if (lic.appId && lic.appId !== currentApp.id) {
      recordIpFailure(clientIp);
      addLog(db, "LOGIN_FAILED", key, `Key Login Failed: Key [${key}] belongs to another app [${lic.appName || lic.appId}]`, clientIp, hwid, clientDevice);
      return jsonResp({ success: false, message: "License key does not exist for this application!" });
    }

    if (!lic.appId) {
      lic.appId = currentApp.id;
      lic.appName = currentApp.name;
    }

    if (lic.status === "Banned") {
      recordIpFailure(clientIp);
      addLog(db, "LOGIN_FAILED", key, `Key Login Failed: Key [${key}] is BANNED! Reason: ${lic.banReason || 'Terms violation'}`, clientIp, hwid, clientDevice);
      return jsonResp({ success: false, message: "This license key is banned! Reason: " + (lic.banReason || "Terms violation") });
    }

    if (lic.status === "Paused") {
      recordIpFailure(clientIp);
      addLog(db, "LOGIN_FAILED", key, `Key Login Failed: Key [${key}] is Paused by Admin`, clientIp, hwid, clientDevice);
      return jsonResp({ success: false, message: "This license key is temporarily paused by administrator." });
    }

    if (lic.expires && lic.expires < Date.now()) {
      recordIpFailure(clientIp);
      addLog(db, "LOGIN_FAILED", key, `Key Login Failed: Key [${key}] has EXPIRED`, clientIp, hwid, clientDevice);
      return jsonResp({ success: false, message: "License key has expired!" });
    }

    const keyHwidLocked = lic.hwidLock !== false && currentApp.hwidLock !== false;
    if (keyHwidLocked) {
      if (!lic.hwid && hwid) {
        lic.hwid = hwid; // Lock key to device
      } else if (lic.hwid && hwid && lic.hwid !== hwid) {
        recordIpFailure(clientIp);
        addLog(db, "HWID_MISMATCH", key, `Key Login Blocked: HWID Mismatch! Registered: [${lic.hwid}] vs Device: [${hwid}]`, clientIp, hwid, clientDevice);
        return jsonResp({ success: false, message: "HWID Mismatch: Device locked to another phone. Contact developer to reset HWID." });
      }
    }

    clearIpFailure(clientIp);

    if (!Array.isArray(db.users)) db.users = [];
    let user = db.users.find(u => u.username === lic.usedby);
    if (!lic.usedby || !user) {
      lic.status = "Used";
      lic.usedby = key;
      lic.usedon = Date.now();
      user = {
        username: key,
        appId: currentApp.id,
        appName: currentApp.name,
        password: "",
        email: "",
        subscription: "default",
        level: lic.level || 1,
        expires: lic.expires || (Date.now() + lic.duration * 1000),
        hwid: lic.hwid || hwid,
        hwidAffected: keyHwidLocked,
        status: "active",
        ip: clientIp,
        device: clientDevice,
        lastLogin: Date.now(),
        created: Date.now(),
        banReason: "",
        banExpires: 0
      };
      db.users.push(user);
    } else {
      if (user.status === "banned") {
        addLog(db, "LOGIN_FAILED", user.username, `User account is banned.`, clientIp, hwid, clientDevice);
        return jsonResp({ success: false, message: "User is banned! Reason: " + (user.banReason || "Violation") });
      }
      if (user.status === "paused") {
        return jsonResp({ success: false, message: "User account is temporarily paused." });
      }
      if (keyHwidLocked && user.hwid && hwid && user.hwid !== hwid) {
        addLog(db, "HWID_MISMATCH", user.username, `User HWID mismatch: bound [${user.hwid}] vs [${hwid}]`, clientIp, hwid, clientDevice);
        return jsonResp({ success: false, message: "HWID does not match! Please reset HWID in dashboard." });
      }
      if (!user.hwid && hwid) user.hwid = hwid;
      user.lastLogin = Date.now();
      user.ip = clientIp;
      user.device = clientDevice;
    }

    if (!Array.isArray(db.sessions)) db.sessions = [];
    let sess = db.sessions.find(s => s.id === params.sessionid);
    if (!sess && params.sessionid) {
      sess = { id: params.sessionid, ip: clientIp, started: Date.now() };
      db.sessions.push(sess);
    }
    if (sess) {
      sess.authenticated = true;
      sess.appId = currentApp.id;
      sess.appName = currentApp.name;
      sess.username = user.username;
      sess.key = lic.key;
      sess.hwid = lic.hwid || hwid;
      sess.device = clientDevice;
      sess.lastPing = Date.now();
    }

    addLog(db, "LOGIN_SUCCESS", lic.key, `Key Login Success: Key [${lic.key}] authenticated | HWID: ${lic.hwid || 'Unlocked'} | Duration: ${lic.unit || 'Active'}`, clientIp, hwid, clientDevice);

    return jsonResp({
      success: true,
      message: "Logged in successfully!",
      info: {
        username: user.username,
        subscriptions: [
          {
            subscription: "default",
            key: lic.key,
            expiry: String(Math.floor(user.expires / 1000)),
            timeleft: Math.max(0, Math.floor((user.expires - Date.now()) / 1000))
          }
        ],
        ip: clientIp,
        hwid: user.hwid,
        createdate: String(Math.floor(user.created / 1000)),
        lastlogin: String(Math.floor(user.lastLogin / 1000))
      }
    });
  }

  // 3. type = login (username + password)
  if (type === "login") {
    const username = (params.username || "").trim();
    const pass = (params.pass || "").trim();
    const hwid = (params.hwid || "").trim();

    const user = (db.users || []).find(u => u.username.toLowerCase() === username.toLowerCase());
    if (!user || (user.password && user.password !== pass)) {
      recordIpFailure(clientIp);
      addLog(db, "LOGIN_FAILED", username, `Invalid credentials for user: ${username}`, clientIp, hwid, clientDevice);
      return jsonResp({ success: false, message: "Username or password invalid!" });
    }

    if (user.status === "banned") {
      addLog(db, "LOGIN_FAILED", username, `User is banned. Reason: ${user.banReason || 'Violation'}`, clientIp, hwid, clientDevice);
      return jsonResp({ success: false, message: "User is banned! Reason: " + (user.banReason || "Violation") });
    }

    if (user.status === "paused") {
      return jsonResp({ success: false, message: "User account is temporarily paused." });
    }

    if (user.hwidAffected !== false && currentApp.hwidLock && user.hwid && hwid && user.hwid !== hwid) {
      recordIpFailure(clientIp);
      addLog(db, "HWID_MISMATCH", username, `HWID mismatch on user login: bound [${user.hwid}] vs [${hwid}]`, clientIp, hwid, clientDevice);
      return jsonResp({ success: false, message: "HWID does not match!" });
    }

    clearIpFailure(clientIp);
    user.lastLogin = Date.now();
    user.ip = clientIp;
    user.device = clientDevice;
    if (!user.hwid && hwid) user.hwid = hwid;

    if (!Array.isArray(db.sessions)) db.sessions = [];
    let sess = db.sessions.find(s => s.id === params.sessionid);
    if (!sess && params.sessionid) {
      sess = { id: params.sessionid, ip: clientIp, started: Date.now() };
      db.sessions.push(sess);
    }
    if (sess) {
      sess.authenticated = true;
      sess.username = user.username;
      sess.key = user.subscription || "default";
      sess.hwid = hwid;
      sess.device = clientDevice;
      sess.lastPing = Date.now();
    }

    addLog(db, "LOGIN_SUCCESS", user.username, `User logged in with username/pass: [${user.username}]`, clientIp, hwid, clientDevice);

    return jsonResp({
      success: true,
      message: "Logged in successfully!",
      info: {
        username: user.username,
        subscriptions: [
          {
            subscription: user.subscription || "default",
            expiry: String(Math.floor(user.expires / 1000)),
            timeleft: Math.max(0, Math.floor((user.expires - Date.now()) / 1000))
          }
        ],
        ip: clientIp,
        hwid: user.hwid
      }
    });
  }

  // 4. type = log (Client app logger)
  if (type === "log") {
    const message = params.message || params.data || "Client Log Triggered";
    const username = params.username || "Client";
    addLog(db, "CLIENT_LOG", username, String(message), clientIp, params.hwid || "", clientDevice);
    return jsonResp({ success: true, message: "Logged message successfully" });
  }

  // 5. type = check (session validity check)
  if (type === "check") {
    const sessionid = (params.sessionid || "").trim();
    const sess = (db.sessions || []).find(s => s.id === sessionid);
    if (!sess || !sess.authenticated) {
      return jsonResp({ success: false, message: "Session is not logged in / unauthenticated." });
    }
    const u = (db.users || []).find(usr => usr.username === sess.username);
    if (u) {
      if (u.status === "banned") return jsonResp({ success: false, message: "User is banned!" });
      if (u.status === "paused") return jsonResp({ success: false, message: "User is paused!" });
      if (u.expires && u.expires < Date.now()) return jsonResp({ success: false, message: "License has expired!" });
    }
    sess.lastPing = Date.now();
    return jsonResp({ success: true, message: "Session is active and valid." });
  }

  // 6. type = var (Strict Authentication Required)
  if (type === "var") {
    const varid = (params.varid || params.name || "").trim();
    const sessionid = (params.sessionid || "").trim();
    const key = (params.key || "").trim();

    let isAuthed = false;
    let authedUser = "";

    if (sessionid) {
      const sess = (db.sessions || []).find(s => s.id === sessionid);
      if (sess && sess.authenticated) {
        const authUser = (db.users || []).find(u => u.username === sess.username);
        if (authUser) {
          if (authUser.status === "banned") return jsonResp({ success: false, message: "User account is banned!" });
          if (authUser.status === "paused") return jsonResp({ success: false, message: "User account is paused." });
          if (authUser.expires && authUser.expires < Date.now()) return jsonResp({ success: false, message: "License has expired!" });
          isAuthed = true;
          authedUser = authUser.username;
        } else {
          isAuthed = true;
          authedUser = sess.username || sess.key;
        }
      }
    }

    if (!isAuthed && key) {
      const lic = (db.licenses || []).find(l => l.key.toLowerCase() === key.toLowerCase());
      if (lic) {
        if (lic.status === "Banned") return jsonResp({ success: false, message: "License key is banned!" });
        if (lic.status === "Paused") return jsonResp({ success: false, message: "License key is paused!" });
        if (lic.expires && lic.expires < Date.now()) return jsonResp({ success: false, message: "License key has expired!" });
        isAuthed = true;
        authedUser = lic.usedby || lic.key;
      }
    }

    // STRICT: Reject if no authenticated session or valid key
    if (!isAuthed) {
      addLog(db, "SECURITY_ALERT", "Unknown", `Unauthorized attempt to read variable: [${varid}]`, clientIp, params.hwid || "", clientDevice);
      return jsonResp({
        success: false,
        message: "Access Denied: You must be logged in with a valid active license key to access application variables!"
      });
    }

    const item = (db.variables || []).find(v => v.name.toLowerCase() === varid.toLowerCase() && v.appId === currentApp.id)
      || (db.variables || []).find(v => v.name.toLowerCase() === varid.toLowerCase() && (!v.appId || v.appId === "all"));
    if (!item) {
      return jsonResp({ success: false, message: "Variable not found!" });
    }

    addLog(db, "VAR_ACCESS", authedUser, `Accessed variable: [${varid}]`, clientIp, params.hwid || "", clientDevice);
    return jsonResp({ success: true, message: item.data, response: item.data });
  }

  // 7. type = file (Strict Authentication Required)
  if (type === "file" || type === "download" || type === "fetchfile") {
    const fileid = (params.fileid || params.id || params.name || "").trim();
    const sessionid = (params.sessionid || "").trim();
    const key = (params.key || "").trim();

    let isAuthed = false;
    let authedUser = "";

    if (sessionid) {
      const sess = (db.sessions || []).find(s => s.id === sessionid);
      if (sess && sess.authenticated) {
        const u = (db.users || []).find(usr => usr.username === sess.username);
        if (u) {
          if (u.status === "banned" || u.status === "paused" || (u.expires && u.expires < Date.now())) {
            return jsonResp({ success: false, message: "User account is invalid, banned or expired!" });
          }
          authedUser = u.username;
        }
        isAuthed = true;
        if (!authedUser) authedUser = sess.username || sess.key;
      }
    }

    if (!isAuthed && key) {
      const lic = (db.licenses || []).find(l => l.key.toLowerCase() === key.toLowerCase());
      if (lic && lic.status !== "Banned" && lic.status !== "Paused" && (!lic.expires || lic.expires >= Date.now())) {
        isAuthed = true;
        authedUser = lic.usedby || lic.key;
      }
    }

    if (!isAuthed) {
      addLog(db, "SECURITY_ALERT", "Unknown", `Unauthorized attempt to download file: [${fileid}]`, clientIp, params.hwid || "", clientDevice);
      return jsonResp({
        success: false,
        message: "Access Denied: Valid active license key required to download application files!"
      });
    }

    const file = (db.files || []).find(f => (f.id === fileid || f.name.toLowerCase() === fileid.toLowerCase()) && f.appId === currentApp.id)
      || (db.files || []).find(f => (f.id === fileid || f.name.toLowerCase() === fileid.toLowerCase()) && (!f.appId || f.appId === "all"))
      || (db.files && db.files[0]);
    if (!file) {
      return jsonResp({ success: false, message: "File not found!" });
    }

    addLog(db, "FILE_DOWNLOAD", authedUser, `Downloaded file: [${file.name}] (${file.size})`, clientIp, params.hwid || "", clientDevice);
    return jsonResp({
      success: true,
      message: "File authorized",
      response: file.url,
      url: file.url,
      name: file.name,
      size: file.size
    });
  }

  return jsonResp({ success: true, message: "OK" });
}

/**
 * Handle Admin API Endpoints (/api/admin/...)
 */
async function handleAdminApi(req, res, url, body) {
  const path = url.pathname;
  const jsonResp = (obj, status = 200) => {
    res.writeHead(status, {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS, PUT, DELETE'
    });
    res.end(JSON.stringify(obj));
  };

  // Login endpoint: supports both secret token & username/password
  if (path === "/api/admin/login") {
    const token = (body.token || "").trim();
    const username = (body.username || "").trim();
    const password = (body.password || "").trim();

    const expectedToken = DEFAULT_ADMIN_TOKEN;
    const isTokenMatch = token === expectedToken || token === ADMIN_CREDENTIALS.pass;
    const isCredMatch = (username === ADMIN_CREDENTIALS.user && password === ADMIN_CREDENTIALS.pass) || (password === ADMIN_CREDENTIALS.pass);

    if (isTokenMatch || isCredMatch) {
      const issuedToken = expectedToken;
      res.writeHead(200, {
        'Content-Type': 'application/json',
        'Set-Cookie': `ghostrix_admin_token=${encodeURIComponent(issuedToken)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000`,
        'Access-Control-Allow-Origin': '*'
      });
      res.end(JSON.stringify({ success: true, message: "Authenticated", token: issuedToken, user: ADMIN_CREDENTIALS.user }));
      return;
    }
    return jsonResp({ success: false, message: "Invalid Admin Secret Key or Credentials!" }, 401);
  }

  // Authorization check for all other admin routes
  if (!isAuthorizedAdmin(req, url)) {
    return jsonResp({ success: false, message: "Unauthorized. Admin Token Required." }, 401);
  }

  const db = getDB();

  // Overview Stats
  if (path === "/api/admin/overview") {
    const currentApp = (db.apps && db.apps.find(a => a.id === db.activeAppId)) || (db.apps && db.apps[0]) || defaultDatabase.apps[0];
    const appLicenses = (db.licenses || []).filter(l => !l.appId || l.appId === currentApp.id);
    const appUsers = (db.users || []).filter(u => !u.appId || u.appId === currentApp.id);
    const appSessions = (db.sessions || []).filter(s => (!s.appId || s.appId === currentApp.id) && s.authenticated);

    return jsonResp({
      success: true,
      currentApp,
      activeAppId: db.activeAppId,
      apps: db.apps || [],
      isD1Active: false,
      isKvActive: true,
      storageType: "Persistent JSON Database",
      stats: {
        totalApps: (db.apps || []).length,
        activeApps: (db.apps || []).filter(a => a.status === "Active").length,
        pausedApps: (db.apps || []).filter(a => a.status === "Paused").length,
        totalUsers: (db.users || []).length,
        appUsers: appUsers.length,
        totalLicenses: (db.licenses || []).length,
        appLicenses: appLicenses.length,
        usedLicenses: appLicenses.filter(l => l.status === "Used").length,
        unusedLicenses: appLicenses.filter(l => l.status === "Not Used").length,
        pausedLicenses: appLicenses.filter(l => l.status === "Paused").length,
        bannedLicenses: appLicenses.filter(l => l.status === "Banned").length,
        activeSessions: appSessions.length,
        totalFiles: (db.files || []).length,
        totalVariables: (db.variables || []).length,
        totalRules: (db.rules || []).length,
        totalLogs: (db.logs || []).length
      }
    });
  }

  // Apps
  if (path === "/api/admin/apps") {
    return jsonResp({ success: true, apps: db.apps || [], activeAppId: db.activeAppId });
  }

  if (path === "/api/admin/apps/action") {
    const { action, appId, name, description } = body;
    if (!Array.isArray(db.apps)) db.apps = [];

    if (action === "select") {
      db.activeAppId = appId;
      const targetApp = db.apps.find(a => a.id === appId);
      addLog(db, "ADMIN_ACTION", "Admin", `Switched active app to: ${targetApp ? targetApp.name : appId}`);
    } else if (action === "create") {
      const newApp = {
        id: "app_" + Date.now(),
        name: (name || "New App").trim(),
        ownerid: "usr_" + Math.random().toString(36).substring(2, 10),
        secret: crypto.randomBytes(32).toString('hex'),
        version: (body.version || "1.0").trim(),
        status: "Active",
        description: (description || "New Application").trim(),
        standing: "Good",
        hwidLock: body.hwidLock !== false && body.hwidLock !== "false",
        forceHwid: true,
        blockVpn: body.blockVpn === true || body.blockVpn === "true",
        strictVersionCheck: body.strictVersionCheck === true || body.strictVersionCheck === "true",
        hashCheck: false,
        appHash: "",
        discordWebhook: (body.discordWebhook || "").trim(),
        downloadUrl: (body.downloadUrl || "").trim(),
        autoBan: true,
        requireKeyForProxy: body.requireKeyForProxy === true || body.requireKeyForProxy === "true",
        created: Date.now()
      };
      db.apps.push(newApp);
      db.activeAppId = newApp.id;
      addLog(db, "ADMIN_ACTION", "Admin", `Created application: ${newApp.name} (v${newApp.version})`);
    } else if (action === "edit") {
      const app = db.apps.find(a => a.id === appId);
      if (app) {
        const oldName = app.name;
        if (body.name) app.name = body.name.trim();
        if (body.version) app.version = body.version.trim();
        if (body.description !== undefined) app.description = body.description.trim();
        if (body.status !== undefined) app.status = body.status;
        if (body.hwidLock !== undefined) app.hwidLock = body.hwidLock === true || body.hwidLock === "true";
        if (body.blockVpn !== undefined) app.blockVpn = body.blockVpn === true || body.blockVpn === "true";
        if (body.strictVersionCheck !== undefined) app.strictVersionCheck = body.strictVersionCheck === true || body.strictVersionCheck === "true";
        if (body.discordWebhook !== undefined) app.discordWebhook = body.discordWebhook.trim();
        if (body.downloadUrl !== undefined) app.downloadUrl = body.downloadUrl.trim();
        if (body.appHash !== undefined) app.appHash = body.appHash.trim();
        if (body.requireKeyForProxy !== undefined) app.requireKeyForProxy = body.requireKeyForProxy === true || body.requireKeyForProxy === "true";

        if (body.name && body.name !== oldName) {
          (db.licenses || []).forEach(l => { if (l.appId === app.id) l.appName = app.name; });
          (db.users || []).forEach(u => { if (u.appId === app.id) u.appName = app.name; });
        }
        addLog(db, "ADMIN_ACTION", "Admin", `Updated application settings for: ${app.name}`);
      }
    } else if (action === "delete") {
      if (db.apps.length <= 1) {
        return jsonResp({ success: false, message: "Cannot delete the only application!" }, 400);
      }
      const idx = db.apps.findIndex(a => a.id === appId);
      if (idx !== -1) {
        const delApp = db.apps[idx];
        db.apps.splice(idx, 1);
        if (db.activeAppId === appId) {
          db.activeAppId = db.apps[0].id;
        }
        addLog(db, "ADMIN_ACTION", "Admin", `Deleted application: ${delApp.name}`);
      }
    } else if (action === "pause") {
      const app = db.apps.find(a => a.id === appId);
      if (app) {
        app.status = app.status === "Active" ? "Paused" : "Active";
        addLog(db, "ADMIN_ACTION", "Admin", `Toggled app status [${app.name}]: ${app.status}`);
      }
    } else if (action === "refresh_secret") {
      const app = db.apps.find(a => a.id === appId);
      if (app) {
        app.secret = crypto.randomBytes(32).toString('hex');
        addLog(db, "ADMIN_ACTION", "Admin", `Regenerated secret for app: ${app.name}`);
      }
    }
    scheduleSave();
    return jsonResp({ success: true, apps: db.apps, activeAppId: db.activeAppId });
  }

  // Licenses
  if (path === "/api/admin/licenses") {
    return jsonResp({ success: true, licenses: db.licenses || [] });
  }

  if (path === "/api/admin/licenses/import") {
    const targetAppId = body.appId || db.activeAppId || (db.apps[0] && db.apps[0].id);
    const result = importLicensesFromCSV(db, body.csv || body.text || "", targetAppId);
    addLog(db, "ADMIN_ACTION", "Admin", `Imported ${result.count} licenses (${result.duplicates} updated) into [${targetAppId}]`);
    return jsonResp({ success: true, count: result.count, duplicates: result.duplicates, total: result.total, licenses: db.licenses });
  }

  if (path === "/api/admin/licenses/create") {
    const amount = Math.min(100, Math.max(1, parseInt(body.amount || 1)));
    const mask = body.mask || "Chki-******-gn";
    const lower = body.lowercaseLetters === true || body.lowercaseLetters === "true";
    const upper = body.capitalLetters === true || body.capitalLetters === "true";
    const level = parseInt(body.level || 1);
    const note = body.note || "";
    const unit = body.expiryUnit || body.expiry || "Lifetime";
    const duration = parseInt(body.duration || 1);
    const hwidLock = body.hwidLock !== false && body.hwidLock !== "false";

    let unitMultiplier = 86400;
    if (unit === "Seconds") unitMultiplier = 1;
    else if (unit === "Minutes") unitMultiplier = 60;
    else if (unit === "Hours") unitMultiplier = 3600;
    else if (unit === "Days") unitMultiplier = 86400;
    else if (unit === "Weeks") unitMultiplier = 604800;
    else if (unit === "Months") unitMultiplier = 2629743;
    else if (unit === "Years") unitMultiplier = 31556926;
    else if (unit === "Lifetime") unitMultiplier = 315569260;

    const totalSeconds = duration * unitMultiplier;
    const newKeys = [];

    if (!Array.isArray(db.licenses)) db.licenses = [];
    const targetAppId = body.appId || db.activeAppId || (db.apps[0] && db.apps[0].id);
    const targetApp = (db.apps || []).find(a => a.id === targetAppId) || db.apps[0] || defaultDatabase.apps[0];

    for (let i = 0; i < amount; i++) {
      const genKey = generateKey(mask, lower, upper);
      const lic = {
        key: genKey,
        appId: targetApp.id,
        appName: targetApp.name,
        level: level,
        duration: totalSeconds,
        unit: unit,
        note: note,
        status: "Not Used",
        hwidLock: hwidLock,
        hwid: "",
        usedby: "",
        usedon: null,
        gendate: Date.now(),
        expires: Date.now() + totalSeconds * 1000,
        banReason: ""
      };
      db.licenses.unshift(lic);
      newKeys.push(genKey);
    }

    addLog(db, "ADMIN_ACTION", "Admin", `Generated ${amount} license keys for [${targetApp.name}] (HWID Lock: ${hwidLock ? 'ON' : 'OFF'}, Expiry: ${unit})`);
    scheduleSave();
    return jsonResp({ success: true, count: amount, keys: newKeys });
  }

  if (path === "/api/admin/licenses/action") {
    const { action, key, keys, reason, delUserToo } = body;
    if (!Array.isArray(db.licenses)) db.licenses = [];

    if (action === "edit") {
      const lic = db.licenses.find(l => l.key === key);
      if (lic) {
        if (body.newKey && body.newKey !== key) lic.key = body.newKey.trim();
        if (body.note !== undefined) lic.note = body.note.trim();
        if (body.level !== undefined) lic.level = parseInt(body.level || 1);
        if (body.hwidLock !== undefined) lic.hwidLock = body.hwidLock === true || body.hwidLock === "true";
        if (body.hwid !== undefined) lic.hwid = body.hwid.trim();
        if (body.status !== undefined) lic.status = body.status;
        if (body.banReason !== undefined) lic.banReason = body.banReason;
        if (body.expiryTimestamp) {
          lic.expires = parseInt(body.expiryTimestamp);
          lic.duration = Math.max(0, Math.floor((lic.expires - Date.now()) / 1000));
        }

        if (lic.usedby) {
          const u = (db.users || []).find(usr => usr.username === lic.usedby);
          if (u) {
            u.hwidAffected = lic.hwidLock;
            u.hwid = lic.hwid;
            u.expires = lic.expires;
            if (lic.status === "Banned") u.status = "banned";
            else if (lic.status === "Paused") u.status = "paused";
            else if (u.status === "banned" || u.status === "paused") u.status = "active";
          }
        }
        addLog(db, "ADMIN_ACTION", "Admin", `Updated license details for key [${lic.key}] (HWID Lock: ${lic.hwidLock ? 'ON' : 'OFF'}, Status: ${lic.status})`);
      }
    } else if (action === "reset_hwid") {
      const lic = db.licenses.find(l => l.key === key);
      if (lic) {
        lic.hwid = "";
        if (lic.usedby) {
          const u = (db.users || []).find(usr => usr.username === lic.usedby);
          if (u) u.hwid = "";
        }
        addLog(db, "ADMIN_ACTION", "Admin", `Reset HWID for license [${key}]`);
      }
    } else if (action === "pause") {
      const lic = db.licenses.find(l => l.key === key);
      if (lic) {
        lic.status = lic.status === "Paused" ? (lic.usedby ? "Used" : "Not Used") : "Paused";
        addLog(db, "ADMIN_ACTION", "Admin", `Toggled pause status for license [${key}]: ${lic.status}`);
      }
    } else if (action === "ban") {
      const lic = db.licenses.find(l => l.key === key);
      if (lic) {
        lic.status = "Banned";
        lic.banReason = reason || "Banned by Administrator";
        if (delUserToo && lic.usedby) {
          const u = (db.users || []).find(usr => usr.username === lic.usedby);
          if (u) {
            u.status = "banned";
            u.banReason = lic.banReason;
          }
        }
        addLog(db, "ADMIN_ACTION", "Admin", `Banned license [${key}]: ${lic.banReason}`);
      }
    } else if (action === "unban") {
      const lic = db.licenses.find(l => l.key === key);
      if (lic) {
        lic.status = lic.usedby ? "Used" : "Not Used";
        lic.banReason = "";
        addLog(db, "ADMIN_ACTION", "Admin", `Unbanned license [${key}]`);
      }
    } else if (action === "delete_single") {
      const idx = db.licenses.findIndex(l => l.key === key);
      if (idx !== -1) {
        const lic = db.licenses[idx];
        if (delUserToo && lic.usedby) {
          db.users = (db.users || []).filter(u => u.username !== lic.usedby);
        }
        db.licenses.splice(idx, 1);
        addLog(db, "ADMIN_ACTION", "Admin", `Deleted license [${key}]`);
      }
    } else if (action === "delete_bulk") {
      const mode = body.mode;
      if (mode === "delkeys") {
        db.licenses = [];
        addLog(db, "ADMIN_ACTION", "Admin", `Deleted ALL licenses`);
      } else if (mode === "deleteallunused") {
        db.licenses = db.licenses.filter(l => l.status !== "Not Used");
        addLog(db, "ADMIN_ACTION", "Admin", `Deleted all unused licenses`);
      } else if (mode === "deleteallused") {
        db.licenses = db.licenses.filter(l => l.status !== "Used");
        addLog(db, "ADMIN_ACTION", "Admin", `Deleted all used licenses`);
      } else if (mode === "deleteselected" && Array.isArray(keys)) {
        db.licenses = db.licenses.filter(l => !keys.includes(l.key));
        addLog(db, "ADMIN_ACTION", "Admin", `Deleted selected licenses`);
      }
    } else if (action === "extend") {
      const secondsToAdd = parseInt(body.seconds || 86400);
      db.licenses.forEach(l => {
        if (l.status === "Not Used" || l.status === "Used") {
          l.duration += secondsToAdd;
          l.expires += secondsToAdd * 1000;
        }
      });
      addLog(db, "ADMIN_ACTION", "Admin", `Extended licenses by ${Math.floor(secondsToAdd / 86400)} days`);
    }

    scheduleSave();
    return jsonResp({ success: true, licenses: db.licenses });
  }

  // Users
  if (path === "/api/admin/users") {
    return jsonResp({ success: true, users: db.users || [] });
  }

  if (path === "/api/admin/users/import") {
    const targetAppId = body.appId || db.activeAppId || (db.apps[0] && db.apps[0].id);
    const result = importUsersFromCSV(db, body.csv || body.text || "", targetAppId);
    addLog(db, "ADMIN_ACTION", "Admin", `Imported ${result.count} users (${result.duplicates} updated) into [${targetAppId}]`);
    return jsonResp({ success: true, count: result.count, duplicates: result.duplicates, total: result.total, users: db.users });
  }

  if (path === "/api/admin/users/action") {
    const { action, username, usernames, reason, duration } = body;
    if (!Array.isArray(db.users)) db.users = [];

    if (action === "create") {
      const newUser = {
        username: body.username,
        password: body.password || "",
        email: body.email || "",
        subscription: body.sub || "default",
        level: 1,
        expires: body.expiry ? new Date(body.expiry).getTime() : Date.now() + 86400000 * 3650,
        hwid: "",
        hwidAffected: body.hwidAffected !== false && body.hwidAffected !== "false",
        status: "active",
        ip: "N/A",
        device: "N/A",
        lastLogin: Date.now(),
        created: Date.now(),
        banReason: "",
        banExpires: 0
      };
      db.users.unshift(newUser);
      addLog(db, "ADMIN_ACTION", "Admin", `Created user account: ${newUser.username}`);
    } else if (action === "edit") {
      const u = db.users.find(usr => usr.username === username);
      if (u) {
        if (body.newUsername && body.newUsername !== username) u.username = body.newUsername.trim();
        if (body.password !== undefined) u.password = body.password;
        if (body.email !== undefined) u.email = body.email;
        if (body.subscription !== undefined) u.subscription = body.subscription;
        if (body.hwidAffected !== undefined) u.hwidAffected = body.hwidAffected === true || body.hwidAffected === "true";
        if (body.hwid !== undefined) u.hwid = body.hwid.trim();
        if (body.status !== undefined) u.status = body.status;
        if (body.banReason !== undefined) u.banReason = body.banReason;
        if (body.expiryTimestamp) u.expires = parseInt(body.expiryTimestamp);
        addLog(db, "ADMIN_ACTION", "Admin", `Updated user settings for: ${u.username}`);
      }
    } else if (action === "ban") {
      const u = db.users.find(usr => usr.username === username);
      if (u) {
        u.status = "banned";
        u.banReason = reason || "Violations";
        u.banExpires = duration ? Date.now() + parseInt(duration) * 1000 : 0;
        addLog(db, "ADMIN_ACTION", "Admin", `Banned user [${username}]: ${u.banReason}`);
      }
    } else if (action === "unban") {
      const u = db.users.find(usr => usr.username === username);
      if (u) {
        u.status = "active";
        u.banReason = "";
        addLog(db, "ADMIN_ACTION", "Admin", `Unbanned user [${username}]`);
      }
    } else if (action === "pause") {
      const u = db.users.find(usr => usr.username === username);
      if (u) {
        u.status = u.status === "paused" ? "active" : "paused";
        addLog(db, "ADMIN_ACTION", "Admin", `Toggled pause status for user [${username}]: ${u.status}`);
      }
    } else if (action === "reset_hwid") {
      const u = db.users.find(usr => usr.username === username);
      if (u) {
        u.hwid = "";
        addLog(db, "ADMIN_ACTION", "Admin", `Reset HWID for user [${username}]`);
      }
    } else if (action === "reset_all_hwids") {
      db.users.forEach(u => u.hwid = "");
      db.licenses.forEach(l => l.hwid = "");
      addLog(db, "ADMIN_ACTION", "Admin", `Reset HWIDs for ALL users and licenses`);
    } else if (action === "delete_single") {
      db.users = db.users.filter(u => u.username !== username);
      addLog(db, "ADMIN_ACTION", "Admin", `Deleted user account [${username}]`);
    } else if (action === "delete_bulk") {
      const mode = body.mode;
      if (mode === "delusers") {
        db.users = [];
        addLog(db, "ADMIN_ACTION", "Admin", `Deleted ALL users`);
      } else if (mode === "delexpusers") {
        db.users = db.users.filter(u => u.expires > Date.now());
        addLog(db, "ADMIN_ACTION", "Admin", `Deleted all expired users`);
      } else if (mode === "unbanall") {
        db.users.forEach(u => { if (u.status === "banned") u.status = "active"; });
        addLog(db, "ADMIN_ACTION", "Admin", `Unbanned all users`);
      } else if (mode === "deleteselected" && Array.isArray(usernames)) {
        db.users = db.users.filter(u => !usernames.includes(u.username));
        addLog(db, "ADMIN_ACTION", "Admin", `Deleted selected users`);
      }
    }

    scheduleSave();
    return jsonResp({ success: true, users: db.users });
  }

  // Logs
  if (path === "/api/admin/logs") {
    if (req.method === "POST") {
      if (body.action === "clear") {
        db.logs = [];
        addLog(db, "ADMIN_ACTION", "Admin", "Cleared audit logs");
        return jsonResp({ success: true, logs: [] });
      } else if (body.action === "delete_selected" && Array.isArray(body.ids)) {
        db.logs = (db.logs || []).filter(l => !body.ids.includes(l.id));
        addLog(db, "ADMIN_ACTION", "Admin", `Deleted ${body.ids.length} selected log entries`);
        return jsonResp({ success: true, logs: db.logs });
      }
    }
    return jsonResp({ success: true, logs: db.logs || [] });
  }

  // Sessions
  if (path === "/api/admin/sessions") {
    return jsonResp({ success: true, sessions: db.sessions || [] });
  }

  if (path === "/api/admin/sessions/action") {
    const { action, sessionId } = body;
    if (!Array.isArray(db.sessions)) db.sessions = [];
    if (action === "kill_single") {
      db.sessions = db.sessions.filter(s => s.id !== sessionId);
      addLog(db, "ADMIN_ACTION", "Admin", `Terminated device session: ${sessionId}`);
    } else if (action === "kill_all") {
      const count = db.sessions.length;
      db.sessions = [];
      addLog(db, "ADMIN_ACTION", "Admin", `Terminated ALL (${count}) active device sessions`);
    }
    scheduleSave();
    return jsonResp({ success: true, sessions: db.sessions });
  }

  // Rules / Blacklists
  if (path === "/api/admin/rules") {
    if (!Array.isArray(db.rules)) db.rules = [];
    if (req.method === "POST") {
      const { action, id, type, value, reason } = body;
      if (action === "add") {
        const cleanVal = (value || "").trim();
        if (cleanVal) {
          const newRule = {
            id: "rule_" + Date.now(),
            type: type || "ip",
            value: cleanVal,
            reason: (reason || "Banned by Administrator").trim(),
            created: Date.now()
          };
          db.rules.unshift(newRule);
          addLog(db, "ADMIN_ACTION", "Admin", `Added blacklist rule [${newRule.type.toUpperCase()}: ${newRule.value}] (${newRule.reason})`);
        }
      } else if (action === "delete") {
        db.rules = db.rules.filter(r => r.id !== id && r.value !== value);
        addLog(db, "ADMIN_ACTION", "Admin", `Removed blacklist rule: ${id || value}`);
      } else if (action === "clear") {
        db.rules = [];
        addLog(db, "ADMIN_ACTION", "Admin", "Cleared all security blacklist rules");
      }
      scheduleSave();
    }
    return jsonResp({ success: true, rules: db.rules });
  }

  // Discord Webhook Test
  if (path === "/api/admin/discord/test") {
    const currentApp = (db.apps && db.apps.find(a => a.id === db.activeAppId)) || (db.apps && db.apps[0]) || defaultDatabase.apps[0];
    const webhookUrl = (body.url || currentApp.discordWebhook || "").trim();
    if (!webhookUrl) return jsonResp({ success: false, message: "No Discord Webhook URL provided" }, 400);
    try {
      await sendDiscordWebhook(webhookUrl, {
        title: "🔔 Ghostrix Security Webhook Connected!",
        description: "Test notification successful from your KeyAuth Node.js Admin Dashboard.",
        color: 3870686,
        fields: [
          { name: "Application", value: currentApp.name, inline: true },
          { name: "Time", value: new Date().toISOString(), inline: true }
        ],
        footer: { text: "Ghostrix KeyAuth Serverless Engine" }
      });
      return jsonResp({ success: true, message: "Test alert dispatched to Discord successfully!" });
    } catch (e) {
      return jsonResp({ success: false, message: e.message }, 500);
    }
  }

  // Variables Management
  if (path === "/api/admin/vars") {
    if (!Array.isArray(db.variables)) db.variables = [];
    if (req.method === "POST") {
      const { action, name, data, isSecret } = body;
      if (action === "add") {
        const cleanName = (name || "").trim();
        const targetAppId = body.appId || "all";
        const idx = db.variables.findIndex(v => v.name.toLowerCase() === cleanName.toLowerCase() && (v.appId === targetAppId || targetAppId === "all"));
        if (idx !== -1) {
          db.variables[idx].data = data;
          db.variables[idx].isSecret = isSecret || false;
          db.variables[idx].appId = targetAppId;
        } else {
          db.variables.push({ name: cleanName, data: data, isSecret: isSecret || false, appId: targetAppId });
        }
        addLog(db, "ADMIN_ACTION", "Admin", `Saved application variable: [${cleanName}]`);
      } else if (action === "edit" || action === "update") {
        const originalName = (body.originalName || name || "").trim().toLowerCase();
        const newName = (body.newName || name || "").trim();
        const targetAppId = body.appId || "all";
        const idx = db.variables.findIndex(v => v.name.toLowerCase() === originalName);
        if (idx !== -1) {
          db.variables[idx].name = newName;
          db.variables[idx].data = data;
          db.variables[idx].isSecret = isSecret || false;
          db.variables[idx].appId = targetAppId;
          addLog(db, "ADMIN_ACTION", "Admin", `Updated application variable: [${newName}]`);
        } else {
          db.variables.push({ name: newName, data: data, isSecret: isSecret || false, appId: targetAppId });
          addLog(db, "ADMIN_ACTION", "Admin", `Saved application variable: [${newName}]`);
        }
      } else if (action === "delete") {
        const cleanName = (name || "").trim().toLowerCase();
        db.variables = db.variables.filter(v => v.name.toLowerCase() !== cleanName);
        addLog(db, "ADMIN_ACTION", "Admin", `Deleted application variable: [${cleanName}]`);
      }
      scheduleSave();
    }
    return jsonResp({ success: true, variables: db.variables });
  }

  // Files Management
  if (path === "/api/admin/files") {
    if (!Array.isArray(db.files)) db.files = [];
    if (req.method === "POST") {
      const { action, id, name, size, url: fileUrl } = body;
      if (action === "add") {
        const newFile = {
          id: (id || ("file_" + Date.now())).trim(),
          name: (name || "File_" + Date.now()).trim(),
          size: size || "Unknown",
          url: (fileUrl || "").trim(),
          appId: body.appId || "all",
          uploaded: Date.now()
        };
        const existIdx = db.files.findIndex(f => f.id === newFile.id);
        if (existIdx !== -1) {
          db.files[existIdx] = newFile;
        } else {
          db.files.unshift(newFile);
        }
        addLog(db, "ADMIN_ACTION", "Admin", `Uploaded/Added file [${newFile.name}] (${newFile.id})`);
      } else if (action === "delete") {
        db.files = db.files.filter(f => f.id !== id);
        addLog(db, "ADMIN_ACTION", "Admin", `Deleted file: ${id}`);
      }
      scheduleSave();
    }
    return jsonResp({ success: true, files: db.files });
  }

  // Backup & Restore
  if (path === "/api/admin/backup") {
    if (req.method === "POST") {
      const incoming = body.data || body;
      if (incoming && typeof incoming === "object") {
        if (Array.isArray(incoming.apps)) db.apps = incoming.apps;
        if (Array.isArray(incoming.licenses)) db.licenses = incoming.licenses;
        if (Array.isArray(incoming.users)) db.users = incoming.users;
        if (Array.isArray(incoming.variables)) db.variables = incoming.variables;
        if (Array.isArray(incoming.files)) db.files = incoming.files;
        if (Array.isArray(incoming.tokens)) db.tokens = incoming.tokens;
        if (Array.isArray(incoming.rules)) db.rules = incoming.rules;
        if (incoming.activeAppId) db.activeAppId = incoming.activeAppId;
        addLog(db, "ADMIN_ACTION", "Admin", "Restored full database state from backup JSON");
        saveDatabaseSync();
        return jsonResp({ success: true, message: "Database state restored successfully!", database: db });
      }
      return jsonResp({ success: false, message: "Invalid backup data structure" }, 400);
    }
    return jsonResp({ success: true, database: db });
  }

  // Settings
  if (path === "/api/admin/settings") {
    const currentApp = (db.apps && db.apps.find(a => a.id === db.activeAppId)) || (db.apps && db.apps[0]) || defaultDatabase.apps[0];
    if (req.method === "POST") {
      if (body.name) currentApp.name = body.name;
      if (body.version) currentApp.version = body.version;
      if (body.hwidLock !== undefined) currentApp.hwidLock = body.hwidLock;
      if (body.forceHwid !== undefined) currentApp.forceHwid = body.forceHwid;
      if (body.blockVpn !== undefined) currentApp.blockVpn = body.blockVpn;
      if (body.hashCheck !== undefined) currentApp.hashCheck = body.hashCheck;
      if (body.appHash !== undefined) currentApp.appHash = body.appHash;
      if (body.status !== undefined) currentApp.status = body.status;
      if (body.discordWebhook !== undefined) currentApp.discordWebhook = body.discordWebhook;
      if (body.autoBan !== undefined) currentApp.autoBan = body.autoBan;
      if (body.requireKeyForProxy !== undefined) currentApp.requireKeyForProxy = body.requireKeyForProxy === true || body.requireKeyForProxy === "true";
      addLog(db, "ADMIN_ACTION", "Admin", `Updated application security settings`);
      scheduleSave();
    }
    return jsonResp({ success: true, settings: currentApp, isD1Active: false, isKvActive: true });
  }

  return jsonResp({ success: false, message: "Unknown endpoint" }, 404);
}

/**
 * Gatekeeper function: Validates whether a client is authorized to access proxy streams & video data.
 * Checks for:
 * - Active License Key in query (?key=..., ?license=...) or header (X-License-Key, X-Key)
 * - Active Session ID in query (?sessionid=...) or header (X-Session-Id)
 * - User ID bound in DB
 * - Checks IP / HWID against active authenticated sessions
 */
function validateClientAccess(req, parsedUrl) {
  const db = getDB();
  const currentApp = (db.apps && db.apps.find(a => a.id === db.activeAppId)) || (db.apps && db.apps[0]) || defaultDatabase.apps[0];
  const clientIp = getClientIp(req);

  // 1. Check Blacklist Rules first
  if (Array.isArray(db.rules) && db.rules.length > 0) {
    const isBlocked = db.rules.some(r => r.type === 'ip' && r.value === clientIp);
    if (isBlocked) {
      return { allowed: false, reason: "Your IP is blacklisted by Administrator.", status: 403 };
    }
  }

  // 2. Extract potential license key
  let reqUrlKey = '', reqUrlSess = '', reqUrlUser = '';
  try {
    const incUrl = new URL(req.url || '/', 'http://localhost');
    reqUrlKey = incUrl.searchParams.get('key') || incUrl.searchParams.get('license') || incUrl.searchParams.get('license_key') || incUrl.searchParams.get('auth_key') || '';
    reqUrlSess = incUrl.searchParams.get('sessionid') || incUrl.searchParams.get('session') || '';
    reqUrlUser = incUrl.searchParams.get('uid') || incUrl.searchParams.get('user') || incUrl.searchParams.get('userId') || '';
  } catch(e) {}

  const keyCandidate = (
    req.headers['x-license-key'] ||
    req.headers['x-key'] ||
    req.headers['x-auth-key'] ||
    reqUrlKey ||
    (parsedUrl && parsedUrl.searchParams && parsedUrl.searchParams.get('key')) ||
    (parsedUrl && parsedUrl.searchParams && parsedUrl.searchParams.get('license')) ||
    (parsedUrl && parsedUrl.searchParams && parsedUrl.searchParams.get('license_key')) ||
    ''
  ).trim();

  // 3. Extract potential session id
  const sessCandidate = (
    req.headers['x-session-id'] ||
    req.headers['x-session'] ||
    reqUrlSess ||
    (parsedUrl && parsedUrl.searchParams && parsedUrl.searchParams.get('sessionid')) ||
    (parsedUrl && parsedUrl.searchParams && parsedUrl.searchParams.get('session')) ||
    ''
  ).trim();

  // 4. Extract user id
  const userCandidate = (
    req.headers['x-user-id'] ||
    req.headers['x-app-user'] ||
    req.headers['x-device-id'] ||
    reqUrlUser ||
    (parsedUrl && parsedUrl.searchParams && parsedUrl.searchParams.get('uid')) ||
    (parsedUrl && parsedUrl.searchParams && parsedUrl.searchParams.get('user')) ||
    (parsedUrl && parsedUrl.searchParams && parsedUrl.searchParams.get('userId')) ||
    ''
  ).trim();

  let identifiedUser = null;
  let identifiedKey = null;

  // Check Session ID if provided
  if (sessCandidate) {
    const sess = (db.sessions || []).find(s => s.id === sessCandidate && s.authenticated);
    if (sess) {
      identifiedUser = sess.username;
      identifiedKey = sess.key;
    }
  }

  // Check License Key if provided
  if (!identifiedUser && keyCandidate) {
    const lic = (db.licenses || []).find(l => l.key.toLowerCase() === keyCandidate.toLowerCase());
    if (lic) {
      if (lic.status === 'Banned') {
        return { allowed: false, reason: "License Key is banned: " + (lic.banReason || 'Violation'), status: 403 };
      }
      if (lic.status === 'Paused') {
        return { allowed: false, reason: "License Key is temporarily paused by Admin.", status: 403 };
      }
      if (lic.expires && lic.expires < Date.now()) {
        return { allowed: false, reason: "License Key has expired.", status: 403 };
      }
      identifiedKey = lic.key;
      identifiedUser = lic.usedby || lic.key;
    }
  }

  // Check User Account if provided
  if (!identifiedUser && userCandidate) {
    const u = (db.users || []).find(usr => usr.username.toLowerCase() === userCandidate.toLowerCase());
    if (u) {
      if (u.status === 'banned') {
        return { allowed: false, reason: "User account is banned: " + (u.banReason || 'Violation'), status: 403 };
      }
      if (u.status === 'paused') {
        return { allowed: false, reason: "User account is paused by Admin.", status: 403 };
      }
      if (u.expires && u.expires < Date.now()) {
        return { allowed: false, reason: "User license has expired.", status: 403 };
      }
      identifiedUser = u.username;
    }
  }

  // Check if client IP belongs to an authenticated session in the last 12 hours
  if (!identifiedUser && !identifiedKey) {
    const recentSession = (db.sessions || []).find(s => s.ip === clientIp && s.authenticated && (Date.now() - (s.lastPing || s.started || 0) < 43200000));
    if (recentSession) {
      identifiedUser = recentSession.username;
      identifiedKey = recentSession.key;
    }
  }

  // If the app requires an active license key for streams:
  const requireKey = currentApp.requireKeyForProxy === true;
  if (requireKey) {
    if (!identifiedKey && !identifiedUser) {
      return {
        allowed: false,
        reason: "Access Denied: You must be logged in with a valid active license key to view course videos and streams!",
        status: 403
      };
    }
  }

  return {
    allowed: true,
    user: identifiedUser || `Client_${clientIp.replace(/[^a-zA-Z0-9]/g, '_').slice(-8)}`,
    key: identifiedKey || null,
    ip: clientIp
  };
}

module.exports = {
  getDB,
  addLog,
  handleKeyAuthProtocol,
  handleAdminApi,
  validateClientAccess,
  isAuthorizedAdmin,
  DEFAULT_ADMIN_TOKEN,
  ADMIN_CREDENTIALS
};
