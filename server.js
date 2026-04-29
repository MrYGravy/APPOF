const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const multer = require('multer');
const XLSX = require('xlsx');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(express.json());

// ── Paths ─────────────────────────────────────────────────────
const DATA_DIR      = path.join(__dirname, 'data');
const DB_PATH       = path.join(DATA_DIR, 'stockDB.json');
const META_PATH     = path.join(DATA_DIR, 'stockMeta.json');
const CHANGELOG_PATH = path.join(DATA_DIR, 'stockChangelog.json');
const HISTORY_PATH  = path.join(DATA_DIR, 'history.json');
const ORDERS_PATH   = path.join(DATA_DIR, 'orders.json');
const USERS_PATH    = path.join(DATA_DIR, 'users.json');
const HASHWALL_PATH = path.join(DATA_DIR, 'hashwall.json');
const REPOHORA_PATH    = path.join(DATA_DIR, 'repohora.json');
const PIES_PATH        = path.join(DATA_DIR, 'piesPerdidos.json');
const BULTOS_PATH      = path.join(DATA_DIR, 'bultos.json');
const BINS_VACIOS_PATH = path.join(DATA_DIR, 'binsVacios.json');
const REPOHORA_HIST_PATH = path.join(DATA_DIR, 'repohoraHist.json');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);

// ── Auth ──────────────────────────────────────────────────────
function hash(str) { return crypto.createHash('sha256').update(str).digest('hex'); }

function getUsers() {
  try { return JSON.parse(fs.readFileSync(USERS_PATH,'utf8')); } catch(e) { return []; }
}
function saveUsers(users) { fs.writeFileSync(USERS_PATH, JSON.stringify(users, null, 2), 'utf8'); }

const SESSIONS_PATH = path.join(DATA_DIR, 'sessions.json');
const sessions = new Map();

function saveSessions() {
  try {
    const obj = {};
    sessions.forEach((v, k) => { obj[k] = v; });
    fs.writeFileSync(SESSIONS_PATH, JSON.stringify(obj), 'utf8');
  } catch(e) {}
}

function loadSessions() {
  try {
    if (!fs.existsSync(SESSIONS_PATH)) return;
    const obj = JSON.parse(fs.readFileSync(SESSIONS_PATH, 'utf8'));
    const now = Date.now();
    Object.entries(obj).forEach(([token, s]) => {
      if (s.expiresAt && s.expiresAt > now) sessions.set(token, s);
    });
  } catch(e) {}
}

function createSession(username, role, roles) {
  const token = uuidv4();
  sessions.set(token, { username, role, roles: roles || [role], createdAt: Date.now(), expiresAt: Date.now() + 24*60*60*1000 });
  saveSessions();
  return token;
}

function getSession(token) {
  if (!token) return null;
  const s = sessions.get(token);
  if (!s) return null;
  if (Date.now() > s.expiresAt) { sessions.delete(token); saveSessions(); return null; }
  s.expiresAt = Date.now() + 24*60*60*1000; // sliding window
  return s;
}

// Load sessions on startup
loadSessions();

// ── Horario de Acceso ─────────────────────────────────────────
// Applies to 'sala' and 'bodega' roles only (jefe/admin always allowed)
const ACCESS_PATH = path.join(DATA_DIR, 'access_control.json');
let accessControl = { manualLock: false, lockMessage: 'Fuera de horario laboral' };
try {
  if (fs.existsSync(ACCESS_PATH)) accessControl = JSON.parse(fs.readFileSync(ACCESS_PATH, 'utf8'));
} catch(e) {}
function saveAccessControl() {
  try { fs.writeFileSync(ACCESS_PATH, JSON.stringify(accessControl)); } catch(e) {}
}

// Returns true if access is currently allowed for restricted roles
// Santiago timezone (UTC-4 in summer, UTC-3 in winter - handled by Date)
function isWithinAccessHours() {
  if (accessControl.manualLock) return false;
  const now = new Date();
  const santiago = new Date(now.toLocaleString('en-US', { timeZone: 'America/Santiago' }));
  const hour   = santiago.getHours();
  const minute = santiago.getMinutes();
  const totalMinutes = hour * 60 + minute;
  // Default: 9:30 AM (570 min) to 20:30 (1230 min)
  const startMin = (accessControl.startHour ?? 9) * 60 + (accessControl.startMin ?? 30);
  const endMin   = (accessControl.endHour   ?? 20) * 60 + (accessControl.endMin   ?? 30);
  return totalMinutes >= startMin && totalMinutes < endMin;
}

function requireAccess() {
  return (req, res, next) => {
    const token = req.headers['x-auth-token'] || req.query.token;
    const session = getSession(token);
    if (!session) return next(); // let requireAuth handle it
    const roles = session.roles || [session.role];
    // jefe and admin bypass access control
    if (roles.includes('jefe') || roles.includes('admin')) return next();
    if (!isWithinAccessHours()) {
      return res.status(423).json({
        ok: false,
        locked: true,
        error: accessControl.lockMessage || 'Fuera de horario laboral',
        startHour: accessControl.startHour ?? 10,
        endHour:   accessControl.endHour   ?? 22,
      });
    }
    next();
  };
}
function requireAuth(role) {
  return (req, res, next) => {
    const token = req.headers['x-auth-token'] || req.query.token;
    const session = getSession(token);
    if (!session) return res.status(401).json({ ok: false, error: 'No autenticado' });
    const roles = session.roles || [session.role];
    if (role) {
      if (!roles.includes(role) && !roles.includes('admin')) return res.status(403).json({ ok: false });
    }
    req.session = session;
    next();
  };
}

// Separate middleware for access hour check (used only on /api/me)
function requireAccessHours() {
  return (req, res, next) => {
    const token = req.headers['x-auth-token'] || req.query.token;
    const session = getSession(token);
    if (!session) return next();
    const roles = session.roles || [session.role];
    if (roles.includes('jefe') || roles.includes('admin')) return next();
    if (!isWithinAccessHours()) {
      return res.status(423).json({
        ok: false, locked: true,
        error: accessControl.lockMessage || 'Fuera de horario laboral',
        startHour: accessControl.startHour ?? 9,
        endHour:   accessControl.endHour   ?? 20,
      });
    }
    next();
  };
}

// ── State ─────────────────────────────────────────────────────
let stockDB   = {};
let stockMeta = { updatedAt: null, total: 0, withBin: 0, filename: '' };
let stockChangelog = []; // [ { date, filename, newProducts, binChanges, removed } ]
let orders    = [];
let history   = [];
let hashwall  = { updatedAt: null, categories: { 'Hombre': [], 'Mujer': [], 'Niño': [], 'Fútbol Hombre': [], 'Fútbol Niño': [] } };
let repoHoraRequested = {};
let salesRanking = {}; // { 'DD6203-001': { styleColor, desc, count, lastSeen } }
let imageCache  = {}; // { 'DD6203-001': 'https://...' } — cache de imágenes Nike
let upcIndex = {}; // { '012345678901': 'DD6203-001' }
let repoHoraHistory   = [];
let piesPerdidos      = [];
let bultos            = []; // [ { id, date, time, filename, items:
let binsVacios        = []; // [ { id, styleColor, bin, desc, estado, reportedBy, createdAt } ] [{styleColor,desc,talla,bin}] } ]
let repoHoraLastTime  = {}; // { date: 'HH:MM:SS' } — última hora de venta del archivo anterior
let recentlyDone = []; // [ { id, vendedor, completedAt } ] — orders completed in last 24h for sala sync

try {
  if (fs.existsSync(DB_PATH))       { stockDB   = JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
    Object.entries(stockDB).forEach(([sc, p]) => {
      Object.entries(p.sizes||{}).forEach(([size, info]) => {
        if (info.upc) upcIndex[info.upc] = { styleColor: sc, size };
      });
    });
  }
  if (fs.existsSync(META_PATH))     stockMeta   = JSON.parse(fs.readFileSync(META_PATH,     'utf8'));
  if (fs.existsSync(CHANGELOG_PATH)) stockChangelog = JSON.parse(fs.readFileSync(CHANGELOG_PATH, 'utf8'));
  if (fs.existsSync(HISTORY_PATH))  history   = JSON.parse(fs.readFileSync(HISTORY_PATH,  'utf8'));
  if (fs.existsSync(ORDERS_PATH)) {
    const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    orders = JSON.parse(fs.readFileSync(ORDERS_PATH, 'utf8'))
      .filter(o => o.status !== 'listo' && o.timestamp > cutoff);
  }
  if (fs.existsSync(HASHWALL_PATH)) hashwall  = JSON.parse(fs.readFileSync(HASHWALL_PATH,  'utf8'));
  if (fs.existsSync(REPOHORA_PATH))      repoHoraRequested = JSON.parse(fs.readFileSync(REPOHORA_PATH, 'utf8'));
  const RANKING_PATH = path.join(DATA_DIR, 'salesRanking.json');
  if (fs.existsSync(RANKING_PATH)) salesRanking = JSON.parse(fs.readFileSync(RANKING_PATH, 'utf8'));
  if (fs.existsSync(REPOHORA_HIST_PATH)) repoHoraHistory   = JSON.parse(fs.readFileSync(REPOHORA_HIST_PATH, 'utf8'));
  if (fs.existsSync(PIES_PATH))          piesPerdidos      = JSON.parse(fs.readFileSync(PIES_PATH,   'utf8'));
  if (fs.existsSync(BULTOS_PATH))        bultos            = JSON.parse(fs.readFileSync(BULTOS_PATH, 'utf8'));
  if (fs.existsSync(BINS_VACIOS_PATH))   binsVacios        = JSON.parse(fs.readFileSync(BINS_VACIOS_PATH, 'utf8'));
  // Load last hour cutoff per day
  const LASTTIME_PATH = path.join(DATA_DIR, 'repohoraLastTime.json');
  if (fs.existsSync(LASTTIME_PATH)) repoHoraLastTime = JSON.parse(fs.readFileSync(LASTTIME_PATH, 'utf8'));
  console.log(`Stock: ${stockMeta.total} | History: ${history.length} | Hashwall loaded`);
} catch(e) { console.error('Load error:', e.message); }

function save(path, data) { fs.writeFileSync(path, JSON.stringify(data), 'utf8'); }

// ── Static ────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));

// ── Auth routes ───────────────────────────────────────────────
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ ok: false, error: 'Faltan credenciales' });
  const user = getUsers().find(u => u.username.toLowerCase() === username.toLowerCase().trim() && u.password === hash(password));
  if (!user) return res.status(401).json({ ok: false, error: 'Usuario o contraseña incorrectos' });
  // Support both old role string and new roles array
  const roles = user.roles || [user.role];
  const primaryRole = roles.includes('bodega') ? 'bodega' : 'sala';
  const token = createSession(user.username, primaryRole, roles);
  res.json({
    ok: true, token,
    username: user.username,
    displayName: user.displayName || user.username,
    role: primaryRole,
    roles,
    mustChangePassword: user.mustChangePassword || false
  });
});
// Debounced orders save - prevents disk thrash when checkboxes tick rapidly
let _saveOrdersTimer = null;
function saveOrdersDebounced() {
  if (_saveOrdersTimer) clearTimeout(_saveOrdersTimer);
  _saveOrdersTimer = setTimeout(() => {
    save(ORDERS_PATH, orders);
    _saveOrdersTimer = null;
  }, 1500); // Save 1.5s after last checkbox tick
}

// ── Change password ───────────────────────────────────────────
app.post('/api/change-password', requireAuth(), (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const session = getSession(req.headers['x-auth-token']);
  if (!session) return res.status(401).json({ ok: false });
  const users = getUsers();
  const idx = users.findIndex(u => u.username === session.username);
  if (idx === -1) return res.status(404).json({ ok: false });
  if (users[idx].password !== hash(currentPassword)) return res.status(400).json({ ok: false, error: 'Contraseña actual incorrecta' });
  if (!newPassword || newPassword.length < 6) return res.status(400).json({ ok: false, error: 'La contraseña debe tener al menos 6 caracteres' });
  users[idx].password = hash(newPassword);
  users[idx].mustChangePassword = false;
  saveUsers(users);
  res.json({ ok: true });
});

// -- Admin: list users --
app.get('/api/admin/users', requireAuth('admin'), (req, res) => {
  const users = getUsers().map(u => ({
    username: u.username, displayName: u.displayName,
    roles: u.roles || [u.role], mustChangePassword: u.mustChangePassword
  }));
  res.json(users);
});
app.post('/api/logout', (req, res) => { sessions.delete(req.headers['x-auth-token']); saveSessions(); res.json({ ok: true }); });

// Re-authenticate with stored credentials (used after server restart)
app.post('/api/reauth', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ ok: false });
  const user = getUsers().find(u => u.username.toLowerCase() === username.toLowerCase().trim() && u.password === hash(password));
  if (!user) return res.status(401).json({ ok: false });
  const roles = user.roles || [user.role];
  const primaryRole = roles.includes('bodega') ? 'bodega' : 'sala';
  const token = createSession(user.username, primaryRole, roles);
  res.json({ ok: true, token, roles, role: primaryRole, username: user.username, displayName: user.displayName || user.username });
});
app.get('/api/me', (req, res) => {
  const session = getSession(req.headers['x-auth-token']);
  if (!session) return res.status(401).json({ ok: false });
  const users = getUsers();
  const user = users.find(u => u.username === session.username) || {};
  res.json({
    ok: true,
    username: session.username,
    displayName: user.displayName || session.username,
    role: session.role,
    roles: session.roles || [session.role],
    mustChangePassword: user.mustChangePassword || false
  });
});

// ── Stock Excel upload ────────────────────────────────────────
// Disk storage for stock Excel (large files - avoid OOM)
const uploadDir = path.join(DATA_DIR, 'uploads_tmp');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
// Clean up any leftover temp files from previous crashes
try {
  fs.readdirSync(uploadDir).forEach(f => {
    const fp = path.join(uploadDir, f);
    if (Date.now() - fs.statSync(fp).mtimeMs > 60000) fs.unlinkSync(fp); // older than 1 min
  });
} catch(e) {}
const diskStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => cb(null, 'stock_' + Date.now() + path.extname(file.originalname))
});
const uploadStock = multer({ storage: diskStorage, limits: { fileSize: 50 * 1024 * 1024 } });
// Memory storage for POS files (small DBF files, fast processing)
const uploadPOS = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } });
app.post('/api/upload-stock', requireAuth('bodega'), uploadStock.single('file'), (req, res) => {
  const tmpPath = req.file ? req.file.path : null;
  try {
    if (!req.file || !tmpPath) return res.status(400).json({ ok: false, error: 'No se recibió archivo' });
    // Read from disk - much more memory efficient than buffer
    const wb = XLSX.readFile(tmpPath, { dense: false });
    const sheetName = wb.SheetNames.includes('BODEGA') ? 'BODEGA' : wb.SheetNames[0];
    const sheet = wb.Sheets[sheetName];
    // Free the rest of the workbook immediately
    wb.SheetNames.forEach(n => { if (n !== sheetName) delete wb.Sheets[n]; });
    const rows = XLSX.utils.sheet_to_json(sheet, { defval: null, raw: false });
    // Free sheet reference
    delete wb.Sheets[sheetName];
    const db = {};
    const upc = {};
    rows.forEach(row => {
      const sc = (row['STYLE COLOR'] || '').toString().trim().toUpperCase();
      if (!sc) return;
      if (!db[sc]) db[sc] = { desc: (row['DESCRIPCION']||'').toString().trim(), bu: (row['BU']||'').toString().trim(), genero: (row['GENERO']||'').toString().trim(), sizes: {} };
      const size   = (row['SIZE']||'').toString().trim();
      const bin    = row['BIN'] ? row['BIN'].toString().trim() : '';
      // Try multiple possible UPC column names
      const upcRaw = row['UPC'] || row['Upc'] || row['upc'] || row['CODIGO_BARRAS'] || row['BARCODE'] || row['EAN'] || row['GTIN'] || '';
      const upcVal = upcRaw ? upcRaw.toString().trim().replace(/[^0-9]/g,'') : '';
      if (size) {
        db[sc].sizes[size] = { bin, upc: upcVal };
        if (upcVal) upc[upcVal] = { styleColor: sc, size };
      }
    });
    // ── Compute diff against previous stock ──────────────────
    const prevDB = stockDB;
    const newProducts  = [];
    const removedProducts = [];
    const binChanges   = [];

    // New and changed
    Object.entries(db).forEach(([sc, prod]) => {
      if (!prevDB[sc]) {
        newProducts.push({ styleColor: sc, desc: prod.desc });
      } else {
        // Check BIN changes
        Object.entries(prod.sizes).forEach(([size, info]) => {
          const prev = prevDB[sc]?.sizes?.[size];
          if (prev && prev.bin !== info.bin) {
            binChanges.push({ styleColor: sc, desc: prod.desc, size, oldBin: prev.bin || '—', newBin: info.bin || '—' });
          }
        });
      }
    });

    // Removed products
    Object.entries(prevDB).forEach(([sc, prod]) => {
      if (!db[sc]) removedProducts.push({ styleColor: sc, desc: prod.desc });
    });

    // Save changelog entry (keep last 20 uploads)
    const changeEntry = {
      date: new Date().toISOString(),
      filename: req.file.originalname,
      newProducts,
      binChanges,
      removedProducts,
      totalBefore: Object.keys(prevDB).length,
      totalAfter:  Object.keys(db).length,
    };
    stockChangelog.unshift(changeEntry);
    if (stockChangelog.length > 20) stockChangelog = stockChangelog.slice(0, 20);
    fs.writeFileSync(CHANGELOG_PATH, JSON.stringify(stockChangelog), 'utf8');

    stockDB = db;
    upcIndex = upc;
    const total   = Object.keys(db).length;
    const withBin = Object.values(db).filter(p => Object.values(p.sizes).some(s => s.bin)).length;
    stockMeta = { updatedAt: new Date().toISOString(), total, withBin, filename: req.file.originalname };
    save(DB_PATH, stockDB); save(META_PATH, stockMeta);
    // Save original file for later download
    const origPath = path.join(DATA_DIR, 'stock_original' + path.extname(req.file.originalname));
    try { fs.copyFileSync(tmpPath, origPath); } catch(e) {}
    // Auto-resolve binsVacios if style color no longer has that BIN in new stock
    const beforeCount = binsVacios.length;
    binsVacios = binsVacios.filter(b => {
      if (b.estado === 'resuelto') return false; // always remove resolved
      const prod = db[b.styleColor];
      if (!prod) return true; // product removed entirely, keep report
      const hasBin = Object.values(prod.sizes).some(s => s.bin === b.bin);
      return hasBin; // keep if BIN still exists, remove if already cleaned
    });
    if (binsVacios.length !== beforeCount) {
      fs.writeFileSync(BINS_VACIOS_PATH, JSON.stringify(binsVacios), 'utf8');
    }
    io.emit('stock_updated', { ...stockMeta, changelog: changeEntry });
    io.emit('bins_vacios_updated');
    res.json({ ok: true, ...stockMeta, changelog: changeEntry });
  } catch(err) {
    res.status(500).json({ ok: false, error: err.message });
  } finally {
    // Always delete temp file and hint GC
    if (tmpPath && fs.existsSync(tmpPath)) {
      try { fs.unlinkSync(tmpPath); } catch(e) {}
    }
    if (global.gc) global.gc();
  }
});

// ── Stock Changelog ──────────────────────────────────────────
app.get('/api/stock-changelog', requireAuth('bodega'), (req, res) => {
  res.json(stockChangelog);
});

app.delete('/api/stock-changelog', requireAuth('bodega'), (req, res) => {
  stockChangelog = [];
  fs.writeFileSync(CHANGELOG_PATH, JSON.stringify(stockChangelog), 'utf8');
  res.json({ ok: true });
});

// ── POS File upload (DBF/XLS from point of sale) ──────────────
app.post('/api/upload-pos', requireAuth('bodega'), uploadPOS.single('file'), (req, res) => {
  try {
    const buf = req.file.buffer;
    const styleColorRegex = /([A-Z0-9]{2,8}-[A-Z0-9]{3})\b/;
    let rows = [];

    const isOLE2 = buf[0] === 0xD0 && buf[1] === 0xCF; // real XLS (OLE2)
    const isDBF  = buf[0] === 0x03;                     // DBF disfrazado de XLS

    if (isOLE2) {
      // ── Real XLS: use XLSX library to parse ──────────────────
      const wb = XLSX.read(buf, { type: 'buffer' });
      const sheet = wb.Sheets[wb.SheetNames[0]];
      const raw = XLSX.utils.sheet_to_json(sheet, { defval: '' });

      // Normalize: XLSX may return column headers as-is
      rows = raw.map(r => {
        const norm = {};
        Object.entries(r).forEach(([k, v]) => { norm[k.trim().toUpperCase()] = String(v).trim(); });
        return norm;
      });

    } else if (isDBF) {
      // ── DBF format parser ────────────────────────────────────
      const recordsCount = buf.readUInt32LE(4);
      const headerSize   = buf.readUInt16LE(8);
      const recordSize   = buf.readUInt16LE(10);

      const fields = [];
      let offset = 32;
      while (buf[offset] !== 0x0D && offset < headerSize) {
        const name  = buf.slice(offset, offset+11).toString('ascii').replace(/\0/g, '').trim();
        const ftype = String.fromCharCode(buf[offset+11]);
        const flen  = buf[offset+16];
        fields.push({ name, ftype, flen });
        offset += 32;
      }

      const recStart = headerSize;
      for (let i = 0; i < recordsCount; i++) {
        const recOffset = recStart + i * recordSize;
        if (recOffset + recordSize > buf.length) break;
        if (buf[recOffset] === 0x2A) continue; // deleted
        let roff = recOffset + 1;
        const row = {};
        for (const f of fields) {
          row[f.name] = buf.slice(roff, roff + f.flen).toString('latin1').trim();
          roff += f.flen;
        }
        rows.push(row);
      }
    } else {
      return res.status(400).json({ ok: false, error: 'Formato de archivo no reconocido. Sube el archivo .XLS del POS.' });
    }

    // Helper: parse HH:MM:SS to comparable number
    const timeToNum = t => {
      if (!t) return 0;
      const [h,m,sec] = t.split(':').map(Number);
      return (h||0)*3600 + (m||0)*60 + (sec||0);
    };

    const today = new Date().toLocaleDateString('es-CL', { year:'numeric', month:'2-digit', day:'2-digit', timeZone: 'America/Santiago' });

    // All real sales (TD=T, qty>0)
    const allSales = rows.filter(r => r.TD === 'T' && parseFloat(r.CANTIDAD || '0') > 0);

    // Find the max hour in THIS file (will become the cutoff for the next upload)
    const maxTimeInFile = allSales.reduce((max, r) => {
      const t = timeToNum(r.ULTHOR);
      return t > max ? t : max;
    }, 0);
    const maxTimeStr = allSales.reduce((latest, r) => {
      return timeToNum(r.ULTHOR) >= timeToNum(latest) ? (r.ULTHOR || '') : latest;
    }, '');

    // Get cutoff time from previous upload (if any)
    const prevCutoff = repoHoraLastTime[today] || null;
    const prevCutoffNum = prevCutoff ? timeToNum(prevCutoff) : 0;

    // Filter: only sales AFTER the previous cutoff time (strictly greater)
    // If no previous cutoff, take all sales
    const sales = prevCutoff
      ? allSales.filter(r => timeToNum(r.ULTHOR) > prevCutoffNum)
      : allSales;

    // Cross-reference with stockDB - aggregate quantities per styleColor+talla
    const resultMap = {};
    const alreadyRequested = repoHoraRequested[today] || {};

    sales.forEach(sale => {
      const descri = (sale.DESCRI || '').trim();
      const m = styleColorRegex.exec(descri);
      if (!m) return;
      const styleColor = m[1].toUpperCase();

      const parts = descri.split(/\s+/);
      const talla = parts[parts.length - 1] || '';

      const product = stockDB[styleColor];
      if (!product) return;

      const sizeEntry = product.sizes[talla];
      const bin = sizeEntry ? sizeEntry.bin : '';
      if (!bin) return;

      const key = `${styleColor}||${talla}`;
      if (alreadyRequested[key]) return; // already marked as requested today

      // Support CANTIDAD or CANTV field, handle comma decimals
      const rawQty = sale.CANTIDAD || sale.CANTV || sale.CANT || '1';
      const qty = Math.max(1, Math.round(parseFloat(String(rawQty).replace(',','.')) || 1));
      const hora = sale.ULTHOR || '';

      if (resultMap[key]) {
        // Aggregate: sum quantities, keep latest hora
        resultMap[key].qty += qty;
        if (timeToNum(hora) > timeToNum(resultMap[key].hora)) {
          resultMap[key].hora = hora;
        }
      } else {
        resultMap[key] = {
          styleColor,
          desc: product.desc,
          talla,
          bin,
          genero: product.genero,
          bu: product.bu,
          hora,
          qty,
          key
        };
      }
    });

    const result = Object.values(resultMap);
    // Debug: log aggregation summary
    console.log(`[POS] ${req.file.originalname}: ${allSales.length} ventas totales, ${sales.length} después del filtro, ${result.length} items únicos con BIN`);
    // Check for items with qty > 1 to verify aggregation
    const multiQty = result.filter(i => i.qty > 1);
    if (multiQty.length) console.log(`[POS] Items con qty>1:`, multiQty.map(i => `${i.styleColor} T.${i.talla} x${i.qty}`).join(', '));

    // Save the max time of THIS file as the cutoff for the next upload
    if (maxTimeStr) {
      // Keep previous value so cancel can restore it
      if (repoHoraLastTime[today] !== undefined) {
        repoHoraLastTime[today + '_prev'] = repoHoraLastTime[today];
      }
      repoHoraLastTime[today] = maxTimeStr;
      fs.writeFileSync(path.join(DATA_DIR, 'repohoraLastTime.json'), JSON.stringify(repoHoraLastTime), 'utf8');
    }

    res.json({
      ok: true,
      items: result,
      totalSales: allSales.length,
      filteredFrom: prevCutoff || null,
      filteredTo: maxTimeStr,
      withBin: result.length,
      date: today,
      filename: req.file.originalname
    });
  } catch(err) { res.status(500).json({ ok: false, error: err.message }); }
});

// Mark items as requested (so they don't appear next hour)
// ── Sync checkbox state across bodega sessions ──────────────
app.post('/api/orders/:id/check', requireAuth('bodega'), (req, res) => {
  const { key, checked, checkedKeys } = req.body;
  const orderId = req.params.id;
  const order = orders.find(o => o.id === orderId);
  if (!order) return res.status(404).json({ ok: false });
  // Persist checkedKeys in the order object so reconnecting clients get it
  if (checkedKeys !== undefined) {
    order.checkedKeys = checkedKeys;
  } else if (key !== undefined) {
    // Single key update - maintain server-side set
    if (!order.checkedKeys) order.checkedKeys = [];
    if (checked) {
      if (!order.checkedKeys.includes(key)) order.checkedKeys.push(key);
    } else {
      order.checkedKeys = order.checkedKeys.filter(k => k !== key);
    }
  }
  // Debounced save - avoid disk thrash on rapid checkbox ticking
  saveOrdersDebounced();
  // Broadcast to all bodega sessions
  io.emit('item_checked', { orderId, key, checked, checkedKeys: order.checkedKeys });
  // Calculate and broadcast progress
  const pct = order.items.length ? Math.round(((order.checkedKeys||[]).length / order.items.length) * 100) : 0;
  io.emit('order_progress', { orderId, pct, checkedKeys: order.checkedKeys });
  res.json({ ok: true });
});

app.post('/api/repo-hora/mark', requireAuth('bodega'), (req, res) => {
  const { keys, date, items, filename } = req.body;
  if (!keys || !date) return res.status(400).json({ ok: false });

  // Track already-requested keys
  if (!repoHoraRequested[date]) repoHoraRequested[date] = {};
  keys.forEach(k => { repoHoraRequested[date][k] = true; });

  // Save to history
  if (items && items.length) {
    const entry = {
      id: uuidv4(),
      date,
      time: new Date().toLocaleTimeString('es-CL', { hour: '2-digit', minute: '2-digit', timeZone: 'America/Santiago' }),
      timestamp: new Date().toISOString(),
      filename: filename || '',
      items: items
        .filter(i => keys.includes(i.key))
        .map(i => ({
          styleColor: i.styleColor,
          desc: i.desc || '',
          talla: i.talla || i.size || '',  // normalize: repohora uses talla, orders use size
          bin: i.bin || '',
          hora: i.hora || '',
          qty: i.qty || 1,
          key: i.key || (i.styleColor + '||' + (i.talla || i.size || ''))
        }))
    };
    repoHoraHistory.unshift(entry);
    // Keep last 30 days
    const cutoffHist = new Date(); cutoffHist.setDate(cutoffHist.getDate() - 30);
    repoHoraHistory = repoHoraHistory.filter(e => new Date(e.timestamp) > cutoffHist);
    fs.writeFileSync(REPOHORA_HIST_PATH, JSON.stringify(repoHoraHistory), 'utf8');
    // Update sales ranking
    if (items && items.length) {
      items.filter(i => keys.includes(i.key)).forEach(i => {
        if (!salesRanking[i.styleColor]) {
          salesRanking[i.styleColor] = { styleColor: i.styleColor, desc: i.desc || '', count: 0, lastSeen: '' };
        }
        salesRanking[i.styleColor].count++;
        salesRanking[i.styleColor].lastSeen = new Date().toLocaleDateString('es-CL', { timeZone: 'America/Santiago' });
        if (i.desc) salesRanking[i.styleColor].desc = i.desc;
      });
      fs.writeFileSync(path.join(DATA_DIR, 'salesRanking.json'), JSON.stringify(salesRanking), 'utf8');
    }
  }

  // Cleanup old dates (keep only last 7 days)
  const cutoff = new Date();
  cutoff.setDate(cutoff.getDate() - 7);
  Object.keys(repoHoraRequested).forEach(d => {
    const parts = d.split('/');
    if (parts.length === 3) {
      const dt = new Date(`${parts[2]}-${parts[1]}-${parts[0]}`);
      if (dt < cutoff) delete repoHoraRequested[d];
    }
  });
  save(REPOHORA_PATH, repoHoraRequested);
  res.json({ ok: true });
});

// Cancel last POS upload - removes the lastTime marker so items reappear on next upload
app.post('/api/repo-hora/cancel-last', requireAuth('bodega'), (req, res) => {
  const { date } = req.body;
  const today = new Date().toLocaleDateString('es-CL', { year:'numeric', month:'2-digit', day:'2-digit', timeZone:'America/Santiago' });
  const targetDate = date || today;

  // Only revert the lastTime cutoff so items reappear on next upload
  // Do NOT touch repoHoraHistory - those are confirmed marks that should stay
  if (repoHoraLastTime[targetDate + '_prev'] !== undefined) {
    repoHoraLastTime[targetDate] = repoHoraLastTime[targetDate + '_prev'];
    delete repoHoraLastTime[targetDate + '_prev'];
  } else {
    delete repoHoraLastTime[targetDate];
  }
  fs.writeFileSync(path.join(DATA_DIR, 'repohoraLastTime.json'), JSON.stringify(repoHoraLastTime), 'utf8');

  res.json({ ok: true });
});

app.delete('/api/repo-hora/reset', requireAuth('bodega'), (req, res) => {
  const today = new Date().toLocaleDateString('es-CL', { year:'numeric', month:'2-digit', day:'2-digit', timeZone: 'America/Santiago' });
  // Clear requested keys for today
  delete repoHoraRequested[today];
  save(REPOHORA_PATH, repoHoraRequested);
  // Also clear history and last time cutoff for today
  repoHoraHistory = repoHoraHistory.filter(e => e.date !== today);
  fs.writeFileSync(REPOHORA_HIST_PATH, JSON.stringify(repoHoraHistory), 'utf8');
  delete repoHoraLastTime[today];
  fs.writeFileSync(path.join(DATA_DIR, 'repohoraLastTime.json'), JSON.stringify(repoHoraLastTime), 'utf8');
  res.json({ ok: true });
});

app.get('/api/repo-hora/history', requireAuth('bodega'), (req, res) => {
  const { date } = req.query;
  const result = date ? repoHoraHistory.filter(e => e.date === date) : repoHoraHistory;
  res.json(result);
});

// Delete repo hora history by specific date
app.delete('/api/repo-hora/history', requireAuth('bodega'), (req, res) => {
  const { date } = req.body;
  if (date) {
    // Delete only that specific date
    repoHoraHistory = repoHoraHistory.filter(e => e.date !== date);
  } else {
    // Delete ALL history
    repoHoraHistory = [];
  }
  fs.writeFileSync(REPOHORA_HIST_PATH, JSON.stringify(repoHoraHistory), 'utf8');
  res.json({ ok: true });
});

app.get('/api/repo-hora/history/dates', requireAuth('bodega'), (req, res) => {
  const map = {};
  repoHoraHistory.forEach(e => {
    if (!map[e.date]) map[e.date] = { date: e.date, runs: 0, items: 0 };
    map[e.date].runs++;
    map[e.date].items += e.items.length;
  });
  res.json(Object.values(map));
});

// ── Stock query ───────────────────────────────────────────────

// -- Download stock as Excel --
app.get('/api/download-stock', (req, res) => {
  // Accept token via header OR query param (needed for direct download links)
  const token = req.headers['x-auth-token'] || req.query.token;
  const session = getSession(token);
  if (!session) return res.status(401).json({ ok: false, error: 'No autenticado' });
  const roles = session.roles || [session.role];
  if (!roles.includes('bodega') && !roles.includes('admin') && !roles.includes('jefe')) {
    return res.status(403).json({ ok: false });
  }
  if (!stockDB || Object.keys(stockDB).length === 0) {
    return res.status(404).json({ ok: false, error: 'Sin stock cargado' });
  }
  // Try to serve the original uploaded file first (exact same format)
  const origName = stockMeta.filename || 'STOCK_BODEGA.xlsx';
  const ext = path.extname(origName) || '.xlsx';
  const origPath = path.join(DATA_DIR, 'stock_original' + ext);
  if (fs.existsSync(origPath)) {
    res.setHeader('Content-Disposition', `attachment; filename="${origName}"`);
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    return res.sendFile(origPath);
  }
  // Fallback: reconstruct from stockDB
  try {
    const rows = [];
    Object.entries(stockDB).forEach(([sc, prod]) => {
      Object.entries(prod.sizes || {}).forEach(([size, info]) => {
        rows.push({
          'STYLE COLOR': sc,
          'DESCRIPCION': prod.desc || '',
          'BU':          prod.bu   || '',
          'GENERO':      prod.genero || '',
          'SIZE':        size,
          'BIN':         info.bin || '',
          'UPC':         info.upc || ''
        });
      });
    });
    const ws = XLSX.utils.json_to_sheet(rows);
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, 'BODEGA');
    const buf = XLSX.write(wb, { type: 'buffer', bookType: 'xlsx' });
    res.setHeader('Content-Disposition', `attachment; filename="${origName}"`);
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.send(buf);
  } catch(e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.get('/api/stock-status', requireAuth(), (req, res) => res.json({ loaded: stockMeta.total > 0, ...stockMeta }));

// Returns all style colors for autocomplete
app.get('/api/stock-keys', requireAuth('bodega'), (req, res) => {
  res.json(Object.keys(stockDB));
});

// ── Pies Perdidos ─────────────────────────────────────────────
app.get('/api/pies-perdidos', requireAuth('bodega'), (req, res) => {
  res.json({ pies: piesPerdidos, bultos });
});

app.post('/api/pies-perdidos', requireAuth('bodega'), (req, res) => {
  const { styleColor, talla, lado, bultoId, nota } = req.body;
  if (!styleColor || !talla || !lado || !bultoId)
    return res.status(400).json({ ok: false, error: 'Faltan campos requeridos' });
  // Duplicates allowed - same SC+talla+lado can appear multiple times (e.g. two left shoes)
  const scClean = styleColor.toUpperCase().trim();
  // Warn if SC not in stock but don't block (stock may not be loaded)
  const scInStock = Object.keys(stockDB).length === 0 || !!stockDB[scClean];
  const entry = {
    id: uuidv4(),
    styleColor: scClean,
    talla: talla.trim(),
    lado,
    bultoId,
    nota: nota || '',
    estado: 'pendiente',
    addedBy: req.session.username,
    createdAt: new Date().toISOString()
  };
  piesPerdidos.unshift(entry);
  fs.writeFileSync(PIES_PATH, JSON.stringify(piesPerdidos), 'utf8');
  io.emit('pies_updated');

  // Auto-detect if there's a matching opposite foot already confirmed
  const opuesto = lado === 'izquierdo' ? 'derecho' : 'izquierdo';
  const match = piesPerdidos.find(p =>
    p.id !== entry.id &&
    p.styleColor === entry.styleColor &&
    p.talla === entry.talla &&
    p.lado === opuesto &&
    p.estado === 'confirmado'
  );
  if (match) {
    const bultoPar = bultos.find(b => b.id === match.bultoId);
    io.emit('pie_coincidencia', {
      nuevo: entry,
      par: match,
      bultoPar: bultoPar ? bultoPar.nombre : '—'
    });
  }

  res.json({ ok: true, entry, match: match || null, scInStock });
});

app.post('/api/pies-perdidos/:id/aprobar', requireAuth('jefe'), (req, res) => {
  const entry = piesPerdidos.find(p => p.id === req.params.id);
  if (!entry) return res.status(404).json({ ok: false });
  entry.estado = 'confirmado';
  entry.approvedBy = req.session.username;
  entry.approvedAt = new Date().toISOString();
  fs.writeFileSync(PIES_PATH, JSON.stringify(piesPerdidos), 'utf8');
  io.emit('pies_updated');
  res.json({ ok: true });
});

app.post('/api/pies-perdidos/:id/rechazar', requireAuth('jefe'), (req, res) => {
  piesPerdidos = piesPerdidos.filter(p => p.id !== req.params.id);
  fs.writeFileSync(PIES_PATH, JSON.stringify(piesPerdidos), 'utf8');
  io.emit('pies_updated');
  res.json({ ok: true });
});

app.post('/api/pies-perdidos/:id/editar', requireAuth('jefe'), (req, res) => {
  const { styleColor, talla, lado, nota } = req.body;
  const pie = piesPerdidos.find(p => p.id === req.params.id);
  if (!pie) return res.status(404).json({ ok: false, error: 'Pie no encontrado' });
  if (styleColor) pie.styleColor = styleColor.toUpperCase().trim();
  if (talla)      pie.talla = talla.trim();
  if (lado)       pie.lado = lado;
  if (nota !== undefined) pie.nota = nota;
  save(PIES_PATH, piesPerdidos);
  res.json({ ok: true });
});

app.post('/api/pies-perdidos/encontrado', requireAuth('bodega'), (req, res) => {
  const { ids } = req.body;
  if (!ids || !ids.length) return res.status(400).json({ ok: false });
  // Remove ONLY the exact IDs provided - no collateral deletion
  const before = piesPerdidos.length;
  piesPerdidos = piesPerdidos.filter(p => !ids.includes(p.id));
  console.log(`[Pies] Par encontrado: eliminados ${before - piesPerdidos.length} pies (IDs: ${ids.join(', ')})`);
  fs.writeFileSync(PIES_PATH, JSON.stringify(piesPerdidos), 'utf8');
  io.emit('pies_updated');
  res.json({ ok: true });
});

app.delete('/api/pies-perdidos/:id', requireAuth('jefe'), (req, res) => {
  piesPerdidos = piesPerdidos.filter(p => p.id !== req.params.id);
  fs.writeFileSync(PIES_PATH, JSON.stringify(piesPerdidos), 'utf8');
  io.emit('pies_updated');
  res.json({ ok: true });
});

// Bultos
app.post('/api/pies-perdidos/bultos', requireAuth('jefe'), (req, res) => {
  const { nombre } = req.body;
  if (!nombre) return res.status(400).json({ ok: false });
  bultos.push({ id: uuidv4(), nombre: nombre.trim() });
  fs.writeFileSync(BULTOS_PATH, JSON.stringify(bultos), 'utf8');
  res.json({ ok: true, bultos });
});

app.delete('/api/pies-perdidos/bultos/:id', requireAuth('jefe'), (req, res) => {
  bultos = bultos.filter(b => b.id !== req.params.id);
  fs.writeFileSync(BULTOS_PATH, JSON.stringify(bultos), 'utf8');
  res.json({ ok: true, bultos });
});

// ── BINs Vacíos ──────────────────────────────────────────────
app.get('/api/bins-vacios', requireAuth('bodega'), (req, res) => {
  res.json({ bins: binsVacios });
});

app.post('/api/bins-vacios', requireAuth('bodega'), (req, res) => {
  const { styleColor, bin, nota } = req.body;
  if (!styleColor || !bin) return res.status(400).json({ ok: false, error: 'Faltan campos' });
  const sc = styleColor.toUpperCase().trim();
  // Check for duplicate pending
  const dup = binsVacios.find(b => b.styleColor === sc && b.bin === bin.trim() && b.estado === 'pendiente');
  if (dup) return res.status(400).json({ ok: false, error: 'Ya existe este reporte pendiente' });
  // Get description from stockDB
  const prod = stockDB[sc];
  const entry = {
    id: uuidv4(),
    styleColor: sc,
    bin: bin.trim(),
    desc: prod ? prod.desc : '',
    nota: nota || '',
    estado: 'pendiente',
    reportedBy: req.session.username,
    createdAt: new Date().toISOString()
  };
  binsVacios.unshift(entry);
  fs.writeFileSync(BINS_VACIOS_PATH, JSON.stringify(binsVacios), 'utf8');
  io.emit('bins_vacios_updated');
  res.json({ ok: true, entry });
});

app.post('/api/bins-vacios/:id/resolver', requireAuth('jefe'), (req, res) => {
  const entry = binsVacios.find(b => b.id === req.params.id);
  if (!entry) return res.status(404).json({ ok: false });
  entry.estado = 'resuelto';
  entry.resolvedBy = req.session.username;
  entry.resolvedAt = new Date().toISOString();
  fs.writeFileSync(BINS_VACIOS_PATH, JSON.stringify(binsVacios), 'utf8');
  io.emit('bins_vacios_updated');
  res.json({ ok: true });
});

app.post('/api/bins-vacios/nota', requireAuth('bodega'), (req, res) => {
  const { nota, orderId } = req.body;
  if (!nota) return res.json({ ok: true });
  const entry = {
    id: uuidv4(),
    styleColor: '—',
    bin: '—',
    desc: nota,
    nota: nota,
    estado: 'pendiente',
    tipo: 'nota_listo',
    orderId: orderId || '',
    reportedBy: req.session.username,
    createdAt: new Date().toISOString()
  };
  binsVacios.unshift(entry);
  fs.writeFileSync(BINS_VACIOS_PATH, JSON.stringify(binsVacios), 'utf8');
  io.emit('bins_vacios_updated');
  res.json({ ok: true });
});

app.delete('/api/bins-vacios/:id', requireAuth('jefe'), (req, res) => {
  binsVacios = binsVacios.filter(b => b.id !== req.params.id);
  fs.writeFileSync(BINS_VACIOS_PATH, JSON.stringify(binsVacios), 'utf8');
  io.emit('bins_vacios_updated');
  res.json({ ok: true });
});

// ── Control de Acceso (jefe only) ───────────────────────────
app.get('/api/access-control', requireAuth('jefe'), (req, res) => {
  res.json({ ok: true, ...accessControl,
    startHour: accessControl.startHour ?? 10,
    endHour:   accessControl.endHour   ?? 22,
    currentlyOpen: isWithinAccessHours(),
  });
});
app.post('/api/access-control', requireAuth('jefe'), (req, res) => {
  const { manualLock, lockMessage, startHour, endHour } = req.body;
  if (manualLock !== undefined) accessControl.manualLock = !!manualLock;
  if (lockMessage !== undefined) accessControl.lockMessage = lockMessage.trim();
  if (startHour !== undefined) accessControl.startHour = parseInt(startHour);
  if (endHour   !== undefined) accessControl.endHour   = parseInt(endHour);
  saveAccessControl();
  if (accessControl.manualLock) io.emit('access_locked', { message: accessControl.lockMessage });
  else io.emit('access_unlocked');
  console.log('[Access] ' + (accessControl.manualLock ? 'BLOQUEADO' : 'Abierto') + ' por ' + req.session.username);
  res.json({ ok: true, ...accessControl });
});

app.get('/api/jefatura/resumen', requireAuth('jefe'), (req, res) => {
  res.json({
    binsVacios: binsVacios.filter(b => b.estado === 'pendiente'),
    piesPendientes: piesPerdidos.filter(p => p.estado !== 'encontrado'), // all active pies
    bultos
  });
});

// ── Pies Perdidos Excel Download ─────────────────────────────
app.get('/api/pies-perdidos/download', requireAuth('jefe'), (req, res) => {
  try {
    const confirmados = piesPerdidos.filter(p => p.estado === 'confirmado');
    const rows = [['Style Color - Talla', 'Pie', 'Bulto']];
    confirmados.forEach(p => {
      const bulto = bultos.find(b => b.id === p.bultoId);
      rows.push([
        `${p.styleColor} - ${p.talla}`,
        p.lado === 'izquierdo' ? 'IZQ' : 'DER',
        bulto ? bulto.nombre : '—'
      ]);
    });
    // Build CSV with semicolon separator (Spanish Excel compatible)
    const csv = rows.map(r => r.join(';')).join('\r\n');
    const date = new Date().toLocaleDateString('es-CL',{timeZone:'America/Santiago'}).replace(/\//g,'-');
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="PiesPerdidos_${date}.csv"`);
    res.send('﻿' + csv); // BOM for Excel UTF-8
  } catch(e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// Health check endpoint - shows system status at a glance
// ── Exhibiciones ─────────────────────────────────────────────
const EXHIB_PATH = path.join(DATA_DIR, 'exhibiciones.json');
let exhibiciones = [];
try {
  if (fs.existsSync(EXHIB_PATH)) exhibiciones = JSON.parse(fs.readFileSync(EXHIB_PATH, 'utf8'));
} catch(e) { exhibiciones = []; }
function saveExhibiciones() {
  try { fs.writeFileSync(EXHIB_PATH, JSON.stringify(exhibiciones)); } catch(e) {}
}
function getWeekKey() {
  const d = new Date();
  const utc = new Date(Date.UTC(d.getFullYear(), d.getMonth(), d.getDate()));
  const day = utc.getUTCDay() || 7;
  utc.setUTCDate(utc.getUTCDate() + 4 - day);
  const yearStart = new Date(Date.UTC(utc.getUTCFullYear(), 0, 1));
  const week = Math.ceil((((utc - yearStart) / 86400000) + 1) / 7);
  return utc.getUTCFullYear() + '-S' + String(week).padStart(2, '0');
}

app.get('/api/exhibiciones', requireAuth(), (req, res) => {
  res.json(exhibiciones);
});
app.get('/api/exhibiciones/semanas', requireAuth(), (req, res) => {
  const semanas = [...new Set(exhibiciones.map(e => e.semana))].sort().reverse();
  res.json(semanas);
});
app.post('/api/exhibiciones', requireAuth(), (req, res) => {
  const { styleColor, talla, cajaEstado, pieEstado, pieUbicacion, nota } = req.body;
  if (!styleColor || !talla) return res.status(400).json({ ok: false, error: 'Faltan campos' });
  const exhib = {
    id: Date.now().toString(),
    styleColor: styleColor.toUpperCase().trim(),
    talla: talla.trim(),
    cajaEstado, pieEstado, pieUbicacion,
    nota: nota || '',
    completada: cajaEstado !== 'no_hay' && pieEstado === 'completo',
    creadoEn: new Date().toISOString(),
    semana: getWeekKey(),
    creadoPor: req.session.username
  };
  exhibiciones.unshift(exhib);
  saveExhibiciones();
  io.emit('exhibicion_nueva', exhib);
  res.json({ ok: true, exhib });
});
app.patch('/api/exhibiciones/:id', requireAuth(), (req, res) => {
  const exhib = exhibiciones.find(e => e.id === req.params.id);
  if (!exhib) return res.status(404).json({ ok: false });
  const { styleColor, talla, cajaEstado, pieEstado, pieUbicacion, nota } = req.body;
  if (styleColor)   exhib.styleColor   = styleColor.toUpperCase().trim();
  if (talla)        exhib.talla        = talla.trim();
  if (cajaEstado)   exhib.cajaEstado   = cajaEstado;
  if (pieEstado)    exhib.pieEstado    = pieEstado;
  if (pieUbicacion) exhib.pieUbicacion = pieUbicacion;
  if (nota !== undefined) exhib.nota   = nota;
  exhib.completada = exhib.cajaEstado !== 'no_hay' && exhib.pieEstado === 'completo';
  exhib.editadoEn  = new Date().toISOString();
  saveExhibiciones();
  io.emit('exhibicion_actualizada', exhib);
  res.json({ ok: true, exhib });
});
app.post('/api/exhibiciones/reset', requireAuth(), (req, res) => {
  exhibiciones = [];
  saveExhibiciones();
  io.emit('exhibicion_nueva');
  console.log('[Exhibiciones] Reset manual por ' + req.session.username);
  res.json({ ok: true });
});

app.delete('/api/exhibiciones/:id', requireAuth(), (req, res) => {
  const before = exhibiciones.length;
  exhibiciones = exhibiciones.filter(e => e.id !== req.params.id);
  if (exhibiciones.length === before) return res.status(404).json({ ok: false });
  saveExhibiciones();
  res.json({ ok: true });
});

app.get('/api/health', requireAuth('bodega'), (req, res) => {
  const mem = process.memoryUsage();
  const uptime = process.uptime();
  const days = Math.floor(uptime / 86400);
  const hours = Math.floor((uptime % 86400) / 3600);
  const mins = Math.floor((uptime % 3600) / 60);

  res.json({
    ok: true,
    uptime: `${days}d ${hours}h ${mins}m`,
    memory: {
      heapUsed: Math.round(mem.heapUsed / 1024 / 1024) + ' MB',
      heapTotal: Math.round(mem.heapTotal / 1024 / 1024) + ' MB',
      rss: Math.round(mem.rss / 1024 / 1024) + ' MB',
      pct: Math.round(mem.heapUsed / mem.heapTotal * 100) + '%'
    },
    stock: {
      loaded: stockMeta.total > 0,
      products: stockMeta.total || 0,
      withBin: stockMeta.withBin || 0,
      updatedAt: stockMeta.updatedAt || null,
      filename: stockMeta.filename || null
    },
    orders: {
      active: orders.filter(o => o.status !== 'listo').length,
      pendiente: orders.filter(o => o.status === 'pendiente').length,
      enProceso: orders.filter(o => o.status === 'en_proceso').length
    },
    sessions: Object.keys(sessions).length,
    node: process.version,
    timestamp: new Date().toISOString()
  });
});

// -- Download stock as Excel --
// ── Sales Ranking ────────────────────────────────────────────
// Build ranking from BOTH repoHoraHistory AND completed orders history
function buildRanking(limit) {
  const map = {};

  function addItem(sc, desc, date) {
    const key = (sc || '').toString().trim().toUpperCase();
    // Exclude hash wall and invalid entries
    if (!key || key === 'HASH-WALL' || key.startsWith('HASH')) return;
    if (!map[key]) map[key] = { styleColor: key, desc: desc || '', count: 0, lastSeen: date || '' };
    map[key].count++;
    if (date && date > map[key].lastSeen) map[key].lastSeen = date;
    if (desc && !map[key].desc) map[key].desc = desc;
  }

  // Source 1: Repo por hora history
  repoHoraHistory.forEach(entry => {
    (entry.items || []).forEach(item => {
      addItem(item.styleColor, item.desc, entry.date);
    });
  });

  // Source 2: Completed orders from sala (pedidos completados)
  history.forEach(order => {
    if (order.tipo === 'hashwall') return; // skip hash orders
    if (order.tipo === 'repohora') return; // skip repohora - already counted via repoHoraHistory
    (order.items || []).forEach(item => {
      addItem(item.styleColor, item.desc, order.dateKey);
    });
  });

  const sorted = Object.values(map).sort((a, b) => b.count - a.count);
  return limit ? sorted.slice(0, limit) : sorted;
}

app.get('/api/ranking', requireAuth(), (req, res) => {
  const limit = parseInt(req.query.limit) || 20;
  res.json(buildRanking(limit));
});

app.delete('/api/ranking', requireAuth('bodega'), (req, res) => {
  // Reset means clear the history ranking — we keep history but can reset salesRanking
  salesRanking = {};
  fs.writeFileSync(path.join(DATA_DIR, 'salesRanking.json'), JSON.stringify(salesRanking), 'utf8');
  res.json({ ok: true });
});

// ── Nike Product Name Lookup ─────────────────────────────────
const https = require('https');
let nameCache = {}; // { 'FQ8331-600': 'ZM SUPERFLY 10 ACADEMY TF' }


// -- Admin: update user --
app.put('/api/admin/users/:username', requireAuth('admin'), (req, res) => {
  const users = getUsers();
  const idx = users.findIndex(u => u.username === req.params.username);
  if (idx === -1) return res.status(404).json({ ok: false });
  if (req.body.roles) users[idx].roles = req.body.roles;
  if (req.body.displayName) users[idx].displayName = req.body.displayName;
  if (req.body.resetPassword) { users[idx].password = hash('nike2020'); users[idx].mustChangePassword = true; }
  saveUsers(users);
  res.json({ ok: true });
});

// -- Admin: create user --
app.post('/api/admin/users', requireAuth('admin'), (req, res) => {
  const users = getUsers();
  const { username, displayName, password, roles, mustChangePassword } = req.body;
  if (!username || !displayName || !roles) return res.status(400).json({ ok: false, error: 'Faltan campos' });
  if (users.find(u => u.username === username)) return res.status(400).json({ ok: false, error: 'Usuario ya existe' });
  users.push({
    username: username.toLowerCase().trim(),
    displayName,
    password: hash(password || 'nike2020'),
    roles: roles || ['sala'],
    mustChangePassword: mustChangePassword !== false
  });
  saveUsers(users);
  res.json({ ok: true });
});

// -- Admin: delete user --
app.delete('/api/admin/users/:username', requireAuth('admin'), (req, res) => {
  if (req.params.username === 'matias.saravia') return res.status(403).json({ ok: false, error: 'No puedes eliminar al admin principal' });
  let users = getUsers();
  const before = users.length;
  users = users.filter(u => u.username !== req.params.username);
  if (users.length === before) return res.status(404).json({ ok: false });
  saveUsers(users);
  res.json({ ok: true });
});

app.get('/api/stock-upc/debug', requireAuth('bodega'), (req, res) => {
  // Shows first 10 UPC entries so you can verify the column name
  const sample = Object.entries(upcIndex).slice(0, 10).map(([u, v]) => ({ upc: u, ...v }));
  res.json({ total: Object.keys(upcIndex).length, sample });
});

app.get('/api/stock-upc/:upc', requireAuth(), (req, res) => {
  const upcQuery = req.params.upc.trim().replace(/[^0-9]/g,'');
  const match = upcIndex[upcQuery];
  if (!match) return res.json({ found: false, debug_upc: upcQuery, debug_total: Object.keys(upcIndex).length });
  const product = stockDB[match.styleColor];
  if (!product) return res.json({ found: false });
  res.json({ found: true, styleColor: match.styleColor, matchedSize: match.size, product });
});

app.get('/api/stock/:styleColor', requireAuth(), (req, res) => {
  const sc = req.params.styleColor.toUpperCase();
  const product = stockDB[sc];
  if (!product) return res.status(404).json({ found: false });
  res.json({ found: true, product });
});

// ── Orders ────────────────────────────────────────────────────
app.post('/api/orders', requireAuth(), (req, res) => {
  const { vendedor, items, tipo, filename } = req.body;
  if (!items || !items.length) return res.status(400).json({ ok: false });
  const roles = req.session.roles || [req.session.role];
  // Sala can post normal orders; bodega+jefe can post repohora orders
  const isRepohora = tipo === 'repohora';
  const canPost = roles.includes('sala') || roles.includes('admin') ||
                  (isRepohora && (roles.includes('jefe')));
  if (!canPost) return res.status(403).json({ ok: false });
  const order = {
    id: uuidv4(),
    timestamp: new Date().toISOString(),
    vendedor: vendedor || req.session.username,
    items, status: 'pendiente',
    ...(tipo && { tipo }),
    ...(filename && { filename })
  };
  orders.push(order);
  save(ORDERS_PATH, orders);
  io.emit('order_new', order);
  res.json({ ok: true, order });
});
app.get('/api/orders', requireAuth(), (req, res) => {
  const { vendedor } = req.query;
  const active = orders.filter(o => o.status !== 'listo');
  if (vendedor) return res.json(active.filter(o => o.vendedor === vendedor));
  res.json(active);
});
app.patch('/api/orders/:id/status', requireAuth('bodega'), (req, res) => {
  const { status, nota } = req.body;
  const order = orders.find(o => o.id === req.params.id);
  if (!order) return res.status(404).json({ ok: false });
  order.status = status;
  if (nota) order.notaFinal = nota; // bodega's completion note
  save(ORDERS_PATH, orders);
  if (status === 'listo') {
    const completed = { ...order, completedAt: new Date().toISOString(), dateKey: new Date().toLocaleDateString('es-CL', { year:'numeric', month:'2-digit', day:'2-digit', timeZone: 'America/Santiago' }) };
    history.unshift(completed);
    save(HISTORY_PATH, history);
    // Track completion so disconnected sala clients pick it up on next sync
    recentlyDone.unshift({ id: order.id, vendedor: order.vendedor, completedAt: new Date().toISOString() });
    // Keep only last 24h
    const doneCutoff = new Date(Date.now() - 24*60*60*1000).toISOString();
    recentlyDone = recentlyDone.filter(d => d.completedAt > doneCutoff);
    io.emit('order_done', { id: order.id });
    io.emit('history_updated', { order: completed });
    setTimeout(() => { orders = orders.filter(o => o.id !== order.id); save(ORDERS_PATH, orders); }, 3000);
  } else { io.emit('order_status', { id: order.id, status }); }
  res.json({ ok: true });
});

// Sala checks this to find orders completed while offline
app.get('/api/orders/completed', requireAuth('sala'), (req, res) => {
  const vendedor = req.query.vendedor;
  const since = req.query.since; // ISO timestamp - only return completions after this
  let done = recentlyDone;
  if (vendedor) done = done.filter(d => d.vendedor === vendedor);
  if (since) done = done.filter(d => d.completedAt > since);
  res.json(done.map(d => d.id));
});

// ── History ───────────────────────────────────────────────────
app.get('/api/history', requireAuth('bodega'), (req, res) => {
  const { date } = req.query;
  res.json(date ? history.filter(o => o.dateKey === date) : history);
});
app.get('/api/history/dates', requireAuth('bodega'), (req, res) => {
  const map = {};
  history.forEach(o => {
    if (!map[o.dateKey]) map[o.dateKey] = { date: o.dateKey, orders: 0, units: 0 };
    map[o.dateKey].orders++;
    map[o.dateKey].units += o.items.reduce((s,i) => s+i.qty, 0);
  });
  res.json(Object.values(map));
});
// Delete individual history order - jefe only
app.delete('/api/history/:id', requireAuth('jefe'), (req, res) => {
  const { id } = req.params;
  const before = history.length;
  history = history.filter(o => o.id !== id);
  if (history.length === before) return res.status(404).json({ ok: false, error: 'No encontrado' });
  save(HISTORY_PATH, history);
  io.emit('history_updated');
  res.json({ ok: true });
});

app.delete('/api/history', requireAuth('bodega'), (req, res) => {
  const { date } = req.query;
  if (date) history = history.filter(o => o.dateKey !== date); else history = [];
  save(HISTORY_PATH, history);
  io.emit('history_cleared', { date: date || null });
  res.json({ ok: true });
});

// ── Hash Wall ─────────────────────────────────────────────────
app.get('/api/hashwall', requireAuth(), (req, res) => res.json(hashwall));
app.put('/api/hashwall', requireAuth(), (req, res) => {
  const { categories, qtys } = req.body;
  if (!categories && !qtys) return res.status(400).json({ ok: false });
  if (qtys) {
    hashwall = { updatedAt: new Date().toISOString(), qtys };
  } else {
    hashwall = { updatedAt: new Date().toISOString(), categories };
  }
  save(HASHWALL_PATH, hashwall);
  io.emit('hashwall_updated', hashwall);
  res.json({ ok: true, hashwall });
});
app.patch('/api/hashwall/:category', requireAuth(), (req, res) => {
  const cat = decodeURIComponent(req.params.category);
  const { items } = req.body;
  if (!hashwall.categories[cat]) hashwall.categories[cat] = [];
  hashwall.categories[cat] = items;
  hashwall.updatedAt = new Date().toISOString();
  save(HASHWALL_PATH, hashwall);
  io.emit('hashwall_updated', hashwall);
  res.json({ ok: true });
});

// ── Socket ────────────────────────────────────────────────────
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!getSession(token)) return next(new Error('No autenticado'));
  socket.session = getSession(token);
  next();
});
io.on('connection', (socket) => {
  socket.emit('init', { stockLoaded: stockMeta.total > 0, ...stockMeta, orders: orders.filter(o => o.status !== 'listo') });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Nike corriendo en http://localhost:${PORT}`));

// Auto-cleanup stale orders every hour
setInterval(() => {
  const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
  const before = orders.length;
  orders = orders.filter(o => o.status !== 'listo' && o.timestamp > cutoff);
  if (orders.length !== before) {
    save(ORDERS_PATH, orders);
    io.emit('orders_cleanup');
    console.log(`[Cleanup] Removed ${before - orders.length} stale orders`);
  }
}, 15 * 60 * 1000); // every 15 minutes
