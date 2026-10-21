/**
 * OZON 定价存档 · 实时网页服务
 * ------------------------------------------------------------------
 * 零依赖单文件服务（只用 Node.js 内置模块），数据存本地 JSON 文件。
 * 启动：  node server.js
 * 端口：  环境变量 PORT（默认 3000）
 * 密码：  环境变量 ARCHIVE_PASSWORD（默认 ozon2026，请务必修改）
 * 数据：  环境变量 DATA_DIR（默认 ./data）
 * ------------------------------------------------------------------
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const PASSWORD = process.env.ARCHIVE_PASSWORD || 'ozon2026';
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'archive.json');
const TOKEN_SECRET = process.env.TOKEN_SECRET || ('ozon-' + PASSWORD);

/* ---------------- 存储 ---------------- */
function ensureDir() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
}
function readDB() {
  ensureDir();
  if (!fs.existsSync(DB_FILE)) return { items: [], updatedAt: 0 };
  try {
    const d = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    return { items: Array.isArray(d.items) ? d.items : [], updatedAt: d.updatedAt || 0 };
  } catch (e) {
    // 文件损坏时保留备份
    try { fs.copyFileSync(DB_FILE, DB_FILE + '.broken.' + Date.now()); } catch (_) {}
    return { items: [], updatedAt: 0 };
  }
}
function writeDB(db) {
  ensureDir();
  db.updatedAt = Date.now();
  const tmp = DB_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2), 'utf8');
  fs.renameSync(tmp, DB_FILE);            // 原子写，避免半截文件
  return db;
}

/* ---------------- 鉴权：简单签名为 token，免 session ---------------- */
function sign(ts) {
  return crypto.createHmac('sha256', TOKEN_SECRET).update(String(ts)).digest('hex').slice(0, 32);
}
function makeToken() {
  const ts = Date.now();
  return ts + '.' + sign(ts);
}
const TOKEN_TTL = 1000 * 60 * 60 * 24 * 30;   // 30 天免登录
function verifyToken(token) {
  if (!token || typeof token !== 'string') return false;
  const [ts, sig] = token.split('.');
  if (!ts || !sig) return false;
  if (sign(ts) !== sig) return false;
  return Date.now() - Number(ts) < TOKEN_TTL;
}
function getToken(req, url) {
  const h = req.headers['authorization'] || '';
  if (h.startsWith('Bearer ')) return h.slice(7);
  const cookie = req.headers.cookie || '';
  const m = cookie.match(/(?:^|;\s*)ozon_token=([^;]+)/);
  if (m) return decodeURIComponent(m[1]);
  return url.searchParams.get('token') || '';
}

/* ---------------- 工具 ---------------- */
function send(res, code, body, headers) {
  const h = Object.assign({
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  }, headers || {});
  res.writeHead(code, h);
  res.end(typeof body === 'string' ? body : JSON.stringify(body));
}
function readBody(req, limit = 4 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0, chunks = [];
    req.on('data', c => {
      size += c.length;
      if (size > limit) { reject(new Error('payload too large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      if (!chunks.length) return resolve({});
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
      catch (e) { reject(new Error('invalid json')); }
    });
    req.on('error', reject);
  });
}

/* ---------------- 路由 ---------------- */
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://' + (req.headers.host || 'localhost'));
  const p = url.pathname.replace(/\/+$/, '') || '/';

  // 浏览器跨域预检
  if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }

  // 静态页
  if (req.method === 'GET' && (p === '/' || p === '/index.html')) {
    const file = path.join(__dirname, 'public', 'index.html');
    if (!fs.existsSync(file)) return send(res, 500, { error: 'public/index.html 缺失' });
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
    return res.end(fs.readFileSync(file));
  }

  // 健康检查（无需登录，供部署平台探活）
  if (p === '/api/health') return send(res, 200, { ok: true, uptime: Math.round(process.uptime()), items: readDB().items.length });

  // 登录
  if (req.method === 'POST' && p === '/api/login') {
    let body;
    try { body = await readBody(req); } catch (e) { return send(res, 400, { error: '请求格式错误' }); }
    const pwd = String(body.password || '');
    // 定长比较，避免时序侧信道
    const a = Buffer.from(crypto.createHash('sha256').update(pwd).digest('hex'));
    const b = Buffer.from(crypto.createHash('sha256').update(PASSWORD).digest('hex'));
    const ok = a.length === b.length && crypto.timingSafeEqual(a, b);
    if (!ok) { await new Promise(r => setTimeout(r, 300)); return send(res, 401, { error: '密码不正确' }); }
    const token = makeToken();
    return send(res, 200, { token }, {
      'Set-Cookie': `ozon_token=${token}; Path=/; Max-Age=${60 * 60 * 24 * 30}; SameSite=Lax; HttpOnly`,
    });
  }

  // 校验登录态
  if (req.method === 'GET' && p === '/api/session') {
    return send(res, 200, { ok: verifyToken(getToken(req, url)) });
  }

  // 以下接口需登录
  const authed = verifyToken(getToken(req, url));
  if (p.startsWith('/api/')) {
    if (!authed) return send(res, 401, { error: '未登录或登录已过期' });
  }

  // 拉取全部存档
  if (req.method === 'GET' && p === '/api/archive') {
    const db = readDB();
    return send(res, 200, db);
  }

  // 新增 / 覆盖
  if (req.method === 'POST' && p === '/api/archive') {
    let body;
    try { body = await readBody(req); } catch (e) { return send(res, 400, { error: '数据格式错误或过大' }); }
    const rec = body.item || body;
    if (!rec || !rec.name) return send(res, 400, { error: '缺少产品名称' });
    const db = readDB();
    const now = Date.now();
    let id = rec.id;
    if (!id) {
      // 同名则覆盖，否则新建
      const same = db.items.find(x => x.name === rec.name);
      id = same ? same.id : 'p' + now + Math.random().toString(36).slice(2, 6);
    }
    const item = Object.assign({}, rec, { id, savedAt: rec.savedAt || now, updatedAt: now });
    const idx = db.items.findIndex(x => x.id === id);
    if (idx >= 0) db.items[idx] = item; else db.items.unshift(item);
    writeDB(db);
    return send(res, 200, { ok: true, item, total: db.items.length });
  }

  // 更新单条
  if ((req.method === 'PUT' || req.method === 'PATCH') && p.startsWith('/api/archive/')) {
    const id = decodeURIComponent(p.split('/').pop());
    let body;
    try { body = await readBody(req); } catch (e) { return send(res, 400, { error: '数据格式错误' }); }
    const db = readDB();
    const idx = db.items.findIndex(x => x.id === id);
    if (idx < 0) return send(res, 404, { error: '记录不存在' });
    db.items[idx] = Object.assign({}, db.items[idx], body.item || body, { id, updatedAt: Date.now() });
    writeDB(db);
    return send(res, 200, { ok: true, item: db.items[idx] });
  }

  // 删除
  if (req.method === 'DELETE' && p.startsWith('/api/archive/')) {
    const id = decodeURIComponent(p.split('/').pop());
    const db = readDB();
    const before = db.items.length;
    db.items = db.items.filter(x => x.id !== id);
    if (db.items.length === before) return send(res, 404, { error: '记录不存在' });
    writeDB(db);
    return send(res, 200, { ok: true, total: db.items.length });
  }

  // 批量导入（合并，按 id/name 去重）
  if (req.method === 'POST' && p === '/api/import') {
    let body;
    try { body = await readBody(req); } catch (e) { return send(res, 400, { error: '数据格式错误' }); }
    const list = Array.isArray(body) ? body : (body.items || []);
    if (!Array.isArray(list)) return send(res, 400, { error: '需要数组' });
    const db = readDB();
    let added = 0, updated = 0;
    list.forEach(r => {
      if (!r || !r.name) return;
      const id = r.id || ('p' + Date.now() + Math.random().toString(36).slice(2, 6));
      const idx = db.items.findIndex(x => x.id === id || x.name === r.name);
      if (idx >= 0) { db.items[idx] = Object.assign({}, db.items[idx], r, { id: db.items[idx].id }); updated++; }
      else { db.items.unshift(Object.assign({}, r, { id })); added++; }
    });
    writeDB(db);
    return send(res, 200, { ok: true, added, updated, total: db.items.length });
  }

  send(res, 404, { error: '接口不存在' });
});

server.listen(PORT, () => {
  console.log(`\n  OZON 定价存档服务已启动`);
  console.log(`  地址：http://localhost:${PORT}`);
  console.log(`  密码：${PASSWORD}${PASSWORD === 'ozon2026' ? '  ← 默认密码，请用环境变量 ARCHIVE_PASSWORD 修改' : ''}`);
  console.log(`  数据：${DB_FILE}\n`);
});
