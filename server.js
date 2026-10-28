'use strict';
const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

const PORT = process.env.PORT || 3000;
const PROD = process.env.NODE_ENV === 'production';
const DBFILE = process.env.DB_PATH || path.join(__dirname, 'data', 'granaxp.db');
fs.mkdirSync(path.dirname(DBFILE), { recursive: true });
const db = new Database(DBFILE);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL COLLATE NOCASE, hash TEXT NOT NULL, state TEXT NOT NULL DEFAULT '{}', created INTEGER NOT NULL, seen INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(th TEXT PRIMARY KEY, uid INTEGER, kind TEXT NOT NULL, exp INTEGER NOT NULL, FOREIGN KEY(uid) REFERENCES users(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS notices(id INTEGER PRIMARY KEY AUTOINCREMENT, msg TEXT NOT NULL, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT, act TEXT NOT NULL, at INTEGER NOT NULL);
`);

const get = k => { const r = db.prepare('SELECT v FROM settings WHERE k=?').get(k); return r && r.v; };
const set = (k, v) => db.prepare('INSERT INTO settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v').run(k, v);
const log = act => db.prepare('INSERT INTO audit(act,at) VALUES(?,?)').run(act, Date.now());

// Senha administrativa: só vem do ambiente na primeira vez (ou com RESET_ADMIN=1).
// Depois disso vale a senha trocada no painel, guardada apenas como hash.
if (!get('admin_hash') || process.env.RESET_ADMIN === '1') {
  const p = process.env.ADMIN_PASSWORD;
  if (!p || p.length < 6) {
    console.error('Defina a variável ADMIN_PASSWORD (mínimo 6 caracteres) para criar a senha administrativa inicial.');
    process.exit(1);
  }
  set('admin_hash', bcrypt.hashSync(p, 10));
  log('senha admin definida pelo ambiente');
}
const DUMMY = bcrypt.hashSync('x', 10);

const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(express.json({ limit: '300kb' }));
app.use((q, s, n) => {
  s.set({ 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'same-origin' });
  n();
});

const now = () => Date.now();
const sha = t => crypto.createHash('sha256').update(t).digest('hex');
const cookies = q => Object.fromEntries((q.headers.cookie || '').split(';').map(c => c.trim().split(/=(.*)/s).slice(0, 2)).filter(a => a[0]));
const TWO_WEEKS = 12096e5, TWO_HOURS = 72e5;

function startSession(res, uid, kind, ms) {
  const t = crypto.randomBytes(32).toString('hex');
  db.prepare('DELETE FROM sessions WHERE exp<?').run(now());
  db.prepare('INSERT INTO sessions(th,uid,kind,exp) VALUES(?,?,?,?)').run(sha(t), uid, kind, now() + ms);
  res.cookie(kind === 'admin' ? 'gxp_a' : 'gxp_s', t, { httpOnly: true, sameSite: kind === 'admin' ? 'strict' : 'lax', secure: PROD, maxAge: ms, path: '/' });
}
function session(q, kind) {
  const t = cookies(q)[kind === 'admin' ? 'gxp_a' : 'gxp_s'];
  if (!t) return null;
  const r = db.prepare('SELECT * FROM sessions WHERE th=? AND kind=?').get(sha(t), kind);
  if (!r || r.exp < now()) { if (r) db.prepare('DELETE FROM sessions WHERE th=?').run(r.th); return null; }
  return r;
}
const needUser = (q, s, n) => { const r = session(q, 'user'); if (!r) return s.status(401).json({ error: 'Faça login para continuar.' }); q.uid = r.uid; n(); };
const needAdmin = (q, s, n) => { if (!session(q, 'admin')) return s.status(401).json({ error: 'Acesso restrito.' }); n(); };

// Limitação de tentativas (em memória): janela de 15 minutos
const tries = new Map();
function limited(key, max) {
  let t = tries.get(key);
  if (!t || t.r < now()) { t = { n: 0, r: now() + 9e5 }; tries.set(key, t); }
  return t.n >= max;
}
const fail = key => { const t = tries.get(key); if (t) t.n++; };
const ok = key => tries.delete(key);

// ---- Contas ----
app.post('/api/register', async (q, s) => {
  const u = String(q.body.username || '').trim();
  const p = String(q.body.password || '');
  const d = String(q.body.displayName || '').trim().slice(0, 30);
  if (!/^[A-Za-z0-9_.]{3,20}$/.test(u)) return s.status(400).json({ error: 'Use de 3 a 20 letras, números, ponto ou _ no nome de usuário.' });
  if (p.length < 6 || p.length > 72) return s.status(400).json({ error: 'A senha deve ter de 6 a 72 caracteres.' });
  const key = 'reg|' + q.ip;
  if (limited(key, 10)) return s.status(429).json({ error: 'Muitas tentativas. Aguarde alguns minutos.' });
  fail(key);
  const taken = 'Esse nome de usuário já está em uso. Escolha outro.';
  if (db.prepare('SELECT 1 FROM users WHERE username=?').get(u)) return s.status(409).json({ error: taken });
  const hash = await bcrypt.hash(p, 10);
  const state = { name: d };
  try {
    const r = db.prepare('INSERT INTO users(username,hash,state,created,seen) VALUES(?,?,?,?,?)').run(u, hash, JSON.stringify(state), now(), now());
    startSession(s, r.lastInsertRowid, 'user', TWO_WEEKS);
    s.json({ user: { username: u }, state });
  } catch (e) { s.status(409).json({ error: taken }); }
});

app.post('/api/login', async (q, s) => {
  const u = String(q.body.username || '').trim();
  const p = String(q.body.password || '');
  const key = 'login|' + q.ip + '|' + u.toLowerCase();
  if (limited(key, 6)) return s.status(429).json({ error: 'Muitas tentativas. Aguarde 15 minutos e tente de novo.' });
  const r = db.prepare('SELECT * FROM users WHERE username=?').get(u);
  const good = await bcrypt.compare(p, r ? r.hash : DUMMY);
  if (!r || !good) { fail(key); return s.status(401).json({ error: 'Usuário ou senha incorretos.' }); }
  ok(key);
  db.prepare('UPDATE users SET seen=? WHERE id=?').run(now(), r.id);
  startSession(s, r.id, 'user', TWO_WEEKS);
  s.json({ user: { username: r.username }, state: JSON.parse(r.state) });
});

app.get('/api/me', needUser, (q, s) => {
  const r = db.prepare('SELECT username,state FROM users WHERE id=?').get(q.uid);
  db.prepare('UPDATE users SET seen=? WHERE id=?').run(now(), q.uid);
  s.json({ user: { username: r.username }, state: JSON.parse(r.state) });
});

const asObj = o => (o && typeof o === 'object' && !Array.isArray(o) ? o : {});
const arr = (a, n) => (Array.isArray(a) ? a.slice(0, n) : []);
app.put('/api/state', needUser, (q, s) => {
  const b = q.body;
  if (!b || typeof b !== 'object' || Array.isArray(b)) return s.status(400).json({ error: 'Dados inválidos.' });
  const old = JSON.parse(db.prepare('SELECT state FROM users WHERE id=?').get(q.uid).state);
  const st = {
    name: String(b.name || '').slice(0, 30),
    tx: arr(b.tx, 5000).filter(t => t && Number.isFinite(t.val) && t.val > 0 && (t.type === 'r' || t.type === 'd')),
    goals: arr(b.goals, 200).filter(g => g && Number.isFinite(g.val) && g.val > 0 && Array.isArray(g.hist)),
    log: arr(b.log, 30), ach: arr(b.ach, 50),
    av: String(b.av || '').slice(0, 8),
    acc: /^#[0-9a-f]{6}$/i.test(b.acc) ? b.acc : '',
    claimed: asObj(b.claimed), xpday: asObj(b.xpday),
    // limite simples contra XP inflado: no máximo +300 por salvamento
    xp: Math.max(0, Math.min(Number(b.xp) || 0, (Number(old.xp) || 0) + 300)),
  };
  db.prepare('UPDATE users SET state=? WHERE id=?').run(JSON.stringify(st), q.uid);
  s.json({ ok: true });
});

app.post('/api/logout', (q, s) => {
  const t = cookies(q).gxp_s;
  if (t) db.prepare('DELETE FROM sessions WHERE th=?').run(sha(t));
  s.clearCookie('gxp_s');
  s.json({ ok: true });
});

app.delete('/api/me', needUser, async (q, s) => {
  const r = db.prepare('SELECT hash FROM users WHERE id=?').get(q.uid);
  if (!(await bcrypt.compare(String((q.body || {}).password || ''), r.hash))) return s.status(401).json({ error: 'Senha incorreta.' });
  db.prepare('DELETE FROM users WHERE id=?').run(q.uid);
  s.clearCookie('gxp_s');
  s.json({ ok: true });
});

app.get('/api/config', (q, s) => s.json({
  accent: get('accent') || '',
  notices: db.prepare('SELECT id,msg FROM notices ORDER BY id DESC LIMIT 5').all(),
}));

// ---- Administrador ----
app.post('/api/admin/login', async (q, s) => {
  const key = 'admin|' + q.ip;
  if (limited(key, 5)) return s.status(429).json({ error: 'Muitas tentativas. Aguarde 15 minutos.' });
  if (!(await bcrypt.compare(String(q.body.password || ''), get('admin_hash')))) {
    fail(key);
    return s.status(401).json({ error: 'Senha incorreta. Tente novamente' });
  }
  ok(key);
  startSession(s, null, 'admin', TWO_HOURS);
  log('login do administrador');
  s.json({ ok: true });
});

app.get('/api/admin/stats', needAdmin, (q, s) => {
  const c = (w, ...a) => db.prepare('SELECT COUNT(*) c FROM users ' + w).get(...a).c;
  const d = 864e5, n = now();
  s.json({
    total: c(''), new7: c('WHERE created>?', n - 7 * d),
    a1: c('WHERE seen>?', n - d), a7: c('WHERE seen>?', n - 7 * d), a30: c('WHERE seen>?', n - 30 * d),
    notices: db.prepare('SELECT id,msg FROM notices ORDER BY id DESC').all(),
    audit: db.prepare('SELECT act,at FROM audit ORDER BY id DESC LIMIT 10').all(),
  });
});

app.post('/api/admin/notices', needAdmin, (q, s) => {
  const m = String(q.body.msg || '').trim().slice(0, 200);
  if (!m) return s.status(400).json({ error: 'Escreva o aviso.' });
  db.prepare('INSERT INTO notices(msg,created) VALUES(?,?)').run(m, now());
  log('aviso publicado');
  s.json({ ok: true });
});
app.delete('/api/admin/notices/:id', needAdmin, (q, s) => {
  db.prepare('DELETE FROM notices WHERE id=?').run(Number(q.params.id));
  log('aviso excluído');
  s.json({ ok: true });
});
app.post('/api/admin/accent', needAdmin, (q, s) => {
  const a = String(q.body.accent || '');
  if (a && !/^#[0-9a-f]{6}$/i.test(a)) return s.status(400).json({ error: 'Cor inválida.' });
  set('accent', a);
  log('cor global alterada');
  s.json({ ok: true });
});
app.post('/api/admin/password', needAdmin, async (q, s) => {
  const cur = String(q.body.current || ''), nxt = String(q.body.next || '');
  if (!(await bcrypt.compare(cur, get('admin_hash')))) return s.status(401).json({ error: 'Senha atual incorreta.' });
  if (nxt.length < 8 || nxt.length > 72) return s.status(400).json({ error: 'A nova senha deve ter de 8 a 72 caracteres.' });
  set('admin_hash', await bcrypt.hash(nxt, 10));
  db.prepare("DELETE FROM sessions WHERE kind='admin'").run();
  log('senha do administrador alterada');
  startSession(s, null, 'admin', TWO_HOURS);
  s.json({ ok: true });
});
app.post('/api/admin/logout', (q, s) => {
  const t = cookies(q).gxp_a;
  if (t) db.prepare('DELETE FROM sessions WHERE th=?').run(sha(t));
  s.clearCookie('gxp_a');
  s.json({ ok: true });
});

app.use('/api', (q, s) => s.status(404).json({ error: 'Não encontrado.' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use((e, q, s, n) => s.status(400).json({ error: 'Requisição inválida.' }));

app.listen(PORT, () => console.log('GranaXP rodando na porta ' + PORT));
