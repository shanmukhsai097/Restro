require('dotenv').config();

const path = require('path');
const fs = require('fs');
const os = require('os');
const http = require('http');
const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { Server } = require('socket.io');
const { Pool } = require('pg');

const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET;
const DATABASE_URL = process.env.DATABASE_URL;
const OCR_ENABLED = String(process.env.OCR_ENABLED || 'true') === 'true';
const FRONTEND_URL = process.env.FRONTEND_URL || undefined;

if (!DATABASE_URL) {
  console.error('DATABASE_URL is missing. Use the Supabase Transaction Pooler URL in Render.');
  process.exit(1);
}
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error('JWT_SECRET is missing or too short. Use a random value of at least 32 characters.');
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: Number(process.env.PG_POOL_MAX || 5),
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 15000,
});

const app = express();
app.disable('x-powered-by');
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: FRONTEND_URL || true, credentials: true }
});
const upload = multer({ dest: os.tmpdir(), limits: { fileSize: 12 * 1024 * 1024 } });

app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(cors({ origin: FRONTEND_URL || true, credentials: true }));
app.use(express.json({ limit: '25mb' }));
app.use(express.urlencoded({ extended: true }));

const apiLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 300, standardHeaders: true, legacyHeaders: false, message: { error: 'Too many requests' } });
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, standardHeaders: true, legacyHeaders: false, message: { error: 'Too many login attempts. Try again later.' } });

const DEFAULT_SETTINGS = { name: 'RESTO', vat_no: '', address: '', city: '', currency: 'EUR', vat_pct: 10, service_charge: 0, invoice_prefix: 'INV-', footer: 'Thank you!' };
const DEFAULT_STATE = {
  users: [
    { id: 1, email: 'owner@resto.com', passwordHash: bcrypt.hashSync('owner123', 12), role: 'owner', name: 'Owner Admin', color: '#f5a623', active: true }
  ],
  tables: [], menu: [], orders: [], invoices: [], employees: [], expenses: [], purchases: [], shifts: [], leaves: [], attendance: [], workhours: [], pending_resets: [],
  settings: DEFAULT_SETTINGS,
  lang: 'en'
};
let state = clone(DEFAULT_STATE);
let dbReady = false;

function clone(v) { return JSON.parse(JSON.stringify(v)); }
function publicUser(u) { return { id: u.id, email: u.email, role: u.role, name: u.name, color: u.color, active: u.active !== false }; }
function publicReset(r, idx) { return { idx, email: r.email, name: r.name, requestedAt: r.requestedAt }; }
function publicState() {
  const out = clone(state);
  out.users = (out.users || []).map(publicUser);
  out.pending_resets = (out.pending_resets || []).map(publicReset);
  return out;
}
function normalizeUsers(users) {
  const source = Array.isArray(users) && users.length ? users : clone(DEFAULT_STATE.users);
  return source.map((u, idx) => ({
    id: Number(u.id || idx + 1),
    email: String(u.email || '').trim().toLowerCase(),
    passwordHash: u.passwordHash || bcrypt.hashSync(String(u.pass || (idx === 0 ? 'owner123' : crypto.randomBytes(10).toString('hex'))), 12),
    role: ['owner','manager','waiter','chef','bar'].includes(u.role) ? u.role : 'waiter',
    name: String(u.name || u.email || `User ${idx + 1}`),
    color: u.color || '#f5a623',
    active: u.active !== false
  }));
}
function normalizeState(input) {
  const out = { ...clone(DEFAULT_STATE), ...(input || {}) };
  out.settings = { ...DEFAULT_SETTINGS, ...(out.settings || {}) };
  out.users = normalizeUsers(out.users);
  if (!Array.isArray(out.pending_resets)) out.pending_resets = [];
  return out;
}
async function initDb() {
  await pool.query(`create table if not exists app_state (key text primary key, value jsonb not null, updated_at timestamptz not null default now())`);
  for (const [key, value] of Object.entries(DEFAULT_STATE)) {
    await pool.query(`insert into app_state (key, value) values ($1, $2::jsonb) on conflict (key) do nothing`, [key, JSON.stringify(value)]);
  }
  state = await loadState();
  dbReady = true;
}
async function loadState() {
  const rows = await pool.query('select key, value from app_state');
  const loaded = clone(DEFAULT_STATE);
  for (const row of rows.rows) loaded[row.key] = row.value;
  return normalizeState(loaded);
}
async function saveKey(key, value) {
  await pool.query(`insert into app_state (key, value, updated_at) values ($1, $2::jsonb, now()) on conflict (key) do update set value = excluded.value, updated_at = now()`, [key, JSON.stringify(value)]);
}
async function saveMany(entries) {
  const client = await pool.connect();
  try {
    await client.query('begin');
    for (const [key, value] of Object.entries(entries)) {
      await client.query(`insert into app_state (key, value, updated_at) values ($1, $2::jsonb, now()) on conflict (key) do update set value = excluded.value, updated_at = now()`, [key, JSON.stringify(value)]);
    }
    await client.query('commit');
  } catch (e) { await client.query('rollback'); throw e; }
  finally { client.release(); }
}
function validate(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ error: 'Invalid input', details: errors.array().map(e => ({ path: e.path, msg: e.msg })) });
  next();
}
function authRequired(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Missing token' });
  try { req.user = jwt.verify(token, JWT_SECRET); return next(); }
  catch { return res.status(401).json({ error: 'Invalid or expired token' }); }
}
function ownerOnly(req, res, next) { return req.user?.role === 'owner' ? next() : res.status(403).json({ error: 'Owner only' }); }

io.use((socket, next) => {
  try {
    const token = socket.handshake.auth?.token;
    if (!token) return next(new Error('Missing token'));
    socket.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch { next(new Error('Authentication failed')); }
});
io.on('connection', socket => socket.emit('connected', { ok: true, user: socket.user.email, time: new Date().toISOString() }));

app.get('/healthz', async (req, res) => {
  try { await pool.query('select 1'); res.json({ ok: true, mode: 'supabase-postgres', dbReady, time: new Date().toISOString() }); }
  catch { res.status(500).json({ ok: false }); }
});
app.get('/api/health', async (req, res) => {
  try { await pool.query('select 1'); res.json({ ok: true, mode: 'supabase-postgres', dbReady, time: new Date().toISOString() }); }
  catch { res.status(500).json({ ok: false }); }
});

app.post('/api/login', authLimiter,
  body('email').isEmail().normalizeEmail(),
  body('password').isString().isLength({ min: 1 }),
  validate,
  (req, res) => {
    const email = String(req.body.email || '').trim().toLowerCase();
    const pass = String(req.body.password || '');
    const user = (state.users || []).find(u => String(u.email).toLowerCase() === email);
    if (!user || user.active === false || !bcrypt.compareSync(pass, user.passwordHash || '')) {
      console.warn('Failed login', { email, ip: req.ip, at: new Date().toISOString() });
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN || '12h' });
    res.json({ token, user: publicUser(user) });
  }
);

app.post('/api/password-reset-request', authLimiter,
  body('email').isEmail().normalizeEmail(),
  body('newPassword').isString().isLength({ min: 6 }),
  validate,
  async (req, res) => {
    const email = String(req.body.email || '').trim().toLowerCase();
    const user = (state.users || []).find(u => u.email === email && u.active !== false);
    if (!user) return res.status(404).json({ error: 'No active account found with that email' });
    state.pending_resets = (state.pending_resets || []).filter(r => r.email !== email);
    state.pending_resets.push({ email, name: user.name, passwordHash: bcrypt.hashSync(String(req.body.newPassword), 12), requestedAt: new Date().toISOString() });
    await saveKey('pending_resets', state.pending_resets);
    io.emit('state:update', { key: 'pending_resets', value: state.pending_resets.map(publicReset), at: new Date().toISOString() });
    res.json({ ok: true });
  }
);

app.use('/api', apiLimiter);
app.use('/api', authRequired);

app.get('/api/bootstrap', async (req, res) => {
  state = await loadState();
  res.json({ state: publicState(), serverTime: new Date().toISOString() });
});
app.get('/api/state/:key', (req, res) => {
  const key = req.params.key;
  if (!(key in state) && !key.startsWith('seq_')) return res.status(404).json({ error: 'State key not found' });
  const value = key === 'users' ? (state.users || []).map(publicUser) : key === 'pending_resets' ? (state.pending_resets || []).map(publicReset) : state[key];
  res.json({ key, value });
});
app.post('/api/state/:key', async (req, res) => {
  const key = req.params.key;
  if (!(key in DEFAULT_STATE) && !key.startsWith('seq_')) return res.status(400).json({ error: 'Unsupported state key' });
  if (key === 'users' && req.user.role !== 'owner') return res.status(403).json({ error: 'Only owner can manage users' });
  if (key === 'pending_resets') return res.status(403).json({ error: 'Use password reset endpoints' });
  let value = req.body.value;
  if (key === 'users') {
    const existing = state.users || [];
    value = (Array.isArray(value) ? value : []).map((u, idx) => {
      const old = existing.find(x => Number(x.id) === Number(u.id) || String(x.email).toLowerCase() === String(u.email).toLowerCase());
      return {
        id: Number(u.id || Date.now() + idx),
        email: String(u.email || '').trim().toLowerCase(),
        passwordHash: u.pass ? bcrypt.hashSync(String(u.pass), 12) : (old?.passwordHash || bcrypt.hashSync(crypto.randomBytes(14).toString('hex'), 12)),
        role: ['owner','manager','waiter','chef','bar'].includes(u.role) ? u.role : (old?.role || 'waiter'),
        name: u.name || old?.name || u.email,
        color: u.color || old?.color || '#f5a623',
        active: u.active !== false
      };
    });
  }
  state[key] = value;
  await saveKey(key, value);
  const publicValue = key === 'users' ? value.map(publicUser) : value;
  io.emit('state:update', { key, value: publicValue, updatedBy: req.user.email, at: new Date().toISOString() });
  res.json({ ok: true, key, value: publicValue });
});

app.post('/api/import-state', ownerOnly, async (req, res) => {
  state = normalizeState(req.body.state || req.body || {});
  await saveMany(state);
  io.emit('state:reload', { updatedBy: req.user.email, at: new Date().toISOString() });
  res.json({ ok: true });
});
app.post('/api/users/:id/password', async (req, res) => {
  const id = Number(req.params.id);
  if (req.user.role !== 'owner' && Number(req.user.id) !== id) return res.status(403).json({ error: 'Not allowed' });
  const user = (state.users || []).find(u => Number(u.id) === id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const newPassword = String(req.body.newPassword || '');
  if (newPassword.length < 6) return res.status(400).json({ error: 'New password must be at least 6 characters' });
  if (req.user.role !== 'owner') {
    const oldPassword = String(req.body.oldPassword || '');
    if (!bcrypt.compareSync(oldPassword, user.passwordHash || '')) return res.status(400).json({ error: 'Current password is incorrect' });
  }
  user.passwordHash = bcrypt.hashSync(newPassword, 12);
  await saveKey('users', state.users);
  io.emit('state:update', { key: 'users', value: state.users.map(publicUser), updatedBy: req.user.email, at: new Date().toISOString() });
  res.json({ ok: true });
});
app.post('/api/password-resets/:idx/approve', ownerOnly, async (req, res) => {
  const idx = Number(req.params.idx);
  const reset = (state.pending_resets || [])[idx];
  if (!reset) return res.status(404).json({ error: 'Reset request not found' });
  const user = (state.users || []).find(u => u.email === reset.email);
  if (!user) return res.status(404).json({ error: 'User not found' });
  user.passwordHash = reset.passwordHash;
  state.pending_resets.splice(idx, 1);
  await saveMany({ users: state.users, pending_resets: state.pending_resets });
  io.emit('state:reload', { updatedBy: req.user.email, at: new Date().toISOString() });
  res.json({ ok: true });
});
app.post('/api/password-resets/:idx/deny', ownerOnly, async (req, res) => {
  const idx = Number(req.params.idx);
  if (!(state.pending_resets || [])[idx]) return res.status(404).json({ error: 'Reset request not found' });
  state.pending_resets.splice(idx, 1);
  await saveKey('pending_resets', state.pending_resets);
  io.emit('state:update', { key: 'pending_resets', value: state.pending_resets.map(publicReset), updatedBy: req.user.email, at: new Date().toISOString() });
  res.json({ ok: true });
});

app.post('/api/ocr', upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  let rawText = '';
  try {
    if (OCR_ENABLED && req.file.mimetype && req.file.mimetype.startsWith('image/')) {
      const { createWorker } = require('tesseract.js');
      const worker = await createWorker('eng');
      const result = await worker.recognize(req.file.path);
      rawText = result?.data?.text || '';
      await worker.terminate();
    }
  } catch (err) {
    console.error('OCR failed:', err.message);
    rawText = '';
  } finally { fs.rm(req.file.path, { force: true }, () => {}); }
  res.json({ rawText, fields: parseReceiptText(rawText), note: rawText ? 'OCR completed' : 'OCR did not extract text; enter fields manually.' });
});
function parseReceiptText(text) {
  const lines = String(text || '').split(/\r?\n/).map(x => x.trim()).filter(Boolean);
  const money = (String(text || '').match(/(?:€|EUR)?\s*(\d+[\.,]\d{2})/g) || []).map(v => Number(v.replace(/[^0-9,.]/g, '').replace(',', '.'))).filter(n => !Number.isNaN(n));
  const total = money.length ? Math.max(...money) : 0;
  const dateMatch = String(text || '').match(/(\d{4}-\d{2}-\d{2}|\d{2}[./-]\d{2}[./-]\d{4})/);
  let date = new Date().toISOString().slice(0,10);
  if (dateMatch) {
    const d = dateMatch[1];
    if (/^\d{4}/.test(d)) date = d;
    else { const [dd, mm, yyyy] = d.split(/[./-]/); date = `${yyyy}-${mm.padStart(2,'0')}-${dd.padStart(2,'0')}`; }
  }
  const invMatch = String(text || '').match(/(?:invoice|inv|receipt|bill)\s*[:#-]?\s*([A-Z0-9-]+)/i);
  return { supplier: lines[0] || 'Supplier Name', invNo: invMatch ? invMatch[1] : 'INV-0001', date, payment: /card|visa|mastercard/i.test(text) ? 'Card' : 'Cash', subtotal: 0, vat: 0, total, notes: '' };
}

app.use(express.static(path.join(__dirname, 'public'), { index: false, dotfiles: 'deny' }));
app.use('/api', (req, res) => res.status(404).json({ error: 'API route not found' }));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

initDb().then(() => server.listen(PORT, '0.0.0.0', () => console.log(`RESTO PRO v5 Supabase backend running on port ${PORT}`))).catch(err => {
  console.error('Failed to initialize database:', err);
  process.exit(1);
});
