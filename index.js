import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import nodemailer from 'nodemailer';
import multer from 'multer';
import session from 'express-session';
import bcrypt from 'bcryptjs';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';

// ─── Secrets validation ─────────────────────────────────────────────────────────
const REQUIRED_ENV = [
  'SESSION_SECRET',
  'ADMIN_USERNAME',
  'ADMIN_PASSWORD_HASH',
  'SMTP_HOST',
  'SMTP_PORT',
  'SMTP_USER',
  'SMTP_PASS',
  'MAIL_TO',
];

const missingEnv = REQUIRED_ENV.filter((key) => !process.env[key]);
if (missingEnv.length > 0) {
  console.error(`❌ Chybí povinné proměnné prostředí: ${missingEnv.join(', ')}`);
  process.exit(1);
}

const {
  SESSION_SECRET,
  ADMIN_USERNAME,
  ADMIN_PASSWORD_HASH,
  SMTP_HOST,
  SMTP_PORT,
  SMTP_USER,
  SMTP_PASS,
  MAIL_FROM,
  MAIL_FROM_NAME,
  MAIL_TO,
  PUBLIC_BASE_URL,
  NODE_ENV,
  PORT: ENV_PORT,
} = process.env;

const BASE_URL = (PUBLIC_BASE_URL || '').replace(/\/$/, '');

const SMTP_PORT_NUM = Number(SMTP_PORT);
const SMTP_SECURE = process.env.SMTP_SECURE
  ? process.env.SMTP_SECURE === 'true'
  : SMTP_PORT_NUM === 465;
const FROM_ADDRESS = MAIL_FROM || SMTP_USER;
const FROM_HEADER = MAIL_FROM_NAME
  ? `${MAIL_FROM_NAME} <${FROM_ADDRESS}>`
  : `Web PLOTANA <${FROM_ADDRESS}>`;

// Ověřovací režim anti-spamu: zachycené zprávy se zatím nezahazují, ale posílají
// se na tuto adresu označené důvodem, aby se dalo ověřit, že filtr funguje.
// Až bude filtr ověřený, stačí SPAM_VERIFY_TO vyprázdnit (zachycené se pak tiše zahodí).
const SPAM_VERIFY_TO = process.env.SPAM_VERIFY_TO ?? 'stepan.kraus7@seznam.cz';

const PORT = ENV_PORT || 3000;
const isProduction = NODE_ENV === 'production';

const app = express();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.resolve(__dirname, '..');

// Paths can be overridden via env vars for production deployments where the
// directory layout differs from the local dev tree.
const PUBLIC_HTML_DIR = process.env.PUBLIC_HTML_DIR
  ? path.resolve(process.env.PUBLIC_HTML_DIR)
  : path.join(ROOT_DIR, 'public_html');

const DATA_DIR = process.env.DATA_DIR
  ? path.resolve(process.env.DATA_DIR)
  : path.join(ROOT_DIR, 'data');

const UPLOADS_DIR = process.env.UPLOADS_DIR
  ? path.resolve(process.env.UPLOADS_DIR)
  : path.join(PUBLIC_HTML_DIR, 'images', 'realizace');

const REALIZACE_JSON = path.join(DATA_DIR, 'realizace.json');

// Ensure directories exist
[DATA_DIR, UPLOADS_DIR].forEach((dir) => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

// Seed JSON if it doesn't exist yet
if (!fs.existsSync(REALIZACE_JSON)) {
  fs.writeFileSync(REALIZACE_JSON, '[]', 'utf8');
}

app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));

const corsOptions = {
  origin: [
    'https://klatovskeploty.cz',
    'https://www.klatovskeploty.cz',
    'http://klatovskeploty.cz',
    'http://www.klatovskeploty.cz',
    'https://www.plotana.cz',
    'https://plotana.cz',
    'http://localhost:3000',
    'http://127.0.0.1:5500',
    'http://localhost:5500',
    'http://127.0.0.1:3000',
  ],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  credentials: true,
  optionsSuccessStatus: 200,
};

app.use(cors(corsOptions));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    name: 'plotana.sid',
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    proxy: true,
    cookie: {
      httpOnly: true,
      secure: isProduction,
      sameSite: 'lax',
      maxAge: 1000 * 60 * 60 * 4,
    },
  })
);

// ─── Multer: contact form (images/pdf only) ─────────────────────────────────────
const ALLOWED_MIME_TYPES = ['image/jpeg', 'image/png', 'image/webp', 'image/gif', 'application/pdf'];

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    cb(null, ALLOWED_MIME_TYPES.includes(file.mimetype));
  },
});

// ─── Multer: realizace photo uploads (disk storage, images only) ────────────────
const ALLOWED_IMAGE_TYPES = ['image/jpeg', 'image/png', 'image/webp'];

const uploadRealizace = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, UPLOADS_DIR),
    filename: (_req, file, cb) => {
      const ext = path.extname(file.originalname).toLowerCase();
      const uniqueName = `${Date.now()}-${Math.random().toString(36).slice(2)}${ext}`;
      cb(null, uniqueName);
    },
  }),
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    if (ALLOWED_IMAGE_TYPES.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new multer.MulterError('LIMIT_UNEXPECTED_FILE', file.fieldname));
    }
  },
});

const transporter = nodemailer.createTransport({
  host: SMTP_HOST,
  port: SMTP_PORT_NUM,
  secure: SMTP_SECURE,
  requireTLS: !SMTP_SECURE,
  auth: { user: SMTP_USER, pass: SMTP_PASS },
});

transporter.verify((err) => {
  if (err) console.error('❌ SMTP připojení selhalo:', err.message);
  else console.log(`✉️  SMTP připraveno (${SMTP_HOST}:${SMTP_PORT_NUM})`);
});

// ─── Rate limiters ──────────────────────────────────────────────────────────────
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Příliš mnoho pokusů o přihlášení. Zkus to prosím za 15 minut.' },
});

const emailLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: isProduction ? 5 : 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Příliš mnoho požadavků. Zkus to prosím za hodinu.' },
});

// ─── Helpers ────────────────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (req.session?.adminAuthenticated) return next();
  const acceptsHtml = req.headers.accept?.includes('text/html');
  return acceptsHtml ? res.redirect('/admin/login') : res.status(401).json({ error: 'Nepřihlášený uživatel.' });
}

function escapeHtml(value = '') {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

function looksLikeGibberish(s = '') {
  const t = String(s).replace(/\s/g, '');
  if (t.length < 10) return false;            // krátké texty neřešíme
  if (/\s/.test(String(s).trim())) return false; // má mezery = nech projít
  const vowels = (t.match(/[aeiouyáéíóúůýěAEIOUY]/g) || []).length;
  return vowels / t.length < 0.18;            // skoro žádné samohlásky = balast
}

function readRealizace() {
  return JSON.parse(fs.readFileSync(REALIZACE_JSON, 'utf8'));
}

function writeRealizace(data) {
  fs.writeFileSync(REALIZACE_JSON, JSON.stringify(data, null, 2), 'utf8');
}

function toAbsoluteImageUrl(p) {
  if (!p || typeof p !== 'string') return p;
  if (/^https?:\/\//i.test(p)) return p;
  if (!BASE_URL) return p;
  return `${BASE_URL}${p.startsWith('/') ? '' : '/'}${p}`;
}

function withAbsoluteImages(r) {
  if (!r) return r;
  const out = { ...r };
  if (out.hlavniFoto) out.hlavniFoto = toAbsoluteImageUrl(out.hlavniFoto);
  if (Array.isArray(out.fotky)) {
    out.fotky = out.fotky.map((f) =>
      f && typeof f === 'object' ? { ...f, src: toAbsoluteImageUrl(f.src) } : toAbsoluteImageUrl(f)
    );
  }
  return out;
}

// Servíruje nahrané fotky realizací pod stejnou cestou, jakou má klient v JSON odpovědi.
app.use('/images/realizace', express.static(UPLOADS_DIR, { fallthrough: false }));

// ─── Admin: login page ──────────────────────────────────────────────────────────
app.get('/admin/login', (req, res) => {
  if (req.session?.adminAuthenticated) return res.redirect('/admin');
  res.send(`<!DOCTYPE html>
<html lang="cs">
<head>
  <meta charset="UTF-8" /><meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Admin přihlášení</title>
  <style>
    body { font-family: Arial, sans-serif; background: #f4f4f4; margin: 0; min-height: 100vh; display: grid; place-items: center; }
    .card { background: white; padding: 32px; border-radius: 12px; box-shadow: 0 10px 30px rgba(0,0,0,0.08); width: 100%; max-width: 380px; }
    h1 { margin-top: 0; font-size: 24px; }
    label { display: block; margin: 12px 0 6px; }
    input { width: 100%; padding: 12px; box-sizing: border-box; border: 1px solid #ccc; border-radius: 8px; }
    button { margin-top: 16px; width: 100%; padding: 12px; border: 0; background: #111; color: white; border-radius: 8px; cursor: pointer; }
    .muted { color: #666; font-size: 14px; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Admin přihlášení</h1>
    <p class="muted">Pouze pro správu webu.</p>
    <form method="POST" action="/admin/login">
      <label for="username">Uživatelské jméno</label>
      <input id="username" name="username" autocomplete="username" required />
      <label for="password">Heslo</label>
      <input id="password" name="password" type="password" autocomplete="current-password" required />
      <button type="submit">Přihlásit se</button>
    </form>
  </div>
</body>
</html>`);
});

// ─── Admin: login action ────────────────────────────────────────────────────────
app.post('/admin/login', loginLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).send('Chybí přihlašovací údaje.');

    const usernameMatches = username === ADMIN_USERNAME;
    const passwordMatches = await bcrypt.compare(password, ADMIN_PASSWORD_HASH);

    if (!usernameMatches || !passwordMatches) {
      return res.status(401).send(`<!DOCTYPE html><html lang="cs"><head><meta charset="UTF-8"/>
<style>body{font-family:Arial,sans-serif;background:#f4f4f4;min-height:100vh;display:grid;place-items:center;margin:0}.card{background:white;padding:32px;border-radius:12px;box-shadow:0 10px 30px rgba(0,0,0,0.08);width:100%;max-width:380px}a{color:#111}.error{color:#b00020}</style></head>
<body><div class="card"><h1>Přihlášení selhalo</h1><p class="error">Neplatné jméno nebo heslo.</p><p><a href="/admin/login">Zpět na přihlášení</a></p></div></body></html>`);
    }

    req.session.adminAuthenticated = true;
    req.session.adminUsername = ADMIN_USERNAME;

    return req.session.save((err) => {
      if (err) { console.error('❌ Session error:', err); return res.status(500).send('Nepodařilo se vytvořit session.'); }
      return res.redirect('/admin');
    });
  } catch (error) {
    console.error('❌ Login error:', error);
    return res.status(500).send('Chyba serveru při přihlášení.');
  }
});

// ─── Admin: dashboard ───────────────────────────────────────────────────────────
app.get('/admin', requireAuth, (req, res) => {
  const username = escapeHtml(req.session.adminUsername || 'admin');
  const realizace = readRealizace();

  res.send(`<!DOCTYPE html>
<html lang="cs">
<head>
  <meta charset="UTF-8" /><meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Admin dashboard – PLOTANA</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; }
    body { font-family: Arial, sans-serif; background: #f7f7f7; margin: 0; color: #111; }
    header { background: #111; color: white; padding: 20px 24px; display: flex; align-items: center; justify-content: space-between; }
    header a { color: white; text-decoration: none; margin-right: 16px; font-size: 14px; }
    header a:hover { text-decoration: underline; }
    main { max-width: 1100px; margin: 32px auto; padding: 0 16px; }
    .card { background: white; padding: 24px; border-radius: 12px; box-shadow: 0 8px 24px rgba(0,0,0,0.06); margin-bottom: 20px; }
    h1 { margin-top: 0; }
    h2 { margin-top: 0; }
    .btn { padding: 10px 18px; border: none; border-radius: 8px; background: #111; color: white; cursor: pointer; font-size: 14px; text-decoration: none; display: inline-block; }
    .btn-danger { background: #b00020; }
    .btn-sm { padding: 6px 12px; font-size: 13px; }
    table { width: 100%; border-collapse: collapse; margin-top: 16px; }
    th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid #eee; font-size: 14px; }
    th { background: #f0f0f0; font-weight: 600; }
    tr:hover td { background: #fafafa; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 20px; font-size: 12px; font-weight: 600; }
    .badge-pletivo { background: #e8f5e9; color: #2e7d32; }
    .badge-3d { background: #e3f2fd; color: #1565c0; }
    .badge-kombinace { background: #fff3e0; color: #e65100; }
    .actions { display: flex; gap: 8px; }
  </style>
</head>
<body>
  <header>
    <div>
      <strong>PLOTANA Admin</strong>
      <a href="/admin/realizace/nova" style="margin-left:24px;">+ Nová realizace</a>
    </div>
    <form method="POST" action="/admin/logout">
      <button type="submit" class="btn">Odhlásit se</button>
    </form>
  </header>
  <main>
    <div class="card">
      <h1>Vítej, ${username}</h1>
      <p>Celkem realizací: <strong>${realizace.length}</strong></p>
      <a href="/admin/realizace/nova" class="btn">+ Přidat novou realizaci</a>
    </div>

    <div class="card">
      <h2>Všechny realizace</h2>
      <table>
        <thead>
          <tr>
            <th>Název</th>
            <th>Lokalita</th>
            <th>Rok</th>
            <th>Délka</th>
            <th>Akce</th>
          </tr>
        </thead>
        <tbody>
          ${realizace.map((r) => `
          <tr>
            <td>${escapeHtml(r.nazev)}</td>
            <td>${escapeHtml(r.lokalita)}</td>
            <td>${r.rok || '—'}</td>
            <td>${r.delka ? r.delka + ' m' : '—'}</td>
            <td>
              <div class="actions">
                <a href="/admin/realizace/upravit/${escapeHtml(r.id)}" class="btn btn-sm">Upravit</a>
                <form method="POST" action="/admin/realizace/smazat/${escapeHtml(r.id)}" onsubmit="return confirm('Opravdu smazat?')">
                  <button type="submit" class="btn btn-sm btn-danger">Smazat</button>
                </form>
              </div>
            </td>
          </tr>`).join('')}
        </tbody>
      </table>
    </div>
  </main>
</body>
</html>`);
});

// ─── Admin: session status ──────────────────────────────────────────────────────
app.get('/admin/session', (req, res) => {
  res.json({
    loggedIn: !!req.session?.adminAuthenticated,
    username: req.session?.adminAuthenticated ? req.session.adminUsername : null,
  });
});

// ─── Admin: logout ──────────────────────────────────────────────────────────────
app.post('/admin/logout', requireAuth, (req, res) => {
  req.session.destroy((err) => {
    if (err) { console.error('❌ Logout error:', err); return res.status(500).send('Nepodařilo se odhlásit.'); }
    res.clearCookie('plotana.sid');
    return res.redirect('/admin/login');
  });
});

// ─── Shared form HTML (create + edit) ──────────────────────────────────────────
function realizaceFormHtml({ title, action, r = {}, buttonLabel = 'Uložit' }) {
  // Build existing specifikace as prefilled tabs HTML
  const existingSpec = r.specifikace || [];
  const specHtml = existingSpec.map((spec, si) => `
    <div class="spec-tab" data-tab="${si}">
      <div class="spec-tab-header">
        <input class="spec-tab-name" name="spec_nazev_${si}" placeholder="Název záložky (např. Plotová linie)" value="${escapeHtml(spec.nazev || '')}" required />
        <button type="button" class="btn-remove-tab" onclick="removeTab(this)">✕ Odebrat záložku</button>
      </div>
      <div class="spec-rows">
        ${spec.polozky.map((p, pi) => `
        <div class="spec-row">
          <input name="spec_klic_${si}_${pi}" placeholder="Vlastnost (např. Výška pletiva)" value="${escapeHtml(p.klic || '')}" />
          <input name="spec_hodnota_${si}_${pi}" placeholder="Hodnota (např. 125 cm)" value="${escapeHtml(p.hodnota || '')}" />
          <button type="button" class="btn-remove-row" onclick="removeRow(this)">✕</button>
        </div>`).join('')}
      </div>
      <button type="button" class="btn-add-row" onclick="addRow(this, ${si})">+ Přidat řádek</button>
    </div>`).join('');

  return `<!DOCTYPE html>
<html lang="cs">
<head>
  <meta charset="UTF-8" /><meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>${escapeHtml(title)} – PLOTANA Admin</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; }
    body { font-family: Arial, sans-serif; background: #f7f7f7; margin: 0; color: #111; }
    header { background: #111; color: white; padding: 20px 24px; display: flex; align-items: center; justify-content: space-between; }
    main { max-width: 860px; margin: 32px auto; padding: 0 16px; }
    .card { background: white; padding: 28px; border-radius: 12px; box-shadow: 0 8px 24px rgba(0,0,0,0.06); margin-bottom: 20px; }
    h1 { margin-top: 0; }
    h2 { font-size: 17px; margin: 28px 0 12px; border-bottom: 2px solid #f0f0f0; padding-bottom: 8px; }
    label { display: block; margin: 16px 0 6px; font-weight: 600; font-size: 14px; }
    input[type=text], input[type=number], textarea { width: 100%; padding: 10px 12px; border: 1px solid #ccc; border-radius: 8px; font-size: 14px; font-family: inherit; }
    textarea { min-height: 120px; resize: vertical; }
    .hint { font-size: 12px; color: #666; margin-top: 4px; }
    .btn { padding: 10px 18px; border: none; border-radius: 8px; background: #111; color: white; cursor: pointer; font-size: 14px; }
    .btn-secondary { background: #666; margin-left: 10px; text-decoration: none; display: inline-block; padding: 10px 18px; border-radius: 8px; color: white; font-size: 14px; }
    .btn-outline { background: white; border: 2px solid #111; color: #111; padding: 8px 16px; border-radius: 8px; cursor: pointer; font-size: 14px; margin-top: 12px; }
    .row { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
    @media (max-width: 600px) { .row { grid-template-columns: 1fr; } }

    /* Specifikace builder */
    #specBuilder { margin-top: 8px; }
    .spec-tab { border: 1px solid #e0e0e0; border-radius: 10px; padding: 16px; margin-bottom: 16px; background: #fafafa; }
    .spec-tab-header { display: flex; gap: 10px; align-items: center; margin-bottom: 12px; }
    .spec-tab-header input { flex: 1; }
    .btn-remove-tab { background: #fdecea; color: #b00020; border: 1px solid #f5c6cb; border-radius: 6px; padding: 6px 12px; cursor: pointer; font-size: 13px; white-space: nowrap; }
    .spec-row { display: grid; grid-template-columns: 1fr 1fr auto; gap: 8px; margin-bottom: 8px; align-items: center; }
    .spec-row input { margin: 0; }
    .btn-remove-row { background: #fdecea; color: #b00020; border: 1px solid #f5c6cb; border-radius: 6px; padding: 6px 10px; cursor: pointer; font-size: 13px; }
    .btn-add-row { background: #e8f5e9; color: #2e7d32; border: 1px solid #c8e6c9; border-radius: 6px; padding: 6px 14px; cursor: pointer; font-size: 13px; margin-top: 4px; }
    .btn-add-tab { display: block; width: 100%; padding: 12px; border: 2px dashed #ccc; background: white; border-radius: 10px; cursor: pointer; font-size: 14px; color: #555; margin-top: 4px; }
    .btn-add-tab:hover { border-color: #111; color: #111; }
  </style>
</head>
<body>
  <header>
    <strong>PLOTANA Admin</strong>
    <a href="/admin" style="color:white;text-decoration:none;">← Zpět na dashboard</a>
  </header>
  <main>
    <div class="card">
      <h1>${escapeHtml(title)}</h1>
      <form method="POST" action="${action}" enctype="multipart/form-data" id="mainForm">

        <div class="row">
          <div>
            <label for="nazev">Název realizace *</label>
            <input type="text" id="nazev" name="nazev" required value="${escapeHtml(r.nazev || '')}" placeholder="např. Oplocení zahrady" />
          </div>
          <div>
            <label for="lokalita">Lokalita *</label>
            <input type="text" id="lokalita" name="lokalita" required value="${escapeHtml(r.lokalita || '')}" placeholder="např. Žichovice" />
          </div>
        </div>

        <div class="row">
          <div>
            <label for="rok">Rok realizace</label>
            <input type="number" id="rok" name="rok" min="2000" max="2099" value="${r.rok || new Date().getFullYear()}" />
          </div>
          <div>
            <label for="delka">Délka (m)</label>
            <input type="number" id="delka" name="delka" min="0" value="${r.delka || ''}" placeholder="např. 70" />
          </div>
        </div>

        <div class="row">
          <div>
            <label for="typ">Typ plotu</label>
            <input type="text" id="typ" name="typ" value="${escapeHtml(r.typ || '')}" placeholder="např. Klasické PVC pletivo" />
          </div>
          <div>
            <label for="barva">Barva</label>
            <input type="text" id="barva" name="barva" value="${escapeHtml(r.barva || '')}" placeholder="např. Zelená" />
          </div>
        </div>

        <label for="popisKratky">Krátký popis * <small style="font-weight:400;color:#666">(zobrazí se v galerii na kartičce, 1–2 věty)</small></label>
        <textarea id="popisKratky" name="popisKratky" required style="min-height:70px" placeholder="1–2 věty, max. cca 150 znaků">${escapeHtml(r.popisKratky || '')}</textarea>

        <label for="popisDlouhy">Dlouhý popis <small style="font-weight:400;color:#666">(zobrazí se na detailní stránce — odstavce odděluj prázdným řádkem)</small></label>
        <textarea id="popisDlouhy" name="popisDlouhy" style="min-height:160px" placeholder="Podrobný popis projektu...">${escapeHtml(r.popisDlouhy || '')}</textarea>

        <label>Fotky <small style="font-weight:400;color:#666">(max. 20 × 10 MB, JPEG/PNG/WebP)</small></label>
        <input id="fotky" name="fotky" type="file" accept="image/jpeg,image/png,image/webp" multiple style="padding:8px;background:#f7f7f7;border:1px solid #ccc;border-radius:8px;cursor:pointer;" />
        <p class="hint">První nahraná fotka bude použita jako hlavní náhled v galerii. Fotky se uloží do <code>/images/realizace/</code>.</p>

        <h2>Specifikace (záložky na detailní stránce)</h2>
        <p class="hint" style="margin-bottom:12px">Každá záložka má název (např. "Plotová linie") a řádky s vlastností a hodnotou (např. "Výška pletiva" / "125 cm"). Záložky jsou nepovinné.</p>

        <div id="specBuilder">${specHtml}</div>
        <button type="button" class="btn-add-tab" onclick="addTab()">+ Přidat záložku specifikace</button>

        <!-- Hidden field to carry serialized spec JSON -->
        <input type="hidden" name="specifikace" id="specHidden" />

        <div style="margin-top: 28px;">
          <button type="submit" class="btn" onclick="serializeSpec()">${escapeHtml(buttonLabel)}</button>
          <a href="/admin" class="btn-secondary">Zrušit</a>
        </div>
      </form>
    </div>
  </main>

  <script>
    let tabCount = ${existingSpec.length};

    function addTab() {
      const builder = document.getElementById('specBuilder');
      const idx = tabCount++;
      const div = document.createElement('div');
      div.className = 'spec-tab';
      div.dataset.tab = idx;
      div.innerHTML =
        '<div class="spec-tab-header">' +
          '<input class="spec-tab-name" name="spec_nazev_' + idx + '" placeholder="Název záložky (např. Plotová linie)" required />' +
          '<button type="button" class="btn-remove-tab" onclick="removeTab(this)">✕ Odebrat záložku</button>' +
        '</div>' +
        '<div class="spec-rows"></div>' +
        '<button type="button" class="btn-add-row" onclick="addRow(this, ' + idx + ')">+ Přidat řádek</button>';
      builder.appendChild(div);
      addRow(div.querySelector('.btn-add-row'), idx);
    }

    function addRow(btn, tabIdx) {
      const rowsEl = btn.previousElementSibling;
      const rowIdx = rowsEl.children.length;
      const div = document.createElement('div');
      div.className = 'spec-row';
      div.innerHTML =
        '<input name="spec_klic_' + tabIdx + '_' + rowIdx + '" placeholder="Vlastnost (např. Výška pletiva)" />' +
        '<input name="spec_hodnota_' + tabIdx + '_' + rowIdx + '" placeholder="Hodnota (např. 125 cm)" />' +
        '<button type="button" class="btn-remove-row" onclick="removeRow(this)">✕</button>';
      rowsEl.appendChild(div);
    }

    function removeTab(btn) {
      btn.closest('.spec-tab').remove();
    }

    function removeRow(btn) {
      btn.closest('.spec-row').remove();
    }

    function serializeSpec() {
      const tabs = document.querySelectorAll('#specBuilder .spec-tab');
      const spec = [];
      tabs.forEach(tab => {
        const nazev = tab.querySelector('.spec-tab-name').value.trim();
        if (!nazev) return;
        const rows = tab.querySelectorAll('.spec-row');
        const polozky = [];
        rows.forEach(row => {
          const inputs = row.querySelectorAll('input');
          const klic = inputs[0].value.trim();
          const hodnota = inputs[1].value.trim();
          if (klic && hodnota) polozky.push({ klic, hodnota });
        });
        spec.push({ nazev, polozky });
      });
      document.getElementById('specHidden').value = JSON.stringify(spec);
    }

    // Also serialize on any submit
    document.getElementById('mainForm').addEventListener('submit', serializeSpec);
  </script>
</body>
</html>`;
}

// ─── Admin: nová realizace – formulář ──────────────────────────────────────────
app.get('/admin/realizace/nova', requireAuth, (_req, res) => {
  res.send(realizaceFormHtml({
    title: 'Nová realizace',
    action: '/admin/realizace/nova',
    buttonLabel: 'Vytvořit realizaci',
  }));
});

// ─── Admin: nová realizace – uložení ───────────────────────────────────────────
app.post('/admin/realizace/nova', requireAuth, uploadRealizace.array('fotky', 20), (req, res) => {
  try {
    const { nazev, lokalita, rok, delka, typ, barva, popisKratky, popisDlouhy, specifikace } = req.body;

    if (!nazev?.trim() || !lokalita?.trim() || !popisKratky?.trim()) {
      return res.status(400).send('Chybí povinné pole (název, lokalita nebo krátký popis).');
    }

    // Parse specifikace JSON (serialized by frontend JS)
    let spec = [];
    try {
      spec = JSON.parse(specifikace || '[]');
    } catch {
      return res.status(400).send('Chyba při zpracování specifikací.');
    }

    // Build ID from year + slugified location
    const slug = lokalita.trim().toLowerCase()
      .normalize('NFD').replace(/[\u0300-\u036f]/g, '')  // remove diacritics
      .replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
    const year = rok || new Date().getFullYear();
    const id = `${year}-${slug}`;

    const realizace = readRealizace();

    if (realizace.find((r) => r.id === id)) {
      return res.status(400).send(`Realizace s ID "${id}" již existuje. Zkus jiný název lokality nebo rok.`);
    }

    // Build fotky array from uploaded files
    const fotky = (req.files || []).map((f, i) => ({
      src: `/images/realizace/${f.filename}`,
      alt: i === 0 ? `${nazev} – hlavní pohled` : `${nazev} – detail ${i}`,
    }));

    const nova = {
      id,
      nazev: nazev.trim(),
      lokalita: lokalita.trim(),
      rok: parseInt(rok) || new Date().getFullYear(),
      popisKratky: popisKratky.trim(),
      popisDlouhy: popisDlouhy?.trim() || '',
      delka: delka ? parseInt(delka) : null,
      typ: typ?.trim() || null,
      barva: barva?.trim() || null,
      hlavniFoto: fotky[0]?.src || null,
      fotky,
      specifikace: spec,
    };

    realizace.unshift(nova);  // newest first
    writeRealizace(realizace);

    console.log(`✅ Nová realizace přidána: ${id}`);
    return res.redirect('/admin');
  } catch (err) {
    console.error('❌ Chyba při vytváření realizace:', err);
    return res.status(500).send('Chyba serveru při ukládání realizace.');
  }
});

// ─── Admin: upravit realizaci – formulář ───────────────────────────────────────
app.get('/admin/realizace/upravit/:id', requireAuth, (req, res) => {
  const realizace = readRealizace();
  const r = realizace.find((x) => x.id === req.params.id);
  if (!r) return res.status(404).send('Realizace nenalezena.');

  res.send(realizaceFormHtml({
    title: `Upravit: ${r.nazev}`,
    action: `/admin/realizace/upravit/${r.id}`,
    r,
    buttonLabel: 'Uložit změny',
  }));
});

// ─── Admin: upravit realizaci – uložení ────────────────────────────────────────
app.post('/admin/realizace/upravit/:id', requireAuth, uploadRealizace.array('fotky', 20), (req, res) => {
  try {
    const realizace = readRealizace();
    const idx = realizace.findIndex((x) => x.id === req.params.id);
    if (idx === -1) return res.status(404).send('Realizace nenalezena.');

    const { nazev, lokalita, rok, delka, typ, barva, popisKratky, popisDlouhy, specifikace } = req.body;

    let spec = realizace[idx].specifikace;
    try {
      spec = JSON.parse(specifikace || '[]');
    } catch {
      return res.status(400).send('Chyba při zpracování specifikací.');
    }

    // If new photos uploaded, append them; otherwise keep existing
    const noveFotky = (req.files || []).map((f, i) => ({
      src: `/images/realizace/${f.filename}`,
      alt: `${nazev || realizace[idx].nazev} – foto ${i + 1}`,
    }));

    const fotky = noveFotky.length > 0
      ? [...(realizace[idx].fotky || []), ...noveFotky]
      : realizace[idx].fotky;

    realizace[idx] = {
      ...realizace[idx],
      nazev: nazev?.trim() || realizace[idx].nazev,
      lokalita: lokalita?.trim() || realizace[idx].lokalita,
      rok: rok ? parseInt(rok) : realizace[idx].rok,
      delka: delka ? parseInt(delka) : realizace[idx].delka,
      typ: typ?.trim() || realizace[idx].typ,
      barva: barva?.trim() || realizace[idx].barva,
      popisKratky: popisKratky?.trim() || realizace[idx].popisKratky,
      popisDlouhy: popisDlouhy?.trim() ?? realizace[idx].popisDlouhy,
      hlavniFoto: fotky[0]?.src || realizace[idx].hlavniFoto,
      fotky,
      specifikace: spec,
    };

    writeRealizace(realizace);
    console.log(`✅ Realizace upravena: ${req.params.id}`);
    return res.redirect('/admin');
  } catch (err) {
    console.error('❌ Chyba při úpravě realizace:', err);
    return res.status(500).send('Chyba serveru při ukládání změn.');
  }
});

// ─── Admin: smazat realizaci ────────────────────────────────────────────────────
app.post('/admin/realizace/smazat/:id', requireAuth, (req, res) => {
  try {
    const realizace = readRealizace();
    const idx = realizace.findIndex((x) => x.id === req.params.id);
    if (idx === -1) return res.status(404).send('Realizace nenalezena.');

    const [removed] = realizace.splice(idx, 1);
    writeRealizace(realizace);

    console.log(`🗑️ Realizace smazána: ${removed.id}`);
    return res.redirect('/admin');
  } catch (err) {
    console.error('❌ Chyba při mazání:', err);
    return res.status(500).send('Chyba serveru při mazání.');
  }
});

// ─── Public API: všechny realizace ─────────────────────────────────────────────
app.get('/api/realizace', (_req, res) => {
  try {
    const realizace = readRealizace();
    const summary = realizace.map(({ id, nazev, lokalita, rok, kategorie, popisKratky, popisDlouhy, delka, typ, barva, hlavniFoto }) =>
      withAbsoluteImages({ id, nazev, lokalita, rok, kategorie, popisKratky, popisDlouhy, delka, typ, barva, hlavniFoto })
    );
    res.json(summary);
  } catch {
    res.status(500).json({ error: 'Chyba při načítání realizací.' });
  }
});

// ─── Public API: jedna realizace ───────────────────────────────────────────────
app.get('/api/realizace/:id', (req, res) => {
  try {
    const realizace = readRealizace();
    const r = realizace.find((x) => x.id === req.params.id);
    if (!r) return res.status(404).json({ error: 'Realizace nenalezena.' });
    res.json(withAbsoluteImages(r));
  } catch {
    res.status(500).json({ error: 'Chyba při načítání realizace.' });
  }
});

// ─── Admin: example API ─────────────────────────────────────────────────────────
app.get('/admin/api/me', requireAuth, (req, res) => {
  res.json({ success: true, user: req.session.adminUsername });
});

// ─── Contact form ───────────────────────────────────────────────────────────────
app.post('/api/send-email', emailLimiter, upload.array('fotky', 5), async (req, res) => {
  const { name, phone, email, message, adress, interests, website, formElapsedMs } = req.body;
  const files = req.files;

  // ── Anti-spam: detekce + ověřovací režim ───────────────────────────────────
  // Zachytáváme: honeypot, příliš rychlé odeslání a balastní text.
  // Místo tichého zahození zatím zachycenou zprávu OZNAČÍME a pošleme na
  // ověřovací adresu (SPAM_VERIFY_TO), aby šlo ověřit, že filtr funguje správně.
  let spamReason = null;

  // 1) Honeypot – pole „website" je pro člověka neviditelné (mimo obrazovku),
  //    takže ho vyplní jen bot.
  if (website) {
    spamReason = 'honeypot (vyplněné skryté pole „website")';
  } else {
    // 2) Časová značka – formulář odeslaný pod 3 sekundy je téměř jistě bot.
    const elapsed = Number(formElapsedMs);
    if (!Number.isFinite(elapsed) || elapsed < 3000) {
      spamReason = `příliš rychlé odeslání (${formElapsedMs ?? 'chybí'} ms, limit 3000 ms)`;
    } else if (looksLikeGibberish(name) || looksLikeGibberish(message)) {
      // 3) Balastní jméno / zpráva – náhodné řetězce bez samohlásek a bez mezer.
      spamReason = 'balastní text (jméno nebo zpráva bez samohlásek)';
    }
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

  // Validace polí provádíme jen u skutečných poptávek – u spamu může být cokoli.
  if (!spamReason) {
    if (email && !emailRegex.test(email)) return res.status(400).json({ error: 'Neplatná e-mailová adresa.' });
    if (!name || String(name).trim().length < 2) return res.status(400).json({ error: 'Jméno je povinné.' });
  }

  // Zachycený spam bez ověřovací adresy se tiše zahodí (bot dostane „úspěch").
  if (spamReason && !SPAM_VERIFY_TO) {
    console.log(`🤖 Spam zachycen (${spamReason}) – zahozeno.`);
    return res.status(200).json({ success: true, message: 'E-mail odeslán!' });
  }

  try {
    const v = {
      name: escapeHtml(name) || 'Neuvedeno',
      phone: escapeHtml(phone) || 'Neuveden',
      email: escapeHtml(email) || 'Neuveden',
      interests: escapeHtml(interests) || 'Nevybráno',
      message: escapeHtml(message) || 'Uživatel nezanechal žádnou doplňující zprávu',
      adresa: escapeHtml(adress) || 'Nebylo vybráno z mapy',
    };

    const spamBanner = spamReason
      ? `<div style="background:#fdecea;border:1px solid #f5c6cb;color:#b00020;padding:12px;border-radius:6px;margin-bottom:16px;font-weight:bold;">
           ⚠️ ZACHYCENO ANTI-SPAM FILTREM<br>
           <span style="font-weight:normal;">Důvod: ${escapeHtml(spamReason)}</span><br>
           <span style="font-weight:normal;font-size:12px;">Tato zpráva by za normálního provozu nebyla doručena. Slouží k ověření filtru.</span>
         </div>`
      : '';

    const html = `
      <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;color:#222;">
        ${spamBanner}
        <h2 style="color:#2c5f2d;border-bottom:2px solid #2c5f2d;padding-bottom:8px;">
          ${spamReason ? '[SPAM] ' : ''}Nová poptávka z webu PLOTANA
        </h2>
        <table style="width:100%;border-collapse:collapse;margin-top:16px;">
          <tr><td style="padding:6px 0;font-weight:bold;width:130px;">Jméno:</td><td>${v.name}</td></tr>
          <tr><td style="padding:6px 0;font-weight:bold;">Telefon:</td><td>${v.phone}</td></tr>
          <tr><td style="padding:6px 0;font-weight:bold;">E-mail:</td><td>${v.email}</td></tr>
          <tr><td style="padding:6px 0;font-weight:bold;">Adresa:</td><td>${v.adresa}</td></tr>
          <tr><td style="padding:6px 0;font-weight:bold;vertical-align:top;">Zájem o:</td><td>${v.interests}</td></tr>
        </table>
        <h3 style="margin-top:20px;color:#2c5f2d;">Zpráva</h3>
        <p style="white-space:pre-wrap;background:#f5f5f5;padding:12px;border-radius:4px;">${v.message}</p>
      </div>
    `;

    const text = [
      spamReason ? `⚠️ ZACHYCENO ANTI-SPAM FILTREM – důvod: ${spamReason}` : null,
      spamReason ? 'Tato zpráva by za normálního provozu nebyla doručena (ověření filtru).' : null,
      spamReason ? '' : null,
      'Nová poptávka z webu PLOTANA',
      '',
      `Jméno:   ${v.name}`,
      `Telefon: ${v.phone}`,
      `E-mail:  ${v.email}`,
      `Adresa:  ${v.adresa}`,
      `Zájem o: ${v.interests}`,
      '',
      'Zpráva:',
      v.message,
    ].filter((line) => line !== null).join('\n');

    const mailOptions = {
      from: FROM_HEADER,
      // Zachycený spam jde na ověřovací adresu, skutečná poptávka na MAIL_TO.
      to: spamReason ? SPAM_VERIFY_TO : MAIL_TO,
      subject: spamReason
        ? `[SPAM ZACHYCEN] ${escapeHtml(name) || 'Neznámý'}`
        : `Nová poptávka: ${escapeHtml(name) || 'Neznámý'}`,
      html,
      text,
      // U spamu nenastavujeme replyTo (mohl by být podvržený), jen u reálné poptávky.
      replyTo: !spamReason && email && emailRegex.test(email) ? email : undefined,
    };

    if (files?.length > 0) {
      mailOptions.attachments = files.map((f) => ({
        filename: f.originalname,
        content: f.buffer,
        contentType: f.mimetype,
      }));
    }

    const info = await transporter.sendMail(mailOptions);
    if (spamReason) {
      console.log(`🤖 Spam zachycen (${spamReason}) – přeposláno na ${SPAM_VERIFY_TO}:`, info.messageId);
    } else {
      console.log('✅ E-mail odeslán:', info.messageId);
    }
    return res.status(200).json({ success: true, message: 'E-mail odeslán!' });
  } catch (error) {
    console.error('❌ SMTP error:', error);
    return res.status(500).json({ error: 'Chyba při odesílání e-mailu.' });
  }
});

// ─── Static files ───────────────────────────────────────────────────────────────
app.use(express.static(PUBLIC_HTML_DIR));

// ─── Error handler ──────────────────────────────────────────────────────────────
app.use((err, req, res, _next) => {
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') return res.status(400).json({ error: 'Soubor je příliš velký. Maximum je 10 MB.' });
    if (err.code === 'LIMIT_UNEXPECTED_FILE') return res.status(400).json({ error: 'Nepodporovaný typ souboru.' });
  }
  console.error('❌ Nezachycená chyba:', err);
  return res.status(500).json({ error: 'Něco se pokazilo na serveru.' });
});

// ─── Start ──────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`🚀 Server běží na http://localhost:${PORT}`);
});