import express, { Request, Response, NextFunction } from 'express';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { DatabaseSync } from 'node:sqlite';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const isProd = process.env.NODE_ENV === 'production';
const PORT = Number(process.env.PORT) || 3000;

// Initialize SQLite database
const dataDir = process.env.VERCEL ? '/tmp/data' : path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}
const dbPath = path.join(dataDir, 'toca.db');
const db = new DatabaseSync(dbPath);

// Execute schema
db.exec(`
  CREATE TABLE IF NOT EXISTS kv(k TEXT PRIMARY KEY, v TEXT);
  CREATE TABLE IF NOT EXISTS ev(id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, t TEXT, l TEXT, city TEXT, dev TEXT);
  CREATE INDEX IF NOT EXISTS ev_ts ON ev(ts);
`);

// KV Storage helpers
function kget(k: string): string | null {
  const row = db.prepare('SELECT v FROM kv WHERE k = ?').get(k) as { v: string } | undefined;
  return row ? row.v : null;
}

function kset(k: string, v: string): void {
  db.prepare('INSERT INTO kv(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v').run(k, v);
}

// Crypto & Security helpers (compatible with Cloudflare Web Crypto)
const enc = new TextEncoder();
const b64 = (b: ArrayBuffer | Uint8Array) => Buffer.from(b instanceof Uint8Array ? b : new Uint8Array(b)).toString('base64');
const ub64 = (s: string) => new Uint8Array(Buffer.from(s, 'base64'));

async function hash(pw: string, salt: Uint8Array): Promise<string> {
  const k = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: salt as any, iterations: 100000 }, k, 256);
  return b64(bits);
}

async function sign(sec: string, msg: string): Promise<string> {
  const k = await crypto.subtle.importKey('raw', enc.encode(sec), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', k, enc.encode(msg));
  return b64(sig);
}

async function sess(res: Response) {
  const sec = kget('secret') || '';
  const exp = Date.now() + 6048e5; // 7 days
  const signature = await sign(sec, String(exp));
  const sidValue = encodeURIComponent(exp + '.' + signature);
  // SameSite=None; Secure; Partitioned allows cookies in AI Studio preview iframes and regular browsers
  res.setHeader(
    'Set-Cookie',
    `sid=${sidValue}; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=604800; Partitioned`
  );
  return res.status(200).json({ ok: 1 });
}

async function authed(req: Request): Promise<boolean> {
  const cookieHeader = req.headers.cookie || '';
  const m = cookieHeader.match(/sid=([^;]+)/);
  if (!m) return false;
  const [exp, sig] = decodeURIComponent(m[1]).split('.');
  if (!exp || Number(exp) < Date.now()) return false;
  const sec = kget('secret');
  if (!sec) return false;
  const expectedSig = await sign(sec, exp);
  return sig === expectedSig;
}

const KEYS = ['h1a', 'h1b', 'sub', 'cta', 'l40', 'l100', 'phone', 'waMsg', 'scText', 'ends'];
const D = 864e5; // 1 day in ms
const TZ = 108e5; // 3 hours in ms (UTC-3 Brazil)

const app = express();

// Parse body (JSON and text/beacon)
app.use(express.json({ limit: '1mb' }));
app.use(express.text({ type: '*/*' }));
app.use((req, res, next) => {
  if (typeof req.body === 'string' && req.body.trim().startsWith('{')) {
    try {
      req.body = JSON.parse(req.body);
    } catch {}
  }
  next();
});

// API Routes
app.get('/api/config', (_req: Request, res: Response) => {
  const c = kget('cfg');
  res.setHeader('Cache-Control', 'no-store');
  return res.json(c ? JSON.parse(c) : {});
});

app.post('/api/track', (req: Request, res: Response) => {
  const b = req.body || {};
  const ua = req.headers['user-agent'] || '';
  const city = (req.headers['cf-ipcity'] || req.headers['x-appengine-city'] || req.headers['x-client-city'] || b.city || '').toString().slice(0, 40);
  const dev = /mobile/i.test(ua) ? 'm' : 'd';
  const eventType = b.t === 'click' ? 'click' : 'view';
  const label = String(b.l || '').slice(0, 40);
  db.prepare('INSERT INTO ev(ts,t,l,city,dev) VALUES(?,?,?,?,?)').run(Date.now(), eventType, label, city, dev);
  return res.json({ ok: 1 });
});

app.get('/api/status', (_req: Request, res: Response) => {
  res.setHeader('Cache-Control', 'no-store');
  return res.json({
    setup: !kget('pw'),
    code: Boolean(process.env.SETUP_CODE)
  });
});

app.post('/api/setup', async (req: Request, res: Response) => {
  if (kget('pw')) {
    return res.status(403).json({ error: 'Já configurado.' });
  }
  const b = req.body || {};
  if (process.env.SETUP_CODE && b.code !== process.env.SETUP_CODE) {
    return res.status(403).json({ error: 'Código de ativação incorreto.' });
  }
  if (!b.password || b.password.length < 10) {
    return res.status(400).json({ error: 'A senha precisa ter pelo menos 10 caracteres.' });
  }
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hashedPw = await hash(b.password, salt);
  kset('pw', b64(salt) + '.' + hashedPw);
  kset('secret', b64(crypto.getRandomValues(new Uint8Array(32))));
  return sess(res);
});

app.post('/api/login', async (req: Request, res: Response) => {
  const rawFails = kget('fails') || '{"n":0,"t":0}';
  let f = { n: 0, t: 0 };
  try {
    f = JSON.parse(rawFails);
  } catch {}
  if (f.n >= 5 && Date.now() - f.t < 6e4) {
    return res.status(429).json({ error: 'Muitas tentativas. Espere 1 minuto.' });
  }
  const b = req.body || {};
  const sv = kget('pw');
  if (!sv || !b.password) {
    return res.status(401).json({ error: 'Senha incorreta.' });
  }
  const [s, h] = sv.split('.');
  const pwHash = await hash(b.password, ub64(s));
  if (pwHash !== h) {
    kset('fails', JSON.stringify({ n: f.n + 1, t: Date.now() }));
    return res.status(401).json({ error: 'Senha incorreta.' });
  }
  kset('fails', '{"n":0,"t":0}');
  return sess(res);
});

// Guard for protected admin API endpoints
async function requireAuth(req: Request, res: Response, next: NextFunction) {
  if (await authed(req)) return next();
  return res.status(401).json({ error: 'Não autorizado.' });
}

app.all('/api/logout', (_req: Request, res: Response) => {
  res.setHeader(
    'Set-Cookie',
    'sid=; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=0; Partitioned'
  );
  return res.json({ ok: 1 });
});

app.get('/api/stats', requireAuth, (_req: Request, res: Response) => {
  const now = Date.now();
  const t0 = Math.floor((now - TZ) / D) * D + TZ;
  const d13 = t0 - 13 * D;
  const tot = (db.prepare(
    "SELECT COALESCE(SUM(ts>=?),0) a, COALESCE(SUM(ts>=?),0) b, COUNT(*) c FROM ev WHERE t='view' AND ts>=?"
  ).get(t0, t0 - 6 * D, now - 30 * D) as any) || { a: 0, b: 0, c: 0 };

  const dr = (db.prepare(
    "SELECT CAST((ts-?)/86400000 AS INTEGER) i, COUNT(*) n FROM ev WHERE t='view' AND ts>=? GROUP BY i"
  ).all(d13, d13) as any[]) || [];

  const mp: Record<number, number> = {};
  for (const r of dr) mp[r.i] = r.n;

  const days = [];
  for (let i = 0; i < 14; i++) {
    days.push({
      d: new Date(d13 + i * D - TZ).toISOString().slice(5, 10).split('-').reverse().join('/'),
      n: mp[i] || 0,
    });
  }

  const q = (s: string) => (db.prepare(s).all(now - 30 * D) as any[]) || [];
  const clicks = q("SELECT l, COUNT(*) n FROM ev WHERE t='click' AND ts>=? GROUP BY l ORDER BY n DESC");
  const cities = q("SELECT COALESCE(NULLIF(city,''),'Não identificada') l, COUNT(*) n FROM ev WHERE t='view' AND ts>=? GROUP BY l ORDER BY n DESC LIMIT 8");
  const devices = q("SELECT dev l, COUNT(*) n FROM ev WHERE t='view' AND ts>=? GROUP BY dev");

  res.setHeader('Cache-Control', 'no-store');
  return res.json({
    today: tot.a,
    week: tot.b,
    month: tot.c,
    days,
    clicks,
    cities,
    devices,
  });
});

app.put('/api/config', requireAuth, (req: Request, res: Response) => {
  const b = req.body || {};
  const c: Record<string, any> = {};
  for (const k of KEYS) {
    if (typeof b[k] === 'string' && b[k].trim()) {
      c[k] = b[k].trim().slice(0, 400);
    }
  }
  for (const k of ['l40', 'l100']) {
    if (c[k] && !/^https:\/\//.test(c[k])) {
      return res.status(400).json({ error: 'Links precisam começar com https://' });
    }
  }
  c.scOn = Boolean(b.scOn);
  c.scLeft = Math.max(0, parseInt(b.scLeft) || 0);
  kset('cfg', JSON.stringify(c));
  return res.json({ ok: 1 });
});

// SEO & Meta endpoints
app.get('/robots.txt', (req: Request, res: Response) => {
  const host = req.get('host') || 'localhost:3000';
  const proto = req.secure || req.headers['x-forwarded-proto'] === 'https' ? 'https' : 'http';
  const origin = `${proto}://${host}`;
  res.type('text/plain; charset=utf-8').send(
    `User-agent: *\nAllow: /\nDisallow: /painel\nDisallow: /api/\nSitemap: ${origin}/sitemap.xml\n`
  );
});

app.get('/sitemap.xml', (req: Request, res: Response) => {
  const host = req.get('host') || 'localhost:3000';
  const proto = req.secure || req.headers['x-forwarded-proto'] === 'https' ? 'https' : 'http';
  const origin = `${proto}://${host}`;
  const today = new Date().toISOString().slice(0, 10);
  res.type('application/xml; charset=utf-8').send(
    `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>${origin}/</loc><lastmod>${today}</lastmod><priority>1.0</priority></url></urlset>`
  );
});

app.get('/llms.txt', (_req: Request, res: Response) => {
  const filePath = path.join(__dirname, 'llms.txt');
  if (fs.existsSync(filePath)) {
    return res.sendFile(filePath);
  }
  return res.status(404).send('Not found');
});

// Admin Panel route (/painel and /painel/)
app.get(['/painel', '/painel/'], (_req: Request, res: Response) => {
  const painelPath = isProd
    ? path.join(__dirname, 'dist', 'painel', 'index.html')
    : path.join(__dirname, 'painel', 'index.html');
  if (fs.existsSync(painelPath)) {
    return res.sendFile(painelPath);
  }
  return res.sendFile(path.join(__dirname, 'painel', 'index.html'));
});

// Static / Frontend serving
if (!isProd) {
  // Vite dev server in middleware mode
  const { createServer: createViteServer } = await import('vite');
  const vite = await createViteServer({
    server: { middlewareMode: true },
    appType: 'custom',
  });
  app.use(vite.middlewares);

  app.get('*', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const url = req.originalUrl;
      if (url.startsWith('/painel')) {
        let template = fs.readFileSync(path.join(__dirname, 'painel', 'index.html'), 'utf-8');
        template = await vite.transformIndexHtml(url, template);
        return res.status(200).set({ 'Content-Type': 'text/html' }).end(template);
      }
      let template = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf-8');
      template = await vite.transformIndexHtml(url, template);
      return res.status(200).set({ 'Content-Type': 'text/html' }).end(template);
    } catch (e: any) {
      vite.ssrFixStacktrace(e);
      next(e);
    }
  });
} else {
  // Production static server
  app.use(express.static(path.join(__dirname, 'dist')));
  app.get('*', (req: Request, res: Response) => {
    if (req.originalUrl.startsWith('/painel')) {
      return res.sendFile(path.join(__dirname, 'dist', 'painel', 'index.html'));
    }
    return res.sendFile(path.join(__dirname, 'dist', 'index.html'));
  });
}

export default app;

if (!process.env.VERCEL) {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running at http://0.0.0.0:${PORT}`);
  });
}
