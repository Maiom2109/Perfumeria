'use strict';

const crypto = require('crypto');
const fs = require('fs/promises');
const path = require('path');
const express = require('express');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const { z } = require('zod');

/* ===================== Configuración ===================== */
const PORT = process.env.PORT || 3000;
const GITHUB_TOKEN = process.env.GITHUB_TOKEN || '';
const GITHUB_OWNER = process.env.GITHUB_OWNER || 'Maiom2109';
const GITHUB_REPO = process.env.GITHUB_REPO || 'Perfumeria';
const GITHUB_BRANCH = process.env.GITHUB_BRANCH || 'data';
const FILE_PATH = 'data.json';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const SESSION_SECRET = process.env.SESSION_SECRET || '';
const ADMIN_ENABLED = ADMIN_PASSWORD.length >= 10 && SESSION_SECRET.length >= 32;

const PUBLIC_DIR = path.join(__dirname, 'public');
const COOKIE_NAME = 'arenas_session';
const SESSION_MS = 12 * 60 * 60 * 1000;
const CACHE_MS = 60 * 1000;
const CDN = ['https://cdn.tailwindcss.com', 'https://unpkg.com', 'https://cdnjs.cloudflare.com'];

const DEFAULT_SETTINGS = {
  brandTitle: 'ARENAS',
  brandSubtitle: 'Perfumes Árabes & Decants',
  splashSubtitle: 'perfumería árabe',
  brandLogoImg: '',
  heroTitle: 'Perfumes árabes originales y decants en Lima',
  heroSubtitle: 'Fragancias originales con garantía, decants de 5, 10 y 15 ml. Pago por Yape o Plin y envíos seguros.',
  heroCtaText: 'Ver colección',
  brandTabs: 'Lattafa, Rasasi, Afnan, Armaf, Al Haramain',
  shippingText: 'Delivery en Lima S/ 12.00',
  yapeNumber: '',
  yapeQrImg: '',
  whatsapp: '',
  limaShippingEnabled: true,
  limaShippingCost: 12,
  limaPaymentMode: 'prepaid',
  provinceShippingEnabled: true,
  provinceShippingText: 'Envío a provincia (pago en destino al recibir)',
  reservationEnabled: true,
  reservationPerItem: 20,
  faq1Q: '¿Los perfumes árabes son 100% originales?',
  faq1A: 'Sí, trabajamos exclusivamente con perfumes árabes originales de marcas reconocidas como Lattafa, Rasasi, Afnan, Armaf y Al Haramain con garantía.',
  faq2Q: '¿Cómo se realizan los pagos?',
  faq2A: 'Aceptamos pagos rápidos y seguros mediante Yape y Plin directo al número oficial de la tienda o escaneando nuestro QR.',
  faq3Q: '¿Cómo funcionan los envíos a Lima y Provincia?',
  faq3A: 'Realizamos entregas en Lima y envíos a todo el Perú por agencia (Shalom / Olva) con pago en destino.',
  faq4Q: '¿Puedo separar un perfume con adelanto?',
  faq4A: 'Sí, puedes separar cada perfume con el monto indicado en la boleta y cancelar la diferencia al momento de la entrega o antes del despacho.',
};

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

/* ===================== Almacén temporal de comprobantes ===================== */
const PROOFS = new Map();
const PROOF_TTL_MS = 48 * 60 * 60 * 1000;
const MAX_PROOFS = 300;

function cleanupProofs() {
  const now = Date.now();
  for (const [k, v] of PROOFS.entries()) {
    if (v.exp <= now) PROOFS.delete(k);
  }
  while (PROOFS.size > MAX_PROOFS) {
    const oldest = PROOFS.keys().next().value;
    PROOFS.delete(oldest);
  }
}

/* ===================== Validación (zod) ===================== */
z.setErrorMap((issue, ctx) => {
  switch (issue.code) {
    case 'invalid_type':
      if (issue.expected === 'integer') return { message: 'debe ser un número entero' };
      if (issue.received === 'undefined' || issue.received === 'null') return { message: 'es obligatorio' };
      return { message: 'tiene un tipo de dato inválido' };
    case 'invalid_union':
      return { message: 'tiene un valor inválido' };
    case 'too_small':
      if (issue.type === 'string') {
        return { message: issue.minimum <= 1 ? 'no puede estar vacío' : `debe tener al menos ${issue.minimum} caracteres` };
      }
      return { message: `no puede ser menor que ${issue.minimum}` };
    case 'too_big':
      if (issue.type === 'string') return { message: `no puede superar ${issue.maximum} caracteres` };
      if (issue.type === 'array') return { message: `no puede tener más de ${issue.maximum} elementos` };
      return { message: `no puede ser mayor que ${issue.maximum}` };
    default:
      return { message: ctx.defaultError };
  }
});

const perfumeImageField = z
  .string()
  .trim()
  .min(1, 'es obligatoria')
  .max(250000)
  .refine((v) => {
    if (/^data:image\/(png|jpeg|jpg|webp);base64,[A-Za-z0-9+/=]+$/.test(v)) return true;
    try {
      return v.length <= 500 && new URL(v).protocol === 'https:';
    } catch (e) {
      return false;
    }
  }, 'debe ser una foto válida o una URL https://');

const imageDataOrUrlField = z
  .string()
  .trim()
  .max(250000)
  .default('')
  .refine((v) => {
    if (!v) return true;
    if (/^data:image\/(png|jpeg|jpg|webp|svg\+xml);base64,[A-Za-z0-9+/=]+$/.test(v)) return true;
    try {
      return v.length <= 500 && new URL(v).protocol === 'https:';
    } catch (e) {
      return false;
    }
  }, 'debe ser una imagen válida o una URL https://');

const settingsSchema = z.object({
  brandTitle: z.string().trim().min(1).max(40),
  brandSubtitle: z.string().trim().min(1).max(60),
  splashSubtitle: z.string().trim().min(1).max(50).default(DEFAULT_SETTINGS.splashSubtitle),
  brandLogoImg: imageDataOrUrlField,
  heroTitle: z.string().trim().min(1).max(90).default(DEFAULT_SETTINGS.heroTitle),
  heroSubtitle: z.string().trim().min(1).max(180).default(DEFAULT_SETTINGS.heroSubtitle),
  heroCtaText: z.string().trim().min(1).max(30).default(DEFAULT_SETTINGS.heroCtaText),
  brandTabs: z.string().trim().max(250).default(DEFAULT_SETTINGS.brandTabs),
  shippingText: z.string().trim().min(1).max(80),
  yapeNumber: z.string().trim().regex(/^9\d{8}$/, 'debe tener 9 dígitos y empezar con 9'),
  yapeQrImg: imageDataOrUrlField,
  whatsapp: z.string().trim().regex(/^51\d{9}$/, 'debe ser 51 + 9 dígitos (solo números)'),
  limaShippingEnabled: z.boolean().default(true),
  limaShippingCost: z.number().int().min(0).max(200).default(12),
  limaPaymentMode: z.enum(['prepaid', 'cod']).default('prepaid'),
  provinceShippingEnabled: z.boolean().default(true),
  provinceShippingText: z.string().trim().min(1).max(100).default(DEFAULT_SETTINGS.provinceShippingText),
  reservationEnabled: z.boolean().default(true),
  reservationPerItem: z.number().int().min(1).max(500).default(20),
  faq1Q: z.string().trim().max(120).default(DEFAULT_SETTINGS.faq1Q),
  faq1A: z.string().trim().max(400).default(DEFAULT_SETTINGS.faq1A),
  faq2Q: z.string().trim().max(120).default(DEFAULT_SETTINGS.faq2Q),
  faq2A: z.string().trim().max(400).default(DEFAULT_SETTINGS.faq2A),
  faq3Q: z.string().trim().max(120).default(DEFAULT_SETTINGS.faq3Q),
  faq3A: z.string().trim().max(400).default(DEFAULT_SETTINGS.faq3A),
  faq4Q: z.string().trim().max(120).default(DEFAULT_SETTINGS.faq4Q),
  faq4A: z.string().trim().max(400).default(DEFAULT_SETTINGS.faq4A),
});

const perfumeSchema = z.object({
  id: z.union([z.number().int().min(0), z.string().trim().min(1).max(40)]).nullish(),
  name: z.string().trim().min(1).max(80),
  desc: z.string().trim().max(300).default(''),
  price: z.number().int().min(0).max(5000),
  img: perfumeImageField,
  active: z.boolean().default(true),
});

const dataSchema = z.object({
  settings: settingsSchema,
  perfumes: z.array(perfumeSchema).max(200),
});

const proofUploadSchema = z.object({
  image: z
    .string()
    .trim()
    .max(450000)
    .regex(/^data:image\/(jpeg|jpg|png|webp);base64,[A-Za-z0-9+/=]+$/, 'Formato de imagen no válido'),
});

const LABELS = {
  settings: 'Configuración', perfumes: 'Perfumes', brandTitle: 'Título', brandSubtitle: 'Subtítulo',
  splashSubtitle: 'Subtítulo intro', brandLogoImg: 'Logo de la tienda',
  heroTitle: 'Título portada', heroSubtitle: 'Subtítulo portada', heroCtaText: 'Botón portada',
  brandTabs: 'Marcas', shippingText: 'Texto de envío', yapeNumber: 'Yape', yapeQrImg: 'Imagen QR de Yape',
  whatsapp: 'WhatsApp', limaShippingCost: 'Costo envío Lima', provinceShippingText: 'Texto provincia',
  reservationPerItem: 'Monto separación', name: 'Nombre', desc: 'Descripción', price: 'Precio',
  img: 'Imagen', active: 'Activo', id: 'ID',
};

function formatZodError(err) {
  const msgs = err.issues.slice(0, 4).map((i) => {
    const parts = [];
    i.path.forEach((seg, idx) => {
      if (typeof seg === 'number') return;
      if (seg === 'perfumes' && typeof i.path[idx + 1] === 'number') parts.push(`Perfume #${i.path[idx + 1] + 1}`);
      else parts.push(LABELS[seg] || String(seg));
    });
    return `${parts.join(' · ') || 'Datos'}: ${i.message}`;
  });
  return 'Datos inválidos. ' + msgs.join(' | ');
}

function withIds(data, rejectDuplicates) {
  const used = new Set();
  let max = 0;
  for (const p of data.perfumes) {
    if (p.id != null && /^\d{1,9}$/.test(String(p.id))) max = Math.max(max, Number(p.id));
  }
  const perfumes = data.perfumes.map((p) => {
    let id = p.id;
    if (id != null && used.has(String(id))) {
      if (rejectDuplicates) throw new HttpError(400, `Hay IDs de perfume duplicados (${id}).`);
      id = null;
    }
    if (id == null) id = ++max;
    used.add(String(id));
    return { id, name: p.name, desc: p.desc, price: p.price, img: p.img, active: p.active };
  });
  return { settings: data.settings, perfumes };
}

function normalizeStored(raw) {
  const mergedRaw = {
    settings: { ...DEFAULT_SETTINGS, ...((raw && raw.settings) || {}) },
    perfumes: Array.isArray(raw && raw.perfumes) ? raw.perfumes : [],
  };
  const parsed = dataSchema.safeParse(mergedRaw);
  if (parsed.success) return withIds(parsed.data, false);
  if (!raw || typeof raw !== 'object' || !Array.isArray(raw.perfumes)) {
    throw new HttpError(502, 'El data.json tiene un formato inválido.');
  }
  console.warn('data.json no cumple la validación estricta:', formatZodError(parsed.error));
  return withIds(
    {
      settings: mergedRaw.settings,
      perfumes: raw.perfumes
        .filter((p) => p && typeof p === 'object')
        .map((p) => ({
          id: p.id ?? null,
          name: String(p.name ?? ''),
          desc: String(p.desc ?? ''),
          price: Number(p.price) || 0,
          img: String(p.img ?? ''),
          active: p.active !== false,
        })),
    },
    false
  );
}

/* ===================== GitHub (Contents API) ===================== */
const ghUrl = `https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${FILE_PATH}`;

async function ghFetch(url, options = {}) {
  if (!GITHUB_TOKEN) throw new HttpError(500, 'Falta configurar GITHUB_TOKEN en el servidor.');
  try {
    return await fetch(url, {
      ...options,
      headers: {
        Authorization: `Bearer ${GITHUB_TOKEN}`,
        'User-Agent': 'arenas-tienda',
        Accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        ...(options.headers || {}),
      },
      signal: AbortSignal.timeout(15000),
    });
  } catch (e) {
    throw new HttpError(502, 'No se pudo conectar con GitHub. Intenta de nuevo en unos segundos.');
  }
}

function ghFail(status) {
  if (status === 404) {
    return new HttpError(502, `No se encontró data.json en la rama "${GITHUB_BRANCH}" de GitHub. Revisa el README (paso 1).`);
  }
  if (status === 401 || status === 403) {
    return new HttpError(502, 'GitHub rechazó la petición (token inválido, sin permiso "Contents: Read and write" o límite de uso).');
  }
  return new HttpError(502, `GitHub respondió con el error ${status}.`);
}

async function ghGetFile() {
  const res = await ghFetch(`${ghUrl}?ref=${encodeURIComponent(GITHUB_BRANCH)}`);
  if (!res.ok) throw ghFail(res.status);
  return res.json();
}

async function loadFromGitHub() {
  const file = await ghGetFile();
  let raw;
  try {
    raw = JSON.parse(Buffer.from(file.content || '', 'base64').toString('utf8'));
  } catch (e) {
    throw new HttpError(502, 'El data.json de GitHub no es un JSON válido.');
  }
  return normalizeStored(raw);
}

async function ghWrite(data, attempt = 0) {
  const { sha } = await ghGetFile();
  const res = await ghFetch(ghUrl, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      message: 'Actualización desde el Panel Admin - ARENAS',
      content: Buffer.from(JSON.stringify(data, null, 2) + '\n').toString('base64'),
      sha,
      branch: GITHUB_BRANCH,
    }),
  });
  if ((res.status === 409 || res.status === 422) && attempt === 0) return ghWrite(data, 1);
  if (!res.ok) throw ghFail(res.status);
}

/* ===================== Caché en memoria ===================== */
let cache = { data: null, ts: 0 };
let inflight = null;

function getData(force) {
  if (!force && cache.data && Date.now() - cache.ts < CACHE_MS) return Promise.resolve(cache.data);
  if (!inflight) {
    inflight = loadFromGitHub()
      .then((d) => {
        cache = { data: d, ts: Date.now() };
        return d;
      })
      .finally(() => {
        inflight = null;
      });
  }
  return inflight;
}

async function getPublicData() {
  if (!GITHUB_TOKEN) {
    if (!cache.data) {
      const local = await fs.readFile(path.join(__dirname, FILE_PATH), 'utf8');
      cache = { data: normalizeStored(JSON.parse(local)), ts: Date.now() };
    }
    return cache.data;
  }

  try {
    return await getData(false);
  } catch (err) {
    console.error('Lectura de GitHub falló, se usa copia de respaldo:', err.message);
    if (!cache.data) {
      try {
        const local = await fs.readFile(path.join(__dirname, FILE_PATH), 'utf8');
        cache.data = normalizeStored(JSON.parse(local));
      } catch (e) {
        throw err;
      }
    }
    cache.ts = Date.now() - CACHE_MS + 10000;
    return cache.data;
  }
}

/* ===================== Sesión (cookie firmada, sin estado) ===================== */
const sha256 = (s) => crypto.createHash('sha256').update(String(s)).digest();
const safeEqual = (a, b) => crypto.timingSafeEqual(sha256(a), sha256(b));
const sign = (payload) => crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');

function createToken() {
  const payload = Buffer.from(JSON.stringify({ exp: Date.now() + SESSION_MS })).toString('base64url');
  return `${payload}.${sign(payload)}`;
}

function verifyToken(token) {
  if (!ADMIN_ENABLED || !token) return false;
  const [payload, sig] = String(token).split('.');
  if (!payload || !sig) return false;
  const a = Buffer.from(sig);
  const b = Buffer.from(sign(payload));
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return false;
  try {
    const { exp } = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    return typeof exp === 'number' && exp > Date.now();
  } catch (e) {
    return false;
  }
}

function getCookie(req, name) {
  const header = req.headers.cookie;
  if (!header) return null;
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return null;
}

const cookieOpts = (req) => ({ httpOnly: true, secure: req.secure, sameSite: 'strict', path: '/' });

function requireAdmin(req, res, next) {
  if (!ADMIN_ENABLED) {
    return next(new HttpError(503, 'El panel no está configurado (faltan ADMIN_PASSWORD o SESSION_SECRET).'));
  }
  if (!verifyToken(getCookie(req, COOKIE_NAME))) {
    return next(new HttpError(401, 'Tu sesión no es válida o expiró. Ingresa de nuevo.'));
  }
  next();
}

/* ===================== App ===================== */
const app = express();
const ah = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

app.set('trust proxy', 1);

app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        defaultSrc: ["'self'"],
        baseUri: ["'self'"],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"],
        formAction: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", ...CDN],
        styleSrc: ["'self'", "'unsafe-inline'", 'https://cdnjs.cloudflare.com', 'https://fonts.googleapis.com'],
        fontSrc: ["'self'", 'https://cdnjs.cloudflare.com', 'https://fonts.gstatic.com', 'data:'],
        imgSrc: ["'self'", 'https:', 'data:', 'blob:'],
        connectSrc: ["'self'"],
      },
    },
    crossOriginEmbedderPolicy: false,
  })
);
app.use(compression());
app.use(express.json({ limit: '6mb' }));

app.get('/healthz', (req, res) => res.type('text').send('ok'));

/* ---------- Vista pública del comprobante subido ---------- */
app.get('/comprobante/:id', (req, res) => {
  const id = String(req.params.id || '').replace(/\.(jpg|jpeg|png|webp)$/i, '');
  const item = PROOFS.get(id);
  if (!item || item.exp <= Date.now()) {
    PROOFS.delete(id);
    return res.status(404).type('text').send('Comprobante no encontrado o expirado.');
  }
  res.set('Content-Type', item.type);
  res.set('Cache-Control', 'public, max-age=3600');
  res.send(item.buf);
});

app.use(['/admin', '/api/admin'], (req, res, next) => {
  res.set('X-Robots-Tag', 'noindex, nofollow');
  res.set('Cache-Control', 'no-store');
  next();
});

app.use((req, res, next) => {
  let p;
  try {
    p = decodeURIComponent(req.path);
  } catch (e) {
    return res.status(400).type('text').send('Solicitud inválida');
  }
  const n = path.posix.normalize(p).toLowerCase();
  if (n === '/admin.html' || n.startsWith('/admin.html/')) return res.status(404).type('text').send('No encontrado');
  next();
});
app.use(express.static(PUBLIC_DIR, { index: 'index.html' }));

app.get('/admin', (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'admin.html')));

/* ---------- Límites y verificación de origen ---------- */
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 120,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Demasiadas peticiones. Espera un momento e intenta de nuevo.' },
});

const proofLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 15,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Demasiados comprobantes enviados. Espera unos minutos.' },
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  skipSuccessfulRequests: true,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Demasiados intentos fallidos. Espera 15 minutos e intenta de nuevo.' },
});

function originGuard(req, res, next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  const origin = req.get('origin');
  if (!origin) {
    if (process.env.NODE_ENV === 'production') {
      return next(new HttpError(403, 'Cabecera Origin requerida.'));
    }
    return next();
  }
  let host = null;
  try {
    host = new URL(origin).host;
  } catch (e) {
    /* origen inválido */
  }
  if (host !== req.get('host')) return next(new HttpError(403, 'Origen no permitido.'));
  next();
}

app.use('/api', apiLimiter, originGuard);

/* ---------- API pública ---------- */
app.get(
  '/api/data',
  ah(async (req, res) => {
    const { settings, perfumes } = await getPublicData();
    res.set('Cache-Control', 'public, max-age=30').json({
      settings,
      perfumes: perfumes.filter((p) => p.active !== false).map(({ active, ...rest }) => rest),
    });
  })
);

/* Subida de captura de pago del cliente */
app.post(
  '/api/proof',
  proofLimiter,
  ah(async (req, res) => {
    const parsed = proofUploadSchema.safeParse(req.body);
    if (!parsed.success) throw new HttpError(400, 'La imagen del comprobante no es válida.');
    const match = parsed.data.image.match(/^data:(image\/(?:jpeg|jpg|png|webp));base64,(.+)$/);
    if (!match) throw new HttpError(400, 'Formato de imagen no soportado.');

    const mime = match[1] === 'image/jpg' ? 'image/jpeg' : match[1];
    const ext = mime === 'image/png' ? 'png' : mime === 'image/webp' ? 'webp' : 'jpg';
    const buf = Buffer.from(match[2], 'base64');
    if (buf.length > 350 * 1024) throw new HttpError(413, 'La captura es demasiado pesada.');

    cleanupProofs();
    const id = crypto.randomBytes(10).toString('hex');
    PROOFS.set(id, { buf, type: mime, exp: Date.now() + PROOF_TTL_MS });

    const proto = req.get('x-forwarded-proto') || req.protocol || 'https';
    const host = req.get('host');
    const url = `${proto}://${host}/comprobante/${id}.${ext}`;
    res.json({ ok: true, url });
  })
);

/* ---------- API admin ---------- */
app.post(
  '/api/admin/login',
  loginLimiter,
  ah(async (req, res) => {
    if (!ADMIN_ENABLED) throw new HttpError(503, 'El panel no está configurado (faltan ADMIN_PASSWORD o SESSION_SECRET).');
    const password = typeof req.body?.password === 'string' ? req.body.password : '';
    if (!password || !safeEqual(password, ADMIN_PASSWORD)) throw new HttpError(401, 'Contraseña incorrecta.');
    res.cookie(COOKIE_NAME, createToken(), { ...cookieOpts(req), maxAge: SESSION_MS });
    res.json({ ok: true });
  })
);

app.post('/api/admin/logout', (req, res) => {
  res.clearCookie(COOKIE_NAME, cookieOpts(req));
  res.json({ ok: true });
});

app.get('/api/admin/me', (req, res) => {
  res.json({ authenticated: verifyToken(getCookie(req, COOKIE_NAME)), enabled: ADMIN_ENABLED });
});

app.get(
  '/api/admin/data',
  requireAdmin,
  ah(async (req, res) => {
    res.json(await getData(true));
  })
);

app.put(
  '/api/admin/data',
  requireAdmin,
  ah(async (req, res) => {
    const parsed = dataSchema.safeParse(req.body);
    if (!parsed.success) throw new HttpError(400, formatZodError(parsed.error));
    const data = withIds(parsed.data, true);
    await ghWrite(data);
    cache = { data, ts: Date.now() };
    res.json({ ok: true, data });
  })
);

/* ---------- 404 y errores ---------- */
app.use('/api', (req, res) => res.status(404).json({ error: 'Ruta no encontrada.' }));
app.use((req, res) => res.status(404).type('text').send('No encontrado'));

app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  let status = 500;
  let message = 'Error interno del servidor.';
  if (err instanceof HttpError) {
    status = err.status;
    message = err.message;
  } else if (err.type === 'entity.parse.failed') {
    status = 400;
    message = 'El cuerpo de la petición no es un JSON válido.';
  } else if (err.type === 'entity.too.large') {
    status = 413;
    message = 'La petición es demasiado grande.';
  } else {
    console.error('Error no controlado:', err.message);
  }
  res.status(status).json({ error: message });
});

app.listen(PORT, () => {
  console.log(`Servidor ARENAS en el puerto ${PORT} (datos: ${GITHUB_OWNER}/${GITHUB_REPO}@${GITHUB_BRANCH})`);
  if (!ADMIN_ENABLED) console.warn('Panel admin desactivado: define ADMIN_PASSWORD (10+ caracteres) y SESSION_SECRET (32+ caracteres).');
  if (!GITHUB_TOKEN) console.warn('Falta GITHUB_TOKEN: la tienda usará el data.json local y no se podrá guardar.');
});
