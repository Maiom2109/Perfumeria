'use strict';

const crypto = require('crypto');
const fs = require('fs/promises');
const path = require('path');
const express = require('express');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const { z } = require('zod');

const app = express();

app.set('trust proxy', 1);

const PORT = Number(process.env.PORT) || 3000;
const GITHUB_TOKEN = process.env.GITHUB_TOKEN || '';
const GITHUB_OWNER = process.env.GITHUB_OWNER || '';
const GITHUB_REPO = process.env.GITHUB_REPO || '';
const DEFAULT_BRANCH = (process.env.GITHUB_BRANCH || 'data').trim() || 'data';
const DATA_PATH = 'data.json';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const SESSION_SECRET = process.env.SESSION_SECRET || '';
const COOKIE_NAME = 'arenas_admin_session';
const SESSION_TTL_MS = 12 * 60 * 60 * 1000;
const CACHE_TTL_MS = 60 * 1000;

const cacheStore = new Map();
const lastGoodStore = new Map();

class AppError extends Error {
  constructor(statusCode, message) {
    super(message);
    this.statusCode = statusCode;
    this.expose = true;
  }
}

function sha256Buffer(value) {
  return crypto.createHash('sha256').update(String(value), 'utf8').digest();
}

function verifyPassword(inputPassword, expectedPassword) {
  if (!inputPassword || !expectedPassword) return false;
  const left = sha256Buffer(inputPassword);
  const right = sha256Buffer(expectedPassword);
  return crypto.timingSafeEqual(left, right);
}

function getSigningKey() {
  if (SESSION_SECRET) return SESSION_SECRET;
  if (process.env.NODE_ENV !== 'production') return 'dev-only-session-secret';
  throw new AppError(500, 'Falta configurar SESSION_SECRET en el servidor.');
}

function signSessionToken(payloadObj) {
  const encodedPayload = Buffer.from(JSON.stringify(payloadObj), 'utf8').toString('base64url');
  const signature = crypto
    .createHmac('sha256', getSigningKey())
    .update(encodedPayload)
    .digest('base64url');
  return `${encodedPayload}.${signature}`;
}

function verifySessionToken(token) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [encodedPayload, signature] = parts;
  if (!encodedPayload || !signature) return null;

  let expectedSig;
  try {
    expectedSig = crypto
      .createHmac('sha256', getSigningKey())
      .update(encodedPayload)
      .digest('base64url');
  } catch {
    return null;
  }

  const sigBuf = Buffer.from(signature, 'utf8');
  const expBuf = Buffer.from(expectedSig, 'utf8');
  if (sigBuf.length !== expBuf.length) return null;
  if (!crypto.timingSafeEqual(sigBuf, expBuf)) return null;

  try {
    const parsed = JSON.parse(Buffer.from(encodedPayload, 'base64url').toString('utf8'));
    if (!parsed || parsed.role !== 'admin' || typeof parsed.exp !== 'number') return null;
    if (Date.now() > parsed.exp) return null;
    return parsed;
  } catch {
    return null;
  }
}

function parseCookies(cookieHeader) {
  const cookies = {};
  if (!cookieHeader || typeof cookieHeader !== 'string') return cookies;
  const pairs = cookieHeader.split(';');
  for (const pair of pairs) {
    const idx = pair.indexOf('=');
    if (idx === -1) continue;
    const key = pair.slice(0, idx).trim();
    const val = pair.slice(idx + 1).trim();
    if (key) {
      cookies[key] = decodeURIComponent(val);
    }
  }
  return cookies;
}

function getSessionFromReq(req) {
  const cookies = parseCookies(req.headers.cookie);
  return verifySessionToken(cookies[COOKIE_NAME]);
}

function requireAdmin(req, res, next) {
  const session = getSessionFromReq(req);
  if (!session) {
    return next(new AppError(401, 'No autorizado. Inicia sesión como administrador.'));
  }
  req.adminSession = session;
  return next();
}

function setSessionCookie(req, res, token) {
  const isHttps = req.secure || req.headers['x-forwarded-proto'] === 'https' || process.env.NODE_ENV === 'production';
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    secure: Boolean(isHttps),
    sameSite: 'strict',
    maxAge: SESSION_TTL_MS,
    path: '/'
  });
}

function clearSessionCookie(req, res) {
  const isHttps = req.secure || req.headers['x-forwarded-proto'] === 'https' || process.env.NODE_ENV === 'production';
  res.clearCookie(COOKIE_NAME, {
    httpOnly: true,
    secure: Boolean(isHttps),
    sameSite: 'strict',
    path: '/'
  });
}

function verifyOrigin(req, res, next) {
  const method = req.method.toUpperCase();
  if (method === 'GET' || method === 'HEAD' || method === 'OPTIONS') {
    return next();
  }

  const origin = req.headers.origin;
  const host = req.headers.host;

  if (!origin) {
    if (process.env.NODE_ENV === 'production') {
      return next(new AppError(403, 'Cabecera Origin requerida para esta operación.'));
    }
    return next();
  }

  try {
    const parsedOrigin = new URL(origin);
    const allowedHosts = new Set([host, 'tienda-arenas.onrender.com'].filter(Boolean));
    if (!allowedHosts.has(parsedOrigin.host)) {
      return next(new AppError(403, 'Origen no permitido.'));
    }
    return next();
  } catch {
    return next(new AppError(403, 'Cabecera Origin inválida.'));
  }
}

const settingsSchema = z.object({
  brandTitle: z.string().trim().min(1, 'El título es obligatorio').max(40, 'Máximo 40 caracteres'),
  brandSubtitle: z.string().trim().min(1, 'El subtítulo es obligatorio').max(60, 'Máximo 60 caracteres'),
  shippingText: z.string().trim().min(1, 'El texto de envío es obligatorio').max(80, 'Máximo 80 caracteres'),
  yapeNumber: z.string().trim().regex(/^9\d{8}$/, 'Yape debe tener 9 dígitos y empezar con 9'),
  whatsapp: z.string().trim().regex(/^51\d{9}$/, 'WhatsApp debe tener formato 51 seguido de 9 dígitos')
});

const perfumeInputSchema = z.object({
  id: z.union([z.number().int().positive(), z.string().trim().min(1)]).optional().nullable(),
  name: z.string().trim().min(1, 'El nombre es obligatorio').max(80, 'Máximo 80 caracteres'),
  desc: z.string().trim().max(300, 'Máximo 300 caracteres').optional().default(''),
  price: z.number({ invalid_type_error: 'El precio debe ser un número entero' })
    .int('El precio debe ser un número entero')
    .min(0, 'El precio no puede ser negativo')
    .max(5000, 'El precio máximo es 5000'),
  img: z.string().trim().max(500, 'URL demasiado larga').refine((val) => {
    try {
      const u = new URL(val);
      return u.protocol === 'https:';
    } catch {
      return false;
    }
  }, 'La imagen debe ser una URL HTTPS válida'),
  active: z.boolean().optional().default(true)
});

const adminDataPayloadSchema = z.object({
  settings: settingsSchema,
  perfumes: z.array(perfumeInputSchema).max(200, 'Máximo 200 perfumes permitidos'),
  branch: z.string().trim().min(1).max(100).optional()
});

function normalizeAndValidateAdminPayload(rawBody, existingPerfumes = []) {
  const parsed = adminDataPayloadSchema.safeParse(rawBody);
  if (!parsed.success) {
    const firstIssue = parsed.error.issues[0];
    throw new AppError(400, firstIssue ? firstIssue.message : 'Datos inválidos.');
  }

  const { settings, perfumes, branch } = parsed.data;

  const existingIds = new Set();
  let maxNumericId = 0;

  for (const item of existingPerfumes) {
    if (item && item.id !== undefined && item.id !== null) {
      existingIds.add(String(item.id));
      const num = Number(item.id);
      if (Number.isInteger(num) && num > maxNumericId) {
        maxNumericId = num;
      }
    }
  }

  const seenInBatch = new Set();
  const normalizedPerfumes = perfumes.map((item) => {
    let assignedId = null;

    if (item.id !== undefined && item.id !== null && String(item.id).trim() !== '') {
      const candidateStr = String(item.id).trim();
      const candidateNum = Number(candidateStr);
      if (existingIds.has(candidateStr)) {
        if (seenInBatch.has(candidateStr)) {
          throw new AppError(400, `ID duplicado en perfumes: ${candidateStr}`);
        }
        assignedId = Number.isInteger(candidateNum) && String(candidateNum) === candidateStr
          ? candidateNum
          : candidateStr;
        seenInBatch.add(candidateStr);
        if (Number.isInteger(candidateNum) && candidateNum > maxNumericId) {
          maxNumericId = candidateNum;
        }
      }
    }

    if (assignedId === null) {
      maxNumericId += 1;
      while (existingIds.has(String(maxNumericId)) || seenInBatch.has(String(maxNumericId))) {
        maxNumericId += 1;
      }
      assignedId = maxNumericId;
      seenInBatch.add(String(assignedId));
    }

    return {
      id: assignedId,
      name: item.name,
      desc: item.desc,
      price: item.price,
      img: item.img,
      active: item.active !== false
    };
  });

  return {
    branch: branch || DEFAULT_BRANCH,
    data: {
      settings,
      perfumes: normalizedPerfumes
    }
  };
}

function toPublicData(fullData) {
  const settings = fullData && fullData.settings ? fullData.settings : {};
  const list = Array.isArray(fullData && fullData.perfumes) ? fullData.perfumes : [];

  const publicPerfumes = list
    .filter((p) => p && p.active !== false)
    .map((p) => ({
      id: p.id,
      name: p.name,
      desc: p.desc,
      price: p.price,
      img: p.img
    }));

  return {
    settings: {
      brandTitle: settings.brandTitle || 'ARENAS',
      brandSubtitle: settings.brandSubtitle || 'Perfumes Árabes & Decants',
      shippingText: settings.shippingText || 'Delivery en Lima S/ 12.00',
      yapeNumber: settings.yapeNumber || '',
      whatsapp: settings.whatsapp || ''
    },
    perfumes: publicPerfumes
  };
}

function assertGitHubConfig() {
  if (!GITHUB_TOKEN || !GITHUB_OWNER || !GITHUB_REPO) {
    throw new AppError(500, 'Configuración incompleta de GitHub en el servidor.');
  }
}

function githubHeaders() {
  return {
    Authorization: `Bearer ${GITHUB_TOKEN}`,
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
    'Content-Type': 'application/json',
    'User-Agent': 'tienda-arenas-server'
  };
}

async function fetchGitHubFile(branch) {
  assertGitHubConfig();
  const encodedPath = encodeURIComponent(DATA_PATH);
  const encodedRef = encodeURIComponent(branch);
  const url = `https://api.github.com/repos/${encodeURIComponent(GITHUB_OWNER)}/${encodeURIComponent(GITHUB_REPO)}/contents/${encodedPath}?ref=${encodedRef}`;

  const response = await fetch(url, {
    method: 'GET',
    headers: githubHeaders()
  });

  if (!response.ok) {
    throw new AppError(502, `Error al consultar GitHub (${response.status}).`);
  }

  const json = await response.json();
  if (!json || typeof json.content !== 'string' || typeof json.sha !== 'string') {
    throw new AppError(502, 'Respuesta inesperada de GitHub Contents API.');
  }

  const rawText = Buffer.from(json.content, 'base64').toString('utf8');
  let parsedData;
  try {
    parsedData = JSON.parse(rawText);
  } catch {
    throw new AppError(502, 'El archivo data.json en GitHub no contiene JSON válido.');
  }

  return {
    data: {
      settings: parsedData.settings || {},
      perfumes: Array.isArray(parsedData.perfumes) ? parsedData.perfumes : []
    },
    sha: json.sha
  };
}

async function putGitHubFile(branch, contentObj, sha, message) {
  assertGitHubConfig();
  const encodedPath = encodeURIComponent(DATA_PATH);
  const url = `https://api.github.com/repos/${encodeURIComponent(GITHUB_OWNER)}/${encodeURIComponent(GITHUB_REPO)}/contents/${encodedPath}`;
  const formattedContent = `${JSON.stringify(contentObj, null, 2)}\n`;
  const encodedContent = Buffer.from(formattedContent, 'utf8').toString('base64');

  const body = {
    message,
    content: encodedContent,
    branch
  };
  if (sha) {
    body.sha = sha;
  }

  const response = await fetch(url, {
    method: 'PUT',
    headers: githubHeaders(),
    body: JSON.stringify(body)
  });

  return response;
}

async function saveGitHubFileWithRetry(branch, contentObj) {
  let currentSha = null;
  try {
    const existing = await fetchGitHubFile(branch);
    currentSha = existing.sha;
  } catch (err) {
    if (err instanceof AppError && err.statusCode === 502) {
      currentSha = null;
    } else {
      throw err;
    }
  }

  const commitMsg = `Actualizar data.json (${new Date().toISOString()})`;
  let res = await putGitHubFile(branch, contentObj, currentSha, commitMsg);

  if (res.status === 409 || res.status === 422) {
    const refreshed = await fetchGitHubFile(branch);
    res = await putGitHubFile(branch, contentObj, refreshed.sha, commitMsg);
  }

  if (!res.ok) {
    throw new AppError(502, `No se pudo guardar en GitHub (${res.status}).`);
  }

  const resultJson = await res.json();
  return resultJson.content && resultJson.content.sha ? resultJson.content.sha : null;
}

async function readLocalFallbackData() {
  const localFile = path.join(__dirname, 'data.json');
  const raw = await fs.readFile(localFile, 'utf8');
  const parsed = JSON.parse(raw);
  return {
    settings: parsed.settings || {},
    perfumes: Array.isArray(parsed.perfumes) ? parsed.perfumes : []
  };
}

async function getStoreData(branch, { bypassCache = false } = {}) {
  const targetBranch = (branch || DEFAULT_BRANCH).trim() || DEFAULT_BRANCH;
  const now = Date.now();
  const cached = cacheStore.get(targetBranch);

  if (!bypassCache && cached && cached.expiresAt > now) {
    return cached.data;
  }

  try {
    const { data } = await fetchGitHubFile(targetBranch);
    cacheStore.set(targetBranch, { data, expiresAt: now + CACHE_TTL_MS });
    lastGoodStore.set(targetBranch, data);
    return data;
  } catch (err) {
    if (lastGoodStore.has(targetBranch)) {
      return lastGoodStore.get(targetBranch);
    }
    try {
      const localData = await readLocalFallbackData();
      lastGoodStore.set(targetBranch, localData);
      return localData;
    } catch {
      throw err;
    }
  }
}

function invalidateBranchCache(branch) {
  const targetBranch = (branch || DEFAULT_BRANCH).trim() || DEFAULT_BRANCH;
  cacheStore.delete(targetBranch);
}

app.use(compression());

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: [
          "'self'",
          "'unsafe-inline'",
          "'unsafe-eval'",
          'https://cdn.tailwindcss.com',
          'https://unpkg.com',
          'https://cdnjs.cloudflare.com'
        ],
        styleSrc: [
          "'self'",
          "'unsafe-inline'",
          'https://cdn.tailwindcss.com',
          'https://cdnjs.cloudflare.com'
        ],
        fontSrc: ["'self'", 'https://cdnjs.cloudflare.com', 'data:'],
        imgSrc: ["'self'", 'https:', 'data:'],
        connectSrc: ["'self'"],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"]
      }
    }
  })
);

app.use(express.json({ limit: '100kb' }));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (_req, res) => {
    res.status(429).json({ error: 'Demasiados intentos de inicio de sesión. Intenta en 15 minutos.' });
  }
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 180,
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => req.path === '/admin/login',
  handler: (_req, res) => {
    res.status(429).json({ error: 'Límite de peticiones alcanzado. Intenta más tarde.' });
  }
});

app.use('/api', apiLimiter);
app.use('/api', verifyOrigin);

app.get('/healthz', (_req, res) => {
  res.status(200).json({ status: 'ok' });
});

app.get('/api/data', async (req, res, next) => {
  try {
    const refParam = typeof req.query.ref === 'string' && req.query.ref.trim()
      ? req.query.ref.trim()
      : DEFAULT_BRANCH;

    const storeData = await getStoreData(refParam);
    const publicPayload = toPublicData(storeData);

    res.set('Cache-Control', 'public, max-age=30');
    return res.status(200).json(publicPayload);
  } catch (err) {
    return next(err);
  }
});

app.post('/api/admin/login', loginLimiter, (req, res, next) => {
  try {
    if (!ADMIN_PASSWORD) {
      return next(new AppError(500, 'ADMIN_PASSWORD no está configurada en el servidor.'));
    }

    const password = req.body && typeof req.body.password === 'string' ? req.body.password : '';
    if (!verifyPassword(password, ADMIN_PASSWORD)) {
      return next(new AppError(401, 'Contraseña incorrecta.'));
    }

    const exp = Date.now() + SESSION_TTL_MS;
    const token = signSessionToken({ role: 'admin', exp });
    setSessionCookie(req, res, token);

    return res.status(200).json({ authenticated: true, expiresAt: exp });
  } catch (err) {
    return next(err);
  }
});

app.post('/api/admin/logout', (req, res) => {
  clearSessionCookie(req, res);
  return res.status(200).json({ authenticated: false });
});

app.get('/api/admin/me', (req, res) => {
  const session = getSessionFromReq(req);
  if (!session) {
    return res.status(200).json({ authenticated: false });
  }
  return res.status(200).json({ authenticated: true, expiresAt: session.exp });
});

app.get('/api/admin/data', requireAdmin, async (req, res, next) => {
  try {
    const refParam = typeof req.query.ref === 'string' && req.query.ref.trim()
      ? req.query.ref.trim()
      : DEFAULT_BRANCH;

    const storeData = await getStoreData(refParam, { bypassCache: true });
    const perfumesWithActive = (Array.isArray(storeData.perfumes) ? storeData.perfumes : []).map((p) => ({
      id: p.id,
      name: p.name,
      desc: p.desc || '',
      price: Number(p.price),
      img: p.img,
      active: p.active !== false
    }));

    return res.status(200).json({
      branch: refParam,
      settings: storeData.settings,
      perfumes: perfumesWithActive
    });
  } catch (err) {
    return next(err);
  }
});

app.put('/api/admin/data', requireAdmin, async (req, res, next) => {
  try {
    const requestedBranch = req.body && typeof req.body.branch === 'string' && req.body.branch.trim()
      ? req.body.branch.trim()
      : DEFAULT_BRANCH;

    let currentPerfumes = [];
    try {
      const current = await getStoreData(requestedBranch, { bypassCache: true });
      currentPerfumes = Array.isArray(current.perfumes) ? current.perfumes : [];
    } catch {
      currentPerfumes = [];
    }

    const { branch, data } = normalizeAndValidateAdminPayload(req.body, currentPerfumes);
    await saveGitHubFileWithRetry(branch, data);

    invalidateBranchCache(branch);
    lastGoodStore.set(branch, data);

    return res.status(200).json({
      ok: true,
      branch,
      settings: data.settings,
      perfumes: data.perfumes
    });
  } catch (err) {
    return next(err);
  }
});

app.get(['/admin', '/admin/'], (_req, res, next) => {
  res.set('X-Robots-Tag', 'noindex, nofollow');
  res.sendFile(path.join(__dirname, 'public', 'admin.html'), (err) => {
    if (err) next(new AppError(404, 'Panel no encontrado.'));
  });
});

app.use((req, res, next) => {
  if (req.path.toLowerCase() === '/admin.html') {
    return res.status(404).json({ error: 'Recurso no encontrado.' });
  }
  return next();
});

app.use(express.static(path.join(__dirname, 'public')));

app.use((req, res, _next) => {
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ error: 'Endpoint no encontrado.' });
  }
  return res.status(404).sendFile(path.join(__dirname, 'public', 'index.html'), () => {
    res.status(404).json({ error: 'Página no encontrada.' });
  });
});

app.use((err, _req, res, _next) => {
  const status = err && err.expose && typeof err.statusCode === 'number' ? err.statusCode : 500;
  const message = err && err.expose && err.message
    ? err.message
    : 'Error interno del servidor.';

  if (status >= 500) {
    console.error(`[ERROR ${status}]: ${err && err.message ? err.message : 'Error desconocido'}`);
  }

  return res.status(status).json({ error: message });
});

app.listen(PORT, () => {
  console.log(`Servidor ARENAS escuchando en puerto ${PORT}`);
});
