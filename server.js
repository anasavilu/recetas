require('dotenv').config();
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const path = require('path');
const dns = require('dns').promises;
const net = require('net');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(cors());
app.use(express.json({ limit: '15mb' }));
app.use(express.static('public'));

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);
const APP_PIN = process.env.APP_PIN || '1234';
const TOKEN = crypto.createHash('sha256').update(APP_PIN).digest('hex');

// Categorías generales. Si cambias esta lista, cambia también CATEGORIAS en public/index.html
const CATEGORIAS = [
  'pescado', 'marisco', 'carne', 'aves', 'embutido', 'huevos', 'lácteos',
  'verdura', 'fruta', 'legumbres', 'arroz', 'pasta', 'pan y masas', 'cereales',
  'frutos secos', 'salsas y condimentos', 'especias y hierbas', 'aceites y grasas', 'dulces',
];

// ---------- autenticación ----------
function requireAuth(req, res, next) {
  if (req.headers['x-app-token'] !== TOKEN) return res.status(401).json({ error: 'No autorizado' });
  next();
}

async function requirePerfil(req, res, next) {
  const raw = req.headers['x-perfil'];
  if (!raw) return res.status(403).json({ error: 'Elige un perfil', code: 'perfil' });
  let nombre;
  try { nombre = decodeURIComponent(raw); } catch (e) { nombre = raw; }
  const { data, error } = await supabase.from('perfiles').select('nombre').eq('nombre', nombre).maybeSingle();
  if (error) return res.status(500).json({ error: error.message });
  if (!data) return res.status(403).json({ error: 'Ese perfil ya no existe', code: 'perfil' });
  req.perfil = data.nombre;
  next();
}

app.post('/api/login', (req, res) => {
  const { pin } = req.body || {};
  if (pin === APP_PIN) return res.json({ token: TOKEN });
  res.status(401).json({ error: 'PIN incorrecto' });
});

// ---------- perfiles ----------
app.get('/api/perfiles', requireAuth, async (req, res) => {
  const { data, error } = await supabase.from('perfiles').select('*').order('creado', { ascending: true });
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/perfiles', requireAuth, async (req, res) => {
  const nombre = String((req.body || {}).nombre || '').trim().slice(0, 30);
  if (!nombre) return res.status(400).json({ error: 'Escribe un nombre' });
  const { data: existentes, error: e1 } = await supabase.from('perfiles').select('*');
  if (e1) return res.status(500).json({ error: e1.message });
  if ((existentes || []).some(p => p.nombre.toLowerCase() === nombre.toLowerCase())) {
    return res.status(409).json({ error: 'Ya existe un perfil con ese nombre' });
  }
  const { data, error } = await supabase.from('perfiles').insert([{ nombre }]).select();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data[0]);
});

// ---------- recetas ----------
app.get('/api/recipes', requireAuth, requirePerfil, async (req, res) => {
  const { data, error } = await supabase.from('recipes').select('*').order('creado', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  // Ves: las tuyas, las que otros han compartido y las antiguas sin propietario.
  const visibles = (data || []).filter(r => r.propietario === req.perfil || r.compartida || !r.propietario);
  // El enlace público solo lo ve su dueño; los demás perfiles solo saben que existe.
  res.json(visibles.map(r => {
    if (r.propietario === req.perfil) return r;
    const { token_publico, ...resto } = r;
    return { ...resto, publica: !!token_publico };
  }));
});

// ---------- enlace público (solo lectura, sin PIN) ----------
// Quien tenga el enlace puede ver esa receta, y nada más. El enlace lleva un código aleatorio imposible de adivinar.
app.get('/api/publica/:token', async (req, res) => {
  res.set('X-Robots-Tag', 'noindex, nofollow');
  const token = String(req.params.token || '');
  if (!/^[a-f0-9]{32}$/.test(token)) return res.status(404).json({ error: 'No disponible' });
  const { data, error } = await supabase.from('recipes').select('*').eq('token_publico', token);
  if (error) return res.status(500).json({ error: 'No disponible' });
  const r = (data || [])[0];
  if (!r) return res.status(404).json({ error: 'No disponible' });
  res.json({
    titulo: r.titulo, raciones: r.raciones, ingredientes: r.ingredientes, etiquetas: r.etiquetas,
    categorias: r.categorias, pasos: r.pasos, origen: r.origen, source_url: r.source_url,
    video_id: r.video_id, image_url: r.image_url,
  });
});

app.get('/r/:token', (req, res) => {
  res.set('X-Robots-Tag', 'noindex, nofollow');
  res.sendFile(path.join(__dirname, 'public', 'r.html'));
});

app.post('/api/recipes', requireAuth, requirePerfil, async (req, res) => {
  try {
    const { titulo, ingredientes, etiquetas, categorias, raciones, pasos, origen, source_url, video_id, compartida, image_base64, image_mime } = req.body;
    if (!titulo || !titulo.trim()) return res.status(400).json({ error: 'Falta el título' });

    let image_url = null;
    if (image_base64) {
      const buf = Buffer.from(image_base64, 'base64');
      const ext = (image_mime || 'image/jpeg').split('/')[1] || 'jpg';
      const filename = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}.${ext}`;
      const { error: upErr } = await supabase.storage.from('images').upload(filename, buf, { contentType: image_mime || 'image/jpeg' });
      if (upErr) return res.status(500).json({ error: 'Error subiendo imagen: ' + upErr.message });
      const { data: pub } = supabase.storage.from('images').getPublicUrl(filename);
      image_url = pub.publicUrl;
    }

    const { data, error } = await supabase.from('recipes').insert([{
      titulo: titulo.trim(),
      ingredientes: ingredientes || [],
      etiquetas: etiquetas || [],
      categorias: limpiarCategorias(categorias),
      raciones: raciones || null,
      pasos: pasos || [],
      origen: origen || 'manual',
      source_url: source_url || null,
      video_id: video_id || null,
      image_url,
      propietario: req.perfil,
      compartida: !!compartida,
    }]).select();

    if (error) return res.status(500).json({ error: error.message });
    res.json(data[0]);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.patch('/api/recipes/:id/compartir', requireAuth, requirePerfil, async (req, res) => {
  const { data: rows, error: e1 } = await supabase.from('recipes').select('*').eq('id', req.params.id);
  if (e1) return res.status(500).json({ error: e1.message });
  const receta = (rows || [])[0];
  if (!receta) return res.status(404).json({ error: 'Receta no encontrada' });
  if (receta.propietario !== req.perfil) return res.status(403).json({ error: 'Solo quien guardó la receta puede cambiar esto' });
  const { data, error } = await supabase.from('recipes').update({ compartida: !!(req.body || {}).compartida }).eq('id', req.params.id).select();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data[0]);
});

app.patch('/api/recipes/:id/publico', requireAuth, requirePerfil, async (req, res) => {
  const { data: rows, error: e1 } = await supabase.from('recipes').select('*').eq('id', req.params.id);
  if (e1) return res.status(500).json({ error: e1.message });
  const receta = (rows || [])[0];
  if (!receta) return res.status(404).json({ error: 'Receta no encontrada' });
  if (receta.propietario !== req.perfil) return res.status(403).json({ error: 'Solo quien guardó la receta puede cambiar esto' });
  const activar = !!(req.body || {}).publica;
  // Si ya estaba activo se conserva el mismo enlace; al desactivar se borra y el enlace antiguo deja de funcionar.
  const token = activar ? (receta.token_publico || crypto.randomBytes(16).toString('hex')) : null;
  const { data, error } = await supabase.from('recipes').update({ token_publico: token }).eq('id', req.params.id).select();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data[0]);
});

app.delete('/api/recipes/:id', requireAuth, requirePerfil, async (req, res) => {
  const { data: rows, error: e1 } = await supabase.from('recipes').select('*').eq('id', req.params.id);
  if (e1) return res.status(500).json({ error: e1.message });
  const receta = (rows || [])[0];
  if (!receta) return res.status(404).json({ error: 'Receta no encontrada' });
  if (receta.propietario && receta.propietario !== req.perfil) {
    return res.status(403).json({ error: 'Solo quien guardó la receta puede borrarla' });
  }
  const { error } = await supabase.from('recipes').delete().eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true });
});

// ---------- IA ----------
function limpiarCategorias(lista) {
  return [...new Set((lista || []).map(c => String(c).toLowerCase().trim()).filter(c => CATEGORIAS.includes(c)))];
}

function parseJson(texto) {
  const clean = texto.trim().replace(/^```json/, '').replace(/^```/, '').replace(/```$/, '').trim();
  try {
    return JSON.parse(clean);
  } catch (e) {
    const first = clean.indexOf('{');
    const last = clean.lastIndexOf('}');
    if (first === -1 || last === -1) throw new Error('La IA no devolvió JSON: ' + clean.slice(0, 150));
    return JSON.parse(clean.slice(first, last + 1));
  }
}

async function preguntarIA(system, content) {
  const r = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': process.env.ANTHROPIC_API_KEY,
      'anthropic-version': '2023-06-01',
    },
    body: JSON.stringify({
      model: 'claude-sonnet-4-6',
      max_tokens: 2000,
      system,
      messages: [{ role: 'user', content }],
    }),
  });
  const data = await r.json();
  if (data.error) throw new Error(data.error.message);
  const textBlock = (data.content || []).find(b => b.type === 'text');
  if (!textBlock) throw new Error('Sin respuesta de texto de la IA');
  return parseJson(textBlock.text);
}

const REGLAS_ETIQUETAS =
  '"etiquetas" es una lista aparte con SOLO el nombre del ingrediente principal de cada uno, corto (1-3 palabras), en minusculas, sin cantidades ni unidades ni aclaraciones (ej: "salmon", "salsa de soja", "ajo"), con un elemento por cada ingrediente. ' +
  '"categorias" es la lista de categorias generales a las que pertenecen los ingredientes, elegidas UNICAMENTE de esta lista cerrada: ' + CATEGORIAS.join(', ') + '. ' +
  'Incluye cada categoria que aplique al menos a un ingrediente (ej: filetes de salmon -> "pescado"; salsa de soja -> "salsas y condimentos"), sin inventar ninguna fuera de la lista.';

const SYSTEM_RECETA =
  'Devuelve UNICAMENTE un objeto JSON valido, sin texto adicional, sin backticks ni markdown, con esta forma exacta: ' +
  '{"titulo": "string", "raciones": "string o null", "ingredientes": ["string", ...], "etiquetas": ["string", ...], "categorias": ["string", ...], "pasos": ["string", ...]}. ' +
  '"raciones" es el numero de personas/raciones si se menciona (ej: "4 personas"), o null si no se indica. ' +
  '"ingredientes" es la lista tal cual se usaria para cocinar, CON cantidades y unidades (ej: "800 g de filetes de salmon", "4 cucharadas de salsa de soja", "1 diente de ajo"), uno por elemento, conservando aclaraciones entre parentesis. ' +
  REGLAS_ETIQUETAS +
  ' Los pasos deben ser frases completas, una por elemento del array.';

const SYSTEM_CLASIFICAR =
  'Recibes una lista de ingredientes de cocina. Devuelve UNICAMENTE un objeto JSON valido, sin texto adicional ni markdown, con esta forma exacta: {"etiquetas": ["string", ...], "categorias": ["string", ...]}. ' +
  REGLAS_ETIQUETAS;

app.post('/api/analyze', requireAuth, requirePerfil, async (req, res) => {
  try {
    const { image_base64, image_mime, text } = req.body;
    const content = [];
    if (image_base64) {
      content.push({ type: 'image', source: { type: 'base64', media_type: image_mime || 'image/jpeg', data: image_base64 } });
      content.push({ type: 'text', text: 'Extrae la receta de esta foto (puede ser un plato, una libreta escrita a mano, o una página de un libro de cocina).' });
    } else {
      content.push({ type: 'text', text: 'Extrae la receta de este texto:\n\n' + (text || '') });
    }
    const parsed = await preguntarIA(SYSTEM_RECETA, content);
    parsed.categorias = limpiarCategorias(parsed.categorias);
    res.json(parsed);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ---------- leer recetas desde un enlace ----------
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36';

function esIpPrivada(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return a === 0 || a === 10 || a === 127 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || a >= 224;
  }
  if (net.isIPv6(ip)) {
    const l = ip.toLowerCase();
    return l === '::' || l === '::1' || l.startsWith('fc') || l.startsWith('fd') || l.startsWith('fe80') || l.startsWith('::ffff:');
  }
  return true;
}

// Evita que el servidor se use para entrar en redes internas (localhost, 10.x, 192.168.x, metadatos de la nube...).
// ALLOW_PRIVATE_URLS=1 solo se usa en pruebas locales.
async function comprobarUrlPublica(u) {
  if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new Error('Solo se admiten enlaces http o https');
  if (process.env.ALLOW_PRIVATE_URLS === '1') return;
  const host = u.hostname.replace(/^\[|\]$/g, '');
  let ips;
  try {
    ips = net.isIP(host) ? [host] : (await dns.lookup(host, { all: true })).map(r => r.address);
  } catch (e) {
    throw new Error('No se encuentra esa dirección web');
  }
  if (!ips.length || ips.some(esIpPrivada)) throw new Error('Ese enlace no es válido');
}

async function descargar(urlStr) {
  let u;
  try { u = new URL(urlStr); } catch (e) { throw new Error('El enlace no es válido'); }
  for (let i = 0; i < 5; i++) {
    await comprobarUrlPublica(u);
    let r;
    try {
      r = await fetch(u, {
        redirect: 'manual',
        signal: AbortSignal.timeout(15000),
        headers: { 'User-Agent': UA, 'Accept': 'text/html,application/xhtml+xml', 'Accept-Language': 'es-ES,es;q=0.9,en;q=0.5' },
      });
    } catch (e) {
      throw new Error('No se pudo abrir la página (' + (e.name === 'TimeoutError' ? 'tardó demasiado' : 'sin conexión') + ')');
    }
    const destino = r.headers.get('location');
    if (r.status >= 300 && r.status < 400 && destino) { u = new URL(destino, u); continue; }
    if (!r.ok) throw new Error('La web respondió con el error ' + r.status + ' (puede que bloquee lecturas automáticas)');
    const tipo = r.headers.get('content-type') || '';
    if (!/text\/html|text\/plain|application\/xhtml/.test(tipo)) throw new Error('El enlace no es una página web de texto');
    const buf = Buffer.from(await r.arrayBuffer());
    if (buf.length > 5 * 1024 * 1024) throw new Error('La página es demasiado grande');
    return { html: buf.toString('utf8'), url: u.toString() };
  }
  throw new Error('La página redirige demasiadas veces');
}

function cp(n) { try { return String.fromCodePoint(n); } catch (e) { return ''; } }
function decodificarEntidades(s) {
  return s.replace(/&nbsp;/g, ' ').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"')
    .replace(/&#39;|&apos;/g, "'").replace(/&#(\d+);/g, (m, n) => cp(+n)).replace(/&#x([0-9a-f]+);/gi, (m, h) => cp(parseInt(h, 16)))
    .replace(/&amp;/g, '&');
}

function htmlATexto(html) {
  return decodificarEntidades(
    html
      .replace(/<!--[\s\S]*?-->/g, ' ')
      .replace(/<(script|style|noscript|svg|template|head)[\s\S]*?<\/\1>/gi, ' ')
      .replace(/<\/(p|div|li|ul|ol|h[1-6]|tr|section|article|header|footer)>|<br\s*\/?>/gi, '\n')
      .replace(/<[^>]+>/g, ' ')
  ).split('\n').map(l => l.replace(/[ \t]+/g, ' ').trim()).filter(Boolean).join('\n');
}

// Muchas webs de recetas incluyen la receta ya estructurada (schema.org) dentro de la página.
function recetaJsonLd(html) {
  const re = /<script[^>]*type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi;
  let m;
  while ((m = re.exec(html))) {
    let data;
    try { data = JSON.parse(m[1].trim()); } catch (e) { continue; }
    const nodos = [];
    (function visitar(x) {
      if (Array.isArray(x)) x.forEach(visitar);
      else if (x && typeof x === 'object') { nodos.push(x); if (x['@graph']) visitar(x['@graph']); }
    })(data);
    const rec = nodos.find(n => [].concat(n['@type'] || []).includes('Recipe'));
    if (rec) return rec;
  }
  return null;
}

function pasosJsonLd(x) {
  if (!x) return [];
  if (typeof x === 'string') return [x];
  if (Array.isArray(x)) return x.flatMap(pasosJsonLd);
  if (x.itemListElement) return pasosJsonLd(x.itemListElement);
  return x.text ? [x.text] : (x.name ? [x.name] : []);
}

function textoDeReceta(rec) {
  const partes = ['Título: ' + (rec.name || '')];
  if (rec.recipeYield) partes.push('Raciones: ' + [].concat(rec.recipeYield).join(' '));
  if (rec.recipeIngredient) partes.push('Ingredientes:\n' + [].concat(rec.recipeIngredient).join('\n'));
  const pasos = pasosJsonLd(rec.recipeInstructions);
  if (pasos.length) partes.push('Pasos:\n' + pasos.join('\n'));
  return decodificarEntidades(partes.join('\n\n'));
}

function idYoutube(u) {
  const h = u.hostname.replace(/^www\.|^m\./, '');
  if (h === 'youtu.be') return u.pathname.slice(1).split('/')[0] || null;
  if (h === 'youtube.com') {
    if (u.pathname === '/watch') return u.searchParams.get('v');
    const m = u.pathname.match(/^\/(?:embed|shorts)\/([\w-]{6,})/);
    return m ? m[1] : null;
  }
  return null;
}

function datosYoutube(html) {
  const t = html.match(/<meta property="og:title" content="([^"]*)"/);
  const d = html.match(/"shortDescription":"((?:[^"\\]|\\.)*)"/);
  let descripcion = '';
  if (d) { try { descripcion = JSON.parse('"' + d[1] + '"'); } catch (e) { /* sin descripción */ } }
  // leido=false: YouTube no ha devuelto los datos del vídeo (bloqueo, aviso de cookies...)
  return { titulo: t ? decodificarEntidades(t[1]) : '', descripcion, leido: !!d };
}

// ---- subtítulos de YouTube (intento: puede fallar si YouTube bloquea al servidor) ----
function urlYoutubeValida(s) {
  try {
    const u = new URL(s);
    return u.protocol === 'https:' && /(^|\.)youtube\.com$/.test(u.hostname);
  } catch (e) { return false; }
}

function extraerJsonArray(html, clave) {
  const i = html.indexOf('"' + clave + '":[');
  if (i === -1) return null;
  const ini = html.indexOf('[', i);
  let prof = 0, enStr = false, esc = false;
  for (let k = ini; k < html.length; k++) {
    const c = html[k];
    if (enStr) { if (esc) esc = false; else if (c === '\\') esc = true; else if (c === '"') enStr = false; continue; }
    if (c === '"') enStr = true;
    else if (c === '[') prof++;
    else if (c === ']') {
      prof--;
      if (prof === 0) { try { return JSON.parse(html.slice(ini, k + 1)); } catch (e) { return null; } }
    }
  }
  return null;
}

function elegirPista(pistas) {
  const validas = (Array.isArray(pistas) ? pistas : []).filter(p => p && urlYoutubeValida(p.baseUrl));
  const es = validas.filter(p => /^es/i.test(p.languageCode || ''));
  const manual = l => l.find(p => p.kind !== 'asr');
  return manual(es) || es[0] || manual(validas) || validas[0] || null;
}

async function textoDePista(pista) {
  const u = new URL(pista.baseUrl);
  u.searchParams.set('fmt', 'json3');
  const r = await fetch(u, { redirect: 'manual', signal: AbortSignal.timeout(15000), headers: { 'User-Agent': UA, 'Accept-Language': 'es-ES,es;q=0.9' } });
  if (!r.ok) return '';
  const cuerpo = await r.text();
  if (!cuerpo.trim()) return '';
  let texto;
  try {
    const j = JSON.parse(cuerpo);
    texto = (j.events || []).map(ev => (ev.segs || []).map(s => s.utf8 || '').join('')).join(' ');
  } catch (e) {
    texto = [...cuerpo.matchAll(/<text[^>]*>([\s\S]*?)<\/text>/g)]
      .map(m => decodificarEntidades(decodificarEntidades(m[1])).replace(/<[^>]+>/g, '')).join(' ');
  }
  return texto.replace(/\s+/g, ' ').trim();
}

async function subtitulosYoutube(videoId, html) {
  const vias = [
    async () => extraerJsonArray(html || '', 'captionTracks'),
    async () => {
      const r = await fetch('https://www.youtube.com/youtubei/v1/player?prettyPrint=false', {
        method: 'POST', redirect: 'manual', signal: AbortSignal.timeout(15000),
        headers: { 'Content-Type': 'application/json', 'User-Agent': 'com.google.android.youtube/20.10.38 (Linux; U; Android 14) gzip' },
        body: JSON.stringify({ context: { client: { clientName: 'ANDROID', clientVersion: '20.10.38', androidSdkVersion: 34, hl: 'es' } }, videoId }),
      });
      if (!r.ok) return null;
      const d = await r.json();
      return (((d || {}).captions || {}).playerCaptionsTracklistRenderer || {}).captionTracks || null;
    },
  ];
  for (const via of vias) {
    try {
      const pista = elegirPista(await via());
      if (!pista) continue;
      const texto = await textoDePista(pista);
      if (texto.length >= 100) return texto.slice(0, 25000);
    } catch (e) { /* probamos la siguiente vía */ }
  }
  return '';
}

app.post('/api/importar-url', requireAuth, requirePerfil, async (req, res) => {
  try {
    const url = String((req.body || {}).url || '').trim();
    if (!url) return res.status(400).json({ error: 'Pega un enlace' });
    let u;
    try { u = new URL(url); } catch (e) { return res.status(400).json({ error: 'El enlace no es válido' }); }

    let texto;
    const extra = {};
    const videoId = idYoutube(u);
    if (videoId) {
      let html = '';
      try { html = (await descargar('https://www.youtube.com/watch?v=' + encodeURIComponent(videoId))).html; } catch (e) { /* se intenta igualmente por la otra vía */ }
      const y = datosYoutube(html);
      const desc = y.descripcion.trim();
      const descSirve = desc.length >= 150 && /ingredient/i.test(desc);

      let subs = '';
      if (!descSirve) subs = await subtitulosYoutube(videoId, html);

      if (!descSirve && !subs) {
        if (!y.leido) {
          return res.status(422).json({ error: 'YouTube no ha dejado leer ese vídeo desde el servidor (ni la descripción ni los subtítulos). Pega la transcripción o la descripción en el cuadro de abajo.' });
        }
        if (desc.length < 150) {
          const vista = desc.replace(/\s+/g, ' ').slice(0, 80);
          return res.status(422).json({ error: 'La descripción del vídeo es muy corta' + (vista ? ' (dice: «' + vista + '»)' : ' (está vacía)') + ' y no he podido leer sus subtítulos. Pega la transcripción en el cuadro de abajo.' });
        }
        // descripción larga sin receta y sin subtítulos: se intenta con lo que hay
      }
      texto = 'Título del vídeo: ' + y.titulo + '\n\nDescripción del vídeo:\n' + y.descripcion;
      if (subs) texto += '\n\nSubtítulos del vídeo (transcripción automática de lo que se dice):\n' + subs;
      extra.video_id = videoId;
    } else {
      const { html, url: final } = await descargar(url);
      const rec = recetaJsonLd(html);
      const plano = htmlATexto(html);
      if (!rec && plano.length < 300) {
        return res.status(422).json({ error: 'No he podido leer esa página (puede cargar el contenido con JavaScript o estar protegida). Pega el texto de la receta en el cuadro de abajo.' });
      }
      texto = rec
        ? 'DATOS ESTRUCTURADOS DE LA RECETA:\n' + textoDeReceta(rec) + '\n\nTEXTO DE LA PÁGINA (por si falta algo):\n' + plano.slice(0, 8000)
        : plano.slice(0, 25000);
      extra.source_url = final;
    }

    const parsed = await preguntarIA(SYSTEM_RECETA, [{ type: 'text', text: 'Extrae la receta de este texto:\n\n' + texto }]);
    parsed.categorias = limpiarCategorias(parsed.categorias);
    res.json({ ...parsed, ...extra });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/clasificar', requireAuth, requirePerfil, async (req, res) => {
  try {
    const ingredientes = ((req.body || {}).ingredientes || []).filter(Boolean);
    if (!ingredientes.length) return res.status(400).json({ error: 'No hay ingredientes' });
    const parsed = await preguntarIA(SYSTEM_CLASIFICAR, [{ type: 'text', text: 'Ingredientes:\n' + ingredientes.join('\n') }]);
    res.json({ etiquetas: parsed.etiquetas || [], categorias: limpiarCategorias(parsed.categorias) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('Recetario escuchando en el puerto ' + PORT));
