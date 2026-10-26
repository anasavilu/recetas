require('dotenv').config();
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
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
  res.json(visibles);
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
