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

function requireAuth(req, res, next) {
  if (req.headers['x-app-token'] !== TOKEN) return res.status(401).json({ error: 'No autorizado' });
  next();
}

app.post('/api/login', (req, res) => {
  const { pin } = req.body || {};
  if (pin === APP_PIN) return res.json({ token: TOKEN });
  res.status(401).json({ error: 'PIN incorrecto' });
});

app.get('/api/recipes', requireAuth, async (req, res) => {
  const { data, error } = await supabase.from('recipes').select('*').order('creado', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/recipes', requireAuth, async (req, res) => {
  try {
    const { titulo, ingredientes, pasos, origen, source_url, video_id, image_base64, image_mime } = req.body;
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
      pasos: pasos || [],
      origen: origen || 'manual',
      source_url: source_url || null,
      video_id: video_id || null,
      image_url,
    }]).select();

    if (error) return res.status(500).json({ error: error.message });
    res.json(data[0]);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/recipes/:id', requireAuth, async (req, res) => {
  const { error } = await supabase.from('recipes').delete().eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true });
});

app.post('/api/analyze', requireAuth, async (req, res) => {
  try {
    const { image_base64, image_mime, text } = req.body;
    const content = [];
    if (image_base64) {
      content.push({ type: 'image', source: { type: 'base64', media_type: image_mime || 'image/jpeg', data: image_base64 } });
      content.push({ type: 'text', text: 'Extrae la receta de esta foto (puede ser un plato, una libreta escrita a mano, o una página de un libro de cocina).' });
    } else {
      content.push({ type: 'text', text: 'Extrae la receta de este texto:\n\n' + (text || '') });
    }

    const r = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-6',
        max_tokens: 1500,
        system: 'Devuelve UNICAMENTE un objeto JSON valido, sin texto adicional, sin backticks ni markdown, con esta forma exacta: {"titulo": "string", "ingredientes": ["string", ...], "pasos": ["string", ...]}. Los ingredientes deben ser cortos (2-4 palabras), en minusculas, sin cantidades ni unidades, solo el nombre del ingrediente, pensados para usarse como etiquetas de busqueda. Los pasos deben ser frases completas, una por elemento del array.',
        messages: [{ role: 'user', content }],
      }),
    });
    const data = await r.json();
    if (data.error) return res.status(500).json({ error: data.error.message });

    const textBlock = (data.content || []).find(b => b.type === 'text');
    if (!textBlock) return res.status(500).json({ error: 'Sin respuesta de texto de la IA' });

    let clean = textBlock.text.trim().replace(/^```json/, '').replace(/^```/, '').replace(/```$/, '').trim();
    let parsed;
    try {
      parsed = JSON.parse(clean);
    } catch (e) {
      const first = clean.indexOf('{');
      const last = clean.lastIndexOf('}');
      if (first === -1 || last === -1) throw new Error('La IA no devolvió JSON: ' + clean.slice(0, 150));
      parsed = JSON.parse(clean.slice(first, last + 1));
    }
    res.json(parsed);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('Recetario escuchando en el puerto ' + PORT));
