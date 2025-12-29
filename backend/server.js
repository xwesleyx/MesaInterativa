
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3001;
const SECRET = process.env.JWT_SECRET || 'aventurizer-v3-secret-key-2025';

// Configuração PostgreSQL para Render/Heroku
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Migrações e Inicialização do Banco
const initDb = async () => {
  const client = await pool.connect();
  try {
    console.log("Iniciando Tabelas PostgreSQL...");
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS game_sessions (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        gm_id TEXT,
        status TEXT,
        map_url TEXT,
        active_image_id TEXT,
        active_video_id TEXT,
        updated_at BIGINT
      );

      CREATE TABLE IF NOT EXISTS tokens (
        id TEXT PRIMARY KEY,
        session_id TEXT,
        owner_id TEXT,
        name TEXT,
        url TEXT,
        role TEXT,
        active BOOLEAN,
        x REAL,
        y REAL,
        size REAL,
        hp INTEGER,
        max_hp INTEGER,
        san INTEGER,
        max_san INTEGER,
        max_weight INTEGER,
        stats JSONB,
        inventory JSONB,
        status_effects JSONB
      );

      CREATE TABLE IF NOT EXISTS walls (id TEXT PRIMARY KEY, session_id TEXT, x REAL, y REAL, width REAL, height REAL);
      CREATE TABLE IF NOT EXISTS fogs (id TEXT PRIMARY KEY, session_id TEXT, x REAL, y REAL, width REAL, height REAL);
      CREATE TABLE IF NOT EXISTS annotations (
        id TEXT PRIMARY KEY, session_id TEXT, x REAL, y REAL,
        title TEXT, content TEXT, is_revealed BOOLEAN, attached_item_data JSONB
      );

      CREATE TABLE IF NOT EXISTS library_images (id TEXT PRIMARY KEY, session_id TEXT, title TEXT, url TEXT, owner_id TEXT);
      CREATE TABLE IF NOT EXISTS library_videos (id TEXT PRIMARY KEY, session_id TEXT, title TEXT, url TEXT);
      CREATE TABLE IF NOT EXISTS library_sounds (id TEXT PRIMARY KEY, session_id TEXT, name TEXT, shortcut_key TEXT, url TEXT);
      CREATE TABLE IF NOT EXISTS interaction_logs (id TEXT PRIMARY KEY, username TEXT, message TEXT, response TEXT, timestamp BIGINT);
    `);
    console.log("Banco de Dados Pronto.");
  } catch (err) {
    console.error("Erro no DB:", err);
  } finally {
    client.release();
  }
};

initDb();

app.use(cors());
app.use(express.json({ limit: '50mb' }));

// Middleware de Auth
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token ausente.' });
  jwt.verify(token, SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Sessão expirada.' });
    req.user = user;
    next();
  });
};

// Endpoints
app.get('/api/health', (req, res) => res.json({ status: 'ok', server: 'online' }));

app.post('/api/register', async (req, res) => {
  const { username, password, role } = req.body;
  try {
    const hash = await bcrypt.hash(password, 10);
    await pool.query(
      'INSERT INTO users (id, username, password_hash, role) VALUES ($1, $2, $3, $4)',
      [Date.now().toString(), username.trim(), hash, role || 'player']
    );
    res.status(201).json({ success: true });
  } catch (e) {
    res.status(400).json({ error: "Usuário já existe." });
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE LOWER(username) = LOWER($1)', [username.trim()]);
    const user = result.rows[0];
    if (user && await bcrypt.compare(password, user.password_hash)) {
      const token = jwt.sign({ name: user.username, role: user.role }, SECRET, { expiresIn: '24h' });
      return res.json({ token, user: { name: user.username, role: user.role } });
    }
    res.status(401).json({ error: "Credenciais inválidas." });
  } catch (e) {
    res.status(500).json({ error: "Erro no servidor." });
  }
});

app.get('/api/sessions', authenticateToken, async (req, res) => {
  const result = await pool.query('SELECT id, name, gm_id as "gmId", status, map_url as "mapUrl" FROM game_sessions');
  res.json(result.rows || []);
});

app.get('/api/game/:sessionId', authenticateToken, async (req, res) => {
  const { sessionId } = req.params;
  const since = parseInt(req.query.since) || 0;
  try {
    const sessionRes = await pool.query('SELECT * FROM game_sessions WHERE id = $1', [sessionId]);
    const session = sessionRes.rows[0];
    if (!session) return res.status(404).json({ error: "Mesa não encontrada." });
    if (session.updated_at <= since) return res.json({ notModified: true });

    const [tokens, walls, fogs, annotations, images, videos, sounds] = await Promise.all([
      pool.query('SELECT * FROM tokens WHERE session_id = $1', [sessionId]),
      pool.query('SELECT * FROM walls WHERE session_id = $1', [sessionId]),
      pool.query('SELECT * FROM fogs WHERE session_id = $1', [sessionId]),
      pool.query('SELECT * FROM annotations WHERE session_id = $1', [sessionId]),
      pool.query('SELECT * FROM library_images WHERE session_id = $1', [sessionId]),
      pool.query('SELECT * FROM library_videos WHERE session_id = $1', [sessionId]),
      pool.query('SELECT * FROM library_sounds WHERE session_id = $1', [sessionId])
    ]);

    res.json({
      id: session.id,
      name: session.name,
      status: session.status,
      mapUrl: session.map_url,
      activeImageId: session.active_image_id,
      activeVideoId: session.active_video_id,
      tokens: tokens.rows.map(t => ({
        ...t, ownerId: t.owner_id, stats: t.stats || {}, inventory: t.inventory || [], statusEffects: t.status_effects || [], active: !!t.active, maxHp: t.max_hp, maxSan: t.max_san, maxWeight: t.max_weight
      })),
      walls: walls.rows,
      fog: fogs.rows,
      annotations: annotations.rows.map(a => ({ ...a, isRevealed: !!a.is_revealed, attachedItem: a.attached_item_data })),
      images: images.rows,
      videos: videos.rows,
      sounds: sounds.rows.map(s => ({ ...s, key: s.shortcut_key })),
      timestamp: session.updated_at
    });
  } catch (e) {
    res.status(500).json({ error: "Erro interno." });
  }
});

app.post('/api/game', authenticateToken, async (req, res) => {
  const { id, name, status, mapUrl, activeImageId, activeVideoId, tokens, walls, fog, annotations, images, videos, sounds } = req.body;
  const timestamp = Date.now();
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`
      INSERT INTO game_sessions (id, name, gm_id, status, map_url, active_image_id, active_video_id, updated_at) 
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8) 
      ON CONFLICT(id) DO UPDATE SET 
      name=EXCLUDED.name, status=EXCLUDED.status, map_url=EXCLUDED.map_url, 
      active_image_id=EXCLUDED.active_image_id, active_video_id=EXCLUDED.active_video_id, updated_at=EXCLUDED.updated_at`,
      [id, name, req.user.name, status, mapUrl, activeImageId || null, activeVideoId || null, timestamp]
    );

    await client.query('DELETE FROM tokens WHERE session_id = $1', [id]);
    if (tokens) {
      for (const t of tokens) {
        await client.query('INSERT INTO tokens (id, session_id, owner_id, name, url, role, active, x, y, size, hp, max_hp, san, max_san, max_weight, stats, inventory, status_effects) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)',
          [t.id, id, t.ownerId || '', t.name, t.url, t.role, t.active, t.x, t.y, t.size, t.hp, t.maxHp, t.san, t.maxSan, t.maxWeight, t.stats, t.inventory, t.statusEffects]);
      }
    }
    // Delete and Re-insert for simplicity in this VTT version
    await client.query('DELETE FROM walls WHERE session_id = $1', [id]);
    if (walls) for (const w of walls) await client.query('INSERT INTO walls (id, session_id, x, y, width, height) VALUES ($1,$2,$3,$4,$5,$6)', [w.id, id, w.x, w.y, w.width, w.height]);

    await client.query('COMMIT');
    res.json({ sessionId: id, timestamp });
  } catch (e) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: e.message });
  } finally {
    client.release();
  }
});

app.listen(PORT, () => console.log(`Aventurizer V3 Backend na porta ${PORT}`));
