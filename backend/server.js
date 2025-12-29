
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3001;
const SECRET = process.env.JWT_SECRET || 'aventurizer-ultra-secret-key-2024';

// Configuração do Pool do PostgreSQL (DATABASE_URL injetada pelo Render)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

// Inicialização automática das tabelas no PostgreSQL (Migrations)
const initDb = async () => {
  const client = await pool.connect();
  try {
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

      CREATE TABLE IF NOT EXISTS walls (
        id TEXT PRIMARY KEY,
        session_id TEXT,
        x REAL, y REAL, width REAL, height REAL
      );

      CREATE TABLE IF NOT EXISTS fogs (
        id TEXT PRIMARY KEY,
        session_id TEXT,
        x REAL, y REAL, width REAL, height REAL
      );

      CREATE TABLE IF NOT EXISTS annotations (
        id TEXT PRIMARY KEY,
        session_id TEXT,
        x REAL, y REAL,
        title TEXT,
        content TEXT,
        is_revealed BOOLEAN,
        attached_item_data JSONB
      );

      CREATE TABLE IF NOT EXISTS library_images (id TEXT PRIMARY KEY, session_id TEXT, title TEXT, url TEXT, owner_id TEXT);
      CREATE TABLE IF NOT EXISTS library_videos (id TEXT PRIMARY KEY, session_id TEXT, title TEXT, url TEXT);
      CREATE TABLE IF NOT EXISTS library_sounds (id TEXT PRIMARY KEY, session_id TEXT, name TEXT, shortcut_key TEXT, url TEXT);
      CREATE TABLE IF NOT EXISTS interaction_logs (id TEXT PRIMARY KEY, username TEXT, message TEXT, response TEXT);
    `);
    console.log("Banco de Dados PostgreSQL inicializado com sucesso.");
  } catch (err) {
    console.error("Erro ao inicializar tabelas:", err);
  } finally {
    client.release();
  }
};

initDb();

app.use(cors());
app.use(express.json({ limit: '50mb' }));

// Middleware de Autenticação
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Sessão inválida. Faça login.' });

  jwt.verify(token, SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Sessão expirada. Faça login novamente.' });
    req.user = user;
    next();
  });
};

// --- HEALTH CHECK ---
app.get('/api/health', async (req, res) => {
  try {
    const result = await pool.query('SELECT NOW()');
    res.json({ status: 'ok', db: 'connected', time: result.rows[0].now });
  } catch (e) {
    res.status(500).json({ status: 'error', db: 'disconnected', message: e.message });
  }
});

// --- AUTH ---

app.post('/api/register', async (req, res) => {
  const { username, password, role } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Dados incompletos." });
  
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const id = Date.now().toString();
    
    await pool.query(
      'INSERT INTO users (id, username, password_hash, role) VALUES ($1, $2, $3, $4)',
      [id, username.trim(), hashedPassword, role || 'player']
    );
    
    res.status(201).json({ message: "Conta criada com sucesso." });
  } catch (e) {
    if (e.code === '23505') return res.status(400).json({ error: "Este usuário já existe." });
    res.status(500).json({ error: "Erro ao criar usuário." });
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Preencha todos os campos." });

  try {
    const result = await pool.query('SELECT * FROM users WHERE LOWER(username) = LOWER($1)', [username.trim()]);
    const user = result.rows[0];

    if (!user) {
      return res.status(401).json({ error: "Credenciais inválidas." });
    }

    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: "Credenciais inválidas." });
    }

    const token = jwt.sign({ name: user.username, role: user.role }, SECRET, { expiresIn: '24h' });
    res.json({ token, user: { name: user.username, role: user.role } });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro de conexão com o banco de dados." });
  }
});

// Fix: Added endpoint for password change
app.post('/api/change-password', authenticateToken, async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  const username = req.user.name;

  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    const user = result.rows[0];

    const validPassword = await bcrypt.compare(oldPassword, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: "Senha atual incorreta." });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE users SET password_hash = $1 WHERE username = $2', [hashedPassword, username]);

    res.json({ message: "Senha alterada com sucesso." });
  } catch (e) {
    res.status(500).json({ error: "Erro ao alterar senha." });
  }
});

// Fix: Added endpoint for logging AI interactions
app.post('/api/log', authenticateToken, async (req, res) => {
  const { username, message, response } = req.body;
  const id = Date.now().toString() + Math.random().toString().substring(2, 6);
  try {
    await pool.query(
      'INSERT INTO interaction_logs (id, username, message, response) VALUES ($1, $2, $3, $4)',
      [id, username, message, response]
    );
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: "Erro ao logar interação." });
  }
});

// --- GAME LOGIC ---

app.get('/api/sessions', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, name, gm_id as "gmId", status, map_url as "mapUrl" FROM game_sessions');
    res.json(result.rows || []);
  } catch (e) {
    res.status(500).json({ error: "Erro ao carregar sessões." });
  }
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
        ...t,
        maxHp: t.max_hp, maxSan: t.max_san, maxWeight: t.max_weight, ownerId: t.owner_id,
        stats: t.stats || {},
        inventory: t.inventory || [],
        statusEffects: t.status_effects || [],
        active: !!t.active
      })),
      walls: walls.rows,
      fog: fogs.rows,
      annotations: annotations.rows.map(a => ({
        ...a,
        isRevealed: !!a.is_revealed,
        attachedItem: a.attached_item_data || null
      })),
      images: images.rows,
      videos: videos.rows,
      sounds: sounds.rows.map(s => ({ ...s, key: s.shortcut_key })),
      timestamp: session.updated_at
    });
  } catch (e) {
    res.status(500).json({ error: "Erro ao carregar dados da mesa." });
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
        await client.query(`
          INSERT INTO tokens (id, session_id, owner_id, name, url, role, active, x, y, size, hp, max_hp, san, max_san, max_weight, stats, inventory, status_effects) 
          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)`,
          [t.id, id, t.ownerId || '', t.name, t.url, t.role, t.active, t.x, t.y, t.size, t.hp, t.maxHp, t.san, t.maxSan, t.maxWeight, t.stats, t.inventory, t.statusEffects]
        );
      }
    }

    await client.query('DELETE FROM walls WHERE session_id = $1', [id]);
    if (walls) {
      for (const w of walls) {
        await client.query('INSERT INTO walls (id, session_id, x, y, width, height) VALUES ($1, $2, $3, $4, $5, $6)', [w.id, id, w.x, w.y, w.width, w.height]);
      }
    }

    await client.query('DELETE FROM fogs WHERE session_id = $1', [id]);
    if (fog) {
      for (const f of fog) {
        await client.query('INSERT INTO fogs (id, session_id, x, y, width, height) VALUES ($1, $2, $3, $4, $5, $6)', [f.id, id, f.x, f.y, f.width, f.height]);
      }
    }

    await client.query('DELETE FROM annotations WHERE session_id = $1', [id]);
    if (annotations) {
      for (const a of annotations) {
        await client.query('INSERT INTO annotations (id, session_id, x, y, title, content, is_revealed, attached_item_data) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)', [a.id, id, a.x, a.y, a.title, a.content, a.isRevealed, a.attachedItem]);
      }
    }

    await client.query('DELETE FROM library_images WHERE session_id = $1', [id]);
    if (images) {
      for (const img of images) {
        await client.query('INSERT INTO library_images (id, session_id, title, url, owner_id) VALUES ($1, $2, $3, $4, $5)', [img.id, id, img.title, img.url, img.ownerId || '']);
      }
    }
    
    await client.query('DELETE FROM library_videos WHERE session_id = $1', [id]);
    if (videos) {
      for (const v of videos) {
        await client.query('INSERT INTO library_videos (id, session_id, title, url) VALUES ($1, $2, $3, $4)', [v.id, id, v.title, v.url]);
      }
    }

    await client.query('DELETE FROM library_sounds WHERE session_id = $1', [id]);
    if (sounds) {
      for (const s of sounds) {
        await client.query('INSERT INTO library_sounds (id, session_id, name, shortcut_key, url) VALUES ($1, $2, $3, $4, $5)', [s.id, id, s.name, s.key, s.url]);
      }
    }

    await client.query('COMMIT');
    res.json({ sessionId: id, timestamp });
  } catch (e) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: "Erro ao salvar alterações." });
  } finally {
    client.release();
  }
});

app.get('/api/my-characters', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM tokens WHERE LOWER(owner_id) = LOWER($1)', [req.user.name]);
    res.json(result.rows.map(t => ({
      ...t,
      maxHp: t.max_hp, maxSan: t.max_san, maxWeight: t.max_weight, ownerId: t.owner_id,
      stats: t.stats || {},
      inventory: t.inventory || [],
      statusEffects: t.status_effects || [],
      active: !!t.active
    })));
  } catch (e) {
    res.status(500).json({ error: "Erro ao buscar personagens." });
  }
});

app.listen(PORT, () => {
  console.log(`Backend online na porta ${PORT}`);
});
