
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3001;
const SECRET = process.env.JWT_SECRET || 'aventurizer-ultra-secret-key-2024';

// Conexão com o banco de dados
const dbPath = path.resolve(__dirname, 'database.sqlite');
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) console.error('Erro ao abrir banco SQLite:', err.message);
  else console.log('SQLite conectado conforme estrutura CSV em:', dbPath);
});

// Inicialização das Tabelas baseada no CSV fornecido
db.serialize(() => {
  // Usuários
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE,
    password_hash TEXT,
    role TEXT
  )`);

  // Sessões de Jogo
  db.run(`CREATE TABLE IF NOT EXISTS game_sessions (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    gm_id TEXT,
    map_url TEXT,
    status TEXT,
    active_image_id TEXT,
    active_video_id TEXT,
    updated_at INTEGER
  )`);

  // Tokens
  db.run(`CREATE TABLE IF NOT EXISTS tokens (
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
    stats TEXT,
    inventory TEXT,
    status_effects TEXT,
    FOREIGN KEY(session_id) REFERENCES game_sessions(id)
  )`);

  // Paredes (Walls)
  db.run(`CREATE TABLE IF NOT EXISTS walls (
    id TEXT PRIMARY KEY,
    session_id TEXT,
    x REAL,
    y REAL,
    width REAL,
    height REAL,
    FOREIGN KEY(session_id) REFERENCES game_sessions(id)
  )`);

  // Nevoeiro (Fogs)
  db.run(`CREATE TABLE IF NOT EXISTS fogs (
    id TEXT PRIMARY KEY,
    session_id TEXT,
    x REAL,
    y REAL,
    width REAL,
    height REAL,
    FOREIGN KEY(session_id) REFERENCES game_sessions(id)
  )`);

  // Anotações
  db.run(`CREATE TABLE IF NOT EXISTS annotations (
    id TEXT PRIMARY KEY,
    session_id TEXT,
    x REAL,
    y REAL,
    title TEXT,
    content TEXT,
    is_revealed BOOLEAN,
    attached_item_data TEXT,
    FOREIGN KEY(session_id) REFERENCES game_sessions(id)
  )`);

  // Biblioteca de Mídia
  db.run(`CREATE TABLE IF NOT EXISTS library_images (id TEXT PRIMARY KEY, session_id TEXT, title TEXT, url TEXT, owner_id TEXT)`);
  db.run(`CREATE TABLE IF NOT EXISTS library_videos (id TEXT PRIMARY KEY, session_id TEXT, title TEXT, url TEXT)`);
  db.run(`CREATE TABLE IF NOT EXISTS library_sounds (id TEXT PRIMARY KEY, session_id TEXT, name TEXT, shortcut_key TEXT, url TEXT)`);
  
  // Logs de Interação (Gemini)
  db.run(`CREATE TABLE IF NOT EXISTS interaction_logs (id TEXT PRIMARY KEY, username TEXT, message TEXT, response TEXT)`);
});

app.use(cors());
app.use(express.json({ limit: '50mb' }));

// Middleware de Autenticação
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token não fornecido.' });

  jwt.verify(token, SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Token expirado ou inválido.' });
    req.user = user;
    next();
  });
};

// --- AUTH ROUTES ---

app.post('/api/register', async (req, res) => {
  const { username, password, role } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const id = Date.now().toString();
    db.run(`INSERT INTO users (id, username, password_hash, role) VALUES (?, ?, ?, ?)`, 
    [id, username, hashedPassword, role || 'player'], (err) => {
      if (err) return res.status(400).json({ error: "Usuário já existe." });
      res.status(201).json({ message: "Conta criada." });
    });
  } catch (e) {
    res.status(500).json({ error: "Erro no servidor." });
  }
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
    if (err || !user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: "Credenciais inválidas." });
    }
    const token = jwt.sign({ name: user.username, role: user.role }, SECRET);
    res.json({ token, user: { name: user.username, role: user.role } });
  });
});

// --- GAME ROUTES ---

app.get('/api/sessions', authenticateToken, (req, res) => {
  db.all(`SELECT id, name, gm_id as gmId, status, map_url as mapUrl FROM game_sessions`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows || []);
  });
});

app.get('/api/game/:sessionId', authenticateToken, async (req, res) => {
  const { sessionId } = req.params;
  const since = parseInt(req.query.since) || 0;

  db.get(`SELECT * FROM game_sessions WHERE id = ?`, [sessionId], async (err, session) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!session) return res.status(404).json({ error: "Mesa não encontrada." });

    if (session.updated_at <= since) {
      return res.json({ notModified: true });
    }

    try {
      // Carregar todos os componentes da mesa em paralelo
      const tokens = await new Promise((resolve) => db.all(`SELECT * FROM tokens WHERE session_id = ?`, [sessionId], (err, rows) => resolve(rows || [])));
      const walls = await new Promise((resolve) => db.all(`SELECT * FROM walls WHERE session_id = ?`, [sessionId], (err, rows) => resolve(rows || [])));
      const fogs = await new Promise((resolve) => db.all(`SELECT * FROM fogs WHERE session_id = ?`, [sessionId], (err, rows) => resolve(rows || [])));
      const annotations = await new Promise((resolve) => db.all(`SELECT * FROM annotations WHERE session_id = ?`, [sessionId], (err, rows) => resolve(rows || [])));
      const images = await new Promise((resolve) => db.all(`SELECT * FROM library_images WHERE session_id = ?`, [sessionId], (err, rows) => resolve(rows || [])));
      const videos = await new Promise((resolve) => db.all(`SELECT * FROM library_videos WHERE session_id = ?`, [sessionId], (err, rows) => resolve(rows || [])));
      const sounds = await new Promise((resolve) => db.all(`SELECT * FROM library_sounds WHERE session_id = ?`, [sessionId], (err, rows) => resolve(rows || [])));

      // Mapear campos SQLite para campos do Frontend (camelCase)
      const mappedTokens = tokens.map(t => ({
        ...t,
        maxHp: t.max_hp, maxSan: t.max_san, maxWeight: t.max_weight, ownerId: t.owner_id,
        stats: JSON.parse(t.stats || "{}"),
        inventory: JSON.parse(t.inventory || "[]"),
        statusEffects: JSON.parse(t.status_effects || "[]"),
        active: !!t.active
      }));

      const mappedAnnotations = annotations.map(a => ({
        ...a,
        isRevealed: !!a.is_revealed,
        attachedItem: JSON.parse(a.attached_item_data || "null")
      }));

      const mappedSounds = sounds.map(s => ({ ...s, key: s.shortcut_key }));

      res.json({
        id: session.id,
        name: session.name,
        status: session.status,
        mapUrl: session.map_url,
        activeImageId: session.active_image_id,
        activeVideoId: session.active_video_id,
        tokens: mappedTokens,
        walls,
        fog: fogs,
        annotations: mappedAnnotations,
        images,
        videos,
        sounds: mappedSounds,
        timestamp: session.updated_at
      });

    } catch (e) {
      console.error(e);
      res.status(500).json({ error: "Erro ao reconstruir estado da mesa." });
    }
  });
});

app.post('/api/game', authenticateToken, (req, res) => {
  const { id, name, status, mapUrl, activeImageId, activeVideoId, tokens, walls, fog, annotations, images, videos, sounds } = req.body;
  const timestamp = Date.now();

  db.serialize(() => {
    db.run("BEGIN TRANSACTION");

    // Upsert game_sessions
    db.run(`INSERT INTO game_sessions (id, name, gm_id, status, map_url, active_image_id, active_video_id, updated_at) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?) 
            ON CONFLICT(id) DO UPDATE SET 
            name=excluded.name, status=excluded.status, map_url=excluded.map_url, 
            active_image_id=excluded.active_image_id, active_video_id=excluded.active_video_id, updated_at=excluded.updated_at`,
    [id, name, req.user.name, status, mapUrl, activeImageId || null, activeVideoId || null, timestamp]);

    // Limpar e reinserir componentes vinculados (Mais simples que Upsert para coleções dinâmicas)
    db.run(`DELETE FROM tokens WHERE session_id = ?`, [id]);
    if (tokens) {
      const tokenStmt = db.prepare(`INSERT INTO tokens (id, session_id, owner_id, name, url, role, active, x, y, size, hp, max_hp, san, max_san, max_weight, stats, inventory, status_effects) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`);
      tokens.forEach(t => tokenStmt.run(t.id, id, t.ownerId || '', t.name, t.url, t.role, t.active, t.x, t.y, t.size, t.hp, t.maxHp, t.san, t.maxSan, t.maxWeight, JSON.stringify(t.stats), JSON.stringify(t.inventory), JSON.stringify(t.statusEffects)));
      tokenStmt.finalize();
    }

    db.run(`DELETE FROM walls WHERE session_id = ?`, [id]);
    if (walls) {
      const wallStmt = db.prepare(`INSERT INTO walls (id, session_id, x, y, width, height) VALUES (?,?,?,?,?,?)`);
      walls.forEach(w => wallStmt.run(w.id, id, w.x, w.y, w.width, w.height));
      wallStmt.finalize();
    }

    db.run(`DELETE FROM fogs WHERE session_id = ?`, [id]);
    if (fog) {
      const fogStmt = db.prepare(`INSERT INTO fogs (id, session_id, x, y, width, height) VALUES (?,?,?,?,?,?)`);
      fog.forEach(f => fogStmt.run(f.id, id, f.x, f.y, f.width, f.height));
      fogStmt.finalize();
    }

    db.run(`DELETE FROM annotations WHERE session_id = ?`, [id]);
    if (annotations) {
      const annStmt = db.prepare(`INSERT INTO annotations (id, session_id, x, y, title, content, is_revealed, attached_item_data) VALUES (?,?,?,?,?,?,?,?)`);
      annotations.forEach(a => annStmt.run(a.id, id, a.x, a.y, a.title, a.content, a.isRevealed, JSON.stringify(a.attachedItem)));
      annStmt.finalize();
    }

    // Mídia
    db.run(`DELETE FROM library_images WHERE session_id = ?`, [id]);
    if (images) {
      const imgStmt = db.prepare(`INSERT INTO library_images (id, session_id, title, url, owner_id) VALUES (?,?,?,?,?)`);
      images.forEach(img => imgStmt.run(img.id, id, img.title, img.url, img.ownerId || ''));
      imgStmt.finalize();
    }
    
    db.run(`DELETE FROM library_videos WHERE session_id = ?`, [id]);
    if (videos) {
      const vidStmt = db.prepare(`INSERT INTO library_videos (id, session_id, title, url) VALUES (?,?,?,?)`);
      videos.forEach(v => vidStmt.run(v.id, id, v.title, v.url));
      vidStmt.finalize();
    }

    db.run(`DELETE FROM library_sounds WHERE session_id = ?`, [id]);
    if (sounds) {
      const sndStmt = db.prepare(`INSERT INTO library_sounds (id, session_id, name, shortcut_key, url) VALUES (?,?,?,?,?)`);
      sounds.forEach(s => sndStmt.run(s.id, id, s.name, s.key, s.url));
      sndStmt.finalize();
    }

    db.run("COMMIT", (err) => {
      if (err) return res.status(500).json({ error: "Erro ao confirmar transação." });
      res.json({ sessionId: id, timestamp });
    });
  });
});

app.get('/api/my-characters', authenticateToken, (req, res) => {
  db.all(`SELECT * FROM tokens WHERE owner_id = ? OR name LIKE ?`, [req.user.name, `%${req.user.name}%`], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    const mapped = (rows || []).map(t => ({
        ...t,
        maxHp: t.max_hp, maxSan: t.max_san, maxWeight: t.max_weight, ownerId: t.owner_id,
        stats: JSON.parse(t.stats || "{}"),
        inventory: JSON.parse(t.inventory || "[]"),
        statusEffects: JSON.parse(t.status_effects || "[]"),
        active: !!t.active
    }));
    res.json(mapped);
  });
});

app.post('/api/interaction-log', authenticateToken, (req, res) => {
  const { message, response } = req.body;
  const id = Date.now().toString();
  db.run(`INSERT INTO interaction_logs (id, username, message, response) VALUES (?,?,?,?)`, 
  [id, req.user.name, message, response], () => {
    res.sendStatus(200);
  });
});

app.listen(PORT, () => {
  console.log(`Servidor Aventurizer Normalizado Online na porta ${PORT}`);
});
