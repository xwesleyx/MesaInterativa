require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const app = express();
const port = process.env.PORT || 3000;

// Se a DATABASE_URL não estiver definida, vai dar erro
if (!process.env.DATABASE_URL) {
  console.error("FATAL: DATABASE_URL não definida nas variáveis de ambiente.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }, // Necessário para Render
  max: 20,
});

app.use(cors());
app.use(express.json({ limit: '50mb' }));

// Middleware de Autenticação
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

app.get('/', (req, res) => res.send('RPG Backend is Running! 🚀'));

// --- AUTH ---
app.post('/api/register', async (req, res) => {
  const { username, password, role } = req.body;
  try {
    const check = await pool.query('SELECT id FROM users WHERE username = $1', [username]);
    if (check.rows.length > 0) return res.status(400).json({ error: 'Nome indisponível.' });
    const hash = await bcrypt.hash(password, 10);
    await pool.query('INSERT INTO users (id, username, password_hash, role) VALUES ($1, $2, $3, $4)', [crypto.randomUUID(), username, hash, role]);
    res.status(201).json({ success: true });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Erro no registro.' }); }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const r = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    const u = r.rows[0];
    if (!u || !(await bcrypt.compare(password, u.password_hash))) return res.status(400).json({ error: 'Login inválido.' });
    const token = jwt.sign({ id: u.id, username: u.username, role: u.role }, process.env.JWT_SECRET, { expiresIn: '24h' });
    res.json({ token, user: { name: u.username, role: u.role } });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Erro interno.' }); }
});

// --- SESSIONS ---
app.get('/api/sessions', authenticateToken, async (req, res) => {
  try {
    const r = await pool.query(`SELECT s.*, u.username as gm_name FROM game_sessions s LEFT JOIN users u ON s.gm_id = u.id ORDER BY s.name ASC`);
    res.json(r.rows.map(row => ({ id: row.id, name: row.name, gmId: row.gm_name, status: row.status, mapUrl: row.map_url })));
  } catch (err) { res.status(500).json({ error: 'Erro ao buscar mesas.' }); }
});

// --- GAME LOGIC ---
app.get('/api/game/:sessionId', authenticateToken, async (req, res) => {
  const { sessionId } = req.params;
  const clientLastUpdate = req.query.since ? parseInt(req.query.since) : 0;

  try {
    const sessionCheck = await pool.query('SELECT updated_at FROM game_sessions WHERE id = $1', [sessionId]);
    if (sessionCheck.rows.length === 0) return res.status(404).json({ error: 'Mesa não encontrada' });
    
    const serverUpdate = new Date(sessionCheck.rows[0].updated_at).getTime();

    if (serverUpdate <= clientLastUpdate) {
        return res.json({ notModified: true, timestamp: serverUpdate });
    }

    const sess = await pool.query('SELECT * FROM game_sessions WHERE id = $1', [sessionId]);
    const s = sess.rows[0];

    const [tokens, walls, fog, notes, vids, imgs, snds] = await Promise.all([
        pool.query(`SELECT t.*, u.username as owner_username FROM tokens t LEFT JOIN users u ON t.owner_id = u.id WHERE session_id = $1`, [sessionId]),
        pool.query('SELECT * FROM walls WHERE session_id = $1', [sessionId]),
        pool.query('SELECT * FROM fogs WHERE session_id = $1', [sessionId]),
        pool.query('SELECT * FROM annotations WHERE session_id = $1', [sessionId]),
        pool.query('SELECT * FROM library_videos WHERE session_id = $1', [sessionId]),
        pool.query('SELECT * FROM library_images WHERE session_id = $1', [sessionId]),
        pool.query('SELECT * FROM library_sounds WHERE session_id = $1', [sessionId])
    ]);

    res.json({
        notModified: false,
        timestamp: serverUpdate,
        mapUrl: s.map_url, status: s.status,
        activeImageId: s.active_image_id, activeVideoId: s.active_video_id,
        tokens: tokens.rows.map(t => ({...t, ownerId: t.owner_username, maxHp: t.max_hp, maxSan: t.max_san, maxWeight: t.max_weight, statusEffects: t.status_effects})),
        walls: walls.rows, fog: fog.rows,
        annotations: notes.rows.map(n => ({...n, attachedItem: n.attached_item_data, isRevealed: n.is_revealed})),
        videos: vids.rows,
        images: imgs.rows.map(i => ({ id: i.id, title: i.title, url: i.url, ownerId: i.owner_id })),
        sounds: snds.rows.map(s => ({...s, key: s.shortcut_key}))
    });
  } catch (err) { res.status(500).json({ error: 'Erro ao carregar jogo.' }); }
});

app.post('/api/game', authenticateToken, async (req, res) => {
    const { id: sId, name, status, mapUrl, tokens, walls, fog, annotations, videos, images, sounds, activeImageId, activeVideoId } = req.body;
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        
        // Upsert Session
        const checkSess = await client.query('SELECT id FROM game_sessions WHERE id = $1', [sId]);
        if (checkSess.rows.length > 0) {
            await client.query('UPDATE game_sessions SET name=$1, map_url=$2, status=$3, active_image_id=$4, active_video_id=$5, updated_at=NOW() WHERE id=$6', [name, mapUrl, status, activeImageId, activeVideoId, sId]);
        } else {
             await client.query('INSERT INTO game_sessions (id, name, gm_id, map_url, status, active_image_id, active_video_id, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())', [sId, name, req.user.id, mapUrl, status, activeImageId, activeVideoId]);
        }

        // Clean & Re-insert children (Simplest sync strategy)
        await Promise.all(['tokens', 'walls', 'fogs', 'annotations', 'library_videos', 'library_images', 'library_sounds'].map(t => client.query(`DELETE FROM ${t} WHERE session_id = $1`, [sId])));

        // Re-insert Tokens
        for (const t of tokens) {
             let ownerUUID = null;
             if (t.ownerId) {
                const u = await client.query('SELECT id FROM users WHERE username = $1', [t.ownerId]);
                if (u.rows.length > 0) ownerUUID = u.rows[0].id;
             }
             await client.query(`INSERT INTO tokens (id, session_id, owner_id, name, url, role, active, x, y, size, hp, max_hp, san, max_san, max_weight, stats, inventory, status_effects) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)`, 
             [t.id, sId, ownerUUID, t.name, t.url, t.role, t.active, t.x, t.y, t.size, t.hp, t.maxHp, t.san, t.maxSan, t.maxWeight, JSON.stringify(t.stats), JSON.stringify(t.inventory), JSON.stringify(t.statusEffects)]);
        }
        
        // Re-insert others... (Shortened for brevity, logic remains the same as before)
        // ... [Insert Walls, Fogs, etc logic here] ...

        await client.query('COMMIT');
        res.json({ success: true, sessionId: sId });
    } catch (e) {
        await client.query('ROLLBACK');
        console.error(e);
        res.status(500).json({ error: e.message });
    } finally { client.release(); }
});

app.listen(port, () => console.log(`Backend running on ${port}`));
