require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const app = express();
const port = process.env.PORT || 3000;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 20, 
});

app.use(cors());
app.use(express.json({ limit: '50mb' }));

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

app.get('/', (req, res) => res.send('Aventurizer Backend v5.0 (Smart Sync) 🚀'));

// --- USER ROUTES (Mantidas iguais) ---
app.post('/api/register', async (req, res) => {
  const { username, password, role } = req.body;
  try {
    const check = await pool.query('SELECT id FROM users WHERE username = $1', [username]);
    if (check.rows.length > 0) return res.status(400).json({ error: 'Nome indisponível.' });
    const hash = await bcrypt.hash(password, 10);
    await pool.query('INSERT INTO users (id, username, password_hash, role) VALUES ($1, $2, $3, $4)', [crypto.randomUUID(), username, hash, role]);
    res.status(201).json({ success: true });
  } catch (err) { res.status(500).json({ error: 'Erro no registro.' }); }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const r = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    const u = r.rows[0];
    if (!u || !(await bcrypt.compare(password, u.password_hash))) return res.status(400).json({ error: 'Login inválido.' });
    const token = jwt.sign({ id: u.id, username: u.username, role: u.role }, process.env.JWT_SECRET, { expiresIn: '24h' });
    res.json({ token, user: { name: u.username, role: u.role } });
  } catch (err) { res.status(500).json({ error: 'Erro interno.' }); }
});

app.post('/api/change-password', authenticateToken, async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;
    const u = (await pool.query('SELECT * FROM users WHERE id = $1', [req.user.id])).rows[0];
    if (!(await bcrypt.compare(oldPassword, u.password_hash))) return res.status(400).json({ error: 'Senha incorreta.' });
    await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [await bcrypt.hash(newPassword, 10), req.user.id]);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: 'Erro.' }); }
});

app.get('/api/my-characters', authenticateToken, async (req, res) => {
  try {
    const r = await pool.query(`SELECT t.*, s.name as session_name FROM tokens t JOIN game_sessions s ON t.session_id = s.id WHERE t.owner_id = $1`, [req.user.id]);
    res.json(r.rows.map(t => ({...t, maxHp: t.max_hp, maxSan: t.max_san, maxWeight: t.max_weight, statusEffects: t.status_effects })));
  } catch (err) { res.status(500).json({ error: 'Erro.' }); }
});

app.get('/api/sessions', authenticateToken, async (req, res) => {
  try {
    const r = await pool.query(`SELECT s.*, u.username as gm_name FROM game_sessions s LEFT JOIN users u ON s.gm_id = u.id ORDER BY s.name ASC`);
    res.json(r.rows.map(row => ({ id: row.id, name: row.name, gmId: row.gm_name, status: row.status, mapUrl: row.map_url })));
  } catch (err) { res.status(500).json({ error: 'Erro.' }); }
});

// --- SMART LOAD ---
app.get('/api/game/:sessionId', authenticateToken, async (req, res) => {
  const { sessionId } = req.params;
  const clientLastUpdate = req.query.since; // Timestamp enviado pelo frontend

  try {
    // 1. Checa apenas o timestamp primeiro (Query ultra leve)
    const sessionCheck = await pool.query('SELECT updated_at FROM game_sessions WHERE id = $1', [sessionId]);
    if (sessionCheck.rows.length === 0) return res.status(404).json({ error: 'Mesa não encontrada' });
    
    const serverUpdate = new Date(sessionCheck.rows[0].updated_at).getTime();
    const clientUpdate = clientLastUpdate ? parseInt(clientLastUpdate as string) : 0;

    // 2. Se o cliente já tem a versão atual, retorna 304 (Not Modified) simulado
    // (Retornamos JSON { notModified: true } para facilitar o frontend)
    if (clientLastUpdate && serverUpdate <= clientUpdate) {
        return res.json({ notModified: true, timestamp: serverUpdate });
    }

    // 3. Se mudou, carrega tudo (Heavy Load)
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
        timestamp: serverUpdate, // Envia o novo timestamp para o cliente guardar
        mapUrl: s.map_url, status: s.status,
        activeImageId: s.active_image_id, activeVideoId: s.active_video_id,
        tokens: tokens.rows.map(t => ({...t, ownerId: t.owner_username, maxHp: t.max_hp, maxSan: t.max_san, maxWeight: t.max_weight, statusEffects: t.status_effects})),
        walls: walls.rows, fog: fog.rows,
        annotations: notes.rows.map(n => ({...n, attachedItem: n.attached_item_data, isRevealed: n.is_revealed})),
        videos: vids.rows,
        images: imgs.rows.map(i => ({ id: i.id, title: i.title, url: i.url, ownerId: i.owner_id })),
        sounds: snds.rows.map(s => ({...s, key: s.shortcut_key}))
    });
  } catch (err) { res.status(500).json({ error: 'Erro ao carregar.' }); }
});

// --- SAVE ---
app.post('/api/game', authenticateToken, async (req, res) => {
    const { id: sId, name, status, mapUrl, tokens, walls, fog, annotations, videos, images, sounds, activeImageId, activeVideoId } = req.body;
    const client = await pool.connect();
    
    try {
        await client.query('BEGIN');

        if (req.user.role !== 'gm') {
             const check = await client.query('SELECT status FROM game_sessions WHERE id = $1', [sId]);
             if (check.rows.length === 0 || check.rows[0].status === 'closed') throw new Error('Permissão negada.');
        }

        // UPDATE TIMESTAMP ON SAVE
        const checkSess = await client.query('SELECT id FROM game_sessions WHERE id = $1', [sId]);
        if (checkSess.rows.length > 0) {
            await client.query('UPDATE game_sessions SET name=$1, map_url=$2, status=$3, active_image_id=$4, active_video_id=$5, updated_at=NOW() WHERE id=$6', [name, mapUrl, status, activeImageId, activeVideoId, sId]);
        } else {
            if (req.user.role !== 'gm') throw new Error('Apenas GM cria.');
            await client.query('INSERT INTO game_sessions (id, name, gm_id, map_url, status, active_image_id, active_video_id, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())', [sId, name, req.user.id, mapUrl, status, activeImageId, activeVideoId]);
        }

        await Promise.all(['tokens', 'walls', 'fogs', 'annotations', 'library_videos', 'library_images', 'library_sounds'].map(t => 
            client.query(`DELETE FROM ${t} WHERE session_id = $1`, [sId])
        ));

        await Promise.all(tokens.map(async t => {
            let ownerUUID = null;
            if (t.ownerId) {
                const u = await client.query('SELECT id FROM users WHERE username = $1', [t.ownerId]);
                if (u.rows.length > 0) ownerUUID = u.rows[0].id;
            }
            return client.query(`INSERT INTO tokens (id, session_id, owner_id, name, url, role, active, x, y, size, hp, max_hp, san, max_san, max_weight, stats, inventory, status_effects) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)`, 
            [t.id || crypto.randomUUID(), sId, ownerUUID, t.name, t.url, t.role, t.active, t.x, t.y, t.size, t.hp, t.maxHp, t.san, t.maxSan, t.maxWeight, JSON.stringify(t.stats), JSON.stringify(t.inventory), JSON.stringify(t.statusEffects)]);
        }));

        await Promise.all([
            ...walls.map(w => client.query('INSERT INTO walls (id, session_id, x, y, width, height) VALUES ($1, $2, $3, $4, $5, $6)', [w.id || crypto.randomUUID(), sId, w.x, w.y, w.width, w.height])),
            ...fog.map(f => client.query('INSERT INTO fogs (id, session_id, x, y, width, height) VALUES ($1, $2, $3, $4, $5, $6)', [f.id || crypto.randomUUID(), sId, f.x, f.y, f.width, f.height])),
            ...annotations.map(a => client.query('INSERT INTO annotations (id, session_id, x, y, title, content, is_revealed, attached_item_data) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)', [a.id || crypto.randomUUID(), sId, a.x, a.y, a.title, a.content, a.isRevealed, JSON.stringify(a.attachedItem)])),
            ...videos.map(v => client.query('INSERT INTO library_videos (id, session_id, title, url) VALUES ($1, $2, $3, $4)', [v.id || crypto.randomUUID(), sId, v.title, v.url])),
            ...images.map(i => client.query('INSERT INTO library_images (id, session_id, title, url, owner_id) VALUES ($1, $2, $3, $4, $5)', [i.id || crypto.randomUUID(), sId, i.title, i.url, i.ownerId || null])),
            ...sounds.map(s => client.query('INSERT INTO library_sounds (id, session_id, name, shortcut_key, url) VALUES ($1, $2, $3, $4, $5)', [s.id || crypto.randomUUID(), sId, s.name, s.key, s.url]))
        ]);

        await client.query('COMMIT');
        res.json({ success: true, sessionId: sId });
    } catch (e) {
        await client.query('ROLLBACK');
        console.error(e);
        res.status(500).json({ error: e.message });
    } finally { client.release(); }
});

app.post('/log', async (req, res) => {
    try { await pool.query('INSERT INTO interaction_logs (id, username, message, response) VALUES ($1, $2, $3, $4)', [crypto.randomUUID(), req.body.usuario, req.body.mensagem, req.body.resposta]); res.sendStatus(200); } catch(e) { res.sendStatus(500); }
});

app.listen(port, () => console.log(`Backend running on ${port}`));
