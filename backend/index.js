require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const app = express();
const port = process.env.PORT || 3000;

// Configuração do Banco de Dados
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }, // Necessário para Render/Neon/Supabase
  max: 20, // Limite de conexões
});

// Middlewares
app.use(cors());
app.use(express.json({ limit: '50mb' })); // Aumentado para suportar mapas em Base64

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

app.get('/', (req, res) => res.send('Aventurizer Backend v5.2 (Stable) 🚀'));

// ==================================================================
// ROTAS DE USUÁRIO (AUTH)
// ==================================================================

app.post('/api/register', async (req, res) => {
  const { username, password, role } = req.body;
  try {
    const check = await pool.query('SELECT id FROM users WHERE username = $1', [username]);
    if (check.rows.length > 0) return res.status(400).json({ error: 'Nome indisponível.' });
    
    const hash = await bcrypt.hash(password, 10);
    await pool.query('INSERT INTO users (id, username, password_hash, role) VALUES ($1, $2, $3, $4)', 
      [crypto.randomUUID(), username, hash, role]);
    
    res.status(201).json({ success: true });
  } catch (err) { 
    console.error(err);
    res.status(500).json({ error: 'Erro no registro.' }); 
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const r = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    const u = r.rows[0];
    
    if (!u || !(await bcrypt.compare(password, u.password_hash))) {
      return res.status(400).json({ error: 'Login inválido.' });
    }
    
    const token = jwt.sign({ id: u.id, username: u.username, role: u.role }, process.env.JWT_SECRET, { expiresIn: '24h' });
    res.json({ token, user: { name: u.username, role: u.role } });
  } catch (err) { 
    console.error(err);
    res.status(500).json({ error: 'Erro interno.' }); 
  }
});

app.post('/api/change-password', authenticateToken, async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;
    const u = (await pool.query('SELECT * FROM users WHERE id = $1', [req.user.id])).rows[0];
    
    if (!(await bcrypt.compare(oldPassword, u.password_hash))) {
      return res.status(400).json({ error: 'Senha incorreta.' });
    }
    
    await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [await bcrypt.hash(newPassword, 10), req.user.id]);
    res.json({ success: true });
  } catch(e) { 
    res.status(500).json({ error: 'Erro ao alterar senha.' }); 
  }
});

app.get('/api/my-characters', authenticateToken, async (req, res) => {
  try {
    const r = await pool.query(`
        SELECT t.*, s.name as session_name 
        FROM tokens t 
        JOIN game_sessions s ON t.session_id = s.id 
        WHERE t.owner_id = $1`, 
    [req.user.id]);
    
    // Normalizar Snake Case para Camel Case
    res.json(r.rows.map(t => ({
        ...t, 
        maxHp: t.max_hp, 
        maxSan: t.max_san, 
        maxWeight: t.max_weight, 
        statusEffects: t.status_effects 
    })));
  } catch (err) { res.status(500).json({ error: 'Erro.' }); }
});

// ==================================================================
// ROTAS DE SESSÃO
// ==================================================================

app.get('/api/sessions', authenticateToken, async (req, res) => {
  try {
    const r = await pool.query(`
        SELECT s.*, u.username as gm_name 
        FROM game_sessions s 
        LEFT JOIN users u ON s.gm_id = u.id 
        ORDER BY s.updated_at DESC`);
    
    res.json(r.rows.map(row => ({ 
        id: row.id, 
        name: row.name, 
        gmId: row.gm_name, 
        status: row.status, 
        mapUrl: row.map_url 
    })));
  } catch (err) { res.status(500).json({ error: 'Erro.' }); }
});

// EXCLUIR MESA
app.delete('/api/sessions/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        
        // 1. Verificar Dono
        const sessionCheck = await client.query('SELECT gm_id FROM game_sessions WHERE id = $1', [id]);
        if (sessionCheck.rows.length === 0) return res.status(404).json({ error: 'Mesa não encontrada.' });
        
        if (sessionCheck.rows[0].gm_id !== req.user.id) {
            return res.status(403).json({ error: 'Apenas o Mestre criador pode excluir esta mesa.' });
        }

        // 2. Cascade Delete Manual
        const tables = ['tokens', 'walls', 'fogs', 'annotations', 'library_videos', 'library_images', 'library_sounds'];
        for (const table of tables) {
            await client.query(`DELETE FROM ${table} WHERE session_id = $1`, [id]);
        }

        // 3. Deletar Sessão
        await client.query('DELETE FROM game_sessions WHERE id = $1', [id]);

        await client.query('COMMIT');
        res.json({ success: true });
    } catch (e) {
        await client.query('ROLLBACK');
        console.error(e);
        res.status(500).json({ error: 'Erro ao excluir mesa.' });
    } finally {
        client.release();
    }
});

// ==================================================================
// ROTAS DO JOGO (GAME LOOP)
// ==================================================================

// CARREGAR JOGO (SMART LOAD)
app.get('/api/game/:sessionId', authenticateToken, async (req, res) => {
  const { sessionId } = req.params;
  const clientLastUpdate = req.query.since;

  try {
    const sessionCheck = await pool.query('SELECT updated_at FROM game_sessions WHERE id = $1', [sessionId]);
    if (sessionCheck.rows.length === 0) return res.status(404).json({ error: 'Mesa não encontrada' });
    
    const serverUpdate = new Date(sessionCheck.rows[0].updated_at).getTime();
    const clientUpdate = clientLastUpdate ? parseInt(clientLastUpdate) : 0;

    // Se o cliente já tem a versão mais recente, retorna 304 (Not Modified simulado)
    if (clientLastUpdate && serverUpdate <= clientUpdate) {
        return res.json({ notModified: true, timestamp: serverUpdate });
    }

    // Se mudou, carrega tudo
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
        tokens: tokens.rows.map(t => ({
            ...t, 
            ownerId: t.owner_username, 
            maxHp: t.max_hp, 
            maxSan: t.max_san, 
            maxWeight: t.max_weight, 
            statusEffects: t.status_effects
        })),
        walls: walls.rows, fog: fog.rows,
        annotations: notes.rows.map(n => ({...n, attachedItem: n.attached_item_data, isRevealed: n.is_revealed})),
        videos: vids.rows,
        images: imgs.rows.map(i => ({ id: i.id, title: i.title, url: i.url, ownerId: i.owner_id })),
        sounds: snds.rows.map(s => ({...s, key: s.shortcut_key}))
    });
  } catch (err) { res.status(500).json({ error: 'Erro ao carregar.' }); }
});

// SALVAR JOGO
app.post('/api/game', authenticateToken, async (req, res) => {
    const { id: sId, name, status, mapUrl, tokens, walls, fog, annotations, videos, images, sounds, activeImageId, activeVideoId } = req.body;
    const client = await pool.connect();
    
    try {
        await client.query('BEGIN');

        // Permissão: Apenas GM pode alterar status/mapa/estrutura global, mas Players podem salvar seus tokens (inventário)
        if (req.user
