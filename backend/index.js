require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const port = process.env.PORT || 3000;

// ==================================================================
// CONFIGURAÇÃO DO BANCO DE DADOS (RENDER.COM)
// ==================================================================
// O Render injeta a URL automaticamente na variável DATABASE_URL
// Não precisa colar o link aqui se estiver usando Environment Variables no painel
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false // Obrigatório para conexão externa segura no Render
  }
});

// Middlewares
app.use(cors());
app.use(express.json({ limit: '50mb' }));

// Middleware de Autenticação (Protege as rotas)
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Formato: "Bearer TOKEN"

  if (!token) return res.sendStatus(401); // Unauthorized

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403); // Forbidden
    req.user = user;
    next();
  });
};

// ==================================================================
// ROTA DE TESTE (Para saber se o backend está vivo)
// ==================================================================
app.get('/', (req, res) => {
  res.send('Aventurizer RPG Backend is Online! 🚀');
});

// ==================================================================
// ROTAS DE USUÁRIO (LOGIN / TROCA DE SENHA)
// ==================================================================

// 1. LOGIN
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    const user = result.rows[0];

    if (!user) {
      return res.status(400).json({ error: 'Usuário não encontrado' });
    }

    // Compara senha (Hash)
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(400).json({ error: 'Senha incorreta' });
    }

    // Gera Token
    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({ token, user: { name: user.username, role: user.role } });
  } catch (err) {
    console.error('Erro Login:', err);
    res.status(500).json({ error: 'Erro interno no servidor' });
  }
});

// 2. TROCAR SENHA
app.post('/api/change-password', authenticateToken, async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  const userId = req.user.id;

  try {
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
    const user = result.rows[0];

    const validPassword = await bcrypt.compare(oldPassword, user.password_hash);
    if (!validPassword) return res.status(400).json({ error: 'Senha atual incorreta.' });

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);

    await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [hashedPassword, userId]);
    res.json({ message: 'Senha alterada com sucesso!' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao alterar senha.' });
  }
});

// 3. MEUS PERSONAGENS
app.get('/api/my-characters', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT t.*, s.name as session_name 
      FROM tokens t
      JOIN game_sessions s ON t.session_id = s.id
      WHERE t.owner_id = $1
    `, [req.user.id]);
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao buscar personagens.' });
  }
});

// ==================================================================
// ROTAS DE JOGO (SALVAR / CARREGAR)
// ==================================================================

// LISTAR MESAS
app.get('/api/sessions', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT s.*, u.username as gm_name 
      FROM game_sessions s
      LEFT JOIN users u ON s.gm_id = u.id
      ORDER BY s.updated_at DESC
    `);
    
    // Mapeia para o formato do Frontend
    const sessions = result.rows.map(row => ({
      id: row.id,
      name: row.name,
      gmId: row.gm_name,
      status: row.status,
      mapUrl: row.map_url
    }));

    res.json(sessions);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao listar sessões.' });
  }
});

// CARREGAR JOGO (Load)
app.get('/api/game/:sessionId', authenticateToken, async (req, res) => {
  const { sessionId } = req.params;
  try {
    const sessionRes = await pool.query('SELECT * FROM game_sessions WHERE id = $1', [sessionId]);
    if (sessionRes.rows.length === 0) return res.status(404).json({ error: 'Mesa não encontrada' });
    const session = sessionRes.rows[0];

    // Carrega tudo
    const tokensRes = await pool.query(`
        SELECT t.*, u.username as owner_username 
        FROM tokens t
        LEFT JOIN users u ON t.owner_id = u.id
        WHERE session_id = $1
    `, [sessionId]);

    const wallsRes = await pool.query('SELECT * FROM walls WHERE session_id = $1', [sessionId]);
    const fogRes = await pool.query('SELECT * FROM fogs WHERE session_id = $1', [sessionId]);
    const notesRes = await pool.query('SELECT * FROM annotations WHERE session_id = $1', [sessionId]);
    const videosRes = await pool.query('SELECT * FROM library_videos WHERE session_id = $1', [sessionId]);
    const imagesRes = await pool.query('SELECT * FROM library_images WHERE session_id = $1', [sessionId]);
    const soundsRes = await pool.query('SELECT * FROM library_sounds WHERE session_id = $1', [sessionId]);

    // Formata Tokens
    const formattedTokens = tokensRes.rows.map(t => ({
        ...t,
        ownerId: t.owner_username, 
        maxHp: t.max_hp, maxSan: t.max_san, maxWeight: t.max_weight, statusEffects: t.status_effects
    }));

    const formattedNotes = notesRes.rows.map(n => ({
        ...n, attachedItem: n.attached_item_data, isRevealed: n.is_revealed
    }));

    const gameState = {
        mapUrl: session.map_url,
        status: session.status,
        tokens: formattedTokens,
        walls: wallsRes.rows,
        fog: fogRes.rows,
        annotations: formattedNotes,
        videos: videosRes.rows,
        images: imagesRes.rows,
        sounds: soundsRes.rows.map(s => ({...s, key: s.shortcut_key}))
    };

    res.json(gameState);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao carregar jogo.' });
  }
});

// SALVAR JOGO (Save)
app.post('/api/game', authenticateToken, async (req, res) => {
    const { id: sessionId, name, status, mapUrl, tokens, walls, fog, annotations, videos, images, sounds } = req.body;
    
    if (req.user.role !== 'gm') return res.status(403).json({ error: 'Apenas GM salva.' });

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // Cria ou Atualiza Sessão (Upsert simplificado)
        // Nota: Assumindo que o frontend enviou um UUID válido em sessionId
        // Se for "new", cria nova
        let targetId = sessionId;
        
        // Verifica se é UUID válido
        const isUUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(sessionId);

        if (isUUID) {
            // Tenta atualizar
            const check = await client.query('SELECT id FROM game_sessions WHERE id = $1', [sessionId]);
            if (check.rows.length > 0) {
                 await client.query('UPDATE game_sessions SET name=$1, map_url=$2, status=$3, updated_at=NOW() WHERE id=$4', [name, mapUrl, status, sessionId]);
            } else {
                 // UUID mas não existe (ex: gerado no front), cria
                 const newS = await client.query('INSERT INTO game_sessions (id, name, gm_id, map_url, status) VALUES ($1, $2, $3, $4, $5) RETURNING id', [sessionId, name, req.user.id, mapUrl, status]);
            }
        } else {
             // ID inválido ou temporário, cria nova sessão
             const newS = await client.query('INSERT INTO game_sessions (name, gm_id, map_url, status) VALUES ($1, $2, $3, $4) RETURNING id', [name, req.user.id, mapUrl, status]);
             targetId = newS.rows[0].id;
        }

        // Limpa filhos antigos
        await client.query('DELETE FROM tokens WHERE session_id = $1', [targetId]);
        await client.query('DELETE FROM walls WHERE session_id = $1', [targetId]);
        await client.query('DELETE FROM fogs WHERE session_id = $1', [targetId]);
        await client.query('DELETE FROM annotations WHERE session_id = $1', [targetId]);
        await client.query('DELETE FROM library_videos WHERE session_id = $1', [targetId]);
        await client.query('DELETE FROM library_images WHERE session_id = $1', [targetId]);
        await client.query('DELETE FROM library_sounds WHERE session_id = $1', [targetId]);

        // Insere Tokens
        for (const t of tokens) {
            let ownerUUID = null;
            if (t.ownerId) {
                const u = await client.query('SELECT id FROM users WHERE username = $1', [t.ownerId]);
                if (u.rows.length > 0) ownerUUID = u.rows[0].id;
            }
            await client.query(`
                INSERT INTO tokens (session_id, owner_id, name, url, role, active, x, y, size, hp, max_hp, san, max_san, max_weight, stats, inventory, status_effects)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
            `, [targetId, ownerUUID, t.name, t.url, t.role, t.active, t.x, t.y, t.size, t.hp, t.maxHp, t.san, t.maxSan, t.maxWeight, JSON.stringify(t.stats), JSON.stringify(t.inventory), JSON.stringify(t.statusEffects)]);
        }

        // Insere outros objetos...
        for (const w of walls) await client.query('INSERT INTO walls (session_id, x, y, width, height) VALUES ($1, $2, $3, $4, $5)', [targetId, w.x, w.y, w.width, w.height]);
        for (const f of fog) await client.query('INSERT INTO fogs (session_id, x, y, width, height) VALUES ($1, $2, $3, $4, $5)', [targetId, f.x, f.y, f.width, f.height]);
        for (const a of annotations) await client.query('INSERT INTO annotations (session_id, x, y, title, content, is_revealed, attached_item_data) VALUES ($1, $2, $3, $4, $5, $6, $7)', [targetId, a.x, a.y, a.title, a.content, a.isRevealed, JSON.stringify(a.attachedItem)]);
        for (const v of videos) await client.query('INSERT INTO library_videos (session_id, title, url) VALUES ($1, $2, $3)', [targetId, v.title, v.url]);
        for (const i of images) await client.query('INSERT INTO library_images (session_id, title, url) VALUES ($1, $2, $3)', [targetId, i.title, i.url]);
        for (const s of sounds) await client.query('INSERT INTO library_sounds (session_id, name, shortcut_key, url) VALUES ($1, $2, $3, $4)', [targetId, s.name, s.key, s.url]);

        await client.query('COMMIT');
        res.json({ success: true, sessionId: targetId });
    } catch (e) {
        await client.query('ROLLBACK');
        console.error(e);
        res.status(500).json({ error: 'Erro ao salvar' });
    } finally {
        client.release();
    }
});

// LOG IA
app.post('/log', async (req, res) => {
  const { usuario, mensagem, resposta } = req.body;
  try {
    await pool.query('INSERT INTO interaction_logs (username, message, response) VALUES ($1, $2, $3)', [usuario, mensagem, resposta]);
    res.sendStatus(200);
  } catch (err) {
    console.error(err);
    res.sendStatus(500);
  }
});

app.listen(port, () => {
  console.log(`Backend Aventurizer rodando na porta ${port}`);
});
