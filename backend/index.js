require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const app = express();
const port = process.env.PORT || 3000;

// ==========================================
// CONFIGURAÇÃO DO BANCO DE DADOS
// ==========================================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false } // Obrigatório para Render
});

app.use(cors());
app.use(express.json({ limit: '50mb' })); // Limite aumentado para mapas grandes

// ==========================================
// MIDDLEWARE DE AUTENTICAÇÃO
// ==========================================
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

// ==========================================
// ROTA DE TESTE
// ==========================================
app.get('/', (req, res) => {
  res.send('Aventurizer RPG Backend Online 🚀');
});

// ==========================================
// ROTAS DE USUÁRIO (AUTH)
// ==========================================

// 1. REGISTRAR NOVO USUÁRIO (NOVO!)
app.post('/api/register', async (req, res) => {
  const { username, password, role } = req.body;

  if (!username || !password || !role) {
    return res.status(400).json({ error: 'Preencha todos os campos.' });
  }

  if (role !== 'gm' && role !== 'player') {
    return res.status(400).json({ error: 'Papel inválido. Use "gm" ou "player".' });
  }

  try {
    // Verifica se já existe
    const userCheck = await pool.query('SELECT id FROM users WHERE username = $1', [username]);
    if (userCheck.rows.length > 0) {
      return res.status(400).json({ error: 'Nome de usuário indisponível.' });
    }

    // Criptografa senha
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(password, salt);
    
    // Gera ID e salva
    const newId = crypto.randomUUID();
    await pool.query(
      'INSERT INTO users (id, username, password_hash, role) VALUES ($1, $2, $3, $4)',
      [newId, username, hash, role]
    );

    res.status(201).json({ success: true, message: 'Usuário criado com sucesso!' });

  } catch (err) {
    console.error("Erro no registro:", err);
    res.status(500).json({ error: 'Erro ao criar usuário.' });
  }
});

// 2. LOGIN
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    const user = result.rows[0];

    if (!user) return res.status(400).json({ error: 'Usuário não encontrado' });

    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) return res.status(400).json({ error: 'Senha incorreta' });

    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({ token, user: { name: user.username, role: user.role } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro interno no servidor' });
  }
});

// 3. TROCAR SENHA
app.post('/api/change-password', authenticateToken, async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  try {
    const userRes = await pool.query('SELECT * FROM users WHERE id = $1', [req.user.id]);
    const user = userRes.rows[0];
    
    const valid = await bcrypt.compare(oldPassword, user.password_hash);
    if (!valid) return res.status(400).json({ error: 'Senha atual incorreta' });

    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(newPassword, salt);
    
    await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [hash, req.user.id]);
    res.json({ success: true });
  } catch(e) {
    res.status(500).json({ error: 'Erro ao trocar senha' });
  }
});

// 4. MEUS PERSONAGENS
app.get('/api/my-characters', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT t.*, s.name as session_name 
      FROM tokens t
      JOIN game_sessions s ON t.session_id = s.id
      WHERE t.owner_id = $1
    `, [req.user.id]);
    
    // Converte snake_case do banco para camelCase do React
    const formatted = result.rows.map(t => ({
        ...t,
        maxHp: t.max_hp,
        maxSan: t.max_san,
        maxWeight: t.max_weight,
        statusEffects: t.status_effects
        // stats e inventory já vêm como objeto JSON automático do Postgres
    }));
    
    res.json(formatted);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao buscar personagens.' });
  }
});

// ==========================================
// ROTAS DE JOGO (SESSIONS & GAME STATE)
// ==========================================

// 1. LISTAR MESAS
app.get('/api/sessions', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT s.*, u.username as gm_name 
      FROM game_sessions s
      LEFT JOIN users u ON s.gm_id = u.id
      ORDER BY s.name ASC
    `);
    
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
    res.status(500).json({ error: 'Erro ao listar sessões' });
  }
});

// 2. CARREGAR JOGO (LOAD)
app.get('/api/game/:sessionId', authenticateToken, async (req, res) => {
  const { sessionId } = req.params;
  try {
    // Busca a sessão
    const sessionRes = await pool.query('SELECT * FROM game_sessions WHERE id = $1', [sessionId]);
    if (sessionRes.rows.length === 0) return res.status(404).json({ error: 'Mesa não encontrada' });
    const session = sessionRes.rows[0];

    // Busca Tokens (e junta com usuário para saber o dono)
    const tokensRes = await pool.query(`
        SELECT t.*, u.username as owner_username 
        FROM tokens t
        LEFT JOIN users u ON t.owner_id = u.id
        WHERE session_id = $1
    `, [sessionId]);

    const formattedTokens = tokensRes.rows.map(t => ({
        ...t,
        ownerId: t.owner_username, 
        maxHp: t.max_hp,
        maxSan: t.max_san,
        maxWeight: t.max_weight,
        statusEffects: t.status_effects
    }));

    // Busca os outros elementos
    const wallsRes = await pool.query('SELECT * FROM walls WHERE session_id = $1', [sessionId]);
    const fogRes = await pool.query('SELECT * FROM fogs WHERE session_id = $1', [sessionId]);
    const notesRes = await pool.query('SELECT * FROM annotations WHERE session_id = $1', [sessionId]);
    
    const formattedNotes = notesRes.rows.map(n => ({
        ...n,
        attachedItem: n.attached_item_data,
        isRevealed: n.is_revealed
    }));

    const videosRes = await pool.query('SELECT * FROM library_videos WHERE session_id = $1', [sessionId]);
    const imagesRes = await pool.query('SELECT * FROM library_images WHERE session_id = $1', [sessionId]);
    const soundsRes = await pool.query('SELECT * FROM library_sounds WHERE session_id = $1', [sessionId]);

    // Retorna tudo montado
    res.json({
        mapUrl: session.map_url,
        status: session.status,
        tokens: formattedTokens,
        walls: wallsRes.rows,
        fog: fogRes.rows,
        annotations: formattedNotes,
        videos: videosRes.rows,
        images: imagesRes.rows,
        sounds: soundsRes.rows.map(s => ({...s, key: s.shortcut_key}))
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao carregar jogo' });
  }
});

// 3. SALVAR JOGO (SAVE)
app.post('/api/game', authenticateToken, async (req, res) => {
    const { id: sessionId, name, status, mapUrl, tokens, walls, fog, annotations, videos, images, sounds } = req.body;
    
    // Apenas GM salva estrutura global, mas aqui deixamos aberto para validação no front
    if (req.user.role !== 'gm') return res.status(403).json({ error: 'Apenas GM salva o mapa.' });

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // 1. UPSERT DA SESSÃO
        // Verifica se existe pelo ID (agora TEXTO)
        const checkSess = await client.query('SELECT id FROM game_sessions WHERE id = $1', [sessionId]);
        
        let targetId = sessionId;
        if (checkSess.rows.length > 0) {
            // Atualiza existente
            await client.query('UPDATE game_sessions SET name=$1, map_url=$2, status=$3 WHERE id=$4', 
                [name, mapUrl, status, sessionId]);
        } else {
            // Cria nova (se o ID veio do front e não existe, usamos ele)
            await client.query('INSERT INTO game_sessions (id, name, gm_id, map_url, status) VALUES ($1, $2, $3, $4, $5)', 
                [sessionId, name, req.user.id, mapUrl, status]);
        }

        // 2. LIMPEZA COMPLETA DOS FILHOS (Para reinserir o estado atualizado)
        const tables = ['tokens', 'walls', 'fogs', 'annotations', 'library_videos', 'library_images', 'library_sounds'];
        for(const tbl of tables) {
            await client.query(`DELETE FROM ${tbl} WHERE session_id = $1`, [targetId]);
        }

        // 3. INSERÇÃO DOS ELEMENTOS

        // Tokens
        for (const t of tokens) {
            let ownerUUID = null;
            if (t.ownerId) {
                // Busca o ID do usuário baseado no nome
                const u = await client.query('SELECT id FROM users WHERE username = $1', [t.ownerId]);
                if (u.rows.length > 0) ownerUUID = u.rows[0].id;
            }
            
            // Usa crypto.randomUUID() se o token vier sem ID (segurança)
            const tokenId = t.id || crypto.randomUUID();

            await client.query(`
                INSERT INTO tokens (
                    id, session_id, owner_id, name, url, role, active, x, y, size,
                    hp, max_hp, san, max_san, max_weight, 
                    stats, inventory, status_effects
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
            `, [
                tokenId, targetId, ownerUUID, t.name, t.url, t.role, t.active, t.x, t.y, t.size,
                t.hp, t.maxHp, t.san, t.maxSan, t.maxWeight,
                JSON.stringify(t.stats), JSON.stringify(t.inventory), JSON.stringify(t.statusEffects)
            ]);
        }

        // Paredes
        for (const w of walls) {
            await client.query('INSERT INTO walls (id, session_id, x, y, width, height) VALUES ($1, $2, $3, $4, $5, $6)',
            [w.id || crypto.randomUUID(), targetId, w.x, w.y, w.width, w.height]);
        }

        // Névoa
        for (const f of fog) {
            await client.query('INSERT INTO fogs (id, session_id, x, y, width, height) VALUES ($1, $2, $3, $4, $5, $6)',
            [f.id || crypto.randomUUID(), targetId, f.x, f.y, f.width, f.height]);
        }
        
        // Notas
        for (const a of annotations) {
            await client.query('INSERT INTO annotations (id, session_id, x, y, title, content, is_revealed, attached_item_data) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)',
            [a.id || crypto.randomUUID(), targetId, a.x, a.y, a.title, a.content, a.isRevealed, JSON.stringify(a.attachedItem)]);
        }

        // Bibliotecas
        for (const v of videos) await client.query('INSERT INTO library_videos (id, session_id, title, url) VALUES ($1, $2, $3, $4)', [v.id || crypto.randomUUID(), targetId, v.title, v.url]);
        for (const i of images) await client.query('INSERT INTO library_images (id, session_id, title, url) VALUES ($1, $2, $3, $4)', [i.id || crypto.randomUUID(), targetId, i.title, i.url]);
        for (const s of sounds) await client.query('INSERT INTO library_sounds (id, session_id, name, shortcut_key, url) VALUES ($1, $2, $3, $4, $5)', [s.id || crypto.randomUUID(), targetId, s.name, s.key, s.url]);

        await client.query('COMMIT');
        
        // Retorna o ID da sessão (importante caso tenha sido criado agora)
        res.json({ success: true, sessionId: targetId });

    } catch (e) {
        await client.query('ROLLBACK');
        console.error("Save Error:", e);
        res.status(500).json({ error: 'Erro ao salvar jogo: ' + e.message });
    } finally {
        client.release();
    }
});

// ==========================================
// ROTAS DE LOG (IA)
// ==========================================
app.post('/log', async (req, res) => {
    try {
        await pool.query('INSERT INTO interaction_logs (id, username, message, response) VALUES ($1, $2, $3, $4)', 
        [crypto.randomUUID(), req.body.usuario, req.body.mensagem, req.body.resposta]);
        res.sendStatus(200);
    } catch(e) { 
        console.error("Log Error:", e); 
        res.sendStatus(500); 
    }
});

// ==========================================
// INICIALIZAÇÃO
// ==========================================
app.listen(port, () => {
  console.log(`Backend Aventurizer rodando na porta ${port}`);
});
