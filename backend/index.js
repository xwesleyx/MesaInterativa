require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 10000;

// Configuração Básica
app.use(cors()); // Permite conexões do Frontend (CORS)
app.use(express.json({ limit: '50mb' })); // Limite alto para imagens

// Rota de Health Check (Necessária para o Render não derrubar o serviço)
app.get('/', (req, res) => {
    res.status(200).send('RPG AI Backend está online!');
});

// Conexão DB
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false } // Necessário para Render/Neon/Supabase
});

// Middleware de Autenticação
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ error: 'Token não fornecido' });

    jwt.verify(token, process.env.JWT_SECRET || 'secret_key_dev', (err, user) => {
        if (err) return res.status(403).json({ error: 'Token inválido' });
        req.user = user;
        next();
    });
};

// ==================================================
// 1. AUTENTICAÇÃO
// ==================================================

// Registro
app.post('/api/register', async (req, res) => {
    const { username, password, role } = req.body;
    
    if (!username || !password) return res.status(400).json({ error: "Preencha todos os campos" });
    if (username.toLowerCase() === 'mestre') return res.status(400).json({ error: "Nome reservado" });

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query(
            'INSERT INTO users (username, password, role) VALUES ($1, $2, $3)',
            [username, hashedPassword, role || 'player']
        );
        res.status(201).json({ message: "Usuário criado com sucesso" });
    } catch (err) {
        if (err.code === '23505') return res.status(400).json({ error: "Usuário já existe" });
        console.error(err);
        res.status(500).json({ error: "Erro no servidor" });
    }
});

// Login
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        if (result.rows.length === 0) return res.status(400).json({ error: "Usuário não encontrado" });

        const user = result.rows[0];
        if (await bcrypt.compare(password, user.password)) {
            const token = jwt.sign(
                { id: user.id, name: user.username, role: user.role },
                process.env.JWT_SECRET || 'secret_key_dev',
                { expiresIn: '30d' }
            );
            res.json({ token, user: { name: user.username, role: user.role } });
        } else {
            res.status(400).json({ error: "Senha incorreta" });
        }
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Erro no login" });
    }
});

// Alterar Própria Senha
app.post('/api/change-password', authenticateToken, async (req, res) => {
    const { oldPassword, newPassword } = req.body;
    try {
        const result = await pool.query('SELECT * FROM users WHERE username = $1', [req.user.name]);
        const user = result.rows[0];

        if (await bcrypt.compare(oldPassword, user.password)) {
            const hashedPassword = await bcrypt.hash(newPassword, 10);
            await pool.query('UPDATE users SET password = $1 WHERE id = $2', [hashedPassword, user.id]);
            res.json({ message: "Senha alterada com sucesso" });
        } else {
            res.status(400).json({ error: "Senha atual incorreta" });
        }
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Erro ao alterar senha" });
    }
});

// ==================================================
// 2. ADMINISTRAÇÃO (SUPER ADMIN / MESTRE)
// ==================================================

// Listar Todos Usuários
app.get('/api/users', authenticateToken, async (req, res) => {
    if (req.user.name.toLowerCase() !== 'mestre') {
        return res.status(403).json({ error: 'Acesso negado. Apenas o Mestre pode ver usuários.' });
    }

    try {
        const result = await pool.query('SELECT id, username, role, created_at FROM users ORDER BY username ASC');
        res.json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Erro ao buscar usuários' });
    }
});

// Mestre redefine senha de usuário
app.put('/api/users/:username/reset', authenticateToken, async (req, res) => {
    const { username } = req.params;
    const { newPassword } = req.body;

    if (req.user.name.toLowerCase() !== 'mestre') {
        return res.status(403).json({ error: 'Acesso negado.' });
    }
    
    if (!newPassword || newPassword.length < 3) {
        return res.status(400).json({ error: 'Senha muito curta.' });
    }

    try {
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await pool.query('UPDATE users SET password = $1 WHERE username = $2', [hashedPassword, username]);
        res.json({ message: `Senha de ${username} redefinida com sucesso.` });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Erro ao redefinir senha.' });
    }
});

// Mestre deleta usuário (e suas mesas)
app.delete('/api/users/:username', authenticateToken, async (req, res) => {
    const { username } = req.params;

    if (req.user.name.toLowerCase() !== 'mestre') {
        return res.status(403).json({ error: 'Acesso negado.' });
    }

    if (username.toLowerCase() === 'mestre') {
        return res.status(400).json({ error: 'O Mestre Supremo é imortal.' });
    }

    try {
        // 1. Deleta sessões onde o usuário é o GM
        await pool.query('DELETE FROM game_sessions WHERE gm_id = $1', [username]);
        
        // 2. Deleta o usuário
        await pool.query('DELETE FROM users WHERE username = $1', [username]);
        
        res.json({ message: `Usuário ${username} e todas as suas mesas foram eliminados.` });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Erro ao deletar usuário' });
    }
});

// ==================================================
// 3. GAME SESSIONS (MESAS)
// ==================================================

// Listar Mesas
app.get('/api/sessions', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT id, name, gm_id as "gmId", status, map_url as "mapUrl", created_at 
            FROM game_sessions 
            ORDER BY created_at DESC
        `);
        res.json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Erro ao listar sessões" });
    }
});

// Carregar Mesa
app.get('/api/game/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    try {
        const result = await pool.query('SELECT * FROM game_sessions WHERE id = $1', [id]);
        if (result.rows.length === 0) return res.status(404).json({ error: "Mesa não encontrada" });

        const session = result.rows[0];
        
        const fullState = {
            ...session.game_state,
            id: session.id,
            name: session.name,
            gmId: session.gm_id,
            status: session.status,
            mapUrl: session.map_url,
            // Fallbacks para evitar null
            tokens: session.game_state.tokens || [],
            walls: session.game_state.walls || [],
            fog: session.game_state.fog || [],
            annotations: session.game_state.annotations || [],
            videos: session.game_state.videos || [],
            images: session.game_state.images || [],
            sounds: session.game_state.sounds || [],
            timestamp: new Date(session.updated_at).getTime()
        };

        res.json(fullState);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Erro ao carregar jogo" });
    }
});

// Criar ou Salvar Mesa
app.post('/api/game', authenticateToken, async (req, res) => {
    const { id, name, status, mapUrl, tokens, walls, fog, annotations, videos, images, sounds, activeImageId, activeVideoId } = req.body;
    const gmId = req.user.name;

    const gameState = {
        tokens, walls, fog, annotations, videos, images, sounds, activeImageId, activeVideoId
    };

    try {
        const check = await pool.query('SELECT gm_id FROM game_sessions WHERE id = $1', [id]);

        if (check.rows.length > 0) {
            // Atualizar
            await pool.query(`
                UPDATE game_sessions 
                SET name = COALESCE($1, name), 
                    status = COALESCE($2, status), 
                    map_url = COALESCE($3, map_url), 
                    game_state = $4,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = $5
            `, [name, status, mapUrl, gameState, id]);
            
            res.json({ message: "Jogo salvo", sessionId: id });
        } else {
            // Criar
            await pool.query(`
                INSERT INTO game_sessions (id, name, gm_id, status, map_url, game_state)
                VALUES ($1, $2, $3, $4, $5, $6)
            `, [id, name, gmId, status, mapUrl, gameState]);
            
            res.status(201).json({ message: "Mesa criada", sessionId: id });
        }
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Erro ao salvar jogo" });
    }
});

// Deletar Mesa (Dono ou Mestre)
app.delete('/api/game/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const username = req.user.name;

    try {
        const result = await pool.query('SELECT gm_id FROM game_sessions WHERE id = $1', [id]);
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Mesa não encontrada' });
        }

        const owner = result.rows[0].gm_id;

        // Permite se for o DONO ou o MESTRE
        if (username.toLowerCase() === 'mestre' || owner.toLowerCase() === username.toLowerCase()) {
            await pool.query('DELETE FROM game_sessions WHERE id = $1', [id]);
            res.json({ message: 'Sessão excluída com sucesso' });
        } else {
            res.status(403).json({ error: 'Apenas o criador pode excluir esta mesa.' });
        }
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Erro ao excluir sessão' });
    }
});

// ==================================================
// 4. HELPERS
// ==================================================

// Buscar Personagens do Usuário (em todas as mesas)
app.get('/api/my-characters', authenticateToken, async (req, res) => {
    const username = req.user.name;
    try {
        const query = `
            SELECT 
                token->>'id' as id,
                token->>'name' as name,
                token->>'url' as url,
                token->>'hp' as hp,
                token->>'maxHp' as "maxHp",
                token->>'role' as role,
                token->>'ownerId' as "ownerId",
                gs.name as "sessionName"
            FROM game_sessions gs,
            jsonb_array_elements(gs.game_state->'tokens') as token
            WHERE LOWER(token->>'ownerId') = LOWER($1)
        `;
        const result = await pool.query(query, [username]);
        res.json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Erro ao buscar personagens" });
    }
});

// Log de IA
app.post('/log', async (req, res) => {
    const { usuario, mensagem, resposta } = req.body;
    try {
        await pool.query(
            'INSERT INTO interaction_logs (usuario, mensagem, resposta) VALUES ($1, $2, $3)',
            [usuario, mensagem, resposta]
        );
        res.sendStatus(200);
    } catch (err) {
        console.error("Log error", err);
        res.sendStatus(200); 
    }
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
