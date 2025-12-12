const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();

// Aumenta o limite para aceitar mapas e imagens grandes em Base64
app.use(express.json({ limit: '50mb' }));
app.use(cors());

// Conexão com Banco de Dados (PostgreSQL)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false } // Obrigatório para Render/Neon/Supabase
});

const SECRET_KEY = process.env.JWT_SECRET || 'chave_super_secreta_rpg_123';

// ------------------------------------------------------------------
// CRIAÇÃO AUTOMÁTICA DE TABELAS (Caso não existam)
// ------------------------------------------------------------------
const initDB = async () => {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role VARCHAR(20) DEFAULT 'player'
            );
        `);
        
        await pool.query(`
            CREATE TABLE IF NOT EXISTS games (
                id VARCHAR(100) PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                gm_id VARCHAR(50) NOT NULL,
                status VARCHAR(20) DEFAULT 'open',
                map_url TEXT,
                game_data JSONB,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);
        console.log("Banco de dados inicializado/verificado.");
    } catch (err) {
        console.error("Erro ao iniciar DB:", err);
    }
};
initDB();

// ------------------------------------------------------------------
// MIDDLEWARE DE AUTENTICAÇÃO
// ------------------------------------------------------------------
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ error: 'Token não fornecido' });

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ error: 'Token inválido' });
        req.user = user;
        next();
    });
};

// ------------------------------------------------------------------
// ROTAS DE AUTENTICAÇÃO
// ------------------------------------------------------------------

// Registrar
app.post('/api/register', async (req, res) => {
    const { username, password, role } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query(
            'INSERT INTO users (username, password_hash, role) VALUES ($1, $2, $3)',
            [username, hashedPassword, role || 'player']
        );
        res.status(201).json({ message: 'Usuário criado com sucesso' });
    } catch (err) {
        if (err.code === '23505') { // Código de erro do Postgres para duplicidade
            return res.status(400).json({ error: 'Usuário já existe' });
        }
        res.status(500).json({ error: 'Erro ao registrar usuário' });
    }
});

// Login
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        if (result.rows.length === 0) return res.status(400).json({ error: 'Usuário não encontrado' });

        const user = result.rows[0];
        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) return res.status(400).json({ error: 'Senha incorreta' });

        const token = jwt.sign({ name: user.username, role: user.role }, SECRET_KEY);
        res.json({ token, user: { name: user.username, role: user.role } });
    } catch (err) {
        res.status(500).json({ error: 'Erro no login' });
    }
});

// Alterar Senha
app.post('/api/change-password', authenticateToken, async (req, res) => {
    const { oldPassword, newPassword } = req.body;
    const username = req.user.name;

    try {
        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        const user = result.rows[0];

        const validPassword = await bcrypt.compare(oldPassword, user.password_hash);
        if (!validPassword) return res.status(400).json({ error: 'Senha atual incorreta' });

        const newHashedPassword = await bcrypt.hash(newPassword, 10);
        await pool.query('UPDATE users SET password_hash = $1 WHERE username = $2', [newHashedPassword, username]);

        res.json({ message: 'Senha alterada com sucesso' });
    } catch (err) {
        res.status(500).json({ error: 'Erro ao alterar senha' });
    }
});

// ------------------------------------------------------------------
// ROTAS DO JOGO (GAME)
// ------------------------------------------------------------------

// Listar Mesas (Sessions)
app.get('/api/sessions', authenticateToken, async (req, res) => {
    try {
        // Retorna apenas informações básicas para a lista
        const result = await pool.query('SELECT id, name, gm_id as "gmId", status, map_url as "mapUrl" FROM games ORDER BY updated_at DESC');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: 'Erro ao buscar sessões' });
    }
});

// Carregar Jogo Específico
app.get('/api/game/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    try {
        const result = await pool.query('SELECT game_data FROM games WHERE id = $1', [id]);
        if (result.rows.length === 0) return res.status(404).json({ error: 'Mesa não encontrada' });
        
        // Retorna o JSON completo do jogo
        res.json(result.rows[0].game_data);
    } catch (err) {
        res.status(500).json({ error: 'Erro ao carregar jogo' });
    }
});

// Salvar Jogo
app.post('/api/game', authenticateToken, async (req, res) => {
    const { id, name, status, mapUrl, ...gameData } = req.body;
    const gmId = req.user.name; // Quem está salvando (geralmente o mestre ou autosave)

    // Monta o objeto completo para salvar no JSONB
    const fullGameState = {
        id, name, status, mapUrl, ...gameData, gmId // Inclui metadados dentro do JSON também
    };

    try {
        // UPSERT (Inserir ou Atualizar se existir)
        await pool.query(`
            INSERT INTO games (id, name, gm_id, status, map_url, game_data, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, NOW())
            ON CONFLICT (id) 
            DO UPDATE SET 
                name = EXCLUDED.name,
                status = EXCLUDED.status,
                map_url = EXCLUDED.map_url,
                game_data = EXCLUDED.game_data,
                updated_at = NOW();
        `, [id, name, gmId, status, mapUrl, JSON.stringify(fullGameState)]);
        
        res.json({ message: 'Jogo salvo', sessionId: id });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Erro ao salvar jogo' });
    }
});

// EXCLUIR MESA (A Rota que faltava!)
app.delete('/api/game/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const userId = req.user.name;

    try {
        // 1. Verifica se a mesa existe
        const result = await pool.query('SELECT * FROM games WHERE id = $1', [id]);
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: "Mesa não encontrada." });
        }

        const game = result.rows[0];
        
        // 2. Verifica permissão: Apenas o Dono (gm_id) ou o usuário 'Mestre' (Super Admin) pode apagar
        const isOwner = game.gm_id === userId;
        const isMaster = userId.toLowerCase() === 'mestre'; // Super Admin hardcoded

        if (!isOwner && !isMaster) {
            return res.status(403).json({ error: "Você não tem permissão para excluir esta mesa." });
        }

        // 3. Executa a exclusão
        await pool.query('DELETE FROM games WHERE id = $1', [id]);
        
        res.json({ message: "Mesa excluída com sucesso." });

    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Erro interno ao excluir mesa." });
    }
});

// Buscar Meus Personagens (Varre todas as mesas)
app.get('/api/my-characters', authenticateToken, async (req, res) => {
    const username = req.user.name;
    try {
        // Busca o JSON de todos os jogos
        const result = await pool.query('SELECT game_data FROM games');
        
        let myTokens = [];

        // Varre cada jogo para encontrar tokens pertencentes ao usuário
        result.rows.forEach(row => {
            const data = row.game_data;
            if (data && data.tokens && Array.isArray(data.tokens)) {
                const userTokens = data.tokens.filter(t => 
                    // Verifica se o ownerId bate OU se o nome do token é o nome do usuário
                    (t.ownerId && t.ownerId.toLowerCase() === username.toLowerCase()) || 
                    (t.name.toLowerCase() === username.toLowerCase())
                );
                myTokens.push(...userTokens);
            }
        });

        res.json(myTokens);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Erro ao buscar personagens' });
    }
});

// ------------------------------------------------------------------
// ROTA DE LOG (Opcional)
// ------------------------------------------------------------------
app.post('/log', async (req, res) => {
    console.log("INTERACTION LOG:", req.body);
    res.sendStatus(200);
});

// Porta do Servidor
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
});
