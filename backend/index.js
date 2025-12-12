require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 10000;

// Configuração do CORS
app.use(cors());
app.use(express.json({ limit: '50mb' })); // Limite alto para upload de mapas/imagens em base64

// Conexão com Banco de Dados
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false } // Necessário para maioria dos hosts em nuvem (Render, Neon)
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

// ==========================================
// ROTAS DE AUTENTICAÇÃO
// ==========================================

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
                { expiresIn: '30d' } // Token dura 30 dias para evitar logins constantes
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

// Alterar Senha
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

// ==========================================
// ROTAS DE ADMINISTRAÇÃO (USUÁRIOS)
// ==========================================

// Listar Usuários (Apenas Mestre)
app.get('/api/users', authenticateToken, async (req, res) => {
    if (req.user.name.toLowerCase() !== 'mestre') {
        return res.status(403).json({ error: 'Acesso negado. Apenas o Mestre Supremo pode ver usuários.' });
    }

    try {
        const result = await pool.query('SELECT id, username, role, created_at FROM users ORDER BY username ASC');
        res.json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Erro ao buscar usuários' });
    }
});

// Deletar Usuário (Apenas Mestre)
app.delete('/api/users/:username', authenticateToken, async (req, res) => {
    const { username } = req.params;

    if (req.user.name.toLowerCase() !== 'mestre') {
        return res.status(403).json({ error: 'Acesso negado.' });
    }

    if (username.toLowerCase() === 'mestre') {
        return res.status(400).json({ error: 'O Mestre Supremo é imortal.' });
    }

    try {
        // Deleta sessões do usuário primeiro para manter integridade (ou set null dependendo da lógica)
        await pool.query('DELETE FROM game_sessions WHERE gm_id = $1', [username]);
        
        // Deleta o usuário
        await pool.query('DELETE FROM users WHERE username = $1', [username]);
        
        res.json({ message: `Usuário ${username} eliminado da existência.` });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Erro ao deletar usuário' });
    }
});

// ==========================================
// ROTAS DE JOGO (SESSÕES)
// ==========================================

// Listar Sessões
app.get('/api/sessions', authenticateToken, async (req, res) => {
    try {
        // Retorna metadados básicos das sessões
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

// Carregar Jogo Completo
app.get('/api/game/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    try {
        const result = await pool.query('SELECT * FROM game_sessions WHERE id = $1', [id]);
        if (result.rows.length === 0) return res.status(404).json({ error: "Mesa não encontrada" });

        const session = result.rows[0];
        
        // Mescla metadados com o estado do jogo salvo no JSONB
        const fullState = {
            ...session.game_state,
            id: session.id,
            name: session.name,
            gmId: session.gm_id,
            status: session.status,
            mapUrl: session.map_url,
            // Fallback para arrays vazios se o JSONB estiver incompleto
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

// Salvar/Criar Jogo
app.post('/api/game', authenticateToken, async (req, res) => {
    const { id, name, status, mapUrl, tokens, walls, fog, annotations, videos, images, sounds, activeImageId, activeVideoId } = req.body;
    const gmId = req.user.name;

    // Monta o objeto JSONB para salvar
    const gameState = {
        tokens, walls, fog, annotations, videos, images, sounds, activeImageId, activeVideoId
    };

    try {
        // Verifica se a sessão já existe
        const check = await pool.query('SELECT gm_id FROM game_sessions WHERE id = $1', [id]);

        if (check.rows.length > 0) {
            // Sessão existe: Atualizar
            // Lógica de permissão: Apenas o dono ou o Mestre podem salvar, 
            // MAS jogadores podem salvar alterações menores (movimento) se a mesa estiver aberta.
            // Para simplicidade, permitimos update se o ID bater, o front controla a lógica de quem mexe no que.
            
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
            // Nova Sessão
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

// Deletar Jogo (ATUALIZADO PARA SUPORTE AO MESTRE)
app.delete('/api/game/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const username = req.user.name;

    try {
        // Busca quem é o dono da mesa
        const result = await pool.query('SELECT gm_id FROM game_sessions WHERE id = $1', [id]);
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Mesa não encontrada' });
        }

        const owner = result.rows[0].gm_id;

        // VERIFICAÇÃO DE PERMISSÃO:
        // 1. É o dono da mesa (case-insensitive)
        // 2. É o usuário "mestre" (Super Admin)
        if (username.toLowerCase() === 'mestre' || owner.toLowerCase() === username.toLowerCase()) {
            await pool.query('DELETE FROM game_sessions WHERE id = $1', [id]);
            res.json({ message: 'Sessão excluída com sucesso' });
        } else {
            res.status(403).json({ error: 'Apenas o Mestre criador pode excluir esta mesa.' });
        }
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Erro ao excluir sessão' });
    }
});

// Rota de Compatibilidade (caso o frontend antigo chame /sessions/:id)
app.delete('/api/sessions/:id', authenticateToken, async (req, res) => {
    // Redireciona a lógica para a mesma função acima se fosse um middleware, 
    // mas aqui repetimos a lógica por simplicidade ou fazemos um redirect interno.
    // Vamos apenas retornar 404 para forçar o front a usar a rota nova, 
    // ou copiar a lógica acima se necessário. O front fornecido já usa /api/game/:id.
    res.status(404).json({ error: "Endpoint deprecated. Use DELETE /api/game/:id" });
});

// ==========================================
// ROTAS AUXILIARES
// ==========================================

// Buscar "Meus Personagens" (Procura tokens onde ownerId == usuário logado em todas as sessões)
app.get('/api/my-characters', authenticateToken, async (req, res) => {
    const username = req.user.name;
    try {
        // Query complexa de JSONB para extrair tokens de dentro dos objetos de sessão
        // PostgreSql permite expandir arrays JSON
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

// Log de Interação (Para debug da IA)
app.post('/log', async (req, res) => {
    const { usuario, mensagem, resposta } = req.body;
    try {
        await pool.query(
            'INSERT INTO interaction_logs (usuario, mensagem, resposta) VALUES ($1, $2, $3)',
            [usuario, mensagem, resposta]
        );
        res.sendStatus(200);
    } catch (err) {
        // Não falhar o app se o log falhar
        console.error("Log error", err);
        res.sendStatus(200); 
    }
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
