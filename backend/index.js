const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.JWT_SECRET || 'chave_secreta_padrao_mude_no_render';
const DATA_DIR = path.join(__dirname, 'data');

// Cria a pasta data se não existir
if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR);
}

app.use(cors());
app.use(express.json({ limit: '50mb' }));

// Funções auxiliares de persistência
function loadData(file, defaultVal) {
    const filePath = path.join(DATA_DIR, file);
    if (fs.existsSync(filePath)) {
        try {
            return JSON.parse(fs.readFileSync(filePath));
        } catch (e) {
            return defaultVal;
        }
    }
    return defaultVal;
}

function saveData(file, data) {
    fs.writeFileSync(path.join(DATA_DIR, file), JSON.stringify(data, null, 2));
}

// Carregar dados iniciais
let users = loadData('users.json', []);
let sessions = loadData('sessions.json', {});

// Middleware de Autenticação
const authenticate = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'Token não fornecido' });

    const token = authHeader.split(' ')[1];
    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ error: 'Sessão expirada. Faça login novamente.' });
        req.user = user;
        next();
    });
};

// --- ROTAS ---

app.get('/', (req, res) => res.send('Aventurizer Backend Online!'));

app.post('/api/register', (req, res) => {
    const { username, password, role } = req.body;
    if (users.find(u => u.username === username)) {
        return res.status(400).json({ error: 'Este usuário já existe.' });
    }
    users.push({ username, password, role });
    saveData('users.json', users);
    res.status(201).json({ message: 'Registrado com sucesso' });
});

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username && u.password === password);
    if (!user) return res.status(401).json({ error: 'Usuário ou senha incorretos.' });

    const token = jwt.sign({ name: user.username, role: user.role }, SECRET_KEY, { expiresIn: '7d' });
    res.json({ token, user: { name: user.username, role: user.role } });
});

app.get('/api/sessions', authenticate, (req, res) => {
    const sessionList = Object.values(sessions).map(s => ({
        id: s.id,
        name: s.name,
        gmId: s.gmId,
        status: s.status,
        mapUrl: s.mapUrl
    }));
    res.json(sessionList);
});

app.get('/api/game/:id', authenticate, (req, res) => {
    const session = sessions[req.params.id];
    if (!session) return res.status(404).json({ error: 'Sessão não encontrada' });

    const since = parseInt(req.query.since) || 0;
    if (session.timestamp <= since) {
        return res.json({ notModified: true });
    }
    res.json(session);
});

app.post('/api/game', authenticate, (req, res) => {
    const state = req.body;
    const sessionId = state.id;
    const existing = sessions[sessionId];

    if (existing && existing.gmId !== req.user.name && existing.status === 'closed') {
        return res.status(403).json({ error: 'A mesa está fechada para alterações por jogadores.' });
    }

    const newState = {
        ...state,
        gmId: existing ? existing.gmId : req.user.name,
        timestamp: Date.now()
    };

    sessions[sessionId] = newState;
    saveData('sessions.json', sessions);
    res.json({ sessionId, timestamp: newState.timestamp });
});

app.get('/api/my-characters', authenticate, (req, res) => {
    const myChars = [];
    Object.values(sessions).forEach(session => {
        const owned = session.tokens.filter(t => t.ownerId === req.user.name);
        myChars.push(...owned);
    });
    res.json(myChars);
});

app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
});
