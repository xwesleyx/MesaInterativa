
import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

// Configuração do __dirname para ES Modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.JWT_SECRET || 'chave_mestra_aventurizer';
const DATA_DIR = path.join(__dirname, 'data');

// Criar pasta de dados se não existir
if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR);
}

app.use(cors());
app.use(express.json({ limit: '50mb' }));

// Helper para carregar/salvar JSON
const loadJSON = (file, def) => {
    const p = path.join(DATA_DIR, file);
    return fs.existsSync(p) ? JSON.parse(fs.readFileSync(p, 'utf-8')) : def;
};
const saveJSON = (file, data) => fs.writeFileSync(path.join(DATA_DIR, file), JSON.stringify(data, null, 2));

let users = loadJSON('users.json', []);
let sessions = loadJSON('sessions.json', {});

// Middleware de Autenticação
const authenticate = (req, res, next) => {
    const auth = req.headers.authorization;
    if (!auth) return res.status(401).json({ error: 'Não autorizado' });
    const token = auth.split(' ')[1];
    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) return res.status(403).json({ error: 'Sessão expirada' });
        req.user = decoded;
        next();
    });
};

// Rotas
app.get('/', (req, res) => res.send('Servidor Aventurizer Ativo!'));

app.post('/api/register', (req, res) => {
    const { username, password, role } = req.body;
    if (users.find(u => u.username === username)) return res.status(400).json({ error: 'Usuário já existe' });
    users.push({ username, password, role });
    saveJSON('users.json', users);
    res.status(201).json({ message: 'Registrado!' });
});

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username && u.password === password);
    if (!user) return res.status(401).json({ error: 'Credenciais inválidas' });
    const token = jwt.sign({ name: user.username, role: user.role }, SECRET_KEY, { expiresIn: '7d' });
    res.json({ token, user: { name: user.username, role: user.role } });
});

app.get('/api/sessions', authenticate, (req, res) => res.json(Object.values(sessions)));

app.get('/api/game/:id', authenticate, (req, res) => {
    const game = sessions[req.params.id];
    if (!game) return res.status(404).send();
    const since = parseInt(req.query.since || 0);
    if (game.timestamp <= since) return res.json({ notModified: true });
    res.json(game);
});

app.post('/api/game', authenticate, (req, res) => {
    const state = req.body;
    const existing = sessions[state.id];
    if (existing && existing.gmId !== req.user.name && existing.status === 'closed') {
        return res.status(403).json({ error: 'Mesa fechada' });
    }
    const newState = { ...state, gmId: existing?.gmId || req.user.name, timestamp: Date.now() };
    sessions[state.id] = newState;
    saveJSON('sessions.json', sessions);
    res.json({ sessionId: state.id, timestamp: newState.timestamp });
});

app.listen(PORT, () => console.log(`Rodando na porta ${PORT}`));
