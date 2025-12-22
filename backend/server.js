const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const PORT = process.env.PORT || 3001;
const SECRET = process.env.JWT_SECRET || 'rpg-secret-key';

// Configuração do Banco de Dados SQLite
const db = new sqlite3.Database('./database.sqlite', (err) => {
  if (err) console.error('Erro ao conectar ao banco:', err.message);
  else console.log('Conectado ao banco de dados SQLite.');
});

// Inicialização das tabelas necessárias para o Aventurizer
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE,
    password TEXT,
    role TEXT
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    name TEXT,
    gmId TEXT,
    status TEXT,
    mapUrl TEXT,
    last_updated INTEGER
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS game_states (
    sessionId TEXT PRIMARY KEY,
    state TEXT,
    last_updated INTEGER
  )`);
});

app.use(cors());
app.use(express.json({ limit: '50mb' }));

// Middleware de Autenticação JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Acesso negado. Token não fornecido.' });

  jwt.verify(token, SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Token inválido ou expirado.' });
    req.user = user;
    next();
  });
};

// --- ROTAS DE AUTENTICAÇÃO ---

app.post('/api/register', async (req, res) => {
  const { username, password, role } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const id = Date.now().toString();
    db.run(`INSERT INTO users (id, username, password, role) VALUES (?, ?, ?, ?)`, 
    [id, username, hashedPassword, role], (err) => {
      if (err) return res.status(400).json({ error: "Este nome de usuário já está em uso." });
      res.status(201).json({ message: "Conta criada com sucesso." });
    });
  } catch (e) {
    res.status(500).json({ error: "Erro interno ao criar conta." });
  }
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
    if (err || !user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: "Usuário ou senha inválidos." });
    }
    const token = jwt.sign({ name: user.username, role: user.role }, SECRET);
    res.json({ token, user: { name: user.username, role: user.role } });
  });
});

app.post('/api/change-password', authenticateToken, async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  db.get(`SELECT * FROM users WHERE username = ?`, [req.user.name], async (err, user) => {
    if (err || !user || !(await bcrypt.compare(oldPassword, user.password))) {
      return res.status(401).json({ error: "Senha atual está incorreta." });
    }
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    db.run(`UPDATE users SET password = ? WHERE username = ?`, [hashedPassword, req.user.name], (err) => {
      if (err) return res.status(500).json({ error: "Erro ao atualizar banco de dados." });
      res.json({ message: "Senha alterada com sucesso." });
    });
  });
});

// --- ROTAS DE JOGO ---

app.get('/api/sessions', authenticateToken, (req, res) => {
  db.all(`SELECT id, name, gmId, status, mapUrl FROM sessions`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.get('/api/game/:sessionId', authenticateToken, (req, res) => {
  const { sessionId } = req.params;
  const since = parseInt(req.query.since) || 0;

  db.get(`SELECT state, last_updated FROM game_states WHERE sessionId = ?`, [sessionId], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!row) return res.status(404).json({ error: "Mesa não encontrada." });

    // Lógica de Smart Polling: se não mudou nada desde o último timestamp do cliente
    if (row.last_updated <= since) {
      return res.json({ notModified: true });
    }

    const state = JSON.parse(row.state);
    res.json({ ...state, timestamp: row.last_updated });
  });
});

app.post('/api/game', authenticateToken, (req, res) => {
  const { id, name, status, mapUrl, ...state } = req.body;
  const timestamp = Date.now();
  const stateString = JSON.stringify({ ...state, status, mapUrl });

  db.serialize(() => {
    // Atualiza ou insere a sessão
    db.run(`INSERT INTO sessions (id, name, gmId, status, mapUrl, last_updated) 
            VALUES (?, ?, ?, ?, ?, ?) 
            ON CONFLICT(id) DO UPDATE SET 
            name=excluded.name, status=excluded.status, mapUrl=excluded.mapUrl, last_updated=excluded.last_updated`,
    [id, name, req.user.name, status, mapUrl, timestamp]);

    // Atualiza ou insere o estado detalhado (tokens, walls, fog, etc)
    db.run(`INSERT INTO game_states (sessionId, state, last_updated) 
            VALUES (?, ?, ?) 
            ON CONFLICT(sessionId) DO UPDATE SET 
            state=excluded.state, last_updated=excluded.last_updated`,
    [id, stateString, timestamp], (err) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ sessionId: id, timestamp });
    });
  });
});

app.get('/api/my-characters', authenticateToken, (req, res) => {
  db.all(`SELECT state FROM game_states`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    let myChars = [];
    rows.forEach(row => {
      const state = JSON.parse(row.state);
      if (state.tokens) {
        const owned = state.tokens.filter(t => t.ownerId === req.user.name);
        myChars = [...myChars, ...owned];
      }
    });
    res.json(myChars);
  });
});

app.post('/log', (req, res) => {
  console.log('Interação Registrada:', req.body);
  res.sendStatus(200);
});

app.listen(PORT, () => {
  console.log(`Servidor Aventurizer rodando na porta ${PORT}`);
});
