import express from "express";
import http from "http";
import { Server } from "socket.io";
import dotenv from "dotenv";
import { Pool } from "pg";
dotenv.config();

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

app.use(express.json());

// Conexão com Postgres via DATABASE_URL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false
});

// Função para criar tabelas básicas (rodada no start)
async function ensureTables() {
  await pool.query(`
    CREATE EXTENSION IF NOT EXISTS "pgcrypto";
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE,
      name TEXT,
      picture TEXT,
      role TEXT DEFAULT 'player',
      created_at TIMESTAMP DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS game_sessions (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      name TEXT,
      master_id TEXT REFERENCES users(id),
      state JSONB DEFAULT '{}'::jsonb,
      history JSONB DEFAULT '[]'::jsonb,
      created_at TIMESTAMP DEFAULT now(),
      updated_at TIMESTAMP DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS tokens (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      session_id UUID REFERENCES game_sessions(id) ON DELETE CASCADE,
      owner_id TEXT REFERENCES users(id),
      name TEXT,
      x INTEGER,
      y INTEGER,
      meta JSONB DEFAULT '{}'::jsonb,
      created_at TIMESTAMP DEFAULT now(),
      updated_at TIMESTAMP DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS actions_log (
      id BIGSERIAL PRIMARY KEY,
      session_id UUID,
      user_id TEXT,
      action_type TEXT,
      payload JSONB,
      created_at TIMESTAMP DEFAULT now()
    );
  `);
  console.log("Tabelas verificadas/criadas");
}

// rota simples
app.get("/health", (req, res) => res.json({ ok: true }));

// rota para criar sessão (simples)
app.post("/api/session", async (req, res) => {
  const { name, master_id } = req.body;
  try {
    const result = await pool.query(
      `INSERT INTO game_sessions(name, master_id, state) VALUES($1,$2,$3) RETURNING *`,
      [name || "Sala", master_id || null, JSON.stringify({})]
    );
    res.json(result.rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro ao criar sessão" });
  }
});

// rota para listar sessões
app.get("/api/sessions", async (req, res) => {
  const result = await pool.query(`SELECT id, name, master_id, created_at FROM game_sessions ORDER BY created_at DESC`);
  res.json(result.rows);
});

// websocket minimal: join room e broadcast simples
io.on("connection", (socket) => {
  console.log("socket conectado:", socket.id);
  socket.on("join_session", ({ sessionId }) => {
    socket.join(sessionId);
    console.log("Socket", socket.id, "entrou em", sessionId);
  });
  socket.on("send_message", ({ sessionId, msg }) => {
    io.to(sessionId).emit("message", { msg, ts: Date.now() });
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, async () => {
  console.log("Server listening on", PORT);
  try {
    await ensureTables();
  } catch (e) {
    console.error("Erro criando tabelas:", e);
  }
});
