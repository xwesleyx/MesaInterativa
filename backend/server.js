import express from "express";
import { Pool } from "pg";
import cors from "cors";

const app = express();
app.use(express.json());
app.use(cors());

// conexão com o banco do Render
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// cria tabela quando o backend inicia
(async () => {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS jogadores (
      id SERIAL PRIMARY KEY,
      nome TEXT,
      classe TEXT,
      pos_x INTEGER,
      pos_y INTEGER
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS logs (
      id SERIAL PRIMARY KEY,
      usuario TEXT,
      mensagem TEXT,
      resposta TEXT,
      criado_em TIMESTAMP DEFAULT NOW()
    );
  `);

  console.log("Tabelas criadas / OK");
})();

// salvar posição do personagem
app.post("/mover", async (req, res) => {
  const { nome, x, y } = req.body;

  await pool.query(
    "UPDATE jogadores SET pos_x=$1, pos_y=$2 WHERE nome=$3",
    [x, y, nome]
  );

  res.json({ ok: true });
});

// registrar conversa ou ações
app.post("/log", async (req, res) => {
  const { usuario, mensagem, resposta } = req.body;

  await pool.query(
    "INSERT INTO logs(usuario, mensagem, resposta) VALUES ($1,$2,$3)",
    [usuario, mensagem, resposta]
  );

  res.json({ ok: true });
});

// lista jogadores (para o mestre)
app.get("/jogadores", async (req, res) => {
  const result = await pool.query("SELECT * FROM jogadores");
  res.json(result.rows);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Backend ativo na porta " + PORT));
