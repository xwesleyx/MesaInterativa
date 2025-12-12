// --- ROTA DE EXCLUSÃO (Adicione isso no index.js do Backend) ---

app.delete('/api/game/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const userId = req.user.name;

    try {
        // 1. Verificar se a mesa existe
        const result = await pool.query('SELECT * FROM games WHERE id = $1', [id]);
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: "Mesa não encontrada." });
        }

        const game = result.rows[0];

        // 2. Verificar permissão (Apenas o Dono ou o usuário 'Mestre' pode apagar)
        // Nota: Ajuste a lógica de 'gm_id' conforme o nome da coluna no seu banco (pode ser 'gm_id', 'owner', etc)
        // Se o seu banco salva o JSON inteiro na coluna 'game_data', o mestre estaria dentro do JSON.
        
        // Exemplo assumindo estrutura simples onde gm_id é coluna:
        const isOwner = game.gm_id === userId;
        const isMaster = userId.toLowerCase() === 'mestre';

        if (!isOwner && !isMaster) {
            return res.status(403).json({ error: "Você não tem permissão para excluir esta mesa." });
        }

        // 3. Executar a exclusão
        await pool.query('DELETE FROM games WHERE id = $1', [id]);
        
        res.json({ message: "Mesa excluída com sucesso." });

    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Erro interno ao excluir mesa." });
    }
});
