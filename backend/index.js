// DELETE /api/game/:id - Excluir uma mesa
app.delete('/api/game/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const user = req.user;

  try {
    // Verificar se a mesa existe
    const checkQuery = 'SELECT * FROM games WHERE id = $1';
    const checkResult = await pool.query(checkQuery, [id]);

    if (checkResult.rows.length === 0) {
      return res.status(404).json({ error: 'Mesa não encontrada.' });
    }

    const game = checkResult.rows[0];

    // Verificar permissão: Apenas o dono (GM) ou o usuário mestre ('Mestre') pode excluir
    const isOwner = game.gm_id === user.username; // Supondo que a coluna seja gm_id
    const isMaster = user.username.toLowerCase() === 'mestre';

    if (!isOwner && !isMaster) {
      return res.status(403).json({ error: 'Permissão negada. Apenas o Mestre da mesa pode excluí-la.' });
    }

    // EXECUTAR EXCLUSÃO
    const deleteQuery = 'DELETE FROM games WHERE id = $1';
    await pool.query(deleteQuery, [id]);

    res.json({ message: 'Mesa excluída com sucesso.' });
  } catch (error) {
    console.error('Erro ao excluir mesa:', error);
    res.status(500).json({ error: 'Erro interno ao excluir a mesa.' });
  }
});
