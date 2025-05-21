import express from 'express';
const router = express.Router();

router.get('/api', (req, res) => {
  res.json({ mensagem: 'Olá do servidor Node.js!' });
});

export default router;
