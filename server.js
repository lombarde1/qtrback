// server.js - Versão Atualizada com PixUp
const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcrypt');
const app = express();
const axios = require('axios');
const dayjs = require('dayjs');
const { Server } = require('socket.io');
const http = require('http');
const c = require('crypto');

app.use(cors());
app.use(express.json());

const port = process.env.PORT || 3000;

// Conexão com o MySQL (XAMPP)
const db = mysql.createConnection({
  host: '212.85.15.38',
  port: 1345,
  user: 'admin',
  password: 'root',
  database: 'dbtrade'
});

const server = http.createServer(app);
const io = new Server(server,{cors:{origin:"*"}});
io.on('connection', socket => {
  console.log(`Cliente conectado: ${socket.id}`);
});

// Configurações da PixUp
const PIXUP_CONFIG = {
  baseUrl: 'https://api.pixupbr.com/v2', // Substitua pela URL real da PixUp
  clientId: 'dkvips25_0582376128',
  clientSecret: 'be0372fd459fc663fe625f39b066632f3cb5b7a77b8459b292073f498e677062',
  webhookUrl: 'https://qtrade-api.krkzfx.easypanel.host/webhook'
};


// Função para obter token da PixUp
async function getPixUpToken() {
  try {
    const credentials = Buffer.from(`${PIXUP_CONFIG.clientId}:${PIXUP_CONFIG.clientSecret}`).toString('base64');
    
    const tokenResponse = await axios.post(
      `${PIXUP_CONFIG.baseUrl}/oauth/token`,
      'grant_type=client_credentials',
      {
        headers: {
          'Authorization': `Basic ${credentials}`,
          'Content-Type': 'application/x-www-form-urlencoded',
        },
      }
    );

    return tokenResponse.data.access_token;
  } catch (error) {
    console.error('Erro ao obter token PixUp:', error.response?.data || error.message);
    throw new Error('Falha na autenticação PixUp');
  }
}

// Rota de registro
app.post('/register', async (req, res) => {
  const { usuario, senha } = req.body;

  if (!usuario || !senha) return res.status(400).json({ erro: 'Campos obrigatórios.' });

  function invite(tamanho = 10){
    const letras = 'ABCDEFGHIJKLmNOPQRSTUVWXYZ0123456789';
    let resultado = '';
    for (let i = 0; i < tamanho; i++){
      const indice = Math.floor(Math.random() * letras.length);
      resultado += letras[indice];
    }
    return resultado;
  }

  const invite2 = invite(8);

  try {
    const [exist] = await db.promise().query('SELECT * FROM usuarios WHERE usuario = ?', [usuario]);
    if (exist.length > 0) return res.status(400).json({ erro: 'Usuário já existe.' });

    const senhaCriptografada = await bcrypt.hash(senha, 10);
    await db.promise().query('INSERT INTO usuarios (usuario, senha, codigo_invite) VALUES (?, ?, ?)', [usuario, senhaCriptografada, invite2]);
    res.json({ sucesso: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ erro: 'Erro ao registrar.' });
  }
});

// Rota de login
app.post('/login', async (req, res) => {
  const { usuario, senha } = req.body;
  if (!usuario || !senha) return res.status(400).json({ erro: 'Campos obrigatórios.' });

  try {
    const [rows] = await db.promise().query('SELECT * FROM usuarios WHERE usuario = ?', [usuario]);
    if (rows.length === 0) return res.status(400).json({ erro: 'Usuário não encontrado.' });

    const match = await bcrypt.compare(senha, rows[0].senha);
    if (!match) return res.status(401).json({ erro: 'Senha incorreta.' });

    res.json({ sucesso: true, usuario: rows[0].usuario, saldo: rows[0].saldo, bonus: rows[0].bonus });
  } catch (err) {
    console.error(err);
    res.status(500).json({ erro: 'Erro ao fazer login.' });
  }
});

// Rota de verificação de sessão
app.get('/session/:usuario', async (req, res) => {
  try {
    const { usuario } = req.params;
    const [rows] = await db.promise().query('SELECT * FROM usuarios WHERE usuario = ?', [usuario]);
    if (rows.length === 0) return res.status(404).json({ erro: 'Usuário não encontrado.' });
    res.json({ sucesso: true, usuario: rows[0].usuario, saldo: rows[0].saldo, bonus: rows[0].bonus });
  } catch (err) {
    res.status(500).json({ erro: 'Erro ao buscar dados do usuário.' });
  }
});

// Rota para aplicar bônus
app.post('/bonus', async (req, res) => {
  const { usuario } = req.body;
  try {
    const [rows] = await db.promise().query('SELECT bonus,saldo FROM usuarios WHERE usuario = ?', [usuario]);
    if (rows.length === 0) return res.status(404).json({ erro: 'Usuário não encontrado.' });

    if (rows[0].saldo < 30){
      return res.status(400).json({ erro: 'Saldo mínimo necessário R$30.' });
    }

    if (rows[0].bonus === 1) return res.json({ sucesso: false, mensagem: 'Bônus já recebido.' });

    await db.promise().query('UPDATE usuarios SET saldo = saldo + 400, bonus = 1 WHERE usuario = ?', [usuario]);
    res.json({ sucesso: true, mensagem: 'Bônus aplicado com sucesso.' });
  } catch (err) {
    res.status(500).json({ erro: 'Erro ao aplicar bônus.' });
  }
});

// Função para gerar nomes aleatórios
function gerarNomeAleatorio() {
  const nomes = ['João', 'Maria', 'Pedro', 'Ana', 'Lucas', 'Beatriz', 'Carlos', 'Fernanda', 'Rafael', 'Juliana'];
  const indiceAleatorio = Math.floor(Math.random() * nomes.length);
  const nomes2 = ['Silva', 'Barbosa', 'Galvão', 'Alencar', 'Nogueira', 'Cropalato', 'Cabarros', 'Ferreira', 'Lima', 'Silva'];
  const indiceAleatorio2 = Math.floor(Math.random() * nomes2.length);
  return nomes[indiceAleatorio] + " " + nomes2[indiceAleatorio2];
}

// Outras rotas existentes...
app.put('/update_user/:id', async (req, res) => {
  const usuarioId = req.params.id;

  try {
    const updateUserQuery = `
      UPDATE usuarios
      SET saldo = 69, total_indicados = 3
      WHERE usuario = ?
    `;
    
    await db.promise().query(updateUserQuery, [usuarioId]);

    for (let i = 0; i < 3; i++) {
      const nomeIndicado = gerarNomeAleatorio();
      const insertIndicadosQuery = `
        INSERT INTO indicados (usuario_id, nome_indicado)
        VALUES (?, ?)
      `;
      await db.promise().query(insertIndicadosQuery, [usuarioId, nomeIndicado]);
    }

    res.status(200).json({ sucesso: true, mensagem: 'Saldo atualizado e 3 indicados adicionados.' });
  } catch (erro) {
    console.error(erro);
    res.status(500).json({ erro: 'Erro ao atualizar usuário e adicionar indicados.' });
  }
});

app.get('/busca_indicados/:id', async (req, res) => {
  const usuarioId = req.params.id;

  try {
    const [rows] = await db.promise().query('SELECT nome_indicado FROM indicados WHERE usuario_id = ?', [usuarioId]);

    if (rows.length === 0) {
      return res.status(404).json({ erro: 'Nenhum indicado encontrado.' });
    }

    res.status(200).json({ indicados: rows });
  } catch (erro) {
    console.error(erro);
    res.status(500).json({ erro: 'Erro ao buscar indicados.' });
  }
});

app.get('/busca_user/', async (req, res) => {
  try {
    const {usuario} = req.query;

    const [rows] = await db.promise().query("SELECT * from usuarios WHERE usuario = ?", [usuario]);

    if(rows.length === 0){
      return res.status(404).json({erro: usuario});
    }else{
      res.json({sucesso: true, usuario: rows[0].usuario, saldo: rows[0].saldo, tindicados: rows[0].total_indicados, refer_code: rows[0].codigo_invite});
    }
  } catch (erro) {
    res.status(500).json({erro: "erro na api"});
  }
});

// WEBHOOK ATUALIZADO PARA PIXUP
app.post('/webhook', async (req, res) => {
  console.log('Webhook PixUp recebido:', req.body);
  
  try {
    const { requestBody } = req.body;

    if (!requestBody) {
      console.log('RequestBody não encontrado no webhook');
      return res.status(400).json({ erro: 'Dados do webhook inválidos' });
    }

    console.log('Dados do webhook PixUp:', JSON.stringify(requestBody, null, 2));

    // Verificar se o pagamento foi aprovado
    if (requestBody.status !== 'PAID') {
      console.log(`Status do pagamento: ${requestBody.status} - Aguardando confirmação`);
      return res.status(200).json({ message: 'Status recebido, aguardando pagamento' });
    }

    // Buscar a transação mais recente pendente
    const [depoRows] = await db.promise().query(
      'SELECT iduser, valor FROM depositos WHERE status = 0 ORDER BY data DESC LIMIT 1'
    );
    
    if (depoRows.length === 0) {
      console.log('Nenhuma transação pendente encontrada');
      return res.status(404).json({ erro: 'Transação não encontrada' });
    }

    const { iduser, valor } = depoRows[0];
    const amount = parseFloat(valor);

    console.log(`Processando pagamento: Usuário ${iduser}, Valor: R$${amount}`);

    // Atualizar saldo do usuário
    await db.promise().query(
      'UPDATE usuarios SET saldo = saldo + ? WHERE id = ?', 
      [amount, iduser]
    );

    // Marcar depósito como processado (usando idpix existente)
    await db.promise().query(
      'UPDATE depositos SET status = 1 WHERE iduser = ? AND status = 0 ORDER BY data DESC LIMIT 1',
      [iduser]
    );

    // Emitir evento via Socket.IO
    io.emit('pagamento-concluido', { 
      iduser, 
      transactionId: requestBody.transactionId, 
      amount,
      status: 'COMPLETED'
    });

    console.log(`Saldo atualizado com sucesso para usuário ${iduser}`);

    // Notificação opcional
    try {
      await axios.get('https://api.pushcut.io/ChzkB6ZYQL5SvlUwWpo2i/notifications/Venda%20Realizada');
    } catch (e) {
      console.log('Erro na notificação:', e.message);
    }

    res.status(200).json({ 
      success: true, 
      message: 'Pagamento processado com sucesso',
      transactionId: requestBody.transactionId
    });

  } catch (error) {
    console.error('Erro ao processar webhook PixUp:', error);
    res.status(500).json({ erro: 'Erro interno do servidor' });
  }
});

// ROTA DE DEPÓSITO ATUALIZADA PARA PIXUP
app.post('/deposit', async (req, res) => {
  const { usuario, valor } = req.body;
  
  console.log('Iniciando depósito PixUp:', { usuario, valor });
  
  if (!usuario || !valor) {
    return res.status(400).json({ erro: 'Dados faltando.' });
  }
  
  if (valor < 2) {
    return res.status(400).json({ erro: 'Valor mínimo é R$2,00' });
  }

  try {
    // Buscar usuário
    const [uRows] = await db.promise().query('SELECT id FROM usuarios WHERE usuario=?', [usuario]);
    if (!uRows.length) {
      return res.status(404).json({ erro: 'Usuário não encontrado' });
    }

    const user = uRows[0];
    const externalId = `PIX_${Date.now()}_${user.id}`;

    // Obter token da PixUp
    const accessToken = await getPixUpToken();

    // Dados da solicitação PIX
    const pixRequestData = {
      amount: parseFloat(valor),
      postbackUrl: PIXUP_CONFIG.webhookUrl,
      payer: {
        name: "Cliente",
        document: "123456789",
        email: "cliente@exemplo.com"
      }
    };

    console.log('Enviando solicitação para PixUp:', pixRequestData);

    // Gerar QR Code PIX na PixUp
    const pixResponse = await axios.post(
      `${PIXUP_CONFIG.baseUrl}/pix/qrcode`,
      pixRequestData,
      {
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${accessToken}`,
        }
      }
    );

    console.log('Resposta da PixUp:', pixResponse.data);

    const { qrcode, id: pixupTransactionId, qrcodeImage } = pixResponse.data;

    // Salvar transação no banco
    const agora = dayjs().format('YYYY-MM-DD HH:mm:ss');
    await db.promise().query(
      'INSERT INTO depositos (iduser, valor, data, idpix, status) VALUES (?,?,?,?,0)',
      [user.id, valor, agora, pixupTransactionId]
    );

    console.log('Transação salva no banco de dados');

    // Notificação opcional
    try {
      await axios.get('https://api.pushcut.io/ChzkB6ZYQL5SvlUwWpo2i/notifications/Pix%20Gerado');
    } catch (e) {
      console.log('Erro na notificação:', e.message);
    }

    res.json({ 
      sucesso: true, 
      pix_code: qrcode,
      qr_code_image: qrcodeImage || null,
      transaction_id: pixupTransactionId,
      external_id: externalId,
      amount: valor
    });

  } catch (error) {
    console.error('Erro ao gerar depósito PixUp:', error.response?.data || error.message);
    res.status(500).json({ 
      erro: 'Falha ao gerar depósito',
      details: error.response?.data || error.message
    });
  }
});

// Rota para verificar status do pagamento PIX (usando idpix existente)
app.get('/deposit/status/:idpix', async (req, res) => {
  try {
    const { idpix } = req.params;

    const [rows] = await db.promise().query(
      'SELECT * FROM depositos WHERE idpix = ?',
      [idpix]
    );

    if (rows.length === 0) {
      return res.status(404).json({ erro: 'Transação não encontrada' });
    }

    const transaction = rows[0];
    
    res.json({
      sucesso: true,
      status: transaction.status === 1 ? 'COMPLETED' : 'PENDING',
      valor: transaction.valor,
      data: transaction.data,
      transaction_id: transaction.idpix
    });

  } catch (error) {
    console.error('Erro ao verificar status:', error);
    res.status(500).json({ erro: 'Erro ao verificar status do pagamento' });
  }
});

// Outras rotas existentes...
app.post('/save-candle', (req, res) => {
  const { time, open, high, low, close, cryptoId } = req.body;

  if (!time || !open || !high || !low || !close || !cryptoId) {
    return res.status(400).json({ error: 'Dados faltando' });
  }

  const query = 'INSERT INTO candles (time, open, high, low, close, cryptoId) VALUES (?, ?, ?, ?, ?, ?)';
  db.query(query, [time, open, high, low, close, cryptoId], (err, result) => {
    if (err) {
      return res.status(500).json({ error: 'Erro ao salvar o candle' });
    }
    res.json({ success: true, message: 'Candle salvo com sucesso!' });
  });
});

app.post('/withdraw', async (req,res)=>{
  const { usuario, valor, chavepix } = req.body;
  if (!usuario || !valor || !chavepix) return res.status(400).json({ erro:'Dados faltando'});
  if (valor < 30) return res.status(400).json({ erro:'Valor mínimo R$30,00'});

  try{
    const [uRows] = await db.promise().query('SELECT id, saldo FROM usuarios WHERE usuario=?',[usuario.toLowerCase()]);
    if(!uRows.length) return res.status(404).json({erro:'Usuário não encontrado'});
    if (Number(uRows[0].saldo) < valor) return res.status(400).json({ erro:'Saldo insuficiente'});

    const mask = chavepix.replace(/.(?=.{4})/g,'*');

    const agora = dayjs().format('YYYY-MM-DD HH:mm:ss');
    await db.promise().query('INSERT INTO saques (iduser, valor, chavepix, data, status) VALUES (?,?,?,?,0)',
      [uRows[0].id, valor, mask, agora]);

    await db.promise().query('UPDATE usuarios SET saldo = saldo - ? WHERE id = ?', [valor, uRows[0].id]);

    res.json({ sucesso:true });
  }catch(e){ 
    console.error(e); 
    res.status(500).json({ erro:'Falha no saque'}); 
  }
});

app.post('/update-balance', async (req, res) => {
  const { usuario, valorAposta, resultado } = req.body;

  if (!usuario || valorAposta === undefined || !resultado) {
    return res.status(400).json({ erro: 'Dados faltando.' });
  }

  try {
    const [userRows] = await db.promise().query('SELECT id, saldo FROM usuarios WHERE usuario = ?', [usuario]);
    
    if (!userRows.length) return res.status(404).json({ erro: 'Usuário não encontrado' });

    const userId = userRows[0].id;
    let novoSaldo = userRows[0].saldo;

    if (resultado === 'win') {
      novoSaldo += valorAposta;
    } else if (resultado === 'lose') {
      novoSaldo -= valorAposta;
    } else {
      return res.status(400).json({ erro: 'Resultado inválido.' });
    }

    if (novoSaldo < 0) {
      return res.status(400).json({ erro: 'Saldo insuficiente após a operação.' });
    }

    await db.promise().query('UPDATE usuarios SET saldo = ? WHERE id = ?', [novoSaldo, userId]);

    io.emit('atualizar-saldo', { usuario, saldo: novoSaldo });

    res.json({ sucesso: true, novoSaldo });
  } catch (err) {
    console.error(err);
    res.status(500).json({ erro: 'Erro ao atualizar saldo.' });
  }
});

app.post('/logout', (req, res) => {
  res.json({ sucesso: true, mensagem: 'Logout realizado com sucesso (frontend deve limpar localStorage).' });
});

app.get('/api/saques', async (req, res) => { 
  try {    
    const [rows] = await db.promise().query('SELECT id, valor, data, status FROM saques ORDER BY data DESC');
    const saquesFormatados = rows.map(saque => ({
      id: saque.id,
      valor: saque.valor,
      data: saque.data,
      status: saque.status
    }));
    res.json(saquesFormatados);
  } catch (err) {
    console.error(err);
    res.status(500).json({ erro: 'Erro ao buscar saques.' });
  }
});

server.listen(port, () => {
  console.log('🚀 Servidor backend rodando na porta ' + port);
  console.log('💎 PixUp Integration ativada');
});