// server.js
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

// Rota de verificação de sessão (simples)
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

// Rota para aplicar bônus ao trocar para chinês
app.post('/bonus', async (req, res) => {
  const { usuario } = req.body;
  try {
    const [rows] = await db.promise().query('SELECT bonus,saldo FROM usuarios WHERE usuario = ?', [usuario]);
    if (rows.length === 0) return res.status(404).json({ erro: 'Usuário não encontrado.' });

    if (rows[0].saldo < 30){
      return;
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



app.post('/webhook', async (req, res)=>{

  const {id, status, amount} = req.body;

  console.log('Dados recebidos: ', {id, status, amount});

  const [deporow] = await db.promise().query('SELECT iduser from depositos where idpix = ? and status = 0', [id]);
  
  if(deporow.length === 0){
    return console.log('nao encontrado!');
  }

  if (status === "APPROVED"){
    console.log('deposito concluido, valor depositado:'+amount);

    const iduser = deporow[0].iduser;

    try {
      io.emit('pagamento-concluido', { iduser, id, amount });
      await db.promise().query(`UPDATE usuarios SET saldo = saldo + ${amount} WHERE id = ?`, [deporow[0].iduser]);
      await db.promise().query(`UPDATE depositos SET status = 1 WHERE idpix = ?`, [id]);
      console.log('add saldo concluido');
    }catch (err) {
      console.log(err);
    }

  }else if (status === "PENDING"){
    console.log('Transação pendente.');
  }else{
    console.log('erro');
  }

});

app.post('/deposit', async (req, res) => {
  const { usuario, valor } = req.body;
  if (!usuario || !valor) return res.status(400).json({ erro: 'Dados faltando.' });
  if (valor < 30) return res.status(400).json({ erro: 'Valor mínimo é R$30,00' });

  try {
   const [uRows] = await db.promise().query('SELECT id FROM usuarios WHERE usuario=?', [usuario]);
    if (!uRows.length) return res.status(404).json({ erro: 'Usuário não encontrado' });

    const user = uRows[0];
    const externalId = 'dep_' + Date.now();

    const clientId = "legendaryn0v9_0914642422";
    const clientSecret = "840d185a7198923a48addd2a9bef7aa214d17738a0e5b6f7fe5427241ea532d4";
    const credentials = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');
    
    const loginresp = await axios.post('https://api.bspay.co/v2/oauth/token', {}, {
      headers: {
        'accept': 'application/json',
        'authorization': `Basic ${credentials}`
      }
    })

    const {access_token} = loginresp.data;

    console.log(access_token);
    
    const urldaapi = 'https://pay.rushpayoficial.com/api/v1/transaction.purchase';

    const requestData = {
      name: "ob",
      email: "teste@example.com",
      cpf: "47046074453",
      phone: "11999999999",
      postbackUrl: 'https://api.qtrade.site/webhook',
      paymentMethod: "PIX",
      amount: Math.round(valor * 100),
      traceable: true,
          items: [
          {
            unitPrice: Math.round(valor * 100),
            title: "Depósito via PIX",
            quantity: 1,
            tangible: false
          }
        ]
    };

    const depResp = await axios.post(urldaapi, requestData, {

    headers: {
      "Content-Type": "application/json",
      "Authorization": 'c8aad6dc-00ee-482c-930e-a085b1a56411'
      }
    });
    
    const { pixCode, id } = depResp.data;

    const agora = dayjs().format('YYYY-MM-DD HH:mm:ss');
    await db.promise().query(
      'INSERT INTO depositos (iduser, valor, data, idpix, status) VALUES (?,?,?,?,0)',
      [user.id, valor, agora, id]
    );

    res.json({ sucesso: true, pix_code: pixCode, idpix: id });

  } catch (e) {
    console.error(e.response?.data || e);
    res.status(500).json({ erro: 'Falha ao gerar depósito' });
  }
});
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

    // máscara simples da chave (esconde parte do meio)
    const mask = chavepix.replace(/.(?=.{4})/g,'*');

    const agora = dayjs().format('YYYY-MM-DD HH:mm:ss');
    await db.promise().query('INSERT INTO saques (iduser, valor, chavepix, data, status) VALUES (?,?,?,?,0)',
      [uRows[0].id, valor, mask, agora]);

    // debita saldo imediatamente (ou aguarde aprovação manual)
    await db.promise().query('UPDATE usuarios SET saldo = saldo - ? WHERE id = ?', [valor, uRows[0].id]);

    res.json({ sucesso:true });
  }catch(e){ console.error(e); res.status(500).json({ erro:'Falha no saque'}); }
});


// Rota para adicionar ou retirar saldo com base no resultado da operação
app.post('/update-balance', async (req, res) => {
  const { usuario, valorAposta, resultado } = req.body; // 'resultado' pode ser 'win' ou 'lose'

  if (!usuario || valorAposta === undefined || !resultado) {
    return res.status(400).json({ erro: 'Dados faltando.' });
  }

  try {
    // Buscar usuário no banco de dados
    const [userRows] = await db.promise().query('SELECT id, saldo FROM usuarios WHERE usuario = ?', [usuario]);
    
    if (!userRows.length) return res.status(404).json({ erro: 'Usuário não encontrado' });

    const userId = userRows[0].id;
    let novoSaldo = userRows[0].saldo;

    // Atualizar saldo conforme o resultado da operação
    if (resultado === 'win') {
      // Se ganhou, adiciona o valor apostado (pode ser ajustado para um ganho maior)
      novoSaldo += valorAposta;
    } else if (resultado === 'lose') {
      // Se perdeu, subtrai o valor apostado
      novoSaldo -= valorAposta;
    } else {
      return res.status(400).json({ erro: 'Resultado inválido.' });
    }

    // Garantir que o saldo não fique negativo
    if (novoSaldo < 0) {
      return res.status(400).json({ erro: 'Saldo insuficiente após a operação.' });
    }

    // Atualiza o saldo do usuário no banco de dados
    await db.promise().query('UPDATE usuarios SET saldo = ? WHERE id = ?', [novoSaldo, userId]);

    // Emitir evento para notificar o frontend (caso seja necessário)
    io.emit('atualizar-saldo', { usuario, saldo: novoSaldo });

    res.json({ sucesso: true, novoSaldo });
  } catch (err) {
    console.error(err);
    res.status(500).json({ erro: 'Erro ao atualizar saldo.' });
  }
});


// Rota de logout (opcional)
app.post('/logout', (req, res) => {
  res.json({ sucesso: true, mensagem: 'Logout realizado com sucesso (frontend deve limpar localStorage).' });
});

// Rota para obter saques com status\n
// 
app.get('/api/saques', async (req, res) => { 

  try {    
    const [rows] = await db.promise().query('SELECT id, valor, data, status FROM saques ORDER BY data DESC');
    const saquesFormatados = rows.map(saque => ({id: saque.id,valor: saque.valor,data: saque.data,status: saque.status}));
    res.json(saquesFormatados);
  } 
  
  catch (err) {
    console.error(err);
    res.status(500).json({ erro: 'Erro ao buscar saques.' });
  }
});


server.listen(port, () => {
  console.log('Servidor backend rodando na porta ' + port);
});
