const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(bodyParser.json());

// Configuração do banco de dados
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'senha',
  database: 'tem_no_entorno_sul'
});

// Conectar ao banco de dados
db.connect(err => {
  if (err) throw err;
  console.log('Conectado ao banco de dados MySQL');
});

// Rota de login
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  
  // Buscar usuário no banco de dados
  const query = 'SELECT * FROM usuarios WHERE email = ?';
  db.query(query, [email], async (err, results) => {
    if (err) return res.status(500).json({ error: 'Erro no servidor' });
    
    if (results.length === 0) {
      return res.status(401).json({ error: 'Credenciais inválidas' });
    }
    
    const user = results[0];
    
    // Verificar senha
    const isMatch = await bcrypt.compare(password, user.senha);
    if (!isMatch) {
      return res.status(401).json({ error: 'Credenciais inválidas' });
    }
    
    // Gerar token JWT
    const token = jwt.sign(
      { id: user.id, tipo: user.tipo },
      'secreto', // Use uma chave secreta mais segura em produção
      { expiresIn: '1h' }
    );
    
    res.json({ token, user: { id: user.id, nome: user.nome, tipo: user.tipo } });
  });
});

// Middleware de autenticação
function authenticate(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Acesso não autorizado' });
  }
  
  try {
    const decoded = jwt.verify(token, 'secreto');
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Token inválido' });
  }
}

// Rota protegida de exemplo
app.get('/api/protected', authenticate, (req, res) => {
  res.json({ message: 'Rota protegida acessada com sucesso!', user: req.user });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});