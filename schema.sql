-- Tabelas: usuarios, transacoes, requests (deposit/withdraw requests), mensagens

CREATE TABLE IF NOT EXISTS usuarios (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  senha_hash TEXT NOT NULL,
  saldo REAL NOT NULL DEFAULT 0,
  criado_em DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS transacoes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  de_usuario INTEGER,
  para_usuario INTEGER,
  tipo TEXT NOT NULL, -- deposit, withdraw, transfer, admin_credit, admin_debit
  valor REAL NOT NULL,
  descricao TEXT,
  criado_em DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  usuario_id INTEGER NOT NULL,
  tipo TEXT NOT NULL, -- deposit, withdraw
  valor REAL NOT NULL,
  status TEXT NOT NULL DEFAULT 'pendente', -- pendente, aprovado, rejeitado
  criado_em DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS mensagens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  de_admin INTEGER DEFAULT 1,
  para_usuario INTEGER NOT NULL,
  conteudo TEXT NOT NULL,
  criado_em DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS auditoria (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    evento TEXT NOT NULL,
    detalhe TEXT,
    usuario_id INTEGER,
    criado_em DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(usuario_id) REFERENCES usuarios(id)
);