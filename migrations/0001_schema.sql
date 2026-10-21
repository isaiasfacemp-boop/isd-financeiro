-- FinanceControl - Schema Multi-Tenant
-- Cada empresa tem seus próprios dados isolados

CREATE TABLE IF NOT EXISTS empresas (
  id         TEXT PRIMARY KEY,
  nome       TEXT NOT NULL,
  codigo     TEXT UNIQUE NOT NULL,  -- código de acesso (ex: ACME2024)
  plano      TEXT DEFAULT 'basico',
  ativo      INTEGER DEFAULT 1,
  criado_em  TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS usuarios (
  id           TEXT PRIMARY KEY,
  empresa_id   TEXT NOT NULL,
  nome         TEXT NOT NULL,
  login        TEXT NOT NULL,
  senha_hash   TEXT NOT NULL,         -- SHA-256 simples
  is_admin     INTEGER DEFAULT 0,
  troca_senha  INTEGER DEFAULT 0,
  permissoes   TEXT DEFAULT '[]',     -- JSON array
  ativo        INTEGER DEFAULT 1,
  criado_em    TEXT DEFAULT (datetime('now')),
  UNIQUE(empresa_id, login),
  FOREIGN KEY (empresa_id) REFERENCES empresas(id)
);

CREATE TABLE IF NOT EXISTS perfis (
  id          TEXT PRIMARY KEY,
  empresa_id  TEXT NOT NULL,
  nome        TEXT NOT NULL,
  cor         TEXT DEFAULT '#2563EB',
  icone       TEXT DEFAULT '🏢',
  ordem       INTEGER DEFAULT 0,
  FOREIGN KEY (empresa_id) REFERENCES empresas(id)
);

CREATE TABLE IF NOT EXISTS categorias (
  id          TEXT PRIMARY KEY,
  empresa_id  TEXT NOT NULL,
  nome        TEXT NOT NULL,
  tipo        TEXT NOT NULL,   -- pagar | receber | ambos
  cor         TEXT DEFAULT '#6B7280',
  FOREIGN KEY (empresa_id) REFERENCES empresas(id)
);

CREATE TABLE IF NOT EXISTS clientes (
  id          TEXT PRIMARY KEY,
  empresa_id  TEXT NOT NULL,
  perfil_id   TEXT NOT NULL,
  nome        TEXT NOT NULL,
  email       TEXT DEFAULT '',
  telefone    TEXT DEFAULT '',
  doc         TEXT DEFAULT '',
  obs         TEXT DEFAULT '',
  ativo       INTEGER DEFAULT 1,
  criado_em   TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (empresa_id) REFERENCES empresas(id)
);

CREATE TABLE IF NOT EXISTS contas (
  id             TEXT PRIMARY KEY,
  empresa_id     TEXT NOT NULL,
  perfil_id      TEXT NOT NULL,
  descricao      TEXT NOT NULL,
  desc_base      TEXT DEFAULT '',
  valor          REAL NOT NULL,
  vencimento     TEXT,               -- YYYY-MM-DD
  tipo           TEXT NOT NULL,      -- pagar | receber
  categoria      TEXT DEFAULT '',
  status         TEXT DEFAULT 'pendente',  -- pendente | pago | recebido
  grupo_id       TEXT DEFAULT '',
  parcela        INTEGER DEFAULT 0,
  total_parcelas INTEGER DEFAULT 0,
  cliente_id     TEXT DEFAULT '',
  obs            TEXT DEFAULT '',
  criado_em      TEXT DEFAULT (datetime('now')),
  atualizado_em  TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (empresa_id) REFERENCES empresas(id)
);

CREATE TABLE IF NOT EXISTS auditoria (
  id          TEXT PRIMARY KEY,
  empresa_id  TEXT NOT NULL,
  usuario_id  TEXT NOT NULL,
  acao        TEXT NOT NULL,
  detalhes    TEXT DEFAULT '',
  criado_em   TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (empresa_id) REFERENCES empresas(id)
);

-- Índices para performance
CREATE INDEX IF NOT EXISTS idx_contas_empresa    ON contas(empresa_id);
CREATE INDEX IF NOT EXISTS idx_contas_perfil     ON contas(empresa_id, perfil_id);
CREATE INDEX IF NOT EXISTS idx_contas_venc       ON contas(empresa_id, vencimento);
CREATE INDEX IF NOT EXISTS idx_contas_status     ON contas(empresa_id, status);
CREATE INDEX IF NOT EXISTS idx_clientes_empresa  ON clientes(empresa_id);
CREATE INDEX IF NOT EXISTS idx_usuarios_empresa  ON usuarios(empresa_id);
CREATE INDEX IF NOT EXISTS idx_auditoria_empresa ON auditoria(empresa_id);
