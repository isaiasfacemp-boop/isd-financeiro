# FinanceControl — Multi-Empresa no Cloudflare

Sistema financeiro multi-tenant: **1 domínio, N empresas, cada uma com banco isolado.**

```
www.seudominio.com.br
        │
        ▼
  Cloudflare Worker  ←── lógica / autenticação
        │
        ▼
  Cloudflare D1     ←── banco de dados (SQLite)
   (1 banco único, dados separados por empresa_id)
```

---

## Como funciona o multi-tenant

- Você tem **1 Worker** e **1 banco D1**.
- Cada empresa tem um `empresa_id` único no banco.
- Ao fazer login, o usuário informa o **código da empresa** (ex: `ACME2024`), login e senha.
- O Worker valida e emite um token JWT com o `empresa_id` embutido.
- Todas as consultas ao banco filtram por `empresa_id` — os dados ficam completamente isolados.

**Não precisa de subdomínio por empresa.** Tudo num único endereço.

---

## Deploy passo a passo

### 1. Pré-requisitos

```bash
# Instalar Node.js 18+ e depois:
npm install -g wrangler
wrangler login   # abre o browser para autenticar com sua conta Cloudflare
```

### 2. Clonar / baixar o projeto

```bash
# Se subiu para GitHub:
git clone https://github.com/SEU_USUARIO/financecontrol.git
cd financecontrol

# Ou descompactar o ZIP enviado e entrar na pasta
npm install
```

### 3. Criar o banco D1

```bash
npm run db:create
# Saída: database_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

Copie o `database_id` e cole no `wrangler.toml`:

```toml
[[d1_databases]]
binding = "DB"
database_name = "financecontrol"
database_id = "COLE_O_ID_AQUI"   # ← substituir aqui
```

### 4. Criar as tabelas

```bash
npm run db:migrate
```

### 5. Configurar o segredo JWT

```bash
wrangler secret put JWT_SECRET
# Digite uma frase secreta forte (ex: uma senha longa aleatória)
```

### 6. Testar localmente

```bash
npm run dev
# Acesse: http://localhost:8787
```

### 7. Deploy para produção

```bash
npm run deploy
# URL gerada: https://financecontrol.SEU_USUARIO.workers.dev
```

### 8. Domínio próprio (opcional)

No painel Cloudflare:
1. Vá em **Workers & Pages → financecontrol → Configurações → Domínios e Rotas**
2. Clique em **+ Adicionar domínio personalizado**
3. Digite `seudominio.com.br` (o domínio precisa estar no Cloudflare)

> **Dica:** Compre o domínio direto na Cloudflare Registrar — sem taxa de revenda e já integra automaticamente.

---

## Primeiro acesso

Abra o sistema e clique em **"Criar empresa"**:

| Campo | Exemplo |
|-------|---------|
| Nome da empresa | Minha Empresa LTDA |
| Código de acesso | MINHA2024 |
| Seu nome | João Silva |
| Login do admin | ADMIN |
| Senha | (sua escolha) |

Para **entrar**: informe Código da Empresa + Login + Senha.

---

## Estrutura do projeto

```
financecontrol/
├── src/
│   └── index.js          # Cloudflare Worker (toda a API)
├── public/
│   └── index.html        # Frontend (HTML + CSS + JS inline)
├── migrations/
│   └── 0001_schema.sql   # Estrutura do banco D1
├── wrangler.toml         # Configuração do Worker
├── package.json
└── README.md
```

---

## API endpoints

| Método | Rota | Descrição |
|--------|------|-----------|
| POST | `/api/auth/register` | Criar nova empresa |
| POST | `/api/auth/login` | Login |
| GET | `/api/perfis` | Listar perfis |
| POST | `/api/perfis` | Criar perfil |
| PUT | `/api/perfis/:id` | Editar perfil |
| DELETE | `/api/perfis/:id` | Excluir perfil |
| GET | `/api/contas` | Listar contas (filtros: tipo, status, ano, mes, perfil_id) |
| POST | `/api/contas` | Criar conta |
| PUT | `/api/contas/:id` | Editar conta |
| DELETE | `/api/contas/:id` | Excluir conta |
| GET | `/api/clientes` | Listar clientes |
| POST | `/api/clientes` | Criar cliente |
| PUT | `/api/clientes/:id` | Editar cliente |
| DELETE | `/api/clientes/:id` | Excluir cliente |
| GET | `/api/dashboard` | Resumo financeiro do mês |
| GET | `/api/usuarios` | Listar usuários (admin) |
| POST | `/api/usuarios` | Criar usuário (admin) |
| PUT | `/api/usuarios/:id` | Editar usuário |

---

## Limites do plano gratuito Cloudflare

| Recurso | Free | Workers Paid ($5/mês) |
|---------|------|-----------------------|
| Requests/dia | 100.000 | 10 milhões |
| D1 reads/dia | 5 milhões | 25 bilhões |
| D1 writes/dia | 100.000 | 50 milhões |
| Storage D1 | 5 GB | 5 GB |

Para um sistema de contas a pagar/receber de PMEs, o plano **gratuito** é suficiente.
