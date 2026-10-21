/**
 * FinanceControl - Cloudflare Worker
 * API multi-tenant com D1 database
 */

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

// ── Utilitários ──────────────────────────────────────────────────────────────

function uid() {
  return crypto.randomUUID().replace(/-/g, '').slice(0, 16);
}

async function sha256(text) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS, 'Content-Type': 'application/json' },
  });
}

function err(msg, status = 400) {
  return json({ error: msg }, status);
}

// JWT simples com HMAC-SHA256
async function signToken(payload, secret) {
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body   = btoa(JSON.stringify(payload));
  const data   = `${header}.${body}`;
  const key    = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig)));
  return `${data}.${sigB64}`;
}

async function verifyToken(token, secret) {
  try {
    const [header, body, sig] = token.split('.');
    const data = `${header}.${body}`;
    const key  = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(secret),
      { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']
    );
    const sigBuf = Uint8Array.from(atob(sig), c => c.charCodeAt(0));
    const valid  = await crypto.subtle.verify('HMAC', key, sigBuf, new TextEncoder().encode(data));
    if (!valid) return null;
    return JSON.parse(atob(body));
  } catch { return null; }
}

async function auth(req, env) {
  const header = req.headers.get('Authorization') || '';
  const token  = header.replace('Bearer ', '');
  if (!token) return null;
  return verifyToken(token, env.JWT_SECRET || 'fc_secret_2024');
}

// ── Roteador ─────────────────────────────────────────────────────────────────

export default {
  async fetch(request, env) {
    const url    = new URL(request.url);
    const path   = url.pathname;
    const method = request.method;

    // CORS preflight
    if (method === 'OPTIONS') {
      return new Response(null, { headers: CORS });
    }

    // Servir frontend
    if (method === 'GET' && (path === '/' || path === '/index.html')) {
      const html = await env.ASSETS?.fetch(request);
      if (html) return html;
    }

    // API routes
    if (path.startsWith('/api/')) {
      return handleAPI(path.slice(5), method, request, env, url);
    }

    // Assets estáticos (Cloudflare Pages)
    if (env.ASSETS) return env.ASSETS.fetch(request);

    return err('Not found', 404);
  }
};

async function handleAPI(path, method, req, env, url) {
  const db = env.DB;

  // ── Auth ────────────────────────────────────────────────────────────────
  if (path === 'auth/register' && method === 'POST') {
    const { empresa_nome, empresa_codigo, admin_nome, admin_login, admin_senha } = await req.json();
    if (!empresa_nome || !empresa_codigo || !admin_login || !admin_senha)
      return err('Campos obrigatórios faltando');

    const codigo = empresa_codigo.toUpperCase().trim();
    const exist = await db.prepare('SELECT id FROM empresas WHERE codigo=?').bind(codigo).first();
    if (exist) return err('Código de empresa já em uso');

    const emp_id  = uid();
    const user_id = uid();
    const hash    = await sha256(admin_senha);

    await db.batch([
      db.prepare('INSERT INTO empresas(id,nome,codigo) VALUES(?,?,?)').bind(emp_id, empresa_nome, codigo),
      db.prepare(`INSERT INTO usuarios(id,empresa_id,nome,login,senha_hash,is_admin,permissoes)
                  VALUES(?,?,?,?,?,1,'["dashboard","consolidado","relatorio","pagar","receber","clientes","calculadora","perfil"]')`)
        .bind(user_id, emp_id, admin_nome || 'Administrador', admin_login.toUpperCase(), hash),
      // Perfil padrão
      db.prepare('INSERT INTO perfis(id,empresa_id,nome,cor,icone,ordem) VALUES(?,?,?,?,?,0)')
        .bind(uid(), emp_id, 'GERAL', '#2563EB', '🏢'),
    ]);

    const token = await signToken({ emp: emp_id, uid: user_id, adm: true }, env.JWT_SECRET || 'fc_secret_2024');
    return json({ token, empresa: { id: emp_id, nome: empresa_nome, codigo } });
  }

  if (path === 'auth/login' && method === 'POST') {
    const { empresa_codigo, login, senha } = await req.json();
    if (!empresa_codigo || !login || !senha) return err('Campos obrigatórios faltando');

    const emp = await db.prepare('SELECT id,nome,codigo FROM empresas WHERE codigo=? AND ativo=1')
      .bind(empresa_codigo.toUpperCase().trim()).first();
    if (!emp) return err('Empresa não encontrada', 401);

    const hash = await sha256(senha);
    const user = await db.prepare(
      'SELECT id,nome,login,is_admin,troca_senha,permissoes FROM usuarios WHERE empresa_id=? AND login=? AND senha_hash=? AND ativo=1'
    ).bind(emp.id, login.toUpperCase().trim(), hash).first();
    if (!user) return err('Login ou senha incorretos', 401);

    const token = await signToken(
      { emp: emp.id, uid: user.id, adm: !!user.is_admin },
      env.JWT_SECRET || 'fc_secret_2024'
    );
    return json({
      token,
      empresa: { id: emp.id, nome: emp.nome, codigo: emp.codigo },
      usuario: {
        id: user.id, nome: user.nome, login: user.login,
        isAdmin: !!user.is_admin, trocaSenha: !!user.troca_senha,
        permissoes: JSON.parse(user.permissoes || '[]')
      }
    });
  }

  // Rotas autenticadas
  const session = await auth(req, env);
  if (!session) return err('Não autenticado', 401);
  const emp_id = session.emp;

  // ── Perfis ──────────────────────────────────────────────────────────────
  if (path === 'perfis') {
    if (method === 'GET') {
      const { results } = await db.prepare('SELECT * FROM perfis WHERE empresa_id=? ORDER BY ordem,nome').bind(emp_id).all();
      return json(results);
    }
    if (method === 'POST') {
      const body = await req.json();
      const id = uid();
      await db.prepare('INSERT INTO perfis(id,empresa_id,nome,cor,icone,ordem) VALUES(?,?,?,?,?,?)')
        .bind(id, emp_id, body.nome, body.cor||'#2563EB', body.icone||'🏢', body.ordem||0).run();
      return json({ id, ...body, empresa_id: emp_id });
    }
  }

  const perfil_match = path.match(/^perfis\/([^/]+)$/);
  if (perfil_match) {
    const pid = perfil_match[1];
    if (method === 'PUT') {
      const body = await req.json();
      await db.prepare('UPDATE perfis SET nome=?,cor=?,icone=?,ordem=? WHERE id=? AND empresa_id=?')
        .bind(body.nome, body.cor, body.icone, body.ordem||0, pid, emp_id).run();
      return json({ ok: true });
    }
    if (method === 'DELETE') {
      await db.prepare('DELETE FROM perfis WHERE id=? AND empresa_id=?').bind(pid, emp_id).run();
      return json({ ok: true });
    }
  }

  // ── Contas ──────────────────────────────────────────────────────────────
  if (path === 'contas') {
    if (method === 'GET') {
      const perfil_id = url.searchParams.get('perfil_id');
      const tipo      = url.searchParams.get('tipo');
      const status    = url.searchParams.get('status');
      const ano       = url.searchParams.get('ano');
      const mes       = url.searchParams.get('mes');

      let q = 'SELECT * FROM contas WHERE empresa_id=?';
      const params = [emp_id];
      if (perfil_id) { q += ' AND perfil_id=?'; params.push(perfil_id); }
      if (tipo)      { q += ' AND tipo=?';       params.push(tipo); }
      if (status)    { q += ' AND status=?';     params.push(status); }
      if (ano && mes) {
        q += ' AND vencimento LIKE ?';
        params.push(`${ano}-${String(mes).padStart(2,'0')}-%`);
      } else if (ano) {
        q += ' AND vencimento LIKE ?'; params.push(`${ano}-%`);
      }
      q += ' ORDER BY vencimento, criado_em';

      const { results } = await db.prepare(q).bind(...params).all();
      return json(results);
    }

    if (method === 'POST') {
      const body = await req.json();
      const contas = Array.isArray(body) ? body : [body];
      const stmts = contas.map(c => {
        const id = c.id || uid();
        return db.prepare(`INSERT INTO contas(id,empresa_id,perfil_id,descricao,desc_base,valor,vencimento,tipo,categoria,status,grupo_id,parcela,total_parcelas,cliente_id,obs)
          VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
          .bind(id, emp_id, c.perfil_id, c.descricao||c.desc, c.desc_base||'', c.valor, c.vencimento||c.venc,
                c.tipo, c.categoria||'', c.status||'pendente', c.grupo_id||'', c.parcela||0, c.total_parcelas||0,
                c.cliente_id||'', c.obs||'');
      });
      await db.batch(stmts);
      return json({ ok: true, count: contas.length });
    }
  }

  const conta_match = path.match(/^contas\/([^/]+)$/);
  if (conta_match) {
    const cid = conta_match[1];
    if (method === 'PUT') {
      const c = await req.json();
      await db.prepare(`UPDATE contas SET descricao=?,desc_base=?,valor=?,vencimento=?,tipo=?,categoria=?,
        status=?,grupo_id=?,parcela=?,total_parcelas=?,cliente_id=?,obs=?,atualizado_em=datetime('now')
        WHERE id=? AND empresa_id=?`)
        .bind(c.descricao||c.desc, c.desc_base||'', c.valor, c.vencimento||c.venc, c.tipo,
              c.categoria||'', c.status||'pendente', c.grupo_id||'', c.parcela||0, c.total_parcelas||0,
              c.cliente_id||'', c.obs||'', cid, emp_id).run();
      return json({ ok: true });
    }
    if (method === 'DELETE') {
      await db.prepare('DELETE FROM contas WHERE id=? AND empresa_id=?').bind(cid, emp_id).run();
      return json({ ok: true });
    }
  }

  // Deletar por grupo (parcelas)
  if (path === 'contas/grupo' && method === 'DELETE') {
    const { grupo_id } = await req.json();
    await db.prepare('DELETE FROM contas WHERE grupo_id=? AND empresa_id=?').bind(grupo_id, emp_id).run();
    return json({ ok: true });
  }

  // ── Clientes ─────────────────────────────────────────────────────────────
  if (path === 'clientes') {
    if (method === 'GET') {
      const perfil_id = url.searchParams.get('perfil_id');
      let q = 'SELECT * FROM clientes WHERE empresa_id=? AND ativo=1';
      const params = [emp_id];
      if (perfil_id) { q += ' AND perfil_id=?'; params.push(perfil_id); }
      q += ' ORDER BY nome';
      const { results } = await db.prepare(q).bind(...params).all();
      return json(results);
    }
    if (method === 'POST') {
      const body = await req.json();
      const id = uid();
      await db.prepare('INSERT INTO clientes(id,empresa_id,perfil_id,nome,email,telefone,doc,obs) VALUES(?,?,?,?,?,?,?,?)')
        .bind(id, emp_id, body.perfil_id, body.nome, body.email||'', body.telefone||'', body.doc||'', body.obs||'').run();
      return json({ id, ...body, empresa_id: emp_id });
    }
  }

  const cli_match = path.match(/^clientes\/([^/]+)$/);
  if (cli_match) {
    const cid = cli_match[1];
    if (method === 'PUT') {
      const body = await req.json();
      await db.prepare('UPDATE clientes SET nome=?,email=?,telefone=?,doc=?,obs=? WHERE id=? AND empresa_id=?')
        .bind(body.nome, body.email||'', body.telefone||'', body.doc||'', body.obs||'', cid, emp_id).run();
      return json({ ok: true });
    }
    if (method === 'DELETE') {
      await db.prepare('UPDATE clientes SET ativo=0 WHERE id=? AND empresa_id=?').bind(cid, emp_id).run();
      return json({ ok: true });
    }
  }

  // ── Categorias ───────────────────────────────────────────────────────────
  if (path === 'categorias') {
    if (method === 'GET') {
      const { results } = await db.prepare('SELECT * FROM categorias WHERE empresa_id=? ORDER BY nome').bind(emp_id).all();
      return json(results);
    }
    if (method === 'POST') {
      const body = await req.json();
      const id = uid();
      await db.prepare('INSERT INTO categorias(id,empresa_id,nome,tipo,cor) VALUES(?,?,?,?,?)')
        .bind(id, emp_id, body.nome, body.tipo||'ambos', body.cor||'#6B7280').run();
      return json({ id, ...body, empresa_id: emp_id });
    }
  }

  const cat_match = path.match(/^categorias\/([^/]+)$/);
  if (cat_match) {
    const cid = cat_match[1];
    if (method === 'DELETE') {
      await db.prepare('DELETE FROM categorias WHERE id=? AND empresa_id=?').bind(cid, emp_id).run();
      return json({ ok: true });
    }
  }

  // ── Usuários ─────────────────────────────────────────────────────────────
  if (path === 'usuarios') {
    if (!session.adm) return err('Sem permissão', 403);
    if (method === 'GET') {
      const { results } = await db.prepare(
        'SELECT id,nome,login,is_admin,troca_senha,permissoes,ativo FROM usuarios WHERE empresa_id=? ORDER BY nome'
      ).bind(emp_id).all();
      return json(results.map(u => ({ ...u, permissoes: JSON.parse(u.permissoes||'[]') })));
    }
    if (method === 'POST') {
      const body = await req.json();
      const id   = uid();
      const hash = await sha256(body.senha || '1234');
      await db.prepare(`INSERT INTO usuarios(id,empresa_id,nome,login,senha_hash,is_admin,troca_senha,permissoes)
        VALUES(?,?,?,?,?,?,?,?)`)
        .bind(id, emp_id, body.nome, body.login.toUpperCase(), hash,
              body.isAdmin?1:0, 1, JSON.stringify(body.permissoes||[])).run();
      return json({ id, ...body, empresa_id: emp_id });
    }
  }

  const usu_match = path.match(/^usuarios\/([^/]+)$/);
  if (usu_match) {
    const uid2 = usu_match[1];
    if (method === 'PUT') {
      if (!session.adm && session.uid !== uid2) return err('Sem permissão', 403);
      const body = await req.json();
      if (body.senha) {
        const hash = await sha256(body.senha);
        await db.prepare('UPDATE usuarios SET senha_hash=?,troca_senha=0 WHERE id=? AND empresa_id=?')
          .bind(hash, uid2, emp_id).run();
      }
      if (session.adm && body.nome) {
        await db.prepare('UPDATE usuarios SET nome=?,login=?,is_admin=?,permissoes=?,ativo=? WHERE id=? AND empresa_id=?')
          .bind(body.nome, body.login.toUpperCase(), body.isAdmin?1:0, JSON.stringify(body.permissoes||[]), body.ativo?1:0, uid2, emp_id).run();
      }
      return json({ ok: true });
    }
    if (method === 'DELETE') {
      if (!session.adm) return err('Sem permissão', 403);
      await db.prepare('UPDATE usuarios SET ativo=0 WHERE id=? AND empresa_id=?').bind(uid2, emp_id).run();
      return json({ ok: true });
    }
  }

  // ── Dashboard stats ──────────────────────────────────────────────────────
  if (path === 'dashboard' && method === 'GET') {
    const perfil_id = url.searchParams.get('perfil_id');
    const ano  = url.searchParams.get('ano')  || new Date().getFullYear();
    const mes  = url.searchParams.get('mes')  || String(new Date().getMonth()+1).padStart(2,'0');
    const like = `${ano}-${String(mes).padStart(2,'0')}-%`;

    let q_base = 'WHERE empresa_id=?';
    const params_base = [emp_id];
    if (perfil_id) { q_base += ' AND perfil_id=?'; params_base.push(perfil_id); }

    const stats = await db.prepare(`
      SELECT
        SUM(CASE WHEN tipo='pagar' THEN valor ELSE 0 END) as total_pagar,
        SUM(CASE WHEN tipo='receber' THEN valor ELSE 0 END) as total_receber,
        SUM(CASE WHEN tipo='pagar' AND status='pago' THEN valor ELSE 0 END) as pago,
        SUM(CASE WHEN tipo='receber' AND status='recebido' THEN valor ELSE 0 END) as recebido,
        COUNT(*) as total
      FROM contas ${q_base} AND vencimento LIKE ?
    `).bind(...params_base, like).first();

    return json(stats);
  }

  return err('Rota não encontrada', 404);
}
