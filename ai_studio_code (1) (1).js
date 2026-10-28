const express = require('express');
const cookieParser = require('cookie-parser');
const Database = require('better-sqlite3');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '31181022';
const JWT_SECRET = process.env.JWT_SECRET || 'granaxp_secret_key_jwt_2026';
const ADMIN_SECRET = process.env.ADMIN_JWT_SECRET || 'granaxp_admin_secret_key_2026';

app.use(express.json());
app.use(cookieParser());

// ==========================================
// 1. BANCO DE DADOS SQLITE PERSISTENTE
// ==========================================
const db = new Database(path.join(__dirname, 'granaxp.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    display_name TEXT,
    password_hash TEXT NOT NULL,
    xp INTEGER DEFAULT 50,
    level INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_active DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS transactions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    type TEXT CHECK(type IN ('income', 'expense')) NOT NULL,
    category TEXT NOT NULL,
    amount REAL NOT NULL,
    description TEXT NOT NULL,
    date TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS goals (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    title TEXT NOT NULL,
    target_amount REAL NOT NULL,
    current_amount REAL DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS system_notices (
    id TEXT PRIMARY KEY,
    message TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

// Função para calcular nível com base no XP (Gamificação sem punição)
function getLevelInfo(xp) {
  if (xp >= 2000) return { level: 5, title: 'Mestre da Organização', nextXp: 99999, progress: 100 };
  if (xp >= 1000) return { level: 4, title: 'Planejador', nextXp: 2000, progress: Math.round(((xp - 1000) / 1000) * 100) };
  if (xp >= 500) return { level: 3, title: 'Estrategista', nextXp: 1000, progress: Math.round(((xp - 500) / 500) * 100) };
  if (xp >= 200) return { level: 2, title: 'Organizado', nextXp: 500, progress: Math.round(((xp - 200) / 300) * 100) };
  return { level: 1, title: 'Iniciante', nextXp: 200, progress: Math.round((xp / 200) * 100) };
}

// ==========================================
// 2. MIDDLEWARES DE AUTENTICAÇÃO
// ==========================================
function authUser(req, res, next) {
  const token = req.cookies.granaxp_session;
  if (!token) return res.status(401).json({ error: 'Não autenticado' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Sessão inválida' });
  }
}

function authAdmin(req, res, next) {
  const token = req.cookies.granaxp_admin;
  if (!token) return res.status(401).json({ error: 'Acesso restrito' });
  try {
    jwt.verify(token, ADMIN_SECRET);
    next();
  } catch {
    return res.status(403).json({ error: 'Sessão administrativa expirada' });
  }
}

// ==========================================
// 3. ROTAS DA API
// ==========================================

// Cadastro e Login (sem exigir e-mail)
app.post('/api/auth/register', async (req, res) => {
  const { username, displayName, password } = req.body;
  if (!username || !password || password.length < 6) {
    return res.status(400).json({ error: 'Senha deve conter ao menos 6 caracteres.' });
  }
  const clean = username.trim().toLowerCase();
  const exists = db.prepare('SELECT id FROM users WHERE username = ?').get(clean);
  if (exists) return res.status(409).json({ error: 'Nome de usuário já cadastrado.' });

  const hash = await bcrypt.hash(password, 10);
  const id = crypto.randomUUID();
  db.prepare('INSERT INTO users (id, username, display_name, password_hash, xp) VALUES (?, ?, ?, ?, 50)').run(
    id, clean, displayName || clean, hash
  );

  const token = jwt.sign({ id, username: clean }, JWT_SECRET, { expiresIn: '7d' });
  res.cookie('granaxp_session', token, { httpOnly: true, sameSite: 'lax' });
  res.json({ success: true, user: { id, username: clean, displayName: displayName || clean, xp: 50, level: 1 } });
});

app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  const clean = (username || '').trim().toLowerCase();
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(clean);
  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return res.status(401).json({ error: 'Usuário ou senha incorretos.' });
  }

  db.prepare('UPDATE users SET last_active = CURRENT_TIMESTAMP WHERE id = ?').run(user.id);
  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
  res.cookie('granaxp_session', token, { httpOnly: true, sameSite: 'lax' });
  res.json({ success: true, user: { id: user.id, username: user.username, displayName: user.display_name, xp: user.xp, level: user.level } });
});

app.get('/api/auth/me', authUser, (req, res) => {
  const user = db.prepare('SELECT id, username, display_name as displayName, xp, level FROM users WHERE id = ?').get(req.user.id);
  const levelInfo = getLevelInfo(user.xp);
  res.json({ user: { ...user, ...levelInfo } });
});

app.post('/api/auth/logout', (_req, res) => {
  res.clearCookie('granaxp_session');
  res.json({ success: true });
});

// Transações
app.get('/api/transactions', authUser, (req, res) => {
  const rows = db.prepare('SELECT * FROM transactions WHERE user_id = ? ORDER BY date DESC, created_at DESC').all(req.user.id);
  res.json({ transactions: rows });
});

app.post('/api/transactions', authUser, (req, res) => {
  const { type, category, amount, description } = req.body;
  const id = crypto.randomUUID();
  const date = new Date().toISOString().split('T')[0];
  db.prepare('INSERT INTO transactions (id, user_id, type, category, amount, description, date) VALUES (?, ?, ?, ?, ?, ?, ?)').run(
    id, req.user.id, type, category || 'Geral', Number(amount), description, date
  );
  // Recompensa com XP: +15 XP por movimentação
  db.prepare('UPDATE users SET xp = xp + 15 WHERE id = ?').run(req.user.id);
  res.json({ success: true, id });
});

app.delete('/api/transactions/:id', authUser, (req, res) => {
  db.prepare('DELETE FROM transactions WHERE id = ? AND user_id = ?').run(req.params.id, req.user.id);
  res.json({ success: true });
});

// Metas / Objetivos
app.get('/api/goals', authUser, (req, res) => {
  const rows = db.prepare('SELECT * FROM goals WHERE user_id = ?').all(req.user.id);
  res.json({ goals: rows });
});

app.post('/api/goals', authUser, (req, res) => {
  const { title, target_amount } = req.body;
  const id = crypto.randomUUID();
  db.prepare('INSERT INTO goals (id, user_id, title, target_amount, current_amount) VALUES (?, ?, ?, ?, 0)').run(
    id, req.user.id, title, Number(target_amount)
  );
  // Recompensa com XP: +40 XP por criar meta
  db.prepare('UPDATE users SET xp = xp + 40 WHERE id = ?').run(req.user.id);
  res.json({ success: true, id });
});

app.post('/api/goals/:id/deposit', authUser, (req, res) => {
  const { amount } = req.body;
  db.prepare('UPDATE goals SET current_amount = current_amount + ? WHERE id = ? AND user_id = ?').run(
    Number(amount), req.params.id, req.user.id
  );
  res.json({ success: true });
});

// Painel Administrativo Discreto
app.post('/api/admin/login', (req, res) => {
  const { password } = req.body;
  if (!password || password !== ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'Senha incorreta.' });
  }
  const token = jwt.sign({ admin: true }, ADMIN_SECRET, { expiresIn: '2h' });
  res.cookie('granaxp_admin', token, { httpOnly: true, sameSite: 'strict' });
  res.json({ success: true });
});

app.get('/api/admin/stats', authAdmin, (_req, res) => {
  const usersCount = db.prepare('SELECT COUNT(*) as c FROM users').get().c;
  const txCount = db.prepare('SELECT COUNT(*) as c FROM transactions').get().c;
  const goalsCount = db.prepare('SELECT COUNT(*) as c FROM goals').get().c;
  const notices = db.prepare('SELECT * FROM system_notices ORDER BY created_at DESC').all();

  // Apenas métricas agregadas! Nunca expõe saldos pessoais dos usuários
  res.json({
    metrics: { totalUsers: usersCount, totalTransactions: txCount, totalGoals: goalsCount },
    notices
  });
});

app.post('/api/admin/logout', (_req, res) => {
  res.clearCookie('granaxp_admin');
  res.json({ success: true });
});

// ==========================================
// 4. FRONTEND COMPLETO ENTREGUE EM UMA TELA SÓ
// ==========================================
app.get('*', (_req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>GranaXP — Sua grana. Seu jogo. Seu próximo nível.</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://unpkg.com/react@18/umd/react.production.min.js"></script>
  <script src="https://unpkg.com/react-dom@18/umd/react-dom.production.min.js"></script>
  <script src="https://unpkg.com/@babel/standalone/babel.min.js"></script>
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
  <style>
    body { font-family: 'Plus Jakarta Sans', sans-serif; background-color: #090D16; color: #F8FAFC; }
  </style>
</head>
<body>
  <div id="root"></div>

  <script type="text/babel">
    const { useState, useEffect, useMemo } = React;

    function App() {
      const [user, setUser] = useState(null);
      const [transactions, setTransactions] = useState([]);
      const [goals, setGoals] = useState([]);
      const [authModal, setAuthModal] = useState(false);
      const [isRegister, setIsRegister] = useState(false);
      const [username, setUsername] = useState('');
      const [displayName, setDisplayName] = useState('');
      const [password, setPassword] = useState('');
      const [authError, setAuthError] = useState('');
      const [adminModal, setAdminModal] = useState(false);
      const [adminPassword, setAdminPassword] = useState('');
      const [adminError, setAdminError] = useState('');
      const [adminView, setAdminView] = useState(false);
      const [adminStats, setAdminStats] = useState(null);

      // Carregar dados do usuário
      const loadData = async () => {
        try {
          const res = await fetch('/api/auth/me');
          if (res.ok) {
            const data = await res.json();
            setUser(data.user);
            const [txRes, goalsRes] = await Promise.all([
              fetch('/api/transactions'),
              fetch('/api/goals')
            ]);
            if (txRes.ok) setTransactions((await txRes.json()).transactions);
            if (goalsRes.ok) setGoals((await goalsRes.json()).goals);
          } else {
            setUser(null);
          }
        } catch (e) {}
      };

      useEffect(() => { loadData(); }, []);

      // Saudação baseada na hora local
      const greeting = useMemo(() => {
        const h = new Date().getHours();
        if (h < 12) return 'Bom dia';
        if (h < 18) return 'Boa tarde';
        return 'Boa noite';
      }, []);

      // Cálculos financeiros
      const { income, expense, balance } = useMemo(() => {
        let inc = 0, exp = 0;
        transactions.forEach(t => {
          if (t.type === 'income') inc += t.amount;
          else exp += t.amount;
        });
        return { income: inc, expense: exp, balance: inc - exp };
      }, [transactions]);

      // Login / Cadastro
      const handleAuth = async (e) => {
        e.preventDefault();
        setAuthError('');
        const endpoint = isRegister ? '/api/auth/register' : '/api/auth/login';
        const res = await fetch(endpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, displayName, password })
        });
        const data = await res.json();
        if (!res.ok) {
          setAuthError(data.error || 'Erro na operação');
        } else {
          setAuthModal(false);
          setUsername('');
          setPassword('');
          loadData();
        }
      };

      // Logout
      const handleLogout = async () => {
        await fetch('/api/auth/logout', { method: 'POST' });
        setUser(null);
        setTransactions([]);
        setGoals([]);
      };

      // Admin Login
      const handleAdminLogin = async (e) => {
        e.preventDefault();
        setAdminError('');
        const res = await fetch('/api/admin/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ password: adminPassword })
        });
        const data = await res.json();
        if (!res.ok) {
          setAdminError(data.error || 'Senha incorreta');
        } else {
          setAdminModal(false);
          setAdminPassword('');
          const statsRes = await fetch('/api/admin/stats');
          if (statsRes.ok) {
            setAdminStats(await statsRes.json());
            setAdminView(true);
          }
        }
      };

      // Adicionar Transação
      const handleAddTx = async (e) => {
        e.preventDefault();
        const desc = e.target.desc.value;
        const amount = e.target.amount.value;
        const type = e.target.type.value;
        if (!desc || !amount) return;

        await fetch('/api/transactions', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ description: desc, amount, type })
        });
        e.target.reset();
        loadData();
      };

      // Adicionar Meta
      const handleAddGoal = async (e) => {
        e.preventDefault();
        const title = e.target.goalTitle.value;
        const target = e.target.goalTarget.value;
        if (!title || !target) return;

        await fetch('/api/goals', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ title, target_amount: target })
        });
        e.target.reset();
        loadData();
      };

      // Simulador Financeiro (Público)
      const [simInitial, setSimInitial] = useState(200);
      const [simMonthly, setSimMonthly] = useState(100);
      const [simMonths, setSimMonths] = useState(12);

      const simResult = useMemo(() => {
        const rate = Math.pow(1 + 0.105, 1 / 12) - 1; // 10.5% ao ano
        let total = simInitial;
        let invested = simInitial;
        for (let i = 0; i < simMonths; i++) {
          total = total * (1 + rate) + simMonthly;
          invested += simMonthly;
        }
        return { total: Math.round(total), invested: Math.round(invested), profit: Math.round(total - invested) };
      }, [simInitial, simMonthly, simMonths]);

      return (
        <div className="min-h-screen flex flex-col justify-between">
          {/* TOPO / NAVBAR */}
          <header className="border-b border-slate-800 bg-slate-950/80 backdrop-blur sticky top-0 z-40 px-6 py-4">
            <div className="max-w-6xl mx-auto flex items-center justify-between">
              <div className="flex items-center gap-2 cursor-pointer" onClick={() => setAdminView(false)}>
                <div className="w-8 h-8 rounded-lg bg-lime-400 flex items-center justify-center text-slate-950 font-black">
                  XP
                </div>
                <span className="font-extrabold text-xl tracking-wider text-white">
                  GRANA<span className="text-lime-400">XP</span>
                </span>
              </div>

              <div>
                {user ? (
                  <div className="flex items-center gap-3">
                    <div className="bg-slate-900 border border-slate-800 px-3 py-1 rounded-full text-xs font-semibold">
                      <span className="text-lime-400 font-bold">{user.xp} XP</span>
                      <span className="text-slate-400 ml-2">Nível {user.level} • {user.title}</span>
                    </div>
                    <span className="text-xs text-slate-300 font-bold hidden sm:inline">{user.displayName}</span>
                    <button onClick={handleLogout} className="text-xs text-rose-400 hover:underline">Sair</button>
                  </div>
                ) : (
                  <button
                    onClick={() => { setAuthError(''); setAuthModal(true); }}
                    className="px-4 py-2 bg-lime-500 hover:bg-lime-400 text-slate-950 font-bold rounded-xl text-xs sm:text-sm transition shadow-lg shadow-lime-500/10"
                  >
                    Entrar / Criar Conta
                  </button>
                )}
              </div>
            </div>
          </header>

          {/* CONTEÚDO PRINCIPAL */}
          <main className="flex-1 max-w-6xl w-full mx-auto px-4 py-8">
            {adminView ? (
              // PAINEL ADMINISTRATIVO
              <div className="space-y-6">
                <div className="flex justify-between items-center border-b border-slate-800 pb-4">
                  <h1 className="text-2xl font-bold text-white">Painel Administrativo</h1>
                  <button onClick={() => setAdminView(false)} className="text-xs text-slate-400 hover:text-white">Voltar ao Site</button>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                  <div className="bg-slate-900 border border-slate-800 p-5 rounded-2xl">
                    <div className="text-xs text-slate-400 uppercase font-semibold">Total de Usuários</div>
                    <div className="text-3xl font-black text-lime-400 mt-2">{adminStats?.metrics.totalUsers}</div>
                  </div>
                  <div className="bg-slate-900 border border-slate-800 p-5 rounded-2xl">
                    <div className="text-xs text-slate-400 uppercase font-semibold">Movimentações no Sistema</div>
                    <div className="text-3xl font-black text-white mt-2">{adminStats?.metrics.totalTransactions}</div>
                  </div>
                  <div className="bg-slate-900 border border-slate-800 p-5 rounded-2xl">
                    <div className="text-xs text-slate-400 uppercase font-semibold">Metas Criadas</div>
                    <div className="text-3xl font-black text-white mt-2">{adminStats?.metrics.totalGoals}</div>
                  </div>
                </div>
                <div className="bg-slate-900/60 border border-slate-800 p-4 rounded-xl text-xs text-slate-400">
                  *Este painel exibe apenas indicadores agregados. Saldos e transações individuais são estritamente privados conforme a LGPD.
                </div>
              </div>
            ) : user ? (
              // PAINEL DO USUÁRIO LOGADO
              <div className="space-y-8">
                <div>
                  <h1 className="text-2xl sm:text-3xl font-extrabold text-white">
                    {greeting}, <span className="text-lime-400">{user.displayName}</span>! 👋
                  </h1>
                  <p className="text-xs text-slate-400 mt-1">
                    Progresso: <span className="text-lime-400 font-semibold">{user.title}</span> ({user.xp} XP)
                  </p>
                  {/* Barra de Progresso de XP */}
                  <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden mt-3 max-w-md">
                    <div className="bg-lime-400 h-full transition-all" style={{ width: user.progress + '%' }}></div>
                  </div>
                </div>

                {/* Métricas Financeiras */}
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                  <div className="bg-slate-900 border border-slate-800 p-5 rounded-2xl">
                    <span className="text-xs text-slate-400 uppercase font-semibold">Saldo Atual</span>
                    <div className={'text-3xl font-black mt-1 ' + (balance >= 0 ? 'text-white' : 'text-rose-400')}>
                      R$ {balance.toFixed(2)}
                    </div>
                  </div>
                  <div className="bg-slate-900 border border-slate-800 p-5 rounded-2xl">
                    <span className="text-xs text-emerald-400 uppercase font-semibold">Receitas</span>
                    <div className="text-3xl font-black text-white mt-1">+ R$ {income.toFixed(2)}</div>
                  </div>
                  <div className="bg-slate-900 border border-slate-800 p-5 rounded-2xl">
                    <span className="text-xs text-rose-400 uppercase font-semibold">Despesas</span>
                    <div className="text-3xl font-black text-white mt-1">- R$ {expense.toFixed(2)}</div>
                  </div>
                </div>

                {/* Registro Rápido */}
                <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl">
                  <h2 className="text-sm font-bold uppercase tracking-wider text-slate-300 mb-4">Adicionar Registro (+15 XP)</h2>
                  <form onSubmit={handleAddTx} className="grid sm:grid-cols-4 gap-3">
                    <input name="desc" type="text" placeholder="Ex.: Lanche, Salário, Freela" className="px-3 py-2 bg-slate-800 border border-slate-700 rounded-xl text-white text-xs" required />
                    <input name="amount" type="number" step="0.01" placeholder="Valor R$" className="px-3 py-2 bg-slate-800 border border-slate-700 rounded-xl text-white text-xs" required />
                    <select name="type" className="px-3 py-2 bg-slate-800 border border-slate-700 rounded-xl text-white text-xs">
                      <option value="expense">Despesa (-)</option>
                      <option value="income">Receita (+)</option>
                    </select>
                    <button type="submit" className="py-2 bg-lime-500 hover:bg-lime-400 text-slate-950 font-bold rounded-xl text-xs transition">Gravar Movimentação</button>
                  </form>
                </div>

                {/* Movimentações e Metas */}
                <div className="grid md:grid-cols-2 gap-6">
                  {/* Movimentações Recentes */}
                  <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl space-y-4">
                    <h2 className="text-sm font-bold uppercase tracking-wider text-slate-300">Últimos Lançamentos</h2>
                    {transactions.length === 0 ? (
                      <p className="text-xs text-slate-500">Nenhum lançamento adicionado ainda.</p>
                    ) : (
                      <div className="space-y-2 max-h-72 overflow-y-auto">
                        {transactions.map(t => (
                          <div key={t.id} className="flex justify-between items-center bg-slate-800/60 p-3 rounded-xl text-xs">
                            <div>
                              <div className="font-semibold text-white">{t.description}</div>
                              <div className="text-[10px] text-slate-400">{t.date}</div>
                            </div>
                            <div className="flex items-center gap-3">
                              <span className={'font-bold ' + (t.type === 'income' ? 'text-emerald-400' : 'text-rose-400')}>
                                {t.type === 'income' ? '+' : '-'} R$ {Number(t.amount).toFixed(2)}
                              </span>
                              <button
                                onClick={async () => {
                                  if (confirm('Deseja excluir este registro?')) {
                                    await fetch('/api/transactions/' + t.id, { method: 'DELETE' });
                                    loadData();
                                  }
                                }}
                                className="text-slate-500 hover:text-rose-400"
                              >
                                &times;
                              </button>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* Metas Financeiras */}
                  <div className="bg-slate-900 border border-slate-800 p-6 rounded-2xl space-y-4">
                    <h2 className="text-sm font-bold uppercase tracking-wider text-slate-300">Metas & Sonhos (+40 XP)</h2>
                    <form onSubmit={handleAddGoal} className="flex gap-2">
                      <input name="goalTitle" type="text" placeholder="Ex.: Celular novo" className="flex-1 px-3 py-1.5 bg-slate-800 border border-slate-700 rounded-xl text-white text-xs" required />
                      <input name="goalTarget" type="number" placeholder="R$ Meta" className="w-24 px-3 py-1.5 bg-slate-800 border border-slate-700 rounded-xl text-white text-xs" required />
                      <button type="submit" className="px-3 py-1.5 bg-lime-500 text-slate-950 font-bold rounded-xl text-xs">+ Meta</button>
                    </form>

                    <div className="space-y-3 max-h-72 overflow-y-auto">
                      {goals.map(g => {
                        const prog = Math.min(100, Math.round((g.current_amount / g.target_amount) * 100));
                        return (
                          <div key={g.id} className="bg-slate-800/60 p-3 rounded-xl text-xs space-y-1.5">
                            <div className="flex justify-between font-semibold">
                              <span>{g.title}</span>
                              <span className="text-lime-400">{prog}%</span>
                            </div>
                            <div className="w-full bg-slate-700 h-2 rounded-full overflow-hidden">
                              <div className="bg-lime-400 h-full" style={{ width: prog + '%' }}></div>
                            </div>
                            <div className="flex justify-between text-[11px] text-slate-400">
                              <span>R$ {g.current_amount.toFixed(2)} / R$ {g.target_amount.toFixed(2)}</span>
                              <button
                                onClick={async () => {
                                  const val = prompt('Quanto deseja guardar nesta meta hoje?');
                                  if (val && Number(val) > 0) {
                                    await fetch('/api/goals/' + g.id + '/deposit', {
                                      method: 'POST',
                                      headers: { 'Content-Type': 'application/json' },
                                      body: JSON.stringify({ amount: val })
                                    });
                                    loadData();
                                  }
                                }}
                                className="text-lime-400 font-bold hover:underline"
                              >
                                + Guardar R$
                              </button>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                </div>
              </div>
            ) : (
              // LANDING PAGE PÚBLICA
              <div className="space-y-16 py-8">
                <div className="text-center max-w-2xl mx-auto space-y-4">
                  <span className="px-3 py-1 bg-lime-400/10 text-lime-400 rounded-full text-xs font-bold uppercase tracking-wider">
                    100% Gratuito • Sem Planilhas
                  </span>
                  <h1 className="text-4xl sm:text-6xl font-extrabold text-white leading-tight">
                    Sua grana. Seu jogo. <br />
                    <span className="text-lime-400">Seu próximo nível.</span>
                  </h1>
                  <p className="text-slate-400 text-sm sm:text-base">
                    Organize seus gastos ganhando XP, alcance objetivos reais e evolua seu nível financeiro sem burocracia nem taxas.
                  </p>
                  <div>
                    <button
                      onClick={() => { setIsRegister(true); setAuthModal(true); }}
                      className="px-6 py-3 bg-lime-500 hover:bg-lime-400 text-slate-950 font-bold rounded-xl text-sm transition shadow-lg shadow-lime-500/20"
                    >
                      Criar Conta Grátis
                    </button>
                  </div>
                </div>

                {/* Simulador Público */}
                <div className="bg-slate-900 border border-slate-800 p-6 sm:p-8 rounded-3xl max-w-3xl mx-auto">
                  <h2 className="text-lg font-bold text-white mb-4 text-center">Simulador de Futuro</h2>
                  <div className="grid sm:grid-cols-2 gap-6 items-center">
                    <div className="space-y-3 text-xs">
                      <div>
                        <label className="text-slate-400">Investimento Inicial: R$ {simInitial}</label>
                        <input type="range" min="0" max="2000" step="50" value={simInitial} onChange={e => setSimInitial(Number(e.target.value))} className="w-full accent-lime-400" />
                      </div>
                      <div>
                        <label className="text-slate-400">Guardando Todo Mês: R$ {simMonthly}</label>
                        <input type="range" min="20" max="1000" step="20" value={simMonthly} onChange={e => setSimMonthly(Number(e.target.value))} className="w-full accent-lime-400" />
                      </div>
                      <div>
                        <label className="text-slate-400">Prazo: {simMonths} meses</label>
                        <input type="range" min="6" max="60" step="6" value={simMonths} onChange={e => setSimMonths(Number(e.target.value))} className="w-full accent-lime-400" />
                      </div>
                    </div>
                    <div className="bg-slate-950 p-6 rounded-2xl border border-slate-800 text-center">
                      <div className="text-xs text-slate-400 uppercase font-semibold">Valor Final Estimado</div>
                      <div className="text-3xl font-black text-lime-400 my-1">R$ {simResult.total.toLocaleString('pt-BR')}</div>
                      <div className="text-xs text-slate-400">Rendimento: + R$ {simResult.profit.toLocaleString('pt-BR')}</div>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </main>

          {/* RODAPÉ COM ACESSO ADMINISTRATIVO DISCRETO */}
          <footer className="border-t border-slate-800 bg-slate-950 py-6 px-4 text-xs text-slate-500">
            <div className="max-w-6xl mx-auto flex justify-between items-center">
              <div>
                <span className="font-bold text-slate-300">GRANAXP</span>
                <p className="text-[11px] mt-0.5">Sua grana. Seu jogo. Seu próximo nível.</p>
              </div>
              <div className="flex items-center gap-4">
                <span>100% Gratuito</span>
                <span>Sem Coleta de E-mails</span>
                {/* Botão discreto com símbolo de engrenagem */}
                <button
                  onClick={() => { setAdminError(''); setAdminModal(true); }}
                  title="Configurações do sistema"
                  className="p-1 text-slate-700 hover:text-slate-400 transition rounded"
                >
                  <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <circle cx="12" cy="12" r="3"></circle>
                    <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path>
                  </svg>
                </button>
              </div>
            </div>
          </footer>

          {/* MODAL DE AUTENTICAÇÃO DO USUÁRIO */}
          {authModal && (
            <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
              <div className="w-full max-w-sm bg-slate-900 border border-slate-800 p-6 rounded-2xl relative shadow-2xl">
                <button onClick={() => setAuthModal(false)} className="absolute top-4 right-4 text-slate-400 hover:text-white">&times;</button>
                <h2 className="text-lg font-bold text-white mb-2">{isRegister ? 'Criar Conta' : 'Entrar no GranaXP'}</h2>
                <form onSubmit={handleAuth} className="space-y-3">
                  <div>
                    <label className="text-xs text-slate-400">Nome de usuário</label>
                    <input type="text" value={username} onChange={e => setUsername(e.target.value)} className="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded-xl text-white text-xs mt-1" required />
                  </div>
                  {isRegister && (
                    <div>
                      <label className="text-xs text-slate-400">Nome de exibição</label>
                      <input type="text" value={displayName} onChange={e => setDisplayName(e.target.value)} className="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded-xl text-white text-xs mt-1" />
                    </div>
                  )}
                  <div>
                    <label className="text-xs text-slate-400">Senha</label>
                    <input type="password" value={password} onChange={e => setPassword(e.target.value)} className="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded-xl text-white text-xs mt-1" required />
                  </div>
                  {authError && <p className="text-xs text-rose-400">{authError}</p>}
                  <button type="submit" className="w-full py-2 bg-lime-500 hover:bg-lime-400 text-slate-950 font-bold rounded-xl text-xs transition">
                    {isRegister ? 'Cadastrar' : 'Entrar'}
                  </button>
                </form>
                <div className="mt-4 text-center">
                  <button onClick={() => { setAuthError(''); setIsRegister(!isRegister); }} className="text-xs text-lime-400 hover:underline">
                    {isRegister ? 'Já tem conta? Clique para entrar' : 'Não tem conta? Crie uma grátis'}
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* MODAL DO ACESSO ADMINISTRATIVO */}
          {adminModal && (
            <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
              <div className="w-full max-w-sm bg-slate-900 border border-slate-800 p-6 rounded-2xl relative shadow-2xl">
                <button onClick={() => setAdminModal(false)} className="absolute top-4 right-4 text-slate-400 hover:text-white">&times;</button>
                <h2 className="text-base font-bold text-white mb-3">Acesso administrativo</h2>
                <form onSubmit={handleAdminLogin} className="space-y-4">
                  <div>
                    <label className="text-xs text-slate-400">Senha de Acesso</label>
                    <input
                      type="password"
                      value={adminPassword}
                      onChange={e => setAdminPassword(e.target.value)}
                      placeholder="Digite a senha..."
                      className="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded-xl text-white text-xs mt-1 focus:outline-none focus:border-lime-400"
                      autoFocus
                      required
                    />
                  </div>
                  {adminError && <p className="text-xs text-rose-400">{adminError}</p>}
                  <button type="submit" className="w-full py-2 bg-lime-500 hover:bg-lime-400 text-slate-950 font-bold rounded-xl text-xs transition">
                    Entrar
                  </button>
                </form>
              </div>
            </div>
          )}
        </div>
      );
    }

    ReactDOM.createRoot(document.getElementById('root')).render(<App />);
  </script>
</body>
</html>`);
});

app.listen(PORT, () => {
  console.log(`\n=================================================`);
  console.log(`🚀 GranaXP ONLINE: http://localhost:${PORT}`);
  console.log(`📁 Banco de Dados: SQLite (granaxp.db criado)`);
  console.log(`⚙️  Senha Admin Inicial: 31181022`);
  console.log(`=================================================\n`);
});