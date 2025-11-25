import os
import secrets
import traceback
import sqlite3 # Mantido para fallback local
from datetime import datetime
from decimal import Decimal, ROUND_DOWN, InvalidOperation

# NOVOS IMPORTS PARA POSTGRESQL
import psycopg2
from psycopg2.extras import DictCursor # Para retornar rows como dicionários
from urllib.parse import urlparse
# FIM NOVOS IMPORTS

from flask import (
    Flask, render_template, request, redirect, url_for, flash, session, abort, g
)
from werkzeug.security import generate_password_hash, check_password_hash
from pathlib import Path

# ----------------- Config -----------------
# Define o caminho do DB SQLite para desenvolvimento local
DB_FILE = 'future_bank.db' # Renomeei para evitar conflito com DB_PATH
ADMIN_USERNAME = 'admin'

app = Flask(__name__)

# Configuração de Ambiente para Produção/Render
# Lê a SECRET_KEY de uma variável de ambiente em produção, ou usa uma padrão para dev
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_urlsafe(32))

# Variável de conexão com o Banco de Dados (PostgreSQL via Render/Neon)
DB_URL = os.environ.get('DATABASE_URL')
if not DB_URL:
    # Se DATABASE_URL não estiver configurada (ambiente de desenvolvimento local)
    print(f"ATENÇÃO: Usando SQLite localmente em: {DB_FILE}")
    db_type = 'sqlite'
else:
    print("Conectando-se ao PostgreSQL (Neon)...")
    db_type = 'postgresql'

# ----------------- Helpers DB -----------------
# A função get_db() e execute() agora são dinâmicas para SQLite ou PostgreSQL

def get_db():
    if 'db' not in g:
        if db_type == 'postgresql':
            try:
                # Parseia a URL de conexão para obter hostname, dbname, user, password, port
                url = urlparse(DB_URL)
                g.db = psycopg2.connect(
                    database=url.path[1:],
                    user=url.username,
                    password=url.password,
                    host=url.hostname,
                    port=url.port,
                    sslmode='require' # Necessário para Neon
                )
                g.db.autocommit = False # Gerenciamos commits manualmente
            except Exception as e:
                print(f"ERRO DE CONEXÃO AO POSTGRESQL: {e}")
                traceback.print_exc()
                raise RuntimeError(f"Falha ao conectar ao Neon: {e}")
        else: # SQLite fallback
            g.db = sqlite3.connect(DB_FILE)
            g.db.row_factory = sqlite3.Row
            g.db.execute('PRAGMA foreign_keys = ON;')
    return g.db

@app.teardown_appcontext
def close_connection(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def execute(query_sql, params=(), fetchone=False, fetchall=False, commit=False):
    db = get_db()
    
    if db_type == 'postgresql':
        cur = db.cursor(cursor_factory=DictCursor) # Usar DictCursor para retornar dicionários
        # Psycopg2 exige que os parâmetros sejam uma tupla, mesmo que seja apenas um
        if not isinstance(params, (tuple, list)):
            params = (params,)
        cur.execute(query_sql, params)
        
    else: # SQLite
        cur = db.cursor()
        cur.execute(query_sql, params)

    if commit:
        db.commit()

    if fetchone:
        result = cur.fetchone()
        return dict(result) if result and db_type == 'postgresql' else result
    
    if fetchall:
        results = cur.fetchall()
        return [dict(row) for row in results] if results and db_type == 'postgresql' else results
    
    return cur.lastrowid if db_type == 'sqlite' and commit else None # lastrowid para SQLite

# Adaptação da função query para usar execute
def query(query_sql, args=(), one=False):
    if one:
        return execute(query_sql, args, fetchone=True)
    else:
        return execute(query_sql, args, fetchall=True)


# ----------------- Inicialização do DB e Admin -----------------
# Esta função será chamada dentro de um contexto de aplicação
def init_db_and_admin_user():
    print("Executando init_db_and_admin_user()...")
    # Para SQLite: Cria o DB e as tabelas se não existirem
    if db_type == 'sqlite' and not Path(DB_FILE).exists():
        print(f"Criando banco de dados SQLite local em {DB_FILE}...")
        db = sqlite3.connect(DB_FILE)
        try:
            with db: # Context manager para commit/rollback automáticos
                db.executescript("""
                CREATE TABLE IF NOT EXISTS usuarios (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    senha_hash TEXT NOT NULL,
                    saldo NUMERIC NOT NULL DEFAULT 0.00,
                    is_admin INTEGER NOT NULL DEFAULT 0,
                    criado_em DATETIME DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS transacoes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    de_usuario INTEGER,
                    para_usuario INTEGER,
                    tipo TEXT,
                    valor NUMERIC,
                    descricao TEXT,
                    criado_em DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(de_usuario) REFERENCES usuarios(id) ON DELETE SET NULL,
                    FOREIGN KEY(para_usuario) REFERENCES usuarios(id) ON DELETE SET NULL
                );
                CREATE TABLE IF NOT EXISTS mensagens (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    para_usuario INTEGER,
                    de_usuario INTEGER,
                    assunto TEXT,
                    corpo TEXT,
                    lida INTEGER DEFAULT 0,
                    criado_em DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(para_usuario) REFERENCES usuarios(id) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS requests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    usuario_id INTEGER,
                    tipo TEXT,
                    valor NUMERIC,
                    aprovado INTEGER DEFAULT 0,
                    criado_em DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS auditoria (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    evento TEXT,
                    detalhe TEXT,
                    usuario_id INTEGER,
                    criado_em DATETIME DEFAULT CURRENT_TIMESTAMP,
                    ip_address TEXT
                );
                """)
            print("Tabelas SQLite criadas.")
        finally:
            db.close()
    
    # Lógica de criação de admin para ambos os tipos de DB (SQLite e PostgreSQL)
    try:
        # A função query já usa get_db(), que estará no contexto correto
        admin_check = query('SELECT id FROM usuarios WHERE username = %s', (ADMIN_USERNAME,), one=True)
        if not admin_check:
            print(f"Criando usuário admin ({ADMIN_USERNAME})...")
            senha_hash = generate_password_hash('admin123')
            # Insere admin com saldo inicial 0.00 e is_admin como TRUE
            # No SQLite, True vira 1. No Postgres, True é True.
            execute(
                'INSERT INTO usuarios (username, senha_hash, saldo, is_admin) VALUES (%s,%s,%s,%s)',
                (ADMIN_USERNAME, senha_hash, str(Decimal('0.00')), True), 
                commit=True
            )
            print("Usuário admin criado com sucesso.")
        else:
            # Garante que o usuário admin sempre tenha a flag is_admin como TRUE
            # Isso é importante se o admin foi criado com is_admin=0 por engano
            execute('UPDATE usuarios SET is_admin = %s WHERE username = %s', (True, ADMIN_USERNAME), commit=True)
            print("Usuário admin verificado/atualizado.")

    except Exception as e:
        print(f'ERRO ao inicializar DB (criação/verificação do admin): {e}')
        traceback.print_exc()
        # Não levante o RuntimeError aqui, apenas logue. Se o DB estiver realmente
        # inacessível, outros erros acontecerão, mas não queremos impedir o boot por completo.
        

# NOVO MÉTODO DE INICIALIZAÇÃO PARA FLASK 3.x
# Usamos um atributo customizado para garantir que seja executado apenas uma vez.
with app.app_context():
    app._initialization_done = False # Adiciona um atributo ao objeto app

@app.before_request
def setup_on_first_request():
    if not app._initialization_done:
        print("Executando setup_on_first_request() (uma vez) ...")
        init_db_and_admin_user()
        app._initialization_done = True # Marca como executado


# ----------------- Utilitários Financeiros & Segurança -----------------
CURRENCY_QUANT = Decimal('0.01')

def to_decimal(value):
    """Converte valor para Decimal com 2 casas, validando."""
    if isinstance(value, Decimal):
        d = value
    else:
        try:
            d = Decimal(str(value).replace(',', '.')) # Aceita vírgula como separador
        except (InvalidOperation, ValueError):
            raise ValueError("Valor inválido.")
    
    d = d.quantize(CURRENCY_QUANT, rounding=ROUND_DOWN)
    if d <= 0:
        raise ValueError("O valor deve ser maior que zero.")
    return d

def verificar_senha_atual(usuario_id, senha_plain):
    """Verifica se a senha fornecida corresponde ao usuário atual."""
    user = query('SELECT senha_hash FROM usuarios WHERE id = %s', (usuario_id,), one=True)
    if not user or not check_password_hash(user['senha_hash'], senha_plain):
        raise ValueError("Senha de confirmação incorreta.")
    return True

# ----------------- Auditoria & Transações -----------------
def log_auditoria(evento, detalhe='', usuario_id=None, ip_address=None):
    if not ip_address:
        ip_address = request.remote_addr if request else 'N/A'
    try:
        execute('INSERT INTO auditoria (evento, detalhe, usuario_id, ip_address) VALUES (%s,%s,%s,%s)',
                (evento, detalhe, usuario_id, ip_address), commit=True)
    except Exception:
        print("Falha ao gravar auditoria:", traceback.format_exc())

def create_transaction_atomic(de_id, para_id, tipo, valor_decimal, descricao=''):
    """Executa transferência de saldo e registro de log atomicamente."""
    if not isinstance(valor_decimal, Decimal) or valor_decimal <= 0:
        raise ValueError("Valor de transação inválido.")

    db = get_db()
    try:
        cur = db.cursor() # Usar cursor simples aqui, pois estamos fazendo operações de UPDATE/SELECT FOR UPDATE

        # 1. Verifica e Debita Origem (se houver)
        if de_id:
            cur.execute('SELECT saldo FROM usuarios WHERE id = %s FOR UPDATE', (de_id,)) # Bloqueia a linha
            row = cur.fetchone()
            if not row: raise ValueError("Usuário de origem não encontrado.")
            saldo_origem = Decimal(row[0]) # Acessa pelo índice 0
            if saldo_origem < valor_decimal:
                raise ValueError(f"Saldo insuficiente. Disponível: P {saldo_origem}")
            
            novo_origem = saldo_origem - valor_decimal
            cur.execute('UPDATE usuarios SET saldo = %s WHERE id = %s', (str(novo_origem), de_id))

        # 2. Credita Destino (se houver)
        if para_id:
            cur.execute('SELECT saldo FROM usuarios WHERE id = %s FOR UPDATE', (para_id,)) # Bloqueia a linha
            if not cur.fetchone(): raise ValueError("Usuário destino não encontrado.") # Apenas verifica existência
            
            cur.execute('UPDATE usuarios SET saldo = saldo + %s WHERE id = %s', (str(valor_decimal), para_id))

        # 3. Registra Transação
        cur.execute('''INSERT INTO transacoes (de_usuario, para_usuario, tipo, valor, descricao) 
                            VALUES (%s,%s,%s,%s,%s)''',
                    (de_id, para_id, tipo, str(valor_decimal), descricao))
        
        db.commit() # Commit explícito
        log_auditoria('transacao_sucesso', f'{tipo} | P {valor_decimal} | {descricao}', usuario_id=de_id or para_id)
        return True 
    except Exception as e:
        db.rollback() # Rollback em caso de erro
        log_auditoria('transacao_falha', f'Erro: {e} | {tipo}', usuario_id=de_id or para_id)
        raise

# ----------------- CSRF -----------------
@app.before_request
def csrf_protect():
    if request.method == "POST":
        token_form = request.form.get('csrf_token')
        token_sess = session.get('csrf_token')
        if not token_form or not token_sess or token_form != token_sess:
            abort(400, description="Token de segurança inválido (CSRF). Tente recarregar a página.")

def ensure_csrf():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_urlsafe(32)
    return session['csrf_token']

@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=ensure_csrf())

# ================= ROTAS =================

@app.route('/')
def root():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

# --- Autenticação ---
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        senha = request.form.get('senha', '')
        user = query('SELECT id, username, senha_hash, is_admin FROM usuarios WHERE username = %s', (username,), one=True)
        if user and check_password_hash(user['senha_hash'], senha):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = user['is_admin'] # Lê o status de admin diretamente do DB
            log_auditoria('login', f'Usuário {username} logado', usuario_id=user['id'])
            return redirect(url_for('dashboard'))
        flash('Usuário ou senha inválidos.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    log_auditoria('logout', f'User {session.get("username")} saiu', usuario_id=session.get('user_id'))
    session.clear()
    flash('Você foi desconectado.', 'info')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        try:
            username = request.form.get('username', '').strip()
            senha = request.form.get('senha', '')
            senha2 = request.form.get('senha2', '')

            if not username or not senha or not senha2:
                flash('Preencha todos os campos.', 'danger')
                return redirect(url_for('register'))

            if senha != senha2:
                flash('As senhas não coincidem.', 'danger')
                return redirect(url_for('register'))
            
            if len(senha) < 6:
                flash('A senha deve ter no mínimo 6 caracteres.', 'danger')
                return redirect(url_for('register'))

            if query('SELECT id FROM usuarios WHERE username = %s', (username,), one=True):
                flash('Nome de usuário já está em uso.', 'warning')
                return redirect(url_for('register'))

            senha_hash = generate_password_hash(senha)
            # is_admin para novos usuários é False
            execute('INSERT INTO usuarios (username, senha_hash, saldo, is_admin) VALUES (%s,%s,%s,%s)',
                    (username, senha_hash, str(Decimal('0.00')), False), commit=True)
            log_auditoria('registro', f'Novo usuário: {username}')
            flash('Conta criada com sucesso! Faça login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash(f'Erro ao criar conta: {e}', 'danger')
            traceback.print_exc()
    return render_template('register.html')

# --- Dashboard e Operações ---

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session: return redirect(url_for('login'))
    uid = session['user_id']
    
    user = query('SELECT * FROM usuarios WHERE id = %s', (uid,), one=True)
    # Últimas 5 mensagens
    msgs = query('SELECT * FROM mensagens WHERE para_usuario = %s ORDER BY criado_em DESC LIMIT 5', (uid,))
    # Últimos 10 requests do usuário
    meus_requests = query('SELECT * FROM requests WHERE usuario_id = %s ORDER BY criado_em DESC LIMIT 10', (uid,))
    
    # Busca transações recentes (enviadas ou recebidas)
    transacoes_recentes = query('''
        SELECT t.*, u_de.username as de_nome, u_para.username as para_nome 
        FROM transacoes t
        LEFT JOIN usuarios u_de ON t.de_usuario = u_de.id
        LEFT JOIN usuarios u_para ON t.para_usuario = u_para.id
        WHERE t.de_usuario = %s OR t.para_usuario = %s
        ORDER BY t.criado_em DESC LIMIT 10
    ''', (uid, uid))

    return render_template('dashboard.html', user=user, mensagens=msgs, requests=meus_requests, transacoes=transacoes_recentes)

# --- ROTA UNIFICADA PARA TRANSFERÊNCIAS ENTRE USUÁRIOS ---
@app.route('/realizar_transferencia', methods=['POST'])
def realizar_transferencia():
    if 'user_id' not in session: return redirect(url_for('login'))
    uid = session['user_id']

    try:
        destinatario_user = request.form.get('destinatario', '').strip()
        valor_str = request.form.get('valor', '')
        senha_confirmacao = request.form.get('senha_confirmacao', '')

        # 1. Validações Básicas
        if not destinatario_user: raise ValueError("Destinatário é obrigatório.")
        if not senha_confirmacao: raise ValueError("Senha de confirmação é obrigatória.")
        if destinatario_user == session['username']: raise ValueError("Não pode transferir para si mesmo.")

        # 2. Valida Valor
        valor_dec = to_decimal(valor_str)

        # 3. Valida Senha ANTES de tentar a transação
        verificar_senha_atual(uid, senha_confirmacao)

        # 4. Busca Destinatário
        target = query('SELECT id FROM usuarios WHERE username = %s', (destinatario_user,), one=True)
        if not target: raise ValueError("Usuário destinatário não encontrado.")

        # 5. Executa Transação Atômica
        create_transaction_atomic(uid, target['id'], 'transferencia', valor_dec, f'Transferência para {destinatario_user}')
        
        flash(f'Sucesso! P {valor_dec} enviados para {destinatario_user}.', 'success')

    except ValueError as e:
        flash(str(e), 'danger')
    except Exception as e:
        flash(f'Erro interno na transferência: {e}', 'danger')
        traceback.print_exc()

    return redirect(url_for('dashboard'))


# --- ROTA UNIFICADA PARA SOLICITAÇÕES (DEPÓSITO/SAQUE) ---
@app.route('/solicitar_operacao', methods=['POST'])
def solicitar_operacao():
    if 'user_id' not in session: return redirect(url_for('login'))
    uid = session['user_id']

    try:
        tipo = request.form.get('tipo_operacao') # 'deposit' ou 'withdraw'
        valor_str = request.form.get('valor')
        senha_confirmacao = request.form.get('senha_confirmacao', '')

        if tipo not in ['deposit', 'withdraw']: raise ValueError("Tipo de operação inválido.")
        if not senha_confirmacao: raise ValueError("Senha de confirmação é obrigatória.")
        
        # 1. Valida Valor e Senha
        valor_dec = to_decimal(valor_str)
        verificar_senha_atual(uid, senha_confirmacao)

        # 2. Cria o Request
        execute('INSERT INTO requests (usuario_id, tipo, valor, aprovado) VALUES (%s,%s,%s,%s)',
                (uid, tipo, str(valor_dec), 0), commit=True) # 0 é o default para 'pendente'
        
        tipo_label = "Depósito" if tipo == "deposit" else "Saque"
        flash(f'Solicitação de {tipo_label} de P {valor_dec} enviada para análise.', 'info')

    except ValueError as e:
        flash(str(e), 'danger')
    except Exception as e:
        flash(f"Erro ao processar solicitação: {e}", 'danger')
        
    return redirect(url_for('dashboard'))

# --- Histórico Completo ---
@app.route('/history')
def history():
    if 'user_id' not in session: return redirect(url_for('login'))
    uid = session['user_id']
    
    sql_base = '''
        SELECT t.*, u1.username as de_nome, u2.username as para_nome
        FROM transacoes t
        LEFT JOIN usuarios u1 ON t.de_usuario = u1.id
        LEFT JOIN usuarios u2 ON t.para_usuario = u2.id
    '''
    
    # Admin vê tudo, usuário comum vê apenas as suas
    if session.get('is_admin'):
        rows = query(sql_base + ' ORDER BY t.criado_em DESC LIMIT 500')
        flash('Modo Admin: Visualizando histórico global.', 'warning')
    else:
        rows = query(sql_base + ' WHERE t.de_usuario = %s OR t.para_usuario = %s ORDER BY t.criado_em DESC LIMIT 200', (uid, uid))

    return render_template('history.html', transacoes=rows)


# ================= ÁREA ADMIN =================
@app.route('/admin')
def admin_dashboard():
    if not session.get('is_admin'):
        abort(403) # Forbidden
    
    # Requests Pendentes
    requests_pendentes = query('''
        SELECT r.*, u.username FROM requests r 
        JOIN usuarios u ON r.usuario_id = u.id 
        WHERE aprovado = 0 ORDER BY r.criado_em ASC''')

    # Todos os Usuários para gerenciamento
    users = query('SELECT id, username, saldo, is_admin FROM usuarios ORDER BY id ASC') # Adicionado is_admin para exibição
    
    # Log de Auditoria
    auditoria = query('''
        SELECT a.*, u.username FROM auditoria a
        LEFT JOIN usuarios u ON a.usuario_id = u.id
        ORDER BY a.criado_em DESC LIMIT 100''') # Aumentado limite para admin

    # Histórico Global de Transações (Admin)
    transacoes_globais = query('''
        SELECT t.*, u_de.username as de_nome, u_para.username as para_nome 
        FROM transacoes t
        LEFT JOIN usuarios u_de ON t.de_usuario = u_de.id
        LEFT JOIN usuarios u_para ON t.para_usuario = u_para.id
        ORDER BY t.criado_em DESC LIMIT 100''') # Aumentado limite para admin


    return render_template('admin.html', 
                            requests_pendentes=requests_pendentes, 
                            users=users,
                            auditoria=auditoria,
                            transacoes=transacoes_globais) # Passando dados adicionais

@app.route('/admin/request/<int:req_id>/<action>', methods=['POST'])
def process_request(req_id, action):
    if not session.get('is_admin'): abort(403)
    if action not in ['approve', 'reject']: abort(400)
    
    admin_id = session['user_id']
    try:
        r = query('SELECT * FROM requests WHERE id = %s', (req_id,), one=True)
        if not r or r['aprovado'] != 0:
            raise ValueError("Request não encontrado ou já processado.")

        usuario_id = r['usuario_id']
        valor = Decimal(r['valor'])
        tipo = r['tipo']

        if action == 'reject':
            execute('UPDATE requests SET aprovado = %s WHERE id = %s', (-1, req_id), commit=True)
            flash(f'Request #{req_id} rejeitado.', 'warning')
            log_auditoria('admin_reject', f'Req #{req_id} rejeitado pelo admin {admin_id}', usuario_id=admin_id)
        
        elif action == 'approve':
            # Processa financeiramente
            if tipo == 'deposit':
                create_transaction_atomic(None, usuario_id, 'deposito_aprovado', valor, f'Depósito Ref #{req_id}')
            elif tipo == 'withdraw':
                create_transaction_atomic(usuario_id, None, 'saque_aprovado', valor, f'Saque Ref #{req_id}')
            
            execute('UPDATE requests SET aprovado = %s WHERE id = %s', (1, req_id), commit=True)
            flash(f'Request #{req_id} aprovado e processado com sucesso.', 'success')
            log_auditoria('admin_approve', f'Req #{req_id} aprovado pelo admin {admin_id}', usuario_id=admin_id)

    except Exception as e:
        flash(f'Erro ao processar request: {e}', 'danger')
        traceback.print_exc()

    return redirect(url_for('admin_dashboard'))

@app.route('/admin/reset_password', methods=['POST'])
def admin_reset_password():
    if not session.get('is_admin'): abort(403)
    try:
        user_id = request.form.get('user_id')
        nova_senha = request.form.get('nova_senha')

        if not user_id: raise ValueError("ID de usuário inválido.")

        # Gerar senha se não for fornecida, ou usar a fornecida
        if not nova_senha:
            nova_senha = secrets.token_urlsafe(8) # Senha aleatória de 8 caracteres
            flash(f'Senha para o usuário ID {user_id} resetada para: <strong class="text-white">{nova_senha}</strong> (exibir apenas uma vez).', 'info')
        else:
            if len(nova_senha) < 6:
                raise ValueError("A nova senha deve ter no mínimo 6 caracteres.")
            flash(f'Senha para o usuário ID {user_id} definida.', 'success')

        senha_hash = generate_password_hash(nova_senha)
        execute('UPDATE usuarios SET senha_hash = %s WHERE id = %s', (senha_hash, user_id), commit=True)
        log_auditoria('admin_reset_senha', f'Senha do usuário {user_id} resetada.', usuario_id=session['user_id'])
        
    except ValueError as e:
        flash(str(e), 'danger')
    except Exception as e:
        flash(f'Erro ao resetar senha: {e}', 'danger')
        traceback.print_exc()
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/send_message', methods=['POST'])
def admin_send_message():
    if not session.get('is_admin'): abort(403)
    try:
        para_id = request.form.get('para_id')
        conteudo = request.form.get('conteudo', '').strip()

        if not para_id or not conteudo:
            raise ValueError("Preencha todos os campos para enviar a mensagem.")
        
        assunto = "Mensagem do Administrador" 

        execute('INSERT INTO mensagens (para_usuario, de_usuario, assunto, corpo, lida) VALUES (%s,%s,%s,%s,%s)',
                (para_id, session['user_id'], assunto, conteudo, False), commit=True)
        log_auditoria('admin_envio_msg', f'Mensagem enviada para {para_id}.', usuario_id=session['user_id'])
        flash('Mensagem enviada com sucesso.', 'success')

    except ValueError as e:
        flash(str(e), 'danger')
    except Exception as e:
        flash(f'Erro ao enviar mensagem: {e}', 'danger')
        traceback.print_exc()
    return redirect(url_for('admin_dashboard'))


# --- Rota para Marcar Mensagem como Lida ---
@app.route('/message/<int:message_id>/read', methods=['POST'])
def mark_message_read(message_id):
    if 'user_id' not in session: abort(403)
    
    try:
        # Marca a mensagem como lida APENAS se for para o usuário logado
        execute('UPDATE mensagens SET lida = %s WHERE id = %s AND para_usuario = %s',
                (True, message_id, session['user_id']), commit=True)
        flash('Mensagem marcada como lida.', 'info')
    except Exception as e:
        flash(f'Erro ao marcar mensagem como lida: {e}', 'danger')
    
    return redirect(url_for('dashboard'))


if __name__ == '__main__':
    # Em desenvolvimento, o app.run irá criar o DB SQLite
    # e a função before_request garantirá o admin na primeira requisição
    app.run(debug=True)
