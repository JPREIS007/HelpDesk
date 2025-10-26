import sqlite3
import os
import time
import threading
import queue
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
import secrets
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

app = Flask(__name__)
app.secret_key = 'helpdesk-secret-key-change-in-production'

# Configurações
DATABASE = 'helpdesk.db'
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'txt', 'docx'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB

# Criar pasta de uploads
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Sistema de filas e threads para simulação
chamados_queue = queue.PriorityQueue()
atendimento_threads = {}
simulacao_ativa = False

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    
    # Tabela de usuários com perfis
    conn.execute('''
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            senha_hash TEXT NOT NULL,
            perfil TEXT NOT NULL DEFAULT 'cliente',
            ativo BOOLEAN DEFAULT 1,
            data_criacao DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Tabela de chamados
    conn.execute('''
        CREATE TABLE IF NOT EXISTS chamados (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            numero_protocolo TEXT UNIQUE NOT NULL,
            titulo TEXT NOT NULL,
            descricao TEXT NOT NULL,
            tipo_problema TEXT NOT NULL,
            prioridade TEXT NOT NULL,
            status TEXT DEFAULT 'aberto',
            cliente_id INTEGER NOT NULL,
            atendente_id INTEGER,
            tecnico_id INTEGER,
            anexo_path TEXT,
            data_criacao DATETIME DEFAULT CURRENT_TIMESTAMP,
            data_atualizacao DATETIME DEFAULT CURRENT_TIMESTAMP,
            estimativa_resolucao INTEGER,
            tempo_atendimento INTEGER DEFAULT 0,
            FOREIGN KEY (cliente_id) REFERENCES usuarios (id),
            FOREIGN KEY (atendente_id) REFERENCES usuarios (id),
            FOREIGN KEY (tecnico_id) REFERENCES usuarios (id)
        )
    ''')
    
    # Tabela de comentários
    conn.execute('''
        CREATE TABLE IF NOT EXISTS comentarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            chamado_id INTEGER NOT NULL,
            usuario_id INTEGER NOT NULL,
            comentario TEXT NOT NULL,
            tipo TEXT DEFAULT 'comentario',
            data_criacao DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (chamado_id) REFERENCES chamados (id),
            FOREIGN KEY (usuario_id) REFERENCES usuarios (id)
        )
    ''')
    
    # Tabela de logs de auditoria
    conn.execute('''
        CREATE TABLE IF NOT EXISTS logs_auditoria (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario_id INTEGER,
            acao TEXT NOT NULL,
            tabela TEXT NOT NULL,
            registro_id INTEGER,
            dados_anteriores TEXT,
            dados_novos TEXT,
            ip_address TEXT,
            user_agent TEXT,
            data_criacao DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (usuario_id) REFERENCES usuarios (id)
        )
    ''')
    
    # Tabela de tokens para recuperação de senha
    conn.execute('''
        CREATE TABLE IF NOT EXISTS tokens_recuperacao (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario_id INTEGER NOT NULL,
            token TEXT UNIQUE NOT NULL,
            data_expiracao DATETIME NOT NULL,
            usado BOOLEAN DEFAULT 0,
            data_criacao DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (usuario_id) REFERENCES usuarios (id)
        )
    ''')
    
    # Criar usuário administrador padrão
    admin_exists = conn.execute('SELECT id FROM usuarios WHERE email = ?', ('admin@helpdesk.com',)).fetchone()
    if not admin_exists:
        senha_hash = generate_password_hash('admin123')
        conn.execute(
            'INSERT INTO usuarios (nome, email, senha_hash, perfil) VALUES (?, ?, ?, ?)',
            ('Administrador', 'admin@helpdesk.com', senha_hash, 'administrador')
        )
    
    conn.commit()
    conn.close()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def perfil_required(*perfis_permitidos):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login'))
            
            conn = get_db_connection()
            usuario = conn.execute('SELECT perfil FROM usuarios WHERE id = ?', (session['user_id'],)).fetchone()
            conn.close()
            
            if usuario and usuario['perfil'] in perfis_permitidos:
                return f(*args, **kwargs)
            else:
                flash('Acesso negado. Permissão insuficiente.', 'error')
                return redirect(url_for('dashboard'))
        return decorated_function
    return decorator

def log_auditoria(acao, tabela, registro_id=None, dados_anteriores=None, dados_novos=None):
    try:
        conn = get_db_connection()
        conn.execute('''
            INSERT INTO logs_auditoria (usuario_id, acao, tabela, registro_id, dados_anteriores, dados_novos, ip_address, user_agent)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            session.get('user_id'),
            acao,
            tabela,
            registro_id,
            str(dados_anteriores) if dados_anteriores else None,
            str(dados_novos) if dados_novos else None,
            request.remote_addr,
            request.headers.get('User-Agent', '')
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Erro ao registrar log de auditoria: {e}")

def gerar_numero_protocolo():
    timestamp = str(int(time.time()))[-6:]
    random_suffix = secrets.token_hex(3).upper()
    return f"HD{timestamp}{random_suffix}"

def calcular_prioridade_automatica(tipo_problema, cliente_id):
    # Regra de negócio para prioridade automática
    prioridades = {
        'sem_internet': 'alta',
        'lentidao': 'media',
        'problema_tecnico': 'media',
        'duvida_comercial': 'baixa',
        'instalacao': 'media',
        'cancelamento': 'baixa'
    }
    
    # Verificar histórico do cliente
    conn = get_db_connection()
    chamados_recentes = conn.execute('''
        SELECT COUNT(*) as total FROM chamados 
        WHERE cliente_id = ? AND data_criacao > datetime('now', '-7 days')
    ''', (cliente_id,)).fetchone()
    conn.close()
    
    prioridade_base = prioridades.get(tipo_problema, 'baixa')
    
    # Escalar prioridade se cliente tem muitos chamados recentes
    if chamados_recentes['total'] > 2:
        if prioridade_base == 'baixa':
            prioridade_base = 'media'
        elif prioridade_base == 'media':
            prioridade_base = 'alta'
    
    return prioridade_base

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Sistema de simulação de atendimento com threads
def simular_atendimento_thread(chamado_id, tempo_estimado):
    global atendimento_threads, simulacao_ativa
    
    if not simulacao_ativa:
        return
    
    print(f"Iniciando atendimento simulado para chamado {chamado_id} - {tempo_estimado}s")
    
    # Simular processamento
    time.sleep(tempo_estimado)
    
    if not simulacao_ativa:
        return
    
    # Atualizar status do chamado
    try:
        conn = get_db_connection()
        conn.execute('''
            UPDATE chamados SET 
            status = 'resolvido',
            tempo_atendimento = ?,
            data_atualizacao = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (tempo_estimado, chamado_id))
        
        # Adicionar comentário automático
        conn.execute('''
            INSERT INTO comentarios (chamado_id, usuario_id, comentario, tipo)
            VALUES (?, 1, 'Chamado resolvido automaticamente pelo sistema de simulação', 'sistema')
        ''', (chamado_id,))
        
        conn.commit()
        conn.close()
        
        log_auditoria('UPDATE', 'chamados', chamado_id, None, f'Status alterado para resolvido via simulação')
        print(f"Chamado {chamado_id} resolvido automaticamente")
        
    except Exception as e:
        print(f"Erro na simulação de atendimento: {e}")
    finally:
        # Remover thread da lista
        if chamado_id in atendimento_threads:
            del atendimento_threads[chamado_id]

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        senha = request.form['senha']
        
        conn = get_db_connection()
        usuario = conn.execute(
            'SELECT * FROM usuarios WHERE email = ? AND ativo = 1', (email,)
        ).fetchone()
        conn.close()
        
        if usuario and check_password_hash(usuario['senha_hash'], senha):
            session['user_id'] = usuario['id']
            session['user_name'] = usuario['nome']
            session['user_profile'] = usuario['perfil']
            
            log_auditoria('LOGIN', 'usuarios', usuario['id'], None, f'Login realizado: {email}')
            flash(f'Bem-vindo(a), {usuario["nome"]}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Email ou senha incorretos', 'error')
            log_auditoria('LOGIN_FAILED', 'usuarios', None, None, f'Tentativa de login falhada: {email}')
    
    return render_template('login.html')

@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    if request.method == 'POST':
        nome = request.form['nome']
        email = request.form['email']
        senha = request.form['senha']
        perfil = request.form.get('perfil', 'cliente')
        
        # Validar se perfil especial requer permissão
        if perfil in ['administrador', 'atendente', 'tecnico'] and session.get('user_profile') != 'administrador':
            perfil = 'cliente'
        
        conn = get_db_connection()
        
        # Verificar se email já existe
        existe = conn.execute('SELECT id FROM usuarios WHERE email = ?', (email,)).fetchone()
        if existe:
            flash('Email já cadastrado no sistema', 'error')
            conn.close()
            return render_template('cadastro.html')
        
        # Criar usuário
        senha_hash = generate_password_hash(senha)
        cursor = conn.execute(
            'INSERT INTO usuarios (nome, email, senha_hash, perfil) VALUES (?, ?, ?, ?)',
            (nome, email, senha_hash, perfil)
        )
        user_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        log_auditoria('CREATE', 'usuarios', user_id, None, f'Usuário criado: {email} - {perfil}')
        flash('Cadastro realizado com sucesso! Faça login para continuar.', 'success')
        return redirect(url_for('login'))
    
    return render_template('cadastro.html')

@app.route('/recuperar-senha', methods=['GET', 'POST'])
def recuperar_senha():
    if request.method == 'POST':
        email = request.form['email']
        
        conn = get_db_connection()
        usuario = conn.execute('SELECT * FROM usuarios WHERE email = ? AND ativo = 1', (email,)).fetchone()
        
        if usuario:
            # Gerar token
            token = secrets.token_urlsafe(32)
            data_expiracao = datetime.now() + timedelta(hours=1)
            
            conn.execute('''
                INSERT INTO tokens_recuperacao (usuario_id, token, data_expiracao)
                VALUES (?, ?, ?)
            ''', (usuario['id'], token, data_expiracao))
            conn.commit()
            
            # Em produção, enviaria email
            print(f"Token de recuperação para {email}: {token}")
            log_auditoria('RECOVERY_REQUEST', 'usuarios', usuario['id'], None, f'Solicitação de recuperação de senha')
            
            flash('Instruções de recuperação enviadas por email (verifique o console)', 'info')
        else:
            flash('Email não encontrado no sistema', 'error')
        
        conn.close()
    
    return render_template('recuperar_senha.html')

@app.route('/redefinir-senha/<token>', methods=['GET', 'POST'])
def redefinir_senha(token):
    if request.method == 'POST':
        nova_senha = request.form['nova_senha']
        
        conn = get_db_connection()
        token_data = conn.execute('''
            SELECT * FROM tokens_recuperacao 
            WHERE token = ? AND data_expiracao > CURRENT_TIMESTAMP AND usado = 0
        ''', (token,)).fetchone()
        
        if token_data:
            # Atualizar senha
            senha_hash = generate_password_hash(nova_senha)
            conn.execute(
                'UPDATE usuarios SET senha_hash = ? WHERE id = ?',
                (senha_hash, token_data['usuario_id'])
            )
            
            # Marcar token como usado
            conn.execute(
                'UPDATE tokens_recuperacao SET usado = 1 WHERE id = ?',
                (token_data['id'],)
            )
            
            conn.commit()
            log_auditoria('PASSWORD_RESET', 'usuarios', token_data['usuario_id'], None, 'Senha redefinida via token')
            flash('Senha redefinida com sucesso!', 'success')
            conn.close()
            return redirect(url_for('login'))
        else:
            flash('Token inválido ou expirado', 'error')
            conn.close()
            return redirect(url_for('recuperar_senha'))
    
    return render_template('redefinir_senha.html', token=token)

@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db_connection()
    
    perfil = session['user_profile']
    user_id = session['user_id']
    
    # Estatísticas baseadas no perfil
    if perfil == 'cliente':
        chamados = conn.execute('''
            SELECT * FROM chamados WHERE cliente_id = ? 
            ORDER BY data_criacao DESC LIMIT 10
        ''', (user_id,)).fetchall()
        
        stats = {
            'total': len(chamados),
            'abertos': len([c for c in chamados if c['status'] == 'aberto']),
            'em_andamento': len([c for c in chamados if c['status'] in ['em_triagem', 'em_atendimento']]),
            'resolvidos': len([c for c in chamados if c['status'] == 'resolvido'])
        }
    else:
        # Estatísticas gerais para staff
        chamados = conn.execute('''
            SELECT c.*, u.nome as cliente_nome 
            FROM chamados c
            LEFT JOIN usuarios u ON c.cliente_id = u.id
            ORDER BY 
                CASE c.prioridade 
                    WHEN 'alta' THEN 1 
                    WHEN 'media' THEN 2 
                    WHEN 'baixa' THEN 3 
                END,
                c.data_criacao DESC
            LIMIT 20
        ''').fetchall()
        
        all_chamados = conn.execute('SELECT status FROM chamados').fetchall()
        stats = {
            'total': len(all_chamados),
            'abertos': len([c for c in all_chamados if c['status'] == 'aberto']),
            'em_andamento': len([c for c in all_chamados if c['status'] in ['em_triagem', 'em_atendimento']]),
            'resolvidos': len([c for c in all_chamados if c['status'] == 'resolvido'])
        }
    
    conn.close()
    return render_template('dashboard.html', chamados=chamados, stats=stats)

@app.route('/novo-chamado', methods=['GET', 'POST'])
@login_required
@perfil_required('cliente', 'administrador')
def novo_chamado():
    if request.method == 'POST':
        titulo = request.form['titulo']
        descricao = request.form['descricao']
        tipo_problema = request.form['tipo_problema']
        
        # Upload de arquivo
        arquivo_path = None
        if 'anexo' in request.files:
            file = request.files['anexo']
            if file.filename != '' and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                timestamp = str(int(time.time()))
                filename = f"{timestamp}_{filename}"
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                arquivo_path = f"uploads/{filename}"
        
        # Gerar protocolo e calcular prioridade
        protocolo = gerar_numero_protocolo()
        prioridade = calcular_prioridade_automatica(tipo_problema, session['user_id'])
        
        # Estimar tempo de resolução baseado na prioridade
        estimativas = {'alta': 120, 'media': 300, 'baixa': 600}  # em segundos
        estimativa = estimativas.get(prioridade, 300)
        
        conn = get_db_connection()
        cursor = conn.execute('''
            INSERT INTO chamados (numero_protocolo, titulo, descricao, tipo_problema, prioridade, cliente_id, anexo_path, estimativa_resolucao)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (protocolo, titulo, descricao, tipo_problema, prioridade, session['user_id'], arquivo_path, estimativa))
        
        chamado_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        log_auditoria('CREATE', 'chamados', chamado_id, None, f'Chamado criado: {protocolo}')
        flash(f'Chamado {protocolo} criado com sucesso!', 'success')
        return redirect(url_for('visualizar_chamado', id=chamado_id))
    
    return render_template('novo_chamado.html')

@app.route('/chamado/<int:id>')
@login_required
def visualizar_chamado(id):
    conn = get_db_connection()
    
    # Verificar permissão
    if session['user_profile'] == 'cliente':
        chamado = conn.execute('''
            SELECT c.*, u.nome as cliente_nome 
            FROM chamados c
            LEFT JOIN usuarios u ON c.cliente_id = u.id
            WHERE c.id = ? AND c.cliente_id = ?
        ''', (id, session['user_id'])).fetchone()
    else:
        chamado = conn.execute('''
            SELECT c.*, u.nome as cliente_nome,
                   a.nome as atendente_nome,
                   t.nome as tecnico_nome
            FROM chamados c
            LEFT JOIN usuarios u ON c.cliente_id = u.id
            LEFT JOIN usuarios a ON c.atendente_id = a.id
            LEFT JOIN usuarios t ON c.tecnico_id = t.id
            WHERE c.id = ?
        ''', (id,)).fetchone()
    
    if not chamado:
        flash('Chamado não encontrado ou sem permissão de acesso', 'error')
        return redirect(url_for('dashboard'))
    
    # Buscar comentários
    comentarios = conn.execute('''
        SELECT c.*, u.nome as usuario_nome
        FROM comentarios c
        LEFT JOIN usuarios u ON c.usuario_id = u.id
        WHERE c.chamado_id = ?
        ORDER BY c.data_criacao ASC
    ''', (id,)).fetchall()
    
    # Buscar atendentes e técnicos para atribuição
    staff = []
    if session['user_profile'] in ['administrador', 'atendente']:
        staff = conn.execute('''
            SELECT id, nome, perfil FROM usuarios 
            WHERE perfil IN ('atendente', 'tecnico') AND ativo = 1
            ORDER BY nome
        ''').fetchall()
    
    conn.close()
    return render_template('visualizar_chamado.html', chamado=chamado, comentarios=comentarios, staff=staff)

@app.route('/chamado/<int:id>/comentar', methods=['POST'])
@login_required
def adicionar_comentario(id):
    comentario = request.form['comentario']
    
    conn = get_db_connection()
    
    # Verificar se usuário tem acesso ao chamado
    if session['user_profile'] == 'cliente':
        chamado_existe = conn.execute(
            'SELECT id FROM chamados WHERE id = ? AND cliente_id = ?', 
            (id, session['user_id'])
        ).fetchone()
    else:
        chamado_existe = conn.execute('SELECT id FROM chamados WHERE id = ?', (id,)).fetchone()
    
    if not chamado_existe:
        flash('Chamado não encontrado ou sem permissão', 'error')
        conn.close()
        return redirect(url_for('dashboard'))
    
    # Adicionar comentário
    conn.execute('''
        INSERT INTO comentarios (chamado_id, usuario_id, comentario)
        VALUES (?, ?, ?)
    ''', (id, session['user_id'], comentario))
    
    # Atualizar data do chamado
    conn.execute(
        'UPDATE chamados SET data_atualizacao = CURRENT_TIMESTAMP WHERE id = ?',
        (id,)
    )
    
    conn.commit()
    conn.close()
    
    log_auditoria('CREATE', 'comentarios', None, None, f'Comentário adicionado ao chamado {id}')
    flash('Comentário adicionado com sucesso!', 'success')
    return redirect(url_for('visualizar_chamado', id=id))

@app.route('/chamado/<int:id>/atribuir', methods=['POST'])
@login_required
@perfil_required('administrador', 'atendente')
def atribuir_chamado(id):
    atendente_id = request.form.get('atendente_id')
    tecnico_id = request.form.get('tecnico_id')
    novo_status = request.form.get('status', 'em_triagem')
    
    conn = get_db_connection()
    
    # Dados anteriores para auditoria
    chamado_anterior = conn.execute('SELECT * FROM chamados WHERE id = ?', (id,)).fetchone()
    
    if not chamado_anterior:
        flash('Chamado não encontrado', 'error')
        conn.close()
        return redirect(url_for('dashboard'))
    
    # Atualizar atribuições
    conn.execute('''
        UPDATE chamados SET 
        atendente_id = ?, 
        tecnico_id = ?, 
        status = ?,
        data_atualizacao = CURRENT_TIMESTAMP
        WHERE id = ?
    ''', (atendente_id or None, tecnico_id or None, novo_status, id))
    
    # Adicionar comentário automático
    comentario_texto = f"Chamado atribuído - Status: {novo_status}"
    if atendente_id:
        atendente = conn.execute('SELECT nome FROM usuarios WHERE id = ?', (atendente_id,)).fetchone()
        comentario_texto += f", Atendente: {atendente['nome']}"
    if tecnico_id:
        tecnico = conn.execute('SELECT nome FROM usuarios WHERE id = ?', (tecnico_id,)).fetchone()
        comentario_texto += f", Técnico: {tecnico['nome']}"
    
    conn.execute('''
        INSERT INTO comentarios (chamado_id, usuario_id, comentario, tipo)
        VALUES (?, ?, ?, 'sistema')
    ''', (id, session['user_id'], comentario_texto))
    
    conn.commit()
    conn.close()
    
    log_auditoria('UPDATE', 'chamados', id, dict(chamado_anterior), f'Atribuição alterada: {comentario_texto}')
    flash('Chamado atribuído com sucesso!', 'success')
    return redirect(url_for('visualizar_chamado', id=id))

@app.route('/simular-atendimento', methods=['GET', 'POST'])
@login_required
@perfil_required('administrador', 'atendente')
def simular_atendimento():
    global simulacao_ativa
    
    if request.method == 'POST':
        acao = request.form['acao']
        
        if acao == 'iniciar':
            simulacao_ativa = True
            
            # Buscar chamados pendentes
            conn = get_db_connection()
            chamados_pendentes = conn.execute('''
                SELECT id, prioridade, estimativa_resolucao 
                FROM chamados 
                WHERE status IN ('aberto', 'em_triagem', 'em_atendimento')
                ORDER BY 
                    CASE prioridade 
                        WHEN 'alta' THEN 1 
                        WHEN 'media' THEN 2 
                        WHEN 'baixa' THEN 3 
                    END
            ''').fetchall()
            conn.close()
            
            # Iniciar threads de simulação
            for chamado in chamados_pendentes[:5]:  # Limitar a 5 chamados simultâneos
                if chamado['id'] not in atendimento_threads:
                    thread = threading.Thread(
                        target=simular_atendimento_thread,
                        args=(chamado['id'], chamado['estimativa_resolucao'] or 300)
                    )
                    thread.daemon = True
                    thread.start()
                    atendimento_threads[chamado['id']] = thread
            
            flash(f'Simulação iniciada com {len(chamados_pendentes[:5])} chamados em processamento!', 'success')
            log_auditoria('SIMULATION', 'chamados', None, None, 'Simulação de atendimento iniciada')
        
        elif acao == 'parar':
            simulacao_ativa = False
            atendimento_threads.clear()
            flash('Simulação de atendimento parada!', 'info')
            log_auditoria('SIMULATION', 'chamados', None, None, 'Simulação de atendimento parada')
    
    # Status da simulação
    conn = get_db_connection()
    chamados_em_processamento = conn.execute('''
        SELECT COUNT(*) as total FROM chamados 
        WHERE status IN ('em_atendimento', 'em_triagem')
    ''').fetchone()
    conn.close()
    
    status = {
        'ativa': simulacao_ativa,
        'threads_ativas': len(atendimento_threads),
        'chamados_processamento': chamados_em_processamento['total']
    }
    
    return render_template('simular_atendimento.html', status=status)

@app.route('/relatorios')
@login_required
@perfil_required('administrador', 'atendente')
def relatorios():
    conn = get_db_connection()
    
    # Relatório por status
    status_report = conn.execute('''
        SELECT status, COUNT(*) as total 
        FROM chamados 
        GROUP BY status
        ORDER BY total DESC
    ''').fetchall()
    
    # Relatório por prioridade
    prioridade_report = conn.execute('''
        SELECT prioridade, COUNT(*) as total 
        FROM chamados 
        GROUP BY prioridade
        ORDER BY 
            CASE prioridade 
                WHEN 'alta' THEN 1 
                WHEN 'media' THEN 2 
                WHEN 'baixa' THEN 3 
            END
    ''').fetchall()
    
    # Relatório por tipo de problema
    tipo_report = conn.execute('''
        SELECT tipo_problema, COUNT(*) as total 
        FROM chamados 
        GROUP BY tipo_problema
        ORDER BY total DESC
    ''').fetchall()
    
    # Performance dos atendentes
    performance = conn.execute('''
        SELECT u.nome, COUNT(c.id) as total_chamados,
               AVG(c.tempo_atendimento) as tempo_medio
        FROM usuarios u
        LEFT JOIN chamados c ON u.id = c.atendente_id
        WHERE u.perfil IN ('atendente', 'tecnico')
        GROUP BY u.id, u.nome
        ORDER BY total_chamados DESC
    ''').fetchall()
    
    # Chamados por dia (últimos 30 dias)
    chamados_diarios = conn.execute('''
        SELECT DATE(data_criacao) as data, COUNT(*) as total
        FROM chamados
        WHERE data_criacao >= datetime('now', '-30 days')
        GROUP BY DATE(data_criacao)
        ORDER BY data DESC
    ''').fetchall()
    
    conn.close()
    
    return render_template('relatorios.html', 
                         status_report=status_report,
                         prioridade_report=prioridade_report,
                         tipo_report=tipo_report,
                         performance=performance,
                         chamados_diarios=chamados_diarios)

@app.route('/logs-auditoria')
@login_required
@perfil_required('administrador')
def logs_auditoria_view():
    page = request.args.get('page', 1, type=int)
    per_page = 50
    
    filtro_usuario = request.args.get('usuario', '')
    filtro_acao = request.args.get('acao', '')
    filtro_tabela = request.args.get('tabela', '')
    
    conn = get_db_connection()
    
    # Query base
    where_conditions = []
    params = []
    
    if filtro_usuario:
        where_conditions.append('u.nome LIKE ?')
        params.append(f'%{filtro_usuario}%')
    
    if filtro_acao:
        where_conditions.append('l.acao = ?')
        params.append(filtro_acao)
    
    if filtro_tabela:
        where_conditions.append('l.tabela = ?')
        params.append(filtro_tabela)
    
    where_clause = ' AND '.join(where_conditions)
    if where_clause:
        where_clause = 'WHERE ' + where_clause
    
    # Buscar logs
    offset = (page - 1) * per_page
    logs = conn.execute(f'''
        SELECT l.*, u.nome as usuario_nome
        FROM logs_auditoria l
        LEFT JOIN usuarios u ON l.usuario_id = u.id
        {where_clause}
        ORDER BY l.data_criacao DESC
        LIMIT ? OFFSET ?
    ''', params + [per_page, offset]).fetchall()
    
    # Contar total para paginação
    total = conn.execute(f'''
        SELECT COUNT(*) as total
        FROM logs_auditoria l
        LEFT JOIN usuarios u ON l.usuario_id = u.id
        {where_clause}
    ''', params).fetchone()['total']
    
    # Opções para filtros
    acoes = conn.execute('SELECT DISTINCT acao FROM logs_auditoria ORDER BY acao').fetchall()
    tabelas = conn.execute('SELECT DISTINCT tabela FROM logs_auditoria ORDER BY tabela').fetchall()
    
    conn.close()
    
    # Paginação
    has_prev = page > 1
    has_next = offset + per_page < total
    prev_num = page - 1 if has_prev else None
    next_num = page + 1 if has_next else None
    
    return render_template('logs_auditoria.html', 
                         logs=logs,
                         acoes=acoes,
                         tabelas=tabelas,
                         filtros={
                             'usuario': filtro_usuario,
                             'acao': filtro_acao,
                             'tabela': filtro_tabela
                         },
                         pagination={
                             'page': page,
                             'has_prev': has_prev,
                             'has_next': has_next,
                             'prev_num': prev_num,
                             'next_num': next_num,
                             'total': total
                         })

@app.route('/usuarios')
@login_required
@perfil_required('administrador')
def gerenciar_usuarios():
    conn = get_db_connection()
    usuarios = conn.execute('''
        SELECT u.*, 
               COUNT(c.id) as total_chamados
        FROM usuarios u
        LEFT JOIN chamados c ON u.id = c.cliente_id
        GROUP BY u.id
        ORDER BY u.data_criacao DESC
    ''').fetchall()
    conn.close()
    
    return render_template('gerenciar_usuarios.html', usuarios=usuarios)

@app.route('/usuario/<int:id>/toggle-status', methods=['POST'])
@login_required
@perfil_required('administrador')
def toggle_usuario_status(id):
    conn = get_db_connection()
    
    usuario = conn.execute('SELECT * FROM usuarios WHERE id = ?', (id,)).fetchone()
    if not usuario:
        flash('Usuário não encontrado', 'error')
        conn.close()
        return redirect(url_for('gerenciar_usuarios'))
    
    novo_status = not usuario['ativo']
    conn.execute('UPDATE usuarios SET ativo = ? WHERE id = ?', (novo_status, id))
    conn.commit()
    conn.close()
    
    status_text = 'ativado' if novo_status else 'desativado'
    log_auditoria('UPDATE', 'usuarios', id, dict(usuario), f'Usuário {status_text}')
    flash(f'Usuário {status_text} com sucesso!', 'success')
    
    return redirect(url_for('gerenciar_usuarios'))

@app.route('/api/chamados-stats')
@login_required
def api_chamados_stats():
    conn = get_db_connection()
    
    # Dados para gráficos
    stats_por_dia = conn.execute('''
        SELECT DATE(data_criacao) as data, COUNT(*) as total
        FROM chamados
        WHERE data_criacao >= datetime('now', '-30 days')
        GROUP BY DATE(data_criacao)
        ORDER BY data ASC
    ''').fetchall()
    
    stats_por_status = conn.execute('''
        SELECT status, COUNT(*) as total
        FROM chamados
        GROUP BY status
    ''').fetchall()
    
    conn.close()
    
    return jsonify({
        'por_dia': [{'data': row['data'], 'total': row['total']} for row in stats_por_dia],
        'por_status': [{'status': row['status'], 'total': row['total']} for row in stats_por_status]
    })

@app.route('/logout')
@login_required
def logout():
    log_auditoria('LOGOUT', 'usuarios', session['user_id'], None, 'Logout realizado')
    session.clear()
    flash('Logout realizado com sucesso!', 'success')
    return redirect(url_for('index'))

# Garantir inicialização do banco (para gunicorn)
try:
    init_db()
except:
    pass  # Pode falhar se já inicializado



@app.template_filter('datetimeformat')
def datetimeformat(value, format='%d/%m/%Y às %H:%M'):
    """Filtro para formatar datetime de forma segura"""
    from datetime import datetime
    if isinstance(value, str):
        try:
            dt = datetime.strptime(value, '%Y-%m-%d %H:%M:%S')
            return dt.strftime(format)
        except:
            return value
    elif hasattr(value, 'strftime'):
        return value.strftime(format)
    return str(value)

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=8080, debug=True)






