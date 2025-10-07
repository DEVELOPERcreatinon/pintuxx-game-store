import os
import secrets
import sqlite3
import logging
import argon2
import hmac
import dotenv
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory, abort, Response
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from cryptography.fernet import Fernet
from werkzeug.utils import secure_filename
from functools import wraps
from dotenv import load_dotenv
from flask_cors import CORS



load_dotenv()

# Инициализация приложения
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 64 * 1024 * 1024  # 64MB
app.config['ALLOWED_EXTENSIONS'] = {'png', 'zip'}
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Инициализация систем безопасности
talisman = Talisman(
    app,
    content_security_policy={
        'default-src': "'self'",
        'script-src': ["'self'", "'unsafe-inline'"],
        'style-src': ["'self'", "'unsafe-inline'"],
        'img-src': ["'self'", "data:"]
    }
)

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["500 per day", "100 per hour"]
)

# Криптография
fernet = Fernet(os.environ.get('ENCRYPTION_KEY', Fernet.generate_key().decode('ascii')))
hmac_secret = os.environ.get('HMAC_SECRET', 'default_secret_change_me').encode('utf-8')
password_hasher = argon2.PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16
)

# Настройка логирования
security_logger = logging.getLogger('security')
security_logger.setLevel(logging.INFO)
file_handler = logging.FileHandler('security.log')
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
security_logger.addHandler(file_handler)

CORS(app, origins=["https://pintuxx.pythonanywhere.com", "http://localhost:3000"],
     supports_credentials=True)
# Глобальные функции безопасности
def log_security_event(event_type, details):
    """Логирование событий безопасности"""
    security_logger.info(f"{event_type}: {details}")
    # В продакшене: отправка в SIEM/ELK

def sanitize_input(input_str):
    """Очистка пользовательского ввода"""
    if not input_str:
        return ""
    # Удаление опасных конструкций
    cleaned = input_str.replace('<', '&lt;').replace('>', '&gt;')
    cleaned = cleaned.replace('"', '&quot;').replace("'", '&#x27;')
    # Удаление специальных символов
    cleaned = ''.join(c for c in cleaned if ord(c) < 128)
    return cleaned.strip()

def allowed_file(filename):
    """Проверка разрешенных расширений файлов"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def validate_file_upload(file):
    """Проверка загружаемых файлов по содержимому"""
    if not file or file.filename == '':
        return False

    # Проверка Magic Numbers
    magic_numbers = {
        b'\x89PNG\r\n\x1a\n': 'png',
        b'PK\x03\x04': 'zip'
    }

    file.seek(0)
    header = file.read(8)
    file.seek(0)
    print(f"File: {file.filename}, Header: {header}")

    for magic, ext in magic_numbers.items():
        if header.startswith(magic) and file.filename.endswith(f".{ext}"):
            return True

    return False

def generate_csrf_token():
    """Генерация CSRF токена"""
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(32)
    return session['_csrf_token']

app.jinja_env.globals['csrf_token'] = generate_csrf_token

# Защита от CSRF
@app.before_request
def csrf_protect():
    if request.method == "POST":
        token = session.pop('_csrf_token', None)
        if not token or not secrets.compare_digest(token, request.form.get('_csrf_token', '')):
            log_security_event("CSRF_ATTEMPT", f"IP: {request.remote_addr}, Path: {request.path}")
            abort(403)

# Контроль доступа
def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if role == 'admin' and not session.get('is_admin'):
                log_security_event("UNAUTHORIZED_ACCESS",
                                  f"User {session.get('username')} tried to access admin area")
                abort(403)
            if role == 'user' and 'user_id' not in session:
                flash('Please log in to access this page.')
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Работа с базой данных
def get_db():
    db = sqlite3.connect('bank.db')
    db.row_factory = sqlite3.Row
    # Включение foreign keys
    db.execute('PRAGMA foreign_keys = ON')
    return db

def safe_db_query(query, params=(), one=False, commit=False):
    """Безопасное выполнение SQL-запросов"""
    db = get_db()
    try:
        cur = db.execute(query, params)
        if commit:
            db.commit()
        rv = cur.fetchall()
        return (rv[0] if rv else None) if one else rv
    except sqlite3.Error as e:
        log_security_event("DB_ERROR", f"Query: {query} | Error: {str(e)}")
        db.rollback()
        abort(500)
    finally:
        db.close()

# Инициализация базы данных
def init_db():
    with app.app_context():
        db = get_db()

        # Включение WAL mode для атомарных транзакций
        db.execute('PRAGMA journal_mode=WAL')

        # Создание таблиц с улучшенными ограничениями
        db.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL CHECK(length(username) >= 3),
                password TEXT NOT NULL CHECK(length(password) > 8),
                balance REAL DEFAULT 0 CHECK(balance >= 0),
                is_admin BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                failed_attempts INTEGER DEFAULT 0,
                locked_until TIMESTAMP
            )
        ''')

        db.execute('''
            CREATE TABLE IF NOT EXISTS apps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL CHECK(length(name) >= 2),
                description TEXT NOT NULL CHECK(length(description) >= 10),
                price REAL NOT NULL CHECK(price >= 0),
                icon_path TEXT NOT NULL,
                file_path TEXT NOT NULL,
                file_hash TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                approved BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')

        db.execute('''
            CREATE TABLE IF NOT EXISTS purchases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                app_id INTEGER NOT NULL,
                purchase_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                FOREIGN KEY (app_id) REFERENCES apps (id) ON DELETE CASCADE
            )
        ''')

        db.execute('''
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                from_user_id INTEGER,
                to_user_id INTEGER NOT NULL,
                amount REAL NOT NULL CHECK(amount > 0),
                app_id INTEGER,
                transaction_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (from_user_id) REFERENCES users (id) ON DELETE SET NULL,
                FOREIGN KEY (to_user_id) REFERENCES users (id) ON DELETE CASCADE,
                FOREIGN KEY (app_id) REFERENCES apps (id) ON DELETE SET NULL
            )
        ''')

        db.execute('''
            CREATE TABLE IF NOT EXISTS reviews (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                app_id INTEGER NOT NULL,
                rating INTEGER NOT NULL CHECK (rating >= 1 AND rating <= 10),
                comment TEXT,
                review_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                FOREIGN KEY (app_id) REFERENCES apps (id) ON DELETE CASCADE,
                UNIQUE(user_id, app_id)
            )
        ''')

        db.execute('''
            CREATE TABLE IF NOT EXISTS security_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                details TEXT NOT NULL,
                ip_address TEXT,
                user_id INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
# В функции init_db() добавить:
        db.execute('''
            CREATE TABLE IF NOT EXISTS api_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')

        db.execute('''
            CREATE TABLE IF NOT EXISTS client_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                session_id TEXT UNIQUE NOT NULL,
                client_info TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')
        # Создание администратора
        admin_exists = db.execute(
            "SELECT 1 FROM users WHERE username = 'adminOFFICIAL'"
        ).fetchone()

        if not admin_exists:
            admin_pass = os.getenv("ADMIN_PASS")
            db.execute(
                "INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)",
                ('adminOFFICIAL', password_hasher.hash(admin_pass), True)
            )
            security_logger.info("Admin user created")

        db.commit()

# Маршруты аутентификации
@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("10 per hour")
def register():
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username', ''))
        password = request.form.get('password', '')

        if len(username) < 3 or len(password) < 10:
            flash('Username must be at least 3 characters and password at least 10 characters')
            return redirect(url_for('register'))

        try:
            hashed_pw = password_hasher.hash(password)
            safe_db_query(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, hashed_pw),
                commit=True
            )
            flash('Registration successful! Please log in.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already taken!')
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username', ''))
        password = request.form.get('password', '')

        user = safe_db_query(
            "SELECT * FROM users WHERE username = ?",
            (username,),
            one=True
        )

        if not user:
            log_security_event("LOGIN_FAIL", f"Unknown user: {username}")
            flash('Invalid username or password')
            return redirect(url_for('login'))

        # Проверка блокировки аккаунта
        if user['locked_until'] and datetime.fromisoformat(user['locked_until']) > datetime.now():
            flash('Account temporarily locked. Try again later.')
            return redirect(url_for('login'))

        try:
            if password_hasher.verify(user['password'], password):
                # Сброс счетчика неудачных попыток
                safe_db_query(
                    "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
                    (user['id'],),
                    commit=True
                )

                # Обновление сессии
                session.clear()
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['is_admin'] = bool(user['is_admin'])
                session['balance'] = user['balance']
                session['_fresh'] = True

                # Обновление времени последнего входа
                safe_db_query(
                    "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?",
                    (user['id'],),
                    commit=True
                )

                log_security_event("LOGIN_SUCCESS", f"User: {username}")
                return redirect(url_for('index'))
        except argon2.exceptions.VerifyMismatchError:
            pass

        # Увеличение счетчика неудачных попыток
        new_attempts = user['failed_attempts'] + 1
        if new_attempts >= 5:
            lock_time = datetime.now() + timedelta(minutes=15)
            safe_db_query(
                "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                (new_attempts, lock_time.isoformat(), user['id']),
                commit=True
            )
            log_security_event("ACCOUNT_LOCKED", f"User: {username}, IP: {request.remote_addr}")
            flash('Too many failed attempts. Account locked for 15 minutes.')
        else:
            safe_db_query(
                "UPDATE users SET failed_attempts = ? WHERE id = ?",
                (new_attempts, user['id']),
                commit=True
            )
            flash('Invalid username or password')

        return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/logout')
@role_required('user')
def logout():
    log_security_event("LOGOUT", f"User: {session['username']}")
    session.clear()
    flash('You have been logged out.')
    return redirect(url_for('index'))

# Маршруты для работы с приложениями
@app.route('/upload', methods=['GET', 'POST'])
@role_required('user')
def upload_app():
    if request.method == 'POST':
        # Валидация ввода
        name = sanitize_input(request.form.get('name', ''))
        description = sanitize_input(request.form.get('description', ''))

        try:
            price = float(request.form.get('price', 0))
            if price < 0:
                raise ValueError
        except ValueError:
            flash('Invalid price!')
            return redirect(url_for('upload_app'))

        # Валидация файлов
        icon = request.files.get('icon')
        app_file = request.files.get('app_file')

        if not icon or not app_file or icon.filename == '' or app_file.filename == '':
            flash('Both icon and app file are required!')
            return redirect(url_for('upload_app'))

        if not validate_file_upload(icon) or not validate_file_upload(app_file):
            flash('Invalid file content!')
            return redirect(url_for('upload_app'))

        # Сохранение файлов
        icon_filename = secure_filename(f"{secrets.token_hex(8)}.png")
        app_filename = secure_filename(f"{secrets.token_hex(8)}.zip")

        icon_path = os.path.join(app.config['UPLOAD_FOLDER'], icon_filename)
        app_path = os.path.join(app.config['UPLOAD_FOLDER'], app_filename)

        icon.save(icon_path)
        app_file.save(app_path)

        # Расчет хешей для проверки целостности
        icon_hash = hmac.new(hmac_secret, open(icon_path, 'rb').read(), 'sha256').hexdigest()
        app_hash = hmac.new(hmac_secret, open(app_path, 'rb').read(), 'sha256').hexdigest()

        # Сохранение в базу данных
        safe_db_query(
            '''INSERT INTO apps
            (name, description, price, icon_path, file_path, file_hash, user_id, approved)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
            (name, description, price, icon_filename, app_filename, app_hash,
             session['user_id'], bool(session.get('is_admin'))),
            commit=True
        )

        flash('App uploaded successfully!' + (' It will be visible after admin approval.' if not session.get('is_admin') else ''))
        return redirect(url_for('index'))

    return render_template('upload.html')

# Главная страница
@app.route('/')
def index():
    if is_admin():
        apps = safe_db_query("SELECT * FROM apps")
    else:
        apps = safe_db_query("SELECT * FROM apps WHERE approved = TRUE")
    return render_template('index.html', apps=apps)

# Страница приложения
@app.route('/app/<int:app_id>')
def app_details(app_id):
    app_data = safe_db_query('''
        SELECT apps.*, users.username
        FROM apps
        JOIN users ON apps.user_id = users.id
        WHERE apps.id = ?
    ''', (app_id,), one=True)

    if not app_data:
        abort(404)

    # Проверка прав доступа
    if not app_data['approved'] and not (is_admin() or ('user_id' in session and session['user_id'] == app_data['user_id'])):
        log_security_event("UNAUTHORIZED_ACCESS",
                          f"User {session.get('username', 'anonymous')} tried to access unapproved app {app_id}")
        abort(403)

    # Проверка владения приложением
    owned = False
    user_review = None
    if 'user_id' in session:
        purchase = safe_db_query(
            'SELECT * FROM purchases WHERE user_id = ? AND app_id = ?',
            (session['user_id'], app_id),
            one=True
        )
        owned = purchase is not None

        if owned:
            user_review = safe_db_query('''
                SELECT r.*, u.username
                FROM reviews r
                JOIN users u ON r.user_id = u.id
                WHERE r.app_id = ? AND r.user_id = ?
            ''', (app_id, session['user_id']), one=True)

    # Отзывы других пользователей
    other_reviews = safe_db_query('''
        SELECT r.*, u.username
        FROM reviews r
        JOIN users u ON r.user_id = u.id
        WHERE r.app_id = ? AND (r.user_id != ? OR ? IS NULL)
        ORDER BY r.review_date DESC
        LIMIT 10
    ''', (app_id, session.get('user_id'), session.get('user_id')))

    # Средний рейтинг
    avg_rating = safe_db_query('''
        SELECT AVG(rating) as avg_rating, COUNT(*) as review_count
        FROM reviews
        WHERE app_id = ?
    ''', (app_id,), one=True)

    average_rating = avg_rating['avg_rating'] if avg_rating and avg_rating['review_count'] > 0 else 0

    return render_template('app.html',
                         app=app_data,
                         owned=owned,
                         user_review=user_review,
                         other_reviews=other_reviews,
                         average_rating=average_rating)

# Покупка приложения
@app.route('/buy/<int:app_id>')
@role_required('user')
def buy_app(app_id):
    # Проверка, не куплено ли уже приложение
    purchase = safe_db_query(
        'SELECT * FROM purchases WHERE user_id = ? AND app_id = ?',
        (session['user_id'], app_id),
        one=True
    )
    if purchase:
        flash('You already own this app!')
        return redirect(url_for('app_details', app_id=app_id))

    app_data = safe_db_query('SELECT * FROM apps WHERE id = ?', (app_id,), one=True)

    if not app_data or not app_data['approved']:
        abort(404)

    if session['balance'] < app_data['price']:
        flash('Insufficient balance!')
        return redirect(url_for('app_details', app_id=app_id))

    # Проверка бизнес-логики
    if not validate_transaction(session['user_id'], app_data['price']):
        flash('Transaction limit exceeded. Please try again later.')
        return redirect(url_for('app_details', app_id=app_id))

    # Обработка транзакции
    try:
        # Списание средств у покупателя
        safe_db_query(
            'UPDATE users SET balance = balance - ? WHERE id = ?',
            (app_data['price'], session['user_id']),
            commit=True
        )

        # Зачисление средств разработчику (минус 10% комиссия)
        platform_fee = app_data['price'] * 0.1
        developer_receives = app_data['price'] - platform_fee

        safe_db_query(
            'UPDATE users SET balance = balance + ? WHERE id = ?',
            (developer_receives, app_data['user_id']),
            commit=True
        )

        # Запись транзакции
        safe_db_query(
            'INSERT INTO transactions (from_user_id, to_user_id, amount, app_id) VALUES (?, ?, ?, ?)',
            (session['user_id'], app_data['user_id'], developer_receives, app_id),
            commit=True
        )

        # Запись покупки
        safe_db_query(
            'INSERT INTO purchases (user_id, app_id) VALUES (?, ?)',
            (session['user_id'], app_id),
            commit=True
        )

        # Обновление баланса в сессии
        session['balance'] -= app_data['price']

        log_security_event("PURCHASE_SUCCESS",
                          f"User {session['username']} purchased app {app_id}")
        flash('Purchase successful!')
    except Exception as e:
        log_security_event("PURCHASE_FAILED",
                          f"User {session['username']} failed to purchase app {app_id}: {str(e)}")
        flash('Transaction failed! Please contact support.')

    return redirect(url_for('app_details', app_id=app_id))

# Транзакции пользователя
@app.route('/transactions')
@role_required('user')
def transactions():
    user_transactions = safe_db_query('''
        SELECT t.*,
               u1.username as from_username,
               u2.username as to_username,
               a.name as app_name
        FROM transactions t
        LEFT JOIN users u1 ON t.from_user_id = u1.id
        LEFT JOIN users u2 ON t.to_user_id = u2.id
        LEFT JOIN apps a ON t.app_id = a.id
        WHERE t.from_user_id = ? OR t.to_user_id = ?
        ORDER BY t.transaction_date DESC
    ''', (session['user_id'], session['user_id']))

    return render_template('transactions.html', transactions=user_transactions)

# Загрузка приложения

# Библиотека пользователя
@app.route('/library')
@role_required('user')
def user_library():
    purchases = safe_db_query('''
        SELECT p.*, a.id as app_id, a.name, a.icon_path, a.price,
               r.id as review_id, r.rating
        FROM purchases p
        JOIN apps a ON p.app_id = a.id
        LEFT JOIN reviews r ON r.app_id = a.id AND r.user_id = ?
        WHERE p.user_id = ?
        ORDER BY p.purchase_date DESC
    ''', (session['user_id'], session['user_id']))

    return render_template('library.html', purchases=purchases)

# Админ-панель
@app.route('/admin')
@role_required('admin')
def admin_panel():
    stats = {
        'user_count': safe_db_query('SELECT COUNT(*) FROM users', one=True)[0],
        'app_count': safe_db_query('SELECT COUNT(*) FROM apps', one=True)[0],
        'transaction_count': safe_db_query('SELECT COUNT(*) FROM transactions', one=True)[0],
        'review_count': safe_db_query('SELECT COUNT(*) FROM reviews', one=True)[0]
    }

    users = safe_db_query('''
        SELECT u.*, COUNT(a.id) as app_count
        FROM users u
        LEFT JOIN apps a ON a.user_id = u.id
        GROUP BY u.id
        ORDER BY u.id
    ''')

    pending_apps = safe_db_query('''
        SELECT apps.*, users.username
        FROM apps
        JOIN users ON apps.user_id = users.id
        WHERE approved = FALSE
        ORDER BY apps.id DESC
    ''')

    recent_reviews = safe_db_query('''
        SELECT r.*, u.username, a.name as app_name, a.id as app_id
        FROM reviews r
        JOIN users u ON r.user_id = u.id
        JOIN apps a ON r.app_id = a.id
        ORDER BY r.review_date DESC
        LIMIT 20
    ''')

    recent_transactions = safe_db_query('''
        SELECT t.*,
               u1.username as from_username,
               u2.username as to_username,
               a.name as app_name,
               a.id as app_id
        FROM transactions t
        LEFT JOIN users u1 ON t.from_user_id = u1.id
        JOIN users u2 ON t.to_user_id = u2.id
        LEFT JOIN apps a ON t.app_id = a.id
        ORDER BY t.transaction_date DESC
        LIMIT 20
    ''')

    return render_template('admin.html',
                         stats=stats,
                         users=users,
                         pending_apps=pending_apps,
                         recent_reviews=recent_reviews,
                         recent_transactions=recent_transactions)

# Админские операции
@app.route('/admin/toggle_admin/<int:user_id>')
@role_required('admin')
def toggle_admin(user_id):
    if user_id == session['user_id']:
        flash('You cannot change your own admin status!')
        return redirect(url_for('admin_panel'))

    user = safe_db_query('SELECT * FROM users WHERE id = ?', (user_id,), one=True)

    if not user:
        abort(404)

    new_status = not bool(user['is_admin'])
    safe_db_query(
        'UPDATE users SET is_admin = ? WHERE id = ?',
        (new_status, user_id),
        commit=True
    )

    log_security_event("ADMIN_STATUS_CHANGE",
                      f"Admin status for user {user['username']} changed to {new_status}")
    flash(f'User {"promoted to admin" if new_status else "demoted from admin"} successfully!')
    return redirect(url_for('admin_panel'))

@app.route('/admin/delete_review/<int:review_id>')
@role_required('admin')
def delete_review_admin(review_id):
    review = safe_db_query('SELECT * FROM reviews WHERE id = ?', (review_id,), one=True)

    if not review:
        abort(404)

    safe_db_query(
        'DELETE FROM reviews WHERE id = ?',
        (review_id,),
        commit=True
    )

    log_security_event("REVIEW_DELETED",
                      f"Admin deleted review {review_id} by user {review['user_id']}")
    flash('Review deleted successfully!')
    return redirect(url_for('admin_panel'))

@app.route('/admin/approve/<int:app_id>')
@role_required('admin')
def approve_app(app_id):
    safe_db_query(
        'UPDATE apps SET approved = TRUE WHERE id = ?',
        (app_id,),
        commit=True
    )

    log_security_event("APP_APPROVED", f"Admin approved app {app_id}")
    flash('App approved successfully!')
    return redirect(url_for('admin_panel'))

@app.route('/admin/reject/<int:app_id>')
@role_required('admin')
def reject_app(app_id):
    app_data = safe_db_query('SELECT * FROM apps WHERE id = ?', (app_id,), one=True)

    if app_data:
        try:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], app_data['icon_path']))
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], app_data['file_path']))
        except OSError as e:
            log_security_event("FILE_DELETE_ERROR",
                              f"Error deleting files for app {app_id}: {str(e)}")

    safe_db_query(
        'DELETE FROM apps WHERE id = ?',
        (app_id,),
        commit=True
    )

    log_security_event("APP_REJECTED", f"Admin rejected app {app_id}")
    flash('App rejected and deleted!')
    return redirect(url_for('admin_panel'))

@app.route('/admin/update_balance', methods=['POST'])
@role_required('admin')
def update_balance():
    user_id = request.form['user_id']
    try:
        new_balance = float(request.form['balance'])
        if new_balance < 0:
            raise ValueError
    except ValueError:
        flash('Invalid balance value!')
        return redirect(url_for('admin_panel'))

    safe_db_query(
        'UPDATE users SET balance = ? WHERE id = ?',
        (new_balance, user_id),
        commit=True
    )

    # Обновление сессии, если это текущий пользователь
    if 'user_id' in session and session['user_id'] == int(user_id):
        session['balance'] = new_balance

    log_security_event("BALANCE_UPDATE",
                      f"Admin updated balance for user {user_id} to {new_balance}")
    flash('Balance updated successfully!')
    return redirect(url_for('admin_panel'))

@app.route('/admin/delete_user/<int:user_id>')
@role_required('admin')
def delete_user(user_id):
    if user_id == session['user_id']:
        flash('You cannot delete your own account!')
        return redirect(url_for('admin_panel'))

    # Удаление приложений пользователя
    user_apps = safe_db_query('SELECT * FROM apps WHERE user_id = ?', (user_id,))
    for app in user_apps:
        try:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], app['icon_path']))
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], app['file_path']))
        except OSError as e:
            log_security_event("FILE_DELETE_ERROR",
                              f"Error deleting files for app {app['id']}: {str(e)}")

    # Удаление из базы данных
    safe_db_query('DELETE FROM apps WHERE user_id = ?', (user_id,), commit=True)
    safe_db_query('DELETE FROM purchases WHERE user_id = ?', (user_id,), commit=True)
    safe_db_query('DELETE FROM users WHERE id = ?', (user_id,), commit=True)

    log_security_event("USER_DELETED", f"Admin deleted user {user_id}")
    flash('User deleted successfully!')
    return redirect(url_for('admin_panel'))

# Работа с отзывами
@app.route('/app/<int:app_id>/review/add', methods=['GET', 'POST'])
@role_required('user')
def add_review(app_id):
    # Проверка владения приложением
    purchase = safe_db_query(
        'SELECT * FROM purchases WHERE user_id = ? AND app_id = ?',
        (session['user_id'], app_id),
        one=True
    )
    if not purchase:
        flash('You need to purchase this app before reviewing.')
        return redirect(url_for('app_details', app_id=app_id))

    # Проверка существующего отзыва
    existing_review = safe_db_query(
        'SELECT * FROM reviews WHERE user_id = ? AND app_id = ?',
        (session['user_id'], app_id),
        one=True
    )
    if existing_review:
        return redirect(url_for('edit_review', review_id=existing_review['id']))

    app_data = safe_db_query('SELECT * FROM apps WHERE id = ?', (app_id,), one=True)

    if request.method == 'POST':
        try:
            rating = int(request.form['rating'])
            if rating < 1 or rating > 10:
                raise ValueError
        except ValueError:
            flash('Rating must be between 1 and 10!')
            return redirect(url_for('add_review', app_id=app_id))

        comment = sanitize_input(request.form.get('comment', ''))

        safe_db_query(
            'INSERT INTO reviews (user_id, app_id, rating, comment) VALUES (?, ?, ?, ?)',
            (session['user_id'], app_id, rating, comment),
            commit=True
        )

        log_security_event("REVIEW_ADDED",
                          f"User {session['username']} added review for app {app_id}")
        flash('Review added successfully!')
        return redirect(url_for('app_details', app_id=app_id))

    return render_template('review_form.html', app=app_data)

@app.route('/review/<int:review_id>/edit', methods=['GET', 'POST'])
@role_required('user')
def edit_review(review_id):
    review = safe_db_query('SELECT * FROM reviews WHERE id = ?', (review_id,), one=True)

    if not review or review['user_id'] != session['user_id']:
        abort(403)

    app_data = safe_db_query('SELECT * FROM apps WHERE id = ?', (review['app_id'],), one=True)

    if request.method == 'POST':
        try:
            rating = int(request.form['rating'])
            if rating < 1 or rating > 10:
                raise ValueError
        except ValueError:
            flash('Rating must be between 1 and 10!')
            return redirect(url_for('edit_review', review_id=review_id))

        comment = sanitize_input(request.form.get('comment', ''))

        safe_db_query(
            'UPDATE reviews SET rating = ?, comment = ? WHERE id = ?',
            (rating, comment, review_id),
            commit=True
        )

        log_security_event("REVIEW_UPDATED",
                          f"User {session['username']} updated review {review_id}")
        flash('Review updated successfully!')
        return redirect(url_for('app_details', app_id=review['app_id']))

    return render_template('review_form.html', app=app_data, review=review)

@app.route('/review/<int:review_id>/delete')
@role_required('user')
def delete_review(review_id):
    review = safe_db_query('SELECT * FROM reviews WHERE id = ?', (review_id,), one=True)

    if not review or review['user_id'] != session['user_id']:
        abort(403)

    app_id = review['app_id']
    safe_db_query(
        'DELETE FROM reviews WHERE id = ?',
        (review_id,),
        commit=True
    )

    log_security_event("REVIEW_DELETED",
                      f"User {session['username']} deleted review {review_id}")
    flash('Review deleted successfully!')
    return redirect(url_for('app_details', app_id=app_id))

# Вспомогательные функции
def is_admin():
    return session.get('is_admin', False)

def validate_transaction(user_id, amount):
    """Проверка бизнес-логики транзакции"""
    if amount <= 0:
        return False
    if amount > 10000:  # Лимит на одну операцию
        return False

    # Проверка частоты операций
    recent_tx_count = safe_db_query(
        "SELECT COUNT(*) FROM transactions WHERE from_user_id = ? AND transaction_date > datetime('now', '-1 hour')",
        (user_id,),
        one=True
    )[0]

    return recent_tx_count < 5

def verify_file_integrity(file_path):
    """Проверка целостности файла"""
    full_path = os.path.join(app.config['UPLOAD_FOLDER'], file_path)

    if not os.path.exists(full_path):
        return False

    # Получение сохраненного хеша
    stored_hash = safe_db_query(
        "SELECT file_hash FROM apps WHERE file_path = ?",
        (file_path,),
        one=True
    )

    if not stored_hash:
        return False

    # Расчет текущего хеша
    with open(full_path, 'rb') as f:
        file_data = f.read()

    current_hash = hmac.new(
        hmac_secret,
        file_data,
        'sha256'
    ).hexdigest()

    return secrets.compare_digest(stored_hash['file_hash'], current_hash)

# Статические страницы
@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

@app.route('/terms')
def terms():
    return render_template('terms.html')

# Предупреждение для пользователей
DISCLAIMER = """
ВНИМАНИЕ:
1. Сервис является учебным проектом
2. Не используйте реальные платежные данные
3. Все транзакции фиктивные
"""

@app.before_request
def show_warning():
    if request.path in ('/register', '/login'):
        flash(DISCLAIMER, 'warning')


@app.route('/sitemap.xml')
def sitemap():
    try:
        with open('static/sitemap.xml', 'r') as f:
            xml_content = f.read()
        return Response(xml_content, mimetype='application/xml')
    except FileNotFoundError:
        abort(404)

# Модифицировать существующий маршрут download_app
@app.route('/download/<int:app_id>')
@role_required('user')
def download_app(app_id):
    """Скачивание приложения с улучшенной проверкой"""
    try:
        app_data = safe_db_query('SELECT * FROM apps WHERE id = ?', (app_id,), one=True)

        if not app_data:
            abort(404)

        # Проверка прав доступа
        if app_data['price'] > 0:
            purchase = safe_db_query(
                'SELECT * FROM purchases WHERE user_id = ? AND app_id = ?',
                (session['user_id'], app_id),
                one=True
            )
            if not purchase and not (is_admin() or session['user_id'] == app_data['user_id']):
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return jsonify({'success': False, 'error': 'Purchase required'}), 403
                flash('Please purchase this app before downloading!')
                return redirect(url_for('app_details', app_id=app_id))

        # Проверка целостности файла
        if not verify_file_integrity(app_data['file_path']):
            log_security_event("FILE_TAMPERED", f"File {app_data['file_path']} for app {app_id} has been tampered with")
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'success': False, 'error': 'File integrity check failed'}), 500
            abort(500)

        # Логирование скачивания
        log_security_event("FILE_DOWNLOAD",
                          f"User {session['username']} downloaded app {app_id}")

        # Для API запросов возвращаем URL
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            download_url = url_for('static', filename=f'uploads/{app_data["file_path"]}', _external=True)
            return jsonify({'success': True, 'download_url': download_url})

        # Для обычных запросов - файл
        return send_from_directory(
            app.config['UPLOAD_FOLDER'],
            app_data['file_path'],
            as_attachment=True,
            download_name=f"{app_data['name']}.zip"
        )

    except Exception as e:
        log_security_event("DOWNLOAD_ERROR", f"Download error for app {app_id}: {str(e)}")
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'error': 'Download failed'}), 500
        abort(500)

# Добавить после существующих маршрутов аутентификации
@app.route('/api/login', methods=['POST'])
@limiter.limit("10 per minute")
def api_login():
    """API для входа в систему"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'Invalid JSON'}), 400

        username = sanitize_input(data.get('username', ''))
        password = data.get('password', '')

        if not username or not password:
            return jsonify({'success': False, 'error': 'Username and password required'}), 400

        user = safe_db_query(
            "SELECT * FROM users WHERE username = ?",
            (username,),
            one=True
        )

        if not user:
            log_security_event("API_LOGIN_FAIL", f"Unknown user: {username}")
            return jsonify({'success': False, 'error': 'Invalid credentials'}), 401

        # Проверка блокировки аккаунта
        if user['locked_until'] and datetime.fromisoformat(user['locked_until']) > datetime.now():
            return jsonify({'success': False, 'error': 'Account temporarily locked'}), 403

        try:
            if password_hasher.verify(user['password'], password):
                # Сброс счетчика неудачных попыток
                safe_db_query(
                    "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
                    (user['id'],),
                    commit=True
                )

                # Создание сессии
                session.clear()
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['is_admin'] = bool(user['is_admin'])
                session['balance'] = user['balance']
                session['_fresh'] = True

                # Обновление времени последнего входа
                safe_db_query(
                    "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?",
                    (user['id'],),
                    commit=True
                )

                log_security_event("API_LOGIN_SUCCESS", f"User: {username}")
                return jsonify({
                    'success': True,
                    'user': {
                        'id': user['id'],
                        'username': user['username'],
                        'balance': float(user['balance']),
                        'is_admin': bool(user['is_admin'])
                    }
                })
        except argon2.exceptions.VerifyMismatchError:
            pass

        # Увеличение счетчика неудачных попыток
        new_attempts = user['failed_attempts'] + 1
        if new_attempts >= 5:
            lock_time = datetime.now() + timedelta(minutes=15)
            safe_db_query(
                "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                (new_attempts, lock_time.isoformat(), user['id']),
                commit=True
            )
            log_security_event("API_ACCOUNT_LOCKED", f"User: {username}")
            return jsonify({'success': False, 'error': 'Account locked'}), 403
        else:
            safe_db_query(
                "UPDATE users SET failed_attempts = ? WHERE id = ?",
                (new_attempts, user['id']),
                commit=True
            )
            return jsonify({'success': False, 'error': 'Invalid credentials'}), 401

    except Exception as e:
        log_security_event("API_LOGIN_ERROR", f"Login error: {str(e)}")
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.route('/api/logout', methods=['POST'])
def api_logout():
    """API для выхода из системы"""
    try:
        log_security_event("API_LOGOUT", f"User: {session.get('username')}")
        session.clear()
        return jsonify({'success': True, 'message': 'Logged out successfully'})

    except Exception as e:
        log_security_event("API_LOGOUT_ERROR", f"Logout error: {str(e)}")
        return jsonify({'success': False, 'error': 'Logout failed'}), 500

# Добавить после существующих маршрутов
# API Routes
@app.route('/api/games', methods=['GET'])
def api_games():
    """API для получения списка игр"""
    try:
        if is_admin():
            games = safe_db_query("SELECT * FROM apps")
        else:
            games = safe_db_query("SELECT * FROM apps WHERE approved = TRUE")

        games_list = []
        for game in games:
            games_list.append({
                'id': game['id'],
                'name': game['name'],
                'description': game['description'],
                'price': float(game['price']),
                'icon_url': url_for('static', filename=f'uploads/{game["icon_path"]}', _external=True),
                'rating': get_average_rating(game['id']),
                'download_url': url_for('download_app', app_id=game['id'], _external=True)
            })

        return jsonify({'success': True, 'games': games_list})

    except Exception as e:
        log_security_event("API_ERROR", f"API games error: {str(e)}")
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.route('/api/game/<int:app_id>', methods=['GET'])
def api_game_details(app_id):
    """API для получения деталей игры"""
    try:
        app_data = safe_db_query('''
            SELECT apps.*, users.username
            FROM apps
            JOIN users ON apps.user_id = users.id
            WHERE apps.id = ?
        ''', (app_id,), one=True)

        if not app_data:
            return jsonify({'success': False, 'error': 'Game not found'}), 404

        # Проверка прав доступа
        if not app_data['approved'] and not (is_admin() or ('user_id' in session and session['user_id'] == app_data['user_id'])):
            return jsonify({'success': False, 'error': 'Access denied'}), 403

        game_details = {
            'id': app_data['id'],
            'name': app_data['name'],
            'description': app_data['description'],
            'price': float(app_data['price']),
            'icon_url': url_for('static', filename=f'uploads/{app_data["icon_path"]}', _external=True),
            'developer': app_data['username'],
            'rating': get_average_rating(app_id),
            'download_url': url_for('download_app', app_id=app_id, _external=True),
            'created_at': app_data['created_at'],
            'approved': bool(app_data['approved'])
        }

        return jsonify({'success': True, 'game': game_details})

    except Exception as e:
        log_security_event("API_ERROR", f"API game details error: {str(e)}")
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.route('/api/user/library', methods=['GET'])
@role_required('user')
def api_user_library():
    """API для получения библиотеки пользователя"""
    try:
        purchases = safe_db_query('''
            SELECT p.*, a.id as app_id, a.name, a.icon_path, a.price, a.description
            FROM purchases p
            JOIN apps a ON p.app_id = a.id
            WHERE p.user_id = ?
            ORDER BY p.purchase_date DESC
        ''', (session['user_id'],))

        library = []
        for purchase in purchases:
            library.append({
                'id': purchase['app_id'],
                'name': purchase['name'],
                'description': purchase['description'],
                'price': float(purchase['price']),
                'icon_url': url_for('static', filename=f'uploads/{purchase["icon_path"]}', _external=True),
                'purchase_date': purchase['purchase_date'],
                'download_url': url_for('download_app', app_id=purchase['app_id'], _external=True)
            })

        return jsonify({'success': True, 'library': library})

    except Exception as e:
        log_security_event("API_ERROR", f"API library error: {str(e)}")
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.route('/api/user/profile', methods=['GET'])
@role_required('user')
def api_user_profile():
    """API для получения профиля пользователя"""
    try:
        user = safe_db_query(
            "SELECT * FROM users WHERE id = ?",
            (session['user_id'],),
            one=True
        )

        if not user:
            return jsonify({'success': False, 'error': 'User not found'}), 404

        profile = {
            'id': user['id'],
            'username': user['username'],
            'balance': float(user['balance']),
            'is_admin': bool(user['is_admin']),
            'created_at': user['created_at'],
            'last_login': user['last_login']
        }

        return jsonify({'success': True, 'profile': profile})

    except Exception as e:
        log_security_event("API_ERROR", f"API profile error: {str(e)}")
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.route('/api/purchase/<int:app_id>', methods=['POST'])
@role_required('user')
def api_purchase_game(app_id):
    """API для покупки игры"""
    try:
        # Проверка, не куплено ли уже приложение
        purchase = safe_db_query(
            'SELECT * FROM purchases WHERE user_id = ? AND app_id = ?',
            (session['user_id'], app_id),
            one=True
        )
        if purchase:
            return jsonify({'success': False, 'error': 'Already purchased'}), 400

        app_data = safe_db_query('SELECT * FROM apps WHERE id = ?', (app_id,), one=True)

        if not app_data or not app_data['approved']:
            return jsonify({'success': False, 'error': 'Game not found'}), 404

        if session['balance'] < app_data['price']:
            return jsonify({'success': False, 'error': 'Insufficient balance'}), 400

        # Проверка бизнес-логики
        if not validate_transaction(session['user_id'], app_data['price']):
            return jsonify({'success': False, 'error': 'Transaction limit exceeded'}), 400

        # Обработка транзакции
        safe_db_query(
            'UPDATE users SET balance = balance - ? WHERE id = ?',
            (app_data['price'], session['user_id']),
            commit=True
        )

        # Зачисление средств разработчику (минус 10% комиссия)
        platform_fee = app_data['price'] * 0.1
        developer_receives = app_data['price'] - platform_fee

        safe_db_query(
            'UPDATE users SET balance = balance + ? WHERE id = ?',
            (developer_receives, app_data['user_id']),
            commit=True
        )

        # Запись транзакции
        safe_db_query(
            'INSERT INTO transactions (from_user_id, to_user_id, amount, app_id) VALUES (?, ?, ?, ?)',
            (session['user_id'], app_data['user_id'], developer_receives, app_id),
            commit=True
        )

        # Запись покупки
        safe_db_query(
            'INSERT INTO purchases (user_id, app_id) VALUES (?, ?)',
            (session['user_id'], app_id),
            commit=True
        )

        # Обновление баланса в сессии
        session['balance'] -= app_data['price']

        log_security_event("API_PURCHASE_SUCCESS", f"User {session['username']} purchased app {app_id}")
        return jsonify({'success': True, 'message': 'Purchase successful'})

    except Exception as e:
        log_security_event("API_PURCHASE_ERROR", f"Purchase error: {str(e)}")
        return jsonify({'success': False, 'error': 'Purchase failed'}), 500

# Вспомогательные функции для API
def get_average_rating(app_id):
    """Получение среднего рейтинга игры"""
    avg_rating = safe_db_query('''
        SELECT AVG(rating) as avg_rating, COUNT(*) as review_count
        FROM reviews
        WHERE app_id = ?
    ''', (app_id,), one=True)

    return float(avg_rating['avg_rating']) if avg_rating and avg_rating['review_count'] > 0 else 0.0



























# Запуск приложения
if __name__ == '__main__':
    # Создание необходимых директорий
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    # Инициализация БД
    init_db()

    # Проверка зависимостей (в реальном проекте использовать pip-audit)

    # Запуск с TLS
    """ssl_context = None
    if os.path.exists('cert.pem') and os.path.exists('key.pem'):
        ssl_context = ('cert.pem', 'key.pem')"""

    app.run(
        host='0.0.0.0',
        port=6174,
#        ssl_context="adhoc", #ssl_context,
        debug=False
    )