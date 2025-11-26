import os
import re
import json
import secrets
import string
import time
import base64
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import jwt

app = Flask(__name__, static_folder='../client/dist', static_url_path='')
CORS(app, resources={r"/api/*": {"origins": "*"}})

DATA_DIR = os.environ.get('DATA_DIR', 'data')
KEY_FILE = os.path.join(DATA_DIR, "master.key.encrypted")
SALT_FILE = os.path.join(DATA_DIR, "salt.salt")
PASSWORDS_FILE = os.path.join(DATA_DIR, "vault.dat")

JWT_SECRET = os.environ.get('JWT_SECRET', secrets.token_hex(32))
JWT_EXPIRY_MINUTES = 30
AUTO_LOCK_MINUTES = 5
DEFAULT_PASSWORD_LENGTH = 16
PBKDF2_ITERATIONS = 200000

os.makedirs(DATA_DIR, exist_ok=True)

sessions = {}

try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=["200 per day", "50 per hour"],
        storage_uri="memory://"
    )
    RATE_LIMITING_ENABLED = True
except ImportError:
    RATE_LIMITING_ENABLED = False
    limiter = None

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    return response

def get_or_create_salt():
    if not os.path.exists(SALT_FILE):
        salt = os.urandom(16)
        with open(SALT_FILE, "wb") as f:
            f.write(salt)
        return salt
    with open(SALT_FILE, "rb") as f:
        return f.read()

def derive_key(master_password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS
    )
    key = kdf.derive(master_password.encode('utf-8'))
    return base64.urlsafe_b64encode(key)

def check_password_strength(password):
    score = 0
    feedback = []
    
    if len(password) >= 16:
        score += 3
    elif len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        feedback.append("Use at least 8 characters")
    
    if re.search(r'[a-z]', password):
        score += 1
    else:
        feedback.append("Add lowercase letters")
    
    if re.search(r'[A-Z]', password):
        score += 1
    else:
        feedback.append("Add uppercase letters")
    
    if re.search(r'\d', password):
        score += 1
    else:
        feedback.append("Add numbers")
    
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        score += 1
    else:
        feedback.append("Add special characters")
    
    if score >= 7:
        strength = "excellent"
        label = "Excellent"
    elif score >= 5:
        strength = "strong"
        label = "Strong"
    elif score >= 3:
        strength = "good"
        label = "Good"
    else:
        strength = "weak"
        label = "Weak"
    
    return {
        "score": score,
        "strength": strength,
        "label": label,
        "feedback": feedback,
        "percentage": min(100, int((score / 7) * 100))
    }

def generate_random_password(length=16, use_uppercase=True, use_lowercase=True, 
                              use_digits=True, use_symbols=True):
    chars = ""
    required = []
    
    if use_lowercase:
        chars += string.ascii_lowercase
        required.append(secrets.choice(string.ascii_lowercase))
    if use_uppercase:
        chars += string.ascii_uppercase
        required.append(secrets.choice(string.ascii_uppercase))
    if use_digits:
        chars += string.digits
        required.append(secrets.choice(string.digits))
    if use_symbols:
        chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"
        required.append(secrets.choice("!@#$%^&*()_+-=[]{}|;:,.<>?"))
    
    if not chars:
        chars = string.ascii_letters + string.digits
    
    remaining_length = length - len(required)
    password_chars = required + [secrets.choice(chars) for _ in range(remaining_length)]
    secrets.SystemRandom().shuffle(password_chars)
    
    return ''.join(password_chars)

def generate_custom_password(phrase, mode="intact"):
    phrase_len = len(phrase)
    if not (4 <= phrase_len <= 12):
        return None
    
    filler_pool = string.punctuation + string.digits + string.ascii_letters
    guaranteed = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
        secrets.choice("!@#$%^&*")
    ]
    
    if mode == "intact":
        total_additional = max(4, DEFAULT_PASSWORD_LENGTH - phrase_len)
        remaining = total_additional - len(guaranteed)
        fillers = guaranteed + [secrets.choice(filler_pool) for _ in range(remaining)]
        secrets.SystemRandom().shuffle(fillers)
        mid = len(fillers) // 2
        return ''.join(fillers[:mid]) + phrase + ''.join(fillers[mid:])
    else:
        chunk_size = int(mode) if mode.isdigit() else 2
        chunks = [phrase[i:i+chunk_size] for i in range(0, phrase_len, chunk_size)]
        target_length = DEFAULT_PASSWORD_LENGTH
        num_fillers = max(4, target_length - phrase_len)
        
        fillers = guaranteed + [secrets.choice(filler_pool) for _ in range(num_fillers - 4)]
        secrets.SystemRandom().shuffle(fillers)
        
        result = []
        filler_per_gap = len(fillers) // (len(chunks) + 1)
        filler_idx = 0
        
        for i, chunk in enumerate(chunks):
            for _ in range(filler_per_gap):
                if filler_idx < len(fillers):
                    result.append(fillers[filler_idx])
                    filler_idx += 1
            result.append(chunk)
        
        while filler_idx < len(fillers):
            result.append(fillers[filler_idx])
            filler_idx += 1
        
        return ''.join(result)[:target_length]

def create_token(session_id):
    payload = {
        'session_id': session_id,
        'exp': datetime.utcnow() + timedelta(minutes=JWT_EXPIRY_MINUTES),
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            return jsonify({'error': 'Token required'}), 401
        
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            session_id = payload['session_id']
            
            if session_id not in sessions:
                return jsonify({'error': 'Session expired'}), 401
            
            session = sessions[session_id]
            if time.time() - session['last_activity'] > AUTO_LOCK_MINUTES * 60:
                del sessions[session_id]
                return jsonify({'error': 'Session locked due to inactivity'}), 401
            
            session['last_activity'] = time.time()
            request.session = session
            request.session_id = session_id
            
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        
        return f(*args, **kwargs)
    return decorated

@app.route('/')
def serve():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/api/status', methods=['GET'])
def get_status():
    is_setup = os.path.exists(KEY_FILE)
    return jsonify({
        'initialized': is_setup,
        'version': '2.0.0',
        'name': 'AegisVault'
    })

@app.route('/api/auth/setup', methods=['POST'])
def setup():
    if os.path.exists(KEY_FILE):
        return jsonify({'error': 'Already initialized'}), 400
    
    data = request.get_json()
    master_password = data.get('masterPassword', '')
    
    if not master_password:
        return jsonify({'error': 'Master password required'}), 400
    
    strength = check_password_strength(master_password)
    if strength['strength'] == 'weak':
        return jsonify({'error': 'Password too weak', 'strength': strength}), 400
    
    salt = get_or_create_salt()
    key = derive_key(master_password, salt)
    fernet = Fernet(key)
    
    verification_data = fernet.encrypt(b"aegisvault_verification_token")
    with open(KEY_FILE, "wb") as f:
        f.write(verification_data)
    
    session_id = secrets.token_hex(32)
    sessions[session_id] = {
        'fernet': fernet,
        'last_activity': time.time()
    }
    
    token = create_token(session_id)
    
    return jsonify({
        'success': True,
        'token': token,
        'message': 'Vault created successfully'
    })

@app.route('/api/auth/login', methods=['POST'])
def login():
    if not os.path.exists(KEY_FILE):
        return jsonify({'error': 'Vault not initialized'}), 400
    
    data = request.get_json()
    master_password = data.get('masterPassword', '')
    
    if not master_password:
        return jsonify({'error': 'Master password required'}), 400
    
    salt = get_or_create_salt()
    key = derive_key(master_password, salt)
    
    try:
        fernet = Fernet(key)
        with open(KEY_FILE, "rb") as f:
            stored_data = f.read()
        fernet.decrypt(stored_data)
        
        session_id = secrets.token_hex(32)
        sessions[session_id] = {
            'fernet': fernet,
            'last_activity': time.time()
        }
        
        token = create_token(session_id)
        
        return jsonify({
            'success': True,
            'token': token
        })
        
    except InvalidToken:
        return jsonify({'error': 'Invalid master password'}), 401

@app.route('/api/auth/logout', methods=['POST'])
@token_required
def logout():
    if request.session_id in sessions:
        del sessions[request.session_id]
    return jsonify({'success': True})

@app.route('/api/auth/refresh', methods=['POST'])
@token_required
def refresh_token():
    new_token = create_token(request.session_id)
    return jsonify({'token': new_token})

@app.route('/api/passwords', methods=['GET'])
@token_required
def get_passwords():
    fernet = request.session['fernet']
    passwords = []
    
    if os.path.exists(PASSWORDS_FILE):
        with open(PASSWORDS_FILE, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    decrypted = fernet.decrypt(line.encode()).decode()
                    parts = decrypted.split(" | ")
                    if len(parts) >= 3:
                        entry = {
                            'id': secrets.token_hex(8),
                            'website': parts[0],
                            'username': parts[1],
                            'password': parts[2],
                            'notes': parts[3] if len(parts) > 3 else ''
                        }
                        passwords.append(entry)
                except (InvalidToken, Exception):
                    continue
    
    passwords.sort(key=lambda x: x['website'].lower())
    return jsonify({'passwords': passwords})

@app.route('/api/passwords', methods=['POST'])
@token_required
def add_password():
    fernet = request.session['fernet']
    data = request.get_json()
    
    website = data.get('website', '').strip()
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    notes = data.get('notes', '').strip()
    
    if not all([website, username, password]):
        return jsonify({'error': 'Website, username, and password are required'}), 400
    
    entries = []
    if os.path.exists(PASSWORDS_FILE):
        with open(PASSWORDS_FILE, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    decrypted = fernet.decrypt(line.encode()).decode()
                    parts = decrypted.split(" | ")
                    if len(parts) >= 3 and parts[0].lower() == website.lower():
                        return jsonify({'error': f'Entry for {website} already exists'}), 400
                    entries.append(line)
                except (InvalidToken, Exception):
                    entries.append(line)
    
    entry_data = f"{website} | {username} | {password}"
    if notes:
        entry_data += f" | {notes}"
    
    encrypted = fernet.encrypt(entry_data.encode()).decode()
    entries.append(encrypted)
    
    with open(PASSWORDS_FILE, 'w') as f:
        for entry in entries:
            f.write(entry + '\n')
    
    return jsonify({'success': True, 'message': f'Password for {website} saved'})

@app.route('/api/passwords/<website>', methods=['PUT'])
@token_required
def update_password(website):
    fernet = request.session['fernet']
    data = request.get_json()
    
    new_website = data.get('website', '').strip()
    new_username = data.get('username', '').strip()
    new_password = data.get('password', '').strip()
    new_notes = data.get('notes', '').strip()
    
    if not all([new_website, new_username, new_password]):
        return jsonify({'error': 'All fields are required'}), 400
    
    entries = []
    found = False
    
    if os.path.exists(PASSWORDS_FILE):
        with open(PASSWORDS_FILE, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    decrypted = fernet.decrypt(line.encode()).decode()
                    parts = decrypted.split(" | ")
                    if len(parts) >= 3 and parts[0] == website:
                        entry_data = f"{new_website} | {new_username} | {new_password}"
                        if new_notes:
                            entry_data += f" | {new_notes}"
                        encrypted = fernet.encrypt(entry_data.encode()).decode()
                        entries.append(encrypted)
                        found = True
                    else:
                        entries.append(line)
                except (InvalidToken, Exception):
                    entries.append(line)
    
    if not found:
        return jsonify({'error': 'Entry not found'}), 404
    
    with open(PASSWORDS_FILE, 'w') as f:
        for entry in entries:
            f.write(entry + '\n')
    
    return jsonify({'success': True, 'message': 'Password updated'})

@app.route('/api/passwords/<website>', methods=['DELETE'])
@token_required
def delete_password(website):
    fernet = request.session['fernet']
    
    entries = []
    found = False
    
    if os.path.exists(PASSWORDS_FILE):
        with open(PASSWORDS_FILE, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    decrypted = fernet.decrypt(line.encode()).decode()
                    parts = decrypted.split(" | ")
                    if len(parts) >= 3 and parts[0] == website:
                        found = True
                        continue
                    entries.append(line)
                except (InvalidToken, Exception):
                    entries.append(line)
    
    if not found:
        return jsonify({'error': 'Entry not found'}), 404
    
    with open(PASSWORDS_FILE, 'w') as f:
        for entry in entries:
            f.write(entry + '\n')
    
    return jsonify({'success': True, 'message': f'Password for {website} deleted'})

@app.route('/api/generate', methods=['POST'])
@token_required
def generate_password():
    data = request.get_json()
    mode = data.get('mode', 'random')
    
    if mode == 'random':
        length = min(max(data.get('length', 16), 8), 64)
        password = generate_random_password(
            length=length,
            use_uppercase=data.get('uppercase', True),
            use_lowercase=data.get('lowercase', True),
            use_digits=data.get('digits', True),
            use_symbols=data.get('symbols', True)
        )
    elif mode == 'custom':
        phrase = data.get('phrase', '')
        style = data.get('style', 'intact')
        password = generate_custom_password(phrase, style)
        if not password:
            return jsonify({'error': 'Phrase must be 4-12 characters'}), 400
    else:
        return jsonify({'error': 'Invalid mode'}), 400
    
    strength = check_password_strength(password)
    
    return jsonify({
        'password': password,
        'strength': strength
    })

@app.route('/api/strength', methods=['POST'])
def check_strength():
    data = request.get_json()
    password = data.get('password', '')
    strength = check_password_strength(password)
    return jsonify(strength)

@app.route('/api/export', methods=['GET'])
@token_required
def export_passwords():
    fernet = request.session['fernet']
    passwords = []
    
    if os.path.exists(PASSWORDS_FILE):
        with open(PASSWORDS_FILE, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    decrypted = fernet.decrypt(line.encode()).decode()
                    parts = decrypted.split(" | ")
                    if len(parts) >= 3:
                        passwords.append({
                            'website': parts[0],
                            'username': parts[1],
                            'password': parts[2],
                            'notes': parts[3] if len(parts) > 3 else ''
                        })
                except (InvalidToken, Exception):
                    continue
    
    return jsonify({'passwords': passwords, 'exported_at': datetime.utcnow().isoformat()})

@app.route('/api/import', methods=['POST'])
@token_required
def import_passwords():
    fernet = request.session['fernet']
    data = request.get_json()
    passwords = data.get('passwords', [])
    
    if not passwords:
        return jsonify({'error': 'No passwords to import'}), 400
    
    entries = []
    if os.path.exists(PASSWORDS_FILE):
        with open(PASSWORDS_FILE, 'r') as f:
            entries = [line.strip() for line in f if line.strip()]
    
    imported = 0
    skipped = 0
    
    existing_websites = set()
    for entry in entries:
        try:
            decrypted = fernet.decrypt(entry.encode()).decode()
            parts = decrypted.split(" | ")
            if len(parts) >= 3:
                existing_websites.add(parts[0].lower())
        except:
            pass
    
    for pwd in passwords:
        website = pwd.get('website', '').strip()
        username = pwd.get('username', '').strip()
        password = pwd.get('password', '').strip()
        notes = pwd.get('notes', '').strip()
        
        if not all([website, username, password]):
            skipped += 1
            continue
        
        if website.lower() in existing_websites:
            skipped += 1
            continue
        
        entry_data = f"{website} | {username} | {password}"
        if notes:
            entry_data += f" | {notes}"
        
        encrypted = fernet.encrypt(entry_data.encode()).decode()
        entries.append(encrypted)
        existing_websites.add(website.lower())
        imported += 1
    
    with open(PASSWORDS_FILE, 'w') as f:
        for entry in entries:
            f.write(entry + '\n')
    
    return jsonify({
        'success': True,
        'imported': imported,
        'skipped': skipped
    })

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy', 'version': '2.0.0'})

@app.route('/<path:path>')
def serve_static(path):
    if os.path.exists(os.path.join(app.static_folder, path)):
        return send_from_directory(app.static_folder, path)
    return send_from_directory(app.static_folder, 'index.html')

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    debug = os.environ.get('FLASK_ENV') == 'development'
    app.run(host='0.0.0.0', port=port, debug=debug)
