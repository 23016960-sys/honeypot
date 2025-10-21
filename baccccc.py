# file: honey_flask.py
from flask import Flask, request, render_template_string
from werkzeug.utils import secure_filename
import sqlite3, time, json, os
from datetime import datetime, timezone

# Config
DB = 'honeypot_logs.db'
LOGFILE = 'honeypot_requests.log'
QUARANTINE_DIR = 'quarantine'
UPLOAD_MAX_BYTES = 10 * 1024 * 1024  # 10 MB

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = UPLOAD_MAX_BYTES

# --- DB helper ---
def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS events (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   ts TEXT,
                   src_ip TEXT,
                   xff TEXT,
                   method TEXT,
                   path TEXT,
                   headers TEXT,
                   body TEXT
                 )''')
    conn.commit()
    conn.close()

def save_event(src_ip, xff, method, path, headers, body):
    """
    Lưu event vào SQLite và append vào logfile human-readable.
    Nếu ghi DB lỗi thì vẫn append vào logfile và log lỗi bằng app.logger.
    """
    ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    # normalize headers: only keep a few interesting ones to avoid huge logs
    try:
        headers_dict = {
            'User-Agent': headers.get('User-Agent', ''),
            'X-Forwarded-For': headers.get('X-Forwarded-For', ''),
            'Content-Type': headers.get('Content-Type', ''),
            'Accept': headers.get('Accept', '')
        }
    except Exception:
        headers_dict = {}

    # truncate body to reasonable size
    try:
        if isinstance(body, bytes):
            body_text = body.decode('utf-8', 'replace')[:2000]
        else:
            body_text = str(body)[:2000]
    except Exception:
        body_text = ''

    try:
        conn = sqlite3.connect(DB, timeout=5)
        c = conn.cursor()
        # 7 columns -> 7 placeholders
        c.execute('INSERT INTO events (ts, src_ip, xff, method, path, headers, body) VALUES (?,?,?,?,?,?,?)',
                  (ts, src_ip, xff, method, path, json.dumps(headers_dict), body_text))
        conn.commit()
        conn.close()
    except Exception as e:
        # if DB fails, still append to logfile
        try:
            with open(LOGFILE, 'a', encoding='utf8') as f:
                f.write(f"{ts} | {src_ip} | {xff} | {method} {path} | headers:{json.dumps(headers_dict)} | body:{body_text}\n")
        except Exception:
            pass
        try:
            app.logger.error("Logging failure: %s", e)
        except Exception:
            pass

# --- simple templates ---
ADMIN_PAGE = """
<!doctype html>
<title>Admin Panel</title>
<h2>Admin Login</h2>
<form method="post" action="/admin/login">
  <input name="username" placeholder="username"/><br/>
  <input name="password" placeholder="password" type="password"/><br/>
  <button type="submit">Login</button>
</form>
"""

GENERIC_PAGE = "<h1>Welcome</h1><p>This server is under maintenance.</p>"

# --- request logger middleware ---
@app.before_request
def log_request():
    try:
        src_ip = request.remote_addr or 'unknown'
        xff = request.headers.get('X-Forwarded-For', '')
        method = request.method
        path = request.path
        headers = request.headers
        # read body safely (limit size)
        body = request.get_data()[:2000]  # bytes capped to 2k
        save_event(src_ip, xff, method, path, headers, body)
    except Exception as e:
        # protect server from logging failures
        try:
            app.logger.error("Logging failure: %s", e)
        except Exception:
            pass

# --- endpoints ---
@app.route('/')
def index():
    return GENERIC_PAGE, 200

@app.route('/admin', methods=['GET'])
def admin():
    return ADMIN_PAGE

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    # accept GET to show form and POST to "handle" attempts
    if request.method == 'GET':
        return ADMIN_PAGE
    username = request.form.get('username')
    password = request.form.get('password')
    # intentionally do not authenticate; just log and show fake response
    return f"<p>Login failed for {username}</p>", 401

@app.route('/api/v1/data', methods=['GET', 'POST'])
def api_data():
    # return structured JSON so scanning tools get a response
    return json.dumps({'error': 'not_found'}), 404

@app.route('/upload', methods=['POST'])
def upload():
    # save uploaded filename + basic meta (do NOT auto-open files)
    file = request.files.get('file')
    if file:
        fname = secure_filename(file.filename or 'upload')
        os.makedirs(QUARANTINE_DIR, exist_ok=True)
        path = os.path.join(QUARANTINE_DIR, f"{int(time.time())}_{fname}")
        try:
            file.save(path)
            # write small note to main logfile
            with open(LOGFILE, 'a', encoding='utf8') as f:
                f.write(f"{datetime.now(timezone.utc).isoformat()} | uploaded_file_saved: {path}\n")
        except Exception as e:
            app.logger.error("Failed to save upload: %s", e)
            return "Failed", 500
    return "OK", 200

if __name__ == '__main__':
    init_db()
    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    app.run(host='0.0.0.0', port=8080, debug=False)
