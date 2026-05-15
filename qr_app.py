#!/usr/bin/env python3
"""
QR Tracker — WVE
Redirect server + volledige scan tracking + admin dashboard
Port: 5010 op Berry
"""

import os, io, csv, json, secrets, sqlite3, hashlib, string, random
from datetime import datetime, timedelta
from functools import wraps
from collections import defaultdict

import requests
from flask import (Flask, request, redirect, session, send_file,
                   render_template_string, g, flash, url_for, Response, abort)

try:
    import qrcode
    from qrcode.image.styledpil import StyledPilImage
    from qrcode.image.styles.moduledrawers import RoundedModuleDrawer
    HAS_QR = True
except ImportError:
    HAS_QR = False

try:
    from user_agents import parse as ua_parse
    HAS_UA = True
except ImportError:
    HAS_UA = False

# ─── Config ──────────────────────────────────────────────────────────────────

app = Flask(__name__)
app.secret_key = os.environ.get('QR_SECRET_KEY', secrets.token_hex(32))

DB_PATH  = os.path.expanduser(os.environ.get('QR_DB_PATH', '~/qr_tracker.db'))
BASE_URL = os.environ.get('QR_BASE_URL', 'https://qr.wve.nl').rstrip('/')
ADMIN_PW = os.environ.get('QR_ADMIN_PASSWORD', 'changeme')

_geo_cache = {}  # IP → geo dict, in-memory cache

# ─── Database ────────────────────────────────────────────────────────────────

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db:
        db.close()

def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript('''
        CREATE TABLE IF NOT EXISTS qr_codes (
            id          TEXT PRIMARY KEY,
            name        TEXT NOT NULL,
            destination TEXT NOT NULL,
            campaign    TEXT DEFAULT '',
            notes       TEXT DEFAULT '',
            created_at  TEXT DEFAULT (datetime('now')),
            is_active   INTEGER DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS scan_events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            code_id     TEXT NOT NULL,
            scanned_at  TEXT DEFAULT (datetime('now','localtime')),
            ip          TEXT,
            country     TEXT,
            country_code TEXT,
            city        TEXT,
            region      TEXT,
            isp         TEXT,
            org         TEXT,
            device      TEXT,
            os          TEXT,
            browser     TEXT,
            ua_string   TEXT,
            referrer    TEXT,
            language    TEXT,
            FOREIGN KEY (code_id) REFERENCES qr_codes(id)
        );
        CREATE INDEX IF NOT EXISTS idx_scans_code ON scan_events(code_id);
        CREATE INDEX IF NOT EXISTS idx_scans_time ON scan_events(scanned_at);
    ''')
    db.commit()
    db.close()

# ─── Helpers ─────────────────────────────────────────────────────────────────

def gen_code(length=6):
    chars = string.ascii_lowercase + string.digits
    while True:
        code = ''.join(random.choices(chars, k=length))
        db = get_db()
        if not db.execute('SELECT 1 FROM qr_codes WHERE id=?', (code,)).fetchone():
            return code

def geolocate(ip):
    if ip in ('127.0.0.1', '::1', None):
        return {}
    if ip in _geo_cache:
        return _geo_cache[ip]
    try:
        r = requests.get(
            f'http://ip-api.com/json/{ip}',
            params={'fields': 'status,country,countryCode,regionName,city,isp,org'},
            timeout=3
        )
        data = r.json()
        if data.get('status') == 'success':
            result = {
                'country':      data.get('country', ''),
                'country_code': data.get('countryCode', ''),
                'city':         data.get('city', ''),
                'region':       data.get('regionName', ''),
                'isp':          data.get('isp', ''),
                'org':          data.get('org', ''),
            }
            _geo_cache[ip] = result
            return result
    except Exception:
        pass
    return {}

def parse_ua(ua_string):
    if not ua_string:
        return {'device': 'onbekend', 'os': '', 'browser': ''}
    if HAS_UA:
        ua = ua_parse(ua_string)
        if ua.is_mobile:
            device = 'mobiel'
        elif ua.is_tablet:
            device = 'tablet'
        else:
            device = 'desktop'
        return {
            'device':  device,
            'os':      f"{ua.os.family} {ua.os.version_string}".strip(),
            'browser': f"{ua.browser.family} {ua.browser.version_string}".strip(),
        }
    ua_lower = ua_string.lower()
    device = 'mobiel' if any(x in ua_lower for x in ('mobile', 'android', 'iphone')) else \
             'tablet' if 'ipad' in ua_lower else 'desktop'
    return {'device': device, 'os': '', 'browser': ''}

def real_ip():
    for header in ('X-Forwarded-For', 'X-Real-IP', 'CF-Connecting-IP'):
        val = request.headers.get(header)
        if val:
            return val.split(',')[0].strip()
    return request.remote_addr

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated

def make_qr_png(url, style='rounded'):
    qr = qrcode.QRCode(
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=12,
        border=4,
    )
    qr.add_data(url)
    qr.make(fit=True)
    if HAS_QR and style == 'rounded':
        img = qr.make_image(
            image_factory=StyledPilImage,
            module_drawer=RoundedModuleDrawer()
        )
    else:
        img = qr.make_image(fill_color='black', back_color='white')
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    return buf

# ─── Public redirect ─────────────────────────────────────────────────────────

@app.route('/c/<code>')
def scan(code):
    db = get_db()
    row = db.execute(
        'SELECT * FROM qr_codes WHERE id=? AND is_active=1', (code,)
    ).fetchone()
    if not row:
        abort(404)

    ip  = real_ip()
    geo = geolocate(ip)
    ua  = parse_ua(request.headers.get('User-Agent', ''))

    db.execute('''
        INSERT INTO scan_events
            (code_id, ip, country, country_code, city, region, isp, org,
             device, os, browser, ua_string, referrer, language)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    ''', (
        code, ip,
        geo.get('country', ''), geo.get('country_code', ''),
        geo.get('city', ''),    geo.get('region', ''),
        geo.get('isp', ''),     geo.get('org', ''),
        ua.get('device', ''),   ua.get('os', ''),
        ua.get('browser', ''),  request.headers.get('User-Agent', ''),
        request.headers.get('Referer', ''),
        request.headers.get('Accept-Language', '').split(',')[0],
    ))
    db.commit()

    return redirect(row['destination'], code=302)

# ─── Auth ────────────────────────────────────────────────────────────────────

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        pw = request.form.get('password', '')
        if pw == ADMIN_PW:
            session['logged_in'] = True
            return redirect(request.args.get('next') or url_for('dashboard'))
        error = 'Verkeerd wachtwoord'
    return render_template_string(LOGIN_TMPL, error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
def index():
    return redirect(url_for('dashboard'))

# ─── Admin dashboard ─────────────────────────────────────────────────────────

@app.route('/admin')
@login_required
def dashboard():
    db = get_db()
    today = datetime.now().strftime('%Y-%m-%d')
    week_ago = (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d')

    stats = {
        'total_codes':  db.execute('SELECT COUNT(*) FROM qr_codes').fetchone()[0],
        'active_codes': db.execute('SELECT COUNT(*) FROM qr_codes WHERE is_active=1').fetchone()[0],
        'total_scans':  db.execute('SELECT COUNT(*) FROM scan_events').fetchone()[0],
        'scans_today':  db.execute("SELECT COUNT(*) FROM scan_events WHERE scanned_at >= ?", (today,)).fetchone()[0],
        'scans_week':   db.execute("SELECT COUNT(*) FROM scan_events WHERE scanned_at >= ?", (week_ago,)).fetchone()[0],
    }

    top_codes = db.execute('''
        SELECT q.id, q.name, q.campaign, q.destination, q.is_active,
               COUNT(s.id) as scan_count,
               MAX(s.scanned_at) as last_scan
        FROM qr_codes q
        LEFT JOIN scan_events s ON s.code_id = q.id
        GROUP BY q.id ORDER BY scan_count DESC LIMIT 10
    ''').fetchall()

    recent = db.execute('''
        SELECT s.scanned_at, s.country, s.city, s.device, s.browser,
               q.name as code_name, q.id as code_id
        FROM scan_events s JOIN qr_codes q ON q.id = s.code_id
        ORDER BY s.scanned_at DESC LIMIT 15
    ''').fetchall()

    # Scans per dag laatste 30 dagen
    days_data = db.execute('''
        SELECT substr(scanned_at,1,10) as dag, COUNT(*) as n
        FROM scan_events
        WHERE scanned_at >= date('now','-30 days')
        GROUP BY dag ORDER BY dag
    ''').fetchall()
    chart_labels = [r['dag'] for r in days_data]
    chart_values = [r['n'] for r in days_data]

    return render_template_string(DASHBOARD_TMPL,
        stats=stats, top_codes=top_codes, recent=recent,
        chart_labels=json.dumps(chart_labels),
        chart_values=json.dumps(chart_values),
    )

# ─── Codes beheer ────────────────────────────────────────────────────────────

@app.route('/admin/codes')
@login_required
def codes_list():
    db = get_db()
    codes = db.execute('''
        SELECT q.*, COUNT(s.id) as scan_count, MAX(s.scanned_at) as last_scan
        FROM qr_codes q
        LEFT JOIN scan_events s ON s.code_id = q.id
        GROUP BY q.id ORDER BY q.created_at DESC
    ''').fetchall()
    return render_template_string(CODES_TMPL, codes=codes, base_url=BASE_URL)

@app.route('/admin/codes/new', methods=['GET', 'POST'])
@login_required
def code_new():
    if request.method == 'POST':
        name        = request.form.get('name', '').strip()
        destination = request.form.get('destination', '').strip()
        campaign    = request.form.get('campaign', '').strip()
        notes       = request.form.get('notes', '').strip()
        custom_id   = request.form.get('custom_id', '').strip().lower()

        if not name or not destination:
            flash('Naam en bestemmings-URL zijn verplicht')
            return redirect(url_for('code_new'))

        if not destination.startswith(('http://', 'https://')):
            destination = 'https://' + destination

        db = get_db()
        code_id = custom_id if custom_id else gen_code()

        if custom_id and db.execute('SELECT 1 FROM qr_codes WHERE id=?', (code_id,)).fetchone():
            flash(f'Code "{code_id}" bestaat al')
            return redirect(url_for('code_new'))

        db.execute(
            'INSERT INTO qr_codes (id, name, destination, campaign, notes) VALUES (?,?,?,?,?)',
            (code_id, name, destination, campaign, notes)
        )
        db.commit()
        flash(f'QR code "{code_id}" aangemaakt')
        return redirect(url_for('code_detail', code_id=code_id))

    return render_template_string(CODE_NEW_TMPL)

@app.route('/admin/codes/<code_id>')
@login_required
def code_detail(code_id):
    db = get_db()
    code = db.execute('SELECT * FROM qr_codes WHERE id=?', (code_id,)).fetchone()
    if not code:
        abort(404)

    total_scans  = db.execute('SELECT COUNT(*) FROM scan_events WHERE code_id=?', (code_id,)).fetchone()[0]
    unique_ips   = db.execute('SELECT COUNT(DISTINCT ip) FROM scan_events WHERE code_id=?', (code_id,)).fetchone()[0]

    by_country = db.execute('''
        SELECT country, COUNT(*) as n FROM scan_events
        WHERE code_id=? AND country != ''
        GROUP BY country ORDER BY n DESC LIMIT 10
    ''', (code_id,)).fetchall()

    by_device = db.execute('''
        SELECT device, COUNT(*) as n FROM scan_events
        WHERE code_id=? GROUP BY device ORDER BY n DESC
    ''', (code_id,)).fetchall()

    by_os = db.execute('''
        SELECT os, COUNT(*) as n FROM scan_events
        WHERE code_id=? AND os != ''
        GROUP BY os ORDER BY n DESC LIMIT 8
    ''', (code_id,)).fetchall()

    by_city = db.execute('''
        SELECT city, country, COUNT(*) as n FROM scan_events
        WHERE code_id=? AND city != ''
        GROUP BY city ORDER BY n DESC LIMIT 10
    ''', (code_id,)).fetchall()

    days_data = db.execute('''
        SELECT substr(scanned_at,1,10) as dag, COUNT(*) as n
        FROM scan_events WHERE code_id=?
        AND scanned_at >= date('now','-30 days')
        GROUP BY dag ORDER BY dag
    ''', (code_id,)).fetchall()

    recent_scans = db.execute('''
        SELECT * FROM scan_events WHERE code_id=?
        ORDER BY scanned_at DESC LIMIT 50
    ''', (code_id,)).fetchall()

    scan_url = f"{BASE_URL}/c/{code_id}"

    return render_template_string(CODE_DETAIL_TMPL,
        code=code, scan_url=scan_url,
        total_scans=total_scans, unique_ips=unique_ips,
        by_country=by_country, by_device=by_device,
        by_os=by_os, by_city=by_city,
        recent_scans=recent_scans,
        chart_labels=json.dumps([r['dag'] for r in days_data]),
        chart_values=json.dumps([r['n'] for r in days_data]),
    )

@app.route('/admin/codes/<code_id>/toggle')
@login_required
def code_toggle(code_id):
    db = get_db()
    db.execute('UPDATE qr_codes SET is_active = 1 - is_active WHERE id=?', (code_id,))
    db.commit()
    return redirect(url_for('codes_list'))

@app.route('/admin/codes/<code_id>/qr.png')
@login_required
def code_qr(code_id):
    db = get_db()
    code = db.execute('SELECT * FROM qr_codes WHERE id=?', (code_id,)).fetchone()
    if not code:
        abort(404)
    scan_url = f"{BASE_URL}/c/{code_id}"
    buf = make_qr_png(scan_url)
    return send_file(buf, mimetype='image/png',
                     download_name=f'qr_{code_id}.png', as_attachment=True)

@app.route('/admin/codes/<code_id>/export')
@login_required
def code_export(code_id):
    db = get_db()
    rows = db.execute('''
        SELECT scanned_at, ip, country, city, region, isp, org,
               device, os, browser, referrer, language
        FROM scan_events WHERE code_id=? ORDER BY scanned_at DESC
    ''', (code_id,)).fetchall()

    def generate():
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(['tijdstip','ip','land','stad','regio','isp','org',
                         'apparaat','os','browser','referrer','taal'])
        for row in rows:
            writer.writerow(list(row))
            yield buf.getvalue()
            buf.seek(0); buf.truncate()

    return Response(generate(), mimetype='text/csv',
                    headers={'Content-Disposition': f'attachment; filename=scans_{code_id}.csv'})

# ─── Templates ───────────────────────────────────────────────────────────────

_BASE = '''<!DOCTYPE html>
<html lang="nl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>QR Tracker — WVE</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">
<style>
body{background:#f5f7fa}
.sidebar{width:220px;min-height:100vh;background:#1a1a2e;color:#ccc}
.sidebar a{color:#adb5bd;text-decoration:none;padding:10px 20px;display:block}
.sidebar a:hover,.sidebar a.active{background:#0d6efd22;color:#fff}
.sidebar .brand{color:#fff;font-weight:700;font-size:1.1rem;padding:20px}
.main{flex:1;padding:30px}
.stat-card{border-radius:12px;border:none}
.scan-badge{font-size:.75rem}
</style>
</head>
<body>
<div class="d-flex">
  <div class="sidebar d-flex flex-column">
    <div class="brand">QR Tracker</div>
    <a href="/admin"><i class="bi bi-speedometer2 me-2"></i>Dashboard</a>
    <a href="/admin/codes"><i class="bi bi-qr-code me-2"></i>QR Codes</a>
    <a href="/admin/codes/new"><i class="bi bi-plus-circle me-2"></i>Nieuwe code</a>
    <div class="mt-auto mb-3">
      <a href="/logout"><i class="bi bi-box-arrow-left me-2"></i>Uitloggen</a>
    </div>
  </div>
  <div class="main">
    {% with msgs = get_flashed_messages() %}
      {% if msgs %}
        {% for m in msgs %}
          <div class="alert alert-info alert-dismissible fade show">{{m}}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
          </div>
        {% endfor %}
      {% endif %}
    {% endwith %}
    {% block content %}{% endblock %}
  </div>
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.3/dist/chart.umd.min.js"></script>
{% block scripts %}{% endblock %}
</body>
</html>'''

LOGIN_TMPL = '''<!DOCTYPE html>
<html lang="nl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Login — QR Tracker</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head><body class="bg-light d-flex align-items-center" style="min-height:100vh">
<div class="container" style="max-width:360px">
  <div class="card shadow-sm">
    <div class="card-body p-4">
      <h4 class="mb-4 text-center">QR Tracker</h4>
      {% if error %}<div class="alert alert-danger">{{error}}</div>{% endif %}
      <form method="post">
        <div class="mb-3">
          <input type="password" name="password" class="form-control"
                 placeholder="Wachtwoord" autofocus required>
        </div>
        <button class="btn btn-primary w-100">Inloggen</button>
      </form>
    </div>
  </div>
</div></body></html>'''

DASHBOARD_TMPL = _BASE.replace('{% block content %}{% endblock %}', '''{% block content %}
<h4 class="mb-4">Dashboard</h4>

<div class="row g-3 mb-4">
  <div class="col-sm-6 col-lg-3">
    <div class="card stat-card shadow-sm">
      <div class="card-body">
        <div class="text-muted small">Totaal scans</div>
        <div class="fs-2 fw-bold">{{stats.total_scans}}</div>
      </div>
    </div>
  </div>
  <div class="col-sm-6 col-lg-3">
    <div class="card stat-card shadow-sm">
      <div class="card-body">
        <div class="text-muted small">Vandaag</div>
        <div class="fs-2 fw-bold text-primary">{{stats.scans_today}}</div>
      </div>
    </div>
  </div>
  <div class="col-sm-6 col-lg-3">
    <div class="card stat-card shadow-sm">
      <div class="card-body">
        <div class="text-muted small">Deze week</div>
        <div class="fs-2 fw-bold text-success">{{stats.scans_week}}</div>
      </div>
    </div>
  </div>
  <div class="col-sm-6 col-lg-3">
    <div class="card stat-card shadow-sm">
      <div class="card-body">
        <div class="text-muted small">Actieve codes</div>
        <div class="fs-2 fw-bold">{{stats.active_codes}} / {{stats.total_codes}}</div>
      </div>
    </div>
  </div>
</div>

<div class="row g-3 mb-4">
  <div class="col-lg-8">
    <div class="card shadow-sm">
      <div class="card-header bg-white fw-semibold">Scans per dag (30 dagen)</div>
      <div class="card-body"><canvas id="scanChart" height="100"></canvas></div>
    </div>
  </div>
  <div class="col-lg-4">
    <div class="card shadow-sm h-100">
      <div class="card-header bg-white fw-semibold">Top codes</div>
      <div class="card-body p-0">
        <table class="table table-sm mb-0">
          {% for c in top_codes %}
          <tr>
            <td><a href="/admin/codes/{{c.id}}">{{c.name}}</a></td>
            <td class="text-end text-muted">{{c.scan_count}}</td>
          </tr>
          {% endfor %}
        </table>
      </div>
    </div>
  </div>
</div>

<div class="card shadow-sm">
  <div class="card-header bg-white fw-semibold">Recente scans</div>
  <div class="card-body p-0">
    <table class="table table-sm mb-0">
      <thead class="table-light">
        <tr><th>Tijdstip</th><th>Code</th><th>Land</th><th>Stad</th><th>Apparaat</th><th>Browser</th></tr>
      </thead>
      <tbody>
        {% for s in recent %}
        <tr>
          <td class="text-muted small">{{s.scanned_at}}</td>
          <td><a href="/admin/codes/{{s.code_id}}">{{s.code_name}}</a></td>
          <td>{{s.country or '—'}}</td>
          <td>{{s.city or '—'}}</td>
          <td><span class="badge bg-secondary scan-badge">{{s.device or '?'}}</span></td>
          <td class="small text-muted">{{s.browser or '—'}}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
</div>
{% endblock %}
{% block scripts %}
<script>
new Chart(document.getElementById('scanChart'), {
  type: 'bar',
  data: {
    labels: {{chart_labels|safe}},
    datasets: [{
      label: 'Scans',
      data: {{chart_values|safe}},
      backgroundColor: '#0d6efd88',
      borderColor: '#0d6efd',
      borderWidth: 1,
    }]
  },
  options: {plugins:{legend:{display:false}}, scales:{y:{beginAtZero:true}}}
});
</script>
{% endblock %}''').replace('{% block content %}{% endblock %}', '').replace('{% block scripts %}{% endblock %}', '')

CODES_TMPL = _BASE.replace('{% block content %}{% endblock %}', '''{% block content %}
<div class="d-flex justify-content-between align-items-center mb-4">
  <h4 class="mb-0">QR Codes</h4>
  <a href="/admin/codes/new" class="btn btn-primary btn-sm">
    <i class="bi bi-plus-circle me-1"></i>Nieuwe code
  </a>
</div>
<div class="card shadow-sm">
  <div class="card-body p-0">
    <table class="table table-hover mb-0">
      <thead class="table-light">
        <tr>
          <th>Naam</th><th>Code</th><th>Campagne</th>
          <th>Bestemming</th><th>Scans</th><th>Laatste scan</th>
          <th>Status</th><th></th>
        </tr>
      </thead>
      <tbody>
        {% for c in codes %}
        <tr>
          <td><a href="/admin/codes/{{c.id}}">{{c.name}}</a></td>
          <td><code>{{c.id}}</code></td>
          <td>{{c.campaign or '—'}}</td>
          <td class="small text-muted text-truncate" style="max-width:180px">{{c.destination}}</td>
          <td><strong>{{c.scan_count}}</strong></td>
          <td class="small text-muted">{{c.last_scan or '—'}}</td>
          <td>
            {% if c.is_active %}
              <span class="badge bg-success">actief</span>
            {% else %}
              <span class="badge bg-secondary">uit</span>
            {% endif %}
          </td>
          <td>
            <a href="/admin/codes/{{c.id}}/qr.png" class="btn btn-outline-secondary btn-sm" title="Download QR">
              <i class="bi bi-download"></i>
            </a>
            <a href="/admin/codes/{{c.id}}/toggle" class="btn btn-outline-secondary btn-sm" title="Toggle actief">
              <i class="bi bi-toggle-on"></i>
            </a>
          </td>
        </tr>
        {% endfor %}
        {% if not codes %}
        <tr><td colspan="8" class="text-center text-muted py-4">Nog geen QR codes</td></tr>
        {% endif %}
      </tbody>
    </table>
  </div>
</div>
{% endblock %}''').replace('{% block scripts %}{% endblock %}', '')

CODE_NEW_TMPL = _BASE.replace('{% block content %}{% endblock %}', '''{% block content %}
<h4 class="mb-4">Nieuwe QR code</h4>
<div class="card shadow-sm" style="max-width:560px">
  <div class="card-body">
    <form method="post">
      <div class="mb-3">
        <label class="form-label fw-semibold">Naam <span class="text-danger">*</span></label>
        <input type="text" name="name" class="form-control" placeholder="Bv. Poster kantoor Amsterdam" required>
      </div>
      <div class="mb-3">
        <label class="form-label fw-semibold">Bestemmings-URL <span class="text-danger">*</span></label>
        <input type="text" name="destination" class="form-control" placeholder="https://www.wve.nl" required>
      </div>
      <div class="mb-3">
        <label class="form-label fw-semibold">Campagne</label>
        <input type="text" name="campaign" class="form-control" placeholder="Bv. zomer2025, poster-nijmegen">
        <div class="form-text">Handig om codes te groeperen</div>
      </div>
      <div class="mb-3">
        <label class="form-label fw-semibold">Aangepaste code (optioneel)</label>
        <div class="input-group">
          <span class="input-group-text text-muted small">/c/</span>
          <input type="text" name="custom_id" class="form-control" placeholder="bv. poster-ams (leeg = automatisch)">
        </div>
      </div>
      <div class="mb-4">
        <label class="form-label fw-semibold">Notities</label>
        <textarea name="notes" class="form-control" rows="2" placeholder="Locatie, formaat, drukker..."></textarea>
      </div>
      <div class="d-flex gap-2">
        <button type="submit" class="btn btn-primary">Aanmaken + QR downloaden</button>
        <a href="/admin/codes" class="btn btn-outline-secondary">Annuleer</a>
      </div>
    </form>
  </div>
</div>
{% endblock %}''').replace('{% block scripts %}{% endblock %}', '')

CODE_DETAIL_TMPL = _BASE.replace('{% block content %}{% endblock %}', '''{% block content %}
<div class="d-flex justify-content-between align-items-start mb-4">
  <div>
    <h4 class="mb-1">{{code.name}}</h4>
    <div class="text-muted small">
      <code>{{scan_url}}</code>
      {% if code.campaign %} · campagne: <strong>{{code.campaign}}</strong>{% endif %}
    </div>
    {% if code.notes %}<div class="text-muted small mt-1">{{code.notes}}</div>{% endif %}
  </div>
  <div class="d-flex gap-2">
    <a href="/admin/codes/{{code.id}}/qr.png" class="btn btn-outline-primary btn-sm">
      <i class="bi bi-download me-1"></i>Download QR
    </a>
    <a href="/admin/codes/{{code.id}}/export" class="btn btn-outline-secondary btn-sm">
      <i class="bi bi-filetype-csv me-1"></i>Export CSV
    </a>
    <a href="/admin/codes/{{code.id}}/toggle" class="btn btn-outline-secondary btn-sm">
      {% if code.is_active %}Deactiveer{% else %}Activeer{% endif %}
    </a>
  </div>
</div>

<div class="row g-3 mb-4">
  <div class="col-sm-4">
    <div class="card shadow-sm text-center py-3">
      <div class="fs-1 fw-bold text-primary">{{total_scans}}</div>
      <div class="text-muted">Totaal scans</div>
    </div>
  </div>
  <div class="col-sm-4">
    <div class="card shadow-sm text-center py-3">
      <div class="fs-1 fw-bold">{{unique_ips}}</div>
      <div class="text-muted">Unieke bezoekers</div>
    </div>
  </div>
  <div class="col-sm-4">
    <div class="card shadow-sm text-center py-3">
      <div class="fs-4 fw-bold text-truncate px-2">{{code.destination}}</div>
      <div class="text-muted">Bestemming</div>
    </div>
  </div>
</div>

<div class="row g-3 mb-4">
  <div class="col-lg-8">
    <div class="card shadow-sm">
      <div class="card-header bg-white fw-semibold">Scans per dag (30 dagen)</div>
      <div class="card-body"><canvas id="scanChart" height="100"></canvas></div>
    </div>
  </div>
  <div class="col-lg-4">
    <div class="card shadow-sm">
      <div class="card-header bg-white fw-semibold">Apparaat</div>
      <div class="card-body"><canvas id="deviceChart"></canvas></div>
    </div>
  </div>
</div>

<div class="row g-3 mb-4">
  <div class="col-md-4">
    <div class="card shadow-sm">
      <div class="card-header bg-white fw-semibold">Top landen</div>
      <div class="card-body p-0">
        <table class="table table-sm mb-0">
          {% for r in by_country %}
          <tr><td>{{r.country}}</td><td class="text-end text-muted">{{r.n}}</td></tr>
          {% endfor %}
          {% if not by_country %}<tr><td colspan="2" class="text-muted text-center py-3">Geen data</td></tr>{% endif %}
        </table>
      </div>
    </div>
  </div>
  <div class="col-md-4">
    <div class="card shadow-sm">
      <div class="card-header bg-white fw-semibold">Top steden</div>
      <div class="card-body p-0">
        <table class="table table-sm mb-0">
          {% for r in by_city %}
          <tr><td>{{r.city}}</td><td class="text-muted small">{{r.country}}</td><td class="text-end">{{r.n}}</td></tr>
          {% endfor %}
          {% if not by_city %}<tr><td colspan="3" class="text-muted text-center py-3">Geen data</td></tr>{% endif %}
        </table>
      </div>
    </div>
  </div>
  <div class="col-md-4">
    <div class="card shadow-sm">
      <div class="card-header bg-white fw-semibold">Besturingssysteem</div>
      <div class="card-body p-0">
        <table class="table table-sm mb-0">
          {% for r in by_os %}
          <tr><td>{{r.os}}</td><td class="text-end text-muted">{{r.n}}</td></tr>
          {% endfor %}
          {% if not by_os %}<tr><td colspan="2" class="text-muted text-center py-3">Geen data</td></tr>{% endif %}
        </table>
      </div>
    </div>
  </div>
</div>

<div class="card shadow-sm">
  <div class="card-header bg-white fw-semibold">Recente scans</div>
  <div class="card-body p-0">
    <div class="table-responsive">
      <table class="table table-sm mb-0">
        <thead class="table-light">
          <tr><th>Tijdstip</th><th>IP</th><th>Land</th><th>Stad</th><th>ISP</th><th>Apparaat</th><th>OS</th><th>Browser</th><th>Taal</th></tr>
        </thead>
        <tbody>
          {% for s in recent_scans %}
          <tr>
            <td class="small text-muted">{{s.scanned_at}}</td>
            <td class="small"><code>{{s.ip or '—'}}</code></td>
            <td>{{s.country or '—'}}</td>
            <td>{{s.city or '—'}}</td>
            <td class="small text-muted">{{s.isp or '—'}}</td>
            <td><span class="badge bg-secondary scan-badge">{{s.device or '?'}}</span></td>
            <td class="small">{{s.os or '—'}}</td>
            <td class="small">{{s.browser or '—'}}</td>
            <td class="small text-muted">{{s.language or '—'}}</td>
          </tr>
          {% endfor %}
          {% if not recent_scans %}<tr><td colspan="9" class="text-center text-muted py-4">Nog geen scans</td></tr>{% endif %}
        </tbody>
      </table>
    </div>
  </div>
</div>
{% endblock %}
{% block scripts %}
<script>
new Chart(document.getElementById('scanChart'), {
  type: 'bar',
  data: {
    labels: {{chart_labels|safe}},
    datasets: [{label:'Scans',data:{{chart_values|safe}},backgroundColor:'#0d6efd88',borderColor:'#0d6efd',borderWidth:1}]
  },
  options: {plugins:{legend:{display:false}},scales:{y:{beginAtZero:true}}}
});
const devData = [{% for r in by_device %}{label:'{{r.device}}',n:{{r.n}}}{% if not loop.last %},{% endif %}{% endfor %}];
if(devData.length){
  new Chart(document.getElementById('deviceChart'), {
    type: 'doughnut',
    data: {
      labels: devData.map(d=>d.label),
      datasets: [{data:devData.map(d=>d.n),backgroundColor:['#0d6efd','#198754','#ffc107','#dc3545']}]
    },
    options: {plugins:{legend:{position:'bottom'}}}
  });
}
</script>
{% endblock %}''').replace('{% block content %}{% endblock %}', '').replace('{% block scripts %}{% endblock %}', '')

# ─── Start ───────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('QR_PORT', 5010))
    print(f"QR Tracker gestart op :{port}")
    print(f"Base URL: {BASE_URL}")
    print(f"Database: {DB_PATH}")
    app.run(host='0.0.0.0', port=port, debug=False)
