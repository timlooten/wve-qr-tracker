#!/usr/bin/env python3
"""
QR Tracker — WVE
Redirect server + volledige scan tracking + admin dashboard
Port: 5010 op Berry
"""

import os, io, csv, json, secrets, sqlite3, hashlib, string, random, base64
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

def make_qr_b64(url):
    buf = make_qr_png(url)
    return base64.b64encode(buf.read()).decode('utf-8')

def trend(current, previous):
    if previous == 0:
        return None
    return round((current - previous) / previous * 100)

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
    now       = datetime.now()
    today     = now.strftime('%Y-%m-%d')
    yesterday = (now - timedelta(days=1)).strftime('%Y-%m-%d')
    week_ago  = (now - timedelta(days=7)).strftime('%Y-%m-%d')
    two_weeks = (now - timedelta(days=14)).strftime('%Y-%m-%d')

    scans_today     = db.execute("SELECT COUNT(*) FROM scan_events WHERE scanned_at >= ?", (today,)).fetchone()[0]
    scans_yesterday = db.execute("SELECT COUNT(*) FROM scan_events WHERE scanned_at >= ? AND scanned_at < ?", (yesterday, today)).fetchone()[0]
    scans_week      = db.execute("SELECT COUNT(*) FROM scan_events WHERE scanned_at >= ?", (week_ago,)).fetchone()[0]
    scans_prev_week = db.execute("SELECT COUNT(*) FROM scan_events WHERE scanned_at >= ? AND scanned_at < ?", (two_weeks, week_ago)).fetchone()[0]

    stats = {
        'total_codes':       db.execute('SELECT COUNT(*) FROM qr_codes').fetchone()[0],
        'active_codes':      db.execute('SELECT COUNT(*) FROM qr_codes WHERE is_active=1').fetchone()[0],
        'total_scans':       db.execute('SELECT COUNT(*) FROM scan_events').fetchone()[0],
        'scans_today':       scans_today,
        'scans_week':        scans_week,
        'trend_today':       trend(scans_today, scans_yesterday),
        'trend_week':        trend(scans_week, scans_prev_week),
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

    def chart_data(days):
        rows = db.execute('''
            SELECT substr(scanned_at,1,10) as dag, COUNT(*) as n
            FROM scan_events WHERE scanned_at >= date('now',?)
            GROUP BY dag ORDER BY dag
        ''', (f'-{days} days',)).fetchall()
        return [r['dag'] for r in rows], [r['n'] for r in rows]

    labels30, values30 = chart_data(30)
    labels7,  values7  = chart_data(7)

    return render_template_string(DASHBOARD_TMPL,
        stats=stats, top_codes=top_codes, recent=recent,
        chart_labels=json.dumps(labels30),
        chart_values=json.dumps(values30),
        chart_labels_7=json.dumps(labels7),
        chart_values_7=json.dumps(values7),
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
    return render_template_string(CODES_TMPL, codes=codes, base_url=BASE_URL, BASE_URL=BASE_URL)

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

    def detail_chart(days):
        rows = db.execute('''
            SELECT substr(scanned_at,1,10) as dag, COUNT(*) as n
            FROM scan_events WHERE code_id=? AND scanned_at >= date('now',?)
            GROUP BY dag ORDER BY dag
        ''', (code_id, f'-{days} days')).fetchall()
        return [r['dag'] for r in rows], [r['n'] for r in rows]

    labels30, values30 = detail_chart(30)
    labels7,  values7  = detail_chart(7)

    recent_scans = db.execute('''
        SELECT * FROM scan_events WHERE code_id=?
        ORDER BY scanned_at DESC LIMIT 50
    ''', (code_id,)).fetchall()

    scan_url = f"{BASE_URL}/c/{code_id}"
    qr_b64   = make_qr_b64(scan_url)

    return render_template_string(CODE_DETAIL_TMPL,
        code=code, scan_url=scan_url, qr_b64=qr_b64,
        total_scans=total_scans, unique_ips=unique_ips,
        by_country=by_country, by_device=by_device,
        by_os=by_os, by_city=by_city,
        recent_scans=recent_scans,
        chart_labels=json.dumps(labels30),
        chart_values=json.dumps(values30),
        chart_labels_7=json.dumps(labels7),
        chart_values_7=json.dumps(values7),
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

# ── Gedeelde CSS ─────────────────────────────────────────────────────────────
_CSS = '''
<style>
:root{
  --wve-basis:#375e53;--wve-primary:#2D6A4F;--wve-accent:#40916C;
  --wve-bright:#52B788;--wve-light:#74C69D;--wve-pale:#B7E4C7;
  --wve-offwhite:#F5F9F7;--wve-dark:#1B3A2D;--wve-text:#1a2e26;--wve-muted:#4A5568;
}
*{font-family:'Poppins',sans-serif;box-sizing:border-box}
body{background:#fff;color:var(--wve-text);margin:0}
/* Accent bar */
.accent-bar{height:4px;background:var(--wve-basis);position:fixed;top:0;left:0;right:0;z-index:100}
/* Sidebar */
.sidebar{width:224px;min-height:100vh;background:var(--wve-basis);display:flex;flex-direction:column;flex-shrink:0;padding-top:4px}
.sidebar .brand{padding:20px 20px 4px;color:#fff}
.sidebar .brand-name{font-weight:700;font-size:.95rem;letter-spacing:.01em}
.sidebar .brand-sub{font-size:.67rem;color:var(--wve-bright);letter-spacing:.09em;text-transform:uppercase;margin-top:1px}
.sidebar nav{margin-top:12px;flex:1}
.sidebar a{color:#b8d4cc;text-decoration:none;padding:9px 20px;display:flex;align-items:center;font-size:.83rem;transition:all .13s;border-left:3px solid transparent;gap:9px}
.sidebar a i{width:16px;text-align:center;font-size:.9rem;opacity:.8}
.sidebar a:hover{background:rgba(82,183,136,.13);color:#fff;border-left-color:rgba(82,183,136,.4)}
.sidebar a.active{background:rgba(82,183,136,.18);color:#fff;border-left-color:var(--wve-bright);font-weight:500}
.sidebar a.active i{opacity:1}
.sidebar .nav-section{font-size:.67rem;color:rgba(255,255,255,.35);letter-spacing:.1em;text-transform:uppercase;padding:16px 20px 4px;font-weight:500}
.sidebar .sidebar-footer{padding:14px 20px;border-top:1px solid rgba(82,183,136,.18);font-size:.72rem;color:rgba(255,255,255,.3);margin-top:auto}
/* Layout */
.layout{display:flex;min-height:100vh;padding-top:4px}
.main{flex:1;padding:28px 32px;background:#fff;min-width:0;overflow-x:hidden}
/* Page header */
.page-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:24px;gap:12px;flex-wrap:wrap}
.page-title{font-size:1.1rem;font-weight:700;color:var(--wve-basis);display:flex;align-items:center;gap:8px;margin:0}
.page-title i{font-size:1rem;color:var(--wve-accent)}
/* Stat cards */
.stats-row{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:24px}
.stat-card{background:var(--wve-offwhite);border-radius:10px;border-left:4px solid var(--wve-bright);padding:16px 18px;box-shadow:0 1px 4px rgba(55,94,83,.07)}
.stat-card.accent{border-left-color:var(--wve-accent)}
.stat-card.dim{border-left-color:var(--wve-pale)}
.stat-label{font-size:.7rem;color:var(--wve-muted);text-transform:uppercase;letter-spacing:.08em;font-weight:500;margin-bottom:5px}
.stat-value{font-size:1.8rem;font-weight:700;color:var(--wve-basis);line-height:1}
.stat-trend{font-size:.72rem;margin-top:5px;font-weight:500}
.stat-trend.up{color:#2D6A4F}.stat-trend.down{color:#e53e3e}.stat-trend.neutral{color:var(--wve-muted)}
/* WVE Card */
.wve-card{background:var(--wve-offwhite);border-radius:10px;box-shadow:0 1px 5px rgba(55,94,83,.08);overflow:hidden;margin-bottom:20px}
.wve-card-header{display:flex;align-items:center;justify-content:space-between;padding:12px 16px;border-bottom:1px solid var(--wve-pale)}
.wve-card-title{font-size:.75rem;font-weight:600;color:var(--wve-basis);text-transform:uppercase;letter-spacing:.07em}
.wve-card-body{padding:16px}
.wve-card-body.p-0{padding:0}
/* Table */
.wve-table{width:100%;border-collapse:collapse;font-size:.82rem}
.wve-table th{font-size:.71rem;font-weight:600;color:var(--wve-basis);text-transform:uppercase;letter-spacing:.07em;padding:9px 14px;background:var(--wve-offwhite);border-bottom:2px solid var(--wve-pale);white-space:nowrap}
.wve-table td{padding:9px 14px;border-bottom:1px solid rgba(183,228,199,.4);vertical-align:middle;color:var(--wve-text)}
.wve-table tbody tr:last-child td{border-bottom:none}
.wve-table tbody tr:hover td{background:rgba(245,249,247,.8)}
/* Buttons */
.btn-wve{display:inline-flex;align-items:center;gap:5px;background:var(--wve-accent);color:#fff;border:none;border-radius:7px;font-size:.82rem;font-weight:500;padding:8px 15px;cursor:pointer;text-decoration:none;transition:background .13s;white-space:nowrap}
.btn-wve:hover{background:var(--wve-primary);color:#fff}
.btn-wve.sm{padding:5px 11px;font-size:.77rem}
.btn-outline{display:inline-flex;align-items:center;gap:5px;border:1.5px solid var(--wve-pale);color:var(--wve-muted);background:transparent;border-radius:7px;font-size:.82rem;padding:7px 13px;cursor:pointer;text-decoration:none;transition:all .13s;white-space:nowrap}
.btn-outline:hover{border-color:var(--wve-accent);color:var(--wve-accent);background:rgba(82,183,136,.05)}
.btn-outline.sm{padding:4px 10px;font-size:.77rem}
.btn-icon{display:inline-flex;align-items:center;justify-content:center;width:30px;height:30px;border-radius:6px;border:1.5px solid var(--wve-pale);color:var(--wve-muted);background:transparent;cursor:pointer;text-decoration:none;transition:all .13s;font-size:.85rem}
.btn-icon:hover{border-color:var(--wve-accent);color:var(--wve-accent);background:rgba(82,183,136,.06)}
/* Badges */
.badge{display:inline-block;font-size:.7rem;padding:3px 9px;border-radius:20px;font-weight:500;white-space:nowrap}
.badge-active{background:rgba(82,183,136,.18);color:#2D6A4F}
.badge-inactive{background:#f1f5f9;color:#94a3b8}
.badge-mobiel{background:rgba(82,183,136,.2);color:#2D6A4F}
.badge-tablet{background:rgba(116,198,157,.2);color:#375e53}
.badge-desktop{background:rgba(45,106,79,.15);color:#2D6A4F}
.badge-onbekend{background:#f1f5f9;color:#94a3b8}
/* Forms */
.form-group{margin-bottom:18px}
.form-label{display:block;font-size:.83rem;font-weight:500;color:var(--wve-basis);margin-bottom:5px}
.form-label .req{color:#e53e3e;margin-left:2px}
.form-label .opt{font-weight:400;color:var(--wve-muted);font-size:.77rem}
.form-control{width:100%;border:1.5px solid #dde5e0;border-radius:7px;padding:8px 12px;font-size:.84rem;color:var(--wve-text);background:#fff;transition:border .13s;outline:none}
.form-control:focus{border-color:var(--wve-bright);box-shadow:0 0 0 3px rgba(82,183,136,.12)}
.form-hint{font-size:.75rem;color:var(--wve-muted);margin-top:4px}
.input-prefix{display:flex;align-items:center}
.input-prefix-text{background:var(--wve-offwhite);border:1.5px solid #dde5e0;border-right:none;border-radius:7px 0 0 7px;padding:8px 11px;font-size:.8rem;color:var(--wve-muted);white-space:nowrap}
.input-prefix .form-control{border-radius:0 7px 7px 0}
/* Search */
.search-box{position:relative;max-width:280px}
.search-box i{position:absolute;left:10px;top:50%;transform:translateY(-50%);color:var(--wve-muted);font-size:.85rem;pointer-events:none}
.search-box input{padding-left:30px;width:100%}
/* Copy button */
.copy-wrap{display:inline-flex;align-items:center;gap:6px}
.copy-wrap code{font-size:.8rem;background:rgba(55,94,83,.07);color:var(--wve-primary);padding:3px 8px;border-radius:5px}
/* Chart toolbar */
.chart-toolbar{display:flex;gap:4px}
.chart-btn{font-size:.72rem;padding:4px 10px;border-radius:5px;border:1.5px solid var(--wve-pale);color:var(--wve-muted);background:transparent;cursor:pointer;font-family:'Poppins',sans-serif;transition:all .12s}
.chart-btn.active{background:var(--wve-accent);color:#fff;border-color:var(--wve-accent)}
/* Toast */
.toast-container{position:fixed;bottom:24px;right:24px;z-index:9999;display:flex;flex-direction:column;gap:8px}
.wve-toast{background:#fff;border-radius:9px;box-shadow:0 4px 20px rgba(55,94,83,.15);padding:12px 16px;border-left:4px solid var(--wve-bright);font-size:.83rem;color:var(--wve-text);display:flex;align-items:center;gap:10px;animation:slideIn .2s ease;min-width:260px}
@keyframes slideIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
/* QR preview */
.qr-preview{background:#fff;border-radius:12px;padding:20px;box-shadow:0 1px 5px rgba(55,94,83,.1);display:inline-block}
.qr-preview img{display:block;width:180px;height:180px}
/* Empty state */
.empty-state{text-align:center;padding:48px 20px;color:var(--wve-muted)}
.empty-state i{font-size:2.5rem;color:var(--wve-pale);display:block;margin-bottom:12px}
.empty-state p{font-size:.9rem;margin-bottom:16px}
/* Misc */
a{color:var(--wve-accent);text-decoration:none}
a:hover{color:var(--wve-primary)}
code{font-size:.82em;background:rgba(55,94,83,.07);color:var(--wve-primary);padding:2px 6px;border-radius:4px}
hr{border:none;border-top:1px solid var(--wve-pale);margin:16px 0}
.text-muted{color:var(--wve-muted) !important}
.truncate{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:200px}
@media(max-width:900px){.stats-row{grid-template-columns:repeat(2,1fr)}.sidebar{width:52px}.sidebar .brand-name,.sidebar .brand-sub,.sidebar a span,.sidebar .nav-section,.sidebar .sidebar-footer{display:none}.sidebar a{padding:12px;justify-content:center}}
</style>'''

# ── HTML head ─────────────────────────────────────────────────────────────────
_HEAD = (
    '<!DOCTYPE html><html lang="nl"><head>'
    '<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
    '<title>QR Tracker — WVE</title>'
    '<link href="https://fonts.googleapis.com/css2?family=Poppins:ital,wght@0,400;0,500;0,600;0,700;1,400&display=swap" rel="stylesheet">'
    '<link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">'
    + _CSS +
    '</head>'
)

# ── Sidebar ───────────────────────────────────────────────────────────────────
_NAV = '''
<div class="sidebar">
  <div class="brand">
    <div class="brand-name">QR Tracker</div>
    <div class="brand-sub">Wij Vergelijken Energie</div>
  </div>
  <nav>
    <div class="nav-section">Beheer</div>
    <a href="/admin" class="{{ 'active' if request.path == '/admin' else '' }}">
      <i class="bi bi-speedometer2"></i><span>Dashboard</span>
    </a>
    <a href="/admin/codes" class="{{ 'active' if request.path.startswith('/admin/codes') and 'new' not in request.path else '' }}">
      <i class="bi bi-qr-code"></i><span>QR Codes</span>
    </a>
    <a href="/admin/codes/new" class="{{ 'active' if 'new' in request.path else '' }}">
      <i class="bi bi-plus-circle"></i><span>Nieuwe code</span>
    </a>
  </nav>
  <div class="sidebar-footer">
    <a href="/logout" style="color:rgba(255,255,255,.35);font-size:.75rem;display:flex;align-items:center;gap:6px">
      <i class="bi bi-box-arrow-left"></i><span>Uitloggen</span>
    </a>
  </div>
</div>'''

# ── Shared footer scripts ─────────────────────────────────────────────────────
_SCRIPTS = '''
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.3/dist/chart.umd.min.js"></script>
<script>
// Copy to clipboard
function copyText(text, btn) {
  navigator.clipboard.writeText(text).then(function() {
    var orig = btn.innerHTML;
    btn.innerHTML = '<i class="bi bi-check2"></i>';
    btn.style.color = '#40916C';
    showToast('Gekopieerd naar klembord');
    setTimeout(function(){btn.innerHTML=orig;btn.style.color='';}, 1800);
  });
}
// Toast
function showToast(msg) {
  var c = document.getElementById('toast-container');
  if(!c){c=document.createElement('div');c.id='toast-container';c.className='toast-container';document.body.appendChild(c);}
  var t = document.createElement('div');
  t.className = 'wve-toast';
  t.innerHTML = '<i class="bi bi-check-circle-fill" style="color:#52B788"></i>' + msg;
  c.appendChild(t);
  setTimeout(function(){t.style.opacity='0';t.style.transition='opacity .3s';setTimeout(function(){t.remove()},300)}, 2500);
}
// Chart defaults
if(typeof Chart !== 'undefined'){
  Chart.defaults.font.family = 'Poppins';
  Chart.defaults.color = '#4A5568';
}
// Flash als toast
document.addEventListener('DOMContentLoaded', function(){
  document.querySelectorAll('.flash-msg').forEach(function(el){
    showToast(el.textContent);
    el.remove();
  });
});
</script>'''

def _page(content, scripts=''):
    """Bouw een volledige pagina met sidebar."""
    return (
        _HEAD + '<body>'
        '<div class="layout">'
        + _NAV +
        '<div class="main">'
        '{% with msgs = get_flashed_messages() %}'
        '{% if msgs %}{% for m in msgs %}<span class="flash-msg" style="display:none">{{m}}</span>{% endfor %}{% endif %}'
        '{% endwith %}'
        + content +
        '</div></div>'
        + _SCRIPTS + scripts +
        '</body></html>'
    )

# ── Chart helper (gedeeld) ────────────────────────────────────────────────────
_CHART_JS = '''
function makeBarChart(id, labels, data) {
  return new Chart(document.getElementById(id), {
    type: 'bar',
    data: {
      labels: labels,
      datasets: [{
        data: data,
        backgroundColor: 'rgba(82,183,136,.3)',
        borderColor: '#40916C',
        borderWidth: 2,
        borderRadius: 4,
        hoverBackgroundColor: 'rgba(64,145,108,.45)',
      }]
    },
    options: {
      plugins: { legend: { display: false } },
      scales: {
        y: { beginAtZero: true, grid: { color: '#B7E4C722' }, ticks: { precision: 0 } },
        x: { grid: { display: false } }
      }
    }
  });
}
'''

# ── LOGIN ─────────────────────────────────────────────────────────────────────
LOGIN_TMPL = (
    _HEAD +
    '<body style="background:var(--wve-offwhite);min-height:100vh;display:flex;align-items:center;justify-content:center">'
    '<div style="width:100%;max-width:380px;padding:24px">'
    '  <div style="text-align:center;margin-bottom:28px">'
    '    <div style="width:48px;height:48px;background:var(--wve-basis);border-radius:12px;display:inline-flex;align-items:center;justify-content:center;margin-bottom:14px">'
    '      <i class="bi bi-qr-code-scan" style="color:#fff;font-size:1.3rem"></i>'
    '    </div>'
    '    <div style="font-size:1.1rem;font-weight:700;color:var(--wve-basis)">QR Tracker</div>'
    '    <div style="font-size:.73rem;color:var(--wve-muted);text-transform:uppercase;letter-spacing:.09em;margin-top:2px">Wij Vergelijken Energie</div>'
    '  </div>'
    '  <div class="wve-card"><div class="wve-card-body">'
    '    {% if error %}<div style="background:#fff0f0;border:1px solid #fca5a5;border-radius:7px;padding:10px 12px;font-size:.82rem;color:#b91c1c;margin-bottom:14px">{{error}}</div>{% endif %}'
    '    <form method="post">'
    '      <div class="form-group"><label class="form-label">Wachtwoord</label>'
    '        <input type="password" name="password" class="form-control" placeholder="Voer wachtwoord in" autofocus required>'
    '      </div>'
    '      <button class="btn-wve" style="width:100%;justify-content:center;padding:10px" type="submit">Inloggen</button>'
    '    </form>'
    '  </div></div>'
    '</div>'
    + _SCRIPTS +
    '</body></html>'
)

# ── DASHBOARD ─────────────────────────────────────────────────────────────────
DASHBOARD_TMPL = _page('''
<div class="page-header">
  <h1 class="page-title"><i class="bi bi-speedometer2"></i>Dashboard</h1>
</div>

<div class="stats-row">
  <div class="stat-card">
    <div class="stat-label">Totaal scans</div>
    <div class="stat-value">{{stats.total_scans}}</div>
    <div class="stat-trend neutral">alle tijd</div>
  </div>
  <div class="stat-card accent">
    <div class="stat-label">Vandaag</div>
    <div class="stat-value">{{stats.scans_today}}</div>
    <div class="stat-trend {% if stats.trend_today is not none %}{% if stats.trend_today >= 0 %}up{% else %}down{% endif %}{% else %}neutral{% endif %}">
      {% if stats.trend_today is not none %}
        {% if stats.trend_today >= 0 %}<i class="bi bi-arrow-up-short"></i>+{{stats.trend_today}}%{% else %}<i class="bi bi-arrow-down-short"></i>{{stats.trend_today}}%{% endif %}
        vs gisteren
      {% else %}geen vergelijking{% endif %}
    </div>
  </div>
  <div class="stat-card">
    <div class="stat-label">Deze week</div>
    <div class="stat-value">{{stats.scans_week}}</div>
    <div class="stat-trend {% if stats.trend_week is not none %}{% if stats.trend_week >= 0 %}up{% else %}down{% endif %}{% else %}neutral{% endif %}">
      {% if stats.trend_week is not none %}
        {% if stats.trend_week >= 0 %}<i class="bi bi-arrow-up-short"></i>+{{stats.trend_week}}%{% else %}<i class="bi bi-arrow-down-short"></i>{{stats.trend_week}}%{% endif %}
        vs vorige week
      {% else %}geen vergelijking{% endif %}
    </div>
  </div>
  <div class="stat-card dim">
    <div class="stat-label">Actieve codes</div>
    <div class="stat-value">{{stats.active_codes}}</div>
    <div class="stat-trend neutral">van {{stats.total_codes}} totaal</div>
  </div>
</div>

<div style="display:grid;grid-template-columns:2fr 1fr;gap:20px;margin-bottom:20px">
  <div class="wve-card">
    <div class="wve-card-header">
      <span class="wve-card-title">Scans over tijd</span>
      <div class="chart-toolbar">
        <button class="chart-btn active" onclick="switchRange(this,7)" data-range="7">7d</button>
        <button class="chart-btn" onclick="switchRange(this,30)" data-range="30">30d</button>
      </div>
    </div>
    <div class="wve-card-body"><canvas id="scanChart" height="120"></canvas></div>
  </div>
  <div class="wve-card">
    <div class="wve-card-header"><span class="wve-card-title">Top codes</span></div>
    <div class="wve-card-body p-0">
      {% if top_codes %}
      <table class="wve-table">
        {% for c in top_codes %}
        <tr>
          <td><a href="/admin/codes/{{c.id}}">{{c.name}}</a></td>
          <td style="text-align:right;font-weight:600;color:var(--wve-accent);width:50px">{{c.scan_count}}</td>
        </tr>
        {% endfor %}
      </table>
      {% else %}
      <div class="empty-state" style="padding:24px"><i class="bi bi-qr-code"></i><p>Nog geen codes</p><a href="/admin/codes/new" class="btn-wve sm">Maak eerste code</a></div>
      {% endif %}
    </div>
  </div>
</div>

<div class="wve-card">
  <div class="wve-card-header">
    <span class="wve-card-title">Recente scans</span>
    <a href="/admin/codes" class="btn-outline sm">Alle codes</a>
  </div>
  <div class="wve-card-body p-0">
    {% if recent %}
    <table class="wve-table">
      <thead><tr><th>Tijdstip</th><th>Code</th><th>Land</th><th>Stad</th><th>ISP</th><th>Apparaat</th><th>Browser</th></tr></thead>
      <tbody>
        {% for s in recent %}
        <tr>
          <td style="color:var(--wve-muted);white-space:nowrap">{{s.scanned_at}}</td>
          <td><a href="/admin/codes/{{s.code_id}}">{{s.code_name}}</a></td>
          <td>{{s.country or '—'}}</td>
          <td>{{s.city or '—'}}</td>
          <td style="color:var(--wve-muted)" class="truncate">{{s.isp or '—'}}</td>
          <td><span class="badge badge-{{s.device or 'onbekend'}}">{{s.device or '?'}}</span></td>
          <td style="color:var(--wve-muted)" class="truncate">{{s.browser or '—'}}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
    {% else %}
    <div class="empty-state"><i class="bi bi-cursor"></i><p>Nog geen scans ontvangen</p></div>
    {% endif %}
  </div>
</div>
''', '''
<script>
''' + _CHART_JS + '''
var allLabels7  = {{chart_labels_7|safe}};
var allValues7  = {{chart_values_7|safe}};
var allLabels30 = {{chart_labels|safe}};
var allValues30 = {{chart_values|safe}};
var scanChart = makeBarChart('scanChart', allLabels7, allValues7);
function switchRange(btn, days) {
  document.querySelectorAll('.chart-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  var labels = days === 7 ? allLabels7 : allLabels30;
  var values = days === 7 ? allValues7 : allValues30;
  scanChart.data.labels = labels;
  scanChart.data.datasets[0].data = values;
  scanChart.update();
}
</script>
''')

# ── CODES LIST ────────────────────────────────────────────────────────────────
CODES_TMPL = _page('''
<div class="page-header">
  <h1 class="page-title"><i class="bi bi-qr-code"></i>QR Codes</h1>
  <a href="/admin/codes/new" class="btn-wve"><i class="bi bi-plus-circle"></i>Nieuwe code</a>
</div>

<div class="wve-card">
  <div class="wve-card-header">
    <span class="wve-card-title">{{codes|length}} code{% if codes|length != 1 %}s{% endif %}</span>
    <div class="search-box">
      <i class="bi bi-search"></i>
      <input type="text" class="form-control" id="searchInput" placeholder="Zoeken..." oninput="filterCodes(this.value)" style="font-size:.82rem;padding:6px 10px 6px 30px">
    </div>
  </div>
  <div class="wve-card-body p-0">
    {% if codes %}
    <table class="wve-table" id="codesTable">
      <thead><tr><th>Naam</th><th>Scan URL</th><th>Campagne</th><th>Scans</th><th>Laatste scan</th><th>Status</th><th style="width:90px"></th></tr></thead>
      <tbody>
        {% for c in codes %}
        <tr data-search="{{ c.name|lower }} {{ c.id|lower }} {{ (c.campaign or '')|lower }}">
          <td>
            <a href="/admin/codes/{{c.id}}" style="font-weight:500">{{c.name}}</a>
            {% if c.notes %}<div style="font-size:.73rem;color:var(--wve-muted);margin-top:1px">{{c.notes[:60]}}</div>{% endif %}
          </td>
          <td>
            <div class="copy-wrap">
              <code>{{base_url}}/c/{{c.id}}</code>
              <button class="btn-icon" onclick="copyText('{{base_url}}/c/{{c.id}}', this)" title="Kopieer URL"><i class="bi bi-clipboard"></i></button>
            </div>
          </td>
          <td style="color:var(--wve-muted)">{{c.campaign or '—'}}</td>
          <td style="font-weight:600;color:var(--wve-accent)">{{c.scan_count}}</td>
          <td style="color:var(--wve-muted);white-space:nowrap;font-size:.79rem">{{c.last_scan or '—'}}</td>
          <td>
            {% if c.is_active %}<span class="badge badge-active">actief</span>
            {% else %}<span class="badge badge-inactive">uit</span>{% endif %}
          </td>
          <td>
            <div style="display:flex;gap:5px">
              <a href="/admin/codes/{{c.id}}" class="btn-icon" title="Statistieken"><i class="bi bi-bar-chart-line"></i></a>
              <a href="/admin/codes/{{c.id}}/qr.png" class="btn-icon" title="Download QR"><i class="bi bi-download"></i></a>
              <a href="/admin/codes/{{c.id}}/toggle" class="btn-icon" title="{% if c.is_active %}Deactiveer{% else %}Activeer{% endif %}">
                <i class="bi bi-toggle-{% if c.is_active %}on{% else %}off{% endif %}"></i>
              </a>
            </div>
          </td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
    <div id="noResults" style="display:none" class="empty-state"><i class="bi bi-search"></i><p>Geen codes gevonden</p></div>
    {% else %}
    <div class="empty-state">
      <i class="bi bi-qr-code"></i>
      <p>Nog geen QR codes aangemaakt</p>
      <a href="/admin/codes/new" class="btn-wve">Maak eerste code aan</a>
    </div>
    {% endif %}
  </div>
</div>
''', '''
<script>
function filterCodes(q) {
  q = q.toLowerCase().trim();
  var rows = document.querySelectorAll('#codesTable tbody tr[data-search]');
  var visible = 0;
  rows.forEach(function(r){
    var match = !q || r.dataset.search.includes(q);
    r.style.display = match ? '' : 'none';
    if(match) visible++;
  });
  document.getElementById('noResults').style.display = (q && visible === 0) ? '' : 'none';
}
</script>
''')

# ── NIEUWE CODE ───────────────────────────────────────────────────────────────
CODE_NEW_TMPL = _page('''
<div class="page-header">
  <h1 class="page-title"><i class="bi bi-plus-circle"></i>Nieuwe QR code</h1>
  <a href="/admin/codes" class="btn-outline"><i class="bi bi-arrow-left"></i>Terug</a>
</div>

<div style="display:grid;grid-template-columns:1fr 320px;gap:24px;align-items:start">
  <div class="wve-card">
    <div class="wve-card-header"><span class="wve-card-title">Code aanmaken</span></div>
    <div class="wve-card-body">
      <form method="post" id="codeForm">
        <div class="form-group">
          <label class="form-label">Naam <span class="req">*</span></label>
          <input type="text" name="name" class="form-control" placeholder="Poster Nijmegen Centrum" required>
        </div>
        <div class="form-group">
          <label class="form-label">Bestemmings-URL <span class="req">*</span></label>
          <input type="text" name="destination" id="destInput" class="form-control" placeholder="https://www.wve.nl" required oninput="updatePreview()">
          <div class="form-hint">Waar komt de bezoeker terecht na het scannen?</div>
        </div>
        <div class="form-group">
          <label class="form-label">Campagne <span class="opt">(optioneel)</span></label>
          <input type="text" name="campaign" class="form-control" placeholder="zomer2025, poster-nijmegen">
          <div class="form-hint">Groepeer codes per actie of locatie</div>
        </div>
        <div class="form-group">
          <label class="form-label">Eigen code-ID <span class="opt">(optioneel)</span></label>
          <div class="input-prefix">
            <span class="input-prefix-text">/c/</span>
            <input type="text" name="custom_id" id="codeIdInput" class="form-control" placeholder="poster-nijmegen-2025" oninput="updatePreview()">
          </div>
          <div class="form-hint">Leeg = automatisch gegenereerd. Gebruik alleen letters, cijfers en koppeltekens.</div>
        </div>
        <div class="form-group">
          <label class="form-label">Notities <span class="opt">(optioneel)</span></label>
          <textarea name="notes" class="form-control" rows="2" placeholder="Locatie, formaat, drukker, ophangdatum..."></textarea>
        </div>
        <div style="display:flex;gap:10px;margin-top:8px">
          <button type="submit" class="btn-wve"><i class="bi bi-qr-code"></i>Code aanmaken</button>
          <a href="/admin/codes" class="btn-outline">Annuleer</a>
        </div>
      </form>
    </div>
  </div>

  <div>
    <div class="wve-card">
      <div class="wve-card-header"><span class="wve-card-title">Scan URL preview</span></div>
      <div class="wve-card-body" style="text-align:center">
        <div class="qr-preview" style="margin:0 auto 14px">
          <img src="" id="qrPreviewImg" style="width:160px;height:160px;display:none">
          <div id="qrPlaceholder" style="width:160px;height:160px;background:var(--wve-offwhite);border-radius:8px;display:flex;align-items:center;justify-content:center;color:var(--wve-pale)">
            <i class="bi bi-qr-code" style="font-size:2.5rem"></i>
          </div>
        </div>
        <div id="previewUrl" style="font-size:.75rem;color:var(--wve-muted);word-break:break-all">Vul een URL in voor preview</div>
      </div>
    </div>
    <div style="margin-top:14px;background:var(--wve-offwhite);border-radius:9px;padding:14px 16px;font-size:.78rem;color:var(--wve-muted)">
      <strong style="color:var(--wve-basis);display:block;margin-bottom:6px"><i class="bi bi-lightbulb me-1"></i>Tip</strong>
      Na aanmaken kun je de QR code als PNG downloaden en direct in je drukwerk gebruiken. De scan URL eindigt op <code>/c/jouw-code</code> en loopt via qr.wve.nl.
    </div>
  </div>
</div>
''', f'''
<script>
var BASE_URL = '{BASE_URL}';
function updatePreview() {{
  var dest = document.getElementById('destInput').value;
  var codeId = document.getElementById('codeIdInput').value || '...';
  var scanUrl = BASE_URL + '/c/' + codeId;
  document.getElementById('previewUrl').textContent = dest ? scanUrl : 'Vul een URL in voor preview';
}}
</script>
''')

# ── CODE DETAIL ───────────────────────────────────────────────────────────────
CODE_DETAIL_TMPL = _page('''
<div class="page-header">
  <div>
    <div style="font-size:.75rem;color:var(--wve-muted);margin-bottom:4px">
      <a href="/admin/codes">QR Codes</a> <i class="bi bi-chevron-right" style="font-size:.65rem"></i> {{code.name}}
    </div>
    <h1 class="page-title" style="margin-bottom:2px"><i class="bi bi-bar-chart-line"></i>{{code.name}}</h1>
    {% if code.campaign %}<span class="badge badge-active" style="font-size:.72rem">{{code.campaign}}</span>{% endif %}
    {% if not code.is_active %}<span class="badge badge-inactive ms-1">inactief</span>{% endif %}
  </div>
  <div style="display:flex;gap:8px;flex-wrap:wrap">
    <a href="/admin/codes/{{code.id}}/qr.png" class="btn-wve"><i class="bi bi-download"></i>Download QR</a>
    <a href="/admin/codes/{{code.id}}/export" class="btn-outline"><i class="bi bi-filetype-csv"></i>Export CSV</a>
    <a href="/admin/codes/{{code.id}}/toggle" class="btn-outline">
      {% if code.is_active %}Deactiveer{% else %}Activeer{% endif %}
    </a>
  </div>
</div>

<div style="display:grid;grid-template-columns:1fr 200px;gap:20px;margin-bottom:20px;align-items:start">
  <div>
    <div class="stats-row" style="grid-template-columns:repeat(3,1fr);margin-bottom:20px">
      <div class="stat-card accent">
        <div class="stat-label">Totaal scans</div>
        <div class="stat-value">{{total_scans}}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Unieke bezoekers</div>
        <div class="stat-value">{{unique_ips}}</div>
      </div>
      <div class="stat-card dim">
        <div class="stat-label">Scan URL</div>
        <div style="margin-top:6px">
          <div class="copy-wrap" style="flex-wrap:wrap">
            <code style="font-size:.73rem;word-break:break-all">{{scan_url}}</code>
            <button class="btn-icon" onclick="copyText('{{scan_url}}', this)" title="Kopieer URL" style="flex-shrink:0"><i class="bi bi-clipboard"></i></button>
          </div>
        </div>
      </div>
    </div>

    <div class="wve-card">
      <div class="wve-card-header">
        <span class="wve-card-title">Scans over tijd</span>
        <div class="chart-toolbar">
          <button class="chart-btn active" onclick="switchRange(this,7)">7d</button>
          <button class="chart-btn" onclick="switchRange(this,30)">30d</button>
        </div>
      </div>
      <div class="wve-card-body"><canvas id="scanChart" height="110"></canvas></div>
    </div>
  </div>

  <div>
    <div class="wve-card">
      <div class="wve-card-header"><span class="wve-card-title">QR Code</span></div>
      <div class="wve-card-body" style="text-align:center;padding:20px">
        <div class="qr-preview" style="margin:0 auto 12px;padding:14px">
          <img src="data:image/png;base64,{{qr_b64}}" style="width:150px;height:150px;display:block">
        </div>
        <a href="/admin/codes/{{code.id}}/qr.png" class="btn-wve sm" style="width:100%;justify-content:center"><i class="bi bi-download"></i>Download PNG</a>
      </div>
    </div>
  </div>
</div>

<div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px;margin-bottom:20px">
  <div class="wve-card">
    <div class="wve-card-header">
      <span class="wve-card-title">Apparaat</span>
    </div>
    <div class="wve-card-body" style="display:flex;align-items:center;justify-content:center;min-height:160px">
      {% if by_device %}
        <canvas id="deviceChart" style="max-width:180px"></canvas>
      {% else %}
        <div class="empty-state" style="padding:16px"><i class="bi bi-phone" style="font-size:1.5rem"></i><p style="font-size:.8rem">Geen data</p></div>
      {% endif %}
    </div>
  </div>
  <div class="wve-card">
    <div class="wve-card-header"><span class="wve-card-title">Top landen</span></div>
    <div class="wve-card-body p-0">
      {% if by_country %}
      <table class="wve-table">
        {% for r in by_country %}
        <tr><td>{{r.country}}</td><td style="text-align:right;font-weight:600;color:var(--wve-accent)">{{r.n}}</td></tr>
        {% endfor %}
      </table>
      {% else %}<div class="empty-state" style="padding:24px"><p style="font-size:.8rem">Geen data</p></div>{% endif %}
    </div>
  </div>
  <div class="wve-card">
    <div class="wve-card-header"><span class="wve-card-title">Top steden</span></div>
    <div class="wve-card-body p-0">
      {% if by_city %}
      <table class="wve-table">
        {% for r in by_city %}
        <tr><td>{{r.city}}</td><td style="color:var(--wve-muted);font-size:.78rem">{{r.country}}</td><td style="text-align:right;font-weight:600;color:var(--wve-accent)">{{r.n}}</td></tr>
        {% endfor %}
      </table>
      {% else %}<div class="empty-state" style="padding:24px"><p style="font-size:.8rem">Geen data</p></div>{% endif %}
    </div>
  </div>
</div>

<div class="wve-card">
  <div class="wve-card-header">
    <span class="wve-card-title">Recente scans</span>
    <a href="/admin/codes/{{code.id}}/export" class="btn-outline sm"><i class="bi bi-download"></i>Export CSV</a>
  </div>
  <div class="wve-card-body p-0" style="overflow-x:auto">
    {% if recent_scans %}
    <table class="wve-table">
      <thead><tr><th>Tijdstip</th><th>IP</th><th>Land</th><th>Stad</th><th>ISP</th><th>Apparaat</th><th>OS</th><th>Browser</th><th>Taal</th></tr></thead>
      <tbody>
        {% for s in recent_scans %}
        <tr>
          <td style="color:var(--wve-muted);white-space:nowrap;font-size:.78rem">{{s.scanned_at}}</td>
          <td><code>{{s.ip or '—'}}</code></td>
          <td>{{s.country or '—'}}</td>
          <td>{{s.city or '—'}}</td>
          <td style="color:var(--wve-muted)" class="truncate">{{s.isp or '—'}}</td>
          <td><span class="badge badge-{{s.device or 'onbekend'}}">{{s.device or '?'}}</span></td>
          <td style="font-size:.78rem">{{s.os or '—'}}</td>
          <td style="font-size:.78rem" class="truncate">{{s.browser or '—'}}</td>
          <td style="color:var(--wve-muted);font-size:.78rem">{{s.language or '—'}}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
    {% else %}
    <div class="empty-state"><i class="bi bi-cursor"></i><p>Nog geen scans voor deze code</p></div>
    {% endif %}
  </div>
</div>
''', '''
<script>
''' + _CHART_JS + '''
var labels7  = {{chart_labels_7|safe}};
var values7  = {{chart_values_7|safe}};
var labels30 = {{chart_labels|safe}};
var values30 = {{chart_values|safe}};
var scanChart = makeBarChart('scanChart', labels7, values7);
function switchRange(btn, days) {
  document.querySelectorAll('.chart-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  scanChart.data.labels  = days === 7 ? labels7  : labels30;
  scanChart.data.datasets[0].data = days === 7 ? values7 : values30;
  scanChart.update();
}
var devData = [{% for r in by_device %}{label:'{{r.device}}',n:{{r.n}}}{% if not loop.last %},{% endif %}{% endfor %}];
if(devData.length && document.getElementById('deviceChart')) {
  new Chart(document.getElementById('deviceChart'), {
    type: 'doughnut',
    data: {
      labels: devData.map(d => d.label),
      datasets: [{
        data: devData.map(d => d.n),
        backgroundColor: ['#52B788','#2D6A4F','#74C69D','#B7E4C7'],
        borderWidth: 0,
        hoverOffset: 4,
      }]
    },
    options: {
      plugins: { legend: { position: 'bottom', labels: { font: { size: 11 }, padding: 10 } } },
      cutout: '58%'
    }
  });
}
</script>
''')


# ─── Start ───────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('QR_PORT', 5010))
    print(f"QR Tracker gestart op :{port}")
    print(f"Base URL: {BASE_URL}")
    print(f"Database: {DB_PATH}")
    app.run(host='0.0.0.0', port=port, debug=False)
