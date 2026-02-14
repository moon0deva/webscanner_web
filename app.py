from flask import Flask, render_template, request, jsonify, session, send_file
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import nmap
import ipaddress
from functools import wraps
import json
import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urlparse, urljoin, urlencode
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import dns.resolver
import dns.rdatatype
import dns.exception
import ssl
import socket
import concurrent.futures
from datetime import timezone
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.units import inch
from io import BytesIO

# ─────────────────────────────────────────────────────────────
# App Setup
# ─────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = 'change-this-to-a-random-secret-key-in-production'  # CHANGE THIS!

app.config['SQLALCHEMY_DATABASE_URI']  = 'sqlite:///scans.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Authentication – CHANGE THESE BEFORE GOING LIVE
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = 'Secret123!'

# Rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# ─────────────────────────────────────────────────────────────
# Database Model
# ─────────────────────────────────────────────────────────────
class ScanHistory(db.Model):
    id           = db.Column(db.Integer,  primary_key=True)
    target_ip    = db.Column(db.String(45), nullable=False)
    requester_ip = db.Column(db.String(45), nullable=False)
    scan_type    = db.Column(db.String(20), nullable=False)
    scan_options = db.Column(db.Text)
    results      = db.Column(db.Text)
    timestamp    = db.Column(db.DateTime, default=datetime.utcnow)
    username     = db.Column(db.String(50), default='anonymous')
    duration     = db.Column(db.Float)
    ports_found  = db.Column(db.Integer,  default=0)

    def to_dict(self):
        return {
            'id':           self.id,
            'target_ip':    self.target_ip,
            'requester_ip': self.requester_ip,
            'scan_type':    self.scan_type,
            'scan_options': json.loads(self.scan_options) if self.scan_options else {},
            'results':      json.loads(self.results)      if self.results      else {},
            'timestamp':    self.timestamp.isoformat(),
            'username':     self.username,
            'duration':     self.duration,
            'ports_found':  self.ports_found,
        }

with app.app_context():
    db.create_all()

# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'logged_in' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated

def is_valid_target(target):
    """Only allow public IPv4 addresses."""
    try:
        ip = ipaddress.ip_address(target)
        if ip.is_private or ip.is_loopback or ip.is_reserved:
            return False, "Scanning private/internal IPs is not allowed"
        return True, None
    except ValueError:
        return False, "Invalid IP address format"

# ─────────────────────────────────────────────────────────────
# Page Routes
# ─────────────────────────────────────────────────────────────
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scanner')
def scanner():
    return render_template('scanner.html', logged_in=session.get('logged_in', False))

@app.route('/cv')
def cv():
    return render_template('cv.html')

@app.route('/history')
def history():
    return render_template('history.html', logged_in=session.get('logged_in', False))

# ─────────────────────────────────────────────────────────────
# Auth Routes
# ─────────────────────────────────────────────────────────────
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if data.get('username') == ADMIN_USERNAME and data.get('password') == ADMIN_PASSWORD:
        session['logged_in'] = True
        session['username']  = data.get('username')
        return jsonify({'success': True})
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('logged_in', None)
    session.pop('username',  None)
    return jsonify({'success': True})

# ─────────────────────────────────────────────────────────────
# Scan Route  (KEY FIX: -sT TCP connect, works with setcap)
# ─────────────────────────────────────────────────────────────
@app.route('/scan', methods=['POST'])
@limiter.limit("10 per minute")
def scan():
    data         = request.get_json()
    target       = data.get('target', '').strip()
    scan_type    = data.get('scan_type', 'quick')
    options      = data.get('options', {})
    requester_ip = request.headers.get('X-Real-IP', request.remote_addr)

    valid, error = is_valid_target(target)
    if not valid:
        return jsonify({'error': error}), 400

    if scan_type == 'full' and 'logged_in' not in session:
        return jsonify({'error': 'Full port scan requires authentication'}), 401

    start_time = datetime.utcnow()

    try:
        nm = nmap.PortScanner()

        # Quick scan
        if scan_type == 'quick':
            ports = '21-23,25,53,80,110,143,443,445,3306,3389,5432,8080,8443'
            args  = '-sT -T4'
            if options.get('version_detection'):
                args += ' -sV'
            nm.scan(target, ports, arguments=args)

        # Full / deep scan (auth required)
        elif scan_type == 'full' and session.get('logged_in'):
            args = '-sT -p-'
            if options.get('version_detection'): args += ' -sV'
            if options.get('os_detection'):      args += ' -O'
            if options.get('aggressive'):        args += ' -A'
            nm.scan(target, arguments=args)

        results     = {}
        ports_found = 0

        if target in nm.all_hosts():
            host    = nm[target]
            results = {
                'host':      target,
                'state':     host.state(),
                'protocols': {},
                'os':        None,
            }
            if 'osmatch' in host and host['osmatch']:
                results['os'] = {
                    'name':     host['osmatch'][0].get('name', 'Unknown'),
                    'accuracy': host['osmatch'][0].get('accuracy', 0),
                }
            for proto in host.all_protocols():
                results['protocols'][proto] = {}
                for port in host[proto].keys():
                    ports_found += 1
                    p = host[proto][port]
                    results['protocols'][proto][port] = {
                        'state':     p.get('state',     'unknown'),
                        'name':      p.get('name',      ''),
                        'product':   p.get('product',   ''),
                        'version':   p.get('version',   ''),
                        'extrainfo': p.get('extrainfo', ''),
                    }
        else:
            results = {'host': target, 'state': 'down', 'protocols': {}, 'os': None}

        duration    = (datetime.utcnow() - start_time).total_seconds()
        scan_record = ScanHistory(
            target_ip    = target,
            requester_ip = requester_ip,
            scan_type    = scan_type,
            scan_options = json.dumps(options),
            results      = json.dumps(results),
            username     = session.get('username', 'anonymous'),
            duration     = duration,
            ports_found  = ports_found,
        )
        db.session.add(scan_record)
        db.session.commit()

        return jsonify({
            'success':  True,
            'results':  results,
            'scan_id':  scan_record.id,
            'duration': duration,
        })

    except Exception as e:
        app.logger.error(f"Scan error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# ─────────────────────────────────────────────────────────────
# History API
# ─────────────────────────────────────────────────────────────
@app.route('/api/scans', methods=['GET'])
def get_scans():
    page             = request.args.get('page',      1,  type=int)
    per_page         = request.args.get('per_page',  10, type=int)
    target_filter    = request.args.get('target',    '')
    scan_type_filter = request.args.get('scan_type', '')
    query = ScanHistory.query
    if target_filter:    query = query.filter(ScanHistory.target_ip.like(f'%{target_filter}%'))
    if scan_type_filter: query = query.filter(ScanHistory.scan_type == scan_type_filter)
    query      = query.order_by(ScanHistory.timestamp.desc())
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    return jsonify({
        'scans':        [s.to_dict() for s in pagination.items],
        'total':        pagination.total,
        'pages':        pagination.pages,
        'current_page': page,
    })

@app.route('/api/scans/<int:scan_id>', methods=['GET'])
def get_scan(scan_id):
    return jsonify(ScanHistory.query.get_or_404(scan_id).to_dict())

@app.route('/api/scans/<int:scan_id>', methods=['DELETE'])
@login_required
def delete_scan(scan_id):
    scan = ScanHistory.query.get_or_404(scan_id)
    db.session.delete(scan)
    db.session.commit()
    return jsonify({'success': True})

# ─────────────────────────────────────────────────────────────
# Export Routes
# ─────────────────────────────────────────────────────────────
@app.route('/api/scans/export/json', methods=['POST'])
def export_json():
    data      = request.get_json()
    scan      = ScanHistory.query.get_or_404(data.get('scan_id'))
    json_data = json.dumps(scan.to_dict(), indent=2)
    response  = app.response_class(response=json_data, status=200, mimetype='application/json')
    response.headers['Content-Disposition'] = \
        f'attachment; filename=scan_{scan.id}_{scan.target_ip}.json'
    return response

@app.route('/api/scans/export/pdf', methods=['POST'])
def export_pdf():
    data      = request.get_json()
    scan      = ScanHistory.query.get_or_404(data.get('scan_id'))
    scan_data = scan.to_dict()
    buffer    = BytesIO()
    doc       = SimpleDocTemplate(buffer, pagesize=letter)
    elements  = []
    styles    = getSampleStyleSheet()

    title_style = ParagraphStyle('T', parent=styles['Heading1'],
                                 fontSize=24, textColor=colors.HexColor('#2563eb'), spaceAfter=30)
    elements.append(Paragraph(f"Network Scan Report #{scan.id}", title_style))
    elements.append(Spacer(1, 0.2 * inch))

    info_data = [
        ['Scan Information', ''],
        ['Target IP',    scan.target_ip],
        ['Scan Type',    scan.scan_type.capitalize()],
        ['Requester IP', scan.requester_ip],
        ['Timestamp',    scan.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')],
        ['Duration',     f'{scan.duration:.2f} seconds'],
        ['Ports Found',  str(scan.ports_found)],
        ['Username',     scan.username],
    ]
    info_table = Table(info_data, colWidths=[2*inch, 4*inch])
    info_table.setStyle(TableStyle([
        ('BACKGROUND',    (0,0),(-1,0), colors.HexColor('#3b82f6')),
        ('TEXTCOLOR',     (0,0),(-1,0), colors.whitesmoke),
        ('ALIGN',         (0,0),(-1,-1),'LEFT'),
        ('FONTNAME',      (0,0),(-1,0), 'Helvetica-Bold'),
        ('FONTSIZE',      (0,0),(-1,0), 14),
        ('BOTTOMPADDING', (0,0),(-1,0), 12),
        ('BACKGROUND',    (0,1),(0,-1), colors.HexColor('#f3f4f6')),
        ('GRID',          (0,0),(-1,-1),1,colors.grey),
        ('FONTNAME',      (0,1),(0,-1), 'Helvetica-Bold'),
    ]))
    elements.append(info_table)
    elements.append(Spacer(1, 0.3*inch))

    results = scan_data['results']
    if results and results.get('protocols'):
        elements.append(Paragraph("Scan Results", styles['Heading2']))
        elements.append(Spacer(1, 0.1*inch))
        if results.get('os'):
            os_table = Table([
                ['Operating System',''],
                ['OS Name',  results['os']['name']],
                ['Accuracy', f"{results['os']['accuracy']}%"],
            ], colWidths=[2*inch,4*inch])
            os_table.setStyle(TableStyle([
                ('BACKGROUND',(0,0),(-1,0),colors.HexColor('#10b981')),
                ('TEXTCOLOR', (0,0),(-1,0),colors.whitesmoke),
                ('FONTNAME',  (0,0),(-1,0),'Helvetica-Bold'),
                ('GRID',      (0,0),(-1,-1),1,colors.grey),
            ]))
            elements.append(os_table)
            elements.append(Spacer(1, 0.2*inch))

        port_data = [['Port','State','Service','Version','Extra Info']]
        for proto, ports in results['protocols'].items():
            for port, info in ports.items():
                port_data.append([
                    f"{port}/{proto}", info.get('state',''),
                    info.get('name','') or 'Unknown',
                    f"{info.get('product','')} {info.get('version','')}".strip(),
                    info.get('extrainfo',''),
                ])
        pt = Table(port_data, colWidths=[1*inch,1*inch,1.5*inch,1.5*inch,2*inch])
        pt.setStyle(TableStyle([
            ('BACKGROUND',    (0,0),(-1,0),colors.HexColor('#ef4444')),
            ('TEXTCOLOR',     (0,0),(-1,0),colors.whitesmoke),
            ('FONTNAME',      (0,0),(-1,0),'Helvetica-Bold'),
            ('FONTSIZE',      (0,0),(-1,0),10),
            ('BOTTOMPADDING', (0,0),(-1,0),12),
            ('GRID',          (0,0),(-1,-1),1,colors.grey),
            ('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.white,colors.HexColor('#f9fafb')]),
        ]))
        elements.append(pt)
    else:
        elements.append(Paragraph("No open ports found.", styles['Normal']))

    elements.append(Spacer(1, 0.5*inch))
    elements.append(Paragraph(
        f"Generated by Network Security Tools Platform – https://nwscan.mooo.com<br/>"
        f"Report generated on {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
        ParagraphStyle('F', parent=styles['Normal'], fontSize=8, textColor=colors.grey)
    ))
    doc.build(elements)
    buffer.seek(0)
    return send_file(buffer, as_attachment=True,
                     download_name=f'scan_report_{scan.id}_{scan.target_ip}.pdf',
                     mimetype='application/pdf')

# ─────────────────────────────────────────────────────────────
# Statistics API
# ─────────────────────────────────────────────────────────────
@app.route('/api/statistics', methods=['GET'])
def get_statistics():
    total_scans     = ScanHistory.query.count()
    seven_days_ago  = datetime.utcnow() - timedelta(days=7)
    recent_scans    = ScanHistory.query.filter(ScanHistory.timestamp >= seven_days_ago).count()
    quick_scans     = ScanHistory.query.filter(ScanHistory.scan_type == 'quick').count()
    full_scans      = ScanHistory.query.filter(ScanHistory.scan_type == 'full').count()
    total_ports     = db.session.query(db.func.sum(ScanHistory.ports_found)).scalar() or 0
    avg_duration    = db.session.query(db.func.avg(ScanHistory.duration)).scalar() or 0
    top_targets     = db.session.query(
        ScanHistory.target_ip,
        db.func.count(ScanHistory.id).label('count')
    ).group_by(ScanHistory.target_ip).order_by(db.desc('count')).limit(5).all()
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    daily_scans     = db.session.query(
        db.func.date(ScanHistory.timestamp).label('date'),
        db.func.count(ScanHistory.id).label('count')
    ).filter(ScanHistory.timestamp >= thirty_days_ago).group_by('date').order_by('date').all()
    return jsonify({
        'total_scans':    total_scans,
        'recent_scans':   recent_scans,
        'quick_scans':    quick_scans,
        'full_scans':     full_scans,
        'total_ports':    total_ports,
        'avg_duration':   round(avg_duration, 2),
        'top_targets':    [{'ip': ip, 'count': c} for ip, c in top_targets],
        'daily_activity': [{'date': str(d), 'count': c} for d, c in daily_scans],
    })

# ─────────────────────────────────────────────────────────────
# Shared helper for web-based tools
# ─────────────────────────────────────────────────────────────
def _fetch_url(url: str):
    """Fetch a URL, return (response, BeautifulSoup). Raises on failure."""
    hdrs = {'User-Agent': 'Mozilla/5.0 (PageScanner/2.0)'}
    resp = requests.get(url, headers=hdrs, timeout=10, verify=False, allow_redirects=True)
    resp.raise_for_status()
    soup = BeautifulSoup(resp.text, 'html.parser')
    return resp, soup

def _validate_url(url: str):
    """Return (True, None) or (False, error_message)."""
    if not url:
        return False, "Missing 'url' parameter"
    try:
        p = urlparse(url)
        if p.scheme not in ('http', 'https'):
            return False, "URL must start with http:// or https://"
        if not p.netloc:
            return False, "Invalid URL"
    except Exception:
        return False, "Invalid URL"
    return True, None


# ─────────────────────────────────────────────────────────────
# Tool 1 – Security Headers Check
# ─────────────────────────────────────────────────────────────
SECURITY_HEADERS = {
    'Strict-Transport-Security':    {'desc': 'Enforces HTTPS (HSTS)',                    'severity': 'high'},
    'Content-Security-Policy':      {'desc': 'Mitigates XSS & injection attacks',        'severity': 'high'},
    'X-Content-Type-Options':       {'desc': 'Prevents MIME-type sniffing',              'severity': 'medium'},
    'X-Frame-Options':              {'desc': 'Protects against clickjacking',            'severity': 'medium'},
    'Permissions-Policy':           {'desc': 'Controls browser feature access',          'severity': 'low'},
    'Referrer-Policy':              {'desc': 'Controls referrer info in requests',       'severity': 'low'},
    'X-XSS-Protection':             {'desc': 'Legacy XSS filter (older browsers)',       'severity': 'low'},
    'Cross-Origin-Opener-Policy':   {'desc': 'Isolates browsing context',                'severity': 'low'},
    'Cross-Origin-Resource-Policy': {'desc': 'Prevents cross-origin resource leakage',  'severity': 'low'},
}

SEVERITY_POINTS = {'high': 3, 'medium': 2, 'low': 1}

@app.route('/api/security-headers', methods=['POST'])
@limiter.limit("20 per minute")
def security_headers():
    data = request.get_json()
    url  = (data.get('url') or '').strip()
    ok, err = _validate_url(url)
    if not ok:
        return jsonify({'error': err}), 400
    try:
        resp, _ = _fetch_url(url)
    except Exception as e:
        return jsonify({'error': str(e)}), 502

    results   = []
    score     = 0
    max_score = sum(SEVERITY_POINTS[v['severity']] for v in SECURITY_HEADERS.values())

    for header, meta in SECURITY_HEADERS.items():
        present = header in resp.headers
        if present:
            score += SEVERITY_POINTS[meta['severity']]
        results.append({
            'header':   header,
            'present':  present,
            'value':    resp.headers.get(header),
            'desc':     meta['desc'],
            'severity': meta['severity'],
        })

    pct   = round(score / max_score * 100)
    grade = 'A' if pct >= 90 else 'B' if pct >= 75 else 'C' if pct >= 60 else 'D' if pct >= 40 else 'F'

    return jsonify({
        'url': url, 'score': score, 'max_score': max_score,
        'grade': grade, 'grade_pct': pct, 'headers': results,
    })


# ─────────────────────────────────────────────────────────────
# Tool 2 – Accessibility Audit
# ─────────────────────────────────────────────────────────────
@app.route('/api/accessibility', methods=['POST'])
@limiter.limit("20 per minute")
def accessibility():
    data = request.get_json()
    url  = (data.get('url') or '').strip()
    ok, err = _validate_url(url)
    if not ok:
        return jsonify({'error': err}), 400
    try:
        _, soup = _fetch_url(url)
    except Exception as e:
        return jsonify({'error': str(e)}), 502

    issues = []
    passes = []

    # 1. Images without alt
    imgs        = soup.find_all('img')
    missing_alt = [str(i)[:120] for i in imgs if i.get('alt') is None]
    if missing_alt:
        issues.append({'rule': 'img-alt', 'impact': 'critical',
                       'desc': f'{len(missing_alt)} image(s) missing alt attribute',
                       'elements': missing_alt[:5]})
    else:
        passes.append({'rule': 'img-alt', 'desc': 'All images have alt attributes'})

    # 2. Inputs without labels
    inputs     = soup.find_all('input', type=lambda t: t not in ('hidden', 'submit', 'button', 'image', 'reset'))
    unlabeled  = []
    for inp in inputs:
        iid = inp.get('id')
        has_label = inp.get('aria-label') or inp.get('aria-labelledby') or \
                    (iid and soup.find('label', {'for': iid})) or inp.find_parent('label')
        if not has_label:
            unlabeled.append(str(inp)[:120])
    if unlabeled:
        issues.append({'rule': 'label', 'impact': 'critical',
                       'desc': f'{len(unlabeled)} input(s) missing label / aria-label',
                       'elements': unlabeled[:5]})
    else:
        passes.append({'rule': 'label', 'desc': 'All inputs have labels'})

    # 3. Page language
    html_tag = soup.find('html')
    if not (html_tag and html_tag.get('lang')):
        issues.append({'rule': 'html-lang', 'impact': 'serious',
                       'desc': '<html> element missing lang attribute', 'elements': []})
    else:
        passes.append({'rule': 'html-lang', 'desc': f'Page language set: {html_tag["lang"]}'})

    # 4. Page title
    title = soup.find('title')
    if not title or not title.get_text(strip=True):
        issues.append({'rule': 'document-title', 'impact': 'serious',
                       'desc': 'Page is missing a <title> element', 'elements': []})
    else:
        passes.append({'rule': 'document-title', 'desc': f'Page title: "{title.get_text(strip=True)}"'})

    # 5. Heading hierarchy
    headings = soup.find_all(re.compile(r'^h[1-6]$'))
    if headings:
        levels = [int(h.name[1]) for h in headings]
        skips  = [f'h{levels[i-1]}→h{levels[i]}' for i in range(1, len(levels))
                  if levels[i] - levels[i-1] > 1]
        if skips:
            issues.append({'rule': 'heading-order', 'impact': 'moderate',
                           'desc': f'Heading levels skipped: {", ".join(skips[:5])}', 'elements': []})
        else:
            passes.append({'rule': 'heading-order', 'desc': 'Heading hierarchy is correct'})
    else:
        issues.append({'rule': 'heading-order', 'impact': 'moderate',
                       'desc': 'No heading elements found on page', 'elements': []})

    # 6. Links with meaningful text
    links      = soup.find_all('a', href=True)
    empty_links = [str(a)[:120] for a in links
                   if not a.get_text(strip=True) and not a.find('img', alt=True)]
    if empty_links:
        issues.append({'rule': 'link-name', 'impact': 'serious',
                       'desc': f'{len(empty_links)} link(s) have no accessible text',
                       'elements': empty_links[:5]})
    else:
        passes.append({'rule': 'link-name', 'desc': 'All links have accessible text'})

    # 7. Colour-contrast placeholder (static analysis only)
    passes.append({'rule': 'meta-viewport',
                   'desc': 'Note: colour-contrast requires browser rendering (use Lighthouse for full audit)'})

    impact_order = {'critical': 0, 'serious': 1, 'moderate': 2, 'minor': 3}
    issues.sort(key=lambda x: impact_order.get(x['impact'], 9))

    score = round(len(passes) / (len(passes) + len(issues)) * 100) if (passes or issues) else 100
    return jsonify({
        'url': url, 'score': score,
        'issues_count': len(issues), 'passes_count': len(passes),
        'issues': issues, 'passes': passes,
    })


# ─────────────────────────────────────────────────────────────
# Tool 3 – Tech Stack Detection
# ─────────────────────────────────────────────────────────────
TECH_SIGNATURES = {
    'WordPress':        {'headers': [], 'html': [r'wp-content/', r'wp-includes/', r'/xmlrpc\.php'],                   'cookies': ['wordpress_', 'wp-settings-']},
    'Drupal':           {'headers': ['X-Generator: Drupal'], 'html': [r'Drupal\.settings', r'/sites/default/files/'], 'cookies': ['Drupal']},
    'Joomla':           {'headers': [], 'html': [r'/components/com_', r'Joomla!'],                                     'cookies': ['joomla_']},
    'Django':           {'headers': [], 'html': [],                                                                    'cookies': ['csrftoken', 'sessionid']},
    'Laravel':          {'headers': [], 'html': [],                                                                    'cookies': ['laravel_session', 'XSRF-TOKEN']},
    'React':            {'headers': [], 'html': [r'__react', r'data-reactroot', r'data-reactid'],                     'cookies': []},
    'Vue.js':           {'headers': [], 'html': [r'data-v-', r'__vue__', r'vue\.js', r'vue\.min\.js'],               'cookies': []},
    'Angular':          {'headers': [], 'html': [r'ng-version=', r'ng-app', r'angular\.js', r'angular\.min\.js'],    'cookies': []},
    'jQuery':           {'headers': [], 'html': [r'jquery[-\./]', r'jQuery'],                                         'cookies': []},
    'Bootstrap':        {'headers': [], 'html': [r'bootstrap\.css', r'bootstrap\.min\.css', r'bootstrap\.min\.js'],  'cookies': []},
    'Nginx':            {'headers': ['server: nginx'],   'html': [],                                                   'cookies': []},
    'Apache':           {'headers': ['server: apache'],  'html': [],                                                   'cookies': []},
    'Cloudflare':       {'headers': ['server: cloudflare', 'cf-ray'], 'html': [],                                     'cookies': ['__cfduid', '__cf_bm', 'cf_clearance']},
    'Google Analytics': {'headers': [], 'html': [r'google-analytics\.com', r'gtag\(', r'UA-\d+-\d+', r'G-[A-Z0-9]+'],'cookies': ['_ga', '_gid']},
    'Google Tag Mgr':   {'headers': [], 'html': [r'googletagmanager\.com', r'GTM-[A-Z0-9]+'],                         'cookies': []},
    'Stripe':           {'headers': [], 'html': [r'js\.stripe\.com'],                                                 'cookies': ['__stripe_sid', '__stripe_mid']},
    'Shopify':          {'headers': [], 'html': [r'cdn\.shopify\.com', r'Shopify\.theme'],                            'cookies': ['_shopify_']},
    'Next.js':          {'headers': ['x-powered-by: next.js'], 'html': [r'__NEXT_DATA__', r'next/dist'],             'cookies': []},
    'Nuxt.js':          {'headers': [], 'html': [r'__NUXT__', r'nuxt\.js'],                                           'cookies': []},
    'Python/Flask':     {'headers': ['server: werkzeug'],  'html': [],                                                'cookies': ['session']},
    'PHP':              {'headers': ['x-powered-by: php'], 'html': [r'\.php'],                                        'cookies': ['PHPSESSID']},
    'ASP.NET':          {'headers': ['x-powered-by: asp.net', 'x-aspnet-version'], 'html': [],                       'cookies': ['ASP.NET_SessionId', '.ASPXAUTH']},
    'Ruby on Rails':    {'headers': ['x-powered-by: phusion passenger'], 'html': [],                                  'cookies': ['_session_id']},
}

TECH_CATEGORIES = {
    'CMS':         ['WordPress','Drupal','Joomla','Shopify'],
    'JS Framework':['React','Vue.js','Angular','Next.js','Nuxt.js','jQuery'],
    'CSS Library': ['Bootstrap'],
    'Backend':     ['Django','Laravel','Python/Flask','PHP','ASP.NET','Ruby on Rails'],
    'Server':      ['Nginx','Apache'],
    'CDN/Security':['Cloudflare'],
    'Analytics':   ['Google Analytics','Google Tag Mgr'],
    'Payments':    ['Stripe'],
}

@app.route('/api/tech-stack', methods=['POST'])
@limiter.limit("20 per minute")
def tech_stack():
    data = request.get_json()
    url  = (data.get('url') or '').strip()
    ok, err = _validate_url(url)
    if not ok:
        return jsonify({'error': err}), 400
    try:
        resp, soup = _fetch_url(url)
    except Exception as e:
        return jsonify({'error': str(e)}), 502

    html_text   = resp.text
    resp_headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}
    cookies_str = ' '.join(resp.cookies.keys())
    detected    = []

    for tech, sigs in TECH_SIGNATURES.items():
        found = False
        # Check response headers
        for h in sigs['headers']:
            key, _, val = h.lower().partition(': ')
            if val:
                if key in resp_headers_lower and val in resp_headers_lower[key]:
                    found = True; break
            else:
                if key in resp_headers_lower:
                    found = True; break
        # Check HTML patterns
        if not found:
            for pattern in sigs['html']:
                if re.search(pattern, html_text, re.IGNORECASE):
                    found = True; break
        # Check cookies
        if not found:
            for ck in sigs['cookies']:
                if ck.lower() in cookies_str.lower():
                    found = True; break
        if found:
            category = next((c for c, techs in TECH_CATEGORIES.items() if tech in techs), 'Other')
            detected.append({'name': tech, 'category': category})

    # Extra server header info
    server_header = resp.headers.get('Server', '')
    x_powered_by  = resp.headers.get('X-Powered-By', '')
    meta_generator = ''
    gen_tag = soup.find('meta', attrs={'name': re.compile(r'generator', re.I)})
    if gen_tag:
        meta_generator = gen_tag.get('content', '')

    # Deduplicate and sort by category
    detected = sorted(detected, key=lambda x: x['category'])

    return jsonify({
        'url':            url,
        'detected':       detected,
        'count':          len(detected),
        'server_header':  server_header,
        'x_powered_by':   x_powered_by,
        'meta_generator': meta_generator,
        'response_code':  resp.status_code,
    })



# ═════════════════════════════════════════════════════════════
# ADVANCED TOOLS
# ═════════════════════════════════════════════════════════════

# ─────────────────────────────────────────────────────────────
# Tool A – DNS Lookup & Records
# ─────────────────────────────────────────────────────────────
DNS_RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'CAA']

@app.route('/api/dns-lookup', methods=['POST'])
@limiter.limit("30 per minute")
def dns_lookup():
    data   = request.get_json()
    domain = (data.get('domain') or '').strip()
    domain = re.sub(r'^https?://', '', domain).split('/')[0]
    if not domain:
        return jsonify({'error': 'Missing domain'}), 400

    results  = {}
    resolver = dns.resolver.Resolver()
    resolver.timeout  = 5
    resolver.lifetime = 5

    for rtype in DNS_RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, rtype)
            records = []
            for rdata in answers:
                if rtype == 'MX':
                    records.append({'priority': rdata.preference, 'exchange': str(rdata.exchange)})
                elif rtype == 'SOA':
                    records.append({'mname': str(rdata.mname), 'rname': str(rdata.rname),
                                    'serial': rdata.serial, 'refresh': rdata.refresh})
                else:
                    records.append(str(rdata))
            results[rtype] = {'found': True, 'records': records, 'ttl': answers.rrset.ttl}
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            results[rtype] = {'found': False, 'records': []}
        except Exception as e:
            results[rtype] = {'found': False, 'records': [], 'error': str(e)}

    reverse_dns = None
    try:
        if results.get('A', {}).get('records'):
            reverse_dns = socket.gethostbyaddr(results['A']['records'][0])[0]
    except Exception:
        pass

    return jsonify({'domain': domain, 'records': results, 'reverse_dns': reverse_dns})


# ─────────────────────────────────────────────────────────────
# Tool B – SSL/TLS Certificate Inspector
# ─────────────────────────────────────────────────────────────
def _parse_cert(cert, cipher, proto, bits, host):
    not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
    not_after  = datetime.strptime(cert['notAfter'],  '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
    now        = datetime.now(timezone.utc)
    days_left  = (not_after - now).days
    subject    = dict(x[0] for x in cert.get('subject', []))
    issuer     = dict(x[0] for x in cert.get('issuer',  []))
    sans       = [v for t, v in cert.get('subjectAltName', []) if t == 'DNS']
    weak_protos = ['SSLv2','SSLv3','TLSv1','TLSv1.1']
    cipher_grade = 'A'
    warnings = []
    if proto in weak_protos:
        cipher_grade = 'F'; warnings.append(f'Weak protocol: {proto}')
    if bits and int(bits) < 2048:
        cipher_grade = 'C'; warnings.append(f'Weak key: {bits} bits')
    if days_left < 0:
        warnings.append('Certificate EXPIRED')
    elif days_left < 30:
        warnings.append(f'Expires in {days_left} days')
    covered = any(s == host or (s.startswith('*.') and host.endswith(s[1:])) for s in sans) \
              or subject.get('commonName','') == host
    return {'host': host, 'subject': subject, 'issuer': issuer,
            'not_before': not_before.isoformat(), 'not_after': not_after.isoformat(),
            'days_left': days_left, 'sans': sans, 'cipher': cipher, 'protocol': proto,
            'key_bits': bits, 'cipher_grade': cipher_grade, 'warnings': warnings,
            'host_covered': covered, 'serial': cert.get('serialNumber',''),
            'version': cert.get('version','')}

@app.route('/api/ssl-inspect', methods=['POST'])
@limiter.limit("20 per minute")
def ssl_inspect():
    data = request.get_json()
    host = re.sub(r'^https?://', '', (data.get('host') or '').strip()).split('/')[0]
    port = int(data.get('port', 443))
    if not host:
        return jsonify({'error': 'Missing host'}), 400
    try:
        ctx  = ssl.create_default_context()
        conn = ctx.wrap_socket(socket.create_connection((host, port), timeout=10), server_hostname=host)
        cert = conn.getpeercert()
        cipher, proto, bits = conn.cipher()
        conn.close()
        parsed = _parse_cert(cert, cipher, proto, bits, host)
        parsed['valid'] = True
        return jsonify(parsed)
    except ssl.SSLCertVerificationError as e:
        try:
            ctx2 = ssl.create_default_context()
            ctx2.check_hostname = False; ctx2.verify_mode = ssl.CERT_NONE
            conn2 = ctx2.wrap_socket(socket.create_connection((host, port), timeout=10), server_hostname=host)
            cert = conn2.getpeercert(); cipher, proto, bits = conn2.cipher(); conn2.close()
            parsed = _parse_cert(cert, cipher, proto, bits, host)
            parsed['valid'] = False; parsed['error'] = str(e)
            return jsonify(parsed)
        except Exception as e2:
            return jsonify({'error': str(e2)}), 502
    except Exception as e:
        return jsonify({'error': str(e)}), 502


@app.route('/api/ssl-download', methods=['POST'])
@limiter.limit("10 per minute")
def ssl_download():
    """Download the PEM certificate chain for a host."""
    data = request.get_json()
    host = re.sub(r'^https?://', '', (data.get('host') or '').strip()).split('/')[0]
    port = int(data.get('port', 443))
    if not host:
        return jsonify({'error': 'Missing host'}), 400
    try:
        # Get full PEM chain
        import ssl as _ssl, OpenSSL
        ctx  = OpenSSL.SSL.Context(OpenSSL.SSL.TLS_CLIENT_METHOD)
        ctx.set_verify(OpenSSL.SSL.VERIFY_NONE, lambda *a: True)
        conn = OpenSSL.SSL.Connection(ctx, socket.create_connection((host, port), timeout=10))
        conn.set_tlsext_host_name(host.encode())
        conn.set_connect_state()
        conn.do_handshake()
        chain     = conn.get_peer_cert_chain()
        conn.close()
        pem_chain = ''
        cert_info = []
        for cert in chain:
            pem  = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert).decode()
            subj = cert.get_subject()
            pem_chain += pem
            cert_info.append({
                'cn':         subj.CN,
                'org':        subj.O,
                'not_after':  cert.get_notAfter().decode(),
                'serial':     str(cert.get_serial_number()),
                'issuer_cn':  cert.get_issuer().CN,
            })
        response = app.response_class(
            response=pem_chain,
            status=200,
            mimetype='application/x-pem-file'
        )
        response.headers['Content-Disposition'] = f'attachment; filename={host}_cert_chain.pem'
        return response
    except ImportError:
        # Fallback without pyOpenSSL – single cert only
        try:
            ctx2 = ssl.create_default_context()
            ctx2.check_hostname = False; ctx2.verify_mode = ssl.CERT_NONE
            conn2 = ctx2.wrap_socket(socket.create_connection((host, port), timeout=10), server_hostname=host)
            der  = conn2.getpeercert(binary_form=True)
            conn2.close()
            import base64
            pem  = '-----BEGIN CERTIFICATE-----\n'
            pem += base64.encodebytes(der).decode()
            pem += '-----END CERTIFICATE-----\n'
            response = app.response_class(response=pem, status=200, mimetype='application/x-pem-file')
            response.headers['Content-Disposition'] = f'attachment; filename={host}.pem'
            return response
        except Exception as e2:
            return jsonify({'error': str(e2)}), 502
    except Exception as e:
        return jsonify({'error': str(e)}), 502


# ─────────────────────────────────────────────────────────────
# Tool C – Subdomain Enumerator  (auth required)
# ─────────────────────────────────────────────────────────────
SUBDOMAIN_WORDLIST = [
    # Common
    'www','www2','www3','mail','mail2','smtp','pop','pop3','imap','mx','mx1','mx2',
    'ns','ns1','ns2','ns3','ns4','dns','dns1','dns2',
    # Infrastructure
    'ftp','sftp','ssh','vpn','vpn2','remote','rdp','citrix',
    'proxy','proxy2','gateway','firewall','edge','lb','load','haproxy',
    # Web / App
    'api','api2','api3','rest','graphql','ws','websocket',
    'app','app2','apps','web','webmail','portal','panel','cp','admin','administrator',
    'backend','internal','intranet','extranet','private',
    # Dev / Staging
    'dev','dev2','development','staging','stage','uat','qa','test','test2','testing',
    'sandbox','demo','preview','preprod','pre','beta','alpha','lab','labs',
    # CDN / Static
    'cdn','cdn2','static','assets','media','img','images','files','uploads',
    'download','downloads','s3','storage','bucket',
    # Business Apps
    'blog','shop','store','ecommerce','cart','checkout','pay','payment',
    'docs','documentation','wiki','kb','knowledge','help','support','helpdesk','desk',
    'forum','community','chat','slack','teams',
    'crm','erp','hr','finance','billing','invoice','accounting',
    # Monitoring / DevOps
    'git','gitlab','github','bitbucket','svn','repo',
    'ci','jenkins','travis','circleci','drone','pipeline',
    'jira','confluence','trello','asana','notion','monday',
    'monitoring','grafana','kibana','elastic','prometheus','nagios','zabbix',
    'status','uptime','health','metrics','logs','logging',
    'dashboard','analytics','stats','reports',
    # Auth / Security
    'auth','sso','oauth','login','logout','signin','signup','register','account',
    'id','identity','iam','ldap','ad','directory',
    # Cloud / Infra
    'cloud','aws','azure','gcp','k8s','kubernetes','docker','rancher',
    'db','database','mysql','postgres','postgresql','mongo','redis','elastic','solr',
    'cache','memcache','rabbit','kafka','queue','worker',
    'backup','archive','vault','secrets',
    # Mobile / Social
    'm','mobile','wap','touch','ios','android',
    'meet','video','zoom','calendar','autodiscover','exchange',
    # Geographic / Regional
    'us','eu','uk','de','fr','au','ca','asia','global',
    # Misc
    'old','new','v2','v3','next','legacy','classic','secure','ssl','office',
]

@app.route('/api/subdomain-enum', methods=['POST'])
@limiter.limit("5 per minute")
@login_required
def subdomain_enum():
    import subprocess, platform
    data   = request.get_json()
    domain = re.sub(r'^https?://', '', (data.get('domain') or '').strip()).split('/')[0]
    if not domain:
        return jsonify({'error': 'Missing domain'}), 400

    found    = []
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2; resolver.lifetime = 2

    def ping_host(fqdn):
        """Returns True if host responds to ping."""
        try:
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            result = subprocess.run(
                ['ping', param, '1', '-W', '1', fqdn],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=3
            )
            return result.returncode == 0
        except Exception:
            return False

    def check_sub(sub):
        fqdn = f'{sub}.{domain}'
        try:
            ans  = resolver.resolve(fqdn, 'A')
            ips  = [str(r) for r in ans]
            # HTTP probe
            http_status = None; https_status = None; final_url = None
            for scheme in ('https', 'http'):
                try:
                    r = requests.get(f'{scheme}://{fqdn}', timeout=3, verify=False, allow_redirects=True)
                    if scheme == 'https': https_status = r.status_code
                    else:                http_status  = r.status_code
                    final_url = r.url
                    break
                except Exception:
                    pass
            # Ping check
            ping_ok = ping_host(fqdn)
            return {
                'subdomain':    fqdn,
                'ips':          ips,
                'http_status':  http_status,
                'https_status': https_status,
                'final_url':    final_url,
                'ping':         ping_ok,
                'online':       ping_ok or bool(http_status) or bool(https_status),
                'alive':        True,
            }
        except Exception:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
        futures = {ex.submit(check_sub, s): s for s in SUBDOMAIN_WORDLIST}
        for f in concurrent.futures.as_completed(futures):
            result = f.result()
            if result:
                found.append(result)

    found.sort(key=lambda x: (not x['online'], x['subdomain']))
    online  = [f for f in found if f['online']]
    offline = [f for f in found if not f['online']]
    return jsonify({
        'domain':  domain, 'found': found,
        'count':   len(found), 'online_count': len(online),
        'offline_count': len(offline), 'checked': len(SUBDOMAIN_WORDLIST),
    })


# ─────────────────────────────────────────────────────────────
# Tool D – HTTP Response Analyser
# ─────────────────────────────────────────────────────────────
@app.route('/api/http-analyse', methods=['POST'])
@limiter.limit("30 per minute")
def http_analyse():
    data = request.get_json()
    url  = (data.get('url') or '').strip()
    ok, err = _validate_url(url)
    if not ok:
        return jsonify({'error': err}), 400
    try:
        import time
        start = time.time()
        resp  = requests.get(url, headers={'User-Agent':'PageScanner/2.0'},
                             timeout=10, verify=False, allow_redirects=True)
        elapsed_ms = round((time.time() - start) * 1000)
    except Exception as e:
        return jsonify({'error': str(e)}), 502

    redirect_chain = [{'url': r.url, 'status': r.status_code,
                        'location': r.headers.get('Location','')} for r in resp.history]
    interesting = {k: v for k, v in {
        'Content-Type': resp.headers.get('Content-Type',''),
        'Content-Encoding': resp.headers.get('Content-Encoding',''),
        'Cache-Control': resp.headers.get('Cache-Control',''),
        'Vary': resp.headers.get('Vary',''),
        'ETag': resp.headers.get('ETag',''),
        'Via': resp.headers.get('Via',''),
    }.items() if v}
    leaks = [{'header': h, 'value': resp.headers[h]}
             for h in ['Server','X-Powered-By','X-AspNet-Version','X-Generator','X-Varnish']
             if h in resp.headers]
    return jsonify({
        'url': url, 'final_url': resp.url, 'status_code': resp.status_code,
        'reason': resp.reason, 'elapsed_ms': elapsed_ms,
        'redirect_chain': redirect_chain, 'redirect_count': len(redirect_chain),
        'headers': dict(resp.headers), 'interesting': interesting,
        'info_leaks': leaks, 'content_length': len(resp.content),
        'compressed': 'gzip' in resp.headers.get('Content-Encoding','').lower(),
    })


# ─────────────────────────────────────────────────────────────
# Tool E – Open Redirect Checker
# ─────────────────────────────────────────────────────────────
REDIRECT_PAYLOADS = ['https://evil.com','//evil.com','/\\evil.com','///evil.com','/%2F%2Fevil.com']
REDIRECT_PARAMS   = ['redirect','redirect_to','url','next','dest','destination','go','return',
                     'returnTo','return_url','continue','forward','location','out','target','redir']

@app.route('/api/open-redirect', methods=['POST'])
@limiter.limit("10 per minute")
def open_redirect():
    data = request.get_json()
    url  = (data.get('url') or '').strip()
    ok, err = _validate_url(url)
    if not ok:
        return jsonify({'error': err}), 400

    vulnerable = []
    tested     = []

    def test_redirect(param, payload):
        sep = '&' if '?' in url else '?'
        test_url = f'{url}{sep}{param}={requests.utils.quote(payload)}'
        try:
            r = requests.get(test_url, timeout=5, allow_redirects=True, verify=False,
                             headers={'User-Agent':'PageScanner/2.0'})
            vuln = 'evil.com' in r.url or any('evil.com' in h.headers.get('Location','') for h in r.history)
            return {'param': param, 'payload': payload, 'final_url': r.url, 'vulnerable': vuln}
        except Exception as e:
            return {'param': param, 'payload': payload, 'error': str(e), 'vulnerable': False}

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        futures = [ex.submit(test_redirect, p, pay)
                   for p in REDIRECT_PARAMS[:8] for pay in REDIRECT_PAYLOADS[:3]]
        for f in concurrent.futures.as_completed(futures):
            result = f.result()
            tested.append(result)
            if result.get('vulnerable'):
                vulnerable.append(result)

    return jsonify({'url': url, 'vulnerable': len(vulnerable) > 0,
                    'vulns': vulnerable, 'tested': len(tested),
                    'params_tested': REDIRECT_PARAMS[:8]})


# ─────────────────────────────────────────────────────────────
# Tool F – CORS Policy Checker
# ─────────────────────────────────────────────────────────────
CORS_TEST_ORIGINS = ['https://evil.com','https://attacker.com','null','https://sub.evil.com']

@app.route('/api/cors-check', methods=['POST'])
@limiter.limit("20 per minute")
def cors_check():
    data = request.get_json()
    url  = (data.get('url') or '').strip()
    ok, err = _validate_url(url)
    if not ok:
        return jsonify({'error': err}), 400

    results = []; issues = []
    for origin in CORS_TEST_ORIGINS:
        try:
            hdrs = {'Origin': origin, 'User-Agent': 'PageScanner/2.0'}
            r    = requests.options(url, headers=hdrs, timeout=8, verify=False)
            if r.status_code == 405:
                r = requests.get(url, headers=hdrs, timeout=8, verify=False)
            acao = r.headers.get('Access-Control-Allow-Origin','')
            acac = r.headers.get('Access-Control-Allow-Credentials','')
            reflected = acao == origin; wildcard = acao == '*'; null_ok = acao == 'null'
            entry = {'origin': origin, 'acao': acao, 'acac': acac,
                     'acam': r.headers.get('Access-Control-Allow-Methods',''),
                     'reflected': reflected, 'wildcard': wildcard, 'null_allowed': null_ok,
                     'status': r.status_code}
            results.append(entry)
            if wildcard and acac.lower() == 'true':
                issues.append({'severity':'critical','origin':origin,'desc':'Wildcard ACAO + credentials=true – full bypass'})
            elif reflected and acac.lower() == 'true':
                issues.append({'severity':'high','origin':origin,'desc':f'Origin reflected with credentials – {origin} can read responses'})
            elif reflected:
                issues.append({'severity':'medium','origin':origin,'desc':f'Origin reflected – {origin} can read responses'})
            elif null_ok:
                issues.append({'severity':'medium','origin':origin,'desc':'Null origin accepted – sandboxed iframe bypass possible'})
        except Exception as e:
            results.append({'origin': origin, 'error': str(e)})

    issues.sort(key=lambda x: {'critical':0,'high':1,'medium':2,'low':3}.get(x['severity'],9))
    return jsonify({'url': url, 'vulnerable': len(issues) > 0, 'issues': issues,
                    'results': results, 'cors_present': any(r.get('acao') for r in results)})


# ─────────────────────────────────────────────────────────────
# Tool G – Cookie Security Analyser
# ─────────────────────────────────────────────────────────────
def _detect_hash_type(value):
    """Detect common hash/encoding types from cookie value."""
    import hashlib, base64 as b64
    v = value.strip()
    length = len(v)
    is_hex = bool(re.match(r'^[0-9a-fA-F]+$', v))
    is_b64 = False
    try:
        decoded = b64.b64decode(v + '==')
        is_b64  = True
    except Exception:
        pass
    is_b64url = bool(re.match(r'^[A-Za-z0-9\-_]+={0,2}$', v) and length % 4 <= 2)

    # JWT check
    parts = v.split('.')
    if len(parts) == 3:
        try:
            b64.urlsafe_b64decode(parts[0] + '==')
            return 'JWT (JSON Web Token)', 'jwt'
        except Exception:
            pass

    # Hex hash lengths
    if is_hex:
        if length == 32:  return 'MD5 hash (128-bit)', 'md5'
        if length == 40:  return 'SHA-1 hash (160-bit)', 'sha1'
        if length == 56:  return 'SHA-224 hash', 'sha224'
        if length == 64:  return 'SHA-256 hash (256-bit)', 'sha256'
        if length == 96:  return 'SHA-384 hash', 'sha384'
        if length == 128: return 'SHA-512 hash (512-bit)', 'sha512'
        if length == 8:   return 'CRC32 checksum', 'crc32'
        return f'Hex-encoded data ({length} chars)', 'hex'

    # Base64
    if is_b64url and '.' not in v:
        return 'Base64URL encoded', 'base64url'
    if is_b64:
        return 'Base64 encoded', 'base64'

    # Flask / Django session patterns
    if v.startswith('.') and '.' in v[1:]:
        return 'Flask signed session cookie', 'flask_session'
    if len(v) > 40 and ':' in v:
        return 'Django signed cookie', 'django_session'

    # UUID
    if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', v, re.I):
        return 'UUID / GUID', 'uuid'

    return 'Plaintext / unknown', 'unknown'


def _encode_decode_value(value, hash_type):
    """Return encode/decode options for a cookie value."""
    import base64 as b64
    result = {}
    v = value.strip()
    try:
        if hash_type == 'base64':
            result['decoded'] = b64.b64decode(v + '==').decode('utf-8', errors='replace')
        elif hash_type == 'base64url':
            result['decoded'] = b64.urlsafe_b64decode(v + '==').decode('utf-8', errors='replace')
        elif hash_type == 'hex':
            result['decoded'] = bytes.fromhex(v).decode('utf-8', errors='replace')
        elif hash_type == 'jwt':
            parts = v.split('.')
            result['header']  = b64.urlsafe_b64decode(parts[0]+'==').decode('utf-8',errors='replace')
            result['payload'] = b64.urlsafe_b64decode(parts[1]+'==').decode('utf-8',errors='replace')
            result['note']    = 'Signature not verified – decode only'
        elif hash_type == 'flask_session':
            payload = v.split('.')[0].lstrip('.')
            result['decoded'] = b64.urlsafe_b64decode(payload+'==').decode('utf-8',errors='replace')
        # Always offer re-encode options
        result['as_base64']    = b64.b64encode(v.encode()).decode()
        result['as_base64url'] = b64.urlsafe_b64encode(v.encode()).decode()
        result['as_hex']       = v.encode().hex()
    except Exception as e:
        result['error'] = str(e)
    return result


@app.route('/api/cookie-security', methods=['POST'])
@limiter.limit("20 per minute")
def cookie_security():
    data = request.get_json()
    url  = (data.get('url') or '').strip()
    ok, err = _validate_url(url)
    if not ok:
        return jsonify({'error': err}), 400
    try:
        # Use a full browser-like headers to capture more cookies
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        sess = requests.Session()
        # Follow all redirects to capture cookies set at each hop
        resp = sess.get(url, headers=headers, timeout=10, verify=False, allow_redirects=True)
        # Also check Set-Cookie headers directly from raw response
        raw_cookies = []
        for r in list(resp.history) + [resp]:
            for sc in r.headers.getlist('Set-Cookie') if hasattr(r.headers,'getlist') else []:
                raw_cookies.append(sc)
    except Exception as e:
        return jsonify({'error': str(e)}), 502

    analysed   = []
    is_https   = url.startswith('https://')
    seen_names = set()
    sensitive_patterns = ['session','sess','auth','token','jwt','csrf','xsrf',
                          'login','user','id','uid','sid','key','secret','pass','pwd']

    for cookie in sess.cookies:
        if cookie.name in seen_names:
            continue
        seen_names.add(cookie.name)

        flags    = cookie._rest if hasattr(cookie,'_rest') else {}
        secure   = bool(cookie.secure)
        httponly = 'httponly' in str(flags).lower()
        samesite = flags.get('SameSite') or flags.get('samesite') or ''
        raw_val  = cookie.value or ''

        # Hash / encoding detection
        hash_label, hash_type = _detect_hash_type(raw_val)
        encode_decode          = _encode_decode_value(raw_val, hash_type)

        issues = []; score = 100
        if not secure:
            issues.append({'severity':'high','desc':'Missing Secure flag – sent over HTTP'}); score -= 30
        if not httponly:
            issues.append({'severity':'high','desc':'Missing HttpOnly – readable via JavaScript (XSS risk)'}); score -= 30
        if not samesite:
            issues.append({'severity':'medium','desc':'Missing SameSite – vulnerable to CSRF'}); score -= 20
        elif samesite.lower() == 'none' and not secure:
            issues.append({'severity':'high','desc':'SameSite=None requires Secure flag'}); score -= 20
        if hash_type == 'unknown' and len(raw_val) < 8:
            issues.append({'severity':'low','desc':'Very short cookie value – may be predictable'})
        if hash_type in ('md5','sha1'):
            issues.append({'severity':'medium','desc':f'{hash_label} is considered weak for session tokens'})

        analysed.append({
            'name':         cookie.name,
            'value':        raw_val[:40] + '…' if len(raw_val) > 40 else raw_val,
            'raw_value':    raw_val,
            'domain':       cookie.domain or '',
            'path':         cookie.path or '/',
            'secure':       secure,
            'httponly':     httponly,
            'samesite':     samesite or 'Not set',
            'expires':      cookie.expires,
            'is_sensitive': any(p in cookie.name.lower() for p in sensitive_patterns),
            'hash_type':    hash_label,
            'hash_key':     hash_type,
            'encode_decode':encode_decode,
            'issues':       issues,
            'score':        max(score, 0),
        })

    analysed.sort(key=lambda x: x['score'])
    return jsonify({
        'url':          url,
        'cookie_count': len(analysed),
        'total_issues': sum(len(c['issues']) for c in analysed),
        'avg_score':    round(sum(c['score'] for c in analysed)/len(analysed)) if analysed else 100,
        'cookies':      analysed,
        'is_https':     is_https,
        'note':         'No cookies found – site may set cookies via JavaScript (not captured by server-side requests)' if not analysed else None,
    })


# ─────────────────────────────────────────────────────────────
# Tool H – Email Security Checker (SPF / DKIM / DMARC)
# ─────────────────────────────────────────────────────────────
@app.route('/api/email-security', methods=['POST'])
@limiter.limit("20 per minute")
def email_security():
    data   = request.get_json()
    domain = re.sub(r'^https?://', '', (data.get('domain') or '').strip()).split('/')[0]
    if not domain:
        return jsonify({'error': 'Missing domain'}), 400

    resolver = dns.resolver.Resolver(); resolver.timeout = 5; resolver.lifetime = 5
    results  = {}

    # SPF
    try:
        ans  = resolver.resolve(domain, 'TXT')
        spfs = [str(r).strip('"') for r in ans if 'v=spf1' in str(r).lower()]
        if spfs:
            spf_val = spfs[0]; all_m = re.search(r'[~\-\+\?]all', spf_val)
            policy  = all_m.group() if all_m else '?all'; strict = policy.startswith('-')
            results['spf'] = {
                'found':True,'record':spf_val,'policy':policy,'strict':strict,
                'warning': None if strict else 'Use -all for strict enforcement',
                'plain_english': (
                    '✅ Your domain is protected. Only listed servers can send email on your behalf.'
                    if strict else
                    '⚠️ Partial protection. Unauthorised servers get a "soft fail" – emails may still be delivered.'
                ),
            }
        else:
            results['spf'] = {
                'found':False,
                'warning':'No SPF record found',
                'plain_english':'❌ Anyone can send emails pretending to be from your domain. Add an SPF record immediately.',
            }
    except Exception as e:
        results['spf'] = {'found':False,'error':str(e)}

    # DMARC
    try:
        ans    = resolver.resolve(f'_dmarc.{domain}', 'TXT')
        dmarcs = [str(r).strip('"') for r in ans if 'v=dmarc1' in str(r).lower()]
        if dmarcs:
            dm_val = dmarcs[0]; p_m = re.search(r'p=(none|quarantine|reject)', dm_val, re.I)
            policy = p_m.group(1).lower() if p_m else 'none'
            rua_m  = re.search(r'rua=([^;]+)', dm_val)
            warn   = None
            plain = ''
            if policy=='none':
                warn = 'DMARC p=none – monitoring only, emails not rejected'
                plain = '⚠️ DMARC is watching but not blocking. Phishing emails from your domain are still delivered.'
            elif policy=='quarantine':
                warn = 'Consider upgrading to p=reject for full protection'
                plain = '⚠️ Suspicious emails go to spam. Good, but p=reject would give full protection.'
            else:
                plain = '✅ Phishing emails claiming to be from your domain are rejected outright.'
            results['dmarc'] = {
                'found':True,'record':dm_val,'policy':policy,
                'rua': rua_m.group(1) if rua_m else None,
                'warning':warn, 'plain_english': plain,
            }
        else:
            results['dmarc'] = {
                'found':False,
                'warning':'No DMARC record found',
                'plain_english':'❌ No DMARC policy. Attackers can send phishing emails appearing to come from your domain.',
            }
    except Exception as e:
        results['dmarc'] = {'found':False,'error':str(e)}

    # DKIM (common selectors)
    dkim_found = []
    for sel in ['default','google','mail','dkim','k1','s1','s2','selector1','selector2','smtp']:
        try:
            ans = resolver.resolve(f'{sel}._domainkey.{domain}', 'TXT')
            for r in ans:
                val = str(r).strip('"')
                if 'p=' in val.lower():
                    dkim_found.append({'selector':sel,'record':val[:120]}); break
        except Exception:
            pass
    results['dkim'] = {
        'found':bool(dkim_found),'selectors':dkim_found,
        'warning': None if dkim_found else 'No DKIM records found with common selectors',
        'plain_english': (
            f'✅ Email signing active on {len(dkim_found)} selector(s). Recipients can verify emails genuinely came from you.'
            if dkim_found else
            '❌ No DKIM found. Emails from your domain cannot be cryptographically verified. Common selectors checked – your provider may use a custom one.'
        ),
    }

    # MTA-STS
    try:
        ans = resolver.resolve(f'_mta-sts.{domain}', 'TXT')
        mta = [str(r).strip('"') for r in ans]
        results['mta_sts'] = {
            'found':bool(mta),'record':mta[0] if mta else None,
            'plain_english': '✅ Mail servers are required to use encryption when delivering to your domain.' if mta else '⚠️ No MTA-STS. Email delivery to your domain may occur over unencrypted connections.',
        }
    except Exception:
        results['mta_sts'] = {
            'found':False,
            'plain_english':'⚠️ No MTA-STS. Email delivery to your domain may occur over unencrypted connections.',
        }

    score = 0
    if results['spf'].get('found'):   score += 25 + (10 if results['spf'].get('strict') else 0)
    if results['dmarc'].get('found'):
        p = results['dmarc'].get('policy','none')
        score += 25 + (10 if p=='reject' else 5 if p=='quarantine' else 0)
    if results['dkim'].get('found'):  score += 25
    if results['mta_sts'].get('found'): score += 5

    return jsonify({'domain':domain,'score':min(score,100),'results':results})


# ─────────────────────────────────────────────────────────────
# Tool I – CSP Analyser  (defensive)
# ─────────────────────────────────────────────────────────────
UNSAFE_CSP = {
    "'unsafe-inline'": {'severity':'high','desc':"Allows inline scripts – negates XSS protection"},
    "'unsafe-eval'":   {'severity':'high','desc':"Allows eval() – code injection vector"},
    'data:':           {'severity':'medium','desc':"data: URIs can load malicious content"},
    '*':               {'severity':'high','desc':"Wildcard source – any origin allowed"},
    'http:':           {'severity':'medium','desc':"Allows plain HTTP resource loading"},
}
IMPORTANT_CSP_DIRS = ['default-src','script-src','style-src','img-src','connect-src',
                      'object-src','base-uri','frame-ancestors','form-action','upgrade-insecure-requests']

@app.route('/api/csp-analyse', methods=['POST'])
@limiter.limit("20 per minute")
def csp_analyse():
    data = request.get_json()
    url  = (data.get('url') or '').strip()
    ok, err = _validate_url(url)
    if not ok:
        return jsonify({'error': err}), 400
    try:
        resp = requests.get(url, headers={'User-Agent':'PageScanner/2.0'}, timeout=10, verify=False, allow_redirects=True)
    except Exception as e:
        return jsonify({'error': str(e)}), 502

    csp_header = resp.headers.get('Content-Security-Policy','')
    csp_ro     = resp.headers.get('Content-Security-Policy-Report-Only','')
    if not csp_header and not csp_ro:
        return jsonify({'url':url,'csp_present':False,'issues':[
            {'severity':'critical','directive':'N/A','desc':'No CSP header – XSS attacks unrestricted'}],'directives':{},'score':0})

    active_csp  = csp_header or csp_ro
    report_only = not bool(csp_header)
    directives  = {}
    for part in active_csp.split(';'):
        part = part.strip()
        if part:
            tokens = part.split()
            if tokens:
                directives[tokens[0].lower()] = tokens[1:]

    issues = []; good = []; seen_issues = set()
    for directive, sources in directives.items():
        for src in sources:
            for unsafe, meta in UNSAFE_CSP.items():
                if unsafe.lower() in src.lower():
                    # Deduplicate: only one issue per (directive, unsafe_pattern) combo
                    dedup_key = f'{directive}:{unsafe}'
                    if dedup_key not in seen_issues:
                        seen_issues.add(dedup_key)
                        issues.append({'severity':meta['severity'],'directive':directive,'value':src,'desc':meta['desc']})

    if 'default-src' not in directives:
        issues.append({'severity':'high','directive':'default-src','desc':'Missing default-src'})
    if 'base-uri' not in directives:
        issues.append({'severity':'medium','directive':'base-uri','desc':'Missing base-uri – base tag injection possible'})
    if 'frame-ancestors' not in directives:
        issues.append({'severity':'medium','directive':'frame-ancestors','desc':'Clickjacking protection absent in CSP'})
    if report_only:
        issues.append({'severity':'medium','directive':'N/A','desc':'CSP is report-only – not enforced'})
    if 'upgrade-insecure-requests' in directives:
        good.append('upgrade-insecure-requests enforced')
    if 'form-action' in directives:
        good.append('form-action restricted')

    issues.sort(key=lambda x: {'critical':0,'high':1,'medium':2,'low':3}.get(x['severity'],9))
    score = max(0, 100 - len([i for i in issues if i['severity']=='critical'])*40
                       - len([i for i in issues if i['severity']=='high'])*20
                       - len([i for i in issues if i['severity']=='medium'])*10)
    return jsonify({'url':url,'csp_present':True,'report_only':report_only,'raw_csp':active_csp[:500],
                    'directives':{k:v for k,v in directives.items()},'issues':issues,'good_parts':good,
                    'score':score,'directive_coverage':[d for d in IMPORTANT_CSP_DIRS if d in directives],
                    'missing_directives':[d for d in IMPORTANT_CSP_DIRS if d not in directives]})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
