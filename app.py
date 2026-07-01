# ---------------------------------------------------------------------------
# corp-api / app.py — REST API v1.0.0
# WSGI puro sin frameworks — Passenger-compatible
# ---------------------------------------------------------------------------
import base64, hashlib, hmac, json, os, subprocess, time, urllib.parse
from datetime import date, datetime
from decimal import Decimal

try:
    import pymysql, pymysql.cursors
    DB_AVAILABLE = True
except ImportError:
    DB_AVAILABLE = False

SERVER_NAME    = 'corp-api'
SERVER_VERSION = '1.0.6'

DB_HOST      = os.environ.get('DB_HOST',      'localhost')
DB_PORT      = int(os.environ.get('DB_PORT',  3306))
DB_USER      = os.environ.get('DB_USER',      '')
DB_PASS      = os.environ.get('DB_PASSWORD',  '')
DB_NAME      = os.environ.get('DB_NAME',      'PINTUADM')
DB_ADMIN     = 'apiAdmin'
JWT_SECRET   = os.environ.get('JWT_SECRET',   '')
JWT_EXP      = 86400   # 24 horas
INTERNAL_KEY = os.environ.get('INTERNAL_KEY', '')
RELOAD_TOKEN = os.environ.get('RELOAD_TOKEN', '')
BASE_URL     = os.environ.get('BASE_URL',     'https://api.pintuandes.com')


# ---------------------------------------------------------------------------
# JSON encoder
# ---------------------------------------------------------------------------

class _Enc(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (date, datetime)): return obj.isoformat()
        if isinstance(obj, Decimal):          return float(obj)
        return super().default(obj)

def _dumps(obj):
    return json.dumps(obj, cls=_Enc, ensure_ascii=False)


# ---------------------------------------------------------------------------
# WSGI helpers
# ---------------------------------------------------------------------------

def _parse_qs(qs):
    out = {}
    for part in (qs or '').split('&'):
        if '=' in part:
            k, v = part.split('=', 1)
            out[urllib.parse.unquote_plus(k)] = urllib.parse.unquote_plus(v)
    return out

def _read_body(environ):
    try:
        n = int(environ.get('CONTENT_LENGTH') or 0)
        return environ['wsgi.input'].read(n) if n > 0 else b''
    except Exception:
        return b''

_STATUS = {
    200: '200 OK',          201: '201 Created',
    204: '204 No Content',  400: '400 Bad Request',
    401: '401 Unauthorized',403: '403 Forbidden',
    404: '404 Not Found',   405: '405 Method Not Allowed',
    500: '500 Internal Server Error', 503: '503 Service Unavailable',
}

_CORS = [
    ('Access-Control-Allow-Origin',  '*'),
    ('Access-Control-Allow-Headers', 'Authorization, Content-Type, X-Internal-Key'),
    ('Access-Control-Allow-Methods', 'GET, POST, OPTIONS'),
]

def _resp(start_response, code, data):
    body = _dumps(data).encode('utf-8')
    headers = ([('Content-Type',   'application/json; charset=utf-8'),
                ('Content-Length', str(len(body))),
                ('Cache-Control',  'no-store')]
               + _CORS)
    start_response(_STATUS.get(code, f'{code} Unknown'), headers)
    return [body]


# ---------------------------------------------------------------------------
# Base de datos
# ---------------------------------------------------------------------------

def _get_db(database=None):
    return pymysql.connect(
        host=DB_HOST, port=DB_PORT,
        user=DB_USER, password=DB_PASS,
        database=database or DB_NAME,
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True, connect_timeout=10,
    )

def _query(sql, params=None, db=None):
    conn = _get_db(db)
    try:
        with conn.cursor() as cur:
            cur.execute(sql, params or ())
            return cur.fetchall()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# JWT — HMAC-SHA256 (stdlib)
# ---------------------------------------------------------------------------

def _b64u(data):
    if isinstance(data, str): data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def _jwt_sign(payload):
    hdr  = _b64u(json.dumps({'alg': 'HS256', 'typ': 'JWT'}, separators=(',', ':')))
    body = _b64u(json.dumps(payload, separators=(',', ':'), ensure_ascii=False))
    msg  = f"{hdr}.{body}".encode()
    sig  = _b64u(hmac.new(JWT_SECRET.encode(), msg, hashlib.sha256).digest())
    return f"{hdr}.{body}.{sig}"

def _jwt_verify(token):
    try:
        hdr, body, sig = token.split('.')
        msg      = f"{hdr}.{body}".encode()
        expected = _b64u(hmac.new(JWT_SECRET.encode(), msg, hashlib.sha256).digest())
        if not hmac.compare_digest(sig, expected): return None
        payload  = json.loads(base64.urlsafe_b64decode(body + '=='))
        if payload.get('exp', 0) < time.time(): return None
        return payload
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Contraseñas — PBKDF2-SHA256 (stdlib)
# ---------------------------------------------------------------------------

def _pwd_hash(pwd, salt=None):
    if salt is None:
        salt = base64.b64encode(os.urandom(16)).decode()
    h = hashlib.pbkdf2_hmac('sha256', pwd.encode(), salt.encode(), 260000)
    return f"{salt}:{h.hex()}"

def _pwd_verify(pwd, stored):
    try:
        salt, _ = stored.split(':', 1)
        return hmac.compare_digest(_pwd_hash(pwd, salt), stored)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Autenticación
# ---------------------------------------------------------------------------

def _auth(environ):
    """Retorna (payload, None) o (None, code) ante error."""
    # Clave interna para el servidor MCP (mismo hosting, sin JWT)
    if INTERNAL_KEY and environ.get('HTTP_X_INTERNAL_KEY') == INTERNAL_KEY:
        return {'cod': '_mcp', 'rol': 'admin', 'internal': True}, None
    # JWT Bearer para usuarios humanos
    auth = environ.get('HTTP_AUTHORIZATION', '')
    if not auth.startswith('Bearer '):
        return None, (401, {'ok': False, 'error': 'Token requerido'})
    payload = _jwt_verify(auth[7:])
    if not payload:
        return None, (401, {'ok': False, 'error': 'Token inválido o expirado'})
    return payload, None


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------

def _log_session(usr_id, ip, met, ruta, sts, ms=None, msg=None):
    try:
        _query(
            'INSERT INTO log (usrId, logIp, logMet, logRuta, logSts, logMs, logMsg) '
            'VALUES (%s, %s, %s, %s, %s, %s, %s)',
            [usr_id, ip[:45], met[:10], ruta[:100] if ruta else None,
             sts, ms, msg[:200] if msg else None],
            db=DB_ADMIN
        )
    except Exception:
        pass


def _login(body_bytes, ip=''):
    try:
        data = json.loads(body_bytes)
    except Exception:
        return 400, {'ok': False, 'error': 'JSON inválido'}

    cod = (data.get('cod') or '').strip()
    pwd = (data.get('pwd') or '').strip()
    if not cod or not pwd:
        return 400, {'ok': False, 'error': 'cod y pwd son requeridos'}

    t0   = time.time()
    rows = _query(
        'SELECT usrId, usrCod, usrNomb, usrPwd, usrRol FROM usr '
        'WHERE usrCod = %s AND usrActv = 1 LIMIT 1',
        [cod], db=DB_ADMIN
    )
    usr = rows[0] if rows else None
    if not usr or not _pwd_verify(pwd, usr['usrPwd']):
        _log_session(usr['usrId'] if usr else None, ip, 'LOGIN', '/auth/login',
                     401, msg='Credenciales incorrectas')
        return 401, {'ok': False, 'error': 'Credenciales incorrectas'}

    ms = int((time.time() - t0) * 1000)
    try:
        _query('UPDATE usr SET usrUlt = NOW() WHERE usrId = %s',
               [usr['usrId']], db=DB_ADMIN)
    except Exception:
        pass

    _log_session(usr['usrId'], ip, 'LOGIN', '/auth/login', 200, ms=ms,
                 msg=f"Login exitoso — rol: {usr['usrRol']}")

    token = _jwt_sign({
        'sub':  usr['usrId'],
        'cod':  usr['usrCod'],
        'nomb': usr['usrNomb'],
        'rol':  usr['usrRol'],
        'exp':  int(time.time()) + JWT_EXP,
    })
    return 200, {
        'ok': True, 'token': token, 'tipo': 'Bearer', 'expira': JWT_EXP,
        'usuario': {'cod': usr['usrCod'], 'nomb': usr['usrNomb'], 'rol': usr['usrRol']},
    }


def _ventas(qs):
    modo = qs.get('modo', 'vntStd')
    emp  = _query('SELECT TRIM(empNomb) AS empNomb FROM emp WHERE empCod = %s LIMIT 1',
                  [DB_NAME], db=DB_ADMIN)
    emp_nomb = emp[0]['empNomb'] if emp else DB_NAME
    conn = _get_db(DB_ADMIN)
    try:
        with conn.cursor() as cur:
            cur.execute('CALL vnt(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)', [
                DB_NAME, modo,
                qs.get('desde')          or None,
                qs.get('hasta')          or None,
                qs.get('producto_desde') or '',
                qs.get('producto_hasta') or '',
                qs.get('almacen_desde')  or '',
                qs.get('almacen_hasta')  or '',
                qs.get('cliente_desde')  or '',
                qs.get('cliente_hasta')  or '',
                qs.get('vendedor_desde') or '',
                qs.get('vendedor_hasta') or '',
                qs.get('sucursal_desde') or '',
                qs.get('sucursal_hasta') or '',
                qs.get('marca_desde')    or '',
                qs.get('marca_hasta')    or '',
            ])
            rows = cur.fetchall()
    finally:
        conn.close()
    return 200, {'ok': True, 'empresa': emp_nomb, 'base': DB_NAME, 'total': len(rows), 'data': rows}


def _clientes(qs):
    t     = f"%{qs.get('buscar', '')}%"
    limit = min(int(qs.get('limite', 20) or 20), 100)
    rows  = _query(
        'SELECT TRIM(socCdg) AS socCdg, TRIM(socDsc) AS socDsc, socRif '
        'FROM clt WHERE socCdg LIKE %s OR socDsc LIKE %s ORDER BY socDsc LIMIT %s',
        [t, t, limit]
    )
    return 200, {'ok': True, 'total': len(rows), 'data': rows}


def _vendedores(qs):
    t     = f"%{qs.get('buscar', '')}%"
    limit = min(int(qs.get('limite', 20) or 20), 100)
    rows  = _query(
        'SELECT TRIM(socCdg) AS socCdg, TRIM(socDsc) AS socDsc '
        'FROM vnd WHERE socCdg LIKE %s OR socDsc LIKE %s ORDER BY socDsc LIMIT %s',
        [t, t, limit]
    )
    return 200, {'ok': True, 'total': len(rows), 'data': rows}


def _productos(qs):
    t     = f"%{qs.get('buscar', '')}%"
    limit = min(int(qs.get('limite', 20) or 20), 100)
    rows  = _query(
        'SELECT TRIM(prdCdg) AS prdCdg, TRIM(prdDsc) AS prdDsc, TRIM(mrcCdg) AS mrcCdg '
        'FROM prd WHERE prdCdg LIKE %s OR prdDsc LIKE %s ORDER BY prdDsc LIMIT %s',
        [t, t, limit]
    )
    return 200, {'ok': True, 'total': len(rows), 'data': rows}


# ---------------------------------------------------------------------------
# WSGI application
# ---------------------------------------------------------------------------

def application(environ, start_response):
    path   = environ.get('PATH_INFO', '/')
    method = environ.get('REQUEST_METHOD', 'GET')
    qs     = _parse_qs(environ.get('QUERY_STRING', ''))

    # CORS preflight
    if method == 'OPTIONS':
        start_response('204 No Content', _CORS + [('Content-Length', '0')])
        return [b'']

    # ── Health ───────────────────────────────────────────────────────────────
    if path == '/health':
        return _resp(start_response, 200, {
            'status': 'ok', 'service': SERVER_NAME, 'version': SERVER_VERSION,
            'db': 'pymysql disponible' if DB_AVAILABLE else 'pymysql NO instalado',
        })

    # ── Login ────────────────────────────────────────────────────────────────
    if path == '/auth/login':
        if method != 'POST':
            return _resp(start_response, 405, {'ok': False, 'error': 'Método no permitido'})
        if not DB_AVAILABLE:
            return _resp(start_response, 503, {'ok': False, 'error': 'Base de datos no disponible'})
        try:
            code, data = _login(_read_body(environ), ip=environ.get('REMOTE_ADDR', ''))
        except Exception as e:
            return _resp(start_response, 500, {'ok': False, 'error': str(e)})
        return _resp(start_response, code, data)

    # ── Hash helper ──────────────────────────────────────────────────────────
    # Genera el hash de una contraseña — solo con RELOAD_TOKEN
    # Uso: POST /auth/hash?token=XXX  body: {"pwd": "contraseña"}
    if path == '/auth/hash' and method == 'POST':
        if not RELOAD_TOKEN or qs.get('token') != RELOAD_TOKEN:
            return _resp(start_response, 401, {'ok': False, 'error': 'Token requerido'})
        try:
            body = json.loads(_read_body(environ))
            pwd  = (body.get('pwd') or '').strip()
            if not pwd:
                return _resp(start_response, 400, {'ok': False, 'error': 'pwd requerido'})
            return _resp(start_response, 200, {'ok': True, 'hash': _pwd_hash(pwd)})
        except Exception as e:
            return _resp(start_response, 400, {'ok': False, 'error': str(e)})

    # ── Deploy desde GitHub ──────────────────────────────────────────────────
    if path == '/deploy':
        if not RELOAD_TOKEN or qs.get('token') != RELOAD_TOKEN:
            return _resp(start_response, 401, {'ok': False, 'error': 'Token inválido'})
        try:
            import shutil
            app_dir  = os.path.dirname(os.path.abspath(__file__))
            REPO_URL = 'https://github.com/Hercrak/corp-api.git'
            output   = []
            git_bin  = shutil.which('git') or 'git'
            output.append(f'git encontrado en: {git_bin}')
            output.append(f'app_dir: {app_dir}')
            output.append(f'PATH: {os.environ.get("PATH", "(vacío)")}')

            def _run(cmd):
                try:
                    r = subprocess.run(cmd, cwd=app_dir, capture_output=True, timeout=45)
                    out = (r.stdout + r.stderr).decode('utf-8', errors='replace').strip()
                    output.append(f"$ {' '.join(cmd)}\n{out}")
                except Exception as ex:
                    output.append(f"$ {' '.join(cmd)}\nERROR: {type(ex).__name__}: {ex}")

            if not os.path.exists(os.path.join(app_dir, '.git')):
                _run([git_bin, 'init'])
                _run([git_bin, 'remote', 'add', 'origin', REPO_URL])

            _run([git_bin, 'fetch', 'origin', 'main'])
            _run([git_bin, 'reset', '--hard', 'origin/main'])

            try:
                restart = os.path.join(app_dir, 'tmp', 'restart.txt')
                os.makedirs(os.path.dirname(restart), exist_ok=True)
                with open(restart, 'w') as f:
                    f.write(time.strftime('%Y-%m-%d %H:%M:%S'))
                output.append('tmp/restart.txt actualizado')
            except Exception as e:
                output.append(f'restart.txt error: {e}')

            return _resp(start_response, 200, {'ok': True, 'deploy': '\n\n'.join(output)})
        except Exception as e:
            return _resp(start_response, 200, {'ok': False, 'error': str(e),
                                               'type': type(e).__name__})

    # ── Rutas protegidas ─────────────────────────────────────────────────────
    if not DB_AVAILABLE:
        return _resp(start_response, 503, {'ok': False, 'error': 'PyMySQL no disponible'})

    user, err = _auth(environ)
    if user is None:
        code, data = err
        return _resp(start_response, code, data)

    try:
        if   path == '/ventas'     and method == 'GET': code, data = _ventas(qs)
        elif path == '/clientes'   and method == 'GET': code, data = _clientes(qs)
        elif path == '/vendedores' and method == 'GET': code, data = _vendedores(qs)
        elif path == '/productos'  and method == 'GET': code, data = _productos(qs)
        else:
            return _resp(start_response, 404, {'ok': False, 'error': 'Ruta no encontrada'})
    except Exception as e:
        return _resp(start_response, 500, {'ok': False, 'error': str(e)})

    return _resp(start_response, code, data)
