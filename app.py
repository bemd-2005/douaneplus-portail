"""
DOUANEPLUS — Portail d'essai
============================
Formulaire -> cle d'essai de 7 jours (signee Ed25519) -> lien de telechargement.
Un seul essai par contact (email ou numero), 3 nouveaux essais maximum par jour et par adresse IP.

Variables d'environnement (voir README.md) :
  LICENSE_PRIVATE_KEY_B64   cle privee (OBLIGATOIRE pour delivrer des cles)
  DOWNLOAD_URL              lien de telechargement du logiciel (GitHub Releases, Drive...)
  ADMIN_PASSWORD            mot de passe de la page /admin (liste des essais, export CSV)
  DATABASE_URL              Postgres en production (sinon SQLite local portail.db)
  WHATSAPP_URL              lien WhatsApp affiche sur la page (optionnel)
  IP_SALT                   sel pour hacher les IP (optionnel mais conseille)
"""
import os, re, csv, io, hmac, hashlib, sqlite3
from datetime import datetime, timedelta
from flask import Flask, request, render_template, Response, abort
import dp_licence

app = Flask(__name__)

DATABASE_URL = os.getenv('DATABASE_URL', '')
USE_PG = DATABASE_URL.startswith(('postgres://', 'postgresql://'))
JOURS_ESSAI = 7
MAX_ESSAIS_PAR_IP_PAR_JOUR = 3


# ── Base de donnees (SQLite en local, Postgres en production) ──
def _conn():
    if USE_PG:
        import psycopg2
        return psycopg2.connect(DATABASE_URL)
    return sqlite3.connect(os.getenv('SQLITE_PATH', 'portail.db'))


def _sql(q: str) -> str:
    return q.replace('?', '%s') if USE_PG else q


def db_exec(q, params=(), fetch=None):
    con = _conn()
    try:
        cur = con.cursor()
        cur.execute(_sql(q), params)
        out = cur.fetchall() if fetch == 'all' else cur.fetchone() if fetch == 'one' else None
        con.commit()
        return out
    finally:
        con.close()


def init_db():
    db_exec("""CREATE TABLE IF NOT EXISTS essais (
        contact_hash TEXT PRIMARY KEY,
        nom          TEXT NOT NULL,
        contact      TEXT NOT NULL,
        type         TEXT NOT NULL,
        ip_hash      TEXT NOT NULL,
        cle          TEXT NOT NULL,
        created_at   TEXT NOT NULL
    )""")


init_db()


# ── Utilitaires ────────────────────────────────────────────────
def normaliser(contact: str):
    """Retourne (type, valeur_normalisee) ou (None, None)."""
    c = (contact or '').strip().lower()
    if '@' in c:
        if re.fullmatch(r"[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}", c):
            return 'email', c
        return None, None
    digits = re.sub(r'\D', '', c)
    if digits.startswith('00'):
        digits = digits[2:]
    if digits.startswith('237') and len(digits) == 12:
        digits = digits[3:]
    if 8 <= len(digits) <= 15:
        return 'tel', digits
    return None, None


def ip_hash() -> str:
    ip = (request.headers.get('X-Forwarded-For', request.remote_addr) or '').split(',')[0].strip()
    return hashlib.sha256((os.getenv('IP_SALT', 'dp') + ip).encode()).hexdigest()[:32]


def ctx():
    return dict(whatsapp=os.getenv('WHATSAPP_URL', ''), jours=JOURS_ESSAI)


# ── Pages ──────────────────────────────────────────────────────
@app.get('/')
def index():
    return render_template('index.html', erreur=None, form={}, **ctx())


@app.get('/health')
def health():
    return 'ok'


@app.post('/essai')
def essai():
    form = {'nom': request.form.get('nom', '').strip(), 'contact': request.form.get('contact', '').strip()}
    # piege a robots : champ cache qui doit rester vide
    if request.form.get('site'):
        return render_template('index.html', erreur=None, form={}, **ctx())

    def refus(msg, code=400):
        return render_template('index.html', erreur=msg, form=form, **ctx()), code

    if not (2 <= len(form['nom']) <= 100):
        return refus('Veuillez indiquer votre nom (ou celui de votre structure).')
    if not request.form.get('consent'):
        return refus('Veuillez accepter d\'être recontacté au sujet de DOUANEPLUS.')
    typ, valeur = normaliser(form['contact'])
    if not typ:
        return refus('Veuillez saisir une adresse email ou un numéro WhatsApp valide.')

    h = hashlib.sha256(valeur.encode()).hexdigest()
    deja = db_exec("SELECT cle, created_at FROM essais WHERE contact_hash = ?", (h,), fetch='one')
    if deja:  # essai deja delivre : on re-affiche la meme cle, jamais une nouvelle
        return render_template('cle.html', cle=deja[0], deja=True, download=os.getenv('DOWNLOAD_URL', ''), **ctx())

    iph = ip_hash()
    depuis = (datetime.utcnow() - timedelta(days=1)).isoformat()
    n = db_exec("SELECT COUNT(*) FROM essais WHERE ip_hash = ? AND created_at > ?", (iph, depuis), fetch='one')[0]
    if n >= MAX_ESSAIS_PAR_IP_PAR_JOUR:
        return refus('Trop de demandes depuis ce réseau aujourd\'hui. Réessayez demain ou contactez-nous.', 429)

    priv = os.getenv('LICENSE_PRIVATE_KEY_B64')
    if not priv:
        app.logger.error('LICENSE_PRIVATE_KEY_B64 manquante')
        return refus('Service momentanément indisponible. Contactez-nous directement.', 503)

    cle, _nonce = dp_licence.emettre(priv, 'essai', JOURS_ESSAI)
    db_exec("INSERT INTO essais (contact_hash, nom, contact, type, ip_hash, cle, created_at) VALUES (?,?,?,?,?,?,?)",
            (h, form['nom'], form['contact'], typ, iph, cle, datetime.utcnow().isoformat()))
    return render_template('cle.html', cle=cle, deja=False, download=os.getenv('DOWNLOAD_URL', ''), **ctx())


# ── Administration (mot de passe HTTP Basic) ───────────────────
def _admin_ok() -> bool:
    pw = os.getenv('ADMIN_PASSWORD', '')
    a = request.authorization
    return bool(pw and a and hmac.compare_digest(a.password or '', pw))


def _admin_required():
    if not os.getenv('ADMIN_PASSWORD'):
        abort(404)
    if not _admin_ok():
        return Response('Authentification requise', 401, {'WWW-Authenticate': 'Basic realm="DOUANEPLUS admin"'})
    return None


@app.get('/admin')
def admin():
    r = _admin_required()
    if r: return r
    rows = db_exec("SELECT nom, contact, type, created_at FROM essais ORDER BY created_at DESC", fetch='all')
    return render_template('admin.html', rows=rows)


@app.get('/admin.csv')
def admin_csv():
    r = _admin_required()
    if r: return r
    rows = db_exec("SELECT nom, contact, type, created_at FROM essais ORDER BY created_at DESC", fetch='all')
    buf = io.StringIO(); w = csv.writer(buf)
    w.writerow(['nom', 'contact', 'type', 'date_utc']); w.writerows(rows)
    return Response(buf.getvalue(), mimetype='text/csv',
                    headers={'Content-Disposition': 'attachment; filename=essais_douaneplus.csv'})


if __name__ == '__main__':
    app.run(port=int(os.getenv('PORT', 5050)), debug=os.getenv('FLASK_DEBUG') == '1')
