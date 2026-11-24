"""
DOUANEPLUS — Cles de licence signees Ed25519 (format DPLS2)
============================================================
Module partage par generer_cles.py et le portail d'essai.
La CLE PRIVEE ne doit exister que chez toi (generateur / portail Render).
Le logiciel distribue ne contient que la CLE PUBLIQUE.

Format : DPLS2-XXXXX-XXXXX-...   (base32, groupes de 5)
Contenu signe (12 octets) : version | lettre pack | jours | jour d'emission | nonce(6)
"""
import base64, struct, secrets
from datetime import date

PREFIX    = 'DPLS2'
EPOCH     = date(2026, 1, 1)
SIGN_CTX  = b'DOUANEPLUS-LICENCE-V2|'
FMT       = '>BcHH6s'          # 1 + 1 + 2 + 2 + 6 = 12 octets
PAYLOAD_N = 12
SIG_N     = 64

PACK_LETTERS = {
    'essai': 'T', 'etudiant': 'E', 'declarant': 'D',
    'entreprise': 'N', 'licence_definitive': 'L', 'ecole': 'S',
}
LETTER_PACKS = {v: k for k, v in PACK_LETTERS.items()}
LIFETIME_PACKS = {'licence_definitive'}

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography.hazmat.primitives import serialization
    from cryptography.exceptions import InvalidSignature
except ImportError as e:  # pragma: no cover
    raise SystemExit("Installe d'abord : pip install cryptography") from e


def new_keypair():
    """Retourne (prive_b64, public_b64) — 32 octets chacun, en base64."""
    sk = Ed25519PrivateKey.generate()
    raw_sk = sk.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                              serialization.NoEncryption())
    raw_pk = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw_sk).decode(), base64.b64encode(raw_pk).decode()


def public_from_private(priv_b64: str) -> str:
    sk = Ed25519PrivateKey.from_private_bytes(base64.b64decode(priv_b64.strip()))
    raw_pk = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw_pk).decode()


def _groupes(s: str, n: int = 5) -> str:
    return '-'.join(s[i:i + n] for i in range(0, len(s), n))


def emettre(priv_b64: str, pack: str, jours: int = 0) -> tuple:
    """Emet une cle. Retourne (cle, nonce_hex). jours ignore pour les packs a vie."""
    if pack not in PACK_LETTERS:
        raise ValueError(f"Pack inconnu : {pack} (valides : {', '.join(PACK_LETTERS)})")
    if pack in LIFETIME_PACKS:
        jours = 0
    elif not (1 <= int(jours) <= 3650):
        raise ValueError('Duree invalide (1 a 3650 jours)')
    nonce = secrets.token_bytes(6)
    issued = (date.today() - EPOCH).days
    payload = struct.pack(FMT, 2, PACK_LETTERS[pack].encode(), int(jours), issued, nonce)
    sk = Ed25519PrivateKey.from_private_bytes(base64.b64decode(priv_b64.strip()))
    sig = sk.sign(SIGN_CTX + payload)
    body = base64.b32encode(payload + sig).decode().rstrip('=')
    return f"{PREFIX}-{_groupes(body)}", nonce.hex().upper()


def verifier(pub_b64: str, cle: str) -> tuple:
    """Retourne (True, infos) ou (False, message)."""
    raw = (cle or '').strip().upper().replace('-', '').replace(' ', '')
    if not raw.startswith(PREFIX):
        return False, 'Format invalide'
    body = raw[len(PREFIX):]
    try:
        blob = base64.b32decode(body + '=' * (-len(body) % 8))
    except Exception:
        return False, 'Format invalide'
    if len(blob) != PAYLOAD_N + SIG_N:
        return False, 'Cle incomplete ou alteree'
    payload, sig = blob[:PAYLOAD_N], blob[PAYLOAD_N:]
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_b64)).verify(sig, SIGN_CTX + payload)
    except (InvalidSignature, ValueError):
        return False, 'Signature incorrecte'
    ver, letter, jours, issued, nonce = struct.unpack(FMT, payload)
    pack = LETTER_PACKS.get(letter.decode())
    if ver != 2 or not pack:
        return False, 'Version ou pack inconnu'
    return True, {'pack': pack, 'jours': jours, 'emise_le': date.fromordinal(EPOCH.toordinal() + issued),
                  'nonce': nonce.hex().upper()}
