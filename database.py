import sqlite3
import hashlib
import hmac
import os
from datetime import datetime, timedelta

DB = "sistema.db"

MAX_INTENTOS_FALLIDOS = 5
DURACION_BLOQUEO_MINUTOS = 15


def _hash_password(password: str) -> str:
    salt = os.urandom(32)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
    return (salt + key).hex()


def _verify_password(password: str, stored_hex: str) -> bool:
    raw = bytes.fromhex(stored_hex)
    salt, key = raw[:32], raw[32:]
    new_key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
    return hmac.compare_digest(new_key, key)


def crear_tablas():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        mfa_secret TEXT NOT NULL,
        intentos_fallidos INTEGER DEFAULT 0,
        bloqueado_hasta TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        ip TEXT,
        pais TEXT,
        ciudad TEXT,
        hora INTEGER,
        score_riesgo INTEGER,
        decision TEXT,
        razones TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )''')
    conn.commit()
    conn.close()


def crear_usuario(username, password, mfa_secret):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute(
        "INSERT INTO usuarios (username, password_hash, mfa_secret) VALUES (?, ?, ?)",
        (username, _hash_password(password), mfa_secret)
    )
    conn.commit()
    conn.close()


def verificar_usuario(username, password):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT * FROM usuarios WHERE username = ?", (username,))
    usuario = c.fetchone()
    conn.close()
    if usuario is None:
        return None
    if _verify_password(password, usuario[2]):
        return usuario
    return None


def obtener_secret_mfa(username):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT mfa_secret FROM usuarios WHERE username = ?", (username,))
    fila = c.fetchone()
    conn.close()
    return fila[0] if fila else None


def esta_bloqueado(username):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT bloqueado_hasta FROM usuarios WHERE username = ?", (username,))
    fila = c.fetchone()
    conn.close()
    if fila is None or fila[0] is None:
        return False
    bloqueado_hasta = datetime.strptime(fila[0], "%Y-%m-%d %H:%M:%S")
    if datetime.now() < bloqueado_hasta:
        return True
    resetear_intentos(username)
    return False


def registrar_intento_fallido(username):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT intentos_fallidos FROM usuarios WHERE username = ?", (username,))
    fila = c.fetchone()
    if fila is None:
        conn.close()
        return
    intentos = fila[0] + 1
    if intentos >= MAX_INTENTOS_FALLIDOS:
        bloqueo_hasta = (datetime.now() + timedelta(minutes=DURACION_BLOQUEO_MINUTOS)) \
            .strftime("%Y-%m-%d %H:%M:%S")
        c.execute(
            "UPDATE usuarios SET intentos_fallidos = ?, bloqueado_hasta = ? WHERE username = ?",
            (intentos, bloqueo_hasta, username)
        )
    else:
        c.execute(
            "UPDATE usuarios SET intentos_fallidos = ? WHERE username = ?",
            (intentos, username)
        )
    conn.commit()
    conn.close()


def resetear_intentos(username):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute(
        "UPDATE usuarios SET intentos_fallidos = 0, bloqueado_hasta = NULL WHERE username = ?",
        (username,)
    )
    conn.commit()
    conn.close()


def obtener_ultimo_login(username):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute(
        "SELECT pais, timestamp FROM logs WHERE username = ? ORDER BY id DESC LIMIT 1",
        (username,)
    )
    fila = c.fetchone()
    conn.close()
    if fila is None:
        return None
    return {"pais": fila[0], "timestamp": fila[1]}


def guardar_log(username, ip, score, geo, decision, razones=None):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    ahora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    razones_texto = " | ".join(razones) if razones else ""
    c.execute(
        '''INSERT INTO logs
           (username, ip, pais, ciudad, hora, score_riesgo, decision, razones, timestamp)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
        (username, ip, geo["country"], geo["city"], datetime.now().hour,
         score, decision, razones_texto, ahora)
    )
    conn.commit()
    conn.close()
