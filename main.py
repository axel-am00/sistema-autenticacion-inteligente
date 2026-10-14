from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
import datetime
import sqlite3

from database import (
    crear_tablas, verificar_usuario, guardar_log, obtener_secret_mfa,
    esta_bloqueado, registrar_intento_fallido, resetear_intentos,
    obtener_ultimo_login,
)
from risk_engine import calcular_riesgo
from geoip import obtener_geoip
from mfa import verificar_codigo

app = FastAPI()
templates = Jinja2Templates(directory="templates")
crear_tablas()


class LoginRequest(BaseModel):
    username: str
    password: str
    timezone: str = "Unknown"


class MFARequest(BaseModel):
    username: str
    codigo: str


def obtener_ip_cliente(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(request, "login.html")


@app.post("/api/login")
async def login(data: LoginRequest, request: Request):
    if esta_bloqueado(data.username):
        return {
            "status": "error",
            "mensaje": "Cuenta bloqueada temporalmente por multiples "
                       "intentos fallidos. Intenta de nuevo en unos minutos."
        }

    usuario = verificar_usuario(data.username, data.password)
    if not usuario:
        registrar_intento_fallido(data.username)
        return {"status": "error", "mensaje": "Usuario o contrasena incorrectos"}

    resetear_intentos(data.username)

    ip = obtener_ip_cliente(request)
    geo = obtener_geoip(ip)

    ultimo_login = obtener_ultimo_login(data.username)
    pais_anterior = None
    minutos_transcurridos = None
    if ultimo_login:
        pais_anterior = ultimo_login["pais"]
        ultimo_timestamp = datetime.datetime.strptime(
            ultimo_login["timestamp"], "%Y-%m-%d %H:%M:%S"
        )
        minutos_transcurridos = (
            datetime.datetime.now() - ultimo_timestamp
        ).total_seconds() / 60

    resultado = calcular_riesgo({
        "pais": geo["country"],
        "ciudad": geo["city"],
        "vpn": geo["is_vpn"],
        "tor": geo["is_tor"],
        "hora": datetime.datetime.now().hour,
        "timezone": data.timezone,
        "pais_anterior": pais_anterior,
        "minutos_desde_ultimo_login": minutos_transcurridos,
    })

    guardar_log(
        data.username, ip, resultado["score"], geo,
        resultado["decision"], resultado["razones"]
    )

    return {
        "status": resultado["decision"],
        "score": resultado["score"],
        "pais": geo["country"],
        "razones": resultado["razones"],
    }


@app.post("/api/verificar-mfa")
async def verificar_mfa(data: MFARequest):
    if esta_bloqueado(data.username):
        return {"status": "error", "mensaje": "Cuenta bloqueada temporalmente."}
    secret = obtener_secret_mfa(data.username)
    if not secret:
        return {"status": "error", "mensaje": "Codigo incorrecto"}
    if verificar_codigo(secret, data.codigo):
        resetear_intentos(data.username)
        return {"status": "permitido", "mensaje": "Acceso concedido"}
    registrar_intento_fallido(data.username)
    return {"status": "error", "mensaje": "Codigo incorrecto"}


@app.get("/api/logs")
async def ver_logs():
    conn = sqlite3.connect("sistema.db")
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM logs ORDER BY timestamp DESC LIMIT 50")
    filas = c.fetchall()
    conn.close()
    return {"total": len(filas), "logs": [dict(f) for f in filas]}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
