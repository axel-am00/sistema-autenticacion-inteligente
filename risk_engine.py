import os
import math
from dotenv import load_dotenv
from google import genai

load_dotenv()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

_client = genai.Client(api_key=GEMINI_API_KEY) if GEMINI_API_KEY else None


PAISES_ALTO_RIESGO = [
    "Russia", "Ukraine", "China", "United States", "Nigeria", "Romania",
    "North Korea", "Belarus", "Canada", "Mexico",
]

HORAS_SOSPECHOSAS = list(range(0, 6))

COORDENADAS_PAISES = {
    "Russia": (55.7558, 37.6173),
    "Ukraine": (50.4501, 30.5234),
    "China": (39.9042, 116.4074),
    "United States": (38.9072, -77.0369),
    "Nigeria": (9.0765, 7.3986),
    "Romania": (44.4268, 26.1025),
    "North Korea": (39.0392, 125.7625),
    "Belarus": (53.9006, 27.5590),
    "Canada": (45.4215, -75.6972),
    "Mexico": (19.4326, -99.1332),
    "Dominican Republic": (18.4861, -69.9312),
}

VELOCIDAD_MAXIMA_KMH = 900


def _distancia_km(lat1, lon1, lat2, lon2):
    R = 6371
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = (math.sin(dlat / 2) ** 2 +
         math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) *
         math.sin(dlon / 2) ** 2)
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return R * c


def detectar_viaje_imposible(pais_actual, pais_anterior, minutos_transcurridos):
    if pais_actual == pais_anterior:
        return False
    if pais_actual not in COORDENADAS_PAISES or pais_anterior not in COORDENADAS_PAISES:
        return False
    if minutos_transcurridos <= 0:
        return True

    lat1, lon1 = COORDENADAS_PAISES[pais_anterior]
    lat2, lon2 = COORDENADAS_PAISES[pais_actual]
    distancia = _distancia_km(lat1, lon1, lat2, lon2)
    horas = minutos_transcurridos / 60
    velocidad_necesaria = distancia / horas

    return velocidad_necesaria > VELOCIDAD_MAXIMA_KMH


def _calcular_score_manual(datos):
    score = 0
    razones = []
    pais = datos["pais"]
    vpn = datos["vpn"]
    hora = int(datos["hora"])

    if pais in PAISES_ALTO_RIESGO:
        score += 45
        razones.append(
            f"Pais de alto riesgo: {pais} "
            f"(Fuente: World Cybercrime Index, Bruce et al., 2024, PLOS ONE)"
        )
    elif pais == "Unknown":
        score += 20
        razones.append(
            "Ubicacion desconocida (Criterio interno: IP no geolocalizable)"
        )
    elif pais != "Dominican Republic":
        score += 15
        razones.append(
            f"Pais inusual: {pais} "
            f"(Criterio interno: distinto al pais de operacion habitual)"
        )

    if vpn:
        score += 25
        razones.append(
            "VPN o proxy detectado "
            "(Fuente: IPLogs / proxycheck.io, o heuristica de ISP)"
        )

    if hora in HORAS_SOSPECHOSAS:
        score += 20
        razones.append(
            f"Hora sospechosa: {hora}:00 "
            f"(Criterio interno: rango 00:00-05:59)"
        )
    elif hora < 7 or hora > 23:
        score += 10
        razones.append(
            f"Hora inusual: {hora}:00 "
            f"(Criterio interno: fuera del horario habitual 07:00-23:00)"
        )

    if pais == "Dominican Republic":
        if "America/Santo_Domingo" not in datos.get("timezone", ""):
            score += 15
            razones.append(
                "Timezone no coincide con la ubicacion "
                "(Criterio interno: comparacion de zona horaria IANA)"
            )

    factores = sum([pais in PAISES_ALTO_RIESGO, pais == "Unknown",
                    vpn, hora in HORAS_SOSPECHOSAS])
    if factores >= 2:
        score += 10
        razones.append(
            "Multiples factores de riesgo combinados "
            "(Criterio interno: bonificacion por acumulacion de senales)"
        )

    return min(score, 100), razones


def evaluar_con_gemini(datos):
    if _client is None:
        return None
    try:
        prompt = f"""
Eres un sistema de seguridad informatica experto en deteccion de fraude.
Analiza este intento de inicio de sesion y devuelve SOLO un numero del 0 al 100
que represente el nivel de riesgo. 0 es completamente seguro, 100 es un
ataque casi confirmado.

Datos del intento:
- Pais de origen: {datos['pais']}
- Hora del acceso: {datos['hora']}:00
- VPN o proxy detectado: {datos['vpn']}
- Timezone del navegador: {datos.get('timezone', 'desconocido')}

Responde UNICAMENTE con el numero, sin texto adicional ni explicacion.
"""
        respuesta = _client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt,
        )
        score_gemini = int(respuesta.text.strip())
        return max(0, min(score_gemini, 100))
    except Exception as e:
        print(f"[Gemini] No se pudo obtener score de IA: {e}")
        return None


def calcular_riesgo(datos):
    score_manual, razones = _calcular_score_manual(datos)

    score_gemini = evaluar_con_gemini(datos)

    if score_gemini is not None:
        score_final = int(score_manual * 0.6 + score_gemini * 0.4)
        razones.append(
            f"Confirmado por IA: score {score_gemini} "
            f"(Modelo: Gemini 2.5 Flash, Google DeepMind)"
        )
    else:
        score_final = score_manual

    score_final = min(score_final, 100)

    bloqueo_forzado = False

    if datos.get("tor"):
        bloqueo_forzado = True
        razones.append(
            "Conexion mediante red Tor detectada - bloqueo automatico "
            "(Fuente: lista oficial de nodos de salida, Tor Project)"
        )

    pais_anterior = datos.get("pais_anterior")
    minutos = datos.get("minutos_desde_ultimo_login")
    if pais_anterior and minutos is not None:
        if detectar_viaje_imposible(datos["pais"], pais_anterior, minutos):
            bloqueo_forzado = True
            razones.append(
                f"Viaje imposible: login previo desde {pais_anterior} hace "
                f"{int(minutos)} min "
                f"(Concepto: deteccion de viaje atipico, similar a "
                f"Microsoft Entra ID Identity Protection)"
            )

    if bloqueo_forzado:
        score_final = 100
        decision = "bloqueado"
    elif score_final <= 40:
        decision = "permitido"
    elif score_final <= 70:
        decision = "mfa_requerido"
    else:
        decision = "bloqueado"

    return {"score": score_final, "decision": decision, "razones": razones}
