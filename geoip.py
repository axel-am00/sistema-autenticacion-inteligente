import ipaddress
import os
import time
import requests
from dotenv import load_dotenv

load_dotenv()
PROXYCHECK_API_KEY = os.getenv("PROXYCHECK_API_KEY")

TOR_LIST_URL = "https://check.torproject.org/torbulkexitlist"
TOR_CACHE_SEGUNDOS = 3600

_tor_nodos_cache = None
_tor_nodos_cache_hora = 0


def _obtener_nodos_tor():
    global _tor_nodos_cache, _tor_nodos_cache_hora
    ahora = time.time()
    if _tor_nodos_cache is not None and (ahora - _tor_nodos_cache_hora) < TOR_CACHE_SEGUNDOS:
        return _tor_nodos_cache
    try:
        r = requests.get(TOR_LIST_URL, timeout=5)
        nodos = set(r.text.strip().splitlines())
        _tor_nodos_cache = nodos
        _tor_nodos_cache_hora = ahora
        return nodos
    except Exception:
        return _tor_nodos_cache or set()


def es_ip_tor(ip):
    return ip in _obtener_nodos_tor()


def detectar_vpn_heuristica(data):
    keywords = ["VPN", "Proxy", "Hosting", "NordVPN", "ExpressVPN",
                "DigitalOcean", "Amazon", "Google Cloud", "Linode", "Vultr"]
    texto = (data.get("isp", "") + " " + data.get("org", "")).lower()
    return any(k.lower() in texto for k in keywords)


def _consultar_iplogs(ip):
    try:
        r = requests.post(
            "https://iplogs.com/v1/check",
            json={"ip": ip},
            timeout=10,
        )
        data = r.json()
        return bool(data.get("is_vpn", False))
    except Exception as e:
        print(f"[IPLogs] No se pudo consultar: {e}")
        return None


def _consultar_proxycheck(ip):
    if not PROXYCHECK_API_KEY:
        return None
    try:
        r = requests.get(
            f"https://proxycheck.io/v2/{ip}",
            params={"key": PROXYCHECK_API_KEY, "vpn": 1, "asn": 0},
            timeout=5,
        )
        data = r.json()
        if data.get("status") not in ("ok", "warning"):
            return None
        info = data.get(ip, {})
        return info.get("proxy") == "yes"
    except Exception as e:
        print(f"[proxycheck.io] No se pudo consultar: {e}")
        return None


def es_ip_local(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def obtener_geoip(ip):
    if es_ip_local(ip):
        return {"country": "Unknown", "city": "Local",
                "isp": "Red local", "is_vpn": False, "is_tor": False}

    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = r.json()
        if data.get("status") != "success":
            data = {}
            base = {"country": "Unknown", "city": "Unknown", "isp": "Unknown"}
        else:
            base = {
                "country": data.get("country", "Unknown"),
                "city":    data.get("city", "Unknown"),
                "isp":     data.get("isp", "Unknown"),
            }
    except Exception:
        data = {}
        base = {"country": "Unknown", "city": "Unknown", "isp": "Unknown"}

    resultado_iplogs = _consultar_iplogs(ip)
    resultado_proxycheck = _consultar_proxycheck(ip)
    resultados_validos = [r for r in (resultado_iplogs, resultado_proxycheck)
                          if r is not None]

    if resultados_validos:
        base["is_vpn"] = any(resultados_validos)
    else:
        base["is_vpn"] = detectar_vpn_heuristica(data)

    base["is_tor"] = es_ip_tor(ip)

    return base
