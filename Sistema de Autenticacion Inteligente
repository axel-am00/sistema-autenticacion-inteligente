# Sistema de Autenticación Inteligente

Sistema de autenticación con **puntuación de riesgo contextual**. En cada inicio de sesión evalúa desde dónde, cuándo y cómo se conecta el usuario, y decide si **permitir** el acceso, **exigir MFA** o **bloquear** el intento. Proyecto de tesis desarrollado en el Instituto Tecnológico de Las Américas (ITLA), Tecnología en Seguridad Informática.

> **Aviso:** proyecto académico y de aprendizaje. No está pensado para producción. Consulta la sección [Limitaciones conocidas](#limitaciones-conocidas).

---

## Características

- **Contraseñas protegidas con PBKDF2-HMAC-SHA256**, con sal única de 32 bytes por usuario y comparación en tiempo constante.
- **Consultas SQL parametrizadas** contra inyección SQL.
- **Bloqueo por intentos fallidos:** 5 intentos y bloqueo temporal de 15 minutos, con reinicio automático.
- **Geolocalización por IP** (país, ciudad, ISP).
- **Detección de VPN/proxy en capas**, con respaldo si una fuente falla.
- **Detección de Tor** con la lista oficial de nodos de salida del Tor Project, con caché de una hora.
- **Detección de viaje imposible** con la fórmula de Haversine: si el usuario habría tenido que viajar a más de 900 km/h entre dos logins, se bloquea.
- **Motor de riesgo híbrido:** reglas manuales (60 %) y segunda opinión de IA con Gemini (40 %).
- **MFA con TOTP** compatible con Google Authenticator.
- **Registro de auditoría** con score, decisión y razones de cada intento.
- **Degradación elegante:** si una API externa falla, el login sigue funcionando con menor precisión de detección.

---

## Arquitectura

| Archivo | Responsabilidad |
|---|---|
| `main.py` | Orquestador. Recibe las peticiones HTTP (FastAPI) y coordina al resto de módulos. |
| `geoip.py` | Geolocalización de IP y detección de VPN/Tor. |
| `database.py` | SQLite, hashing de contraseñas, bloqueo de cuentas e historial de accesos. |
| `risk_engine.py` | Cálculo del score de riesgo, integración con Gemini y bloqueos forzados. |
| `mfa.py` | Generación de secretos TOTP, códigos QR y verificación. |
| `crear_usuarios.py` | Script de inicialización de usuarios (se ejecuta una sola vez). |
| `templates/login.html` | Interfaz de inicio de sesión. |

### Flujo de un login

1. El frontend envía usuario y contraseña a `/api/login`.
2. Se verifica que la cuenta no esté bloqueada y se valida la contraseña. Si falla, se registra el intento fallido y se corta el proceso.
3. Se obtiene la IP del cliente y se geolocaliza, con detección de VPN y Tor.
4. Se recupera el último login del usuario (país y hora) para el cálculo de viaje imposible.
5. El motor de riesgo calcula el score manual, lo combina con Gemini si está disponible y aplica los bloqueos forzados al final.
6. Se guarda el resultado completo, con razones y fuentes, en la base de datos.
7. La decisión vuelve al frontend, que muestra verde (permitido), amarillo (MFA requerido) o rojo (bloqueado).

---

## Motor de riesgo

### Puntuación manual

| Factor | Puntos |
|---|---|
| País en la lista de alto riesgo | +45 |
| Ubicación desconocida | +20 |
| País distinto de República Dominicana | +15 |
| VPN o proxy detectado | +25 |
| Hora sospechosa (00:00–05:59) | +20 |
| Hora inusual (fuera de 07:00–23:00) | +10 |
| Zona horaria no coincide (solo si el país es RD) | +15 |
| Bonificación por 2 o más factores combinados | +10 |

El total se limita a 100.

### Combinación con IA

Si hay clave de Gemini configurada, el score final es **60 % manual + 40 % Gemini**. Si Gemini no responde, se usa solo el score manual.

### Decisión

| Score | Decisión |
|---|---|
| 0–40 | Permitido |
| 41–70 | MFA requerido |
| 71–100 | Bloqueado |

### Bloqueos forzados

Estas condiciones se evalúan **después** de combinar con la IA, de modo que ni el scoring manual ni Gemini puedan diluirlas. Fijan el score en 100 y la decisión en bloqueado:

- Conexión desde un nodo de salida de **Tor**.
- **Viaje imposible**: velocidad necesaria superior a 900 km/h respecto al login anterior.

### Fuentes y criterios

- La lista de países de alto riesgo toma como base el *World Cybercrime Index* (Bruce et al., 2024, PLOS ONE). Corea del Norte y Bielorrusia se añadieron por documentación de agencias de ciberseguridad. **Canadá y México son criterio interno del proyecto**, no del estudio.
- El concepto de viaje imposible está inspirado en la detección de viaje atípico de Microsoft Entra ID Identity Protection.

---

## Tecnologías

- Python y FastAPI
- SQLite
- PyOTP y qrcode (TOTP / Google Authenticator)
- ip-api.com (geolocalización)
- IPLogs y proxycheck.io (detección de VPN/proxy)
- Lista pública de nodos de salida de Tor Project
- Google Gemini (`gemini-2.5-flash`)
- HTML, CSS y JavaScript

---

## Instalación

### Requisitos

- Python 3.10 o superior
- Una cuenta de Google AI Studio para la clave de Gemini (opcional)
- Una cuenta de proxycheck.io para la segunda capa de VPN (opcional)

### Pasos

1. Clona el repositorio y entra a la carpeta del proyecto.
2. Crea y activa un entorno virtual de Python.
3. Instala las dependencias con `pip install -r requirements.txt`.
4. Copia `.env.example` a `.env` y completa tus claves. **Nunca subas `.env` al repositorio.**
5. Ejecuta `python crear_usuarios.py` una vez por cada usuario. El script pide el nombre y la contraseña por consola (no quedan escritos en el código), genera su secreto MFA y su código QR.
6. Escanea el QR de cada usuario con Google Authenticator y **elimina los archivos `qr_*.png`** al terminar.
7. Inicia el servidor con `uvicorn main:app --reload` y abre `http://localhost:8000`.

### Variables de entorno

| Variable | Obligatoria | Uso |
|---|---|---|
| `PROXYCHECK_API_KEY` | No | Segunda capa de detección de VPN/proxy. |
| `GEMINI_API_KEY` | No | Score de IA. Sin ella, solo se usa el score manual. |

---

## Cómo probarlo

- **Acceso normal:** inicio de sesión desde una IP local o de República Dominicana en horario habitual. Resultado esperado: permitido.
- **MFA:** conexión con VPN a un país inusual. Resultado esperado: MFA requerido.
- **Bloqueo por Tor:** acceso desde Tor Browser. Resultado esperado: bloqueado.
- **Fuerza bruta:** cinco contraseñas incorrectas seguidas. Resultado esperado: cuenta bloqueada 15 minutos.
- **Viaje imposible:** inicia sesión desde un país y, minutos después, desde otro lejano.

---

## Limitaciones conocidas

Documentarlas es parte del diseño responsable del proyecto:

1. **Cabecera `X-Forwarded-For` sin validar.** El sistema la usa para obtener la IP real detrás de proxies y túneles como ngrok. Sin un proxy de confianza, un atacante puede falsificarla y elegir su país, lo que debilita la geolocalización, el viaje imposible y los factores de riesgo por país.
2. **Endpoint `/api/logs` sin autenticación.** Expone el historial de accesos y debe protegerse antes de cualquier uso real.
3. **Sin límite de intentos por IP.** El bloqueo es por cuenta, no por origen.
4. **Bloqueo por cuenta.** Avisar de que la cuenta está bloqueada confirma que el usuario existe, y cualquiera que conozca un nombre de usuario puede bloquearlo 15 minutos con intentos fallidos (login o código MFA).
5. **Iteraciones de PBKDF2.** Se usan 100 000, por debajo de las recomendaciones actuales de OWASP para PBKDF2-SHA256. Mejoras posibles: más iteraciones o Argon2id/bcrypt.
6. **Lista de países de alto riesgo.** Penalizar por país es un criterio grueso: genera falsos positivos y no refleja a un atacante individual.
7. **Dependencia de APIs externas.** ip-api.com en su plan gratuito funciona por HTTP sin cifrar y tiene límite de peticiones.
8. **Datos de prueba.** La base de datos es SQLite local y los usuarios se crean con un script; no hay registro, recuperación de contraseña ni gestión de sesiones.

---

## Mejoras futuras

- Autenticación y roles para el panel de logs.
- Gestión de sesiones y tokens (JWT con expiración).
- Validación de la cabecera `X-Forwarded-For` mediante lista de proxies de confianza.
- Límite de peticiones por IP.
- Migración a Argon2id.
- Códigos de recuperación para MFA.
- Panel de visualización de logs y métricas.
- Pruebas automatizadas del motor de riesgo.

---

## Autores

Proyecto de tesis, ITLA.

- Axel José Acosta Medina

---

## Licencia

Distribuido bajo la licencia MIT. Consulta el archivo [LICENSE](LICENSE).
