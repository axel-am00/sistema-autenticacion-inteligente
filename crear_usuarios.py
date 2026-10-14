"""Crea un usuario con su secreto MFA y genera su QR.
Ejecutar una vez por usuario. Elimina el QR después de escanearlo."""
import getpass

from database import crear_tablas, crear_usuario
from mfa import generar_secret, generar_qr

crear_tablas()

usuario = input("Nombre de usuario: ").strip()
clave = getpass.getpass("Contraseña: ")
confirmar = getpass.getpass("Confirmar contraseña: ")

if not usuario or not clave:
    raise SystemExit("Usuario y contraseña son obligatorios.")
if clave != confirmar:
    raise SystemExit("Las contraseñas no coinciden.")

secret = generar_secret()
crear_usuario(usuario, clave, secret)
ruta_qr = generar_qr(usuario, secret)
print(f"Usuario creado. Escanea {ruta_qr} con Google Authenticator y bórralo después.")
