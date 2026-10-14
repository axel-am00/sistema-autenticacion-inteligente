import pyotp
import qrcode


def generar_secret():
    return pyotp.random_base32()


def generar_qr(username, secret):
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=username, issuer_name="SistemaSeguro ITLA")
    img = qrcode.make(uri)
    path = f"qr_{username}.png"
    img.save(path)
    print(f"QR generado: {path}")
    return path


def verificar_codigo(secret, codigo):
    totp = pyotp.TOTP(secret)
    return totp.verify(str(codigo), valid_window=1)