import os
import smtplib
import ssl
import logging
from email.message import EmailMessage


def _smtp_settings():
    host = os.getenv("SMTP_HOST")
    port = int(os.getenv("SMTP_PORT", "587"))
    user = os.getenv("SMTP_USER")
    password = os.getenv("SMTP_PASSWORD")
    starttls = os.getenv("SMTP_STARTTLS", "true").lower() == "true"
    use_ssl = os.getenv("SMTP_SSL", "false").lower() == "true"
    from_email = os.getenv("SMTP_FROM") or user or "no-reply@nowplaying.axioneer.com"
    from_name = os.getenv("SMTP_FROM_NAME", "Axioneer NowPlaying")
    return {
        "host": host,
        "port": port,
        "user": user,
        "password": password,
        "starttls": starttls,
        "use_ssl": use_ssl,
        "from_email": from_email,
        "from_name": from_name,
    }


def send_email(
    to_email: str, subject: str, text_body: str, html_body: str | None = None
) -> bool:
    cfg = _smtp_settings()
    if not cfg["host"] or not cfg["port"]:
        logging.warning("SMTP non configuré: SMTP_HOST/SMTP_PORT manquants")
        return False

    msg = EmailMessage()
    from_header = f"{cfg['from_name']} <{cfg['from_email']}>"
    msg["From"] = from_header
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content(text_body)
    if html_body:
        msg.add_alternative(html_body, subtype="html")

    try:
        if cfg["use_ssl"]:
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(cfg["host"], cfg["port"], context=context) as server:
                if cfg["user"] and cfg["password"]:
                    server.login(cfg["user"], cfg["password"])
                server.send_message(msg)
        else:
            with smtplib.SMTP(cfg["host"], cfg["port"]) as server:
                server.ehlo()
                if cfg["starttls"]:
                    context = ssl.create_default_context()
                    server.starttls(context=context)
                    server.ehlo()
                if cfg["user"] and cfg["password"]:
                    server.login(cfg["user"], cfg["password"])
                server.send_message(msg)
        return True
    except Exception as e:
        logging.error(f"Erreur envoi email: {e}")
        return False


def build_password_reset_link(raw_token: str) -> str:
    """Construit l'URL de réinitialisation. Priorité:
    - PASSWORD_RESET_URL_BASE (ex: https://app/auth/reset?token=)
    - FRONTEND_URL + "/auth/reset?token="
    - http://nowplaying.axioneer.com/auth/reset?token=
    """
    base = os.getenv("PASSWORD_RESET_URL_BASE")
    if not base:
        fe = os.getenv("FRONTEND_URL")
        if fe:
            if fe.endswith("/"):
                fe = fe[:-1]
            base = f"{fe}/auth/reset?token="
        else:
            base = "http://nowplaying.axioneer.com/auth/reset?token="
    return f"{base}{raw_token}"


def build_twofa_disable_link(raw_token: str) -> str:
    """Construit l'URL de désactivation 2FA. Priorité:
    - TWOFA_DISABLE_URL_BASE (ex: https://app/auth/2fa/disable?token=)
    - FRONTEND_URL + "/auth/2fa/disable?token="
    - http://nowplaying.axioneer.com/auth/2fa/disable?token=
    """
    base = os.getenv("TWOFA_DISABLE_URL_BASE")
    if not base:
        fe = os.getenv("FRONTEND_URL")
        if fe:
            if fe.endswith("/"):
                fe = fe[:-1]
            base = f"{fe}/auth/2fa/disable?token="
        else:
            base = "http://nowplaying.axioneer.com/auth/2fa/disable?token="
    return f"{base}{raw_token}"
