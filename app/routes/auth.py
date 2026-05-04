from fastapi import APIRouter, Depends, HTTPException, Response, Request, Body
from datetime import datetime, timedelta
import secrets, hashlib, os
from sqlalchemy.orm import Session
from ..utils.database import get_db
from ..controllers.auth_controller import AuthController
from ..schemas.auth import (
    RegisterIn,
    LoginIn,
    TokenPair,
    RefreshIn,
    ForgotPwdIn,
    ResetPwdIn,
    LoginStep1Out,
    Login2FAIn,
    LoginTokensOut,
    TwoFADisableConfirmIn,
)
from ..schemas.user import TwoFASetupOut, TwoFAVerifyIn, UserOut
from ..utils.security import decode_token
from ..utils.auth_dep import get_current_user_id
from ..models.user import User, PasswordReset
from ..utils.mailer import (
    send_email,
    build_password_reset_link,
    build_twofa_disable_link,
)
from ..utils.cookies import set_access_cookie, set_refresh_cookie, clear_auth_cookies

router = APIRouter()
ctrl = AuthController()


@router.post("/register", response_model=LoginTokensOut)
def register(payload: RegisterIn, resp: Response, db: Session = Depends(get_db)):
    try:
        u = ctrl.register(db, payload.username, payload.email, payload.password)
        # Considéré comme connecté après inscription: maj last_login_at
        u.last_login_at = datetime.utcnow()
        db.add(u)
        db.commit()
        db.refresh(u)
        # Émettre directement les tokens comme pour un login sans 2FA
        access, refresh = ctrl._issue_tokens(db, u)
        # Set HttpOnly cookies
        set_access_cookie(resp, access)
        set_refresh_cookie(resp, refresh)
        return LoginTokensOut(
            access_token=access,
            refresh_token=refresh,
            token_type="bearer",
            requires_2fa=False,
            ticket=None,
            role=getattr(u, "role", "user"),
            user_id=u.id,
        )
    except ValueError as e:
        if str(e) == "email_taken":
            raise HTTPException(status_code=409, detail="Email déjà pris")
        raise


@router.post("/login", response_model=LoginTokensOut | LoginStep1Out)
def login_step1(payload: LoginIn, resp: Response, db: Session = Depends(get_db)):
    try:
        u, ticket = ctrl.login_step1(db, payload.username_or_email, payload.password)
        if ticket:
            return {"requires_2fa": True, "ticket": ticket}
        # Pas de 2FA: on émet les tokens directement
        from ..controllers.auth_controller import AuthController

        # Rôle: default "user" (pas de champ role en DB pour l'instant)
        role = "user"
        access, refresh = AuthController()._issue_tokens(db, u)
        set_access_cookie(resp, access)
        set_refresh_cookie(resp, refresh)
        return LoginTokensOut(
            access_token=access,
            refresh_token=refresh,
            token_type="bearer",
            requires_2fa=False,
            ticket=None,
            role=role,
            user_id=u.id,
        )
    except ValueError as e:
        code = str(e)
        if code == "invalid_credentials":
            raise HTTPException(status_code=401, detail="Identifiants invalides")
        if code == "user_banned":
            raise HTTPException(status_code=403, detail="Utilisateur banni")
        raise


@router.post("/login/2fa", response_model=TokenPair)
def login_step2_totp(body: Login2FAIn, resp: Response, db: Session = Depends(get_db)):
    try:
        u, access, refresh = ctrl.login_step2_totp(db, body.ticket, body.totp)
        set_access_cookie(resp, access)
        set_refresh_cookie(resp, refresh)
        return {
            "access_token": access,
            "refresh_token": refresh,
            "token_type": "bearer",
            "user_id": u.id,
            "role": getattr(u, "role", "user"),
        }
    except ValueError as e:
        code = str(e)
        if code == "invalid_or_expired_ticket":
            raise HTTPException(status_code=400, detail="Ticket invalide ou expiré")
        if code == "totp_required_or_invalid":
            raise HTTPException(status_code=401, detail="Code 2FA requis ou invalide")
        if code == "user_not_found":
            raise HTTPException(status_code=404, detail="Utilisateur introuvable")
        if code == "user_banned":
            raise HTTPException(status_code=403, detail="Utilisateur banni")
        raise


@router.post("/refresh", response_model=TokenPair)
def refresh(
    request: Request,
    resp: Response,
    db: Session = Depends(get_db),
    payload: RefreshIn | None = Body(None),
):
    try:
        # Get refresh token from body or HttpOnly cookie
        rt = (
            payload.refresh_token
            if payload
            else request.cookies.get("mh_refresh_token")
        )
        if not rt:
            raise ValueError("missing_refresh_token")
        access, refresh = ctrl.refresh(db, rt)
        set_access_cookie(resp, access)
        set_refresh_cookie(resp, refresh)
        return {
            "access_token": access,
            "refresh_token": refresh,
            "token_type": "bearer",
        }
    except ValueError as e:
        code = str(e)
        if code == "user_banned":
            raise HTTPException(status_code=403, detail="Utilisateur banni")
        raise HTTPException(status_code=401, detail=code)


@router.post("/2fa/setup", response_model=TwoFASetupOut)
def twofa_setup(uid: str = Depends(get_current_user_id), db: Session = Depends(get_db)):
    u = db.query(User).filter(User.id == uid).first()
    if not u:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")
    secret, url = ctrl.enable_2fa(db, u)
    return {"secret": secret, "otpauth_url": url}


@router.post("/2fa/verify")
def twofa_verify(
    body: TwoFAVerifyIn,
    uid: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
):
    u = db.query(User).filter(User.id == uid).first()
    if not u:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")
    ok = ctrl.verify_2fa(db, u, body.code)
    if not ok:
        raise HTTPException(status_code=400, detail="Code invalide")
    return {"status": "ok"}


@router.post("/2fa/disable")
def twofa_disable(
    body: TwoFAVerifyIn,
    uid: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
):
    u = db.query(User).filter(User.id == uid).first()
    if not u:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")
    try:
        ctrl.disable_2fa(db, u, body.code)
        return {"status": "disabled"}
    except ValueError as e:
        code = str(e)
        if code == "twofa_not_enabled":
            raise HTTPException(status_code=400, detail="2FA non activée")
        if code == "invalid_code":
            raise HTTPException(status_code=400, detail="Code invalide")
        raise


# Password reset placeholders (token storage and email delivery to be implemented)
@router.post("/forgot")
def forgot_password(body: ForgotPwdIn, db: Session = Depends(get_db)):
    u = db.query(User).filter(User.email == body.email).first()
    # Always respond success to prevent enumeration
    if not u:
        return {"status": "sent"}
    raw = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    pr = PasswordReset(
        token=token_hash,
        user_id=u.id,
        created_at=datetime.utcnow(),
        expires_at=datetime.utcnow() + timedelta(hours=1),
    )
    db.add(pr)
    db.commit()
    # Envoi email avec lien de réinitialisation
    reset_link = build_password_reset_link(raw)
    subj = "Réinitialisation de votre mot de passe"
    txt = (
        "Bonjour,\n\n"
        "Nous avons reçu une demande de réinitialisation de mot de passe pour votre compte Axioneer NowPlaying.\n"
        f"Cliquez sur ce lien pour réinitialiser votre mot de passe (valide 1h):\n{reset_link}\n\n"
        "Si vous n'êtes pas à l'origine de cette demande, ignorez cet email.\n"
    )
    html = (
        f"<p>Bonjour,</p><p>Pour réinitialiser votre mot de passe Axioneer NowPlaying, cliquez sur le lien ci-dessous (valide 1h):</p>"
        f'<p><a href="{reset_link}">Réinitialiser mon mot de passe</a></p>'
        f"<p>Si vous n'êtes pas à l'origine de cette demande, ignorez cet email.</p>"
    )
    sent = send_email(u.email, subj, txt, html)
    if os.getenv("EMAIL_DEBUG", "false").lower() == "true":
        # Retourner aussi le token brut en mode debug
        return {"status": "sent", "token": raw, "email_sent": bool(sent)}
    return {"status": "sent", "email_sent": bool(sent)}


@router.post("/reset")
def reset_password(body: ResetPwdIn, db: Session = Depends(get_db)):
    token_hash = hashlib.sha256(body.token.encode("utf-8")).hexdigest()
    pr = db.query(PasswordReset).filter(PasswordReset.token == token_hash).first()
    if not pr:
        raise HTTPException(status_code=400, detail="Token invalide ou expiré")
    # Si expiré ou déjà utilisé: supprimer le token et signaler l'erreur
    if pr.used_at is not None or pr.expires_at < datetime.utcnow():
        try:
            db.delete(pr)
            db.commit()
        except Exception:
            db.rollback()
        raise HTTPException(status_code=400, detail="Token invalide ou expiré")
    u = db.query(User).filter(User.id == pr.user_id).first()
    if not u:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")
    from ..utils.security import hash_password

    # Mettre à jour le mot de passe
    u.password_hash = hash_password(body.new_password)

    # Désactiver la 2FA si elle est activée (sécurité : l'utilisateur a peut-être perdu son dispositif)
    if u.twofa:
        db.delete(u.twofa)
        print(
            f"2FA désactivée pour l'utilisateur {u.username} ({u.email}) lors de la réinitialisation du mot de passe"
        )

    # Consommer définitivement le token: suppression de la ligne
    db.add(u)
    db.delete(pr)
    db.commit()
    return {"status": "ok"}


@router.post("/2fa/disable/request")
def twofa_disable_request(
    uid: str = Depends(get_current_user_id), db: Session = Depends(get_db)
):
    u = db.query(User).filter(User.id == uid).first()
    if not u:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")
    raw = ctrl.request_twofa_disable(db, u)
    link = build_twofa_disable_link(raw)
    subj = "Désactivation 2FA - Confirmation requise"
    txt = (
        "Bonjour,\n\n"
        "Vous avez demandé la désactivation de la double authentification (2FA) sur votre compte Axioneer NowPlaying.\n"
        f"Si vous êtes à l'origine de cette demande, cliquez sur ce lien pour confirmer (valide 1h):\n{link}\n\n"
        "Si vous n'êtes pas à l'origine de cette demande, ignorez cet email.\n"
    )
    html = (
        f"<p>Bonjour,</p><p>Vous avez demandé la désactivation de la double authentification (2FA) sur votre compte Axioneer NowPlaying.</p>"
        f"<p>Si vous êtes à l'origine de cette demande, cliquez sur le lien ci-dessous (valide 1h):</p>"
        f'<p><a href="{link}">Confirmer la désactivation 2FA</a></p>'
        f"<p>Si vous n'êtes pas à l'origine de cette demande, ignorez cet email.</p>"
    )
    sent = send_email(u.email, subj, txt, html)
    if os.getenv("EMAIL_DEBUG", "false").lower() == "true":
        return {"status": "sent", "token": raw, "email_sent": bool(sent)}
    return {"status": "sent", "email_sent": bool(sent)}


@router.post("/2fa/disable/confirm")
def twofa_disable_confirm(body: TwoFADisableConfirmIn, db: Session = Depends(get_db)):
    try:
        ctrl.confirm_twofa_disable(db, body.token)
        return {"status": "disabled"}
    except ValueError as e:
        code = str(e)
        if code == "invalid_or_expired_token":
            raise HTTPException(status_code=400, detail="Token invalide ou expiré")
        if code == "user_not_found":
            raise HTTPException(status_code=404, detail="Utilisateur introuvable")
        raise


@router.get("/2fa/disable/confirm")
def twofa_disable_confirm_get(token: str, db: Session = Depends(get_db)):
    try:
        ctrl.confirm_twofa_disable(db, token)
        return {"status": "disabled"}
    except ValueError as e:
        code = str(e)
        if code == "invalid_or_expired_token":
            raise HTTPException(status_code=400, detail="Token invalide ou expiré")
        if code == "user_not_found":
            raise HTTPException(status_code=404, detail="Utilisateur introuvable")
        raise


@router.post("/logout")
def logout(request: Request, resp: Response, db: Session = Depends(get_db)):
    # Best-effort: supprimer la session liée au refresh token (même expiré)
    rt = request.cookies.get("mh_refresh_token")
    try:
        ctrl.logout(db, rt)
    except Exception:
        pass
    clear_auth_cookies(resp)
    return {"status": "ok"}
