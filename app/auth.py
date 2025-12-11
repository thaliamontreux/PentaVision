from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from flask import Blueprint, current_app, jsonify, request, session
from sqlalchemy import select
from sqlalchemy.orm import Session

from fido2.server import Fido2Server
from fido2.utils import websafe_decode, websafe_encode
from fido2.webauthn import (
    CollectedClientData,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
)
from fido2.ctap2 import AttestationObject

from .db import get_user_engine
from .logging_utils import log_event
from .models import User, WebAuthnCredential
from .security import seed_system_admin_role_for_email


bp = Blueprint("auth", __name__, url_prefix="/api/auth")

_ph = PasswordHasher()


def _webauthn_server() -> Fido2Server:
    rp_id = current_app.config.get("WEBAUTHN_RP_ID") or ""
    if not rp_id:
        host = request.host.split(":", 1)[0]
        rp_id = host
    rp_name = current_app.config.get("WEBAUTHN_RP_NAME", "PentaVision")
    rp = PublicKeyCredentialRpEntity(id=rp_id, name=rp_name)
    return Fido2Server(rp)


def _user_handle_for(user: User) -> bytes:
    return str(user.id).encode("utf-8")


def _credential_descriptors(creds: list[WebAuthnCredential]) -> list[PublicKeyCredentialDescriptor]:
    return [
        PublicKeyCredentialDescriptor(
            type="public-key",
            id=cred.credential_id,
            transports=(cred.transports or "").split(",") if cred.transports else None,
        )
        for cred in creds
    ]


def _webauthn_json(data):
    """Recursively convert WebAuthn/FIDO2 objects into JSON-serializable data.

    Handles:
    - Objects with a ``to_json()`` method (newer python-fido2 versions).
    - Raw bytes/bytearray values (encoded via websafe base64url).
    - Nested dicts/lists composed of the above.
    """

    to_json = getattr(data, "to_json", None)
    if callable(to_json):
        return _webauthn_json(to_json())

    if isinstance(data, (bytes, bytearray)):
        encoded = websafe_encode(data)
        # websafe_encode may return either bytes or str depending on
        # python-fido2 version. Normalize to a plain str.
        if isinstance(encoded, (bytes, bytearray)):
            return encoded.decode("ascii")
        return encoded
    if isinstance(data, dict):
        # Normalize both keys and values so no raw bytes remain anywhere.
        return {
            (
                _webauthn_json(k)
                if not isinstance(k, str)
                else k
            ): _webauthn_json(v)
            for k, v in data.items()
        }
    if isinstance(data, (list, tuple, set)):
        return [_webauthn_json(v) for v in data]
    return data


def _json_default(obj):
    """Fallback serializer for json.dumps to handle bytes and FIDO2 objects.

    This is only used in our custom _json_response helper for WebAuthn options.
    """

    if isinstance(obj, (bytes, bytearray)):
        return websafe_encode(obj).decode("ascii")

    to_json = getattr(obj, "to_json", None)
    if callable(to_json):
        return to_json()

    # Try to serialize arbitrary FIDO2 or dataclass-like objects by attrs.
    try:
        return _webauthn_json(vars(obj))
    except TypeError:
        # Last resort: string representation so JSON encoding never fails.
        return str(obj)


def _json_response(data, status_code: int = 200):
    """Return a Flask Response with JSON generated via json.dumps.

    We bypass Flask's jsonify here so that our _json_default handler is used,
    ensuring that any remaining bytes or custom WebAuthn objects are encoded
    safely instead of triggering TypeError in Flask's JSON provider.
    """

    payload = json.dumps(data, default=_json_default)
    return current_app.response_class(
        payload + "\n", mimetype="application/json", status=status_code
    )


def _encode_webauthn_state(state):
    """Encode WebAuthn state so it can be stored safely in the Flask session.

    Some python-fido2 versions return ``bytes`` for the opaque ``state`` value,
    which cannot be JSON-serialized in cookie-based sessions. For those,
    encode to websafe base64url text. If the state is already a dict or other
    JSON-serializable type, pass it through unchanged.
    """

    if isinstance(state, (bytes, bytearray)):
        return websafe_encode(state).decode("ascii")
    return state


def _decode_webauthn_state(state):
    """Decode WebAuthn state read from the Flask session back to its raw form.

    If the stored value looks like a websafe base64url string, attempt to
    decode it. Otherwise return it unchanged so newer python-fido2 versions
    that use dict-based state continue to work.
    """

    if isinstance(state, str):
        try:
            return websafe_decode(state)
        except Exception:  # noqa: BLE001
            return state
    return state


def _issue_token(user_id: int) -> str:
    """Return a simple JWT access token for the given user id."""

    import jwt

    secret = current_app.config.get("SECRET_KEY") or "change-me"
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=1)).timestamp()),
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def _verify_totp(user: User, code: str) -> bool:
    """Verify a TOTP code for the given user if TOTP is enabled."""

    raw_secret = getattr(user, "totp_secret", None) or ""
    if not raw_secret:
        return True

    if not code:
        return False

    try:
        import pyotp

        secrets: list[str] = [
            s.strip() for s in str(raw_secret).split("|") if s.strip()
        ]
        if not secrets:
            return True

        for secret in secrets:
            totp = pyotp.TOTP(secret)
            if totp.verify(code, valid_window=1):
                return True
        return False
    except Exception:  # noqa: BLE001
        return False


def _authenticate_user(email: str, password: str, totp_code: str = ""):
    """Authenticate a user by email/password/TOTP.

    Returns a tuple of (user, error_message, status_code). On success, user is
    a User instance, error_message is None, and status_code is 200. On failure,
    user is None and error_message/status_code describe the problem.
    """

    if not email or not password:
        return None, "email and password are required", 400

    engine = get_user_engine()
    if engine is None:
        return None, "user database not configured", 500

    with Session(engine, expire_on_commit=False) as session_db:
        user = session_db.scalar(select(User).where(User.email == email))
        if user is None:
            log_event("AUTH_LOGIN_FAILURE", details=f"unknown email={email}")
            return None, "invalid credentials", 401

        now = datetime.now(timezone.utc)
        if user.pin_locked_until and user.pin_locked_until > now:
            log_event(
                "AUTH_LOGIN_LOCKED",
                user_id=user.id,
                details=f"pin_locked_until={user.pin_locked_until.isoformat()}",
            )
            return None, "account locked. try again later.", 403

        try:
            _ph.verify(user.password_hash, password)
        except VerifyMismatchError:
            user.failed_pin_attempts = (user.failed_pin_attempts or 0) + 1
            if user.failed_pin_attempts >= 5:
                user.pin_locked_until = now + timedelta(minutes=15)
                log_event(
                    "AUTH_LOGIN_LOCKED_SET",
                    user_id=user.id,
                    details="failed_pin_attempts>=5",
                )
            session_db.add(user)
            session_db.commit()
            log_event("AUTH_LOGIN_FAILURE", user_id=user.id, details="bad password")
            return None, "invalid credentials", 401

        if user.totp_secret:
            if not _verify_totp(user, totp_code.strip()):
                log_event("AUTH_LOGIN_2FA_FAILURE", user_id=user.id)
                return None, "invalid 2FA code", 401

        if _ph.check_needs_rehash(user.password_hash):
            user.password_hash = _ph.hash(password)
        user.failed_pin_attempts = 0
        user.pin_locked_until = None
        user.last_login_at = now
        session_db.add(user)
        session_db.commit()

        return user, None, 200


def _authenticate_primary_factor(email: str, password: str):
    """Authenticate a user by email/password only for HTML login.

    This helper verifies the primary factor (password), including failed-login
    counters and lockout logic, but does not enforce TOTP. It returns a tuple
    of (user, error_message, status_code, requires_totp).

    - On success, ``user`` is a detached User instance, ``error_message`` is
      None, ``status_code`` is 200, and ``requires_totp`` indicates whether the
      user has TOTP enabled.
    - On failure, ``user`` is None and the other values describe the problem.
    """

    if not email or not password:
        return None, "email and password are required", 400, False

    engine = get_user_engine()
    if engine is None:
        return None, "user database not configured", 500, False

    with Session(engine, expire_on_commit=False) as session_db:
        user = session_db.scalar(select(User).where(User.email == email))
        if user is None:
            log_event("AUTH_LOGIN_FAILURE", details=f"unknown email={email}")
            return None, "invalid credentials", 401, False

        now = datetime.now(timezone.utc)
        if user.pin_locked_until and user.pin_locked_until > now:
            log_event(
                "AUTH_LOGIN_LOCKED",
                user_id=user.id,
                details=f"pin_locked_until={user.pin_locked_until.isoformat()}",
            )
            return None, "account locked. try again later.", 403, False

        try:
            _ph.verify(user.password_hash, password)
        except VerifyMismatchError:
            user.failed_pin_attempts = (user.failed_pin_attempts or 0) + 1
            if user.failed_pin_attempts >= 5:
                user.pin_locked_until = now + timedelta(minutes=15)
                log_event(
                    "AUTH_LOGIN_LOCKED_SET",
                    user_id=user.id,
                    details="failed_pin_attempts>=5",
                )
            session_db.add(user)
            session_db.commit()
            log_event("AUTH_LOGIN_FAILURE", user_id=user.id, details="bad password")
            return None, "invalid credentials", 401, False

        if _ph.check_needs_rehash(user.password_hash):
            user.password_hash = _ph.hash(password)
        user.failed_pin_attempts = 0
        user.pin_locked_until = None
        session_db.add(user)
        session_db.commit()

        requires_totp = bool(getattr(user, "totp_secret", None))
        return user, None, 200, requires_totp


@bp.post("/register")
def register():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not email or not password:
        log_event("AUTH_REGISTER_INVALID", details="missing email or password")
        return jsonify({"error": "email and password are required"}), 400

    engine = get_user_engine()
    if engine is None:
        log_event("AUTH_REGISTER_ERROR", details="user DB not configured")
        return jsonify({"error": "user database not configured"}), 500

    with Session(engine) as session:
        existing = session.scalar(select(User).where(User.email == email))
        if existing is not None:
            log_event("AUTH_REGISTER_EMAIL_EXISTS", details=f"email={email}")
            return jsonify({"error": "email already registered"}), 400

        password_hash = _ph.hash(password)
        user = User(email=email, password_hash=password_hash)
        session.add(user)
        session.commit()

        # Ensure RBAC roles exist and grant System Administrator to special
        # accounts where appropriate (including Thalia's email).
        seed_system_admin_role_for_email(user.email)

        token = _issue_token(user.id)
        log_event("AUTH_REGISTER_SUCCESS", user_id=user.id, details=f"email={email}")
        return (
            jsonify({"id": user.id, "email": user.email, "access_token": token}),
            201,
        )


@bp.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    totp_code = (data.get("totp_code") or "").strip()

    if not email or not password:
        return jsonify({"error": "email and password are required"}), 400

    user, error, status = _authenticate_user(email, password, totp_code)
    if user is None:
        return jsonify({"error": error}), status

    token = _issue_token(user.id)
    log_event("AUTH_LOGIN_SUCCESS", user_id=user.id)
    return jsonify({"access_token": token}), 200


@bp.post("/totp/setup")
def totp_setup():
    """Set up TOTP 2FA for a user using email+password verification.

    This endpoint verifies the user's credentials and, if successful and TOTP is
    not already configured, generates a new TOTP secret and returns an otpauth
    URI suitable for QR codes in authenticator apps.
    """

    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not email or not password:
        return jsonify({"error": "email and password are required"}), 400

    engine = get_user_engine()
    if engine is None:
        return jsonify({"error": "user database not configured"}), 500

    with Session(engine) as session:
        user = session.scalar(select(User).where(User.email == email))
        if user is None:
            log_event("AUTH_TOTP_SETUP_FAILURE", details=f"unknown email={email}")
            return jsonify({"error": "invalid credentials"}), 401

        try:
            _ph.verify(user.password_hash, password)
        except VerifyMismatchError:
            log_event("AUTH_TOTP_SETUP_FAILURE", user_id=user.id, details="bad password")
            return jsonify({"error": "invalid credentials"}), 401

        existing_raw = getattr(user, "totp_secret", None) or ""
        existing_secrets = [
            s.strip() for s in str(existing_raw).split("|") if s.strip()
        ]
        if len(existing_secrets) >= 2:
            return jsonify({"error": "maximum totp keys reached"}), 400

        import pyotp

        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret)
        issuer = current_app.config.get("TOTP_ISSUER", "PentaVision")
        otpauth_url = totp.provisioning_uri(name=email, issuer_name=issuer)

        new_secrets = existing_secrets + [secret]
        user.totp_secret = "|".join(new_secrets)
        session.add(user)
        session.commit()

        log_event("AUTH_TOTP_SETUP_SUCCESS", user_id=user.id)
        return jsonify({"secret": secret, "otpauth_url": otpauth_url}), 201


@bp.post("/totp/verify")
def totp_verify():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    code = (data.get("code") or "").strip()

    if not email or not password or not code:
        return (jsonify({"error": "email, password, and code are required"}), 400)

    engine = get_user_engine()
    if engine is None:
        return jsonify({"error": "user database not configured"}), 500

    with Session(engine) as session_db:
        user = session_db.scalar(select(User).where(User.email == email))
        if user is None:
            log_event("AUTH_TOTP_VERIFY_FAILURE", details=f"unknown email={email}")
            return jsonify({"error": "invalid credentials"}), 401

        try:
            _ph.verify(user.password_hash, password)
        except VerifyMismatchError:
            log_event("AUTH_TOTP_VERIFY_FAILURE", user_id=user.id, details="bad password")
            return jsonify({"error": "invalid credentials"}), 401

        raw_secret = getattr(user, "totp_secret", None) or ""
        secrets = [s.strip() for s in str(raw_secret).split("|") if s.strip()]
        if not secrets:
            return jsonify({"error": "no totp configured"}), 400

        try:
            import pyotp

            latest_secret = secrets[-1]
            totp = pyotp.TOTP(latest_secret)
            if not totp.verify(code, valid_window=1):
                log_event(
                    "AUTH_TOTP_VERIFY_FAILURE",
                    user_id=user.id,
                    details="bad_totp_code",
                )
                return jsonify({"error": "invalid 2FA code"}), 401
        except Exception:  # noqa: BLE001
            log_event(
                "AUTH_TOTP_VERIFY_FAILURE",
                user_id=user.id,
                details="totp_verify_exception",
            )
            return jsonify({"error": "failed to verify 2FA code"}), 400

        log_event("AUTH_TOTP_VERIFY_SUCCESS", user_id=user.id)
        return jsonify({"ok": True}), 200


@bp.post("/passkeys/register/begin")
def passkey_register_begin():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    nickname = (data.get("nickname") or "").strip()

    if not email or not password:
        return jsonify({"error": "email and password are required"}), 400

    engine = get_user_engine()
    if engine is None:
        return jsonify({"error": "user database not configured"}), 500

    with Session(engine) as session_db:
        user = session_db.scalar(select(User).where(User.email == email))
        if user is None:
            log_event("AUTH_WEBAUTHN_REGISTER_BEGIN_FAILURE", details=f"unknown email={email}")
            return jsonify({"error": "invalid credentials"}), 401

        try:
            _ph.verify(user.password_hash, password)
        except VerifyMismatchError:
            log_event("AUTH_WEBAUTHN_REGISTER_BEGIN_FAILURE", user_id=user.id, details="bad password")
            return jsonify({"error": "invalid credentials"}), 401

        creds = (
            session_db.query(WebAuthnCredential)
            .filter(WebAuthnCredential.user_id == user.id)
            .all()
        )

        user_entity = PublicKeyCredentialUserEntity(
            id=_user_handle_for(user),
            name=user.email,
            display_name=user.email,
        )

        server = _webauthn_server()
        options, state = server.register_begin(
            user_entity,
            _credential_descriptors(creds),
        )

        session["webauthn_register_state"] = _encode_webauthn_state(state)
        session["webauthn_register_user_id"] = user.id
        if nickname:
            session["webauthn_register_nickname"] = nickname

        log_event("AUTH_WEBAUTHN_REGISTER_BEGIN", user_id=user.id)
        return _json_response(_webauthn_json(options))


@bp.post("/passkeys/register/complete")
def passkey_register_complete():
    engine = get_user_engine()
    if engine is None:
        return jsonify({"error": "user database not configured"}), 500

    state = _decode_webauthn_state(session.get("webauthn_register_state"))
    user_id = session.get("webauthn_register_user_id")
    nickname = session.pop("webauthn_register_nickname", None)
    if not state or not user_id:
        return jsonify({"error": "no pending registration"}), 400

    data = request.get_json(silent=True) or {}
    raw_id = data.get("id") or data.get("rawId")
    response = data.get("response") or {}
    client_data_b64 = response.get("clientDataJSON")
    att_obj_b64 = response.get("attestationObject")
    if not raw_id or not client_data_b64 or not att_obj_b64:
        return jsonify({"error": "invalid attestation payload"}), 400

    client_data = CollectedClientData(websafe_decode(client_data_b64))
    att_obj = AttestationObject(websafe_decode(att_obj_b64))

    server = _webauthn_server()
    try:
        auth_data = server.register_complete(state, client_data, att_obj)
    except Exception as exc:  # noqa: BLE001
        log_event(
            "AUTH_WEBAUTHN_REGISTER_COMPLETE_FAILURE",
            user_id=int(user_id),
            details=f"{type(exc).__name__}: {exc}",
        )
        return jsonify({"error": "failed to verify attestation"}), 400

    credential_data = auth_data.credential_data
    credential_id = credential_data.credential_id
    public_key = credential_data.public_key
    sign_count = auth_data.sign_count

    with Session(engine) as session_db:
        user = session_db.get(User, int(user_id))
        if user is None:
            return jsonify({"error": "user not found"}), 400

        existing = (
            session_db.query(WebAuthnCredential)
            .filter(
                WebAuthnCredential.user_id == user.id,
                WebAuthnCredential.credential_id == credential_id,
            )
            .first()
        )
        if existing is None:
            cred = WebAuthnCredential(
                user_id=user.id,
                credential_id=credential_id,
                public_key=public_key,
                sign_count=sign_count,
                transports=None,
                nickname=nickname or None,
            )
            session_db.add(cred)
        else:
            existing.public_key = public_key
            existing.sign_count = sign_count
            existing.nickname = nickname or existing.nickname
            session_db.add(existing)
        session_db.commit()

    session.pop("webauthn_register_state", None)
    session.pop("webauthn_register_user_id", None)

    log_event("AUTH_WEBAUTHN_REGISTER_COMPLETE", user_id=int(user_id))
    return jsonify({"ok": True})


@bp.post("/passkeys/login/begin")
def passkey_login_begin():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()

    if not email:
        return jsonify({"error": "email is required"}), 400

    engine = get_user_engine()
    if engine is None:
        return jsonify({"error": "user database not configured"}), 500

    with Session(engine) as session_db:
        user = session_db.scalar(select(User).where(User.email == email))
        if user is None:
            log_event("AUTH_WEBAUTHN_LOGIN_BEGIN_FAILURE", details=f"unknown email={email}")
            return jsonify({"error": "invalid credentials"}), 401

        creds = (
            session_db.query(WebAuthnCredential)
            .filter(WebAuthnCredential.user_id == user.id)
            .all()
        )
        if not creds:
            return jsonify({"error": "no passkeys registered"}), 400

        server = _webauthn_server()
        options, state = server.authenticate_begin(_credential_descriptors(creds))

        session["webauthn_login_state"] = _encode_webauthn_state(state)
        session["webauthn_login_user_id"] = user.id

        log_event("AUTH_WEBAUTHN_LOGIN_BEGIN", user_id=user.id)
        return _json_response(_webauthn_json(options))


@bp.post("/passkeys/login/complete")
def passkey_login_complete():
    engine = get_user_engine()
    if engine is None:
        return jsonify({"error": "user database not configured"}), 500

    state = _decode_webauthn_state(session.get("webauthn_login_state"))
    user_id = session.get("webauthn_login_user_id")
    if not state or not user_id:
        return jsonify({"error": "no pending authentication"}), 400

    data = request.get_json(silent=True) or {}
    raw_id = data.get("id") or data.get("rawId")
    response = data.get("response") or {}
    client_data_b64 = response.get("clientDataJSON")
    auth_data_b64 = response.get("authenticatorData")
    signature_b64 = response.get("signature")
    if not raw_id or not client_data_b64 or not auth_data_b64 or not signature_b64:
        return jsonify({"error": "invalid assertion payload"}), 400

    credential_id = websafe_decode(raw_id)
    client_data = CollectedClientData(websafe_decode(client_data_b64))
    auth_data = websafe_decode(auth_data_b64)
    signature = websafe_decode(signature_b64)

    server = _webauthn_server()

    with Session(engine) as session_db:
        user = session_db.get(User, int(user_id))
        if user is None:
            return jsonify({"error": "user not found"}), 400

        creds = (
            session_db.query(WebAuthnCredential)
            .filter(WebAuthnCredential.user_id == user.id)
            .all()
        )
        if not creds:
            return jsonify({"error": "no passkeys registered"}), 400

        cred_map = {c.credential_id: c for c in creds}
        cred_obj = cred_map.get(credential_id)
        if cred_obj is None:
            log_event("AUTH_WEBAUTHN_LOGIN_COMPLETE_FAILURE", user_id=user.id, details="unknown credential")
            return jsonify({"error": "unknown credential"}), 400

        try:
            auth_result = server.authenticate_complete(
                state,
                _credential_descriptors(creds),
                credential_id,
                client_data,
                auth_data,
                signature,
            )
        except Exception:
            log_event("AUTH_WEBAUTHN_LOGIN_COMPLETE_FAILURE", user_id=user.id, details="verification failed")
            return jsonify({"error": "failed to verify assertion"}), 400

        cred_obj.sign_count = auth_result.new_sign_count
        cred_obj.last_used_at = datetime.now(timezone.utc)
        session_db.add(cred_obj)
        session_db.commit()

    session.pop("webauthn_login_state", None)
    session.pop("webauthn_login_user_id", None)

    token = _issue_token(int(user_id))
    log_event("AUTH_WEBAUTHN_LOGIN_COMPLETE", user_id=int(user_id))
    return jsonify({"access_token": token}), 200
