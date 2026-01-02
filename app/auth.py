from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from flask import Blueprint, current_app, jsonify, request, session, url_for
from sqlalchemy import select
from sqlalchemy.orm import Session

from fido2.server import Fido2Server
from fido2.utils import websafe_decode, websafe_encode
from fido2.webauthn import (
    AttestedCredentialData,
    CollectedClientData,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
)

from cryptography.fernet import Fernet

from .db import get_user_engine
from .logging_utils import _client_ip, ip_is_locked, log_event, pv_log, update_ip_lockout_after_failure
from .models import LoginFailure, User, WebAuthnCredential
from .security import seed_system_admin_role_for_email, login_user


bp = Blueprint("auth", __name__, url_prefix="/api/auth")

_ph = PasswordHasher()


def _login_failures_fernet() -> Fernet | None:
    key = str(os.environ.get("PENTAVISION_LOGIN_FAILURES_KEY") or "").strip()
    if not key:
        return None
    try:
        return Fernet(key.encode("utf-8"))
    except Exception:
        return None


def _record_login_failure(*, username: str, password: str, reason: str) -> None:
    engine = get_user_engine()
    if engine is None:
        return

    ip = _client_ip()
    user_val = str(username or "")[:255]
    pw_val = str(password or "")
    reason_val = str(reason or "")[:64]

    token: bytes | None = None
    try:
        fernet = _login_failures_fernet()
        if fernet is not None and pw_val:
            token = fernet.encrypt(pw_val.encode("utf-8", errors="replace"))
    except Exception:
        token = None

    try:
        with Session(engine) as session_db:
            try:
                LoginFailure.__table__.create(bind=engine, checkfirst=True)
            except Exception:
                pass
            row = LoginFailure(ip=str(ip or "")[:64] if ip else None, username=user_val or None, password_enc=token, reason=reason_val or None)
            session_db.add(row)
            session_db.commit()
    except Exception:
        return


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
    return _verify_totp_with_secret(raw_secret, code)


def _verify_totp_with_secret(raw_secret: str, code: str) -> bool:
    """Verify a TOTP code against a raw secret string (may contain multiple secrets separated by |)."""

    print(f"[TOTP VERIFY] raw_secret length={len(raw_secret) if raw_secret else 0}, code={code}", flush=True)

    # TEMPORARY BYPASS - remove after debugging
    if code == "000000":
        print("[TOTP VERIFY] BYPASS CODE USED", flush=True)
        return True

    if not raw_secret:
        print("[TOTP VERIFY] no secret configured, returning True", flush=True)
        return True

    if not code:
        print("[TOTP VERIFY] no code provided, returning False", flush=True)
        return False

    try:
        import pyotp

        secrets: list[str] = [
            s.strip() for s in str(raw_secret).split("|") if s.strip()
        ]
        print(f"[TOTP VERIFY] found {len(secrets)} secrets", flush=True)
        if not secrets:
            return True

        for i, secret in enumerate(secrets):
            totp = pyotp.TOTP(secret)
            expected = totp.now()
            print(f"[TOTP VERIFY] secret[{i}]={secret} expected={expected}, provided={code}", flush=True)
            if totp.verify(code, valid_window=1):
                print(f"[TOTP VERIFY] SUCCESS with secret[{i}]", flush=True)
                return True
        print("[TOTP VERIFY] no secrets matched", flush=True)
        return False
    except Exception as e:  # noqa: BLE001
        print(f"[TOTP VERIFY] exception {e}", flush=True)
        return False


def _authenticate_user(email: str, password: str, totp_code: str = ""):
    """Authenticate a user by email/password/TOTP.

    Returns a tuple of (user, error_message, status_code). On success, user is
    a User instance, error_message is None, and status_code is 200. On failure,
    user is None and error_message/status_code describe the problem.
    """

    if ip_is_locked():
        pv_log(
            "security",
            "warn",
            "auth_login_rejected_ip_locked",
            component="auth",
            email=str(email or "")[:256],
        )
        return None, "too many failed login attempts from this IP. try again later.", 403

    if not email or not password:
        return None, "email and password are required", 400

    engine = get_user_engine()
    if engine is None:
        return None, "user database not configured", 500

    with Session(engine, expire_on_commit=False) as session_db:
        user = session_db.scalar(select(User).where(User.email == email))
        if user is None:
            _record_login_failure(username=email, password=password, reason="unknown_email")
            log_event("AUTH_LOGIN_FAILURE", details=f"unknown email={email}")
            pv_log(
                "security",
                "warn",
                "auth_login_failure_unknown_email",
                component="auth",
                email=str(email or "")[:256],
            )
            update_ip_lockout_after_failure()
            return None, "invalid credentials", 401

        now = datetime.now(timezone.utc)
        if user.pin_locked_until and user.pin_locked_until > now:
            log_event(
                "AUTH_LOGIN_LOCKED",
                user_id=user.id,
                details=f"pin_locked_until={user.pin_locked_until.isoformat()}",
            )
            pv_log(
                "security",
                "warn",
                "auth_login_rejected_user_locked",
                component="auth",
                user_id=int(user.id),
                email=str(email or "")[:256],
            )
            return None, "account locked. try again later.", 403

        try:
            _ph.verify(user.password_hash, password)
        except VerifyMismatchError:
            _record_login_failure(username=email, password=password, reason="bad_password")
            user.failed_pin_attempts = (user.failed_pin_attempts or 0) + 1
            if user.failed_pin_attempts >= 5:
                user.pin_locked_until = now + timedelta(minutes=15)
                log_event(
                    "AUTH_LOGIN_LOCKED_SET",
                    user_id=user.id,
                    details="failed_pin_attempts>=5",
                )
                pv_log(
                    "security",
                    "warn",
                    "auth_user_lock_set_failed_pin_attempts",
                    component="auth",
                    user_id=int(user.id),
                    email=str(email or "")[:256],
                    failed_pin_attempts=int(user.failed_pin_attempts or 0),
                )
            session_db.add(user)
            session_db.commit()
            log_event("AUTH_LOGIN_FAILURE", user_id=user.id, details="bad password")
            pv_log(
                "security",
                "warn",
                "auth_login_failure_bad_password",
                component="auth",
                user_id=int(user.id),
                email=str(email or "")[:256],
            )
            update_ip_lockout_after_failure()
            return None, "invalid credentials", 401

        if user.totp_secret:
            if not _verify_totp(user, totp_code.strip()):
                _record_login_failure(username=email, password=password, reason="bad_2fa")
                log_event("AUTH_LOGIN_2FA_FAILURE", user_id=user.id)
                pv_log(
                    "security",
                    "warn",
                    "auth_login_2fa_failure",
                    component="auth",
                    user_id=int(user.id),
                    email=str(email or "")[:256],
                )
                update_ip_lockout_after_failure()
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

    if ip_is_locked():
        return None, "too many failed login attempts from this IP. try again later.", 403, False

    if not email or not password:
        return None, "email and password are required", 400, False

    engine = get_user_engine()
    if engine is None:
        return None, "user database not configured", 500, False

    with Session(engine, expire_on_commit=False) as session_db:
        user = session_db.scalar(select(User).where(User.email == email))
        if user is None:
            _record_login_failure(username=email, password=password, reason="unknown_email")
            log_event("AUTH_LOGIN_FAILURE", details=f"unknown email={email}")
            update_ip_lockout_after_failure()
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
            _record_login_failure(username=email, password=password, reason="bad_password")
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
            update_ip_lockout_after_failure()
            return None, "invalid credentials", 401, False

        if _ph.check_needs_rehash(user.password_hash):
            user.password_hash = _ph.hash(password)
        user.failed_pin_attempts = 0
        user.pin_locked_until = None
        session_db.add(user)
        session_db.commit()

        totp_secret_val = getattr(user, "totp_secret", None)
        requires_totp = bool(totp_secret_val)
        print(f"[AUTH DEBUG] User {email} totp_secret={totp_secret_val!r}, requires_totp={requires_totp}", flush=True)
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

    if ip_is_locked():
        return (
            jsonify(
                {
                    "error": "too many failed login attempts from this IP. try again later.",
                }
            ),
            403,
        )

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
            update_ip_lockout_after_failure()
            return jsonify({"error": "invalid credentials"}), 401

        try:
            _ph.verify(user.password_hash, password)
        except VerifyMismatchError:
            log_event("AUTH_TOTP_SETUP_FAILURE", user_id=user.id, details="bad password")
            update_ip_lockout_after_failure()
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
        print(f"[TOTP SETUP] Saving secret for {email}: {secret} (length={len(secret)})", flush=True)
        print(f"[TOTP SETUP] Full totp_secret will be: {user.totp_secret}", flush=True)
        session.add(user)
        session.commit()
        
        # Verify it was saved correctly
        session.refresh(user)
        print(f"[TOTP SETUP] After commit, totp_secret is: {user.totp_secret}", flush=True)

        log_event("AUTH_TOTP_SETUP_SUCCESS", user_id=user.id)
        return jsonify({"secret": secret, "otpauth_url": otpauth_url}), 201


@bp.post("/totp/verify")
def totp_verify():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    code = (data.get("code") or "").strip()

    if ip_is_locked():
        return (
            jsonify(
                {
                    "error": "too many failed login attempts from this IP. try again later.",
                }
            ),
            403,
        )

    if not email or not password or not code:
        return (jsonify({"error": "email, password, and code are required"}), 400)

    engine = get_user_engine()
    if engine is None:
        return jsonify({"error": "user database not configured"}), 500

    with Session(engine) as session_db:
        user = session_db.scalar(select(User).where(User.email == email))
        if user is None:
            log_event("AUTH_TOTP_VERIFY_FAILURE", details=f"unknown email={email}")
            update_ip_lockout_after_failure()
            return jsonify({"error": "invalid credentials"}), 401

        try:
            _ph.verify(user.password_hash, password)
        except VerifyMismatchError:
            log_event("AUTH_TOTP_VERIFY_FAILURE", user_id=user.id, details="bad password")
            update_ip_lockout_after_failure()
            return jsonify({"error": "invalid credentials"}), 401

        raw_secret = getattr(user, "totp_secret", None) or ""
        secrets = [s.strip() for s in str(raw_secret).split("|") if s.strip()]
        print(f"[TOTP VERIFY ENDPOINT] raw_secret from DB: {raw_secret}", flush=True)
        print(f"[TOTP VERIFY ENDPOINT] secrets list: {secrets}", flush=True)
        if not secrets:
            return jsonify({"error": "no totp configured"}), 400

        try:
            import pyotp

            latest_secret = secrets[-1]
            totp = pyotp.TOTP(latest_secret)
            expected_code = totp.now()
            print(f"[TOTP VERIFY ENDPOINT] Using secret: {latest_secret}, expected={expected_code}, provided={code}", flush=True)
            if not totp.verify(code, valid_window=1):
                log_event(
                    "AUTH_TOTP_VERIFY_FAILURE",
                    user_id=user.id,
                    details="bad_totp_code",
                )
                update_ip_lockout_after_failure()
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
            update_ip_lockout_after_failure()
            return jsonify({"error": "invalid credentials"}), 401

        try:
            _ph.verify(user.password_hash, password)
        except VerifyMismatchError:
            log_event("AUTH_WEBAUTHN_REGISTER_BEGIN_FAILURE", user_id=user.id, details="bad password")
            update_ip_lockout_after_failure()
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
    if not isinstance(data, dict):
        return jsonify({"error": "invalid attestation payload"}), 400

    response = data.get("response") or {}
    if not isinstance(response, dict):
        return jsonify({"error": "invalid attestation payload"}), 400

    if not response.get("clientDataJSON") or not response.get("attestationObject"):
        return jsonify({"error": "invalid attestation payload"}), 400

    # Let python-fido2 handle decoding and id/rawId consistency checks using
    # its own RegistrationResponse.from_dict implementation.
    server = _webauthn_server()
    try:
        auth_data = server.register_complete(state, data)
    except Exception as exc:  # noqa: BLE001
        details = f"{type(exc).__name__}: {exc}"
        log_event(
            "AUTH_WEBAUTHN_REGISTER_COMPLETE_FAILURE",
            user_id=int(user_id),
            details=details,
        )
        return jsonify(
            {"error": f"failed to verify attestation: {details}"}
        ), 400

    credential_data = auth_data.credential_data
    credential_id = credential_data.credential_id

    # Serialize the public key object to bytes for storage in the DB. Different
    # python-fido2 versions may expose this as a COSE key object or a plain
    # dict like {1: 2, 3: -7, ...}. SQLAlchemy's LargeBinary expects a
    # bytes-like value, so we CBOR-encode when possible and fall back to a
    # JSON/string representation.
    public_key_bytes = b""
    public_key_obj = getattr(credential_data, "public_key", None)
    if public_key_obj is not None:
        try:  # Prefer canonical CBOR encoding used by WebAuthn COSE keys.
            from fido2 import cbor as _fido2_cbor  # type: ignore

            public_key_bytes = _fido2_cbor.encode(public_key_obj)
        except Exception:  # noqa: BLE001
            try:
                public_key_bytes = json.dumps(_webauthn_json(public_key_obj)).encode(
                    "utf-8"
                )
            except Exception:  # noqa: BLE001
                public_key_bytes = str(public_key_obj).encode("utf-8")

    # Some python-fido2 versions expose the registration counter as
    # auth_data.sign_count, others as auth_data.counter, and some may not
    # expose it at all. Normalize to an int and default to 0.
    sign_count = getattr(auth_data, "sign_count", getattr(auth_data, "counter", 0))

    with Session(engine, expire_on_commit=False) as session_db:
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
                public_key=public_key_bytes,
                sign_count=sign_count,
                transports=None,
                nickname=nickname or None,
            )
            session_db.add(cred)
        else:
            existing.public_key = public_key_bytes
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

    if ip_is_locked():
        return (
            jsonify(
                {
                    "error": "too many failed login attempts from this IP. try again later.",
                }
            ),
            403,
        )

    if not email:
        return jsonify({"error": "email is required"}), 400

    engine = get_user_engine()
    if engine is None:
        return jsonify({"error": "user database not configured"}), 500

    with Session(engine) as session_db:
        user = session_db.scalar(select(User).where(User.email == email))
        if user is None:
            log_event("AUTH_WEBAUTHN_LOGIN_BEGIN_FAILURE", details=f"unknown email={email}")
            update_ip_lockout_after_failure()
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
    if ip_is_locked():
        return (
            jsonify(
                {
                    "error": "too many failed login attempts from this IP. try again later.",
                }
            ),
            403,
        )

    if not state or not user_id:
        return jsonify({"error": "no pending authentication"}), 400

    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return jsonify({"error": "invalid assertion payload"}), 400

    response = data.get("response") or {}
    if not isinstance(response, dict):
        return jsonify({"error": "invalid assertion payload"}), 400

    raw_id_b64 = data.get("rawId") or data.get("id")
    client_data_b64 = response.get("clientDataJSON")
    auth_data_b64 = response.get("authenticatorData")
    signature_b64 = response.get("signature")
    if not raw_id_b64 or not client_data_b64 or not auth_data_b64 or not signature_b64:
        return jsonify({"error": "invalid assertion payload"}), 400

    # Decode credential id bytes so we can look up the stored credential, but
    # otherwise pass the raw WebAuthn response mapping into python-fido2 so it
    # can handle base64url decoding via its from_dict helpers.
    credential_id = websafe_decode(raw_id_b64)

    server = _webauthn_server()

    with Session(engine, expire_on_commit=False) as session_db:
        user = session_db.get(User, int(user_id))
        if user is None:
            return jsonify({"error": "user not found"}), 400

        stored_creds = (
            session_db.query(WebAuthnCredential)
            .filter(WebAuthnCredential.user_id == user.id)
            .all()
        )
        if not stored_creds:
            return jsonify({"error": "no passkeys registered"}), 400

        cred_map = {c.credential_id: c for c in stored_creds}
        cred_obj = cred_map.get(credential_id)
        if cred_obj is None:
            log_event(
                "AUTH_WEBAUTHN_LOGIN_COMPLETE_FAILURE",
                user_id=user.id,
                details="unknown credential",
            )
            return jsonify({"error": "unknown credential"}), 400

        # Build AttestedCredentialData objects from the stored credentials so
        # python-fido2 sees the expected interface (credential_id,
        # public_key.verify(), etc.). We persisted the COSE public key bytes
        # in WebAuthnCredential.public_key, so we can reconstruct the binary
        # attested credential data structure directly.
        try:
            creds_for_verify: list[AttestedCredentialData] = []
            for c in stored_creds:
                aaguid = b"\x00" * 16
                cid = c.credential_id
                raw = aaguid + len(cid).to_bytes(2, "big") + cid + c.public_key
                creds_for_verify.append(AttestedCredentialData(raw))

            # Prefer the newer python-fido2 authenticate_complete(state,
            # credentials, response) API by passing the raw WebAuthn mapping
            # from the browser together with AttestedCredentialData objects.
            try:
                auth_result = server.authenticate_complete(
                    state,
                    creds_for_verify,
                    data,
                )
            except TypeError:
                # Fallback for older python-fido2 versions that expect the
                # expanded multi-argument form using the same credentials
                # list.
                client_data = CollectedClientData(websafe_decode(client_data_b64))
                auth_data = websafe_decode(auth_data_b64)
                signature = websafe_decode(signature_b64)
                auth_result = server.authenticate_complete(
                    state,
                    creds_for_verify,
                    credential_id,
                    client_data,
                    auth_data,
                    signature,
                )
        except Exception as exc:  # noqa: BLE001
            details = f"{type(exc).__name__}: {exc}"
            log_event(
                "AUTH_WEBAUTHN_LOGIN_COMPLETE_FAILURE",
                user_id=user.id,
                details=details,
            )
            return jsonify({"error": f"failed to verify assertion: {details}"}), 400

        # Newer python-fido2 authenticate_complete implementations may not
        # expose a new_sign_count attribute on the returned object. In that
        # case, keep the existing stored sign_count. Older versions that do
        # provide new_sign_count will still be supported via getattr.
        new_sign_count = getattr(auth_result, "new_sign_count", cred_obj.sign_count)
        cred_obj.sign_count = int(new_sign_count or 0)
        cred_obj.last_used_at = datetime.now(timezone.utc)
        session_db.add(cred_obj)

        user.last_login_at = datetime.now(timezone.utc)
        session_db.add(user)

        session_db.commit()

    session.pop("webauthn_login_state", None)
    session.pop("webauthn_login_user_id", None)

    # If the user has TOTP configured, require it as a second step even after
    # successful passkey verification. This mirrors the HTML password login
    # flow, which always routes TOTP-enabled users through /login/totp.
    has_totp = bool(getattr(user, "totp_secret", None))
    if has_totp:
        next_url = data.get("next") or url_for("main.index")
        if not str(next_url).startswith("/"):
            next_url = url_for("main.index")
        session["pending_totp_user_id"] = int(user.id)
        session["pending_totp_next"] = next_url
        log_event(
            "AUTH_WEBAUTHN_LOGIN_TOTP_REQUIRED",
            user_id=int(user_id),
        )
        return (
            jsonify(
                {
                    "totp_required": True,
                    "redirect": url_for("main.login_totp"),
                    "next": next_url,
                }
            ),
            200,
        )

    login_user(user)

    token = _issue_token(int(user_id))
    log_event("AUTH_WEBAUTHN_LOGIN_COMPLETE", user_id=int(user_id))
    return jsonify({"access_token": token}), 200
