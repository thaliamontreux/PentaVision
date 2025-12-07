# Passkey / WebAuthn Architecture

This document explains how passkey-based authentication (WebAuthn/FIDO2) will be integrated into PentaVision.

## Library choice

For the Python backend, we will use **Yubico's `python-fido2`** library:

- Mature, widely used FIDO2/WebAuthn implementation.
- Active maintenance and good test coverage.
- Low-level primitives to build both registration and authentication flows.
- Does not lock us into a specific framework or hosting environment.

We will combine `python-fido2` with the browser's native WebAuthn APIs (via JavaScript) to implement passkey registration and login.

### Alternatives considered

- **Duo Labs `webauthn`**: high-level helpers, but more opinionated and less flexible for our multi-tenant/future use cases.
- **Managed services (Auth0, Okta, etc.)**: not chosen to keep everything self-hosted and to avoid external dependencies for biometric-style auth.

## Data model

We will store WebAuthn credentials in the **UserDB** alongside `User` records, in a `WebAuthnCredential` table. Each record will contain:

- `id` – primary key.
- `user_id` – foreign-key reference to `User.id`.
- `credential_id` – FIDO2 credential ID (binary).
- `public_key` – FIDO2 public key (binary or base64-encoded string).
- `sign_count` – signature counter to detect cloned credentials.
- `transports` – comma-separated transports (e.g. `usb`, `ble`, `nfc`, `internal`).
- `nickname` – optional label for the device ("MacBook Pro", "iPhone", etc.).
- `created_at`, `last_used_at` – timestamps for audit and troubleshooting.

This table will be created in the same database/schema as `users`.

## High-level flows

### Registration (creating a passkey)

1. **Client initiates registration**
   - Authenticated user (after password/2FA) requests a passkey from the UI.
   - Frontend calls `POST /api/auth/passkeys/register/begin`.

2. **Server creates challenge and options**
   - Server uses `python-fido2` to generate a registration challenge with RP ID, user handle, and allowed algorithms.
   - Server stores the challenge temporarily in the session.
   - Server returns the options JSON to the browser.

3. **Browser performs WebAuthn ceremony**
   - JavaScript calls `navigator.credentials.create()` with the options.
   - Browser and authenticator (platform or roaming) create a credential and return an attestation response.

4. **Client sends attestation to server**
   - Frontend calls `POST /api/auth/passkeys/register/complete` with the attestation response.

5. **Server verifies and stores credential**
   - Server uses `python-fido2` to verify the attestation and challenge.
   - On success, server stores a new `WebAuthnCredential` row with credential ID, public key, etc.

### Authentication (logging in with a passkey)

1. **Client initiates login**
   - On the login page, user chooses "Sign in with passkey".
   - Frontend calls `POST /api/auth/passkeys/login/begin` with the username/email (or without, for usernameless flows in a future iteration).

2. **Server builds assertion options**
   - Server looks up registered credentials for that user.
   - Server uses `python-fido2` to construct assertion options and a challenge.
   - Challenge is stored in the session.

3. **Browser performs WebAuthn assertion**
   - JavaScript calls `navigator.credentials.get()` with the assertion options.
   - Authenticator signs the challenge and returns an assertion response.

4. **Client sends assertion to server**
   - Frontend calls `POST /api/auth/passkeys/login/complete` with the assertion response.

5. **Server verifies assertion**
   - Server verifies the assertion using `python-fido2`, checks `sign_count`, and verifies the origin/RP ID.
   - On success, server issues the same JWT/session as used for password logins.
   - `last_used_at` is updated for the credential.

## Integration with existing auth

- Passkeys will become the **primary** login method once implemented.
- Password-based login remains as a fallback, especially while rolling out passkeys.
- 2FA (TOTP) will be available for password logins and optionally enforced for passkey flows depending on policy.

## Security considerations

- All WebAuthn endpoints must be served over **HTTPS**.
- RP ID will be the production hostname (e.g. `example.com`) and must match the TLS certificate.
- Challenges are short-lived and stored in the server-side session.
- `sign_count` is monitored; unexpected decreases trigger alerts and may invalidate credentials.
- Credential IDs and public keys are treated as sensitive but not secret; they are still protected by DB access controls and encryption at rest.

## Next steps

- Add `python-fido2` to `requirements.txt`.
- Add `WebAuthnCredential` model to the UserDB.
- Implement JSON-based registration and login endpoints in the `auth` blueprint.
- Add frontend JavaScript to wire `navigator.credentials.create`/`get` to those endpoints.
