# Privacy and Security Notes

This document provides high-level guidance for deploying PentaVision in a
privacy-conscious way, with an emphasis on biometric data (faces) and logs.
It is not legal advice but is intended to support GDPR-like principles such as
purpose limitation, data minimization, and user rights.

---

## Data categories

PentaVision handles several categories of personal data:

- **Account data** – user identifiers, emails, authentication attributes.
- **Biometric data** – facial embeddings stored in `FaceDB`.
- **Video data** – recordings and live streams from cameras.
- **Logs and audit events** – authentication attempts, configuration changes,
  and operational events.

Treat all of these as potentially sensitive and restrict access accordingly.

---

## Purpose limitation and consent

- Clearly document why facial recognition is used (e.g. access control,
  presence tracking) and who is affected (staff, visitors, etc.).
- Obtain appropriate consent or establish another lawful basis before enrolling
  individuals in FaceDB.
- Avoid using biometric data for unrelated purposes (e.g. marketing) unless
  explicitly and separately agreed.

---

## Data minimization

- Store **embeddings**, not raw facial images, whenever possible.
- Disable recording or facial recognition for cameras where it is not needed.
- Avoid logging more information than necessary (for example, do not include
  full credential data in logs).

---

## Facial recognition data handling

See `docs/facial-recognition.md` for technical details. Operationally:

- Maintain a clear list of who is enrolled and why.
- Use the opt-out APIs to exclude individuals from recognition where required
  by policy or law.
- When processing deletion or access requests, treat the `FaceEmbedding` table
  as part of a person's biometric record.

### Retention

- Define a retention policy for facial embeddings (for example, keep them only
  while a user has an active account and valid consent).
- Periodically review and remove embeddings for users who are no longer active
  or whose consent has been withdrawn.

### Deletion procedures

- When a user requests deletion of their biometric data:
  - Remove or disable their account in `UserDB` as appropriate.
  - Delete all `FaceEmbedding` rows associated with their `user_id` in `FaceDB`.
  - Clear or update any `FacePrivacySetting` records for that user.
- Document who is authorized to perform these deletions and how they are
  audited (for example, via `AuditEvent` entries).

---

## Logging and audit trails

See `docs/logging-monitoring.md` for schema and operational guidance.

- Consider audit logs and web server logs as personal data (IP addresses,
  user IDs, camera identifiers).
- Limit access to logs to a small number of administrators.
- Define retention periods for logs (for example, 90 days for security
  investigations, longer if required by regulation).
- If you export logs to external systems (SIEM, log analytics), ensure those
  systems are subject to the same security and privacy controls.

---

## Security controls

- Use HTTPS everywhere; avoid exposing the app or installer over plain HTTP.
- Store database credentials, storage provider keys, and other secrets in
  environment variables or a secure secrets manager, not in source control.
- Ensure `APP_SECRET_KEY` is strong and never shared between environments.
- Restrict direct database access to application servers and DBAs only.
- Regularly apply OS and dependency security updates.

---

## Data subject rights

For GDPR-like regimes, individuals may have rights to:

- **Access** – obtain a copy of their personal data (account info, relevant
  logs, and any facial recognition records).
- **Rectification** – correct inaccurate account information.
- **Erasure** – request deletion of their data, including biometric templates
  and associated logs, subject to legal retention requirements.
- **Restriction/objection** – opt out of facial recognition where feasible.

You should define internal processes for handling such requests, including
identity verification, response timelines, and documentation of actions taken.

---

## Summary

- Treat biometric data and logs as highly sensitive.
- Use the configuration options and database segmentation provided by the app
  to enforce least privilege and clear boundaries.
- Combine technical controls (encryption, access control, logging) with policy
  and process (consent management, retention schedules, documented deletion
  procedures) to achieve a defensible privacy posture.
