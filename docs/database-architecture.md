# Database Architecture & Segmentation

This document explains how to deploy and secure the three primary MariaDB instances used by PentaVision, matching the **Database architecture and segmentation** section of `TODO.md`.

## Components

PentaVision expects three logical databases (ideally on separate servers or instances):

- **UserDB** – user accounts, authentication, audit logs.
- **FaceDB** – facial embeddings and related biometric data.
- **RecordDB** – recording metadata, storage provider references, etc.

Each database should be isolated and use its own credentials.

---

## Physical deployment (separate instances)

For strong isolation, run each logical database on its **own MariaDB server or instance**:

- `UserDB` – holds login data and audit logs.
- `FaceDB` – holds face embeddings (biometrics).
- `RecordDB` – holds recording metadata and storage pointers.

This reduces blast radius: compromise of one DB does not automatically expose others. Use:

- Separate VMs/containers for each MariaDB instance.
- Distinct OS users and data directories.
- Dedicated network security policies per instance.

Application configuration points to each database via separate URLs:

- `USER_DB_URL`
- `FACE_DB_URL`
- `RECORD_DB_URL`

These are configured via the web installer (`/install`) and stored in `.env`.

---

## Network segmentation & TLS

Place all database servers on a **private network segment** that only the application server(s) can reach:

- Use a VPC/VNet/VLAN or equivalent to isolate DB subnets.
- Block public access to MariaDB ports (e.g. 3306) from the internet.
- Restrict inbound rules so **only the app server IP(s)** can connect.

Enable **TLS/SSL** for database connections where supported:

- Configure MariaDB with SSL certificates (server cert + CA).
- Require client certificates or at least `REQUIRE SSL` for DB users.
- Use SSL parameters in SQLAlchemy URLs if applicable. Example:

  ```text
  mysql+pymysql://user:pass@host:3306/dbname?ssl_ca=/path/to/ca.pem
  ```

This protects credentials and data in transit.

---

## Database users & least privilege

Create separate MariaDB users for each logical application component:

- `user_service` for `UserDB` only.
- `face_service` for `FaceDB` only.
- `record_service` for `RecordDB` only.

Example (run inside MariaDB):

```sql
CREATE DATABASE users_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE DATABASE faces_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE DATABASE records_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE USER 'user_service'@'app-host' IDENTIFIED BY 'strong-password-1';
CREATE USER 'face_service'@'app-host' IDENTIFIED BY 'strong-password-2';
CREATE USER 'record_service'@'app-host' IDENTIFIED BY 'strong-password-3';

GRANT SELECT, INSERT, UPDATE, DELETE ON users_db.* TO 'user_service'@'app-host';
GRANT SELECT, INSERT, UPDATE, DELETE ON faces_db.* TO 'face_service'@'app-host';
GRANT SELECT, INSERT, UPDATE, DELETE ON records_db.* TO 'record_service'@'app-host';

FLUSH PRIVILEGES;
```

Guidelines:

- Do **not** use `root` or any admin account from the application.
- Avoid `GRANT ALL PRIVILEGES` where possible.
- Limit host patterns (`'user'@'app-host'` instead of `'user'@'%'`).

Update `.env` with SQLAlchemy URLs that use these restricted accounts.

---

## No cross-DB joins

Keep tables separate per service:

- Do **not** join across databases in SQL (`SELECT ... FROM users_db.users JOIN faces_db.face_embeddings ...`).
- Instead, perform joins at the **application layer**:

  - Query IDs from one DB (e.g. `user_id` from UserDB).
  - Use those IDs to query related data from other DBs.

This preserves isolation and lets each DB scale or move independently.

---

## Backups

Each database should have its own **backup schedule**, ideally to a separate, encrypted storage location.

Recommended approach:

- Use `mysqldump` or `mariabackup` (for physical backups) per database.
- Encrypt backups at rest (e.g. GPG, encrypted object storage).
- Store backups in a separate environment or provider from production.

Example cron job using `mysqldump` (simplified):

```bash
# /etc/cron.d/pentavision-db-backups (example)
0 2 * * * root mysqldump -u backup_user -p'STRONGPASS' users_db \
  | gzip > /backups/users_db-$(date +\%F).sql.gz
```

Consider:

- Separate backup users with **read-only** access.
- Retention policies (e.g. 30–90 days) depending on compliance.
- Periodic restore tests to verify backups are usable.

---

## Summary

- Three logical databases: `UserDB`, `FaceDB`, `RecordDB`.
- Prefer separate MariaDB instances/servers for each.
- Use private networking and TLS to protect traffic.
- Enforce least-privilege DB users and avoid cross-DB joins.
- Back up each database separately, encrypting and testing restores regularly.
