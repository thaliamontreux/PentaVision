from __future__ import annotations

import io
import json
import os
import tempfile
import ftplib
import ssl
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO, Dict, List, Optional
from urllib.parse import quote_plus
import time

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError, NoCredentialsError
from flask import Flask
from sqlalchemy import Column, DateTime, Integer, LargeBinary, MetaData, Table, create_engine, delete as sa_delete, func, insert, select, update as sa_update
from sqlalchemy.orm import Session
from google.cloud import storage as gcs_storage

try:
    from azure.storage.blob import BlobServiceClient, ContentSettings
except ImportError:
    BlobServiceClient = None  # type: ignore
    ContentSettings = None  # type: ignore

import dropbox
import requests
import paramiko
from scp import SCPClient

from .db import get_record_engine
from .models import RecordingData, StorageModule, StorageSettings
from .storage_csal import (
    StorageAuthError,
    StorageError,
    StorageModuleBase,
    StoragePermanentError,
    StorageRouter,
    StorageTransientError,
)


def _recordings_prefix_for_hint(key_hint: str) -> str:
    raw = str(key_hint or "").strip()
    if not raw:
        return "recordings"
    match = re.match(r"^camera(?P<id>\d+)(?:\b|_)", raw)
    if not match:
        return "recordings"
    cam_id = match.group("id")
    if not cam_id:
        return "recordings"
    return f"recordings/camera_{cam_id}"


class StorageProvider:
    name: str

    def upload(self, data: bytes, key_hint: str) -> str:
        raise NotImplementedError

    def get_url(self, storage_key: str) -> Optional[str]:
        return None

    def delete(self, storage_key: str) -> None:
        raise NotImplementedError

    def record_write_test(self, at: datetime | None = None) -> None:
        raise NotImplementedError


class ExternalSQLDatabaseStorageProvider(StorageProvider):
    def __init__(
        self,
        db_type: str,
        host: str,
        port: Optional[int],
        database: str,
        username: Optional[str],
        password: Optional[str],
        mssql_driver: Optional[str],
    ) -> None:
        self.name = "sql_db"
        self._db_type = (db_type or "").strip().lower()
        self._host = str(host or "").strip()
        self._port = int(port) if port is not None else None
        self._database = str(database or "").strip()
        self._username = str(username or "").strip() or None
        self._password = str(password or "").strip() or None
        self._mssql_driver = str(mssql_driver or "").strip() or None
        self._engine = None
        self._table = None
        self._test_table = None

    def _build_sqlalchemy_url(self) -> str:
        if not self._host:
            raise RuntimeError("SQL DB host is required")
        if not self._database:
            raise RuntimeError("SQL DB database name is required")

        if self._db_type in {"mysql", "mariadb"}:
            port = self._port if self._port is not None else 3306
            auth = ""
            if self._username:
                pwd = quote_plus(self._password or "")
                auth = f"{quote_plus(self._username)}:{pwd}@"
            return f"mysql+pymysql://{auth}{self._host}:{port}/{self._database}"

        if self._db_type in {"postgres", "postgresql"}:
            port = self._port if self._port is not None else 5432
            auth = ""
            if self._username:
                pwd = quote_plus(self._password or "")
                auth = f"{quote_plus(self._username)}:{pwd}@"
            # Requires psycopg2/psycopg in the environment.
            return f"postgresql+psycopg2://{auth}{self._host}:{port}/{self._database}"

        if self._db_type in {"mssql", "sqlserver", "sql_server"}:
            port = self._port if self._port is not None else 1433
            driver = self._mssql_driver or "ODBC Driver 18 for SQL Server"
            # Requires pyodbc + system ODBC driver.
            auth = ""
            if self._username:
                pwd = quote_plus(self._password or "")
                auth = f"{quote_plus(self._username)}:{pwd}@"
            return (
                f"mssql+pyodbc://{auth}{self._host}:{port}/{self._database}"
                f"?driver={quote_plus(driver)}&TrustServerCertificate=yes"
            )

        raise RuntimeError("Unsupported SQL DB type. Use mysql, postgres, or mssql.")

    def _ensure_engine(self):
        if self._engine is not None:
            return
        url = self._build_sqlalchemy_url()
        self._engine = create_engine(url, pool_pre_ping=True)

    def _ensure_table(self):
        if self._table is not None:
            return
        self._ensure_engine()
        metadata = MetaData()
        self._table = Table(
            "external_recording_data",
            metadata,
            Column("id", Integer, primary_key=True, autoincrement=True),
            Column("data", LargeBinary, nullable=False),
            Column("created_at", DateTime(timezone=True), server_default=func.now()),
        )
        metadata.create_all(self._engine)

    def _ensure_test_table(self):
        if self._test_table is not None:
            return
        self._ensure_engine()
        metadata = MetaData()
        self._test_table = Table(
            "pv_sql_write_test",
            metadata,
            Column("id", Integer, primary_key=True, autoincrement=False),
            Column("old_test_date", DateTime(timezone=True), nullable=True),
            Column("latest_test_date", DateTime(timezone=True), nullable=True),
        )
        metadata.create_all(self._engine)

    def ensure_write_test_table(self) -> None:
        self._ensure_test_table()
        with self._engine.begin() as conn:
            row = conn.execute(
                select(self._test_table.c.id).where(self._test_table.c.id == 1)
            ).first()
            if row is None:
                conn.execute(
                    insert(self._test_table).values(
                        {
                            "id": 1,
                            "old_test_date": None,
                            "latest_test_date": None,
                        }
                    )
                )

    def record_write_test(self, at: datetime | None = None) -> None:
        self._ensure_test_table()
        # Use timezone-aware UTC timestamps to keep behavior consistent.
        now_dt = at or datetime.now(timezone.utc)
        with self._engine.begin() as conn:
            prev_latest = None
            try:
                row = conn.execute(
                    select(self._test_table.c.latest_test_date).where(self._test_table.c.id == 1)
                ).first()
                if row is not None:
                    prev_latest = row[0]
            except Exception:  # noqa: BLE001
                prev_latest = None

            # Ensure row exists.
            try:
                exists = conn.execute(
                    select(self._test_table.c.id).where(self._test_table.c.id == 1)
                ).first()
            except Exception:  # noqa: BLE001
                exists = None

            if exists is None:
                conn.execute(
                    insert(self._test_table).values(
                        {
                            "id": 1,
                            "old_test_date": None,
                            "latest_test_date": now_dt,
                        }
                    )
                )
                return

            conn.execute(
                sa_update(self._test_table)
                .where(self._test_table.c.id == 1)
                .values({"old_test_date": prev_latest, "latest_test_date": now_dt})
            )

    def upload(self, data: bytes, key_hint: str) -> str:
        self._ensure_table()
        stmt = insert(self._table).values({"data": data})
        with self._engine.begin() as conn:
            res = conn.execute(stmt)
            try:
                new_id = res.inserted_primary_key[0]
            except Exception:  # noqa: BLE001
                new_id = None
        return f"external_recording_data:{new_id}" if new_id is not None else "external_recording_data"

    def get_url(self, storage_key: str) -> Optional[str]:
        return None

    def delete(self, storage_key: str) -> None:
        self._ensure_table()
        raw = str(storage_key or "").strip()
        if not raw:
            return

        table_name = "external_recording_data"
        row_id: int | None = None
        if ":" in raw:
            parts = raw.split(":", 1)
            if len(parts) == 2:
                table_name = (parts[0] or "").strip() or table_name
                try:
                    row_id = int((parts[1] or "").strip())
                except Exception:  # noqa: BLE001
                    row_id = None
        else:
            try:
                row_id = int(raw)
            except Exception:  # noqa: BLE001
                row_id = None

        if table_name != "external_recording_data":
            return
        if row_id is None:
            return

        stmt = sa_delete(self._table).where(self._table.c.id == row_id)
        with self._engine.begin() as conn:
            conn.execute(stmt)


class S3StorageProvider(StorageProvider):
    def __init__(
        self,
        endpoint: Optional[str],
        region: Optional[str],
        bucket: str,
        access_key: str,
        secret_key: str,
    ) -> None:
        self.name = "s3"
        self.bucket = bucket
        self.endpoint = endpoint or None
        self.region = region or None
        self._client = boto3.client(
            "s3",
            endpoint_url=self.endpoint,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=self.region,
        )

    def upload(self, data: bytes, key_hint: str) -> str:
        safe_hint = key_hint.replace("/", "_").replace("\\", "_")
        now = datetime.utcnow().strftime("%Y%m%dT%H%M%S")
        prefix = _recordings_prefix_for_hint(key_hint)
        key = f"{prefix}/{now}_{safe_hint}.mp4"
        self._client.put_object(
            Bucket=self.bucket,
            Key=key,
            Body=data,
            ContentType="video/mp4",
        )
        return key

    def get_url(self, storage_key: str) -> Optional[str]:
        try:
            url = self._client.generate_presigned_url(
                "get_object",
                Params={"Bucket": self.bucket, "Key": storage_key},
                ExpiresIn=3600,
            )
        except Exception:  # noqa: BLE001
            return None
        return url

    def delete(self, storage_key: str) -> None:
        try:
            self._client.delete_object(Bucket=self.bucket, Key=storage_key)
        except Exception:  # noqa: BLE001
            return


class LocalFilesystemStorageProvider(StorageProvider):
    def __init__(self, base_dir: str) -> None:
        self.name = "local_fs"
        self.base_path = Path(base_dir).expanduser().resolve()
        self.base_path.mkdir(parents=True, exist_ok=True)

    def upload(self, data: bytes, key_hint: str) -> str:
        safe_hint = key_hint.replace("/", "_").replace("\\", "_")
        now = datetime.utcnow().strftime("%Y%m%dT%H%M%S")
        filename = f"{now}_{safe_hint}.mp4"
        prefix = _recordings_prefix_for_hint(key_hint)
        rel_dir = ""
        if prefix.startswith("recordings/"):
            rel_dir = prefix.split("/", 1)[1]
        target_dir = self.base_path / rel_dir if rel_dir else self.base_path
        target_dir.mkdir(parents=True, exist_ok=True)
        path = target_dir / filename
        counter = 1
        while path.exists():
            filename = f"{now}_{safe_hint}_{counter}.mp4"
            path = target_dir / filename
            counter += 1
        with open(path, "wb") as handle:
            handle.write(data)
        return str(path)

    def get_url(self, storage_key: str) -> Optional[str]:
        return None

    def delete(self, storage_key: str) -> None:
        try:
            target = Path(str(storage_key)).expanduser()
            if not target.is_absolute():
                target = self.base_path / target
            target = target.resolve()
            try:
                target.relative_to(self.base_path)
            except ValueError:
                return
            if target.exists() and target.is_file():
                target.unlink()
        except Exception:  # noqa: BLE001
            return


class DatabaseStorageProvider(StorageProvider):
    def __init__(self) -> None:
        self.name = "db"

    def upload(self, data: bytes, key_hint: str) -> str:
        engine = get_record_engine()
        if engine is None:
            raise RuntimeError("Record database is not configured")
        RecordingData.__table__.create(bind=engine, checkfirst=True)
        with Session(engine) as session:
            row = RecordingData(data=data)
            session.add(row)
            session.commit()
            return f"recording_data:{row.id}"

    def get_url(self, storage_key: str) -> Optional[str]:
        return None

    def delete(self, storage_key: str) -> None:
        raw = str(storage_key or "").strip()
        if not raw or ":" not in raw:
            return
        prefix, rid = raw.split(":", 1)
        if (prefix or "").strip() != "recording_data":
            return
        try:
            row_id = int((rid or "").strip())
        except Exception:  # noqa: BLE001
            return

        engine = get_record_engine()
        if engine is None:
            return

        try:
            RecordingData.__table__.create(bind=engine, checkfirst=True)
            with Session(engine) as session:
                row = session.get(RecordingData, row_id)
                if row is None:
                    return
                session.delete(row)
                session.commit()
        except Exception:  # noqa: BLE001
            return

    def record_write_test(self, at: datetime | None = None) -> None:
        engine = get_record_engine()
        if engine is None:
            raise RuntimeError("Record database is not configured")

        now_dt = at or datetime.now(timezone.utc)
        metadata = MetaData()
        test_table = Table(
            "TestRDB",
            metadata,
            Column("id", Integer, primary_key=True, autoincrement=False),
            Column("test_date_old", DateTime(timezone=True), nullable=True),
            Column("test_date", DateTime(timezone=True), nullable=True),
        )
        metadata.create_all(engine)

        with engine.begin() as conn:
            prev = None
            row = conn.execute(select(test_table.c.test_date).where(test_table.c.id == 1)).first()
            if row is not None:
                prev = row[0]

            exists = conn.execute(select(test_table.c.id).where(test_table.c.id == 1)).first()
            if exists is None:
                conn.execute(
                    insert(test_table).values({"id": 1, "test_date_old": None, "test_date": now_dt})
                )
                return

            conn.execute(
                sa_update(test_table)
                .where(test_table.c.id == 1)
                .values({"test_date_old": prev, "test_date": now_dt})
            )


class GCSStorageProvider(StorageProvider):
    def __init__(self, bucket: str) -> None:
        self.name = "gcs"
        self.bucket = bucket
        self._client = gcs_storage.Client()
        self._bucket = self._client.bucket(bucket)

    def upload(self, data: bytes, key_hint: str) -> str:
        safe_hint = key_hint.replace("/", "_").replace("\\", "_")
        now = datetime.utcnow().strftime("%Y%m%dT%H%M%S")
        prefix = _recordings_prefix_for_hint(key_hint)
        key = f"{prefix}/{now}_{safe_hint}.mp4"
        blob = self._bucket.blob(key)
        blob.upload_from_string(data, content_type="video/mp4")
        return key

    def get_url(self, storage_key: str) -> Optional[str]:
        try:
            blob = self._bucket.blob(storage_key)
            url = blob.generate_signed_url(expiration=3600)
            return url
        except Exception:  # noqa: BLE001
            # Fallback to a public-style URL if the bucket/object is public.
            return f"https://storage.googleapis.com/{self.bucket}/{storage_key}"

    def delete(self, storage_key: str) -> None:
        try:
            blob = self._bucket.blob(storage_key)
            blob.delete()
        except Exception:  # noqa: BLE001
            return


class AzureBlobStorageProvider(StorageProvider):
    def __init__(self, connection_string: str, container: str) -> None:
        if BlobServiceClient is None or ContentSettings is None:
            raise ImportError(
                "azure-storage-blob package is not installed. "
                "Install it with: pip install azure-storage-blob"
            )
        self.name = "azure_blob"
        self.container = container
        self._service_client = BlobServiceClient.from_connection_string(
            connection_string
        )
        self._container_client = self._service_client.get_container_client(container)
        base_url = None
        try:
            parts = {
                part.split("=", 1)[0]: part.split("=", 1)[1]
                for part in connection_string.split(";")
                if "=" in part
            }
            endpoint = parts.get("BlobEndpoint", "").strip()
            if endpoint:
                base_url = endpoint.rstrip("/")
            if not base_url:
                account_name = parts.get("AccountName", "").strip()
                if account_name:
                    protocol = parts.get("DefaultEndpointsProtocol", "https").strip() or "https"
                    suffix = parts.get("EndpointSuffix", "core.windows.net").strip() or "core.windows.net"
                    base_url = f"{protocol}://{account_name}.blob.{suffix}"
        except Exception:  # noqa: BLE001
            base_url = None
        self._base_url = base_url

    def upload(self, data: bytes, key_hint: str) -> str:
        safe_hint = key_hint.replace("/", "_").replace("\\", "_")
        now = datetime.utcnow().strftime("%Y%m%dT%H%M%S")
        prefix = _recordings_prefix_for_hint(key_hint)
        blob_name = f"{prefix}/{now}_{safe_hint}.mp4"
        self._container_client.upload_blob(
            name=blob_name,
            data=data,
            overwrite=True,
            content_settings=ContentSettings(content_type="video/mp4"),
        )
        return blob_name

    def get_url(self, storage_key: str) -> Optional[str]:
        if not self._base_url:
            return None
        return f"{self._base_url}/{self.container}/{storage_key}"

    def delete(self, storage_key: str) -> None:
        try:
            self._container_client.delete_blob(storage_key)
        except Exception:  # noqa: BLE001
            return


class DropboxStorageProvider(StorageProvider):
    def __init__(self, access_token: str) -> None:
        self.name = "dropbox"
        self._dbx = dropbox.Dropbox(access_token)

    def upload(self, data: bytes, key_hint: str) -> str:
        safe_hint = key_hint.replace("/", "_").replace("\\", "_")
        now = datetime.utcnow().strftime("%Y%m%dT%H%M%S")
        prefix = _recordings_prefix_for_hint(key_hint)
        path = f"/{prefix}/{now}_{safe_hint}.mp4"
        self._dbx.files_upload(data, path, mute=True)
        return path

    def get_url(self, storage_key: str) -> Optional[str]:
        try:
            link = self._dbx.sharing_create_shared_link_with_settings(storage_key)
            url = link.url
        except Exception:  # noqa: BLE001
            return None
        if "dl=0" in url:
            url = url.replace("dl=0", "dl=1")
        elif "?dl=" not in url:
            sep = "&" if "?" in url else "?"
            url = f"{url}{sep}dl=1"
        return url

    def delete(self, storage_key: str) -> None:
        try:
            self._dbx.files_delete_v2(storage_key)
        except Exception:  # noqa: BLE001
            return


class WebDAVStorageProvider(StorageProvider):
    def __init__(
        self,
        base_url: str,
        username: Optional[str],
        password: Optional[str],
    ) -> None:
        self.name = "webdav"
        self.base_url = base_url.rstrip("/")
        self.username = username or None
        self.password = password or None

    def _auth(self):
        if self.username or self.password:
            return (self.username or "", self.password or "")
        return None

    def upload(self, data: bytes, key_hint: str) -> str:
        safe_hint = key_hint.replace("/", "_").replace("\\", "_")
        now = datetime.utcnow().strftime("%Y%m%dT%H%M%S")
        prefix = _recordings_prefix_for_hint(key_hint)
        key = f"{prefix}/{now}_{safe_hint}.mp4"
        url = f"{self.base_url}/{key}"
        response = requests.put(url, data=data, auth=self._auth())
        if response.status_code >= 400:
            raise RuntimeError(
                f"WebDAV upload failed with status {response.status_code}"
            )
        return key

    def get_url(self, storage_key: str) -> Optional[str]:
        return f"{self.base_url}/{storage_key}"

    def delete(self, storage_key: str) -> None:
        url = f"{self.base_url}/{storage_key}"
        try:
            requests.delete(url, auth=self._auth())
        except Exception:  # noqa: BLE001
            return


class FTPStorageProvider(StorageProvider):
    def __init__(
        self,
        host: str,
        port: int = 21,
        username: Optional[str] = None,
        password: Optional[str] = None,
        base_dir: str = "/",
        use_tls: bool = False,
        ignore_cert: Optional[bool] = None,
        passive: bool = True,
    ) -> None:
        self.name = "ftp"
        self.host = host
        self.port = int(port or 21)
        self.username = username or ""
        self.password = password or ""
        self.base_dir = (base_dir or "/").rstrip("/") or "/"
        self.use_tls = bool(use_tls)
        self.ignore_cert = ignore_cert
        self.passive = bool(passive)

    def _connect(self):
        if self.use_tls:
            if self.ignore_cert is True:
                ctx = ssl._create_unverified_context()
                ftp = ftplib.FTP_TLS(context=ctx)
            else:
                ftp = ftplib.FTP_TLS()
        else:
            ftp = ftplib.FTP()
        ftp.connect(self.host, self.port, timeout=20)
        ftp.login(self.username, self.password)
        try:
            ftp.set_pasv(self.passive)
        except Exception:  # noqa: BLE001
            pass
        if self.use_tls and isinstance(ftp, ftplib.FTP_TLS):
            try:
                ftp.prot_p()
            except Exception:  # noqa: BLE001
                pass
        return ftp

    def _ensure_dirs(self, ftp, path: str) -> None:
        # Best-effort recursive mkdir.
        parts = [p for p in path.split("/") if p]
        if not parts:
            return
        cur = ""
        for part in parts:
            cur = f"{cur}/{part}" if cur else f"/{part}"
            try:
                ftp.mkd(cur)
            except Exception:  # noqa: BLE001
                continue

    def upload(self, data: bytes, key_hint: str) -> str:
        safe_hint = key_hint.replace("/", "_").replace("\\", "_")
        now = datetime.utcnow().strftime("%Y%m%dT%H%M%S")
        prefix = _recordings_prefix_for_hint(key_hint)
        rel_key = f"{prefix}/{now}_{safe_hint}.mp4"
        remote_key = f"{self.base_dir}/{rel_key}" if self.base_dir != "/" else f"/{rel_key}"
        remote_dir = os.path.dirname(remote_key)
        ftp = self._connect()
        try:
            self._ensure_dirs(ftp, remote_dir)
            ftp.storbinary(f"STOR {remote_key}", io.BytesIO(data))
        finally:
            try:
                ftp.quit()
            except Exception:  # noqa: BLE001
                try:
                    ftp.close()
                except Exception:  # noqa: BLE001
                    pass
        return remote_key

    def delete(self, storage_key: str) -> None:
        ftp = self._connect()
        try:
            ftp.delete(storage_key)
        except Exception:  # noqa: BLE001
            return
        finally:
            try:
                ftp.quit()
            except Exception:  # noqa: BLE001
                try:
                    ftp.close()
                except Exception:  # noqa: BLE001
                    pass


class SFTPStorageProvider(StorageProvider):
    def __init__(
        self,
        host: str,
        port: int = 22,
        username: Optional[str] = None,
        password: Optional[str] = None,
        private_key: Optional[str] = None,
        base_dir: str = "/",
        ignore_cert: Optional[bool] = None,
    ) -> None:
        self.name = "sftp"
        self.host = host
        self.port = int(port or 22)
        self.username = (username or "").strip()
        self.password = password or None
        self.private_key = private_key or None
        self.base_dir = (base_dir or "/").rstrip("/") or "/"
        self.ignore_cert = ignore_cert

    def _connect(self):
        client = paramiko.SSHClient()
        if self.ignore_cert is False:
            try:
                client.load_system_host_keys()
            except Exception:  # noqa: BLE001
                pass
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
        else:
            # Backward compatible default: accept and cache host keys.
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        pkey = None
        if self.private_key:
            try:
                pkey = paramiko.RSAKey.from_private_key(io.StringIO(self.private_key))
            except Exception:  # noqa: BLE001
                pkey = None
        client.connect(
            hostname=self.host,
            port=self.port,
            username=self.username or None,
            password=self.password,
            pkey=pkey,
            timeout=20,
            banner_timeout=20,
            auth_timeout=20,
        )
        return client

    def _ensure_dirs(self, sftp, path: str) -> None:
        parts = [p for p in path.split("/") if p]
        cur = ""
        for part in parts:
            cur = f"{cur}/{part}" if cur else f"/{part}"
            try:
                sftp.stat(cur)
            except Exception:  # noqa: BLE001
                try:
                    sftp.mkdir(cur)
                except Exception:  # noqa: BLE001
                    continue

    def upload(self, data: bytes, key_hint: str) -> str:
        safe_hint = key_hint.replace("/", "_").replace("\\", "_")
        now = datetime.utcnow().strftime("%Y%m%dT%H%M%S")
        prefix = _recordings_prefix_for_hint(key_hint)
        rel_key = f"{prefix}/{now}_{safe_hint}.mp4"
        remote_key = f"{self.base_dir}/{rel_key}" if self.base_dir != "/" else f"/{rel_key}"
        remote_dir = os.path.dirname(remote_key)
        client = self._connect()
        try:
            sftp = client.open_sftp()
            try:
                self._ensure_dirs(sftp, remote_dir)
                with sftp.open(remote_key, "wb") as f:
                    f.write(data)
            finally:
                try:
                    sftp.close()
                except Exception:  # noqa: BLE001
                    pass
        finally:
            try:
                client.close()
            except Exception:  # noqa: BLE001
                pass
        return remote_key

    def delete(self, storage_key: str) -> None:
        client = self._connect()
        try:
            sftp = client.open_sftp()
            try:
                sftp.remove(storage_key)
            finally:
                try:
                    sftp.close()
                except Exception:  # noqa: BLE001
                    pass
        except Exception:  # noqa: BLE001
            return
        finally:
            try:
                client.close()
            except Exception:  # noqa: BLE001
                pass


class SCPStorageProvider(StorageProvider):
    def __init__(
        self,
        host: str,
        port: int = 22,
        username: Optional[str] = None,
        password: Optional[str] = None,
        private_key: Optional[str] = None,
        base_dir: str = "/",
        ignore_cert: Optional[bool] = None,
    ) -> None:
        self.name = "scp"
        self.host = host
        self.port = int(port or 22)
        self.username = (username or "").strip()
        self.password = password or None
        self.private_key = private_key or None
        self.base_dir = (base_dir or "/").rstrip("/") or "/"
        self.ignore_cert = ignore_cert

    def _connect(self):
        client = paramiko.SSHClient()
        if self.ignore_cert is False:
            try:
                client.load_system_host_keys()
            except Exception:  # noqa: BLE001
                pass
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
        else:
            # Backward compatible default: accept and cache host keys.
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        pkey = None
        if self.private_key:
            try:
                pkey = paramiko.RSAKey.from_private_key(io.StringIO(self.private_key))
            except Exception:  # noqa: BLE001
                pkey = None
        client.connect(
            hostname=self.host,
            port=self.port,
            username=self.username or None,
            password=self.password,
            pkey=pkey,
            timeout=20,
            banner_timeout=20,
            auth_timeout=20,
        )
        return client

    def upload(self, data: bytes, key_hint: str) -> str:
        safe_hint = key_hint.replace("/", "_").replace("\\", "_")
        now = datetime.utcnow().strftime("%Y%m%dT%H%M%S")
        filename = f"{now}_{safe_hint}.mp4"
        prefix = _recordings_prefix_for_hint(key_hint)
        rel_dir = prefix
        remote_dir = f"{self.base_dir}/{rel_dir}" if self.base_dir != "/" else f"/{rel_dir}"
        remote_path = f"{remote_dir}/{filename}"
        client = self._connect()
        tmp_path = None
        try:
            try:
                # Ensure remote directory exists.
                client.exec_command(f"mkdir -p '{remote_dir}'")
            except Exception:  # noqa: BLE001
                pass

            with tempfile.NamedTemporaryFile(suffix=".mp4", delete=False) as tmp:
                tmp.write(data)
                tmp_path = tmp.name
            with SCPClient(client.get_transport()) as scp:
                scp.put(tmp_path, remote_path)
        finally:
            if tmp_path:
                try:
                    os.remove(tmp_path)
                except Exception:  # noqa: BLE001
                    pass
            try:
                client.close()
            except Exception:  # noqa: BLE001
                pass
        return remote_path

    def delete(self, storage_key: str) -> None:
        client = self._connect()
        try:
            client.exec_command(f"rm -f '{storage_key}'")
        except Exception:  # noqa: BLE001
            return
        finally:
            try:
                client.close()
            except Exception:  # noqa: BLE001
                pass


class GoogleDriveStorageProvider(StorageProvider):
    def __init__(
        self,
        access_token: Optional[str] = None,
        folder_id: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        refresh_token: Optional[str] = None,
    ) -> None:
        # Logical provider type; the actual provider name used by workers is
        # overridden by the StorageModule name so multiple instances can
        # coexist.
        self.name = "gdrive"
        self._folder_id = folder_id or None
        self._client_id = (client_id or "").strip() or None
        self._client_secret = (client_secret or "").strip() or None
        self._refresh_token = (refresh_token or "").strip() or None
        self._access_token = (access_token or "").strip() or None
        self._access_token_expires_at = None

    def _get_access_token(self) -> str:
        if self._access_token and self._refresh_token is None:
            return self._access_token

        now_ts = time.time()
        if (
            self._access_token
            and self._access_token_expires_at is not None
            and (self._access_token_expires_at - 30) > now_ts
        ):
            return self._access_token

        if not (self._client_id and self._client_secret and self._refresh_token):
            if self._access_token:
                return self._access_token
            raise RuntimeError("Google Drive provider is missing OAuth credentials")

        token_url = "https://oauth2.googleapis.com/token"
        payload = {
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "refresh_token": self._refresh_token,
            "grant_type": "refresh_token",
        }
        resp = requests.post(token_url, data=payload, timeout=20)
        if resp.status_code >= 400:
            raise RuntimeError(
                f"Google OAuth token refresh failed with status {resp.status_code}: {resp.text[:512]}"
            )
        try:
            data = resp.json()
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError("Google OAuth token refresh returned invalid JSON") from exc

        token = str(data.get("access_token") or "").strip()
        if not token:
            raise RuntimeError("Google OAuth token refresh response missing access_token")
        expires_in = data.get("expires_in")
        try:
            expires_in_val = int(expires_in) if expires_in is not None else 3600
        except Exception:  # noqa: BLE001
            expires_in_val = 3600

        self._access_token = token
        self._access_token_expires_at = now_ts + max(60, expires_in_val)
        return token

    def upload(self, data: bytes, key_hint: str) -> str:
        """Upload a recording to Google Drive using the HTTP API.

        This implementation uses a pre-generated OAuth 2.0 access token
        provided by the administrator. For production use, the token should be
        managed by an external process (for example, a service account or a
        scheduled refresh flow).
        """

        safe_hint = key_hint.replace("/", "_").replace("\\", "_")
        now = datetime.utcnow().strftime("%Y%m%dT%H%M%S")
        filename = f"recording_{now}_{safe_hint}.mp4"

        metadata: dict[str, object] = {"name": filename}
        if self._folder_id:
            metadata["parents"] = [self._folder_id]

        boundary = "----pentavision-drive-boundary"
        meta_json = json.dumps(metadata).encode("utf-8")

        # Build a multipart/related body: JSON metadata + binary media.
        body_prefix = (
            f"--{boundary}\r\n"
            "Content-Type: application/json; charset=UTF-8\r\n\r\n"
        ).encode("utf-8") + meta_json + (
            f"\r\n--{boundary}\r\n"
            "Content-Type: video/mp4\r\n\r\n"
        ).encode("utf-8")
        body_suffix = f"\r\n--{boundary}--\r\n".encode("utf-8")
        body = body_prefix + data + body_suffix

        headers = {
            "Authorization": f"Bearer {self._get_access_token()}",
            "Content-Type": f"multipart/related; boundary={boundary}",
        }
        url = "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart"
        response = requests.post(url, headers=headers, data=body)
        if response.status_code >= 400:
            raise RuntimeError(
                f"Google Drive upload failed with status {response.status_code}: "
                f"{response.text[:512]}"
            )
        try:
            payload = response.json()
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError("Google Drive upload returned invalid JSON") from exc
        file_id = payload.get("id")
        if not file_id:
            raise RuntimeError("Google Drive upload response missing file id")
        return str(file_id)

    def get_url(self, storage_key: str) -> Optional[str]:
        # Return a direct download URL for the file when possible.
        return f"https://drive.google.com/uc?id={storage_key}&export=download"

    def delete(self, storage_key: str) -> None:
        try:
            headers = {"Authorization": f"Bearer {self._get_access_token()}"}
            url = f"https://www.googleapis.com/drive/v3/files/{storage_key}"
            response = requests.delete(url, headers=headers)
            if response.status_code >= 400:
                # Best-effort cleanup; failures are logged by callers when
                # needed but should not crash the worker.
                return
        except Exception:  # noqa: BLE001
            return


class OneDriveStorageProvider(StorageProvider):
    def __init__(self, access_token: str, root_path: Optional[str] = None) -> None:
        self.name = "onedrive"
        self._access_token = access_token
        self._root_path = (root_path or "").strip("/")
        self._base_url = "https://graph.microsoft.com/v1.0"

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self._access_token}",
            "Content-Type": "application/octet-stream",
        }

    def upload(self, data: bytes, key_hint: str) -> str:
        safe_hint = key_hint.replace("/", "_").replace("\\", "_")
        now = datetime.utcnow().strftime("%Y%m%dT%H%M%S")
        filename = f"recording_{now}_{safe_hint}.mp4"
        if self._root_path:
            rel_path = f"{self._root_path}/{filename}"
        else:
            rel_path = filename
        url = f"{self._base_url}/me/drive/root:/{rel_path}:/content"
        response = requests.put(url, headers=self._headers(), data=data)
        if response.status_code >= 400:
            raise RuntimeError(
                f"OneDrive upload failed with status {response.status_code}: "
                f"{response.text[:512]}"
            )
        try:
            payload = response.json()
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError("OneDrive upload returned invalid JSON") from exc
        file_id = payload.get("id")
        if not file_id:
            raise RuntimeError("OneDrive upload response missing file id")
        return str(file_id)

    def delete(self, storage_key: str) -> None:
        try:
            url = f"{self._base_url}/me/drive/items/{storage_key}"
            response = requests.delete(url, headers={
                "Authorization": f"Bearer {self._access_token}",
            })
            if response.status_code >= 400:
                return
        except Exception:  # noqa: BLE001
            return


class BoxStorageProvider(StorageProvider):
    def __init__(self, access_token: str, folder_id: Optional[str] = None) -> None:
        self.name = "box"
        self._access_token = access_token
        self._folder_id = (folder_id or "0").strip() or "0"
        self._upload_url = "https://upload.box.com/api/2.0/files/content"
        self._api_base = "https://api.box.com/2.0"

    def _headers(self) -> Dict[str, str]:
        return {"Authorization": f"Bearer {self._access_token}"}

    def upload(self, data: bytes, key_hint: str) -> str:
        safe_hint = key_hint.replace("/", "_").replace("\\", "_")
        now = datetime.utcnow().strftime("%Y%m%dT%H%M%S")
        filename = f"recording_{now}_{safe_hint}.mp4"
        attributes = {
            "name": filename,
            "parent": {"id": self._folder_id},
        }
        files = {
            "attributes": (None, json.dumps(attributes), "application/json"),
            "file": (filename, data, "video/mp4"),
        }
        response = requests.post(self._upload_url, headers=self._headers(), files=files)
        if response.status_code >= 400:
            raise RuntimeError(
                f"Box upload failed with status {response.status_code}: "
                f"{response.text[:512]}"
            )
        try:
            payload = response.json()
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError("Box upload returned invalid JSON") from exc
        entries = payload.get("entries") or []
        if not entries:
            raise RuntimeError("Box upload response missing entries")
        file_id = entries[0].get("id")
        if not file_id:
            raise RuntimeError("Box upload response missing file id")
        return str(file_id)

    def delete(self, storage_key: str) -> None:
        try:
            url = f"{self._api_base}/files/{storage_key}"
            response = requests.delete(url, headers=self._headers())
            if response.status_code >= 400:
                return
        except Exception:  # noqa: BLE001
            return


class SwiftStorageProvider(StorageProvider):
    def __init__(
        self,
        storage_url: str,
        auth_token: str,
        container: str,
    ) -> None:
        self.name = "swift"
        self._storage_url = storage_url.rstrip("/")
        self._auth_token = auth_token
        self._container = container.strip("/")

    def _headers(self) -> Dict[str, str]:
        return {"X-Auth-Token": self._auth_token, "Content-Type": "application/octet-stream"}

    def upload(self, data: bytes, key_hint: str) -> str:
        safe_hint = key_hint.replace("/", "_").replace("\\", "_")
        now = datetime.utcnow().strftime("%Y%m%dT%H%M%S")
        prefix = _recordings_prefix_for_hint(key_hint)
        key = f"{prefix}/{now}_{safe_hint}.mp4"
        url = f"{self._storage_url}/{self._container}/{key}"
        response = requests.put(url, headers=self._headers(), data=data)
        if response.status_code >= 400:
            raise RuntimeError(
                f"Swift upload failed with status {response.status_code}: {response.text[:200]}"
            )
        return key

    def delete(self, storage_key: str) -> None:
        url = f"{self._storage_url}/{self._container}/{storage_key}"
        try:
            response = requests.delete(url, headers={"X-Auth-Token": self._auth_token})
            if response.status_code >= 400:
                return
        except Exception:  # noqa: BLE001
            return


class PCloudStorageProvider(StorageProvider):
    def __init__(self, access_token: str, path: Optional[str] = None) -> None:
        self.name = "pcloud"
        self._access_token = access_token
        self._path = path or "/"
        self._api_base = "https://api.pcloud.com"

    def upload(self, data: bytes, key_hint: str) -> str:
        safe_hint = key_hint.replace("/", "_").replace("\\", "_")
        now = datetime.utcnow().strftime("%Y%m%dT%H%M%S")
        filename = f"recording_{now}_{safe_hint}.mp4"
        url = f"{self._api_base}/uploadfile"
        params = {
            "access_token": self._access_token,
            "path": self._path,
        }
        files = {"file": (filename, data, "video/mp4")}
        response = requests.post(url, params=params, files=files)
        if response.status_code >= 400:
            raise RuntimeError(
                f"pCloud upload failed with status {response.status_code}: "
                f"{response.text[:512]}"
            )
        try:
            payload = response.json()
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError("pCloud upload returned invalid JSON") from exc
        if int(payload.get("result", 0)) != 0:
            raise RuntimeError(f"pCloud upload error: {payload}")
        metadata = payload.get("metadata")
        file_id = None
        if isinstance(metadata, list) and metadata:
            file_id = metadata[0].get("fileid") or metadata[0].get("id")
        elif isinstance(metadata, dict):
            file_id = metadata.get("fileid") or metadata.get("id")
        if not file_id:
            raise RuntimeError("pCloud upload response missing file id")
        return str(file_id)

    def delete(self, storage_key: str) -> None:
        url = f"{self._api_base}/deletefile"
        params = {
            "access_token": self._access_token,
            "fileid": storage_key,
        }
        try:
            response = requests.get(url, params=params)
            if response.status_code >= 400:
                return
        except Exception:  # noqa: BLE001
            return


class MegaStorageProvider(StorageProvider):
    def __init__(
        self,
        email: str,
        password: str,
        folder_name: Optional[str] = None,
    ) -> None:
        self.name = "mega"
        self._email = email
        self._password = password
        self._folder_name = folder_name or None
        self._client = None

    def _ensure_client(self):
        if self._client is not None:
            return
        try:
            from mega import Mega  # type: ignore[import]
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(
                "Mega storage provider requires the optional mega.py package"
            ) from exc
        mega = Mega()
        self._client = mega.login(self._email, self._password)

    def upload(self, data: bytes, key_hint: str) -> str:
        self._ensure_client()
        safe_hint = key_hint.replace("/", "_").replace("\\", "_")
        now = datetime.utcnow().strftime("%Y%m%dT%H%M%S")
        filename = f"recording_{now}_{safe_hint}.mp4"
        with tempfile.NamedTemporaryFile(suffix=".mp4", delete=False) as tmp:
            tmp.write(data)
            tmp_path = tmp.name
        try:
            if self._folder_name:
                folder = self._client.find(self._folder_name)
                file_node = self._client.upload(
                    tmp_path,
                    dest=folder,
                    dest_filename=filename,
                )
            else:
                file_node = self._client.upload(
                    tmp_path,
                    dest_filename=filename,
                )
        finally:
            try:
                os.remove(tmp_path)
            except Exception:  # noqa: BLE001
                pass

        file_id = None
        if isinstance(file_node, dict):
            file_id = file_node.get("h") or file_node.get("id")
        if not file_id:
            file_id = str(file_node)
        return str(file_id)

    def delete(self, storage_key: str) -> None:
        self._ensure_client()
        try:
            node = self._client.find(storage_key)
            if node is None:
                return
            self._client.destroy(node)
        except Exception:  # noqa: BLE001
            return


class _LegacyProviderAdapter(StorageModuleBase):
    """Adapter that wraps an existing StorageProvider in the CSAL interface.

    This allows the new Core Storage Abstraction Layer to route requests
    through logical StorageModule instances while reusing the existing
    StorageProvider implementations. Over time, providers can be migrated to
    native CSAL modules without changing callers.
    """

    def __init__(self, provider: StorageProvider) -> None:
        self._provider = provider

    def initialize(self, config: Dict[str, Any]) -> None:  # pragma: no cover
        # Legacy providers do all initialization in __init__.
        return

    def authenticate(self, credentials: Dict[str, Any]) -> None:  # pragma: no cover
        # Legacy providers typically rely on static credentials passed at
        # construction time or via environment variables.
        return

    def validate(self) -> None:  # pragma: no cover
        # Provider-specific cheap validation hooks.
        try:
            if isinstance(self._provider, S3StorageProvider):
                # Force an actual signed request to verify endpoint, bucket,
                # and credentials. This is cheaper than a write/delete and
                # produces clearer auth errors.
                try:
                    self._provider._client.head_bucket(Bucket=self._provider.bucket)
                    self._provider._client.list_objects_v2(
                        Bucket=self._provider.bucket,
                        MaxKeys=1,
                    )
                except NoCredentialsError as exc:
                    raise StorageAuthError("Missing S3 credentials") from exc
                except EndpointConnectionError as exc:
                    raise StorageTransientError(
                        f"Failed to connect to S3 endpoint: {exc}"
                    ) from exc
                except ClientError as exc:
                    code = None
                    try:
                        code = (
                            exc.response.get("Error", {}).get("Code")
                            if hasattr(exc, "response")
                            else None
                        )
                    except Exception:  # noqa: BLE001
                        code = None

                    msg = str(exc)
                    if code in {
                        "InvalidAccessKeyId",
                        "SignatureDoesNotMatch",
                        "AccessDenied",
                        "AllAccessDisabled",
                        "InvalidToken",
                        "ExpiredToken",
                    }:
                        raise StorageAuthError(msg) from exc
                    raise StorageTransientError(msg) from exc
        except StorageError:
            raise
        except Exception:
            # If our validation probe fails unexpectedly, fall back to the
            # write/delete smoke test.
            pass

        # Basic smoke test: attempt to write and then delete a tiny object
        # when the underlying provider supports deletion.
        stream = io.BytesIO(b"csal-test")
        result = self.write(stream, {"key_hint": "csal_test"})
        object_id = str(result.get("object_id") or "")
        if not object_id:
            return
        try:
            self.delete(object_id)
        except StorageError:
            # Validation failures are surfaced to callers; other errors are
            # treated as non-fatal for now.
            raise
        except Exception:
            return

    def write(
        self,
        stream: BinaryIO,
        metadata: Dict[str, Any],
    ) -> Dict[str, Any]:  # pragma: no cover
        try:
            data = stream.read()
        except Exception as exc:  # noqa: BLE001
            raise StorageTransientError(f"failed to read stream: {exc}") from exc

        key_hint = str(metadata.get("key_hint") or "segment")
        try:
            object_id = self._provider.upload(data, key_hint)
        except Exception as exc:  # noqa: BLE001
            raise StorageTransientError(str(exc)) from exc

        return {
            "object_id": object_id,
            "provider_name": self._provider.name,
        }

    def read(
        self,
        object_id: str,
        byte_range: Optional[tuple[int, int]] = None,
    ) -> BinaryIO:  # pragma: no cover
        raise StoragePermanentError(
            "read is not implemented for legacy storage providers",
        )

    def delete(self, object_id: str) -> None:  # pragma: no cover
        try:
            self._provider.delete(object_id)
        except NotImplementedError:
            raise StoragePermanentError(
                "delete is not supported for this provider",
            ) from None
        except Exception as exc:  # noqa: BLE001
            raise StorageTransientError(str(exc)) from exc

    def list(
        self,
        path: str,
        filters: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:  # pragma: no cover
        raise StoragePermanentError(
            "list is not implemented for legacy storage providers",
        )

    def stat(self, object_id: str) -> Dict[str, Any]:  # pragma: no cover
        raise StoragePermanentError(
            "stat is not implemented for legacy storage providers",
        )

    def health_check(self) -> Dict[str, Any]:  # pragma: no cover
        import time

        started = time.monotonic()
        try:
            self.validate()
        except Exception as exc:
            elapsed_ms = int((time.monotonic() - started) * 1000)
            return {
                "status": "error",
                "message": f"Validation failed: {str(exc)[:200]}",
                "latency_ms": elapsed_ms,
            }

        try:
            if isinstance(self._provider, DatabaseStorageProvider):
                from .db import get_record_engine
                from flask import current_app

                engine = get_record_engine(current_app)
                if engine is None:
                    elapsed_ms = int((time.monotonic() - started) * 1000)
                    return {
                        "status": "error",
                        "message": "RecordDB engine not available",
                        "latency_ms": elapsed_ms,
                    }
                with engine.connect() as conn:
                    conn.execute("SELECT 1")
            elif isinstance(self._provider, ExternalSQLDatabaseStorageProvider):
                with self._provider.engine.connect() as conn:
                    conn.execute("SELECT 1")
            elif isinstance(self._provider, S3StorageProvider):
                self._provider.client.list_objects_v2(
                    Bucket=self._provider.bucket,
                    MaxKeys=1,
                )
            elif isinstance(self._provider, LocalFilesystemStorageProvider):
                if not self._provider.base_path.exists():
                    elapsed_ms = int((time.monotonic() - started) * 1000)
                    return {
                        "status": "error",
                        "message": (
                            f"Path does not exist: "
                            f"{self._provider.base_path}"
                        ),
                        "latency_ms": elapsed_ms,
                    }
        except Exception as exc:
            elapsed_ms = int((time.monotonic() - started) * 1000)
            return {
                "status": "error",
                "message": f"Health check failed: {str(exc)[:200]}",
                "latency_ms": elapsed_ms,
            }

        elapsed_ms = int((time.monotonic() - started) * 1000)
        return {
            "status": "ok",
            "message": f"Working / {elapsed_ms}ms",
            "latency_ms": elapsed_ms,
        }

    def shutdown(self) -> None:  # pragma: no cover
        return


def _build_provider_for_module(
    app: Flask,
    module: StorageModule,
    cfg: Optional[Dict[str, Any]] = None,
) -> Optional[StorageProvider]:
    """Construct a legacy StorageProvider for a StorageModule row.

    This is used both by the legacy build_storage_providers helper and by the
    CSAL adapter factory so that provider construction logic is centralized.
    """

    raw_config = getattr(module, "config_json", None) or ""
    if cfg is None:
        try:
            cfg = json.loads(raw_config) if raw_config else {}
        except Exception:  # noqa: BLE001
            cfg = {}

    ptype = (module.provider_type or "").strip().lower()
    provider: Optional[StorageProvider] = None

    if ptype in {"local_fs", "local_drive"}:
        base_dir = (
            str(cfg.get("base_dir") or "").strip()
            or app.config.get("LOCAL_STORAGE_PATH")
            or app.config.get("RECORDING_BASE_DIR")
            or os.path.join(app.instance_path, "recordings")
        )
        provider = LocalFilesystemStorageProvider(str(base_dir))
    elif ptype == "db":
        provider = DatabaseStorageProvider()
    elif ptype == "sql_db":
        db_type = str(cfg.get("db_type") or "").strip().lower()
        host = str(cfg.get("host") or "").strip()
        database = str(cfg.get("database") or "").strip()
        username = str(cfg.get("username") or "").strip() or None
        password = str(cfg.get("password") or "").strip() or None
        mssql_driver = str(cfg.get("mssql_driver") or "").strip() or None
        port = None
        try:
            if cfg.get("port") is not None and str(cfg.get("port") or "").strip() != "":
                port = int(cfg.get("port"))
        except Exception:  # noqa: BLE001
            port = None
        if db_type and host and database:
            provider = ExternalSQLDatabaseStorageProvider(
                db_type=db_type,
                host=host,
                port=port,
                database=database,
                username=username,
                password=password,
                mssql_driver=mssql_driver,
            )
    elif ptype == "s3":
        bucket = str(cfg.get("bucket") or "").strip()
        access_key = str(cfg.get("access_key") or "").strip()
        secret_key = str(cfg.get("secret_key") or "").strip()
        if bucket and access_key and secret_key:
            endpoint = str(cfg.get("endpoint") or "").strip() or None
            region = str(cfg.get("region") or "").strip() or None
            provider = S3StorageProvider(
                endpoint,
                region,
                bucket,
                access_key,
                secret_key,
            )
    elif ptype == "gcs":
        bucket = str(cfg.get("bucket") or "").strip()
        if bucket:
            provider = GCSStorageProvider(bucket)
    elif ptype == "azure_blob":
        conn = str(cfg.get("connection_string") or "").strip()
        container = str(cfg.get("container") or "").strip()
        if not conn:
            account_name = str(cfg.get("account_name") or "").strip()
            account_key = str(cfg.get("account_key") or "").strip()
            if account_name and account_key:
                conn = (
                    "DefaultEndpointsProtocol=https;"
                    f"AccountName={account_name};"
                    f"AccountKey={account_key};"
                    "EndpointSuffix=core.windows.net"
                )
        if conn and container:
            provider = AzureBlobStorageProvider(conn, container)
    elif ptype == "dropbox":
        token = str(cfg.get("access_token") or "").strip()
        if token:
            provider = DropboxStorageProvider(token)
    elif ptype == "webdav":
        base_url = str(cfg.get("base_url") or "").strip()
        username = str(cfg.get("username") or "").strip() or None
        password = str(cfg.get("password") or "").strip() or None
        if base_url:
            provider = WebDAVStorageProvider(base_url, username, password)
    elif ptype == "ftp":
        host = str(cfg.get("host") or "").strip()
        port = int(cfg.get("port") or 21)
        username = str(cfg.get("username") or "").strip() or None
        password = str(cfg.get("password") or "").strip() or None
        base_dir = str(cfg.get("base_dir") or "/").strip() or "/"
        use_tls = bool(cfg.get("use_tls") or False)
        ignore_cert = None
        if "ignore_cert" in cfg:
            ignore_cert = bool(cfg.get("ignore_cert"))
        passive = bool(cfg.get("passive") if "passive" in cfg else True)
        if host:
            provider = FTPStorageProvider(host, port, username, password, base_dir, use_tls, ignore_cert, passive)
    elif ptype == "sftp":
        host = str(cfg.get("host") or "").strip()
        port = int(cfg.get("port") or 22)
        username = str(cfg.get("username") or "").strip() or None
        password = str(cfg.get("password") or "").strip() or None
        private_key = str(cfg.get("private_key") or "").strip() or None
        base_dir = str(cfg.get("base_dir") or "/").strip() or "/"
        if host:
            ignore_cert = None
            if "ignore_cert" in cfg:
                ignore_cert = bool(cfg.get("ignore_cert"))
            provider = SFTPStorageProvider(host, port, username, password, private_key, base_dir, ignore_cert)
    elif ptype == "scp":
        host = str(cfg.get("host") or "").strip()
        port = int(cfg.get("port") or 22)
        username = str(cfg.get("username") or "").strip() or None
        password = str(cfg.get("password") or "").strip() or None
        private_key = str(cfg.get("private_key") or "").strip() or None
        base_dir = str(cfg.get("base_dir") or "/").strip() or "/"
        if host:
            ignore_cert = None
            if "ignore_cert" in cfg:
                ignore_cert = bool(cfg.get("ignore_cert"))
            provider = SCPStorageProvider(host, port, username, password, private_key, base_dir, ignore_cert)
    elif ptype == "onedrive":
        access_token = str(cfg.get("access_token") or "").strip()
        root_path = str(cfg.get("root_path") or "").strip() or None
        if access_token:
            provider = OneDriveStorageProvider(access_token, root_path)
    elif ptype == "box":
        access_token = str(cfg.get("access_token") or "").strip()
        folder_id = str(cfg.get("folder_id") or "").strip() or None
        if access_token:
            provider = BoxStorageProvider(access_token, folder_id)
    elif ptype == "swift":
        storage_url = str(cfg.get("storage_url") or "").strip()
        auth_token = str(cfg.get("auth_token") or "").strip()
        container = str(cfg.get("container") or "").strip()
        if storage_url and auth_token and container:
            provider = SwiftStorageProvider(storage_url, auth_token, container)
    elif ptype == "pcloud":
        access_token = str(cfg.get("access_token") or "").strip()
        path = str(cfg.get("path") or "").strip() or "/"
        if access_token:
            provider = PCloudStorageProvider(access_token, path)
    elif ptype == "mega":
        email = str(cfg.get("email") or "").strip()
        password = str(cfg.get("password") or "").strip()
        folder_name = str(cfg.get("folder_name") or "").strip() or None
        if email and password:
            provider = MegaStorageProvider(email, password, folder_name)

    return provider


def _load_storage_modules() -> list[StorageModule]:
    """Load named storage modules from the recordings database, if present.

    When one or more modules are defined, they take precedence over the legacy
    StorageSettings/"storage_targets" configuration so that deployments can
    cleanly migrate to per-module settings and multiple instances of the same
    provider type.
    """

    engine = get_record_engine()
    if engine is None:
        return []
    StorageModule.__table__.create(bind=engine, checkfirst=True)
    with Session(engine) as session:
        rows = (
            session.query(StorageModule)
            .order_by(getattr(StorageModule, "priority", StorageModule.id), StorageModule.id)
            .all()
        )
    return list(rows)


def _load_storage_settings() -> dict | None:
    """Load global storage settings from the recordings database, if present.

    Returns a plain dict so callers do not depend on an active SQLAlchemy
    session. If the table or row does not exist, returns None.
    """

    engine = get_record_engine()
    if engine is None:
        return None
    # Ensure the table exists before querying.
    StorageSettings.__table__.create(bind=engine, checkfirst=True)
    with Session(engine) as session:
        row = (
            session.query(StorageSettings)
            .order_by(StorageSettings.id)
            .first()
        )
        if row is None:
            return None
        return {
            "storage_targets": row.storage_targets or "",
            "local_storage_path": row.local_storage_path or "",
            "recording_base_dir": row.recording_base_dir or "",
            "s3_bucket": row.s3_bucket or "",
            "s3_endpoint": row.s3_endpoint or "",
            "s3_region": row.s3_region or "",
            "s3_access_key": row.s3_access_key or "",
            "s3_secret_key": row.s3_secret_key or "",
            "gcs_bucket": row.gcs_bucket or "",
            "azure_blob_connection_string": row.azure_blob_connection_string or "",
            "azure_blob_container": row.azure_blob_container or "",
            "dropbox_access_token": row.dropbox_access_token or "",
            "webdav_base_url": row.webdav_base_url or "",
            "webdav_username": row.webdav_username or "",
            "webdav_password": row.webdav_password or "",
        }


def build_storage_providers(app: Flask) -> List[StorageProvider]:
    """Build active storage providers for the recording system.

    Priority is given to the new StorageModule-based configuration which
    supports multiple named instances per provider type. When no modules are
    defined, the legacy StorageSettings/"storage_targets" configuration is
    used as a fallback for backwards compatibility.
    """

    modules = _load_storage_modules()
    providers: List[StorageProvider] = []

    if modules:
        any_enabled = False
        for module in modules:
            if not getattr(module, "is_enabled", 0):
                continue
            any_enabled = True
            provider = _build_provider_for_module(app, module)
            if provider is None:
                continue

            # Use the StorageModule's name as the provider key seen by
            # RecordingManager and policies so multiple instances of the same
            # provider type can coexist.
            provider.name = module.name
            try:
                provider.module_id = int(module.id)
            except Exception:  # noqa: BLE001
                provider.module_id = None
            try:
                provider.priority = int(getattr(module, "priority", 100) or 100)
            except Exception:  # noqa: BLE001
                provider.priority = 100
            providers.append(provider)

        if any_enabled:
            return providers

    # Fallback: legacy StorageSettings-based single-instance configuration.
    db_settings = _load_storage_settings() or {}

    raw_targets = db_settings.get("storage_targets") or str(
        app.config.get("STORAGE_TARGETS", "local_fs") or "local_fs"
    )
    targets = [item.strip() for item in raw_targets.split(",") if item.strip()]

    if "local_fs" in targets:
        base_dir = (
            db_settings.get("local_storage_path")
            or db_settings.get("recording_base_dir")
            or app.config.get("LOCAL_STORAGE_PATH")
            or app.config.get("RECORDING_BASE_DIR")
            or os.path.join(app.instance_path, "recordings")
        )
        providers.append(LocalFilesystemStorageProvider(str(base_dir)))
    if "db" in targets:
        providers.append(DatabaseStorageProvider())
    if "s3" in targets:
        bucket = str(
            db_settings.get("s3_bucket") or app.config.get("S3_BUCKET") or ""
        ).strip()
        access_key = str(
            db_settings.get("s3_access_key")
            or app.config.get("S3_ACCESS_KEY")
            or ""
        ).strip()
        secret_key = str(
            db_settings.get("s3_secret_key")
            or app.config.get("S3_SECRET_KEY")
            or ""
        ).strip()
        if bucket and access_key and secret_key:
            endpoint = (
                str(
                    db_settings.get("s3_endpoint")
                    or app.config.get("S3_ENDPOINT")
                    or ""
                ).strip()
                or None
            )
            region = (
                str(
                    db_settings.get("s3_region")
                    or app.config.get("S3_REGION")
                    or ""
                ).strip()
                or None
            )
            providers.append(
                S3StorageProvider(endpoint, region, bucket, access_key, secret_key)
            )
    if "gcs" in targets:
        bucket = str(
            db_settings.get("gcs_bucket") or app.config.get("GCS_BUCKET") or ""
        ).strip()
        if bucket:
            providers.append(GCSStorageProvider(bucket))
    if "azure_blob" in targets:
        conn = str(
            db_settings.get("azure_blob_connection_string")
            or app.config.get("AZURE_BLOB_CONNECTION_STRING")
            or ""
        ).strip()
        container = str(
            db_settings.get("azure_blob_container")
            or app.config.get("AZURE_BLOB_CONTAINER")
            or ""
        ).strip()
        if conn and container:
            providers.append(AzureBlobStorageProvider(conn, container))
    if "dropbox" in targets:
        token = str(
            db_settings.get("dropbox_access_token")
            or app.config.get("DROPBOX_ACCESS_TOKEN")
            or ""
        ).strip()
        if token:
            providers.append(DropboxStorageProvider(token))
    if "webdav" in targets:
        base_url = str(
            db_settings.get("webdav_base_url")
            or app.config.get("WEBDAV_BASE_URL")
            or ""
        ).strip()
        username = (
            str(
                db_settings.get("webdav_username")
                or app.config.get("WEBDAV_USERNAME")
                or ""
            ).strip()
            or None
        )
        password = (
            str(
                db_settings.get("webdav_password")
                or app.config.get("WEBDAV_PASSWORD")
                or ""
            ).strip()
            or None
        )
        if base_url:
            providers.append(WebDAVStorageProvider(base_url, username, password))

    return providers


def _csal_factory_from_storage_module(
    app: Flask,
    module_row: StorageModule,
    config: Dict[str, Any],
) -> StorageModuleBase:
    """CSAL factory for existing StorageModule rows.

    This factory delegates provider construction to the legacy helpers and then
    wraps the result in a CSAL adapter so that the new StorageRouter can route
    writes and health checks through the same implementations used by the
    recording service today.
    """

    provider = _build_provider_for_module(app, module_row, config)
    if provider is None:
        raise StoragePermanentError(
            f"failed to build storage provider for module {module_row.name}",
        )
    provider.name = module_row.name
    return _LegacyProviderAdapter(provider)


for _ptype in (
    "local_fs",
    "local_drive",
    "db",
    "sql_db",
    "s3",
    "gcs",
    "azure_blob",
    "dropbox",
    "webdav",
    "ftp",
    "sftp",
    "scp",
    "onedrive",
    "box",
    "swift",
    "pcloud",
    "mega",
):
    StorageRouter.register_factory(_ptype, _csal_factory_from_storage_module)

