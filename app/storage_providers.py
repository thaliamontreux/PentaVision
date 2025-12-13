from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import List, Optional

import boto3
from flask import Flask
from sqlalchemy.orm import Session
from google.cloud import storage as gcs_storage
from azure.storage.blob import BlobServiceClient
import dropbox
import requests

from .db import get_record_engine
from .models import RecordingData, StorageModule, StorageSettings


class StorageProvider:
    name: str

    def upload(self, data: bytes, key_hint: str) -> str:
        raise NotImplementedError

    def get_url(self, storage_key: str) -> Optional[str]:
        return None

    def delete(self, storage_key: str) -> None:
        raise NotImplementedError


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
        key = f"recordings/{now}_{safe_hint}.mp4"
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
        path = self.base_path / filename
        counter = 1
        while path.exists():
            filename = f"{now}_{safe_hint}_{counter}.mp4"
            path = self.base_path / filename
            counter += 1
        with open(path, "wb") as handle:
            handle.write(data)
        return str(path)

    def get_url(self, storage_key: str) -> Optional[str]:
        return None


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


class GCSStorageProvider(StorageProvider):
    def __init__(self, bucket: str) -> None:
        self.name = "gcs"
        self.bucket = bucket
        self._client = gcs_storage.Client()
        self._bucket = self._client.bucket(bucket)

    def upload(self, data: bytes, key_hint: str) -> str:
        safe_hint = key_hint.replace("/", "_").replace("\\", "_")
        now = datetime.utcnow().strftime("%Y%m%dT%H%M%S")
        key = f"recordings/{now}_{safe_hint}.mp4"
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
        except Exception:  # noqa: BLE001
            base_url = None
        self._base_url = base_url

    def upload(self, data: bytes, key_hint: str) -> str:
        safe_hint = key_hint.replace("/", "_").replace("\\", "_")
        now = datetime.utcnow().strftime("%Y%m%dT%H%M%S")
        blob_name = f"recordings/{now}_{safe_hint}.mp4"
        self._container_client.upload_blob(
            name=blob_name,
            data=data,
            overwrite=True,
            content_type="video/mp4",
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
        path = f"/recordings/{now}_{safe_hint}.mp4"
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
        key = f"recordings/{now}_{safe_hint}.mp4"
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


class GoogleDriveStorageProvider(StorageProvider):
    def __init__(self, access_token: str, folder_id: Optional[str] = None) -> None:
        # Logical provider type; the actual provider name used by workers is
        # overridden by the StorageModule name so multiple instances can
        # coexist.
        self.name = "gdrive"
        self.access_token = access_token
        self.folder_id = folder_id or None

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
        if self.folder_id:
            metadata["parents"] = [self.folder_id]

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
            "Authorization": f"Bearer {self.access_token}",
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
            headers = {"Authorization": f"Bearer {self.access_token}"}
            url = f"https://www.googleapis.com/drive/v3/files/{storage_key}"
            response = requests.delete(url, headers=headers)
            if response.status_code >= 400:
                # Best-effort cleanup; failures are logged by callers when
                # needed but should not crash the worker.
                return
        except Exception:  # noqa: BLE001
            return


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
            .order_by(StorageModule.id)
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
        for module in modules:
            if not getattr(module, "is_enabled", 0):
                continue
            raw_config = getattr(module, "config_json", None) or ""
            try:
                cfg = json.loads(raw_config) if raw_config else {}
            except Exception:  # noqa: BLE001
                cfg = {}

            provider: Optional[StorageProvider] = None
            ptype = (module.provider_type or "").strip().lower()

            if ptype == "local_fs":
                base_dir = (
                    str(cfg.get("base_dir") or "").strip()
                    or app.config.get("LOCAL_STORAGE_PATH")
                    or app.config.get("RECORDING_BASE_DIR")
                    or os.path.join(app.instance_path, "recordings")
                )
                provider = LocalFilesystemStorageProvider(str(base_dir))
            elif ptype == "db":
                provider = DatabaseStorageProvider()
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
                if conn and container:
                    provider = AzureBlobStorageProvider(conn, container)
            elif ptype == "dropbox":
                token = str(cfg.get("access_token") or "").strip()
                if token:
                    provider = DropboxStorageProvider(token)
            elif ptype == "webdav":
                base_url = str(cfg.get("base_url") or "").strip()
                username = (
                    str(cfg.get("username") or "").strip() or None
                )
                password = (
                    str(cfg.get("password") or "").strip() or None
                )
                if base_url:
                    provider = WebDAVStorageProvider(base_url, username, password)
            elif ptype == "gdrive":
                access_token = str(cfg.get("access_token") or "").strip()
                folder_id = str(cfg.get("folder_id") or "").strip() or None
                if access_token:
                    provider = GoogleDriveStorageProvider(access_token, folder_id)

            if provider is None:
                continue

            # Use the StorageModule's name as the provider key seen by
            # RecordingManager and policies so multiple instances of the same
            # provider type can coexist.
            provider.name = module.name
            providers.append(provider)

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
