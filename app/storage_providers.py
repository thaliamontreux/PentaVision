from __future__ import annotations

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
from .models import RecordingData


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


def build_storage_providers(app: Flask) -> List[StorageProvider]:
    raw = str(app.config.get("STORAGE_TARGETS", "local_fs") or "local_fs")
    targets = [item.strip() for item in raw.split(",") if item.strip()]
    providers: List[StorageProvider] = []
    if "local_fs" in targets:
        base_dir = (
            app.config.get("LOCAL_STORAGE_PATH")
            or app.config.get("RECORDING_BASE_DIR")
            or os.path.join(app.instance_path, "recordings")
        )
        providers.append(LocalFilesystemStorageProvider(str(base_dir)))
    if "db" in targets:
        providers.append(DatabaseStorageProvider())
    if "s3" in targets:
        bucket = str(app.config.get("S3_BUCKET") or "").strip()
        access_key = str(app.config.get("S3_ACCESS_KEY") or "").strip()
        secret_key = str(app.config.get("S3_SECRET_KEY") or "").strip()
        if bucket and access_key and secret_key:
            endpoint = str(app.config.get("S3_ENDPOINT") or "").strip() or None
            region = str(app.config.get("S3_REGION") or "").strip() or None
            providers.append(
                S3StorageProvider(endpoint, region, bucket, access_key, secret_key)
            )
    if "gcs" in targets:
        bucket = str(app.config.get("GCS_BUCKET") or "").strip()
        if bucket:
            providers.append(GCSStorageProvider(bucket))
    if "azure_blob" in targets:
        conn = str(app.config.get("AZURE_BLOB_CONNECTION_STRING") or "").strip()
        container = str(app.config.get("AZURE_BLOB_CONTAINER") or "").strip()
        if conn and container:
            providers.append(AzureBlobStorageProvider(conn, container))
    if "dropbox" in targets:
        token = str(app.config.get("DROPBOX_ACCESS_TOKEN") or "").strip()
        if token:
            providers.append(DropboxStorageProvider(token))
    if "webdav" in targets:
        base_url = str(app.config.get("WEBDAV_BASE_URL") or "").strip()
        username = str(app.config.get("WEBDAV_USERNAME") or "").strip() or None
        password = str(app.config.get("WEBDAV_PASSWORD") or "").strip() or None
        if base_url:
            providers.append(WebDAVStorageProvider(base_url, username, password))
    return providers
