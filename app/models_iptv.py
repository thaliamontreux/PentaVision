from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column

from .models import RecordBase


class CameraIptvChannel(RecordBase):
    __tablename__ = "camera_iptv_channels"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(Integer, index=True, unique=True)
    is_enabled: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    multicast_address: Mapped[str] = mapped_column(String(64))
    port: Mapped[int] = mapped_column(Integer)
    ttl: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    channel_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    last_error: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    last_started_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
