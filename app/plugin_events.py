"""
Plugin Event Integration

Provides hooks for broadcasting camera and system events to plugins.
This module is imported by recording_service and other event sources.
"""

import json
import logging
from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session

from app.db import get_record_engine
from app.models import EnhancedPlugin, PluginEvent, PluginPropertyAssignment

logger = logging.getLogger("pentavision.plugin_events")

# Global reference to plugin service (set by plugin service on startup)
_plugin_service = None


def set_plugin_service(service):
    """Set the global plugin service reference."""
    global _plugin_service
    _plugin_service = service


def broadcast_event(
    event_type: str,
    event_data: dict,
    property_id: Optional[int] = None,
    camera_id: Optional[int] = None,
):
    """
    Broadcast an event to all relevant plugins.

    Args:
        event_type: Type of event (e.g., 'motion_start', 'person_detected')
        event_data: Event payload
        property_id: If specified, only send to plugins for this property
        camera_id: Camera ID that generated the event
    """
    if _plugin_service:
        try:
            _plugin_service.broadcast_event(event_type, event_data, property_id)
        except Exception as e:
            logger.error(f"Error broadcasting event to plugins: {e}")
    else:
        # Plugin service not running, log to database for later processing
        _queue_event(event_type, event_data, property_id, camera_id)


def _queue_event(
    event_type: str,
    event_data: dict,
    property_id: Optional[int],
    camera_id: Optional[int],
):
    """Queue an event in the database when plugin service is not available."""
    engine = get_record_engine()
    if not engine:
        return

    db = Session(engine)
    try:
        # Find plugins that should receive this event
        query = db.query(PluginPropertyAssignment).join(EnhancedPlugin).filter(
            EnhancedPlugin.status.in_(["active", "verified", "enabled"]),
            PluginPropertyAssignment.enabled == True,  # noqa: E712
            PluginPropertyAssignment.admin_allowed == True,  # noqa: E712
        )

        if property_id:
            query = query.filter(PluginPropertyAssignment.property_id == property_id)

        assignments = query.all()

        for assignment in assignments:
            plugin = db.query(EnhancedPlugin).filter(
                EnhancedPlugin.id == assignment.plugin_id
            ).first()

            if plugin:
                # Log event for later processing
                event = PluginEvent(
                    plugin_id=plugin.id,
                    property_id=assignment.property_id,
                    event_type=f"queued:{event_type}",
                    severity="info",
                    message=json.dumps({
                        "original_type": event_type,
                        "data": event_data,
                        "camera_id": camera_id,
                        "queued_at": datetime.utcnow().isoformat(),
                    }),
                )
                db.add(event)

        db.commit()

    except Exception as e:
        logger.error(f"Error queuing event: {e}")
        db.rollback()
    finally:
        db.close()


# Convenience functions for common events

def motion_detected(
    camera_id: int,
    camera_name: str,
    property_id: int,
    confidence: float = 1.0,
    zone: Optional[str] = None,
):
    """Broadcast motion detection event."""
    broadcast_event(
        "motion_start",
        {
            "camera_id": camera_id,
            "camera_name": camera_name,
            "confidence": confidence,
            "zone": zone,
            "timestamp": datetime.utcnow().isoformat(),
        },
        property_id=property_id,
        camera_id=camera_id,
    )


def motion_ended(
    camera_id: int,
    camera_name: str,
    property_id: int,
    duration_seconds: float,
):
    """Broadcast motion ended event."""
    broadcast_event(
        "motion_end",
        {
            "camera_id": camera_id,
            "camera_name": camera_name,
            "duration_seconds": duration_seconds,
            "timestamp": datetime.utcnow().isoformat(),
        },
        property_id=property_id,
        camera_id=camera_id,
    )


def person_detected(
    camera_id: int,
    camera_name: str,
    property_id: int,
    confidence: float,
    bounding_box: Optional[dict] = None,
):
    """Broadcast person detection event."""
    broadcast_event(
        "person_detected",
        {
            "camera_id": camera_id,
            "camera_name": camera_name,
            "confidence": confidence,
            "bounding_box": bounding_box,
            "timestamp": datetime.utcnow().isoformat(),
        },
        property_id=property_id,
        camera_id=camera_id,
    )


def recording_started(
    camera_id: int,
    camera_name: str,
    property_id: int,
    recording_id: int,
):
    """Broadcast recording started event."""
    broadcast_event(
        "recording_started",
        {
            "camera_id": camera_id,
            "camera_name": camera_name,
            "recording_id": recording_id,
            "timestamp": datetime.utcnow().isoformat(),
        },
        property_id=property_id,
        camera_id=camera_id,
    )


def recording_ended(
    camera_id: int,
    camera_name: str,
    property_id: int,
    recording_id: int,
    duration_seconds: float,
    file_size_bytes: Optional[int] = None,
):
    """Broadcast recording ended event."""
    broadcast_event(
        "recording_ended",
        {
            "camera_id": camera_id,
            "camera_name": camera_name,
            "recording_id": recording_id,
            "duration_seconds": duration_seconds,
            "file_size_bytes": file_size_bytes,
            "timestamp": datetime.utcnow().isoformat(),
        },
        property_id=property_id,
        camera_id=camera_id,
    )


def camera_online(camera_id: int, camera_name: str, property_id: int):
    """Broadcast camera online event."""
    broadcast_event(
        "camera_online",
        {
            "camera_id": camera_id,
            "camera_name": camera_name,
            "timestamp": datetime.utcnow().isoformat(),
        },
        property_id=property_id,
        camera_id=camera_id,
    )


def camera_offline(camera_id: int, camera_name: str, property_id: int):
    """Broadcast camera offline event."""
    broadcast_event(
        "camera_offline",
        {
            "camera_id": camera_id,
            "camera_name": camera_name,
            "timestamp": datetime.utcnow().isoformat(),
        },
        property_id=property_id,
        camera_id=camera_id,
    )
