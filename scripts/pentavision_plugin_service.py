#!/usr/bin/env python3
"""
PentaVision Plugin Service

Loads and runs enabled plugins as background workers.
Handles plugin lifecycle, health checks, and event routing.
"""

import importlib.util
import json
import logging
import signal
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

# Add app to path before importing app modules
sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy.orm import Session  # noqa: E402

from app.db import get_record_engine  # noqa: E402
from app.models import (  # noqa: E402
    EnhancedPlugin,
    PluginEvent,
    PluginHealthCheck,
    PluginPropertyAssignment,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger("pentavision.plugin_service")


class PluginInstance:
    """Represents a running plugin instance for a specific property."""

    def __init__(
        self,
        plugin_key: str,
        property_id: int,
        plugin_module: Any,
        config: dict,
        api_key: str,
    ):
        self.plugin_key = plugin_key
        self.property_id = property_id
        self.plugin_module = plugin_module
        self.config = config
        self.api_key = api_key
        self.instance = None
        self.started = False
        self.last_health_check = None
        self.health_status = "unknown"

    def start(self) -> bool:
        """Start the plugin instance."""
        try:
            if hasattr(self.plugin_module, "create_plugin"):
                self.instance = self.plugin_module.create_plugin(
                    self.config, self.property_id, self.api_key
                )
            else:
                logger.error(f"Plugin {self.plugin_key} missing create_plugin function")
                return False

            if hasattr(self.instance, "start"):
                result = self.instance.start()
                self.started = result
                return result
            else:
                self.started = True
                return True

        except Exception as e:
            logger.error(f"Failed to start plugin {self.plugin_key} for property {self.property_id}: {e}")
            return False

    def stop(self):
        """Stop the plugin instance."""
        if self.instance and hasattr(self.instance, "stop"):
            try:
                self.instance.stop()
            except Exception as e:
                logger.error(f"Error stopping plugin {self.plugin_key}: {e}")
        self.started = False

    def health_check(self) -> dict:
        """Run health check on the plugin."""
        if not self.instance or not hasattr(self.instance, "health_check"):
            return {"status": "unknown", "message": "No health check available"}

        try:
            result = self.instance.health_check()
            self.last_health_check = datetime.utcnow()
            self.health_status = result.get("status", "unknown")
            return result
        except Exception as e:
            self.health_status = "error"
            return {"status": "error", "message": str(e)}

    def handle_event(self, event_type: str, event_data: dict) -> bool:
        """Forward an event to the plugin."""
        if not self.instance or not hasattr(self.instance, "handle_event"):
            return False

        try:
            return self.instance.handle_event(event_type, event_data)
        except Exception as e:
            logger.error(f"Plugin {self.plugin_key} error handling event: {e}")
            return False


class PluginService:
    """Main plugin service that manages all plugin instances."""

    def __init__(self, plugins_dir: str = "/opt/pentavision/plugins"):
        self.plugins_dir = Path(plugins_dir)
        self.running = False
        self.instances: dict[str, PluginInstance] = {}  # key: "{plugin_key}:{property_id}"
        self.loaded_modules: dict[str, Any] = {}  # key: plugin_key
        self.health_check_interval = 60  # seconds
        self.reload_interval = 30  # seconds
        self._health_thread: Optional[threading.Thread] = None
        self._reload_thread: Optional[threading.Thread] = None

    def start(self):
        """Start the plugin service."""
        logger.info("Starting PentaVision Plugin Service")
        self.running = True

        # Initial load
        self._load_all_plugins()

        # Start background threads
        self._health_thread = threading.Thread(target=self._health_check_loop, daemon=True)
        self._health_thread.start()

        self._reload_thread = threading.Thread(target=self._reload_loop, daemon=True)
        self._reload_thread.start()

        logger.info(f"Plugin service started with {len(self.instances)} instances")

    def stop(self):
        """Stop the plugin service and all instances."""
        logger.info("Stopping Plugin Service")
        self.running = False

        for key, instance in self.instances.items():
            logger.info(f"Stopping instance {key}")
            instance.stop()

        self.instances.clear()
        logger.info("Plugin Service stopped")

    def _load_all_plugins(self):
        """Load all enabled plugins from database."""
        engine = get_record_engine()
        if not engine:
            logger.error("Record database not configured")
            return

        db = Session(engine)
        try:
            # Get all active/verified plugins
            plugins = db.query(EnhancedPlugin).filter(
                EnhancedPlugin.status.in_(["active", "verified", "enabled"])
            ).all()

            for plugin in plugins:
                self._load_plugin(plugin, db)

        except Exception as e:
            logger.error(f"Error loading plugins: {e}")
        finally:
            db.close()

    def _load_plugin(self, plugin: EnhancedPlugin, db: Session):
        """Load a single plugin and create instances for enabled properties."""
        plugin_path = self.plugins_dir / plugin.plugin_key

        if not plugin_path.exists():
            logger.warning(f"Plugin directory not found: {plugin_path}")
            return

        # Load the plugin module
        if plugin.plugin_key not in self.loaded_modules:
            module = self._load_plugin_module(plugin.plugin_key, plugin_path)
            if module:
                self.loaded_modules[plugin.plugin_key] = module
            else:
                return

        module = self.loaded_modules[plugin.plugin_key]

        # Get property assignments
        assignments = db.query(PluginPropertyAssignment).filter(
            PluginPropertyAssignment.plugin_id == plugin.id,
            PluginPropertyAssignment.enabled == True,
            PluginPropertyAssignment.admin_allowed == True,
        ).all()

        for assignment in assignments:
            instance_key = f"{plugin.plugin_key}:{assignment.property_id}"

            if instance_key in self.instances:
                continue  # Already running

            config = json.loads(assignment.config) if assignment.config else {}

            instance = PluginInstance(
                plugin_key=plugin.plugin_key,
                property_id=assignment.property_id,
                plugin_module=module,
                config=config,
                api_key=assignment.api_key_hash or "",  # Plugin uses hashed key for verification
            )

            if instance.start():
                self.instances[instance_key] = instance
                logger.info(f"Started plugin instance: {instance_key}")

                # Log event
                self._log_event(
                    db, plugin.id, assignment.property_id,
                    "plugin_started", "info", "Plugin instance started"
                )
            else:
                logger.error(f"Failed to start plugin instance: {instance_key}")
                self._log_event(
                    db, plugin.id, assignment.property_id,
                    "plugin_start_failed", "error", "Failed to start plugin instance"
                )

    def _load_plugin_module(self, plugin_key: str, plugin_path: Path) -> Optional[Any]:
        """Load a plugin's Python module."""
        main_file = plugin_path / "main.py"

        if not main_file.exists():
            logger.error(f"Plugin main.py not found: {main_file}")
            return None

        try:
            spec = importlib.util.spec_from_file_location(
                f"pentavision_plugin_{plugin_key}",
                main_file
            )
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                sys.modules[spec.name] = module
                spec.loader.exec_module(module)
                logger.info(f"Loaded plugin module: {plugin_key}")
                return module
        except Exception as e:
            logger.error(f"Failed to load plugin module {plugin_key}: {e}")

        return None

    def _health_check_loop(self):
        """Background thread for periodic health checks."""
        while self.running:
            time.sleep(self.health_check_interval)

            if not self.running:
                break

            engine = get_record_engine()
            if not engine:
                continue

            db = Session(engine)
            try:
                for key, instance in list(self.instances.items()):
                    result = instance.health_check()

                    # Record health check
                    plugin = db.query(EnhancedPlugin).filter(
                        EnhancedPlugin.plugin_key == instance.plugin_key
                    ).first()

                    if plugin:
                        health_record = PluginHealthCheck(
                            plugin_id=plugin.id,
                            property_id=instance.property_id,
                            status=result.get("status", "unknown"),
                            response_time_ms=result.get("response_time_ms"),
                            details=json.dumps(result),
                        )
                        db.add(health_record)

                        # Update plugin health status
                        plugin.last_health_status = result.get("status", "unknown")
                        plugin.last_health_check = datetime.utcnow()

                db.commit()

            except Exception as e:
                logger.error(f"Health check error: {e}")
                db.rollback()
            finally:
                db.close()

    def _reload_loop(self):
        """Background thread to check for new/changed plugin assignments."""
        while self.running:
            time.sleep(self.reload_interval)

            if not self.running:
                break

            try:
                self._check_for_changes()
            except Exception as e:
                logger.error(f"Reload check error: {e}")

    def _check_for_changes(self):
        """Check for new plugin assignments or disabled plugins."""
        engine = get_record_engine()
        if not engine:
            return

        db = Session(engine)
        try:
            # Get all active assignments
            active_assignments = db.query(PluginPropertyAssignment).join(
                EnhancedPlugin
            ).filter(
                EnhancedPlugin.status.in_(["active", "verified", "enabled"]),
                PluginPropertyAssignment.enabled == True,
                PluginPropertyAssignment.admin_allowed == True,
            ).all()

            active_keys = set()
            for assignment in active_assignments:
                plugin = db.query(EnhancedPlugin).filter(
                    EnhancedPlugin.id == assignment.plugin_id
                ).first()
                if plugin:
                    key = f"{plugin.plugin_key}:{assignment.property_id}"
                    active_keys.add(key)

                    # Start new instances
                    if key not in self.instances:
                        self._load_plugin(plugin, db)

            # Stop removed instances
            for key in list(self.instances.keys()):
                if key not in active_keys:
                    logger.info(f"Stopping removed instance: {key}")
                    self.instances[key].stop()
                    del self.instances[key]

        finally:
            db.close()

    def _log_event(
        self,
        db: Session,
        plugin_id: int,
        property_id: Optional[int],
        event_type: str,
        severity: str,
        message: str,
    ):
        """Log a plugin event."""
        try:
            event = PluginEvent(
                plugin_id=plugin_id,
                property_id=property_id,
                event_type=event_type,
                severity=severity,
                message=message,
            )
            db.add(event)
            db.commit()
        except Exception as e:
            logger.error(f"Failed to log event: {e}")
            db.rollback()

    def broadcast_event(self, event_type: str, event_data: dict, property_id: Optional[int] = None):
        """
        Broadcast an event to all relevant plugin instances.

        Args:
            event_type: Type of event (e.g., 'motion_start', 'person_detected')
            event_data: Event payload
            property_id: If specified, only send to plugins for this property
        """
        for key, instance in self.instances.items():
            if property_id and instance.property_id != property_id:
                continue

            try:
                instance.handle_event(event_type, event_data)
            except Exception as e:
                logger.error(f"Error broadcasting to {key}: {e}")


# Global service instance
_service: Optional[PluginService] = None


def get_plugin_service() -> Optional[PluginService]:
    """Get the global plugin service instance."""
    return _service


def broadcast_camera_event(event_type: str, event_data: dict, property_id: Optional[int] = None):
    """
    Broadcast a camera event to all plugins.
    Called from recording_service or other camera event sources.
    """
    if _service:
        _service.broadcast_event(event_type, event_data, property_id)


def main():
    """Main entry point for the plugin service."""
    global _service

    logger.info("=" * 60)
    logger.info("PentaVision Plugin Service Starting")
    logger.info("=" * 60)

    _service = PluginService()

    def signal_handler(signum, frame):
        logger.info(f"Received signal {signum}, shutting down...")
        if _service:
            _service.stop()
        sys.exit(0)

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    _service.start()

    # Keep main thread alive
    try:
        while _service.running:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received")
        _service.stop()


if __name__ == "__main__":
    main()
