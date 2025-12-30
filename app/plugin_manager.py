"""
Enhanced Plugins System - Core Plugin Manager

Handles plugin installation, validation, testing, and lifecycle management.
"""

import hashlib
import json
import os
import secrets
import shutil
import subprocess
import tempfile
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import bcrypt
from packaging import version as pkg_version
from sqlalchemy.orm import Session

from app.models import (
    EnhancedPlugin,
    PluginApiKeyRotation,
    PluginEvent,
    PluginPropertyAssignment,
    PluginTestRun,
)


class PluginValidationError(Exception):
    """Raised when plugin validation fails."""
    pass


class PluginInstallationError(Exception):
    """Raised when plugin installation fails."""
    pass


class PluginTestError(Exception):
    """Raised when plugin tests fail."""
    pass


class PluginManager:
    """Manages the Enhanced Plugins System."""

    def __init__(self, db: Session, plugins_base_dir: str = "/opt/pentavision/plugins"):
        self.db = db
        self.plugins_base_dir = Path(plugins_base_dir)
        self.plugins_base_dir.mkdir(parents=True, exist_ok=True)

    # ========================================================================
    # PHASE 1: PREFLIGHT VALIDATION
    # ========================================================================

    def validate_plugin_package(self, zip_path: str) -> dict[str, Any]:
        """
        Validate plugin package structure and integrity.
        
        Returns plugin metadata if valid, raises PluginValidationError otherwise.
        """
        staging_dir = Path(tempfile.mkdtemp(prefix="pentavision_plugin_"))
        
        try:
            # Extract zip to staging
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(staging_dir)
            
            # Step 1: Validate required files exist
            plugin_id_path = staging_dir / "plugin.id"
            definition_path = staging_dir / "definition.json"
            test_plan_path = staging_dir / "tests" / "test_plan.json"
            readme_path = staging_dir / "README.md"
            
            if not plugin_id_path.exists():
                raise PluginValidationError("Missing required file: plugin.id")
            if not definition_path.exists():
                raise PluginValidationError("Missing required file: definition.json")
            if not test_plan_path.exists():
                raise PluginValidationError("Missing required file: tests/test_plan.json")
            if not readme_path.exists():
                raise PluginValidationError("Missing required file: README.md")
            
            # Step 2: Load and validate plugin.id
            with open(plugin_id_path, 'r') as f:
                plugin_id = json.load(f)
            
            self._validate_plugin_id(plugin_id)
            
            # Step 3: Load and validate definition.json
            with open(definition_path, 'r') as f:
                definition = json.load(f)
            
            self._validate_definition(definition)
            
            # Step 4: Validate entrypoint exists
            entrypoint_path = staging_dir / plugin_id['entrypoint']
            if not entrypoint_path.exists():
                raise PluginValidationError(f"Entrypoint not found: {plugin_id['entrypoint']}")
            
            # Step 5: Validate file integrity (hash check)
            self._validate_file_hashes(staging_dir, plugin_id['hashes'])
            
            # Step 6: Validate compatibility
            self._validate_compatibility(plugin_id)
            
            # Step 7: Validate scopes
            self._validate_scopes(definition.get('scopes', []))
            
            # Step 8: Validate ports
            self._validate_ports(definition.get('install_requirements', {}).get('ports', []))
            
            return {
                'plugin_id': plugin_id,
                'definition': definition,
                'staging_dir': str(staging_dir),
                'valid': True
            }
        
        except Exception as e:
            # Clean up staging directory on failure
            shutil.rmtree(staging_dir, ignore_errors=True)
            raise

    def _validate_plugin_id(self, plugin_id: dict) -> None:
        """Validate plugin.id structure and required fields."""
        required_fields = [
            'plugin_key', 'version', 'author', 'website',
            'min_pentavision_version', 'entrypoint', 'runtime_type', 'hashes'
        ]
        
        for field in required_fields:
            if field not in plugin_id:
                raise PluginValidationError(f"Missing required field in plugin.id: {field}")
        
        # Validate plugin_key format (lowercase alphanumeric + hyphens)
        plugin_key = plugin_id['plugin_key']
        if not all(c.isalnum() or c == '-' for c in plugin_key):
            raise PluginValidationError("plugin_key must contain only lowercase alphanumeric characters and hyphens")
        
        # Validate version format (semver)
        try:
            pkg_version.Version(plugin_id['version'])
        except Exception:
            raise PluginValidationError("Invalid version format (must be semver)")
        
        # Validate runtime_type
        valid_runtime_types = ['worker', 'integration', 'storage', 'analytics']
        if plugin_id['runtime_type'] not in valid_runtime_types:
            raise PluginValidationError(f"Invalid runtime_type. Must be one of: {valid_runtime_types}")

    def _validate_definition(self, definition: dict) -> None:
        """Validate definition.json structure."""
        required_fields = ['name', 'description', 'category', 'capabilities', 'scopes']
        
        for field in required_fields:
            if field not in definition:
                raise PluginValidationError(f"Missing required field in definition.json: {field}")
        
        # Validate category
        valid_categories = ['integration', 'storage', 'analytics', 'worker']
        if definition['category'] not in valid_categories:
            raise PluginValidationError(f"Invalid category. Must be one of: {valid_categories}")

    def _validate_file_hashes(self, staging_dir: Path, hashes: dict) -> None:
        """Validate file integrity using SHA256 hashes."""
        if 'algorithm' not in hashes or hashes['algorithm'] != 'sha256':
            raise PluginValidationError("Only SHA256 hashing is supported")
        
        declared_hashes = hashes.get('files', {})
        
        for file_path, expected_hash in declared_hashes.items():
            full_path = staging_dir / file_path
            
            if not full_path.exists():
                raise PluginValidationError(f"File listed in hashes not found: {file_path}")
            
            # Calculate actual hash
            sha256_hash = hashlib.sha256()
            with open(full_path, 'rb') as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            actual_hash = sha256_hash.hexdigest()
            
            if actual_hash != expected_hash:
                raise PluginValidationError(
                    f"Hash mismatch for {file_path}. Expected: {expected_hash}, Got: {actual_hash}"
                )

    def _validate_compatibility(self, plugin_id: dict) -> None:
        """Validate PentaVision version compatibility."""
        # Get current PentaVision version
        current_version = self._get_pentavision_version()
        
        min_version = pkg_version.Version(plugin_id['min_pentavision_version'])
        
        if current_version < min_version:
            raise PluginValidationError(
                f"Plugin requires PentaVision {min_version} or higher. Current version: {current_version}"
            )
        
        if 'max_pentavision_version' in plugin_id:
            max_version = pkg_version.Version(plugin_id['max_pentavision_version'])
            if current_version >= max_version:
                raise PluginValidationError(
                    f"Plugin is not compatible with PentaVision {current_version}. Maximum supported: {max_version}"
                )

    def _get_pentavision_version(self) -> pkg_version.Version:
        """Get current PentaVision version."""
        # Read from VERSION file
        version_file = Path(__file__).parent.parent / "VERSION"
        if version_file.exists():
            with open(version_file, 'r') as f:
                return pkg_version.Version(f.read().strip())
        return pkg_version.Version("1.1.0")  # Default

    def _validate_scopes(self, scopes: list[str]) -> None:
        """Validate requested scopes."""
        allowed_scopes = [
            'cameras:read', 'cameras:write',
            'streams:read', 'streams:write',
            'properties:read',
            'recordings:read', 'recordings:write',
            'storage:read', 'storage:write'
        ]
        
        for scope in scopes:
            if scope not in allowed_scopes:
                raise PluginValidationError(f"Unknown scope: {scope}")
            
            # Write scopes require special attention
            if scope.endswith(':write'):
                # This will require explicit admin approval in the UI
                pass

    def _validate_ports(self, ports: list[int]) -> None:
        """Validate requested ports."""
        for port in ports:
            # Check port range
            if not (8000 <= port <= 9000):
                raise PluginValidationError(f"Port {port} outside allowed range (8000-9000)")
            
            # Check if port is available (basic check)
            # TODO: More sophisticated port availability check
            pass

    # ========================================================================
    # PHASE 2: INSTALLATION
    # ========================================================================

    def install_plugin(self, validation_result: dict, user_id: int) -> EnhancedPlugin:
        """
        Install a validated plugin.
        
        This creates the plugin directory, installs dependencies, and registers in database.
        """
        plugin_id = validation_result['plugin_id']
        definition = validation_result['definition']
        staging_dir = Path(validation_result['staging_dir'])
        
        plugin_key = plugin_id['plugin_key']
        
        try:
            # Check if plugin already exists
            existing = self.db.query(EnhancedPlugin).filter(
                EnhancedPlugin.plugin_key == plugin_key
            ).first()
            
            if existing:
                raise PluginInstallationError(f"Plugin {plugin_key} is already installed")
            
            # Create plugin directory
            plugin_dir = self.plugins_base_dir / plugin_key
            plugin_dir.mkdir(parents=True, exist_ok=True)
            
            current_dir = plugin_dir / "current"
            venv_dir = plugin_dir / "venv"
            
            # Copy plugin files
            shutil.copytree(staging_dir, current_dir, dirs_exist_ok=True)
            
            # Create virtual environment
            self._create_venv(venv_dir)
            
            # Install dependencies
            requirements_file = current_dir / "requirements.txt"
            if requirements_file.exists():
                self._install_dependencies(venv_dir, requirements_file)
            
            # Run setup.py if exists
            setup_file = current_dir / "setup.py"
            if setup_file.exists():
                self._run_setup(venv_dir, current_dir)
            
            # Register in database
            plugin = EnhancedPlugin(
                plugin_key=plugin_key,
                version=plugin_id['version'],
                name=definition['name'],
                description=definition.get('description'),
                author=plugin_id['author'],
                author_email=plugin_id.get('author_email'),
                website=plugin_id.get('website'),
                category=definition['category'],
                install_path=str(plugin_dir),
                installed_by=user_id,
                status='installed_pending_verification',
                capabilities=json.dumps(definition.get('capabilities', [])),
                scopes=json.dumps(definition.get('scopes', [])),
                runtime_type=plugin_id['runtime_type'],
                entrypoint=plugin_id['entrypoint'],
                min_pentavision_version=plugin_id['min_pentavision_version'],
                max_pentavision_version=plugin_id.get('max_pentavision_version'),
                pip_packages=json.dumps(definition.get('install_requirements', {}).get('pip_packages', [])),
                os_packages=json.dumps(definition.get('install_requirements', {}).get('os_packages', [])),
                required_ports=json.dumps(definition.get('install_requirements', {}).get('ports', [])),
                disk_space_mb=definition.get('install_requirements', {}).get('disk_space_mb'),
                memory_mb=definition.get('install_requirements', {}).get('memory_mb'),
                health_endpoint=definition.get('health_check', {}).get('endpoint', '/health'),
                health_interval_seconds=definition.get('health_check', {}).get('interval_seconds', 30),
                health_timeout_seconds=definition.get('health_check', {}).get('timeout_seconds', 5),
                health_unhealthy_threshold=definition.get('health_check', {}).get('unhealthy_threshold', 3),
            )
            
            self.db.add(plugin)
            self.db.commit()
            self.db.refresh(plugin)
            
            # Log event
            self._log_event(
                plugin_key=plugin_key,
                event_type='PLUGIN_INSTALLED',
                severity='info',
                message=f'Plugin {plugin_key} v{plugin_id["version"]} installed',
                user_id=user_id
            )
            
            # Clean up staging directory
            shutil.rmtree(staging_dir, ignore_errors=True)
            
            return plugin
        
        except Exception as e:
            # Rollback on failure
            self.db.rollback()
            
            # Clean up plugin directory if created
            plugin_dir = self.plugins_base_dir / plugin_key
            if plugin_dir.exists():
                shutil.rmtree(plugin_dir, ignore_errors=True)
            
            raise PluginInstallationError(f"Installation failed: {str(e)}")

    def _create_venv(self, venv_dir: Path) -> None:
        """Create a Python virtual environment for the plugin."""
        result = subprocess.run(
            ['python3', '-m', 'venv', str(venv_dir)],
            capture_output=True,
            text=True,
            timeout=120
        )
        
        if result.returncode != 0:
            raise PluginInstallationError(f"Failed to create venv: {result.stderr}")

    def _install_dependencies(self, venv_dir: Path, requirements_file: Path) -> None:
        """Install Python dependencies in the plugin's venv."""
        pip_path = venv_dir / "bin" / "pip"
        
        result = subprocess.run(
            [str(pip_path), 'install', '-r', str(requirements_file)],
            capture_output=True,
            text=True,
            timeout=600
        )
        
        if result.returncode != 0:
            raise PluginInstallationError(f"Failed to install dependencies: {result.stderr}")

    def _run_setup(self, venv_dir: Path, plugin_dir: Path) -> None:
        """Run plugin setup.py if it exists."""
        python_path = venv_dir / "bin" / "python"
        setup_file = plugin_dir / "setup.py"
        
        result = subprocess.run(
            [str(python_path), str(setup_file), 'install'],
            cwd=str(plugin_dir),
            capture_output=True,
            text=True,
            timeout=300
        )
        
        if result.returncode != 0:
            raise PluginInstallationError(f"Setup failed: {result.stderr}")

    # ========================================================================
    # API KEY MANAGEMENT
    # ========================================================================

    def generate_api_key(
        self,
        plugin_key: str,
        property_id: int,
        user_id: int
    ) -> tuple[str, str]:
        """
        Generate a new API key for a property.
        
        Returns: (full_key, prefix)
        """
        # Generate random key
        random_part = secrets.token_urlsafe(32)
        full_key = f"pk_prop{property_id}_{random_part}"
        prefix = full_key[:13]  # "pk_prop{id}_"
        
        # Hash the key
        key_hash = bcrypt.hashpw(full_key.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        # Update assignment
        assignment = self.db.query(PluginPropertyAssignment).filter(
            PluginPropertyAssignment.plugin_key == plugin_key,
            PluginPropertyAssignment.property_id == property_id
        ).first()
        
        if assignment:
            old_prefix = assignment.api_key_prefix
            
            assignment.api_key_hash = key_hash
            assignment.api_key_prefix = prefix
            assignment.api_key_created_at = datetime.utcnow()
            assignment.api_key_rotated_count += 1
            assignment.api_key_last_rotation = datetime.utcnow()
            
            self.db.commit()
            
            # Log rotation
            rotation = PluginApiKeyRotation(
                plugin_key=plugin_key,
                property_id=property_id,
                old_key_prefix=old_prefix,
                new_key_prefix=prefix,
                rotated_by=user_id,
                rotated_by_admin=False,
                reason='manual'
            )
            self.db.add(rotation)
            self.db.commit()
        
        return full_key, prefix

    def verify_api_key(self, plugin_key: str, api_key: str) -> Optional[int]:
        """
        Verify an API key and return the property_id if valid.
        
        Returns None if invalid.
        """
        # Extract property_id from key prefix
        if not api_key.startswith('pk_prop'):
            return None
        
        try:
            property_id_str = api_key.split('_')[1].replace('prop', '')
            property_id = int(property_id_str)
        except (IndexError, ValueError):
            return None
        
        # Get assignment
        assignment = self.db.query(PluginPropertyAssignment).filter(
            PluginPropertyAssignment.plugin_key == plugin_key,
            PluginPropertyAssignment.property_id == property_id,
            PluginPropertyAssignment.status == 'enabled'
        ).first()
        
        if not assignment or not assignment.api_key_hash:
            return None
        
        # Verify hash
        if bcrypt.checkpw(api_key.encode('utf-8'), assignment.api_key_hash.encode('utf-8')):
            # Update last used timestamp
            assignment.api_key_last_used = datetime.utcnow()
            self.db.commit()
            return property_id
        
        return None

    # ========================================================================
    # UTILITIES
    # ========================================================================

    def _log_event(
        self,
        plugin_key: str,
        event_type: str,
        severity: str,
        message: str,
        user_id: Optional[int] = None,
        property_id: Optional[int] = None,
        details: Optional[dict] = None
    ) -> None:
        """Log a plugin event."""
        event = PluginEvent(
            plugin_key=plugin_key,
            property_id=property_id,
            event_type=event_type,
            severity=severity,
            message=message,
            details=json.dumps(details) if details else None,
            user_id=user_id
        )
        self.db.add(event)
        self.db.commit()
