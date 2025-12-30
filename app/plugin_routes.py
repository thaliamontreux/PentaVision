"""
Enhanced Plugins System - Admin Routes

Flask blueprint for plugin management endpoints.
"""

import os
from datetime import datetime
from pathlib import Path

from flask import (
    Blueprint,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from sqlalchemy.orm import Session
from werkzeug.utils import secure_filename

from app.db import get_record_engine, get_user_engine
from app.models import (
    EnhancedPlugin,
    PluginApiKeyRotation,
    PluginEvent,
    PluginPropertyAssignment,
    Property,
)
from app.plugin_manager import (
    PluginManager,
    PluginInstallationError,
    PluginValidationError,
)
from app.security import get_current_user, user_has_permission

plugin_bp = Blueprint('plugins', __name__)


# ========================================================================
# SYSTEM ADMIN ROUTES
# ========================================================================

@plugin_bp.route('/admin/plugins')
def admin_plugins_list():
    """System Admin: View all installed plugins."""
    user = get_current_user()
    if user is None:
        abort(403)
    if not user_has_permission(user, "Admin.System.*"):
        abort(403)

    engine = get_record_engine()
    if not engine:
        abort(500, "Database not configured")

    # Ensure plugin tables exist
    from app.models import RecordBase
    RecordBase.metadata.create_all(engine)

    db = Session(engine)

    try:
        plugins = db.query(EnhancedPlugin).order_by(
            EnhancedPlugin.category,
            EnhancedPlugin.name
        ).all()
        
        plugin_stats = []
        for plugin in plugins:
            # Count properties using this plugin
            property_count = db.query(PluginPropertyAssignment).filter(
                PluginPropertyAssignment.plugin_key == plugin.plugin_key,
                PluginPropertyAssignment.status == 'enabled'
            ).count()
            
            # Get recent events
            recent_events = db.query(PluginEvent).filter(
                PluginEvent.plugin_key == plugin.plugin_key
            ).order_by(
                PluginEvent.created_at.desc()
            ).limit(5).all()
            
            plugin_stats.append({
                'plugin': plugin,
                'property_count': property_count,
                'recent_events': recent_events
            })
        
        return render_template(
            'admin/plugins/list.html',
            plugin_stats=plugin_stats
        )
    finally:
        db.close()


@plugin_bp.route('/admin/plugins/upload', methods=['GET', 'POST'])
def admin_plugins_upload():
    """System Admin: Upload and install a new plugin."""
    user = get_current_user()
    if user is None:
        abort(403)
    if not user_has_permission(user, "Admin.System.*"):
        abort(403)

    if request.method == 'GET':
        return render_template('admin/plugins/upload.html')

    engine = get_record_engine()
    if not engine:
        abort(500, "Database not configured")
    db = Session(engine)
    
    try:
        if 'plugin_file' not in request.files:
            flash('No file uploaded', 'error')
            return redirect(url_for('plugins.admin_plugins_upload'))
        
        file = request.files['plugin_file']
        
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(url_for('plugins.admin_plugins_upload'))
        
        if not file.filename.endswith('.zip'):
            flash('Plugin must be a .zip file', 'error')
            return redirect(url_for('plugins.admin_plugins_upload'))
        
        # Save uploaded file
        filename = secure_filename(file.filename)
        upload_dir = Path('/tmp/pentavision_uploads')
        upload_dir.mkdir(parents=True, exist_ok=True)
        upload_path = upload_dir / filename
        file.save(str(upload_path))
        
        # Validate and install
        manager = PluginManager(db)
        
        try:
            # Validate
            validation_result = manager.validate_plugin_package(str(upload_path))
            
            # Install
            plugin = manager.install_plugin(
                validation_result,
                user_id=session.get('user_id')
            )
            
            flash(f'Plugin {plugin.name} v{plugin.version} installed successfully', 'success')
            return redirect(url_for('plugins.admin_plugin_detail', plugin_key=plugin.plugin_key))
        
        except PluginValidationError as e:
            flash(f'Validation failed: {str(e)}', 'error')
            return redirect(url_for('plugins.admin_plugins_upload'))
        
        except PluginInstallationError as e:
            flash(f'Installation failed: {str(e)}', 'error')
            return redirect(url_for('plugins.admin_plugins_upload'))
        
        finally:
            # Clean up uploaded file
            if upload_path.exists():
                os.unlink(upload_path)
    
    finally:
        db.close()


@plugin_bp.route('/admin/plugins/<plugin_key>')
def admin_plugin_detail(plugin_key):
    """System Admin: View plugin details and manage property access."""
    user = get_current_user()
    if user is None:
        abort(403)
    if not user_has_permission(user, "Admin.System.*"):
        abort(403)

    engine = get_record_engine()
    if not engine:
        abort(500, "Database not configured")
    db = Session(engine)
    
    try:
        plugin = db.query(EnhancedPlugin).filter(
            EnhancedPlugin.plugin_key == plugin_key
        ).first()
        
        if not plugin:
            abort(404)
        
        # Get all properties
        properties = db.query(Property).order_by(Property.name).all()
        
        # Get property assignments
        assignments = db.query(PluginPropertyAssignment).filter(
            PluginPropertyAssignment.plugin_key == plugin_key
        ).all()
        
        assignment_map = {a.property_id: a for a in assignments}
        
        # Build property status list
        property_statuses = []
        for prop in properties:
            assignment = assignment_map.get(prop.id)
            property_statuses.append({
                'property': prop,
                'assignment': assignment,
                'status': assignment.status if assignment else 'not_assigned',
                'admin_allowed': assignment.admin_allowed if assignment else True,
                'api_key_prefix': assignment.api_key_prefix if assignment else None,
                'api_key_last_used': assignment.api_key_last_used if assignment else None
            })
        
        # Get recent events
        events = db.query(PluginEvent).filter(
            PluginEvent.plugin_key == plugin_key
        ).order_by(
            PluginEvent.created_at.desc()
        ).limit(50).all()
        
        return render_template(
            'admin/plugins/detail.html',
            plugin=plugin,
            property_statuses=property_statuses,
            events=events
        )
    
    finally:
        db.close()


@plugin_bp.route('/admin/plugins/<plugin_key>/properties/<int:property_id>/toggle', methods=['POST'])
def admin_toggle_property_access(plugin_key, property_id):
    """System Admin: Enable/disable plugin access for a property."""
    user = get_current_user()
    if user is None:
        return jsonify({'error': 'Authentication required'}), 401
    if not user_has_permission(user, "Admin.System.*"):
        return jsonify({'error': 'Permission denied'}), 403

    engine = get_record_engine()
    if not engine:
        abort(500, "Database not configured")
    db = Session(engine)
    
    try:
        plugin = db.query(EnhancedPlugin).filter(
            EnhancedPlugin.plugin_key == plugin_key
        ).first()
        
        if not plugin:
            return jsonify({'error': 'Plugin not found'}), 404
        
        assignment = db.query(PluginPropertyAssignment).filter(
            PluginPropertyAssignment.plugin_key == plugin_key,
            PluginPropertyAssignment.property_id == property_id
        ).first()
        
        action = request.json.get('action')  # 'enable' or 'disable'
        
        if action == 'enable':
            if not assignment:
                # Create new assignment
                assignment = PluginPropertyAssignment(
                    plugin_key=plugin_key,
                    property_id=property_id,
                    status='disabled',
                    admin_allowed=True
                )
                db.add(assignment)
            
            assignment.admin_allowed = True
            assignment.admin_disabled_at = None
            assignment.admin_disabled_by = None
            assignment.admin_disabled_reason = None
            
            db.commit()
            
            return jsonify({
                'success': True,
                'message': 'Plugin access enabled for property'
            })
        
        elif action == 'disable':
            if not assignment:
                return jsonify({'error': 'No assignment found'}), 404
            
            assignment.admin_allowed = False
            assignment.admin_disabled_at = datetime.utcnow()
            assignment.admin_disabled_by = session.get('user_id')
            assignment.admin_disabled_reason = request.json.get('reason', 'Disabled by admin')
            
            # Also disable if currently enabled
            if assignment.status == 'enabled':
                assignment.status = 'disabled'
                assignment.disabled_at = datetime.utcnow()
                assignment.disabled_by = session.get('user_id')
            
            db.commit()
            
            return jsonify({
                'success': True,
                'message': 'Plugin access disabled for property'
            })
        
        else:
            return jsonify({'error': 'Invalid action'}), 400
    
    finally:
        db.close()


@plugin_bp.route('/admin/plugins/<plugin_key>/properties/<int:property_id>/rotate-key', methods=['POST'])
def admin_rotate_property_key(plugin_key, property_id):
    """System Admin: Rotate API key for a property (on their behalf)."""
    user = get_current_user()
    if user is None:
        return jsonify({'error': 'Authentication required'}), 401
    if not user_has_permission(user, "Admin.System.*"):
        return jsonify({'error': 'Permission denied'}), 403

    engine = get_record_engine()
    if not engine:
        abort(500, "Database not configured")
    db = Session(engine)
    
    try:
        assignment = db.query(PluginPropertyAssignment).filter(
            PluginPropertyAssignment.plugin_key == plugin_key,
            PluginPropertyAssignment.property_id == property_id
        ).first()
        
        if not assignment:
            return jsonify({'error': 'Assignment not found'}), 404
        
        manager = PluginManager(db)
        
        # Generate new key
        full_key, prefix = manager.generate_api_key(
            plugin_key=plugin_key,
            property_id=property_id,
            user_id=session.get('user_id')
        )
        
        # Log rotation as admin action
        rotation = db.query(PluginApiKeyRotation).filter(
            PluginApiKeyRotation.plugin_key == plugin_key,
            PluginApiKeyRotation.property_id == property_id
        ).order_by(
            PluginApiKeyRotation.rotated_at.desc()
        ).first()
        
        if rotation:
            rotation.rotated_by_admin = True
            rotation.reason = 'admin_rotation'
            db.commit()
        
        return jsonify({
            'success': True,
            'api_key': full_key,
            'prefix': prefix,
            'message': 'API key rotated successfully. Share this key securely with the property manager.'
        })
    
    finally:
        db.close()


# ========================================================================
# PROPERTY MANAGER ROUTES
# ========================================================================

@plugin_bp.route('/properties/<int:property_id>/plugins')
def property_plugins_list(property_id):
    """Property Manager: View available plugins for this property."""
    user = get_current_user()
    if user is None:
        abort(403)
    # TODO: Add property-level permission check

    engine = get_record_engine()
    if not engine:
        abort(500, "Database not configured")
    db = Session(engine)
    
    try:
        # Get all verified plugins
        plugins = db.query(EnhancedPlugin).filter(
            EnhancedPlugin.status.in_(['verified', 'enabled'])
        ).order_by(
            EnhancedPlugin.category,
            EnhancedPlugin.name
        ).all()
        
        # Get assignments for this property
        assignments = db.query(PluginPropertyAssignment).filter(
            PluginPropertyAssignment.property_id == property_id
        ).all()
        
        assignment_map = {a.plugin_key: a for a in assignments}
        
        # Build plugin status list
        plugin_statuses = []
        for plugin in plugins:
            assignment = assignment_map.get(plugin.plugin_key)
            
            # Check if admin allows access
            admin_allowed = True
            if assignment:
                admin_allowed = assignment.admin_allowed
            
            plugin_statuses.append({
                'plugin': plugin,
                'assignment': assignment,
                'status': assignment.status if assignment else 'available',
                'admin_allowed': admin_allowed,
                'api_key_prefix': assignment.api_key_prefix if assignment else None,
                'api_key_last_used': assignment.api_key_last_used if assignment else None,
                'can_enable': admin_allowed and (not assignment or assignment.status == 'disabled')
            })
        
        return render_template(
            'properties/plugins/list.html',
            property_id=property_id,
            plugin_statuses=plugin_statuses
        )
    
    finally:
        db.close()


@plugin_bp.route('/properties/<int:property_id>/plugins/<plugin_key>/enable', methods=['POST'])
def property_enable_plugin(property_id, plugin_key):
    """Property Manager: Enable a plugin for this property."""
    user = get_current_user()
    if user is None:
        return jsonify({'error': 'Authentication required'}), 401
    # TODO: Add property-level permission check

    engine = get_record_engine()
    if not engine:
        abort(500, "Database not configured")
    db = Session(engine)
    
    try:
        plugin = db.query(EnhancedPlugin).filter(
            EnhancedPlugin.plugin_key == plugin_key
        ).first()
        
        if not plugin:
            return jsonify({'error': 'Plugin not found'}), 404
        
        assignment = db.query(PluginPropertyAssignment).filter(
            PluginPropertyAssignment.plugin_key == plugin_key,
            PluginPropertyAssignment.property_id == property_id
        ).first()
        
        if not assignment:
            # Create new assignment
            assignment = PluginPropertyAssignment(
                plugin_key=plugin_key,
                property_id=property_id,
                status='enabled',
                enabled_at=datetime.utcnow(),
                enabled_by=session.get('user_id'),
                admin_allowed=True
            )
            db.add(assignment)
        else:
            # Check if admin allows
            if not assignment.admin_allowed:
                return jsonify({'error': 'Plugin access disabled by administrator'}), 403
            
            assignment.status = 'enabled'
            assignment.enabled_at = datetime.utcnow()
            assignment.enabled_by = session.get('user_id')
        
        db.commit()
        
        # Generate API key if needed
        manager = PluginManager(db)
        full_key, prefix = manager.generate_api_key(
            plugin_key=plugin_key,
            property_id=property_id,
            user_id=session.get('user_id')
        )
        
        return jsonify({
            'success': True,
            'api_key': full_key,
            'prefix': prefix,
            'message': f'Plugin {plugin.name} enabled successfully'
        })
    
    finally:
        db.close()


@plugin_bp.route('/properties/<int:property_id>/plugins/<plugin_key>/disable', methods=['POST'])
def property_disable_plugin(property_id, plugin_key):
    """Property Manager: Disable a plugin for this property."""
    user = get_current_user()
    if user is None:
        return jsonify({'error': 'Authentication required'}), 401
    # TODO: Add property-level permission check

    engine = get_record_engine()
    if not engine:
        abort(500, "Database not configured")
    db = Session(engine)
    
    try:
        assignment = db.query(PluginPropertyAssignment).filter(
            PluginPropertyAssignment.plugin_key == plugin_key,
            PluginPropertyAssignment.property_id == property_id
        ).first()
        
        if not assignment:
            return jsonify({'error': 'Plugin not enabled'}), 404
        
        assignment.status = 'disabled'
        assignment.disabled_at = datetime.utcnow()
        assignment.disabled_by = session.get('user_id')
        
        db.commit()
        
        return jsonify({
            'success': True,
            'message': 'Plugin disabled successfully'
        })
    
    finally:
        db.close()


@plugin_bp.route('/properties/<int:property_id>/plugins/<plugin_key>/configure', methods=['GET', 'POST'])
def property_configure_plugin(property_id, plugin_key):
    """Property Manager: Configure a plugin for this property."""
    user = get_current_user()
    if user is None:
        abort(403)

    engine = get_record_engine()
    if not engine:
        abort(500, "Database not configured")
    db = Session(engine)

    try:
        plugin = db.query(EnhancedPlugin).filter(
            EnhancedPlugin.plugin_key == plugin_key
        ).first()

        if not plugin:
            abort(404, "Plugin not found")

        assignment = db.query(PluginPropertyAssignment).filter(
            PluginPropertyAssignment.plugin_key == plugin_key,
            PluginPropertyAssignment.property_id == property_id
        ).first()

        if not assignment or not assignment.admin_allowed:
            abort(403, "Plugin not available for this property")

        # Load plugin definition for config schema
        config_schema = {}
        plugin_dir = Path("/opt/pentavision/plugins") / plugin_key
        definition_path = plugin_dir / "definition.json"

        if definition_path.exists():
            with open(definition_path) as f:
                definition = json.load(f)
                config_schema = definition.get("config_schema", {})

        if request.method == 'POST':
            # Save configuration
            config_data = request.json or {}

            assignment.config = json.dumps(config_data)
            assignment.config_updated_at = datetime.utcnow()
            db.commit()

            return jsonify({
                'success': True,
                'message': 'Configuration saved successfully'
            })

        # GET - return current config and schema
        current_config = {}
        if assignment.config:
            current_config = json.loads(assignment.config)

        return render_template(
            'properties/plugins/configure.html',
            plugin=plugin,
            property_id=property_id,
            config_schema=config_schema,
            current_config=current_config,
            assignment=assignment,
        )

    finally:
        db.close()


@plugin_bp.route('/properties/<int:property_id>/plugins/<plugin_key>/rotate-key', methods=['POST'])
def property_rotate_key(property_id, plugin_key):
    """Property Manager: Rotate API key for this property."""
    user = get_current_user()
    if user is None:
        return jsonify({'error': 'Authentication required'}), 401
    # TODO: Add property-level permission check

    engine = get_record_engine()
    if not engine:
        abort(500, "Database not configured")
    db = Session(engine)
    
    try:
        assignment = db.query(PluginPropertyAssignment).filter(
            PluginPropertyAssignment.plugin_key == plugin_key,
            PluginPropertyAssignment.property_id == property_id
        ).first()
        
        if not assignment:
            return jsonify({'error': 'Plugin not enabled'}), 404
        
        manager = PluginManager(db)
        
        # Generate new key
        full_key, prefix = manager.generate_api_key(
            plugin_key=plugin_key,
            property_id=property_id,
            user_id=session.get('user_id')
        )
        
        return jsonify({
            'success': True,
            'api_key': full_key,
            'prefix': prefix,
            'message': 'API key rotated successfully'
        })
    
    finally:
        db.close()


# ========================================================================
# DEMO/TESTING ENDPOINTS
# ========================================================================

@plugin_bp.route('/admin/plugins/create-demo', methods=['POST'])
def admin_create_demo_plugins():
    """Create demo plugins for testing the UI. System Admin only."""
    user = get_current_user()
    if user is None:
        abort(403)
    if not user_has_permission(user, "Admin.System.*"):
        abort(403)

    engine = get_record_engine()
    if not engine:
        abort(500, "Database not configured")

    from app.models import RecordBase
    RecordBase.metadata.create_all(engine)

    db = Session(engine)

    try:
        demo_plugins = [
            {
                'plugin_key': 'home-assistant',
                'version': '1.2.0',
                'name': 'Home Assistant',
                'description': 'Integration with Home Assistant for smart home automation and camera events.',
                'author': 'PentaVision',
                'author_email': 'plugins@pentavision.io',
                'category': 'automation',
                'status': 'active',
                'runtime_type': 'python',
                'entrypoint': 'main.py',
                'min_pentavision_version': '2.0.0',
                'install_path': '/opt/pentavision/plugins/home-assistant',
                'last_health_status': 'healthy',
                'capabilities': '["camera_events", "motion_detection", "person_detection"]',
                'scopes': '["read:cameras", "read:events", "write:webhooks"]',
            },
            {
                'plugin_key': 'slack-notifications',
                'version': '1.0.5',
                'name': 'Slack Notifications',
                'description': 'Send camera alerts and events to Slack channels.',
                'author': 'PentaVision',
                'author_email': 'plugins@pentavision.io',
                'category': 'notifications',
                'status': 'verified',
                'runtime_type': 'python',
                'entrypoint': 'slack_plugin.py',
                'min_pentavision_version': '2.0.0',
                'install_path': '/opt/pentavision/plugins/slack-notifications',
                'last_health_status': 'healthy',
                'capabilities': '["notifications", "alerts"]',
                'scopes': '["read:events", "read:cameras"]',
            },
            {
                'plugin_key': 'license-plate-reader',
                'version': '2.1.0',
                'name': 'License Plate Reader',
                'description': 'AI-powered license plate recognition for vehicle tracking.',
                'author': 'VisionAI Labs',
                'author_email': 'support@visionai.com',
                'category': 'analytics',
                'status': 'quarantined',
                'runtime_type': 'python',
                'entrypoint': 'lpr_main.py',
                'min_pentavision_version': '2.0.0',
                'install_path': '/opt/pentavision/plugins/license-plate-reader',
                'last_health_status': 'failed',
                'quarantine_reason': 'Security vulnerability detected',
                'capabilities': '["video_analysis", "object_detection", "license_plates"]',
                'scopes': '["read:cameras", "read:recordings", "write:metadata"]',
            },
            {
                'plugin_key': 'cloud-backup',
                'version': '1.1.2',
                'name': 'Cloud Backup Service',
                'description': 'Automatic backup of recordings to cloud storage providers.',
                'author': 'PentaVision',
                'author_email': 'plugins@pentavision.io',
                'category': 'storage',
                'status': 'inactive',
                'runtime_type': 'python',
                'entrypoint': 'backup_service.py',
                'min_pentavision_version': '2.0.0',
                'install_path': '/opt/pentavision/plugins/cloud-backup',
                'last_health_status': 'unknown',
                'capabilities': '["backup", "cloud_storage", "scheduling"]',
                'scopes': '["read:recordings", "write:storage"]',
            },
            {
                'plugin_key': 'facial-recognition',
                'version': '3.0.0',
                'name': 'Facial Recognition',
                'description': 'Advanced facial recognition with known persons database.',
                'author': 'SecureVision Inc',
                'author_email': 'dev@securevision.io',
                'category': 'analytics',
                'status': 'failed',
                'runtime_type': 'python',
                'entrypoint': 'face_recognition.py',
                'min_pentavision_version': '2.0.0',
                'install_path': '/opt/pentavision/plugins/facial-recognition',
                'last_health_status': 'failed',
                'capabilities': '["face_detection", "face_recognition", "person_tracking"]',
                'scopes': '["read:cameras", "read:faces", "write:faces"]',
            },
        ]

        created = 0
        for plugin_data in demo_plugins:
            existing = db.query(EnhancedPlugin).filter(
                EnhancedPlugin.plugin_key == plugin_data['plugin_key']
            ).first()

            if not existing:
                plugin = EnhancedPlugin(**plugin_data)
                db.add(plugin)
                created += 1

        db.commit()

        return jsonify({
            'success': True,
            'message': f'Created {created} demo plugins',
            'total_plugins': len(demo_plugins)
        })

    finally:
        db.close()


# ========================================================================
# API ENDPOINTS (for plugins to use)
# ========================================================================

@plugin_bp.route('/api/plugins/verify-key', methods=['POST'])
def api_verify_key():
    """Verify an API key and return property context."""
    api_key = request.headers.get('X-Plugin-API-Key')
    plugin_key = request.headers.get('X-Plugin-Key')
    
    if not api_key or not plugin_key:
        return jsonify({'error': 'Missing credentials'}), 401
    
    engine = get_record_engine()
    if not engine:
        abort(500, "Database not configured")
    db = Session(engine)
    
    try:
        manager = PluginManager(db)
        property_id = manager.verify_api_key(plugin_key, api_key)
        
        if not property_id:
            return jsonify({'error': 'Invalid API key'}), 401
        
        # Get property info
        prop = db.query(Property).filter(Property.id == property_id).first()
        
        if not prop:
            return jsonify({'error': 'Property not found'}), 404
        
        return jsonify({
            'valid': True,
            'property_id': property_id,
            'property_name': prop.name
        })
    
    finally:
        db.close()
