# PentaVision Project Blueprint

**Version:** 1.1.0  
**Last Updated:** December 30, 2025  
**Purpose:** Comprehensive architectural documentation for AI assistants and developers

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Technology Stack](#technology-stack)
3. [Architecture](#architecture)
4. [Directory Structure](#directory-structure)
5. [Core Components](#core-components)
6. [Database Schema](#database-schema)
7. [Frontend Architecture](#frontend-architecture)
8. [Backend Architecture](#backend-architecture)
9. [Security & Authentication](#security--authentication)
10. [Storage System](#storage-system)
11. [Recording System](#recording-system)
12. [Development Guidelines](#development-guidelines)
13. [Deployment](#deployment)

---

## Project Overview

**PentaVision** is an enterprise-grade IP camera management and recording system built with Flask. It provides:

- Multi-camera live streaming and recording
- Flexible storage orchestration with multiple provider support
- Role-based access control (RBAC)
- Real-time health monitoring
- Camera grouping and tagging
- Advanced recording schedules
- Storage failover and redundancy

### Key Features

- **Camera Management:** Add, configure, monitor, and organize IP cameras
- **Live Streaming:** Real-time RTSP/HTTP stream viewing with HLS conversion
- **Recording:** Scheduled and continuous recording with segment management
- **Storage Modules:** Pluggable storage providers (GCS, S3, Azure, Dropbox, Local, FTP, etc.)
- **Health Monitoring:** Real-time camera and storage health dashboards
- **User Management:** Multi-user support with granular permissions
- **Audit Logging:** Comprehensive event tracking for security and compliance

---

## Technology Stack

### Backend
- **Framework:** Flask 3.x (Python web framework)
- **Database:** SQLAlchemy ORM with SQLite/PostgreSQL support
- **Video Processing:** FFmpeg for stream conversion and recording
- **Authentication:** Flask-Login with bcrypt password hashing
- **Task Queue:** Background workers for recording and uploads

### Frontend
- **Template Engine:** Jinja2
- **CSS:** Custom CSS with dark theme and glassmorphism design
- **JavaScript:** Vanilla JS with fetch API for AJAX
- **Icons:** Lucide icons (via CDN or local)
- **Video Player:** HLS.js for adaptive streaming

### Infrastructure
- **Deployment:** Ubuntu 24.04 with systemd services (no Docker)
- **Web Server:** Gunicorn with Nginx reverse proxy
- **Process Management:** systemd units for all services
- **Temporary Storage:** /dev/shm (tmpfs) for stream processing

### Storage Providers
- **Cloud Object Storage:** GCS, S3, Azure Blob, Swift
- **File Sync Services:** Dropbox, OneDrive, Box, pCloud, MEGA
- **Network Protocols:** WebDAV, FTP, FTPS, SFTP, SCP
- **Local Storage:** Filesystem paths, mounted drives

---

## Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Web Browser                          │
│              (User Interface - Dark Theme)                  │
└────────────────────┬────────────────────────────────────────┘
                     │ HTTPS
                     ▼
┌─────────────────────────────────────────────────────────────┐
│                      Nginx (Reverse Proxy)                  │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│                   Flask Application                         │
│  ┌──────────────┬──────────────┬──────────────────────┐    │
│  │   Routes     │   Models     │   Business Logic     │    │
│  │  (Blueprints)│  (SQLAlchemy)│   (Services)         │    │
│  └──────────────┴──────────────┴──────────────────────┘    │
└────────┬───────────────┬────────────────┬───────────────────┘
         │               │                │
         ▼               ▼                ▼
┌────────────────┐ ┌──────────────┐ ┌──────────────────┐
│   Database     │ │   FFmpeg     │ │  Storage Modules │
│  (SQLAlchemy)  │ │  (Streaming) │ │   (Providers)    │
└────────────────┘ └──────────────┘ └──────────────────┘
```

### Service Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    systemd Services                         │
├─────────────────────────────────────────────────────────────┤
│  pentavision-web.service      - Flask web application      │
│  pentavision-recorder.service - Recording worker           │
│  pentavision-shell.service    - TCP shell (port 2000)      │
└─────────────────────────────────────────────────────────────┘
```

---

## Directory Structure

```
windsurf-project/
├── app/                          # Main application package
│   ├── __init__.py              # Flask app factory
│   ├── models.py                # SQLAlchemy models
│   ├── security.py              # Authentication & RBAC
│   ├── camera_admin.py          # Camera management routes
│   ├── recording_service.py     # Recording worker logic
│   ├── storage_settings_page.py # Storage module routes
│   ├── storage_providers.py     # Storage provider implementations
│   ├── views.py                 # Main application routes
│   ├── static/                  # Static assets
│   │   ├── css/
│   │   │   └── main.css        # Main stylesheet (~5300 lines)
│   │   ├── js/
│   │   └── images/
│   ├── templates/               # Jinja2 templates
│   │   ├── base.html           # Base template with navigation
│   │   ├── admin/              # Admin panel templates
│   │   ├── cameras/            # Camera management templates
│   │   ├── recordings/         # Recording views
│   │   ├── storage_modules.html # Storage orchestration dashboard
│   │   └── modules/            # Provider-specific templates
│   │       └── storage/        # Storage provider wizards
│   └── modules/                 # Pluggable modules
│       └── storage/            # Storage provider modules
│           ├── gcs/
│           ├── local_fs/
│           ├── dropbox/
│           └── [15+ providers]
├── scripts/                     # Utility scripts
│   ├── git_autopush.ps1        # Auto-commit script
│   └── pentavision_tcp_shell.py # TCP shell service
├── deploy/                      # Deployment files
│   ├── pentavision-web.service
│   ├── pentavision-recorder.service
│   ├── pentavision-shell.service
│   ├── install_ubuntu_24.sh
│   └── install_pentavision_services.sh
├── docs/                        # Documentation
│   └── ui-references/          # UI design references
├── config.py                    # Configuration management
├── run.py                       # Development server entry point
├── requirements.txt             # Python dependencies
├── TODO.md                      # Project roadmap
├── RELEASE_NOTES_v1.1.md       # Release documentation
├── VERSION                      # Current version number
└── Project_Blueprint.md         # This file
```

---

## Core Components

### 1. Flask Application (`app/__init__.py`)

**Purpose:** Application factory pattern for Flask initialization

**Key Functions:**
- `create_app()` - Creates and configures Flask application
- Registers blueprints (routes)
- Initializes database
- Sets up security context
- Configures Jinja2 filters

**Configuration:**
- Loads from environment variables
- Database connection strings
- Secret keys and CSRF tokens
- Upload paths and temp directories

### 2. Database Models (`app/models.py`)

**Purpose:** SQLAlchemy ORM models for all database tables

**Key Models:**
- `User` - User accounts with password hashing
- `Role` - User roles for RBAC
- `Permission` - Granular permissions
- `CameraDevice` - IP camera configurations
- `CameraPattern` - URL patterns for camera streams
- `CameraGroup` - Camera grouping
- `CameraTag` - Camera tagging
- `CameraStoragePolicy` - Recording schedules and storage targets
- `CameraRecording` - Recording metadata
- `StorageModule` - Storage provider instances
- `StorageModuleHealthCheck` - Health monitoring
- `StorageModuleWriteStat` - Write statistics
- `UploadQueueItem` - Upload queue for async transfers
- `AuditLog` - Security audit trail

### 3. Security System (`app/security.py`)

**Purpose:** Authentication, authorization, and RBAC

**Key Functions:**
- `init_security(app)` - Initialize security subsystem
- `get_current_user()` - Get authenticated user
- `user_has_permission(user, permission)` - Check permissions
- `user_has_role(user, role)` - Check role membership
- `require_permission(permission)` - Route decorator
- `hash_password(password)` - Bcrypt hashing
- `verify_password(password, hash)` - Password verification

**Permission System:**
- Format: `"Category.Subcategory.Action"`
- Examples: `"Nav.Feeds.Cameras.View"`, `"Admin.Users.Edit"`
- Hierarchical permission checking
- Role-based permission inheritance

### 4. Camera Management (`app/camera_admin.py`)

**Purpose:** Camera device management and monitoring

**Key Routes:**
- `/admin/cameras/devices` - Camera list with bulk operations
- `/admin/cameras/devices/<id>/edit` - Camera configuration
- `/admin/cameras/health` - Health monitoring dashboard
- `/admin/cameras/groups` - Group management
- `/admin/cameras/tags` - Tag management
- `/admin/cameras/bulk-update` - Bulk enable/disable
- `/admin/cameras/bulk-assign-group` - Bulk group assignment
- `/admin/cameras/bulk-assign-tags` - Bulk tag assignment

**Features:**
- Camera CRUD operations
- Health status detection (active streams + recent recordings)
- Bulk operations with modal dialogs
- Group and tag management
- Pattern-based URL generation

### 5. Recording Service (`app/recording_service.py`)

**Purpose:** Background recording worker

**Key Classes:**
- `RecordingManager` - Manages all camera workers
- `CameraWorker` - Per-camera recording thread
- `StreamSegmentWriter` - Writes HLS segments to /dev/shm
- `StorageUploader` - Uploads segments to storage providers

**Recording Flow:**
1. Check camera schedule and storage policy
2. Start FFmpeg process for stream capture
3. Write segments to /dev/shm (tmpfs)
4. Queue segments for upload to storage providers
5. Upload to configured storage modules (priority order)
6. Clean up temporary files
7. Create database records for recordings

### 6. Storage System (`app/storage_settings_page.py`, `app/storage_providers.py`)

**Purpose:** Pluggable storage orchestration

**Key Routes:**
- `/admin/storage` - Storage modules dashboard
- `/admin/storage?module=<id>` - Module details
- Module actions: test, enable, disable, clone, delete

**Storage Module Structure:**
```
app/modules/storage/<provider>/
├── definition.json      # Provider metadata
├── wizard.html         # Configuration form
├── config.html         # Edit form
└── module.py          # Provider implementation (optional)
```

**Provider Implementation:**
- Base class: `StorageProvider`
- Methods: `test_connection()`, `upload_file()`, `list_files()`, etc.
- Automatic failover on errors
- Priority-based routing
- Health monitoring

---

## Database Schema

### Core Tables

#### users
- `id` (PK)
- `username` (unique)
- `email`
- `password_hash`
- `timezone` (IANA timezone)
- `is_active`
- `created_at`

#### roles
- `id` (PK)
- `name` (unique)
- `description`

#### permissions
- `id` (PK)
- `name` (unique, format: "Category.Subcategory.Action")
- `description`

#### camera_devices
- `id` (PK)
- `name`
- `ip_address`
- `port`
- `username`
- `password_encrypted`
- `pattern_id` (FK to camera_patterns)
- `is_active`
- `created_at`

#### camera_storage_policies
- `id` (PK)
- `device_id` (FK to camera_devices)
- `storage_targets` (JSON array of module names)
- `schedule_type` (continuous/scheduled)
- `schedule_config` (JSON)
- `retention_days`

#### camera_recordings
- `id` (PK)
- `device_id` (FK to camera_devices)
- `storage_provider` (module name)
- `storage_key` (path/object key)
- `file_size`
- `duration`
- `created_at`

#### storage_modules
- `id` (PK)
- `name` (unique)
- `label`
- `provider_type` (gcs, s3, local_fs, etc.)
- `credentials` (JSON, encrypted)
- `config` (JSON)
- `is_enabled`
- `priority` (lower = higher priority)
- `status` (ok/error)
- `created_at`

#### storage_module_health_checks
- `id` (PK)
- `module_id` (FK to storage_modules)
- `status` (ok/error)
- `message`
- `response_time_ms`
- `checked_at`

#### storage_module_write_stats
- `id` (PK)
- `module_id` (FK to storage_modules)
- `bytes_written`
- `write_count`
- `error_count`
- `window_start`
- `window_end`

#### upload_queue_items
- `id` (PK)
- `recording_id` (FK to camera_recordings)
- `module_id` (FK to storage_modules)
- `local_path`
- `target_key`
- `status` (pending/uploading/completed/failed)
- `attempts`
- `last_error`
- `created_at`

---

## Frontend Architecture

### Design System

**Theme:** Dark mode with electric blue accents

**Colors:**
- Background: `#020617` (slate-950)
- Surface: `rgba(2, 6, 23, 0.55)` (dark with transparency)
- Primary: `#38bdf8` (sky-400)
- Success: `#86efac` (green-300)
- Warning: `#fde047` (yellow-300)
- Error: `#fca5a5` (red-300)
- Text: `#e5e7eb` (gray-200)
- Muted: `#94a3b8` (slate-400)

**Typography:**
- Font: System font stack (SF Pro, Segoe UI, Roboto)
- Headings: 600-750 weight
- Body: 400-500 weight
- Code: Monospace font

**Components:**
- Cards with glassmorphism effect
- Gradient borders and shadows
- Smooth transitions and animations
- Progress bars with gradients
- Modal dialogs with backdrop blur
- Toast notifications (bottom-right, green background)

### CSS Architecture (`app/static/css/main.css`)

**Structure:**
```css
/* 1. CSS Reset & Base Styles */
/* 2. Layout Components (grid, flex) */
/* 3. Navigation & Sidebar */
/* 4. Forms & Inputs */
/* 5. Buttons & Actions */
/* 6. Cards & Panels */
/* 7. Tables */
/* 8. Modals & Dialogs */
/* 9. Health Indicators */
/* 10. Storage Modules UI */
/* 11. Camera Management UI */
/* 12. Utility Classes */
```

**Key Classes:**
- `.pv-admin-layout` - Admin panel split layout
- `.pv-card` - Card component with glassmorphism
- `.pv-button` - Button styles with variants
- `.pv-table` - Table styling
- `.pv-modal` - Modal dialog
- `.pv-health-stat` - Health metric card
- `.pv-storage-provider` - Storage provider list item
- `.pv-storage-metric-card` - Metric card with progress bar

### JavaScript Patterns

**Approach:** Vanilla JavaScript with modern ES6+ features

**Common Patterns:**
```javascript
// Fetch API for AJAX
fetch('/api/endpoint', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-CSRFToken': csrfToken
  },
  body: JSON.stringify(data)
})
.then(response => response.json())
.then(data => {
  // Handle success
  showToast('Success!');
})
.catch(error => {
  // Handle error
  showToast('Error: ' + error.message);
});

// Toast notifications
function showToast(message, isSuccess = true) {
  const toast = document.getElementById('pv-global-toast');
  toast.textContent = message;
  toast.style.display = 'block';
  setTimeout(() => toast.style.display = 'none', 10000);
}

// Modal dialogs
function openModal(modalId) {
  document.getElementById(modalId).classList.add('is-visible');
}

function closeModal(modalId) {
  document.getElementById(modalId).classList.remove('is-visible');
}
```

### Template Structure

**Base Template (`base.html`):**
- HTML5 doctype
- Meta tags (viewport, charset)
- CSS includes
- Navigation header
- Main content block
- Toast notification container
- JavaScript includes

**Template Inheritance:**
```jinja2
{% extends 'base.html' %}

{% block title %}Page Title · PentaVision{% endblock %}

{% block content %}
  <!-- Page content -->
{% endblock %}
```

**Common Jinja2 Filters:**
- `|local_dt` - Format datetime in user's timezone
- `|filesizeformat` - Format bytes as human-readable
- `|urlencode` - URL encoding
- `|safe` - Mark HTML as safe

---

## Backend Architecture

### Flask Application Structure

**Blueprint Organization:**
```python
# Main application routes
app.register_blueprint(views.bp)

# Camera management
app.register_blueprint(camera_admin.bp, url_prefix='/admin/cameras')

# Storage management
app.register_blueprint(storage_settings.bp, url_prefix='/admin/storage')

# User management
app.register_blueprint(user_admin.bp, url_prefix='/admin/users')
```

### Route Patterns

**Standard Route:**
```python
@bp.route('/path')
@require_permission('Category.Subcategory.Action')
def route_handler():
    user = get_current_user()
    if user is None:
        abort(403)
    
    # Route logic
    return render_template('template.html', data=data)
```

**POST Route with CSRF:**
```python
@bp.post('/path')
@require_permission('Category.Subcategory.Action')
def post_handler():
    user = get_current_user()
    if user is None:
        abort(403)
    
    if not _validate_csrf_token(request.form.get('csrf_token')):
        abort(400)
    
    # Process form data
    log_event('EVENT_TYPE', user_id=user.id, details='...')
    return redirect(url_for('route_name'))
```

**JSON API Route:**
```python
@bp.post('/api/endpoint')
def api_handler():
    user = get_current_user()
    if user is None:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    try:
        data = request.get_json()
        # Process data
        return jsonify({'success': True, 'data': result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
```

### Database Patterns

**Query Pattern:**
```python
from sqlalchemy.orm import Session
from app.models import CameraDevice

engine = get_record_engine()
with Session(engine) as db:
    devices = db.query(CameraDevice).filter(
        CameraDevice.is_active == 1
    ).order_by(CameraDevice.name).all()
    
    # Use devices
    for device in devices:
        print(device.name)
    
    # Commit changes if needed
    db.commit()
```

**Create/Update Pattern:**
```python
with Session(engine) as db:
    # Create
    device = CameraDevice(
        name='Camera 1',
        ip_address='192.168.1.100',
        is_active=1
    )
    db.add(device)
    db.commit()
    
    # Update
    device = db.query(CameraDevice).filter(
        CameraDevice.id == device_id
    ).first()
    if device:
        device.name = 'Updated Name'
        db.commit()
```

### Error Handling

**Standard Pattern:**
```python
try:
    # Operation
    result = perform_operation()
except SpecificException as e:
    log_error('OPERATION_FAILED', str(e))
    flash('Operation failed: ' + str(e), 'error')
    return redirect(url_for('fallback_route'))
except Exception as e:
    log_error('UNEXPECTED_ERROR', str(e))
    abort(500)
```

---

## Security & Authentication

### Authentication Flow

1. User submits login form
2. `verify_password()` checks bcrypt hash
3. Flask-Login creates session
4. Session cookie stored in browser
5. Subsequent requests include session cookie
6. `get_current_user()` retrieves user from session

### Permission System

**Permission Format:** `"Category.Subcategory.Action"`

**Examples:**
- `"Nav.Feeds.Cameras.View"` - View cameras page
- `"Admin.Users.Edit"` - Edit users
- `"Admin.Storage.Configure"` - Configure storage

**Checking Permissions:**
```python
# In route
@require_permission('Nav.Feeds.Cameras.View')
def camera_list():
    # Route logic
    pass

# In code
if user_has_permission(user, 'Admin.Users.Edit'):
    # Allow action
    pass
```

### CSRF Protection

**Token Generation:**
```python
global_csrf_token = generate_csrf_token()
```

**Template Usage:**
```html
<form method="post">
  <input type="hidden" name="csrf_token" value="{{ global_csrf_token }}" />
  <!-- Form fields -->
</form>
```

**Validation:**
```python
if not _validate_csrf_token(request.form.get('csrf_token')):
    abort(400)
```

### Audit Logging

**Log Event:**
```python
log_event(
    event_type='CAMERA_CREATE',
    user_id=user.id,
    details='name=Camera1, ip=192.168.1.100'
)
```

**Event Types:**
- `USER_LOGIN`, `USER_LOGOUT`
- `CAMERA_CREATE`, `CAMERA_UPDATE`, `CAMERA_DELETE`
- `STORAGE_MODULE_CREATE`, `STORAGE_MODULE_TEST`
- `CAMERA_BULK_UPDATE`, `CAMERA_BULK_GROUP_ASSIGN`

---

## Storage System

### Storage Module Architecture

**Provider Interface:**
```python
class StorageProvider:
    def __init__(self, config: dict):
        self.config = config
    
    def test_connection(self) -> tuple[bool, str]:
        """Test connectivity and credentials"""
        pass
    
    def upload_file(self, local_path: str, remote_key: str) -> bool:
        """Upload file to storage"""
        pass
    
    def list_files(self, prefix: str = '') -> list:
        """List files in storage"""
        pass
    
    def delete_file(self, remote_key: str) -> bool:
        """Delete file from storage"""
        pass
```

### Storage Module Lifecycle

1. **Creation:**
   - User selects provider type
   - Fills configuration form
   - Tests connection
   - Saves module (disabled by default)

2. **Testing:**
   - Validates credentials
   - Writes test file
   - Reads test file
   - Deletes test file
   - Records result in health check

3. **Activation:**
   - User enables module
   - Module added to priority queue
   - Recording service picks up module

4. **Operation:**
   - Receives upload requests
   - Uploads files to provider
   - Records statistics
   - Updates health status

5. **Failover:**
   - On upload failure, try next priority module
   - Log error event
   - Update health status
   - Retry with exponential backoff

### Provider-Specific Notes

**Google Cloud Storage (GCS):**
- Requires service account JSON key
- Bucket must exist
- IAM permissions: `storage.objects.create`, `storage.objects.delete`

**Amazon S3:**
- Requires access key and secret key
- Bucket must exist
- IAM permissions: `s3:PutObject`, `s3:DeleteObject`

**Local Filesystem:**
- Path must be writable
- Supports absolute paths
- Automatic directory creation

**FTP/SFTP:**
- Requires host, port, username, password
- Supports passive mode (FTP)
- SSH key authentication (SFTP)

---

## Recording System

### Recording Flow

```
Camera → FFmpeg → HLS Segments → /dev/shm → Upload Queue → Storage Modules
```

### Recording Worker

**Service:** `pentavision-recorder.service`

**Process:**
1. Load camera devices with storage policies
2. Check schedule (continuous or time-based)
3. Start FFmpeg for each active camera
4. Monitor FFmpeg process
5. Detect new HLS segments in /dev/shm
6. Queue segments for upload
7. Upload to storage modules (priority order)
8. Create recording database entries
9. Clean up /dev/shm files

### FFmpeg Command

```bash
ffmpeg -rtsp_transport tcp \
  -i rtsp://username:password@ip:port/stream \
  -c:v copy -c:a copy \
  -f hls \
  -hls_time 10 \
  -hls_list_size 6 \
  -hls_flags delete_segments \
  /dev/shm/camera_{id}/stream.m3u8
```

### Upload Queue

**Purpose:** Asynchronous upload with retry logic

**States:**
- `pending` - Waiting for upload
- `uploading` - Currently uploading
- `completed` - Successfully uploaded
- `failed` - Upload failed (after retries)

**Retry Logic:**
- Max attempts: 3
- Exponential backoff: 1s, 2s, 4s
- On failure, try next priority module

---

## Development Guidelines

### Code Style

**Python:**
- PEP 8 compliance
- Type hints where appropriate
- Docstrings for functions and classes
- Max line length: 120 characters

**HTML/Jinja2:**
- 2-space indentation
- Semantic HTML5 elements
- Accessibility attributes (ARIA)

**CSS:**
- BEM-like naming: `.pv-component-element--modifier`
- Mobile-first responsive design
- CSS custom properties for theming

**JavaScript:**
- ES6+ features
- Const/let (no var)
- Arrow functions
- Template literals

### Naming Conventions

**Python:**
- Functions: `snake_case`
- Classes: `PascalCase`
- Constants: `UPPER_SNAKE_CASE`
- Private: `_leading_underscore`

**Database:**
- Tables: `snake_case` (plural)
- Columns: `snake_case`
- Foreign keys: `table_id`

**CSS:**
- Classes: `.pv-component-name`
- IDs: `#pv-unique-id`
- Variables: `--pv-color-name`

**Templates:**
- Files: `snake_case.html`
- Partials: `_partial_name.html`

### Adding New Features

**1. Database Model:**
```python
# app/models.py
class NewModel(Base):
    __tablename__ = 'new_models'
    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
```

**2. Route:**
```python
# app/new_feature.py
from flask import Blueprint

bp = Blueprint('new_feature', __name__)

@bp.route('/new-feature')
@require_permission('Feature.View')
def index():
    return render_template('new_feature/index.html')
```

**3. Template:**
```html
<!-- app/templates/new_feature/index.html -->
{% extends 'base.html' %}

{% block title %}New Feature · PentaVision{% endblock %}

{% block content %}
  <section class="pv-admin-layout">
    <!-- Content -->
  </section>
{% endblock %}
```

**4. CSS:**
```css
/* app/static/css/main.css */
.pv-new-feature {
  /* Styles */
}
```

**5. Register Blueprint:**
```python
# app/__init__.py
from app import new_feature
app.register_blueprint(new_feature.bp, url_prefix='/new-feature')
```

### Testing Checklist

- [ ] Route requires authentication
- [ ] Permission checks enforced
- [ ] CSRF token validated on POST
- [ ] Database transactions committed
- [ ] Errors handled gracefully
- [ ] Audit events logged
- [ ] UI responsive on mobile
- [ ] Accessibility (keyboard, screen reader)
- [ ] Cross-browser compatibility

---

## Deployment

### System Requirements

- **OS:** Ubuntu 24.04 LTS
- **Python:** 3.10+
- **FFmpeg:** 4.4+
- **Nginx:** 1.18+
- **RAM:** 4GB minimum (8GB recommended)
- **Storage:** 50GB+ for recordings

### Installation Steps

1. **Clone Repository:**
```bash
git clone https://github.com/thaliamontreux/PentaVision.git
cd PentaVision
```

2. **Install Dependencies:**
```bash
sudo apt update
sudo apt install python3-pip python3-venv ffmpeg nginx
```

3. **Create Virtual Environment:**
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

4. **Configure Environment:**
```bash
cp .env.example .env
# Edit .env with your settings
```

5. **Initialize Database:**
```bash
python run.py
# Database tables auto-created on first run
```

6. **Install systemd Services:**
```bash
sudo bash deploy/install_pentavision_services.sh
```

7. **Configure Nginx:**
```bash
sudo cp deploy/nginx.conf /etc/nginx/sites-available/pentavision
sudo ln -s /etc/nginx/sites-available/pentavision /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

8. **Start Services:**
```bash
sudo systemctl start pentavision-web
sudo systemctl start pentavision-recorder
sudo systemctl enable pentavision-web
sudo systemctl enable pentavision-recorder
```

### Service Management

**View Logs:**
```bash
sudo journalctl -u pentavision-web -f
sudo journalctl -u pentavision-recorder -f
```

**Restart Services:**
```bash
sudo systemctl restart pentavision-web
sudo systemctl restart pentavision-recorder
```

**Check Status:**
```bash
sudo systemctl status pentavision-web
sudo systemctl status pentavision-recorder
```

### Configuration Files

**Environment Variables (`.env`):**
```bash
FLASK_SECRET_KEY=your-secret-key-here
DATABASE_URL=sqlite:///pentavision.db
UPLOAD_FOLDER=/var/lib/pentavision/uploads
TEMP_FOLDER=/dev/shm/pentavision
```

**systemd Service (`pentavision-web.service`):**
```ini
[Unit]
Description=PentaVision Web Application
After=network.target

[Service]
Type=simple
User=pentavision
WorkingDirectory=/opt/pentavision
Environment="PATH=/opt/pentavision/venv/bin"
ExecStart=/opt/pentavision/venv/bin/gunicorn -w 4 -b 127.0.0.1:5000 run:app
Restart=always

[Install]
WantedBy=multi-user.target
```

### Backup & Restore

**Backup Database:**
```bash
sqlite3 pentavision.db ".backup pentavision_backup.db"
```

**Backup Configuration:**
```bash
tar -czf pentavision_config.tar.gz .env config.py
```

**Restore:**
```bash
cp pentavision_backup.db pentavision.db
tar -xzf pentavision_config.tar.gz
sudo systemctl restart pentavision-web
```

---

## Version History

### v1.1.0 (December 29, 2025)
- Storage Modules Manager complete transformation
- Enhanced provider list with health badges and stream counts
- Provider-specific icon colors (15+ providers)
- Bulk camera operations (group/tag assignment)
- Enhanced camera health dashboard with metrics
- Fixed camera health detection logic
- 500+ lines of new code, 240+ lines of CSS

### v1.0.0 (Initial Release)
- Core camera management
- Basic recording functionality
- Storage module system
- User authentication and RBAC
- Admin dashboard

---

## Future Roadmap

### Planned Features
- [ ] Camera export/import functionality
- [ ] Advanced camera search with filters
- [ ] Storage provider wizard improvements
- [ ] Additional provider integrations
- [ ] Link checker for site testing
- [ ] Enhanced analytics and reporting
- [ ] Mobile app (iOS/Android)
- [ ] Cloud deployment options

### Under Consideration
- [ ] Multi-site management
- [ ] Edge computing support
- [ ] AI-powered motion detection
- [ ] Object recognition
- [ ] Facial recognition (with privacy controls)
- [ ] Integration with home automation systems

---

## Support & Maintenance

### Updating This Document

This document should be updated whenever:
- New features are added
- Architecture changes
- New dependencies added
- Deployment process changes
- Breaking changes introduced

**Update Command:**
```bash
# After making changes
git add Project_Blueprint.md
git commit -m "docs: Update Project Blueprint with [feature/change]"
git push origin main
```

### Contact

- **Project Owner:** Thalia Montreux
- **Repository:** https://github.com/thaliamontreux/PentaVision
- **License:** Proprietary

---

**Last Updated:** December 30, 2025  
**Document Version:** 1.1.0  
**Maintained By:** AI Assistant (Cascade)
