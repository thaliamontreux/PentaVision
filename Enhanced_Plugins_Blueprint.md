# PentaVision Enhanced Plugins System Blueprint

**Version:** 1.2.0 (Planned)  
**Last Updated:** December 30, 2025  
**Status:** Specification / Implementation Pending

---

## Executive Summary

The Enhanced Plugins System provides a secure, verifiable, and supervised framework for extending PentaVision functionality. This system enforces:

- **Install-time verification** - Hash validation, compatibility checks, dependency approval
- **Full end-to-end test gates** - Plugins must prove they work before activation
- **Automatic health supervision** - Continuous monitoring with auto-quarantine on failures
- **Zip-based package format** - Standardized distribution with manifests and integrity checks

---

## Two-Tier Control Panel Architecture

### System Administrator Control Panel

**Location:** `/admin/plugins`  
**Access:** System Admins, Root Admin, Staff  
**Purpose:** System-wide plugin management and property access control

**Features:**

1. **Plugin Installation & Management**
   - Upload new plugin packages (.zip)
   - View all installed plugins with status (Verified, Enabled, Quarantined)
   - Enable/Disable plugins system-wide
   - Run verification tests
   - View test results and logs
   - Uninstall plugins

2. **Property Access Control**
   - View which properties are using each plugin
   - Enable/Disable plugin access per property
   - Force-disable plugin for specific properties
   - View property-specific health status
   - Monitor property API key usage (last used timestamp)

3. **API Key Management (Admin Level)**
   - View list of properties with API keys for each plugin
   - **Rotate API key on behalf of property** (upon request)
   - API key shown **once** with copy button, then permanently masked as `*****`
   - View API key metadata (created date, last used date)
   - Revoke API keys (emergency)

4. **Plugin Configuration**
   - Configuration button for each plugin
   - Executes plugin's settings UI (from `ui/config.html`)
   - System-wide configuration overrides
   - View plugin definition and capabilities

5. **Monitoring & Health**
   - Real-time health status for all plugins
   - Quarantine management and reactivation
   - Event log viewer (all properties)
   - Performance metrics

### Property Manager Control Panel

**Location:** `/properties/{property_id}/plugins`  
**Access:** Property Managers (for their property only)  
**Purpose:** Property-specific plugin enablement and configuration

**Features:**

1. **Available Plugins View**
   - List of plugins **available to this property** (system admin approved)
   - Plugin status: Available, Enabled, Disabled (by admin), Quarantined
   - Plugin description and capabilities
   - Enable/Disable toggle (if allowed by system admin)

2. **Home Assistant Plugin Management**
   - **Enable/Disable** toggle for property
   - **API Key Management:**
     - Generate initial API key (shown once with copy button)
     - **Rotate API key** button
     - After rotation: new key shown **once** with copy button
     - Existing keys always displayed as `pk_prop123_***********************`
     - Copy button copies masked value (prevents accidental exposure)
     - Last used timestamp displayed
   - Configuration specific to property
   - Health status for this property

3. **Plugin Configuration (Property-Scoped)**
   - Property-specific settings override
   - Executes plugin's property configuration UI
   - Cannot modify system-wide settings

4. **Property-Specific Monitoring**
   - Health status for plugins on this property
   - Event log (property-scoped only)
   - Usage statistics

### API Key Security Model

**Critical Security Rules:**

1. **Show Once Policy**
   - API keys displayed in full **only once** upon creation/rotation
   - Modal with copy button: "Copy this key now. It will not be shown again."
   - After modal closes, key is permanently masked

2. **Masking Format**
   - Format: `pk_prop{property_id}_{random_32_chars}`
   - Displayed as: `pk_prop123_***********************`
   - First 10 chars visible for identification

3. **Rotation Flow**
   ```
   User clicks "Rotate API Key"
   ↓
   Confirmation modal: "This will invalidate your current key. Continue?"
   ↓
   New key generated
   ↓
   Old key revoked immediately
   ↓
   New key shown ONCE in modal with copy button
   ↓
   User must copy key before closing modal
   ↓
   Modal closes → key permanently masked
   ```

4. **Database Storage**
   - Full key stored hashed (bcrypt/argon2)
   - Only hash stored in `plugin_property_assignments.api_key_hash`
   - Prefix stored separately for display: `api_key_prefix`

5. **Admin Rotation on Behalf of Property**
   - System admin can rotate key for property
   - New key sent to property manager via secure channel
   - Audit log records admin action

---

## Complete Specification

This blueprint includes:

- Detailed plugin package format (`.zip` structure)
- Installation pipeline (5-step verification process)
- Testing standards (self-test, integration, security, load, recovery)
- Runtime supervision (crash loop detection, health monitoring, error storm detection)
- Database schema (5 new tables)
- API endpoints (15+ routes for management and plugin communication)
- **Two-tier UI architecture** (System Admin + Property Manager)
- Security model (RBAC, scopes, property isolation, API key security)
- Home Assistant plugin reference implementation

---

## Quick Reference

### Plugin Package Structure

```
<plugin_key>-<version>.zip
├── plugin.id                 # REQUIRED - Identity + integrity
├── definition.json           # REQUIRED - Capabilities + UI schema
├── tests/test_plan.json     # REQUIRED - Test coverage declaration
├── worker/plugin_worker.py  # REQUIRED - Main entrypoint
├── requirements.txt         # OPTIONAL - Python dependencies
├── ui/wizard.html          # OPTIONAL - Installation wizard
└── README.md               # REQUIRED - Documentation
```

### Installation States

```
UPLOADED → VALIDATING → DEPENDENCIES_PENDING → INSTALLING → 
TESTING → INSTALLED → VERIFIED → ENABLED
```

Any failure results in REJECTED or QUARANTINED status.

### Core Principles

1. **Trust But Verify** - Rigorous validation at every stage
2. **Fail Closed** - Any test failure prevents activation
3. **Property Isolation** - Multi-tenant security enforced
4. **Automatic Recovery** - Supervisor handles failures
5. **Explicit Approval** - Users approve dependencies and permissions

---

## Implementation Checklist

### Phase 1: Foundation (Week 1-2)
- [ ] Create database schema (5 tables)
- [ ] Implement plugin package loader
- [ ] Build preflight validation system
- [ ] Create hash verification engine
- [ ] Implement compatibility checker

### Phase 2: Installation Pipeline (Week 3-4)
- [ ] Build dependency approval modal
- [ ] Implement isolated venv installer
- [ ] Create plugin registration system
- [ ] Build test runner framework
- [ ] Implement test result evaluation

### Phase 3: Runtime Supervision (Week 5-6)
- [ ] Create plugin supervisor service
- [ ] Implement crash loop detector
- [ ] Build health check monitor
- [ ] Create error storm detector
- [ ] Implement quarantine system

### Phase 4: UI & Management (Week 7-8)
- [ ] Build System Admin control panel (`/admin/plugins`)
  - [ ] Plugin list with status indicators
  - [ ] Upload interface
  - [ ] Property access control view
  - [ ] Admin-level API key rotation
  - [ ] Plugin configuration interface
- [ ] Build Property Manager control panel (`/properties/{id}/plugins`)
  - [ ] Available plugins view
  - [ ] Enable/disable toggles
  - [ ] API key management with "show once" modal
  - [ ] Property-specific configuration
- [ ] Implement API key security
  - [ ] "Show once" modal with copy button
  - [ ] Permanent masking after display
  - [ ] Rotation flow with confirmation
- [ ] Build test result viewer
- [ ] Create log viewer (system-wide and property-scoped)

### Phase 5: Home Assistant Plugin (Week 9-10)
- [ ] Implement HA plugin worker
- [ ] Create dedicated HA port handler
- [ ] Build per-property API key system
- [ ] Implement camera enumeration
- [ ] Create stream token generator
- [ ] Write comprehensive test suite

---

## Database Tables Summary

1. **enhanced_plugins** - Core plugin registry
2. **plugin_property_assignments** - Property-level enablement with API keys
3. **plugin_health_checks** - Health check history
4. **plugin_events** - Lifecycle event log
5. **plugin_test_runs** - Test execution history

### Updated Schema for API Key Security

#### `plugin_property_assignments` (Enhanced)

```sql
CREATE TABLE plugin_property_assignments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    plugin_key VARCHAR(255) NOT NULL REFERENCES enhanced_plugins(plugin_key),
    property_id INTEGER NOT NULL REFERENCES properties(id),
    
    -- Status
    status VARCHAR(50) NOT NULL,  -- enabled, disabled, quarantined
    enabled_at DATETIME,
    enabled_by INTEGER REFERENCES users(id),
    disabled_at DATETIME,
    disabled_by INTEGER REFERENCES users(id),
    
    -- Admin Control
    admin_allowed BOOLEAN DEFAULT TRUE,  -- System admin can disable access
    admin_disabled_at DATETIME,
    admin_disabled_by INTEGER REFERENCES users(id),
    admin_disabled_reason TEXT,
    
    -- API Key (SECURE)
    api_key_hash VARCHAR(255),  -- bcrypt/argon2 hash of full key
    api_key_prefix VARCHAR(20),  -- First 10 chars for display (e.g., "pk_prop123_")
    api_key_created_at DATETIME,
    api_key_last_used DATETIME,
    api_key_rotated_count INTEGER DEFAULT 0,
    api_key_last_rotation DATETIME,
    
    -- Configuration (property-specific overrides)
    config JSON,
    
    -- Quarantine (property-specific)
    quarantine_reason VARCHAR(255),
    quarantine_details TEXT,
    quarantined_at DATETIME,
    
    -- Health (property-specific)
    last_health_check DATETIME,
    last_health_status VARCHAR(50),
    
    -- Metadata
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    UNIQUE(plugin_key, property_id)
);

CREATE INDEX idx_plugin_property_assignments_property ON plugin_property_assignments(property_id);
CREATE INDEX idx_plugin_property_assignments_status ON plugin_property_assignments(status);
CREATE INDEX idx_plugin_property_assignments_admin_allowed ON plugin_property_assignments(admin_allowed);
```

#### `plugin_api_key_rotations` (New Table)

Track API key rotation history:

```sql
CREATE TABLE plugin_api_key_rotations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    plugin_key VARCHAR(255) NOT NULL,
    property_id INTEGER NOT NULL,
    
    old_key_prefix VARCHAR(20),  -- For audit trail
    new_key_prefix VARCHAR(20),
    
    rotated_by INTEGER REFERENCES users(id),
    rotated_by_admin BOOLEAN DEFAULT FALSE,  -- True if admin rotated on behalf of property
    reason VARCHAR(255),  -- 'manual', 'security_incident', 'scheduled', 'admin_request'
    
    rotated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    INDEX idx_plugin_api_key_rotations_property (property_id),
    INDEX idx_plugin_api_key_rotations_rotated_at (rotated_at)
);
```

---

## Security Model

### Scopes

Plugins must declare required scopes:
- `cameras:read` / `cameras:write`
- `streams:read` / `streams:write`
- `properties:read`
- `recordings:read` / `recordings:write`
- `storage:read` / `storage:write`

### Property Isolation

All plugin operations are scoped to specific properties. Cross-property access is strictly forbidden and tested.

### Token-Based Authorization

Plugins receive supervisor-issued tokens that must be validated on every gateway request.

---

## Testing Requirements

Every plugin must pass:

1. **Self-Test** - Can start and communicate with gateway
2. **Integration Test** - Works with real PentaVision data
3. **Security Test** - Enforces property isolation and rejects invalid access
4. **Load Test** - Handles burst traffic (50 requests)
5. **Recovery Test** - Survives restart and maintains state

**Gate:** Plugin cannot be enabled until all required tests pass.

---

## Supervisor Policies

### Crash Loop
3 crashes in 2 minutes → Quarantine

### Health Failures
3 consecutive failed health checks → Restart  
9 consecutive failed health checks → Quarantine

### Error Storm
10 ERROR logs in 5 minutes → Quarantine

### Quarantine Actions
- Stop worker process
- Revoke tokens
- Alert Unified Live Feed
- Require full test suite to re-enable

---

## Home Assistant Plugin Specifics

### Dedicated Port
- Single port (default 8129) for HA-only API
- Per-property API key isolation

### Property Manager Experience

1. **Initial Setup**
   - Property manager navigates to `/properties/{id}/plugins`
   - Sees "Home Assistant Integration" in available plugins
   - Clicks "Enable" button
   - System runs property activation test
   - Upon success, API key generated and shown in modal:
     ```
     ┌─────────────────────────────────────────────────┐
     │  Home Assistant API Key Generated               │
     ├─────────────────────────────────────────────────┤
     │                                                  │
     │  Your API key has been generated:               │
     │                                                  │
     │  pk_prop123_a7f9d2e8c4b1x6y3z5w8q9r2t4u7v1n0m3 │
     │                                                  │
     │  [ Copy to Clipboard ]                          │
     │                                                  │
     │  ⚠ IMPORTANT: Copy this key now!                │
     │  It will not be shown again for security.       │
     │                                                  │
     │  [ I've Copied the Key ]                        │
     └─────────────────────────────────────────────────┘
     ```
   - After closing modal, key displayed as: `pk_prop123_***********************`

2. **Ongoing Management**
   - View plugin status: Enabled, Healthy
   - See API key (masked): `pk_prop123_***********************`
   - Last used: "2 hours ago"
   - **Rotate Key** button available

3. **Key Rotation**
   - Click "Rotate API Key"
   - Confirmation modal:
     ```
     ┌─────────────────────────────────────────────────┐
     │  Rotate API Key?                                │
     ├─────────────────────────────────────────────────┤
     │                                                  │
     │  This will immediately invalidate your current  │
     │  Home Assistant API key.                        │
     │                                                  │
     │  You will need to update your Home Assistant    │
     │  configuration with the new key.                │
     │                                                  │
     │  [ Rotate Key ]  [ Cancel ]                     │
     └─────────────────────────────────────────────────┘
     ```
   - New key shown once (same modal as initial setup)
   - Old key immediately revoked

### System Admin Experience

1. **Plugin Overview**
   - Navigate to `/admin/plugins`
   - See "Home Assistant Integration" with:
     - Status: Enabled (System-wide)
     - Properties using: 5 active
     - Health: All healthy

2. **Property Access Control**
   - Click "View Properties" on HA plugin
   - See table:
     ```
     Property Name    | Status  | API Key Last Used | Actions
     ─────────────────┼─────────┼──────────────────┼─────────────────
     Property A       | Enabled | 2 hours ago      | [Disable] [Rotate Key]
     Property B       | Enabled | 5 minutes ago    | [Disable] [Rotate Key]
     Property C       | Disabled| Never            | [Enable]
     ```

3. **Admin Key Rotation (On Request)**
   - Property manager contacts admin: "Lost API key, need rotation"
   - Admin clicks "Rotate Key" for that property
   - New key generated and shown to admin
   - Admin securely sends key to property manager
   - Audit log records: "API key rotated by admin on behalf of property"

### Required Tests
- Camera enumeration (property-scoped)
- Property isolation (cross-property rejection)
- Invalid API key rejection (including revoked keys)
- Rate limiting enforcement
- Stream token generation
- Worker restart recovery
- API key rotation (old key immediately invalid)

---

## Next Steps

1. Review and approve this specification
2. Create detailed implementation tasks
3. Begin Phase 1 development
4. Implement Home Assistant plugin as reference

---

**Document Status:** Draft Specification  
**Approval Required:** Root Admin / System Architect  
**Target Version:** PentaVision 1.2.0
