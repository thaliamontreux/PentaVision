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

## Complete Specification

For the complete Enhanced Plugins Blueprint including:

- Detailed plugin package format (`.zip` structure)
- Installation pipeline (5-step verification process)
- Testing standards (self-test, integration, security, load, recovery)
- Runtime supervision (crash loop detection, health monitoring, error storm detection)
- Database schema (5 new tables)
- API endpoints (15+ routes for management and plugin communication)
- UI components (control panels, modals, status dashboards)
- Security model (RBAC, scopes, property isolation)
- Home Assistant plugin reference implementation

Please see the full specification document that will be created in the next phase of development.

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
- [ ] Build plugin control panel
- [ ] Create upload interface
- [ ] Implement property plugin view
- [ ] Build test result viewer
- [ ] Create log viewer

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
2. **plugin_property_assignments** - Property-level enablement
3. **plugin_health_checks** - Health check history
4. **plugin_events** - Lifecycle event log
5. **plugin_test_runs** - Test execution history

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

### Required Tests
- Camera enumeration (property-scoped)
- Property isolation (cross-property rejection)
- Invalid API key rejection
- Rate limiting enforcement
- Stream token generation
- Worker restart recovery

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
