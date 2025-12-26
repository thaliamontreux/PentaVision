-- PentaVision RBAC seed for main-system staff roles (idempotent)

USE pe_users;

-- Ensure RBAC extension columns exist (safe to re-run)
ALTER TABLE permissions
  ADD COLUMN IF NOT EXISTS risk_level VARCHAR(16) NULL,
  ADD COLUMN IF NOT EXISTS requires_mfa INT NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS requires_approval INT NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS break_glass_only INT NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS always_audit INT NOT NULL DEFAULT 1;

ALTER TABLE role_permissions
  ADD COLUMN IF NOT EXISTS effect VARCHAR(8) NOT NULL DEFAULT 'allow';

CREATE UNIQUE INDEX IF NOT EXISTS ux_role_permissions_role_permission
  ON role_permissions (role_id, permission_id);

/* Roles (main system staff) */
INSERT IGNORE INTO roles (name, scope, description) VALUES
  ('Viewer', 'global', 'Legacy viewer role (backwards compatible).'),
  ('Technician', 'global', 'Legacy technician role (backwards compatible).'),
  (
    'Property Administrator',
    'global',
    'Legacy property administrator role (backwards compatible).'
  ),
  ('Executive Viewer', 'global', 'Read-only executive reporting access.'),
  ('Compliance Officer', 'global', 'Audit and compliance review access.'),
  (
    'Risk & Security Governance Manager',
    'global',
    'Security policy and governance controls.'
  ),
  ('SOC Operator - Tier 1', 'global', 'SOC operations Tier 1.'),
  ('SOC Operator - Tier 2', 'global', 'SOC operations Tier 2.'),
  (
    'SOC Supervisor / Shift Lead',
    'global',
    'SOC supervisory role and export approver.'
  ),
  ('SOC Operations Manager', 'global', 'SOC operations management.'),
  (
    'Investigator / Evidence Specialist',
    'global',
    'Evidence creation and investigations.'
  ),
  ('Incident Response Lead', 'global', 'Incident response lead.'),
  ('Dispatcher', 'global', 'Dispatch operator.'),
  ('Communications Supervisor', 'global', 'Dispatch supervisor.'),
  (
    'Technical Support Agent',
    'global',
    'Support role with restricted impersonation.'
  ),
  ('Field Technician', 'global', 'Field tech device operations.'),
  ('Device Administrator', 'global', 'Device and storage administration.'),
  (
    'Customer Success Manager',
    'global',
    'Customer success reporting and summaries.'
  ),
  (
    'Account Administrator (Internal)',
    'global',
    'Internal customer/property administration.'
  ),
  ('Platform Engineer', 'global', 'Platform engineering / infra role.'),
  ('Integration Engineer', 'global', 'Integration engineering role.'),
  ('Automation Engineer', 'global', 'Automation/playbook engineering role.'),
  ('IAM Administrator', 'global', 'Identity and access management admin.'),
  ('Security Administrator', 'global', 'Security administrator.'),
  ('Audit Administrator', 'global', 'Audit log administrator.'),
  (
    'System Administrator',
    'global',
    'Highest privilege administrator.'
  ),
  (
    'Emergency Access Operator (Break-Glass)',
    'global',
    'Time-limited break-glass operator.'
  ),
  ('Read-Only Operator', 'global', 'Read-only operational viewer.'),
  (
    'NOC / Health Monitor Viewer',
    'global',
    'Health dashboards and device health viewer.'
  ),
  ('Trainer', 'global', 'Training mode operator.'),
  ('QA / Test Operator', 'global', 'Test environment operator.');

/* Permission registry */
INSERT IGNORE INTO permissions (
  name,
  description,
  risk_level,
  requires_mfa,
  requires_approval,
  break_glass_only,
  always_audit
) VALUES
  ('*', 'Wildcard permission for all actions.', 'critical', 1, 1, 1, 1),

  ('Nav.Overview.View', 'Navigation: Overview menu.', 'low', 0, 0, 0, 1),
  ('Nav.IAM.Users.View', 'Navigation: Users pages.', 'medium', 0, 0, 0, 1),
  ('Nav.Cust.Properties.View', 'Navigation: Properties pages.', 'medium', 0, 0, 0, 1),

  ('Nav.Feeds.Cameras.View', 'Navigation: Feeds > Cameras.', 'medium', 0, 0, 0, 1),
  (
    'Nav.Feeds.CameraUrlTemplates.View',
    'Navigation: Feeds > Camera URL Templates.',
    'medium',
    0,
    0,
    0,
    1
  ),
  ('Nav.Feeds.RtmpOutputs.View', 'Navigation: Feeds > RTMP Outputs.', 'medium', 0, 0, 0, 1),

  ('Nav.Recording.Recordings.View', 'Navigation: Recording & Storage > Recordings.', 'medium', 0, 0, 0, 1),
  ('Nav.Recording.Schedule.View', 'Navigation: Recording & Storage > Recording Schedule.', 'high', 1, 0, 0, 1),
  ('Nav.Storage.Providers.View', 'Navigation: Recording & Storage > Storage Providers.', 'high', 1, 0, 0, 1),

  ('Nav.Themes.View', 'Navigation: Themes pages.', 'high', 1, 0, 0, 1),

  ('Nav.NetSec.BlockAllow.View', 'Navigation: Network Security > Block / Allow.', 'critical', 1, 0, 0, 1),
  ('Nav.NetSec.BlocklistDistribution.View', 'Navigation: Network Security > Blocklist Distribution.', 'critical', 1, 0, 0, 1),
  ('Nav.NetSec.BlocklistIntegration.View', 'Navigation: Network Security > Blocklist Integration.', 'critical', 1, 0, 0, 1),

  ('Nav.Audit.AuditLog.View', 'Navigation: Audit & Security Events > Audit Log.', 'high', 1, 0, 0, 1),
  ('Nav.Audit.BlocklistAudit.View', 'Navigation: Audit & Security Events > Blocklist Audit.', 'high', 1, 0, 0, 1),
  ('Nav.Audit.LoginFailures.View', 'Navigation: Audit & Security Events > Login Failures.', 'critical', 1, 0, 0, 1),

  ('Nav.Services.View', 'Navigation: Services pages.', 'high', 1, 0, 0, 1),
  ('Nav.Installer.Databases.View', 'Navigation: Installer & Databases.', 'critical', 1, 0, 0, 1),

  ('Users.Manage', 'Page actions: manage users.', 'critical', 1, 0, 0, 1),
  ('Properties.Manage', 'Page actions: manage properties.', 'high', 0, 0, 0, 1),
  ('Feeds.Cameras.Manage', 'Page actions: manage camera devices.', 'high', 0, 0, 0, 1),
  (
    'Feeds.CameraUrlTemplates.Manage',
    'Page actions: manage camera URL templates.',
    'high',
    0,
    0,
    0,
    1
  ),
  ('Feeds.RtmpOutputs.Manage', 'Page actions: manage RTMP outputs.', 'critical', 1, 0, 0, 1),
  ('Recording.Schedule.Manage', 'Page actions: manage recording schedule.', 'critical', 1, 0, 0, 1),
  ('Storage.Providers.Manage', 'Page actions: manage storage providers.', 'critical', 1, 0, 0, 1),
  ('Themes.Manage', 'Page actions: manage themes.', 'critical', 1, 0, 0, 1),
  ('NetSec.BlockAllow.Manage', 'Page actions: manage IP block/allow rules.', 'critical', 1, 0, 0, 1),
  ('NetSec.BlocklistDistribution.Manage', 'Page actions: manage blocklist distribution.', 'critical', 1, 0, 0, 1),
  ('NetSec.BlocklistIntegration.Manage', 'Page actions: manage blocklist integration.', 'critical', 1, 0, 0, 1),
  ('Audit.LoginFailures.Decrypt', 'Page actions: decrypt login-failure records.', 'critical', 1, 0, 0, 1),
  ('Services.Manage', 'Page actions: manage services and update actions.', 'critical', 1, 0, 0, 1),
  ('Installer.Databases.Manage', 'Page actions: change installer/database settings.', 'critical', 1, 0, 0, 1),

  ('IAM.*', 'Identity and access management (all).', 'critical', 1, 0, 0, 1),
  ('IAM.Users.*', 'IAM users (all).', 'critical', 1, 0, 0, 1),
  ('IAM.Users.List', 'List users.', 'medium', 0, 0, 0, 1),
  ('IAM.Users.View', 'View user profiles.', 'medium', 0, 0, 0, 1),
  ('IAM.Users.Create', 'Create users.', 'high', 1, 0, 0, 1),
  ('IAM.Users.UpdateProfile', 'Update user profile fields.', 'high', 1, 0, 0, 1),
  ('IAM.Users.DisableEnable', 'Disable/enable users.', 'high', 1, 0, 0, 1),
  ('IAM.Users.ResetPassword', 'Reset user passwords.', 'critical', 1, 0, 0, 1),
  ('IAM.Users.ForceLogout', 'Force user logout.', 'high', 0, 0, 0, 1),
  (
    'IAM.Users.SetMFARequirements',
    'Set MFA requirements for user.',
    'critical',
    1,
    0,
    0,
    1
  ),
  ('IAM.Users.ManagePasskeys', 'Manage user passkeys.', 'critical', 1, 0, 0, 1),
  (
    'IAM.Users.ManageAuthenticatorCodes',
    'Manage authenticator codes.',
    'critical',
    1,
    0,
    0,
    1
  ),
  ('IAM.Roles.*', 'IAM roles (all).', 'critical', 1, 0, 0, 1),
  ('IAM.Roles.List', 'List roles.', 'medium', 0, 0, 0, 1),
  ('IAM.Roles.View', 'View role definitions.', 'medium', 0, 0, 0, 1),
  ('IAM.Roles.Create', 'Create roles.', 'high', 1, 0, 0, 1),
  ('IAM.Roles.Update', 'Update roles.', 'high', 1, 0, 0, 1),
  ('IAM.Roles.Delete', 'Delete roles.', 'critical', 1, 1, 0, 1),
  ('IAM.Roles.AssignToUser', 'Assign roles to a user.', 'critical', 1, 0, 0, 1),
  ('IAM.Roles.RemoveFromUser', 'Remove roles from a user.', 'critical', 1, 0, 0, 1),
  ('IAM.Policies.*', 'IAM policies (all).', 'high', 1, 0, 0, 1),
  ('IAM.Policies.List', 'List policies.', 'medium', 0, 0, 0, 1),
  ('IAM.Policies.View', 'View policies.', 'medium', 0, 0, 0, 1),
  ('IAM.Policies.Create', 'Create policies.', 'high', 1, 0, 0, 1),
  ('IAM.Policies.Update', 'Update policies.', 'high', 1, 0, 0, 1),
  ('IAM.Policies.Delete', 'Delete policies.', 'critical', 1, 1, 0, 1),
  ('IAM.PolicySimulator.Use', 'Use policy simulator.', 'medium', 0, 0, 0, 1),
  (
    'IAM.Impersonate.Start',
    'Start impersonation session (restricted mode).',
    'critical',
    1,
    0,
    0,
    1
  ),
  ('IAM.Impersonate.End', 'End impersonation session.', 'high', 0, 0, 0, 1),

  ('Ops.*', 'Operations (all).', 'high', 0, 0, 0, 1),
  ('Ops.Incidents.*', 'Incidents (all).', 'high', 0, 0, 0, 1),
  ('Ops.Incidents.List', 'List incidents.', 'low', 0, 0, 0, 1),
  ('Ops.Incidents.View', 'View incident details.', 'low', 0, 0, 0, 1),
  ('Ops.Incidents.Acknowledge', 'Acknowledge incident.', 'medium', 0, 0, 0, 1),
  (
    'Ops.Incidents.Update',
    'Update incident (notes/classification/etc).',
    'high',
    0,
    0,
    0,
    1
  ),
  ('Ops.Incidents.Close', 'Close incident.', 'high', 0, 0, 0, 1),
  ('Ops.Incidents.Reopen', 'Reopen incident.', 'high', 0, 0, 0, 1),

  ('Ops.Dispatch.*', 'Dispatch (all).', 'high', 0, 0, 0, 1),
  ('Ops.Dispatch.Create', 'Create dispatch action.', 'high', 0, 0, 0, 1),
  ('Ops.Dispatch.Update', 'Update dispatch action.', 'high', 0, 0, 0, 1),
  ('Ops.Dispatch.Cancel', 'Cancel dispatch action.', 'high', 0, 0, 0, 1),
  ('Ops.Dispatch.NotifyContacts', 'Notify contacts via dispatch.', 'high', 0, 0, 0, 1),
  ('Ops.Dispatch.Logs.View', 'View dispatch logs.', 'medium', 0, 0, 0, 1),

  ('Ops.Queues.*', 'Ops queues (all).', 'high', 0, 0, 0, 1),
  ('Ops.Queues.View', 'View queues.', 'low', 0, 0, 0, 1),
  ('Ops.Queues.AssignIncident', 'Assign incident to queue/owner.', 'high', 0, 0, 0, 1),
  ('Ops.Queues.ReassignIncident', 'Reassign incident.', 'high', 0, 0, 0, 1),
  ('Ops.Queues.SetOwnershipRules', 'Configure queue ownership rules.', 'high', 0, 0, 0, 1),

  ('Ops.Shifts.*', 'Shift management (all).', 'medium', 0, 0, 0, 1),
  ('Ops.Shifts.SetOnDutyStatus', 'Set on-duty status for team.', 'medium', 0, 0, 0, 1),
  ('Ops.Shifts.ManageSchedules', 'Manage schedules.', 'high', 0, 0, 0, 1),

  ('Ops.Playbooks.*', 'Playbooks (all).', 'high', 0, 0, 0, 1),
  ('Ops.Playbooks.View', 'View playbooks.', 'low', 0, 0, 0, 1),
  ('Ops.Playbooks.Create', 'Create playbooks.', 'high', 0, 0, 0, 1),
  ('Ops.Playbooks.Update', 'Update playbooks.', 'high', 0, 0, 0, 1),
  ('Ops.Playbooks.Retire', 'Retire playbooks.', 'high', 0, 0, 0, 1),
  (
    'Ops.Playbooks.RequireStepCompletion',
    'Require step completion in playbooks.',
    'medium',
    0,
    0,
    0,
    1
  ),

  ('Ops.Escalation.*', 'Escalation rules (all).', 'high', 0, 0, 0, 1),
  (
    'Ops.Escalation.ManageEscalationRules',
    'Manage escalation rules.',
    'high',
    0,
    0,
    0,
    1
  ),
  (
    'Ops.Escalation.OverridePolicy',
    'Override escalation policy.',
    'critical',
    1,
    1,
    1,
    1
  ),

  ('Ops.Tickets.*', 'Tickets (all).', 'medium', 0, 0, 0, 1),
  ('Ops.Tickets.Create', 'Create tickets.', 'medium', 0, 0, 0, 1),
  ('Ops.Tickets.Update', 'Update tickets.', 'medium', 0, 0, 0, 1),
  ('Ops.Tickets.LinkToIncident', 'Link ticket to incident.', 'medium', 0, 0, 0, 1),

  ('Video.*', 'Video (all).', 'critical', 1, 0, 0, 1),
  ('Video.Live.*', 'Live video (all).', 'high', 0, 0, 0, 1),
  ('Video.Live.View', 'View live video.', 'high', 0, 0, 0, 1),
  ('Video.Live.PTZ.Control', 'Control PTZ on live video.', 'high', 0, 0, 0, 1),
  ('Video.Live.TakeSnapshot', 'Take snapshot.', 'high', 1, 0, 0, 1),
  ('Video.Playback.*', 'Playback (all).', 'high', 0, 0, 0, 1),
  ('Video.Playback.View', 'View playback.', 'high', 0, 0, 0, 1),
  ('Video.Playback.BookmarkCreate', 'Create playback bookmark.', 'medium', 0, 0, 0, 1),
  ('Video.Playback.BookmarkUpdate', 'Update playback bookmark.', 'medium', 0, 0, 0, 1),
  ('Video.Playback.BookmarkDelete', 'Delete playback bookmark.', 'medium', 0, 0, 0, 1),
  ('Video.Export.*', 'Video exports (all).', 'critical', 1, 0, 0, 1),
  ('Video.Export.CreateClip', 'Create export clip.', 'critical', 1, 0, 0, 1),
  ('Video.Export.Download', 'Download export.', 'critical', 1, 0, 0, 1),
  ('Video.Export.ShareLinkCreate', 'Create share link for export.', 'critical', 1, 0, 0, 1),
  ('Video.Export.ShareLinkRevoke', 'Revoke share link.', 'high', 1, 0, 0, 1),
  ('Video.Export.Approve', 'Approve export.', 'critical', 1, 0, 0, 1),
  ('Video.Export.History.View', 'View export history.', 'medium', 0, 0, 0, 1),
  ('Video.EvidenceBundle.Create', 'Create evidence bundle.', 'critical', 1, 0, 0, 1),
  ('Video.EvidenceBundle.Seal', 'Seal evidence bundle.', 'critical', 1, 0, 0, 1),
  ('Video.Evidence.ChainOfCustody.View', 'View chain of custody.', 'high', 0, 0, 0, 1),
  ('Video.Redaction.Use', 'Use redaction tooling.', 'high', 1, 0, 0, 1),

  ('Devices.*', 'Devices (all).', 'high', 0, 0, 0, 1),
  ('Devices.List', 'List devices.', 'low', 0, 0, 0, 1),
  ('Devices.View', 'View device details.', 'low', 0, 0, 0, 1),
  ('Devices.Update', 'Update device (limited fields).', 'high', 0, 0, 0, 1),
  ('Devices.Reboot', 'Reboot device.', 'high', 0, 0, 0, 1),
  ('Devices.Firmware.Update', 'Update firmware.', 'critical', 1, 0, 0, 1),
  ('Devices.TimeSync.Configure', 'Configure time sync.', 'medium', 0, 0, 0, 1),
  ('Devices.Health.*', 'Device health (all).', 'medium', 0, 0, 0, 1),
  ('Devices.Health.View', 'View device health.', 'low', 0, 0, 0, 1),
  ('Devices.Health.RunDiagnostics', 'Run device diagnostics.', 'high', 0, 0, 0, 1),
  ('Devices.Health.SuppressAlert', 'Suppress device alert.', 'high', 0, 0, 0, 1),
  ('Devices.Config.View', 'View device config.', 'high', 1, 0, 0, 1),
  ('Devices.Config.Push', 'Push config to device.', 'critical', 1, 0, 0, 1),
  ('Devices.Credentials.Rotate', 'Rotate device credentials.', 'critical', 1, 1, 0, 1),
  ('Devices.NetworkSettings.View', 'View device network settings.', 'high', 1, 0, 0, 1),
  ('Devices.NetworkSettings.Update', 'Update device network settings.', 'critical', 1, 1, 0, 1),

  ('Cust.*', 'Customer/property (staff-side) (all).', 'high', 0, 0, 0, 1),
  ('Cust.Customers.*', 'Customers (all).', 'high', 0, 0, 0, 1),
  ('Cust.Customers.List', 'List customers.', 'low', 0, 0, 0, 1),
  ('Cust.Customers.View', 'View customer.', 'low', 0, 0, 0, 1),
  ('Cust.Customers.Create', 'Create customer.', 'high', 0, 0, 0, 1),
  ('Cust.Customers.Update', 'Update customer.', 'high', 0, 0, 0, 1),
  ('Cust.Customers.Disable', 'Disable customer.', 'high', 0, 0, 0, 1),
  ('Cust.Properties.*', 'Properties (all).', 'high', 0, 0, 0, 1),
  ('Cust.Properties.List', 'List properties.', 'low', 0, 0, 0, 1),
  ('Cust.Properties.View', 'View property.', 'low', 0, 0, 0, 1),
  ('Cust.Properties.Create', 'Create property.', 'high', 0, 0, 0, 1),
  ('Cust.Properties.Update', 'Update property.', 'high', 0, 0, 0, 1),
  ('Cust.Properties.Disable', 'Disable property.', 'high', 0, 0, 0, 1),
  ('Cust.Properties.AssignStaff', 'Assign staff to property.', 'high', 0, 0, 0, 1),
  ('Cust.Contacts.*', 'Customer contacts (all).', 'high', 0, 0, 0, 1),
  ('Cust.Contacts.View', 'View contacts.', 'medium', 0, 0, 0, 1),
  ('Cust.Contacts.Manage', 'Manage contacts.', 'high', 0, 0, 0, 1),
  ('Cust.SLAs.View', 'View SLAs.', 'low', 0, 0, 0, 1),
  ('Cust.SLAs.Update', 'Update SLAs.', 'high', 0, 0, 0, 1),

  ('Integrations.*', 'Integrations (all).', 'high', 1, 0, 0, 1),
  ('Integrations.List', 'List integrations.', 'medium', 0, 0, 0, 1),
  ('Integrations.View', 'View integration.', 'medium', 0, 0, 0, 1),
  ('Integrations.Add', 'Add integration.', 'high', 1, 0, 0, 1),
  ('Integrations.Update', 'Update integration.', 'high', 1, 0, 0, 1),
  ('Integrations.Remove', 'Remove integration.', 'high', 1, 1, 0, 1),
  ('Integrations.Secrets.Rotate', 'Rotate integration secrets.', 'critical', 1, 0, 0, 1),
  ('Integrations.Webhooks.Test', 'Test webhooks.', 'medium', 0, 0, 0, 1),
  ('Integrations.EmailSMS.Configure', 'Configure email/SMS providers.', 'critical', 1, 0, 0, 1),

  ('Automations.*', 'Automations (all).', 'high', 0, 0, 0, 1),
  ('Automations.Rules.Create', 'Create automation rules.', 'high', 0, 0, 0, 1),
  ('Automations.Rules.Update', 'Update automation rules.', 'high', 0, 0, 0, 1),
  ('Automations.Rules.Disable', 'Disable automation rules.', 'high', 0, 0, 0, 1),

  ('Reports.*', 'Reports (all).', 'medium', 0, 0, 0, 1),
  ('Reports.ViewStandard', 'View standard reports.', 'low', 0, 0, 0, 1),
  ('Reports.ExportData', 'Export report data.', 'high', 1, 0, 0, 1),
  ('Reports.ScheduleDelivery', 'Schedule report delivery.', 'medium', 0, 0, 0, 1),

  ('Analytics.ViewOperationalDashboards', 'View operational dashboards.', 'low', 0, 0, 0, 1),

  ('Audit.*', 'Audit (all).', 'high', 1, 0, 0, 1),
  ('Audit.Logs.View', 'View audit logs.', 'high', 1, 0, 0, 1),
  ('Audit.Logs.Export', 'Export audit logs.', 'critical', 1, 0, 0, 1),
  ('Audit.Logs.ViewEvidenceAccess', 'View evidence access audit.', 'high', 1, 0, 0, 1),
  ('Audit.Logs.ViewImpersonationRecords', 'View impersonation records.', 'high', 1, 0, 0, 1),
  ('Audit.Logs.ConfigureRetention', 'Configure audit retention.', 'critical', 1, 0, 0, 1),

  ('Sec.*', 'Security controls (all).', 'critical', 1, 0, 0, 1),
  ('Sec.Policy.View', 'View security policy.', 'high', 0, 0, 0, 1),
  ('Sec.Policy.Update', 'Update security policy.', 'critical', 1, 0, 0, 1),
  ('Sec.IPAllowlist.Manage', 'Manage IP allowlist.', 'critical', 1, 0, 0, 1),
  ('Sec.DeviceTrust.Manage', 'Manage device trust.', 'critical', 1, 0, 0, 1),
  ('Sec.GeoRules.Manage', 'Manage geo rules.', 'critical', 1, 0, 0, 1),
  ('Sec.DLP.Manage', 'Manage DLP rules.', 'critical', 1, 0, 0, 1),
  ('Sec.BreakGlass.Approve', 'Approve break-glass requests.', 'critical', 1, 0, 0, 1),
  (
    'Sec.IncidentResponse.InitiateLockdown',
    'Initiate lockdown (break-glass).',
    'critical',
    1,
    0,
    1,
    1
  ),
  (
    'Sec.KeyManagement.RotateKeys',
    'Rotate keys (break-glass).',
    'critical',
    1,
    1,
    1,
    1
  ),

  ('Platform.*', 'Platform admin (all).', 'critical', 1, 0, 0, 1),
  ('Platform.Settings.View', 'View platform settings.', 'high', 0, 0, 0, 1),
  ('Platform.Settings.Update', 'Update platform settings.', 'critical', 1, 0, 0, 1),
  ('Platform.Updates.Manage', 'Manage platform updates.', 'critical', 1, 0, 0, 1),
  ('Platform.StorageBackends.Configure', 'Configure storage backends.', 'critical', 1, 0, 0, 1),
  ('Platform.DeleteTenantData', 'Delete tenant data (break-glass).', 'critical', 1, 1, 1, 1),

  ('Storage.*', 'Storage administration (all).', 'critical', 1, 0, 0, 1),
  ('Storage.View', 'View storage configuration.', 'high', 1, 0, 0, 1),
  ('Storage.ConfigureTargets', 'Configure storage targets.', 'critical', 1, 0, 0, 1),
  ('Storage.ConfigureRetention', 'Configure retention.', 'critical', 1, 0, 0, 1),
  ('Storage.DeleteArchive', 'Delete archive (break-glass).', 'critical', 1, 1, 1, 1),

  ('TestEnv.*', 'Test environment (all).', 'medium', 0, 0, 0, 1),
  ('TestEnv.Ops.*', 'Test env ops (all).', 'medium', 0, 0, 0, 1),
  ('TestEnv.Video.*', 'Test env video (all).', 'medium', 0, 0, 0, 1),
  ('TestEnv.Devices.*', 'Test env devices (all).', 'medium', 0, 0, 0, 1);

/* Role -> permission bindings (allow/deny) */

-- Executive Viewer
INSERT INTO role_permissions (role_id, permission_id, effect)
SELECT r.id, p.id, 'allow'
FROM roles r
JOIN permissions p
WHERE r.name = 'Executive Viewer'
  AND p.name IN (
    'Reports.ViewStandard',
    'Analytics.ViewOperationalDashboards',
    'Cust.Customers.List',
    'Cust.Customers.View',
    'Cust.Properties.List',
    'Cust.Properties.View',
    'Ops.Incidents.List',
    'Ops.Incidents.View',
    'Audit.Logs.View'
  )
ON DUPLICATE KEY UPDATE effect = VALUES(effect);

-- Viewer (legacy)
INSERT INTO role_permissions (role_id, permission_id, effect)
SELECT r.id, p.id, 'allow'
FROM roles r
JOIN permissions p
WHERE r.name = 'Viewer'
  AND p.name IN (
    'Nav.Overview.View',
    'Nav.Feeds.Cameras.View',
    'Nav.Recording.Recordings.View',
    'Video.Live.View',
    'Video.Playback.View',
    'Ops.Incidents.List',
    'Ops.Incidents.View'
  )
ON DUPLICATE KEY UPDATE effect = VALUES(effect);

INSERT INTO role_permissions (role_id, permission_id, effect)
SELECT r.id, p.id, 'deny'
FROM roles r
JOIN permissions p
WHERE r.name = 'Viewer'
  AND p.name IN (
    'Video.Export.*',
    'Devices.*',
    'IAM.*',
    'Sec.*',
    'Platform.*'
  )
ON DUPLICATE KEY UPDATE effect = VALUES(effect);

-- Technician (legacy)
INSERT INTO role_permissions (role_id, permission_id, effect)
SELECT r.id, p.id, 'allow'
FROM roles r
JOIN permissions p
WHERE r.name = 'Technician'
  AND p.name IN (
    'Nav.Overview.View',
    'Nav.Feeds.Cameras.View',
    'Nav.Feeds.CameraUrlTemplates.View',
    'Feeds.Cameras.Manage',
    'Feeds.CameraUrlTemplates.Manage',
    'Devices.List',
    'Devices.View',
    'Devices.Update',
    'Devices.Health.View',
    'Devices.Health.RunDiagnostics',
    'Video.Live.View'
  )
ON DUPLICATE KEY UPDATE effect = VALUES(effect);

INSERT INTO role_permissions (role_id, permission_id, effect)
SELECT r.id, p.id, 'deny'
FROM roles r
JOIN permissions p
WHERE r.name = 'Technician'
  AND p.name IN (
    'Video.Export.*',
    'IAM.*',
    'Sec.*',
    'Platform.*'
  )
ON DUPLICATE KEY UPDATE effect = VALUES(effect);

-- Property Administrator (legacy)
INSERT INTO role_permissions (role_id, permission_id, effect)
SELECT r.id, p.id, 'allow'
FROM roles r
JOIN permissions p
WHERE r.name = 'Property Administrator'
  AND p.name IN (
    'Nav.Overview.View',
    'Nav.Cust.Properties.View',
    'Nav.Feeds.Cameras.View',
    'Nav.Recording.Recordings.View',
    'Nav.Recording.Schedule.View',
    'Nav.Storage.Providers.View',
    'Recording.Schedule.Manage',
    'Storage.Providers.Manage',
    'Cust.Properties.*',
    'Cust.Contacts.*',
    'Cust.Customers.View',
    'Devices.*',
    'Video.*',
    'Storage.View'
  )
ON DUPLICATE KEY UPDATE effect = VALUES(effect);

INSERT INTO role_permissions (role_id, permission_id, effect)
SELECT r.id, p.id, 'deny'
FROM roles r
JOIN permissions p
WHERE r.name = 'Property Administrator'
  AND p.name IN (
    'IAM.*',
    'Platform.*',
    'Sec.KeyManagement.RotateKeys'
  )
ON DUPLICATE KEY UPDATE effect = VALUES(effect);

INSERT INTO role_permissions (role_id, permission_id, effect)
SELECT r.id, p.id, 'deny'
FROM roles r
JOIN permissions p
WHERE r.name = 'Executive Viewer'
  AND p.name IN (
    'Video.*',
    'Ops.Dispatch.*',
    'Ops.Queues.*',
    'Ops.Shifts.*',
    'Devices.*',
    'Integrations.*',
    'Sec.*',
    'Platform.*',
    'IAM.*'
  )
ON DUPLICATE KEY UPDATE effect = VALUES(effect);

-- Compliance Officer
INSERT INTO role_permissions (role_id, permission_id, effect)
SELECT r.id, p.id, 'allow'
FROM roles r
JOIN permissions p
WHERE r.name = 'Compliance Officer'
  AND p.name IN (
    'Audit.Logs.View',
    'Audit.Logs.Export',
    'Audit.Logs.ViewImpersonationRecords',
    'Video.Evidence.ChainOfCustody.View',
    'Video.Export.History.View',
    'Reports.ViewStandard',
    'Reports.ExportData',
    'Sec.Policy.View'
  )
ON DUPLICATE KEY UPDATE effect = VALUES(effect);

INSERT INTO role_permissions (role_id, permission_id, effect)
SELECT r.id, p.id, 'deny'
FROM roles r
JOIN permissions p
WHERE r.name = 'Compliance Officer'
  AND p.name IN (
    'Video.Live.View',
    'Video.Playback.View',
    'Video.Export.*',
    'IAM.*',
    'Devices.*',
    'Platform.*',
    'Integrations.*',
    'Ops.Dispatch.*',
    'Ops.Incidents.Update',
    'Ops.Incidents.Close'
  )
ON DUPLICATE KEY UPDATE effect = VALUES(effect);

-- Risk & Security Governance Manager
INSERT INTO role_permissions (role_id, permission_id, effect)
SELECT r.id, p.id, 'allow'
FROM roles r
JOIN permissions p
WHERE r.name = 'Risk & Security Governance Manager'
  AND p.name IN (
    'Sec.Policy.View',
    'Sec.Policy.Update',
    'Sec.IPAllowlist.Manage',
    'Sec.DeviceTrust.Manage',
    'Sec.GeoRules.Manage',
    'Sec.DLP.Manage',
    'Sec.BreakGlass.Approve',
    'Audit.Logs.View',
    'Audit.Logs.Export',
    'Reports.ViewStandard'
  )
ON DUPLICATE KEY UPDATE effect = VALUES(effect);

INSERT INTO role_permissions (role_id, permission_id, effect)
SELECT r.id, p.id, 'deny'
FROM roles r
JOIN permissions p
WHERE r.name = 'Risk & Security Governance Manager'
  AND p.name IN (
    'Video.Export.*',
    'Devices.NetworkSettings.Update',
    'Platform.*',
    'IAM.Roles.AssignToUser',
    'Ops.*'
  )
ON DUPLICATE KEY UPDATE effect = VALUES(effect);

-- SOC Operator - Tier 1
INSERT INTO role_permissions (role_id, permission_id, effect)
SELECT r.id, p.id, 'allow'
FROM roles r
JOIN permissions p
WHERE r.name = 'SOC Operator - Tier 1'
  AND p.name IN (
    'Ops.Incidents.List',
    'Ops.Incidents.View',
    'Ops.Incidents.Acknowledge',
    'Ops.Incidents.Update',
    'Ops.Playbooks.View',
    'Ops.Dispatch.Create',
    'Ops.Dispatch.Update',
    'Ops.Dispatch.NotifyContacts',
    'Video.Live.View',
    'Video.Live.PTZ.Control',
    'Video.Live.TakeSnapshot'
  )
ON DUPLICATE KEY UPDATE effect = VALUES(effect);

INSERT INTO role_permissions (role_id, permission_id, effect)
SELECT r.id, p.id, 'deny'
FROM roles r
JOIN permissions p
WHERE r.name = 'SOC Operator - Tier 1'
  AND p.name IN (
    'Video.Playback.View',
    'Video.Export.*',
    'Devices.*',
    'Integrations.*',
    'IAM.*',
    'Sec.*',
    'Platform.*',
    'Ops.Queues.*',
    'Ops.Shifts.ManageSchedules'
  )
ON DUPLICATE KEY UPDATE effect = VALUES(effect);

-- SOC Operator - Tier 2
INSERT INTO role_permissions (role_id, permission_id, effect)
SELECT r.id, p.id, 'allow'
FROM roles r
JOIN permissions p
WHERE r.name = 'SOC Operator - Tier 2'
  AND p.name IN (
    'Ops.Incidents.List',
    'Ops.Incidents.View',
    'Ops.Incidents.Acknowledge',
    'Ops.Incidents.Update',
    'Ops.Playbooks.View',
    'Ops.Dispatch.Create',
    'Ops.Dispatch.Update',
    'Ops.Dispatch.NotifyContacts',
    'Video.Live.View',
    'Video.Live.PTZ.Control',
    'Video.Live.TakeSnapshot',
    'Video.Playback.View',
    'Video.Playback.BookmarkCreate',
    'Video.Playback.BookmarkUpdate',
    'Video.Playback.BookmarkDelete',
    'Ops.Incidents.Reopen'
  )
ON DUPLICATE KEY UPDATE effect = VALUES(effect);

INSERT INTO role_permissions (role_id, permission_id, effect)
SELECT r.id, p.id, 'deny'
FROM roles r
JOIN permissions p
WHERE r.name = 'SOC Operator - Tier 2'
  AND p.name IN (
    'Video.Export.Download',
    'Video.Export.Approve',
    'Devices.*',
    'Integrations.*',
    'IAM.*',
    'Sec.*',
    'Platform.*',
    'Ops.Queues.AssignIncident'
  )
ON DUPLICATE KEY UPDATE effect = VALUES(effect);

-- SOC Supervisor / Shift Lead
INSERT INTO role_permissions (role_id, permission_id, effect)
SELECT r.id, p.id, 'allow'
FROM roles r
JOIN permissions p
WHERE r.name = 'SOC Supervisor / Shift Lead'
  AND p.name IN (
    'Ops.Incidents.List',
    'Ops.Incidents.View',
    'Ops.Incidents.Acknowledge',
    'Ops.Incidents.Update',
    'Ops.Incidents.Close',
    'Ops.Incidents.Reopen',
    'Ops.Playbooks.View',
    'Ops.Dispatch.Create',
    'Ops.Dispatch.Update',
    'Ops.Dispatch.NotifyContacts',
    'Ops.Dispatch.Cancel',
    'Video.Live.View',
    'Video.Live.PTZ.Control',
    'Video.Live.TakeSnapshot',
    'Video.Playback.View',
    'Ops.Queues.View',
    'Ops.Queues.AssignIncident',
    'Ops.Queues.ReassignIncident',
    'Ops.Shifts.SetOnDutyStatus',
    'Video.Export.Approve',
    'Ops.Playbooks.RequireStepCompletion',
    'Devices.Health.SuppressAlert'
  )
ON DUPLICATE KEY UPDATE effect = VALUES(effect);

INSERT INTO role_permissions (role_id, permission_id, effect)
SELECT r.id, p.id, 'deny'
FROM roles r
JOIN permissions p
WHERE r.name = 'SOC Supervisor / Shift Lead'
  AND p.name IN (
    'Video.Export.CreateClip',
    'Video.Export.Download',
    'IAM.*',
    'Platform.*',
    'Sec.*',
    'Devices.Config.Push',
    'Devices.Credentials.Rotate'
  )
ON DUPLICATE KEY UPDATE effect = VALUES(effect);

-- SOC Operations Manager
INSERT INTO role_permissions (role_id, permission_id, effect)
SELECT r.id, p.id, 'allow'
FROM roles r
JOIN permissions p
WHERE r.name = 'SOC Operations Manager'
  AND p.name IN (
    'Ops.Queues.SetOwnershipRules',
    'Ops.Escalation.ManageEscalationRules',
    'Ops.Playbooks.Create',
    'Ops.Playbooks.Update',
    'Ops.Playbooks.Retire',
    'Reports.ViewStandard',
    'Analytics.ViewOperationalDashboards',
    'Ops.Shifts.ManageSchedules',
    'Video.Export.Approve'
  )
ON DUPLICATE KEY UPDATE effect = VALUES(effect);

INSERT INTO role_permissions (role_id, permission_id, effect)
SELECT r.id, p.id, 'deny'
FROM roles r
JOIN permissions p
WHERE r.name = 'SOC Operations Manager'
  AND p.name IN (
    'Video.Export.CreateClip',
    'Video.Export.Download',
    'IAM.*',
    'Sec.*',
    'Platform.*',
    'Devices.*'
  )
ON DUPLICATE KEY UPDATE effect = VALUES(effect);

-- Investigator / Evidence Specialist
INSERT INTO role_permissions (role_id, permission_id, effect)
SELECT r.id, p.id, 'allow'
FROM roles r
JOIN permissions p
WHERE r.name = 'Investigator / Evidence Specialist'
  AND p.name IN (
    'Video.Playback.View',
    'Video.Export.CreateClip',
    'Video.Export.Download',
    'Video.Export.ShareLinkCreate',
    'Video.Export.ShareLinkRevoke',
    'Video.EvidenceBundle.Create',
    'Video.EvidenceBundle.Seal',
    'Video.Evidence.ChainOfCustody.View',
    'Video.Redaction.Use',
    'Ops.Incidents.View',
    'Ops.Incidents.Update',
    'Ops.Tickets.Create',
    'Ops.Tickets.Update',
    'Ops.Tickets.LinkToIncident'
  )
ON DUPLICATE KEY UPDATE effect = VALUES(effect);

INSERT INTO role_permissions (role_id, permission_id, effect)
SELECT r.id, p.id, 'deny'
FROM roles r
JOIN permissions p
WHERE r.name = 'Investigator / Evidence Specialist'
  AND p.name IN (
    'Video.Export.Approve',
    'Ops.Dispatch.*',
    'Devices.*',
    'Platform.*',
    'Sec.*',
    'IAM.*'
  )
ON DUPLICATE KEY UPDATE effect = VALUES(effect);

-- Incident Response Lead
INSERT INTO role_permissions (role_id, permission_id, effect)
SELECT r.id, p.id, 'allow'
FROM roles r
JOIN permissions p
WHERE r.name = 'Incident Response Lead'
  AND p.name IN (
    'Ops.Incidents.Update',
    'Ops.Incidents.Close',
    'Ops.Incidents.Reopen',
    'Ops.Escalation.OverridePolicy',
    'Ops.Dispatch.*',
    'Video.Live.View',
    'Video.Playback.View',
    'Video.Export.CreateClip'
  )
ON DUPLICATE KEY UPDATE effect = VALUES(effect);

INSERT INTO role_permissions (role_id, permission_id, effect)
SELECT r.id, p.id, 'deny'
FROM roles r
JOIN permissions p
WHERE r.name = 'Incident Response Lead'
  AND p.name IN (
    'Video.Export.Approve',
    'IAM.*',
    'Platform.*',
    'Sec.*',
    'Devices.*'
  )
ON DUPLICATE KEY UPDATE effect = VALUES(effect);

-- Dispatcher
INSERT INTO role_permissions (role_id, permission_id, effect)
SELECT r.id, p.id, 'allow'
FROM roles r
JOIN permissions p
WHERE r.name = 'Dispatcher'
  AND p.name IN (
    'Ops.Dispatch.Create',
    'Ops.Dispatch.Update',
    'Ops.Dispatch.Cancel',
    'Ops.Dispatch.NotifyContacts',
    'Ops.Incidents.List',
    'Ops.Incidents.View',
    'Ops.Incidents.Update',
    'Ops.Playbooks.View',
    'Cust.Contacts.View'
  )
ON DUPLICATE KEY UPDATE effect = VALUES(effect);

INSERT INTO role_permissions (role_id, permission_id, effect)
SELECT r.id, p.id, 'deny'
FROM roles r
JOIN permissions p
WHERE r.name = 'Dispatcher'
  AND p.name IN (
    'Video.*',
    'Devices.*',
    'IAM.*',
    'Sec.*',
    'Platform.*'
  )
ON DUPLICATE KEY UPDATE effect = VALUES(effect);

-- Communications Supervisor
INSERT INTO role_permissions (role_id, permission_id, effect)
SELECT r.id, p.id, 'allow'
FROM roles r
JOIN permissions p
WHERE r.name = 'Communications Supervisor'
  AND p.name IN (
    'Ops.Dispatch.Create',
    'Ops.Dispatch.Update',
    'Ops.Dispatch.Cancel',
    'Ops.Dispatch.NotifyContacts',
    'Ops.Incidents.List',
    'Ops.Incidents.View',
    'Ops.Incidents.Update',
    'Ops.Playbooks.View',
    'Cust.Contacts.View',
    'Ops.Dispatch.Logs.View',
    'Cust.Contacts.Manage',
    'Ops.Escalation.ManageEscalationRules',
    'Reports.ViewStandard'
  )
ON DUPLICATE KEY UPDATE effect = VALUES(effect);

INSERT INTO role_permissions (role_id, permission_id, effect)
SELECT r.id, p.id, 'deny'
FROM roles r
JOIN permissions p
WHERE r.name = 'Communications Supervisor'
  AND p.name IN (
    'Video.Export.*',
    'IAM.*',
    'Platform.*'
  )
ON DUPLICATE KEY UPDATE effect = VALUES(effect);

-- Technical Support Agent
INSERT INTO role_permissions (role_id, permission_id, effect)
SELECT r.id, p.id, 'allow'
FROM roles r
JOIN permissions p
WHERE r.name = 'Technical Support Agent'
  AND p.name IN (
    'Cust.Customers.List',
    'Cust.Customers.View',
    'Cust.Properties.List',
    'Cust.Properties.View',
    'Devices.List',
    'Devices.View',
    'Devices.Health.View',
    'Devices.Health.RunDiagnostics',
    'Ops.Incidents.View',
    'IAM.Impersonate.Start',
    'IAM.Impersonate.End'
  )
ON DUPLICATE KEY UPDATE effect = VALUES(effect);

INSERT INTO role_permissions (role_id, permission_id, effect)
SELECT r.id, p.id, 'deny'
FROM roles r
JOIN permissions p
WHERE r.name = 'Technical Support Agent'
  AND p.name IN (
    'Video.Export.*',
    'Devices.Credentials.Rotate',
    'Devices.NetworkSettings.Update',
    'IAM.Roles.*',
    'IAM.Users.Create',
    'IAM.Users.DisableEnable',
    'Sec.*',
    'Platform.*'
  )
ON DUPLICATE KEY UPDATE effect = VALUES(effect);

-- Field Technician
INSERT INTO role_permissions (role_id, permission_id, effect)
SELECT r.id, p.id, 'allow'
FROM roles r
JOIN permissions p
WHERE r.name = 'Field Technician'
  AND p.name IN (
    'Devices.List',
    'Devices.View',
    'Devices.Update',
    'Devices.Reboot',
    'Devices.Firmware.Update',
    'Devices.TimeSync.Configure',
    'Devices.Health.RunDiagnostics'
  )
ON DUPLICATE KEY UPDATE effect = VALUES(effect);

INSERT INTO role_permissions (role_id, permission_id, effect)
SELECT r.id, p.id, 'deny'
FROM roles r
JOIN permissions p
WHERE r.name = 'Field Technician'
  AND p.name IN (
    'Video.*',
    'Devices.Credentials.Rotate',
    'IAM.*',
    'Sec.*',
    'Platform.*'
  )
ON DUPLICATE KEY UPDATE effect = VALUES(effect);

-- Device Administrator
INSERT INTO role_permissions (role_id, permission_id, effect)
SELECT r.id, p.id, 'allow'
FROM roles r
JOIN permissions p
WHERE r.name = 'Device Administrator'
  AND p.name IN (
    'Devices.*',
    'Devices.Config.View',
    'Devices.Config.Push',
    'Devices.Credentials.Rotate',
    'Devices.NetworkSettings.View',
    'Devices.NetworkSettings.Update',
    'Storage.View',
    'Storage.ConfigureTargets',
    'Storage.ConfigureRetention',
    'Integrations.Webhooks.Test',
    'Audit.Logs.View'
  )
ON DUPLICATE KEY UPDATE effect = VALUES(effect);

INSERT INTO role_permissions (role_id, permission_id, effect)
SELECT r.id, p.id, 'deny'
FROM roles r
JOIN permissions p
WHERE r.name = 'Device Administrator'
  AND p.name IN (
    'Video.Export.*',
    'IAM.Roles.*',
    'Platform.*',
    'Sec.KeyManagement.RotateKeys'
  )
ON DUPLICATE KEY UPDATE effect = VALUES(effect);

/* Additional permissions referenced by mainsecurity.md */
INSERT IGNORE INTO permissions (
  name,
  description,
  risk_level,
  requires_mfa,
  requires_approval,
  break_glass_only,
  always_audit
) VALUES
  (
    'Ops.TrainingScenarios.*',
    'Training scenarios (all).',
    'medium',
    0,
    0,
    0,
    1
  ),
  (
    'Ops.TrainingScenarios.Create',
    'Create training scenarios.',
    'medium',
    0,
    0,
    0,
    1
  ),
  (
    'Ops.TrainingScenarios.Run',
    'Run training scenarios.',
    'medium',
    0,
    0,
    0,
    1
  );

-- Customer Success Manager
INSERT INTO role_permissions (role_id, permission_id, effect)
SELECT r.id, p.id, 'allow'
FROM roles r
JOIN permissions p
WHERE r.name = 'Customer Success Manager'
  AND p.name IN (
    'Cust.Customers.List',
    'Cust.Customers.View',
    'Cust.Properties.List',
    'Cust.Properties.View',
    'Cust.SLAs.View',
    'Reports.ViewStandard',
    'Ops.Incidents.View'
  )
ON DUPLICATE KEY UPDATE effect = VALUES(effect);

INSERT INTO role_permissions (role_id, permission_id, effect)
SELECT r.id, p.id, 'deny'
FROM roles r
JOIN permissions p
WHERE r.name = 'Customer Success Manager'
  AND p.name IN (
    'Video.*',
    'Devices.*',
    'IAM.*',
    'Sec.*',
    'Platform.*',
    'Cust.Customers.Create',
    'Cust.Customers.Disable'
  )
ON DUPLICATE KEY UPDATE effect = VALUES(effect);

-- Account Administrator (Internal)
INSERT INTO role_permissions (role_id, permission_id, effect)
SELECT r.id, p.id, 'allow'
FROM roles r
JOIN permissions p
WHERE r.name = 'Account Administrator (Internal)'
  AND p.name IN (
    'Cust.Customers.Create',
    'Cust.Customers.Update',
    'Cust.Customers.Disable',
    'Cust.Properties.Create',
    'Cust.Properties.Update',
    'Cust.Properties.Disable',
    'Cust.Properties.AssignStaff',
    'Cust.Contacts.Manage',
    'Cust.SLAs.Update',
    'Reports.ViewStandard'
  )
ON DUPLICATE KEY UPDATE effect = VALUES(effect);

INSERT INTO role_permissions (role_id, permission_id, effect)
SELECT r.id, p.id, 'deny'
FROM roles r
JOIN permissions p
WHERE r.name = 'Account Administrator (Internal)'
  AND p.name IN (
    'Video.Export.*',
    'Devices.*',
    'IAM.*',
    'Platform.*',
    'Sec.*'
  )
ON DUPLICATE KEY UPDATE effect = VALUES(effect);

-- Platform Engineer
INSERT INTO role_permissions (role_id, permission_id, effect)
SELECT r.id, p.id, 'allow'
FROM roles r
JOIN permissions p
WHERE r.name = 'Platform Engineer'
  AND p.name IN (
    'Platform.Settings.View',
    'Platform.Settings.Update',
    'Platform.Updates.Manage',
    'Platform.StorageBackends.Configure',
    'Storage.*',
    'Audit.Logs.View',
    'Integrations.EmailSMS.Configure'
  )
ON DUPLICATE KEY UPDATE effect = VALUES(effect);

INSERT INTO role_permissions (role_id, permission_id, effect)
SELECT r.id, p.id, 'deny'
FROM roles r
JOIN permissions p
WHERE r.name = 'Platform Engineer'
  AND p.name IN (
    'Video.Export.*',
    'IAM.Roles.AssignToUser',
    'Cust.*',
    'Ops.*'
  )
ON DUPLICATE KEY UPDATE effect = VALUES(effect);

-- Integration Engineer
INSERT INTO role_permissions (role_id, permission_id, effect)
SELECT r.id, p.id, 'allow'
FROM roles r
JOIN permissions p
WHERE r.name = 'Integration Engineer'
  AND p.name IN (
    'Integrations.List',
    'Integrations.View',
    'Integrations.Add',
    'Integrations.Update',
    'Integrations.Remove',
    'Integrations.Secrets.Rotate',
    'Integrations.Webhooks.Test',
    'Automations.Rules.Create',
    'Automations.Rules.Update',
    'Automations.Rules.Disable',
    'Reports.ScheduleDelivery'
  )
ON DUPLICATE KEY UPDATE effect = VALUES(effect);

INSERT INTO role_permissions (role_id, permission_id, effect)
SELECT r.id, p.id, 'deny'
FROM roles r
JOIN permissions p
WHERE r.name = 'Integration Engineer'
  AND p.name IN (
    'Video.Export.*',
    'IAM.*',
    'Sec.KeyManagement.RotateKeys',
    'Platform.Updates.Manage'
  )
ON DUPLICATE KEY UPDATE effect = VALUES(effect);

-- Automation Engineer
INSERT INTO role_permissions (role_id, permission_id, effect)
SELECT r.id, p.id, 'allow'
FROM roles r
JOIN permissions p
WHERE r.name = 'Automation Engineer'
  AND p.name IN (
    'Automations.Rules.Create',
    'Automations.Rules.Update',
    'Automations.Rules.Disable',
    'Ops.Playbooks.Create',
    'Ops.Playbooks.Update',
    'Ops.Playbooks.Retire',
    'Ops.Escalation.ManageEscalationRules',
    'Integrations.Webhooks.Test',
    'Audit.Logs.View'
  )
ON DUPLICATE KEY UPDATE effect = VALUES(effect);

INSERT INTO role_permissions (role_id, permission_id, effect)
SELECT r.id, p.id, 'deny'
FROM roles r
JOIN permissions p
WHERE r.name = 'Automation Engineer'
  AND p.name IN (
    'Video.Export.*',
    'IAM.*',
    'Platform.*',
    'Devices.NetworkSettings.Update'
  )
ON DUPLICATE KEY UPDATE effect = VALUES(effect);

-- IAM Administrator
INSERT INTO role_permissions (role_id, permission_id, effect)
SELECT r.id, p.id, 'allow'
FROM roles r
JOIN permissions p
WHERE r.name = 'IAM Administrator'
  AND p.name IN (
    'IAM.*',
    'IAM.Users.List',
    'IAM.Users.View',
    'IAM.Users.Create',
    'IAM.Users.UpdateProfile',
    'IAM.Users.DisableEnable',
    'IAM.Users.ResetPassword',
    'IAM.Users.ForceLogout',
    'IAM.Users.SetMFARequirements',
    'IAM.Users.ManagePasskeys',
    'IAM.Users.ManageAuthenticatorCodes',
    'IAM.Roles.List',
    'IAM.Roles.View',
    'IAM.Roles.Create',
    'IAM.Roles.Update',
    'IAM.Roles.Delete',
    'IAM.Roles.AssignToUser',
    'IAM.Roles.RemoveFromUser',
    'IAM.Policies.List',
    'IAM.Policies.View',
    'IAM.Policies.Create',
    'IAM.Policies.Update',
    'IAM.Policies.Delete',
    'IAM.PolicySimulator.Use'
  )
ON DUPLICATE KEY UPDATE effect = VALUES(effect);

INSERT INTO role_permissions (role_id, permission_id, effect)
SELECT r.id, p.id, 'deny'
FROM roles r
JOIN permissions p
WHERE r.name = 'IAM Administrator'
  AND p.name IN (
    'Video.Export.*',
    'Devices.*',
    'Platform.*',
    'Sec.KeyManagement.RotateKeys'
  )
ON DUPLICATE KEY UPDATE effect = VALUES(effect);

-- Security Administrator
INSERT INTO role_permissions (role_id, permission_id, effect)
SELECT r.id, p.id, 'allow'
FROM roles r
JOIN permissions p
WHERE r.name = 'Security Administrator'
  AND p.name IN (
    'Sec.Policy.View',
    'Sec.Policy.Update',
    'Sec.IPAllowlist.Manage',
    'Sec.DeviceTrust.Manage',
    'Sec.GeoRules.Manage',
    'Sec.DLP.Manage',
    'Sec.IncidentResponse.InitiateLockdown',
    'Audit.Logs.View',
    'Audit.Logs.Export'
  )
ON DUPLICATE KEY UPDATE effect = VALUES(effect);

INSERT INTO role_permissions (role_id, permission_id, effect)
SELECT r.id, p.id, 'deny'
FROM roles r
JOIN permissions p
WHERE r.name = 'Security Administrator'
  AND p.name IN (
    'Video.Export.*',
    'IAM.Roles.AssignToUser',
    'Platform.*'
  )
ON DUPLICATE KEY UPDATE effect = VALUES(effect);

-- Audit Administrator
INSERT INTO role_permissions (role_id, permission_id, effect)
SELECT r.id, p.id, 'allow'
FROM roles r
JOIN permissions p
WHERE r.name = 'Audit Administrator'
  AND p.name IN (
    'Audit.Logs.View',
    'Audit.Logs.Export',
    'Audit.Logs.ConfigureRetention',
    'Audit.Logs.ViewEvidenceAccess',
    'Audit.Logs.ViewImpersonationRecords',
    'Reports.ViewStandard'
  )
ON DUPLICATE KEY UPDATE effect = VALUES(effect);

INSERT INTO role_permissions (role_id, permission_id, effect)
SELECT r.id, p.id, 'deny'
FROM roles r
JOIN permissions p
WHERE r.name = 'Audit Administrator'
  AND p.name IN (
    'Sec.Policy.Update',
    'Video.Export.*',
    'IAM.*',
    'Platform.*'
  )
ON DUPLICATE KEY UPDATE effect = VALUES(effect);

-- System Administrator
INSERT INTO role_permissions (role_id, permission_id, effect)
SELECT r.id, p.id, 'allow'
FROM roles r
JOIN permissions p
WHERE r.name = 'System Administrator'
  AND p.name = '*'
ON DUPLICATE KEY UPDATE effect = VALUES(effect);

INSERT INTO role_permissions (role_id, permission_id, effect)
SELECT r.id, p.id, 'allow'
FROM roles r
JOIN permissions p
WHERE r.name = 'System Administrator'
  AND p.name IN (
    'Platform.*',
    'IAM.*',
    'Sec.*',
    'Integrations.*',
    'Storage.*',
    'Audit.*',
    'Cust.*',
    'Devices.*'
  )
ON DUPLICATE KEY UPDATE effect = VALUES(effect);

INSERT INTO role_permissions (role_id, permission_id, effect)
SELECT r.id, p.id, 'deny'
FROM roles r
JOIN permissions p
WHERE r.name = 'System Administrator'
  AND p.name IN (
    'Video.Export.Download'
  )
ON DUPLICATE KEY UPDATE effect = VALUES(effect);

-- Emergency Access Operator (Break-Glass)
INSERT INTO role_permissions (role_id, permission_id, effect)
SELECT r.id, p.id, 'allow'
FROM roles r
JOIN permissions p
WHERE r.name = 'Emergency Access Operator (Break-Glass)'
  AND p.name IN (
    'Ops.Escalation.OverridePolicy',
    'Video.Playback.View',
    'Video.Export.CreateClip',
    'Devices.Credentials.Rotate',
    'Platform.Settings.View'
  )
ON DUPLICATE KEY UPDATE effect = VALUES(effect);

INSERT INTO role_permissions (role_id, permission_id, effect)
SELECT r.id, p.id, 'deny'
FROM roles r
JOIN permissions p
WHERE r.name = 'Emergency Access Operator (Break-Glass)'
  AND p.name IN (
    'IAM.Roles.Create',
    'IAM.Roles.AssignToUser',
    'Audit.Logs.ConfigureRetention',
    'Platform.Updates.Manage'
  )
ON DUPLICATE KEY UPDATE effect = VALUES(effect);

-- Read-Only Operator
INSERT INTO role_permissions (role_id, permission_id, effect)
SELECT r.id, p.id, 'allow'
FROM roles r
JOIN permissions p
WHERE r.name = 'Read-Only Operator'
  AND p.name IN (
    'Ops.Incidents.List',
    'Ops.Incidents.View',
    'Video.Live.View',
    'Video.Playback.View',
    'Devices.Health.View',
    'Reports.ViewStandard'
  )
ON DUPLICATE KEY UPDATE effect = VALUES(effect);

INSERT INTO role_permissions (role_id, permission_id, effect)
SELECT r.id, p.id, 'deny'
FROM roles r
JOIN permissions p
WHERE r.name = 'Read-Only Operator'
  AND p.name IN (
    'Ops.Incidents.Update',
    'Ops.Dispatch.*',
    'Ops.Queues.*',
    'Ops.Shifts.*',
    'Video.Export.*',
    'IAM.*',
    'Platform.*',
    'Sec.*'
  )
ON DUPLICATE KEY UPDATE effect = VALUES(effect);

-- NOC / Health Monitor Viewer
INSERT INTO role_permissions (role_id, permission_id, effect)
SELECT r.id, p.id, 'allow'
FROM roles r
JOIN permissions p
WHERE r.name = 'NOC / Health Monitor Viewer'
  AND p.name IN (
    'Devices.Health.View',
    'Platform.Settings.View',
    'Reports.ViewStandard'
  )
ON DUPLICATE KEY UPDATE effect = VALUES(effect);

INSERT INTO role_permissions (role_id, permission_id, effect)
SELECT r.id, p.id, 'deny'
FROM roles r
JOIN permissions p
WHERE r.name = 'NOC / Health Monitor Viewer'
  AND p.name IN (
    'Cust.*',
    'Video.*',
    'Ops.Incidents.View',
    'IAM.*',
    'Sec.*'
  )
ON DUPLICATE KEY UPDATE effect = VALUES(effect);

-- Trainer
INSERT INTO role_permissions (role_id, permission_id, effect)
SELECT r.id, p.id, 'allow'
FROM roles r
JOIN permissions p
WHERE r.name = 'Trainer'
  AND p.name IN (
    'Ops.TrainingScenarios.Create',
    'Ops.TrainingScenarios.Run',
    'Reports.ViewStandard'
  )
ON DUPLICATE KEY UPDATE effect = VALUES(effect);

INSERT INTO role_permissions (role_id, permission_id, effect)
SELECT r.id, p.id, 'deny'
FROM roles r
JOIN permissions p
WHERE r.name = 'Trainer'
  AND p.name IN (
    'Video.*',
    'IAM.*',
    'Platform.*',
    'Sec.*'
  )
ON DUPLICATE KEY UPDATE effect = VALUES(effect);

-- QA / Test Operator
INSERT INTO role_permissions (role_id, permission_id, effect)
SELECT r.id, p.id, 'allow'
FROM roles r
JOIN permissions p
WHERE r.name = 'QA / Test Operator'
  AND p.name IN (
    'TestEnv.*',
    'Reports.ViewStandard'
  )
ON DUPLICATE KEY UPDATE effect = VALUES(effect);

INSERT INTO role_permissions (role_id, permission_id, effect)
SELECT r.id, p.id, 'deny'
FROM roles r
JOIN permissions p
WHERE r.name = 'QA / Test Operator'
  AND p.name IN (
    'IAM.*',
    'Sec.*',
    'Platform.*',
    'Devices.*',
    'Video.*',
    'Ops.*',
    'Cust.*',
    'Integrations.*',
    'Storage.*'
  )
ON DUPLICATE KEY UPDATE effect = VALUES(effect);

