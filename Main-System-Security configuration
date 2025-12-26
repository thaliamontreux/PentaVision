Below is a **role → permissions map** for the **main system (staff)** roles I listed. I’m going to do this in a way that’s actually usable: **permission families** + **explicit “allow/deny”** + **notes on constraints (MFA/approval/time/SoD)**.

To keep this readable, I’m using a standardized permission namespace:

* **IAM.*** (users/roles/policies/sessions/impersonation)
* **Ops.*** (incidents, queues, shifts, dispatch, playbooks, tickets)
* **Video.*** (live, playback, exports, evidence, sharing, redaction)
* **Devices.*** (inventory, config, credentials, firmware, diagnostics)
* **Cust.*** (customers/properties from staff side)
* **Integrations.***
* **Reports.***
* **Audit.***
* **Sec.*** (security controls)
* **Platform.*** (global platform admin)

I’ll also mark sensitive actions with controls:

* **[MFA]** must require MFA/step-up
* **[APPROVAL]** must be approval-gated (2-person if noted)
* **[BG]** break-glass only
* **[AUDIT]** always logged (assume all are logged; these are “must-have”)

---

# 0) Global “hard rules” (apply to all roles)

* No role gets **Video.Export.*** *and* **Video.Export.Approve** unless explicitly stated (Separation of duties).
* No role gets **IAM.Roles.*** *and* **IAM.Roles.AssignToUser** unless explicitly stated.
* **Audit logs are append-only**: no “delete logs” permission exists.
* **Impersonation** is either forbidden or **restricted mode** unless explicitly allowed, and always **[MFA][AUDIT]**.

---

# 1) Executive Viewer

**ALLOW**

* Reports.ViewStandard
* Analytics.ViewOperationalDashboards
* Cust.Customers.List, Cust.Customers.View
* Cust.Properties.List, Cust.Properties.View
* Ops.Incidents.List, Ops.Incidents.View (metadata only; no live response)
* Audit.Logs.View (optional, but read-only)

**DENY**

* Video.* (all)
* Ops.Dispatch.*, Ops.Queues.*, Ops.Shifts.*
* Devices.*, Integrations.*, Sec.*, Platform.*, IAM.*

**CONSTRAINTS**

* Read-only; no exports.

---

# 2) Compliance Officer

**ALLOW**

* Audit.Logs.View, Audit.Logs.Export **[MFA][AUDIT]**
* Audit.Logs.ViewImpersonationRecords
* Video.Evidence.ChainOfCustody.View
* Video.Export.History.View (if you have it; otherwise Audit covers it)
* Reports.ViewStandard, Reports.ExportData **[MFA][AUDIT]**
* Sec.Policy.View (read-only)

**DENY**

* Video.Live.View, Video.Playback.View (optional; often denied)
* Video.Export.CreateClip/Download (unless policy explicitly allows)
* IAM.*, Devices.*, Platform.*, Integrations.*
* Ops.Dispatch.* (usually deny), Ops.Incidents.Update/Close (deny)

**CONSTRAINTS**

* Exports should be **log-only** (audit exports), not footage exports.

---

# 3) Risk & Security Governance Manager

**ALLOW**

* Sec.Policy.View, Sec.Policy.Update **[MFA][AUDIT]**
* Sec.IPAllowlist.Manage **[MFA][AUDIT]**
* Sec.DeviceTrust.Manage **[MFA][AUDIT]**
* Sec.GeoRules.Manage **[MFA][AUDIT]**
* Sec.DLP.Manage **[MFA][AUDIT]**
* Sec.BreakGlass.Approve **[MFA][AUDIT]**
* Audit.Logs.View, Audit.Logs.Export **[MFA][AUDIT]**
* Reports.ViewStandard (security posture)

**DENY**

* Video.Export.*
* Devices.NetworkSettings.Update
* Platform.*
* IAM.Roles.AssignToUser (deny; avoid power concentration)
* Ops.* operational controls (mostly deny)

---

# 4) SOC Operator – Tier 1

**ALLOW**

* Ops.Incidents.List, Ops.Incidents.View
* Ops.Incidents.Acknowledge
* Ops.Incidents.Update (notes, tags, classification within limits) **[AUDIT]**
* Ops.Playbooks.View
* Ops.Dispatch.Create, Ops.Dispatch.Update, Ops.Dispatch.NotifyContacts **[AUDIT]** (only via playbook)
* Video.Live.View **[AUDIT]**
* Video.Live.PTZ.Control (optional) **[AUDIT]**
* Video.Live.TakeSnapshot (optional; if allowed treat as export-lite) **[MFA?][AUDIT]**

**DENY**

* Video.Playback.View (optional; usually Tier 2)
* Video.Export.* (all)
* Evidence bundle actions
* Devices.*, Integrations.*, IAM.*, Sec.*, Platform.*
* Ops.Queues.*, Ops.Shifts.ManageSchedules

**CONSTRAINTS**

* Often **shift-gated** (must be on duty).

---

# 5) SOC Operator – Tier 2

**ALLOW**
Everything Tier 1 plus:

* Video.Playback.View **[AUDIT]**
* Video.Playback.BookmarkCreate/Update/Delete **[AUDIT]**
* Ops.Incidents.Reopen (optional)
* Ops.Incidents.Update (broader classification/priority changes) **[AUDIT]**
* Ops.Dispatch.Cancel (optional)

**DENY**

* Video.Export.Download (deny)
* Video.Export.CreateClip (optional: allow but **[APPROVAL]** and no self-approve)
* Ops.Queues.AssignIncident (usually supervisor)

**CONSTRAINTS**

* If you allow Video.Export.CreateClip: require **[MFA][APPROVAL]**.

---

# 6) SOC Supervisor / Shift Lead

**ALLOW**
Everything Tier 2 plus:

* Ops.Queues.View
* Ops.Queues.AssignIncident, Ops.Queues.ReassignIncident **[AUDIT]**
* Ops.Shifts.SetOnDutyStatus (for team) **[AUDIT]**
* Ops.Incidents.Close **[AUDIT]**
* Video.Export.Approve **[MFA][AUDIT]** (approver role)
* Ops.Playbooks.RequireStepCompletion (optional)
* Devices.Health.SuppressAlert (limited) **[AUDIT]**

**DENY**

* Video.Export.CreateClip (deny to preserve SoD) *(recommended)*
* IAM.*, Platform.*, Sec.*
* Devices.Config.Push, Devices.Credentials.Rotate

**CONSTRAINTS**

* Cannot approve exports they created (enforce by rule).
* Approval actions always require justification.

---

# 7) SOC Operations Manager

**ALLOW**

* Ops.Queues.SetOwnershipRules **[AUDIT]**
* Ops.Escalation.ManageEscalationRules **[AUDIT]**
* Ops.Playbooks.Create/Update/Retire **[AUDIT]**
* Reports.ViewStandard, Analytics.ViewOperationalDashboards
* Ops.Shifts.ManageSchedules (if in-product)
* Video.Export.Approve **[MFA][AUDIT]** (optional; many orgs keep this at supervisor)

**DENY**

* Video.Export.CreateClip/Download (deny)
* IAM.*, Sec.*, Platform.*
* Devices.* (except health view)

---

# 8) Investigator / Evidence Specialist

**ALLOW**

* Video.Playback.View **[AUDIT]**
* Video.Export.CreateClip **[MFA][AUDIT]**
* Video.Export.Download **[MFA][AUDIT]**
* Video.Export.ShareLinkCreate/Revoke **[MFA][AUDIT]**
* Video.EvidenceBundle.Create/Seal **[MFA][AUDIT]**
* Video.Evidence.ChainOfCustody.View **[AUDIT]**
* Video.Redaction.Use (optional) **[MFA][AUDIT]**
* Ops.Incidents.View, Ops.Incidents.Update (investigation notes) **[AUDIT]**
* Ops.Tickets.Create/Update/LinkToIncident

**DENY**

* Video.Export.Approve (deny; SoD)
* Ops.Dispatch.* (usually deny)
* Devices.*, Platform.*, Sec.*, IAM.*

**CONSTRAINTS**

* Large exports may require **[APPROVAL]** depending on policy.

---

# 9) Incident Response Lead

**ALLOW**

* Ops.Incidents.Update (all fields) **[AUDIT]**
* Ops.Incidents.Close/Reopen **[AUDIT]**
* Ops.Escalation.OverridePolicy **[MFA][AUDIT][BG or APPROVAL]**
* Ops.Dispatch.* (full)
* Video.Live.View, Video.Playback.View **[AUDIT]**
* Video.Export.CreateClip (optional) **[MFA][APPROVAL][AUDIT]**

**DENY**

* Video.Export.Approve (deny)
* IAM.*, Platform.*, Sec.* (except break-glass use if permitted)
* Devices.* (except health view)

---

# 10) Dispatcher

**ALLOW**

* Ops.Dispatch.Create/Update/Cancel **[AUDIT]**
* Ops.Dispatch.NotifyContacts **[AUDIT]**
* Ops.Incidents.List/View
* Ops.Incidents.Update (notes only)
* Ops.Playbooks.View
* Cust.Contacts.View (call lists)

**DENY**

* Video.* (or allow Video.Live.View only, depending on workflow)
* Devices.*, IAM.*, Sec.*, Platform.*

---

# 11) Communications Supervisor

**ALLOW**
Everything Dispatcher plus:

* Ops.Dispatch.Logs.View
* Cust.Contacts.Manage **[AUDIT]**
* Ops.Escalation.ManageEscalationRules (optional)
* Reports.ViewStandard (dispatch KPIs)

**DENY**

* Video.Export.*
* IAM.*, Platform.*

---

# 12) Technical Support Agent

**ALLOW**

* Cust.Customers.List/View
* Cust.Properties.List/View
* Devices.List/View
* Devices.Health.View, Devices.Health.RunDiagnostics **[AUDIT]**
* Ops.Incidents.View (optional; often view-only)
* IAM.Impersonate.Start (RestrictedMode) **[MFA][AUDIT]**
* IAM.Impersonate.End **[AUDIT]**

**DENY**

* Video.Export.*
* Devices.Credentials.Rotate (deny)
* Devices.NetworkSettings.Update (deny)
* IAM.Roles.*, IAM.Users.Create/Disable (deny)
* Sec.*, Platform.*

**CONSTRAINTS**

* Impersonation must block exports, deletes, role changes.

---

# 13) Field Technician

**ALLOW**

* Devices.List/View
* Devices.Update (labels/tags, limited config)
* Devices.Reboot **[AUDIT]**
* Devices.Firmware.Update **[MFA][AUDIT]**
* Devices.TimeSync.Configure **[AUDIT]**
* Devices.Health.RunDiagnostics **[AUDIT]**

**DENY**

* Video.Playback/View/Export (usually all deny)
* Devices.Credentials.Rotate (optional allow only with approval)
* IAM.*, Sec.*, Platform.*

**CONSTRAINTS**

* Often restricted by location/network (on-site VLAN/VPN only).

---

# 14) Device Administrator

**ALLOW**

* Devices.* (most)

  * Devices.Config.View/Push **[MFA][AUDIT]**
  * Devices.Credentials.Rotate **[MFA][APPROVAL?][AUDIT]**
  * Devices.NetworkSettings.View/Update **[MFA][APPROVAL][AUDIT]**
* Storage.View, Storage.ConfigureTargets **[MFA][AUDIT]**
* Storage.ConfigureRetention (optional; often separate)
* Integrations.Webhooks.Test (if device-related)
* Audit.Logs.View (device changes)

**DENY**

* Video.Export.*
* IAM.Roles.*, Platform.*
* Sec.KeyManagement.RotateKeys (deny)

**CONSTRAINTS**

* Credential viewing should not exist; rotate only.

---

# 15) Customer Success Manager

**ALLOW**

* Cust.Customers.List/View
* Cust.Properties.List/View
* Cust.SLAs.View
* Reports.ViewStandard (account reports)
* Ops.Incidents.View (summary)

**DENY**

* Video.*
* Devices.*
* IAM.*, Sec.*, Platform.*
* Cust.Customers.Create/Disable (optional deny)

---

# 16) Account Administrator (Internal)

**ALLOW**

* Cust.Customers.Create/Update/Disable **[AUDIT]**
* Cust.Properties.Create/Update/Disable **[AUDIT]**
* Cust.Properties.AssignStaff **[AUDIT]**
* Cust.Contacts.Manage **[AUDIT]**
* Cust.SLAs.Update **[AUDIT]**
* Reports.ViewStandard

**DENY**

* Video.Export.*
* Devices.* (except view)
* IAM.* (except maybe basic user view if needed)
* Platform.*, Sec.*

---

# 17) Platform Engineer

**ALLOW**

* Platform.Settings.View/Update **[MFA][AUDIT]**
* Platform.Updates.Manage **[MFA][AUDIT]**
* Platform.StorageBackends.Configure **[MFA][AUDIT]**
* Storage.* (infra side) **[MFA][AUDIT]**
* Audit.Logs.View (system logs)
* Integrations.EmailSMS.Configure (optional)

**DENY**

* Video.Export.*
* IAM.Roles.AssignToUser (deny)
* Cust.* (except view)
* Ops.* (except health dashboards)

**CONSTRAINTS**

* Should not routinely access customer content.

---

# 18) Integration Engineer

**ALLOW**

* Integrations.List/View/Add/Update/Remove **[MFA][AUDIT]**
* Integrations.Secrets.Rotate **[MFA][AUDIT]** (rotate only)
* Integrations.Webhooks.Test **[AUDIT]**
* Automations.Rules.Create/Update/Disable **[AUDIT]**
* Reports.ScheduleDelivery (if integration-based)

**DENY**

* Video.Export.*
* IAM.*
* Sec.KeyManagement.RotateKeys
* Platform.Updates.Manage

---

# 19) Automation Engineer

**ALLOW**

* Automations.Rules.Create/Update/Disable **[AUDIT]**
* Ops.Playbooks.Create/Update/Retire **[AUDIT]**
* Ops.Escalation.ManageEscalationRules **[AUDIT]**
* Integrations.Webhooks.Test (limited)
* Audit.Logs.View (automation activity)

**DENY**

* Video.Export.*
* IAM.*, Platform.*, Devices.NetworkSettings.Update

---

# 20) IAM Administrator

**ALLOW**

* IAM.Users.List/View/Create/UpdateProfile/DisableEnable **[AUDIT]**
* IAM.Users.ResetPassword **[MFA][AUDIT]**
* IAM.Users.ForceLogout **[AUDIT]**
* IAM.Users.SetMFARequirements **[MFA][AUDIT]**
* IAM.Users.ManagePasskeys **[MFA][AUDIT]**
* IAM.Users.ManageAuthenticatorCodes **[MFA][AUDIT]**
* IAM.Roles.List/View/Create/Update/Delete **[MFA][AUDIT]**
* IAM.Roles.AssignToUser/RemoveFromUser **[MFA][AUDIT]**
* IAM.Policies.List/View/Create/Update/Delete **[MFA][AUDIT]**
* IAM.PolicySimulator.Use

**DENY**

* Video.Export.*
* Devices.*
* Platform.* (except maybe view-only)
* Sec.KeyManagement.RotateKeys (deny)

**CONSTRAINTS**

* Consider splitting into:

  * “Role Designer” (can create roles)
  * “Role Grantor” (can assign roles)

---

# 21) Security Administrator

**ALLOW**

* Sec.Policy.View/Update **[MFA][AUDIT]**
* Sec.IPAllowlist.Manage **[MFA][AUDIT]**
* Sec.DeviceTrust.Manage **[MFA][AUDIT]**
* Sec.GeoRules.Manage **[MFA][AUDIT]**
* Sec.DLP.Manage **[MFA][AUDIT]**
* Sec.IncidentResponse.InitiateLockdown **[MFA][BG][AUDIT]**
* Audit.Logs.View/Export **[MFA][AUDIT]**

**DENY**

* Video.Export.*
* IAM.Roles.AssignToUser (optional deny)
* Platform.* (optional limited)

---

# 22) Audit Administrator

**ALLOW**

* Audit.Logs.View/Export **[MFA][AUDIT]**
* Audit.Logs.ConfigureRetention **[MFA][AUDIT]**
* Audit.Logs.ViewEvidenceAccess
* Audit.Logs.ViewImpersonationRecords
* Reports.ViewStandard (audit reports)

**DENY**

* Sec.Policy.Update (optional)
* Video.Export.*
* IAM.*
* Platform.*

**CONSTRAINTS**

* Cannot reduce audit retention below minimum (policy guard).

---

# 23) System Administrator (Highest)

**ALLOW**

* Platform.* **[MFA][AUDIT]**
* IAM.* **[MFA][AUDIT]**
* Sec.* **[MFA][AUDIT]** (including key rotation if you choose)
* Integrations.* **[MFA][AUDIT]**
* Storage.* **[MFA][AUDIT]**
* Audit.Logs.View/Export **[MFA][AUDIT]**
* Cust.* (optional)
* Devices.* (optional)

**DENY (recommended even for sysadmin)**

* Video.Export.Download (deny by default; if needed, break-glass)
* Video.Evidence tampering (unseal) unless **[BG]**

**CONSTRAINTS**

* Treat some actions as **Break-glass only** even for SysAdmin:

  * Sec.KeyManagement.RotateKeys **[BG]**
  * Platform.DeleteTenantData **[BG][2-person]**
  * Storage.DeleteArchive **[BG][2-person]**
  * Any mass export **[BG][2-person]**

---

# 24) Emergency Access Operator (Break-Glass)

**ALLOW (only while break-glass active)**

* Ops.Escalation.OverridePolicy **[BG][MFA][AUDIT]**
* Video.Playback.View **[BG][MFA][AUDIT]**
* Video.Export.CreateClip **[BG][MFA][AUDIT]**
* Devices.Credentials.Rotate **[BG][MFA][AUDIT]**
* Platform.Settings.View (limited)

**DENY**

* IAM.Roles.Create/Assign (deny)
* Audit.Logs.ConfigureRetention (deny)
* Platform.Updates.Manage (deny)

**CONSTRAINTS**

* Time-limited + justification + supervisor notification + mandatory post-review

---

# 25) Read-Only Operator

**ALLOW**

* Ops.Incidents.List/View
* Video.Live.View (optional)
* Video.Playback.View (optional)
* Devices.Health.View
* Reports.ViewStandard

**DENY**

* Any create/update/delete/execute permissions
* Video.Export.*
* IAM.*, Platform.*, Sec.*

---

# 26) NOC / Health Monitor Viewer

**ALLOW**

* Devices.Health.View
* Platform.Settings.View (health dashboards only)
* Reports.ViewStandard (uptime/health)

**DENY**

* Customer data access (Cust.*)
* Video.*
* Ops.Incidents.View (optional deny)
* IAM.*, Sec.*

---

# 27) Trainer

**ALLOW**

* Ops.TrainingScenarios.Create/Run (if you build training mode)
* Reports.ViewStandard (training metrics)

**DENY**

* Production video/export
* IAM.*, Platform.*, Sec.*

---

# 28) QA / Test Operator

**ALLOW**

* TestEnv.Ops.*, TestEnv.Video.*, TestEnv.Devices.* (non-production scopes)
* Reports.ViewStandard (test)

**DENY**

* Production scopes by default

---

