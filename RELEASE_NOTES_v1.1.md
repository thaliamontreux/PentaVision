# PentaVision v1.1 Release Notes

**Release Date:** December 29, 2025

## 🎉 Major Features

### Storage Modules Manager - Complete Transformation
The Storage Modules Manager has been completely redesigned into a comprehensive orchestration dashboard with enterprise-grade features.

#### Enhanced Provider List
- **Provider-specific icon colors** - 15+ storage providers with unique visual identities (GCS, S3, Azure, Dropbox, OneDrive, Box, WebDAV, FTP/SFTP/SCP, Local FS, Database, Swift, pCloud, MEGA)
- **Real-time health status badges** - Healthy, Degraded, Failing, Disabled states with color coding
- **Active stream count indicators** - Live stream monitoring with pulsing animations
- **Improved visual design** - Modern glassmorphism with better spacing and alignment

#### Enhanced Overview Tab
- **Metric cards grid** - Active streams, writes (15m), total stored, storage usage
- **Progress bars** - Visual storage usage with color-coded warnings (green/yellow/red at 75%/90% thresholds)
- **Performance metrics panel** - Last write, last successful test, last error, provider type, priority
- **Enhanced statistics** - Better organized with clear labels and real-time data

#### Streams Tab Improvements
- Recent recording segments table with device ID and storage keys
- Upload queue display showing pending/failed uploads
- Status tracking with attempt counts and error messages

#### Logs Tab
- Module events with severity levels (info/warning/error)
- Last 50 events per module
- Searchable and filterable event log

#### Advanced Tab
- **Global priority ordering view** - All modules sorted by priority with visual indicators
- **Failover visualization** - Clear display of primary/backup provider hierarchy
- **Module actions** - Enable/disable/clone/delete with safety checks
- **Active stream warnings** - Prevents accidental configuration changes during active uploads

### Camera Management Enhancements

#### Bulk Operations
- **Bulk group assignment** - Assign multiple cameras to a group simultaneously
- **Bulk tag assignment** - Apply multiple tags to selected cameras at once
- **Modal dialogs** - Clean, intuitive UI for bulk operations
- **Backend routes** - New `/bulk-assign-group` and `/bulk-assign-tags` endpoints
- **Audit logging** - All bulk operations logged for security and compliance

#### Enhanced Camera Health Dashboard
- **Progress bars** - Visual representation of health metrics with gradients
- **Additional metric cards**:
  - Active Streams (currently streaming count)
  - Recording Count (cameras actively recording)
  - Storage OK (properly configured cameras)
  - Uptime Percentage (last 24 hours availability)
- **Color-coded health scores** - Green (≥90%), Yellow (≥70%), Red (<70%)
- **Enhanced backend statistics** - More comprehensive health data collection

### Camera Health Detection Improvements
- Fixed health detection logic to properly identify active cameras
- Cameras now correctly show as "healthy" when recording
- Checks both active streams AND recent recordings (within last hour)
- Proper status indicators for disabled/warning/healthy states

## 🔧 Technical Improvements

### CSS Enhancements (240+ new lines)
- Provider-specific icon colors for 15+ storage providers
- Health status badges with smooth animations
- Stream count indicators with pulse effect
- Progress bars with gradient fills
- Metric cards with responsive grid layout
- Enhanced stat rows with better typography

### Backend Enhancements
- `module_metrics` dictionary for efficient stream tracking
- Bulk assignment routes with proper validation and error handling
- Enhanced health statistics calculation with multiple data sources
- Comprehensive audit logging for all operations
- Improved query performance with optimized database calls

### Template Improvements
- Enhanced Storage Modules Manager UI with split-view layout
- Bulk operation modals with checkbox groups
- Camera health dashboard with metric visualizations
- Better visual hierarchy throughout the application
- Responsive design improvements

## 📊 Statistics

- **Files Modified:** 10+
- **Lines of Code Added:** 500+
- **New Features:** 15+
- **CSS Enhancements:** 240+ lines
- **Backend Routes:** 2 new endpoints
- **UI Components:** 5+ new components

## 🐛 Bug Fixes

- Fixed camera health detection showing all cameras as warnings
- Fixed permission checks on camera admin routes
- Fixed stream manager call with missing app context
- Fixed attribute references in health check logic
- Corrected model field names (ip_address, is_active, device_id)

## 🔐 Security Improvements

- Enhanced RBAC enforcement with permission-based checks
- CSRF token validation on all bulk operations
- Audit logging for security-sensitive actions
- Input validation on bulk assignment endpoints

## 📝 Documentation

- Updated TODO.md with completed features
- Added comprehensive release notes
- Inline code documentation improvements

## 🚀 Deployment Notes

1. **Restart Flask Application** - Required to load new features
2. **Database** - No schema changes required (tables auto-created)
3. **Dependencies** - No new dependencies added
4. **Compatibility** - Fully backward compatible with v1.0

## 🎯 What's Next

Future enhancements planned:
- Camera export/import functionality
- Advanced camera search with filters
- Storage provider wizard improvements
- Additional provider integrations

---

**Full Changelog:** See commit history from v1.0 to v1.1
**Contributors:** Thalia Montreux
**License:** Proprietary
