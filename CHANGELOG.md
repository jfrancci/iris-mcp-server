# Changelog

All notable changes to the DFIR-IRIS MCP Server.

## [1.3.0] - 2025-12-15

### Fixed
- `parse_date_flexible()` helper to handle MM/DD/YYYY format from IRIS API
- `calculate_mttr()` now correctly detects closed cases
- `calculate_mttd()` handles real-time detection (MTTD=0)
- `'list' object has no attribute 'get'` error in API response parsing

### Added
- `safe_get_data()` helper for robust API response handling
- Enhanced debug output for date parsing troubleshooting

## [1.2.0] - 2025-12-01

### Added
- `get_severity_breakdown()` for case severity statistics
- `calculate_mtta()` for Mean Time To Acknowledge
- `calculate_mttc()` for Mean Time To Contain
- `get_kpi_dashboard()` for comprehensive metrics view
- `get_open_cases_aging()` for aging analysis
- `get_sla_compliance()` for SLA tracking
- `get_operational_summary()` for full operational view

## [1.1.0] - 2025-11-15

### Added
- KPI functions: `calculate_mttd()`, `calculate_mttr()`
- `get_cases_by_analyst()` distribution
- `get_cases_trend()` over time period
- `extract_iocs_for_hunting()` in hunting-ready format

## [1.0.0] - 2025-11-01

### Added
- Initial release with 24 core functions
- Case Management (list, details, filter, timeline, tasks, notes, evidences)
- IOC Management (list, add, details, types, statistics)
- Asset Management (list, add, details, types, statistics)
- System functions (connection test, version, customers, alerts)
- Docker deployment with FastMCP and SSE transport
