#!/usr/bin/env python3
"""
DFIR-IRIS MCP Server
MCP Server for interacting with DFIR-IRIS incident response platform.

Author: DFIR-MESI Project
Version: 1.3.0 (Bug fixes: MTTR/MTTD date parsing)

Features:
- Case Management (list, details, filter, severity breakdown)
- IOC Management (list, add, hunting extraction)
- Asset Management (list, add, details)
- Timeline, Tasks, Evidence, Notes
- KPIs & Metrics (MTTD, MTTA, MTTC, MTTR, severity trends, dashboards)

Changes in 1.2.0:
- Added get_severity_breakdown() for case severity statistics
- Added calculate_mtta() for Mean Time To Acknowledge
- Added calculate_mttc() for Mean Time To Contain
- Fixed bug in calculate_mttd() using wrong variable name
- Enhanced get_soc_dashboard() with severity metrics

Changes in 1.1.2:
- Added safe_get_data() helper function to handle API responses
- Fixed "'list' object has no attribute 'get'" error in list_cases, filter_cases,
  get_cases_summary, get_soc_dashboard, and other functions
- All result.get() calls now use safe_get_data() for robustness
"""

import os
import sys
import json
import logging
import httpx
from typing import Any, Optional
from mcp.server.fastmcp import FastMCP

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mcp-iris")

# Initialize FastMCP server
mcp = FastMCP("DFIR MESI IRIS")

# Configuration from environment variables
IRIS_URL = os.getenv("IRIS_URL", "https://iris.yourdomain.com")
IRIS_API_KEY = os.getenv("IRIS_API_KEY", "")
IRIS_VERIFY_SSL = os.getenv("IRIS_VERIFY_SSL", "true").lower() == "true"


def get_headers() -> dict:
    """Return headers for IRIS API requests."""
    return {
        "Authorization": f"Bearer {IRIS_API_KEY}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }


def make_request(method: str, endpoint: str, params: dict = None, data: dict = None) -> dict:
    """Make HTTP request to IRIS API."""
    url = f"{IRIS_URL}{endpoint}"
    
    try:
        with httpx.Client(verify=IRIS_VERIFY_SSL, timeout=30.0) as client:
            if method.upper() == "GET":
                response = client.get(url, headers=get_headers(), params=params)
            elif method.upper() == "POST":
                response = client.post(url, headers=get_headers(), params=params, json=data)
            else:
                return {"error": f"Unsupported method: {method}"}
            
            response.raise_for_status()
            return response.json()
    except httpx.HTTPStatusError as e:
        logger.error(f"HTTP error: {e}")
        return {"error": f"HTTP {e.response.status_code}: {e.response.text}"}
    except Exception as e:
        logger.error(f"Request error: {e}")
        return {"error": str(e)}


def safe_get_data(result: Any, *keys, default=None):
    """
    Safely extract data from API response handling both list and dict responses.
    
    IRIS API sometimes returns:
    - A dict like {"status": "success", "data": {"cases": [...]}}
    - A list directly like [{"case_id": 1, ...}, ...]
    
    Args:
        result: API response (dict or list)
        *keys: Nested keys to extract (e.g., "data", "cases")
        default: Default value if extraction fails
    
    Returns:
        Extracted data or default value
    """
    if default is None:
        default = []
    
    # If result is already a list, return it (API returned list directly)
    if isinstance(result, list):
        return result
    
    # If result is not a dict, return default
    if not isinstance(result, dict):
        return default
    
    # Check for error in response
    if isinstance(result, dict) and "error" in result:
        return default
    
    # Navigate through nested keys
    current = result
    for key in keys:
        if isinstance(current, dict):
            current = current.get(key, default)
        elif isinstance(current, list):
            # If we hit a list and still have keys, return it
            return current
        else:
            return default
    
    return current if current is not None else default


# ==================== CONNECTION & INFO ====================

@mcp.tool()
def validate_iris_connection() -> str:
    """Validate connection to IRIS server and return API info."""
    result = make_request("GET", "/api/ping")
    if isinstance(result, dict) and "error" in result:
        return f"Connection failed: {result['error']}"
    return json.dumps(result, indent=2)


@mcp.tool()
def get_api_versions() -> str:
    """Get IRIS API versions supported by the server."""
    result = make_request("GET", "/api/versions")
    return json.dumps(result, indent=2)


# ==================== CASE MANAGEMENT ====================

@mcp.tool()
def list_cases(limit: int = 100) -> str:
    """List all cases in IRIS."""
    result = make_request("GET", "/manage/cases/list", params={"cid": 1})
    if isinstance(result, dict) and "error" in result:
        return f"Error: {result['error']}"
    
    cases = safe_get_data(result, "data", "cases")
    if limit:
        cases = cases[:limit]
    
    return json.dumps({
        "total": len(cases),
        "cases": cases
    }, indent=2)


@mcp.tool()
def get_case_details(case_id: int) -> str:
    """Get detailed information about a specific case."""
    result = make_request("GET", "/case/export", params={"cid": case_id})
    if isinstance(result, dict) and "error" in result:
        return f"Error: {result['error']}"
    return json.dumps(result, indent=2)


@mcp.tool()
def filter_cases(
    case_name: Optional[str] = None,
    case_customer: Optional[str] = None,
    case_state: Optional[str] = None,
    limit: int = 100
) -> str:
    """Filter cases by name, customer, or state."""
    params = {"cid": 1}
    
    filters = {}
    if case_name:
        filters["case_name"] = case_name
    if case_customer:
        filters["case_customer"] = case_customer
    if case_state:
        filters["case_state"] = case_state
    
    if filters:
        params["q"] = json.dumps(filters)
    
    result = make_request("GET", "/manage/cases/filter", params=params)
    if isinstance(result, dict) and "error" in result:
        return f"Error: {result['error']}"
    
    cases = safe_get_data(result, "data")
    if limit:
        cases = cases[:limit]
    
    return json.dumps({
        "total": len(cases),
        "cases": cases
    }, indent=2)


# ==================== IOC MANAGEMENT ====================

@mcp.tool()
def get_case_iocs(case_id: int) -> str:
    """Get all IOCs (Indicators of Compromise) from a specific case."""
    result = make_request("GET", "/case/ioc/list", params={"cid": case_id})
    if isinstance(result, dict) and "error" in result:
        return f"Error: {result['error']}"
    
    iocs = safe_get_data(result, "data", "ioc")
    
    iocs_by_type = {}
    for ioc in iocs:
        ioc_type = ioc.get("ioc_type", "unknown")
        if ioc_type not in iocs_by_type:
            iocs_by_type[ioc_type] = []
        iocs_by_type[ioc_type].append({
            "ioc_id": ioc.get("ioc_id"),
            "ioc_value": ioc.get("ioc_value"),
            "ioc_description": ioc.get("ioc_description"),
            "ioc_tags": ioc.get("ioc_tags"),
            "tlp": ioc.get("tlp_name")
        })
    
    return json.dumps({
        "case_id": case_id,
        "total_iocs": len(iocs),
        "iocs_by_type": iocs_by_type,
        "all_iocs": iocs
    }, indent=2)


@mcp.tool()
def get_ioc_details(case_id: int, ioc_id: int) -> str:
    """Get detailed information about a specific IOC."""
    result = make_request("GET", f"/case/ioc/{ioc_id}", params={"cid": case_id})
    if isinstance(result, dict) and "error" in result:
        return f"Error: {result['error']}"
    return json.dumps(result, indent=2)


@mcp.tool()
def get_iocs_for_hunting(case_id: int) -> str:
    """Extract IOCs from a case formatted for threat hunting operations."""
    result = make_request("GET", "/case/ioc/list", params={"cid": case_id})
    if isinstance(result, dict) and "error" in result:
        return f"Error: {result['error']}"
    
    iocs = safe_get_data(result, "data", "ioc")
    
    hunting_iocs = {
        "hashes": {"md5": [], "sha1": [], "sha256": []},
        "network": {"ipv4": [], "ipv6": [], "domains": [], "urls": []},
        "files": {"filenames": [], "paths": []},
        "identities": {"emails": [], "usernames": []},
        "other": []
    }
    
    type_mapping = {
        "md5": ("hashes", "md5"),
        "sha1": ("hashes", "sha1"),
        "sha256": ("hashes", "sha256"),
        "hash-md5": ("hashes", "md5"),
        "hash-sha1": ("hashes", "sha1"),
        "hash-sha256": ("hashes", "sha256"),
        "ip-dst": ("network", "ipv4"),
        "ip-src": ("network", "ipv4"),
        "ipv4": ("network", "ipv4"),
        "ipv6": ("network", "ipv6"),
        "domain": ("network", "domains"),
        "hostname": ("network", "domains"),
        "url": ("network", "urls"),
        "uri": ("network", "urls"),
        "filename": ("files", "filenames"),
        "file": ("files", "filenames"),
        "filepath": ("files", "paths"),
        "email": ("identities", "emails"),
        "email-dst": ("identities", "emails"),
        "email-src": ("identities", "emails"),
        "account": ("identities", "usernames"),
        "username": ("identities", "usernames"),
    }
    
    for ioc in iocs:
        ioc_type = ioc.get("ioc_type", "").lower()
        ioc_value = ioc.get("ioc_value", "")
        
        if not ioc_value:
            continue
            
        if ioc_type in type_mapping:
            category, subcategory = type_mapping[ioc_type]
            hunting_iocs[category][subcategory].append(ioc_value)
        else:
            if len(ioc_value) == 32 and all(c in '0123456789abcdefABCDEF' for c in ioc_value):
                hunting_iocs["hashes"]["md5"].append(ioc_value)
            elif len(ioc_value) == 40 and all(c in '0123456789abcdefABCDEF' for c in ioc_value):
                hunting_iocs["hashes"]["sha1"].append(ioc_value)
            elif len(ioc_value) == 64 and all(c in '0123456789abcdefABCDEF' for c in ioc_value):
                hunting_iocs["hashes"]["sha256"].append(ioc_value)
            else:
                hunting_iocs["other"].append({"type": ioc_type, "value": ioc_value})
    
    total_count = 0
    for category in hunting_iocs:
        if isinstance(hunting_iocs[category], dict):
            for subcategory in hunting_iocs[category]:
                total_count += len(hunting_iocs[category][subcategory])
        else:
            total_count += len(hunting_iocs[category])
    
    return json.dumps({
        "case_id": case_id,
        "total_hunting_iocs": total_count,
        "hunting_iocs": hunting_iocs
    }, indent=2)


@mcp.tool()
def add_ioc(case_id: int, ioc_value: str, ioc_type_id: int, ioc_tlp_id: int = 2, ioc_description: str = "", ioc_tags: str = "") -> str:
    """Add a new IOC to a case."""
    data = {
        "ioc_value": ioc_value,
        "ioc_type_id": ioc_type_id,
        "ioc_tlp_id": ioc_tlp_id,
        "ioc_description": ioc_description,
        "ioc_tags": ioc_tags
    }
    
    result = make_request("POST", "/case/ioc/add", params={"cid": case_id}, data=data)
    if isinstance(result, dict) and "error" in result:
        return f"Error: {result['error']}"
    return json.dumps(result, indent=2)


# ==================== ASSET MANAGEMENT ====================

@mcp.tool()
def get_case_assets(case_id: int) -> str:
    """Get all assets linked to a case."""
    result = make_request("GET", "/case/assets/list", params={"cid": case_id})
    if isinstance(result, dict) and "error" in result:
        return f"Error: {result['error']}"
    
    assets = safe_get_data(result, "data", "assets")
    
    return json.dumps({
        "case_id": case_id,
        "total_assets": len(assets),
        "assets": assets
    }, indent=2)


@mcp.tool()
def get_asset_details(case_id: int, asset_id: int) -> str:
    """Get detailed information about a specific asset."""
    result = make_request("GET", f"/case/assets/{asset_id}", params={"cid": case_id})
    if isinstance(result, dict) and "error" in result:
        return f"Error: {result['error']}"
    return json.dumps(result, indent=2)


@mcp.tool()
def add_asset(case_id: int, asset_name: str, asset_type_id: int, asset_ip: str = "", asset_domain: str = "", asset_description: str = "", asset_tags: str = "", compromise_status_id: int = 0) -> str:
    """Add a new asset to a case."""
    data = {
        "asset_name": asset_name,
        "asset_type_id": asset_type_id,
        "asset_ip": asset_ip,
        "asset_domain": asset_domain,
        "asset_description": asset_description,
        "asset_tags": asset_tags,
        "asset_compromise_status_id": compromise_status_id
    }
    
    result = make_request("POST", "/case/assets/add", params={"cid": case_id}, data=data)
    if isinstance(result, dict) and "error" in result:
        return f"Error: {result['error']}"
    return json.dumps(result, indent=2)


# ==================== TIMELINE ====================

@mcp.tool()
def get_case_timeline(case_id: int) -> str:
    """Get the timeline of events for a case."""
    result = make_request("GET", "/case/timeline/events/list", params={"cid": case_id})
    if isinstance(result, dict) and "error" in result:
        return f"Error: {result['error']}"
    
    events = safe_get_data(result, "data", "timeline")
    
    return json.dumps({
        "case_id": case_id,
        "total_events": len(events),
        "timeline": events
    }, indent=2)


# ==================== TASKS ====================

@mcp.tool()
def get_case_tasks(case_id: int) -> str:
    """Get all tasks for a case."""
    result = make_request("GET", "/case/tasks/list", params={"cid": case_id})
    if isinstance(result, dict) and "error" in result:
        return f"Error: {result['error']}"
    
    tasks = safe_get_data(result, "data", "tasks")
    
    return json.dumps({
        "case_id": case_id,
        "total_tasks": len(tasks),
        "tasks": tasks
    }, indent=2)


# ==================== EVIDENCE ====================

@mcp.tool()
def get_case_evidences(case_id: int) -> str:
    """Get all evidences linked to a case."""
    result = make_request("GET", "/case/evidences/list", params={"cid": case_id})
    if isinstance(result, dict) and "error" in result:
        return f"Error: {result['error']}"
    
    evidences = safe_get_data(result, "data", "evidences")
    
    return json.dumps({
        "case_id": case_id,
        "total_evidences": len(evidences),
        "evidences": evidences
    }, indent=2)


# ==================== NOTES ====================

@mcp.tool()
def get_case_notes(case_id: int) -> str:
    """Get all notes and note groups for a case."""
    result = make_request("GET", "/case/notes/directories/filter", params={"cid": case_id})
    if isinstance(result, dict) and "error" in result:
        return f"Error: {result['error']}"
    return json.dumps(result, indent=2)


@mcp.tool()
def search_notes(case_id: int, search_term: str) -> str:
    """Search across notes in a case."""
    result = make_request("GET", "/case/notes/search", params={
        "cid": case_id,
        "search_input": search_term
    })
    if isinstance(result, dict) and "error" in result:
        return f"Error: {result['error']}"
    return json.dumps(result, indent=2)


# ==================== ALERTS ====================

@mcp.tool()
def list_alerts(limit: int = 100) -> str:
    """List alerts in IRIS."""
    result = make_request("GET", "/alerts/filter", params={"cid": 1})
    if isinstance(result, dict) and "error" in result:
        return f"Error: {result['error']}"
    
    alerts = safe_get_data(result, "data", "alerts")
    if limit:
        alerts = alerts[:limit]
    
    return json.dumps({
        "total": len(alerts),
        "alerts": alerts
    }, indent=2)


@mcp.tool()
def get_alert_details(alert_id: int) -> str:
    """Get detailed information about a specific alert."""
    result = make_request("GET", f"/alerts/{alert_id}", params={"cid": 1})
    if isinstance(result, dict) and "error" in result:
        return f"Error: {result['error']}"
    return json.dumps(result, indent=2)


# ==================== TYPES ====================

@mcp.tool()
def list_ioc_types() -> str:
    """List all available IOC types in IRIS."""
    result = make_request("GET", "/manage/ioc-types/list", params={"cid": 1})
    if isinstance(result, dict) and "error" in result:
        return f"Error: {result['error']}"
    return json.dumps(result, indent=2)


@mcp.tool()
def list_asset_types() -> str:
    """List all available asset types in IRIS."""
    result = make_request("GET", "/manage/asset-types/list", params={"cid": 1})
    if isinstance(result, dict) and "error" in result:
        return f"Error: {result['error']}"
    return json.dumps(result, indent=2)


@mcp.tool()
def list_customers() -> str:
    """List all customers in IRIS."""
    result = make_request("GET", "/manage/customers/list", params={"cid": 1})
    if isinstance(result, dict) and "error" in result:
        return f"Error: {result['error']}"
    return json.dumps(result, indent=2)


# ==================== KPIs & METRICS ====================

@mcp.tool()
def get_cases_summary() -> str:
    """Get a summary of all cases with key statistics."""
    from datetime import datetime
    
    result = make_request("GET", "/manage/cases/list", params={"cid": 1})
    if isinstance(result, dict) and "error" in result:
        return f"Error: {result['error']}"
    
    cases = safe_get_data(result, "data", "cases")
    
    open_cases = 0
    closed_cases = 0
    status_count = {}
    severity_count = {}
    
    for case in cases:
        status = case.get("status_name", case.get("case_state", "unknown"))
        status_count[status] = status_count.get(status, 0) + 1
        
        close_date = case.get("close_date")
        if close_date:
            closed_cases += 1
        else:
            open_cases += 1
        
        severity = case.get("severity", case.get("case_severity", "unknown"))
        if isinstance(severity, dict):
            severity = severity.get("severity_name", "unknown")
        severity_count[str(severity)] = severity_count.get(str(severity), 0) + 1
    
    summary = {
        "total_cases": len(cases),
        "open_cases": open_cases,
        "closed_cases": closed_cases,
        "open_rate": f"{(open_cases/len(cases)*100):.1f}%" if cases else "0%",
        "closed_rate": f"{(closed_cases/len(cases)*100):.1f}%" if cases else "0%",
        "by_status": status_count,
        "by_severity": severity_count,
        "generated_at": datetime.now().isoformat()
    }
    
    return json.dumps(summary, indent=2)


@mcp.tool()
def get_cases_by_analyst() -> str:
    """Get case distribution by analyst/owner."""
    result = make_request("GET", "/manage/cases/list", params={"cid": 1})
    if isinstance(result, dict) and "error" in result:
        return f"Error: {result['error']}"
    
    cases = safe_get_data(result, "data", "cases")
    
    analyst_cases = {}
    analyst_open = {}
    analyst_closed = {}
    
    for case in cases:
        owner = case.get("owner", case.get("opened_by", case.get("user", "unassigned")))
        if isinstance(owner, dict):
            owner = owner.get("user_name", owner.get("name", "unassigned"))
        
        analyst_cases[owner] = analyst_cases.get(owner, 0) + 1
        
        if case.get("close_date"):
            analyst_closed[owner] = analyst_closed.get(owner, 0) + 1
        else:
            analyst_open[owner] = analyst_open.get(owner, 0) + 1
    
    analysts = []
    for analyst in analyst_cases:
        total = analyst_cases[analyst]
        opened = analyst_open.get(analyst, 0)
        closed = analyst_closed.get(analyst, 0)
        analysts.append({
            "analyst": analyst,
            "total_cases": total,
            "open_cases": opened,
            "closed_cases": closed,
            "close_rate": f"{(closed/total*100):.1f}%" if total > 0 else "0%"
        })
    
    analysts.sort(key=lambda x: x["total_cases"], reverse=True)
    
    return json.dumps({
        "total_analysts": len(analysts),
        "analysts": analysts
    }, indent=2)


@mcp.tool()
def get_cases_by_customer() -> str:
    """Get case distribution by customer/client."""
    result = make_request("GET", "/manage/cases/list", params={"cid": 1})
    if isinstance(result, dict) and "error" in result:
        return f"Error: {result['error']}"
    
    cases = safe_get_data(result, "data", "cases")
    
    customer_cases = {}
    
    for case in cases:
        customer = case.get("customer", case.get("client", case.get("for_customer", "unknown")))
        if isinstance(customer, dict):
            customer = customer.get("customer_name", customer.get("name", "unknown"))
        
        if customer not in customer_cases:
            customer_cases[customer] = {"total": 0, "open": 0, "closed": 0}
        
        customer_cases[customer]["total"] += 1
        if case.get("close_date"):
            customer_cases[customer]["closed"] += 1
        else:
            customer_cases[customer]["open"] += 1
    
    customers = []
    for name, counts in customer_cases.items():
        customers.append({
            "customer": name,
            "total_cases": counts["total"],
            "open_cases": counts["open"],
            "closed_cases": counts["closed"]
        })
    
    customers.sort(key=lambda x: x["total_cases"], reverse=True)
    
    return json.dumps({
        "total_customers": len(customers),
        "customers": customers
    }, indent=2)


@mcp.tool()

def parse_date_flexible(date_str: str):
    """Parse date string in multiple formats."""
    if not date_str or date_str.strip() == "":
        return None
    from datetime import datetime
    formats = [
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d",
        "%m/%d/%Y",
        "%d/%m/%Y"
    ]
    for fmt in formats:
        try:
            return datetime.strptime(date_str.strip(), fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
    except:
        return None

@mcp.tool()
def calculate_mttr(days: int = 90) -> str:
    """Calculate Mean Time To Respond/Resolve (MTTR)."""
    from datetime import datetime, timedelta
    
    result = make_request("GET", "/manage/cases/list", params={"cid": 1})
    if isinstance(result, dict) and "error" in result:
        return f"Error: {result['error']}"
    
    cases = safe_get_data(result, "data", "cases")
    
    cutoff_date = datetime.now() - timedelta(days=days)
    resolution_times = []
    
    for case in cases:
        open_date_str = case.get("open_date", case.get("case_open_date"))
        close_date_str = case.get("close_date", case.get("case_close_date"))
        
        if not open_date_str or not close_date_str or close_date_str.strip() == "":
            continue
        
        try:
            open_date = parse_date_flexible(open_date_str)
            close_date = parse_date_flexible(close_date_str)
            
            if not open_date or not close_date:
                continue
            
            if open_date < cutoff_date:
                continue
            
            resolution_time = (close_date - open_date).total_seconds() / 3600
            if resolution_time >= 0:
                resolution_times.append(resolution_time)
                
        except Exception as e:
            logger.warning(f"Error parsing dates for case: {e}")
            continue
    
    if not resolution_times:
        return json.dumps({
            "error": "No closed cases found in the specified period",
            "period_days": days,
            "cases_analyzed": 0
        }, indent=2)
    
    resolution_times.sort()
    avg_hours = sum(resolution_times) / len(resolution_times)
    min_hours = min(resolution_times)
    max_hours = max(resolution_times)
    median_hours = resolution_times[len(resolution_times) // 2]
    
    def hours_to_readable(hours):
        if hours < 1:
            return f"{hours * 60:.0f} minutes"
        elif hours < 24:
            return f"{hours:.1f} hours"
        else:
            return f"{hours / 24:.1f} days"
    
    mttr_stats = {
        "metric": "MTTR (Mean Time To Resolve)",
        "period_days": days,
        "cases_analyzed": len(resolution_times),
        "mttr_hours": round(avg_hours, 2),
        "mttr_readable": hours_to_readable(avg_hours),
        "min_hours": round(min_hours, 2),
        "min_readable": hours_to_readable(min_hours),
        "max_hours": round(max_hours, 2),
        "max_readable": hours_to_readable(max_hours),
        "median_hours": round(median_hours, 2),
        "median_readable": hours_to_readable(median_hours),
        "generated_at": datetime.now().isoformat()
    }
    
    return json.dumps(mttr_stats, indent=2)


@mcp.tool()
def calculate_mttd(days: int = 90) -> str:
    """Calculate Mean Time To Detect (MTTD)."""
    from datetime import datetime, timedelta
    
    result = make_request("GET", "/manage/cases/list", params={"cid": 1})
    if isinstance(result, dict) and "error" in result:
        return f"Error: {result['error']}"
    
    cases = safe_get_data(result, "data", "cases")
    cutoff_date = datetime.now() - timedelta(days=days)
    
    detection_times = []
    cases_with_timeline = 0
    cases_without_timeline = 0
    
    for case in cases:
        case_id = case.get("case_id")
        open_date_str = case.get("open_date", case.get("case_open_date"))
        
        if not open_date_str:
            continue
        
        try:
            open_date = parse_date_flexible(open_date_str)
            if not open_date:
                continue
            
            if open_date < cutoff_date:
                continue
            
            timeline_result = make_request("GET", "/case/timeline/events/list", params={"cid": case_id})
            
            if "error" not in timeline_result:
                events = safe_get_data(timeline_result, "data", "timeline")
                
                if events:
                    cases_with_timeline += 1
                    earliest_event_date = None
                    
                    for event in events:
                        event_date_str = event.get("event_date", event.get("event_date_wtz"))
                        if not event_date_str:
                            continue
                        
                        try:
                            event_date = parse_date_flexible(event_date_str)
                            if not event_date:
                                continue
                            
                            if earliest_event_date is None or event_date < earliest_event_date:
                                earliest_event_date = event_date
                                
                        except Exception:
                            continue
                    
                    if earliest_event_date and earliest_event_date < open_date:
                        detection_time = (open_date - earliest_event_date).total_seconds() / 3600
                        if detection_time >= 0:
                            detection_times.append(detection_time)
                else:
                    cases_without_timeline += 1
            else:
                cases_without_timeline += 1
                
        except Exception as e:
            logger.warning(f"Error processing case {case_id}: {e}")
            continue
    
    if not detection_times:
        return json.dumps({
            "metric": "MTTD (Mean Time To Detect)",
            "warning": "Insufficient timeline data to calculate MTTD",
            "period_days": days,
            "cases_with_timeline": cases_with_timeline,
            "cases_without_timeline": cases_without_timeline,
            "suggestion": "Ensure cases have timeline events with event_date populated"
        }, indent=2)
    
    detection_times.sort()
    avg_hours = sum(detection_times) / len(detection_times)
    min_hours = min(detection_times)
    max_hours = max(detection_times)
    median_hours = detection_times[len(detection_times) // 2]
    
    def hours_to_readable(hours):
        if hours < 1:
            return f"{hours * 60:.0f} minutes"
        elif hours < 24:
            return f"{hours:.1f} hours"
        else:
            return f"{hours / 24:.1f} days"
    
    mttd_stats = {
        "metric": "MTTD (Mean Time To Detect)",
        "period_days": days,
        "cases_analyzed": len(detection_times),
        "cases_with_timeline": cases_with_timeline,
        "mttd_hours": round(avg_hours, 2),
        "mttd_readable": hours_to_readable(avg_hours),
        "min_hours": round(min_hours, 2),
        "min_readable": hours_to_readable(min_hours),
        "max_hours": round(max_hours, 2),
        "max_readable": hours_to_readable(max_hours),
        "median_hours": round(median_hours, 2),
        "median_readable": hours_to_readable(median_hours),
        "generated_at": datetime.now().isoformat()
    }
    
    return json.dumps(mttd_stats, indent=2)


@mcp.tool()
def get_severity_breakdown(days: int = 90) -> str:
    """Get case severity breakdown by fetching details for each case."""
    from datetime import datetime, timedelta
    
    result = make_request("GET", "/manage/cases/list", params={"cid": 1})
    if isinstance(result, dict) and "error" in result:
        return f"Error: {result['error']}"
    
    cases = safe_get_data(result, "data", "cases")
    cutoff_date = datetime.now() - timedelta(days=days)
    
    severity_counts = {}
    severity_details = {}
    cases_analyzed = 0
    cases_by_severity = {"critical": [], "high": [], "medium": [], "low": [], "informational": [], "unknown": []}
    
    for case in cases:
        case_id = case.get("case_id")
        open_date_str = case.get("open_date", case.get("case_open_date"))
        
        if not open_date_str:
            continue
        
        try:
            for fmt in ["%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f"]:
                try:
                    open_date = datetime.strptime(open_date_str[:19], fmt[:len(open_date_str)])
                    break
                except ValueError:
                    continue
            else:
                open_date = datetime.fromisoformat(open_date_str.replace("Z", "+00:00").split("+")[0])
            
            if open_date < cutoff_date:
                continue
            
            # Fetch case details to get severity
            detail_result = make_request("GET", f"/case", params={"cid": case_id})
            if isinstance(detail_result, dict) and "error" not in detail_result:
                case_data = safe_get_data(detail_result, "data", default={})
                if isinstance(case_data, dict):
                    severity_name = case_data.get("severity", {}).get("severity_name", "Unknown") if isinstance(case_data.get("severity"), dict) else case_data.get("severity_name", "Unknown")
                    severity_id = case_data.get("severity", {}).get("severity_id", 0) if isinstance(case_data.get("severity"), dict) else case_data.get("severity_id", 0)
                    
                    if severity_name not in severity_counts:
                        severity_counts[severity_name] = 0
                        severity_details[severity_name] = {"id": severity_id, "count": 0}
                    
                    severity_counts[severity_name] += 1
                    severity_details[severity_name]["count"] += 1
                    
                    # Categorize for summary
                    sev_lower = severity_name.lower()
                    if "critical" in sev_lower:
                        cases_by_severity["critical"].append({"case_id": case_id, "name": case.get("case_name", "")})
                    elif "high" in sev_lower:
                        cases_by_severity["high"].append({"case_id": case_id, "name": case.get("case_name", "")})
                    elif "medium" in sev_lower or "moderate" in sev_lower:
                        cases_by_severity["medium"].append({"case_id": case_id, "name": case.get("case_name", "")})
                    elif "low" in sev_lower:
                        cases_by_severity["low"].append({"case_id": case_id, "name": case.get("case_name", "")})
                    elif "info" in sev_lower:
                        cases_by_severity["informational"].append({"case_id": case_id, "name": case.get("case_name", "")})
                    else:
                        cases_by_severity["unknown"].append({"case_id": case_id, "name": case.get("case_name", "")})
                    
                    cases_analyzed += 1
                    
        except Exception as e:
            logger.warning(f"Error processing case {case_id}: {e}")
            continue
    
    # Calculate percentages
    severity_percentages = {}
    for sev, count in severity_counts.items():
        severity_percentages[sev] = round((count / cases_analyzed * 100), 1) if cases_analyzed > 0 else 0
    
    result_data = {
        "metric": "Case Severity Breakdown",
        "period_days": days,
        "total_cases_analyzed": cases_analyzed,
        "by_severity": severity_counts,
        "severity_percentages": severity_percentages,
        "severity_details": severity_details,
        "critical_cases": len(cases_by_severity["critical"]),
        "high_cases": len(cases_by_severity["high"]),
        "medium_cases": len(cases_by_severity["medium"]),
        "low_cases": len(cases_by_severity["low"]),
        "informational_cases": len(cases_by_severity["informational"]),
        "cases_list": {
            "critical": cases_by_severity["critical"][:10],  # Top 10 for each
            "high": cases_by_severity["high"][:10]
        },
        "generated_at": datetime.now().isoformat()
    }
    
    return json.dumps(result_data, indent=2)


@mcp.tool()
def calculate_mtta(days: int = 90) -> str:
    """Calculate Mean Time To Acknowledge (MTTA) - time from case creation to first task assignment or note."""
    from datetime import datetime, timedelta
    
    result = make_request("GET", "/manage/cases/list", params={"cid": 1})
    if isinstance(result, dict) and "error" in result:
        return f"Error: {result['error']}"
    
    cases = safe_get_data(result, "data", "cases")
    cutoff_date = datetime.now() - timedelta(days=days)
    
    acknowledge_times = []
    cases_with_data = 0
    cases_without_data = 0
    
    for case in cases:
        case_id = case.get("case_id")
        open_date_str = case.get("open_date", case.get("case_open_date"))
        
        if not open_date_str:
            continue
        
        try:
            # Parse open date
            for fmt in ["%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f"]:
                try:
                    open_date = datetime.strptime(open_date_str[:19], fmt[:len(open_date_str)])
                    break
                except ValueError:
                    continue
            else:
                open_date = datetime.fromisoformat(open_date_str.replace("Z", "+00:00").split("+")[0])
            
            if open_date < cutoff_date:
                continue
            
            first_activity_date = None
            
            # Check tasks for first assignment/update
            tasks_result = make_request("GET", "/case/tasks/list", params={"cid": case_id})
            if isinstance(tasks_result, dict) and "error" not in tasks_result:
                tasks = safe_get_data(tasks_result, "data", "tasks")
                for task in tasks:
                    task_date_str = task.get("task_open_date", task.get("task_last_update"))
                    if task_date_str:
                        try:
                            for fmt in ["%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"]:
                                try:
                                    task_date = datetime.strptime(task_date_str[:26], fmt)
                                    break
                                except ValueError:
                                    continue
                            else:
                                continue
                            
                            if first_activity_date is None or task_date < first_activity_date:
                                first_activity_date = task_date
                        except Exception:
                            continue
            
            # Check notes for first activity
            notes_result = make_request("GET", "/case/notes/groups/list", params={"cid": case_id})
            if isinstance(notes_result, dict) and "error" not in notes_result:
                groups = safe_get_data(notes_result, "data", "groups")
                for group in groups:
                    for note in group.get("notes", []):
                        note_date_str = note.get("note_creationdate", note.get("note_lastupdate"))
                        if note_date_str:
                            try:
                                for fmt in ["%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"]:
                                    try:
                                        note_date = datetime.strptime(note_date_str[:26], fmt)
                                        break
                                    except ValueError:
                                        continue
                                else:
                                    continue
                                
                                if first_activity_date is None or note_date < first_activity_date:
                                    first_activity_date = note_date
                            except Exception:
                                continue
            
            if first_activity_date:
                acknowledge_time = (first_activity_date - open_date).total_seconds() / 3600
                if acknowledge_time >= 0:
                    acknowledge_times.append(acknowledge_time)
                    cases_with_data += 1
            else:
                cases_without_data += 1
                
        except Exception as e:
            logger.warning(f"Error processing case {case_id}: {e}")
            continue
    
    if not acknowledge_times:
        return json.dumps({
            "metric": "MTTA (Mean Time To Acknowledge)",
            "warning": "Insufficient data to calculate MTTA",
            "period_days": days,
            "cases_with_activity": cases_with_data,
            "cases_without_activity": cases_without_data,
            "suggestion": "Ensure cases have tasks or notes with timestamps"
        }, indent=2)
    
    acknowledge_times.sort()
    avg_hours = sum(acknowledge_times) / len(acknowledge_times)
    min_hours = min(acknowledge_times)
    max_hours = max(acknowledge_times)
    median_hours = acknowledge_times[len(acknowledge_times) // 2]
    
    def hours_to_readable(hours):
        if hours < 1:
            return f"{hours * 60:.0f} minutes"
        elif hours < 24:
            return f"{hours:.1f} hours"
        else:
            return f"{hours / 24:.1f} days"
    
    mtta_stats = {
        "metric": "MTTA (Mean Time To Acknowledge)",
        "period_days": days,
        "cases_analyzed": len(acknowledge_times),
        "cases_with_activity": cases_with_data,
        "mtta_hours": round(avg_hours, 2),
        "mtta_readable": hours_to_readable(avg_hours),
        "min_hours": round(min_hours, 2),
        "min_readable": hours_to_readable(min_hours),
        "max_hours": round(max_hours, 2),
        "max_readable": hours_to_readable(max_hours),
        "median_hours": round(median_hours, 2),
        "median_readable": hours_to_readable(median_hours),
        "generated_at": datetime.now().isoformat()
    }
    
    return json.dumps(mtta_stats, indent=2)


@mcp.tool()
def calculate_mttc(days: int = 90) -> str:
    """Calculate Mean Time To Contain (MTTC) - time from case creation to containment task completion."""
    from datetime import datetime, timedelta
    
    result = make_request("GET", "/manage/cases/list", params={"cid": 1})
    if isinstance(result, dict) and "error" in result:
        return f"Error: {result['error']}"
    
    cases = safe_get_data(result, "data", "cases")
    cutoff_date = datetime.now() - timedelta(days=days)
    
    containment_times = []
    cases_with_containment = 0
    cases_without_containment = 0
    
    # Keywords indicating containment activities
    containment_keywords = [
        "contain", "isolate", "isolation", "quarantine", "block", "disable",
        "disconnect", "network isolation", "isolar", "contenção", "bloquear"
    ]
    
    for case in cases:
        case_id = case.get("case_id")
        open_date_str = case.get("open_date", case.get("case_open_date"))
        
        if not open_date_str:
            continue
        
        try:
            # Parse open date
            for fmt in ["%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f"]:
                try:
                    open_date = datetime.strptime(open_date_str[:19], fmt[:len(open_date_str)])
                    break
                except ValueError:
                    continue
            else:
                open_date = datetime.fromisoformat(open_date_str.replace("Z", "+00:00").split("+")[0])
            
            if open_date < cutoff_date:
                continue
            
            containment_date = None
            
            # Check tasks for containment completion
            tasks_result = make_request("GET", "/case/tasks/list", params={"cid": case_id})
            if isinstance(tasks_result, dict) and "error" not in tasks_result:
                tasks = safe_get_data(tasks_result, "data", "tasks")
                for task in tasks:
                    task_title = (task.get("task_title", "") or "").lower()
                    task_status = (task.get("task_status", {}).get("status_name", "") or task.get("task_status_id", "")).lower() if isinstance(task.get("task_status"), dict) else str(task.get("task_status_id", ""))
                    
                    # Check if this is a containment task
                    is_containment = any(kw in task_title for kw in containment_keywords)
                    is_completed = "done" in str(task_status).lower() or "completed" in str(task_status).lower() or task_status == "3"
                    
                    if is_containment and is_completed:
                        task_close_str = task.get("task_close_date", task.get("task_last_update"))
                        if task_close_str:
                            try:
                                for fmt in ["%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"]:
                                    try:
                                        task_close = datetime.strptime(task_close_str[:26], fmt)
                                        break
                                    except ValueError:
                                        continue
                                else:
                                    continue
                                
                                if containment_date is None or task_close < containment_date:
                                    containment_date = task_close
                            except Exception:
                                continue
            
            # Also check timeline for containment events
            timeline_result = make_request("GET", "/case/timeline/events/list", params={"cid": case_id})
            if isinstance(timeline_result, dict) and "error" not in timeline_result:
                events = safe_get_data(timeline_result, "data", "timeline")
                for event in events:
                    event_title = (event.get("event_title", "") or "").lower()
                    event_content = (event.get("event_content", "") or "").lower()
                    
                    is_containment = any(kw in event_title or kw in event_content for kw in containment_keywords)
                    
                    if is_containment:
                        event_date_str = event.get("event_date", event.get("event_date_wtz"))
                        if event_date_str:
                            try:
                                for fmt in ["%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"]:
                                    try:
                                        event_date = datetime.strptime(event_date_str[:26], fmt)
                                        break
                                    except ValueError:
                                        continue
                                else:
                                    continue
                                
                                if containment_date is None or event_date < containment_date:
                                    containment_date = event_date
                            except Exception:
                                continue
            
            if containment_date:
                containment_time = (containment_date - open_date).total_seconds() / 3600
                if containment_time >= 0:
                    containment_times.append(containment_time)
                    cases_with_containment += 1
            else:
                cases_without_containment += 1
                
        except Exception as e:
            logger.warning(f"Error processing case {case_id}: {e}")
            continue
    
    if not containment_times:
        return json.dumps({
            "metric": "MTTC (Mean Time To Contain)",
            "warning": "Insufficient containment data",
            "period_days": days,
            "cases_with_containment": cases_with_containment,
            "cases_without_containment": cases_without_containment,
            "suggestion": "Ensure containment tasks are marked complete with timestamps",
            "containment_keywords": containment_keywords
        }, indent=2)
    
    containment_times.sort()
    avg_hours = sum(containment_times) / len(containment_times)
    min_hours = min(containment_times)
    max_hours = max(containment_times)
    median_hours = containment_times[len(containment_times) // 2]
    
    def hours_to_readable(hours):
        if hours < 1:
            return f"{hours * 60:.0f} minutes"
        elif hours < 24:
            return f"{hours:.1f} hours"
        else:
            return f"{hours / 24:.1f} days"
    
    mttc_stats = {
        "metric": "MTTC (Mean Time To Contain)",
        "period_days": days,
        "cases_analyzed": len(containment_times),
        "cases_with_containment": cases_with_containment,
        "mttc_hours": round(avg_hours, 2),
        "mttc_readable": hours_to_readable(avg_hours),
        "min_hours": round(min_hours, 2),
        "min_readable": hours_to_readable(min_hours),
        "max_hours": round(max_hours, 2),
        "max_readable": hours_to_readable(max_hours),
        "median_hours": round(median_hours, 2),
        "median_readable": hours_to_readable(median_hours),
        "generated_at": datetime.now().isoformat()
    }
    
    return json.dumps(mttc_stats, indent=2)


@mcp.tool()
def get_kpi_dashboard(days: int = 90) -> str:
    """Get comprehensive KPI dashboard with all security metrics (MTTD, MTTA, MTTC, MTTR, Severity)."""
    from datetime import datetime
    import json as json_module
    
    dashboard = {
        "title": "Security Operations KPI Dashboard",
        "period_days": days,
        "generated_at": datetime.now().isoformat(),
        "metrics": {}
    }
    
    # Get MTTD
    try:
        mttd_result = json_module.loads(calculate_mttd(days))
        dashboard["metrics"]["mttd"] = mttd_result
    except Exception as e:
        dashboard["metrics"]["mttd"] = {"error": str(e)}
    
    # Get MTTA
    try:
        mtta_result = json_module.loads(calculate_mtta(days))
        dashboard["metrics"]["mtta"] = mtta_result
    except Exception as e:
        dashboard["metrics"]["mtta"] = {"error": str(e)}
    
    # Get MTTC
    try:
        mttc_result = json_module.loads(calculate_mttc(days))
        dashboard["metrics"]["mttc"] = mttc_result
    except Exception as e:
        dashboard["metrics"]["mttc"] = {"error": str(e)}
    
    # Get MTTR
    try:
        mttr_result = json_module.loads(calculate_mttr(days))
        dashboard["metrics"]["mttr"] = mttr_result
    except Exception as e:
        dashboard["metrics"]["mttr"] = {"error": str(e)}
    
    # Get Severity Breakdown
    try:
        severity_result = json_module.loads(get_severity_breakdown(days))
        dashboard["metrics"]["severity"] = severity_result
    except Exception as e:
        dashboard["metrics"]["severity"] = {"error": str(e)}
    
    # Summary
    summary = {
        "mttd": dashboard["metrics"]["mttd"].get("mttd_readable", "N/A"),
        "mtta": dashboard["metrics"]["mtta"].get("mtta_readable", "N/A"),
        "mttc": dashboard["metrics"]["mttc"].get("mttc_readable", "N/A"),
        "mttr": dashboard["metrics"]["mttr"].get("mttr_readable", "N/A"),
        "critical_cases": dashboard["metrics"]["severity"].get("critical_cases", 0),
        "high_cases": dashboard["metrics"]["severity"].get("high_cases", 0),
        "total_cases": dashboard["metrics"]["severity"].get("total_cases_analyzed", 0)
    }
    dashboard["summary"] = summary
    
    return json.dumps(dashboard, indent=2)


@mcp.tool()
def get_cases_trend(period: str = "monthly", months: int = 6) -> str:
    """Get case creation trend over time."""
    from datetime import datetime, timedelta
    from collections import defaultdict
    
    result = make_request("GET", "/manage/cases/list", params={"cid": 1})
    if isinstance(result, dict) and "error" in result:
        return f"Error: {result['error']}"
    
    cases = safe_get_data(result, "data", "cases")
    cutoff_date = datetime.now() - timedelta(days=months * 30)
    
    period_counts = defaultdict(lambda: {"opened": 0, "closed": 0})
    
    for case in cases:
        open_date_str = case.get("open_date", case.get("case_open_date"))
        close_date_str = case.get("close_date", case.get("case_close_date"))
        
        if not open_date_str:
            continue
        
        try:
            for fmt in ["%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f"]:
                try:
                    open_date = datetime.strptime(open_date_str[:19], fmt[:len(open_date_str)])
                    break
                except ValueError:
                    continue
            else:
                open_date = datetime.fromisoformat(open_date_str.replace("Z", "+00:00").split("+")[0])
            
            if open_date < cutoff_date:
                continue
            
            if period == "daily":
                key = open_date.strftime("%Y-%m-%d")
            elif period == "weekly":
                key = f"{open_date.year}-W{open_date.isocalendar()[1]:02d}"
            else:
                key = open_date.strftime("%Y-%m")
            
            period_counts[key]["opened"] += 1
            
            if close_date_str:
                try:
                    for fmt in ["%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f"]:
                        try:
                            close_date = datetime.strptime(close_date_str[:19], fmt[:len(close_date_str)])
                            break
                        except ValueError:
                            continue
                    else:
                        close_date = datetime.fromisoformat(close_date_str.replace("Z", "+00:00").split("+")[0])
                    
                    if period == "daily":
                        close_key = close_date.strftime("%Y-%m-%d")
                    elif period == "weekly":
                        close_key = f"{close_date.year}-W{close_date.isocalendar()[1]:02d}"
                    else:
                        close_key = close_date.strftime("%Y-%m")
                    
                    period_counts[close_key]["closed"] += 1
                except Exception:
                    pass
                    
        except Exception as e:
            logger.warning(f"Error parsing date: {e}")
            continue
    
    sorted_periods = sorted(period_counts.keys())
    trend_data = []
    
    for p in sorted_periods:
        trend_data.append({
            "period": p,
            "opened": period_counts[p]["opened"],
            "closed": period_counts[p]["closed"],
            "net_change": period_counts[p]["opened"] - period_counts[p]["closed"]
        })
    
    total_opened = sum(p["opened"] for p in trend_data)
    total_closed = sum(p["closed"] for p in trend_data)
    avg_opened = total_opened / len(trend_data) if trend_data else 0
    avg_closed = total_closed / len(trend_data) if trend_data else 0
    
    return json.dumps({
        "period_type": period,
        "months_analyzed": months,
        "total_periods": len(trend_data),
        "total_opened": total_opened,
        "total_closed": total_closed,
        "avg_opened_per_period": round(avg_opened, 1),
        "avg_closed_per_period": round(avg_closed, 1),
        "trend": trend_data,
        "generated_at": datetime.now().isoformat()
    }, indent=2)


@mcp.tool()
def get_soc_dashboard() -> str:
    """Get a comprehensive SOC dashboard with all key metrics."""
    from datetime import datetime, timedelta
    
    result = make_request("GET", "/manage/cases/list", params={"cid": 1})
    if isinstance(result, dict) and "error" in result:
        return f"Error: {result['error']}"
    
    cases = safe_get_data(result, "data", "cases")
    
    total_cases = len(cases)
    open_cases = 0
    closed_cases = 0
    severity_count = {}
    analyst_count = {}
    customer_count = {}
    
    resolution_times = []
    cutoff_30d = datetime.now() - timedelta(days=30)
    cases_last_30d = 0
    closed_last_30d = 0
    
    for case in cases:
        close_date_str = case.get("close_date", case.get("case_close_date"))
        open_date_str = case.get("open_date", case.get("case_open_date"))
        
        if close_date_str:
            closed_cases += 1
        else:
            open_cases += 1
        
        severity = case.get("severity", case.get("case_severity", "unknown"))
        if isinstance(severity, dict):
            severity = severity.get("severity_name", "unknown")
        severity_count[str(severity)] = severity_count.get(str(severity), 0) + 1
        
        owner = case.get("owner", case.get("opened_by", case.get("user", "unassigned")))
        if isinstance(owner, dict):
            owner = owner.get("user_name", owner.get("name", "unassigned"))
        analyst_count[owner] = analyst_count.get(owner, 0) + 1
        
        customer = case.get("customer", case.get("client", case.get("for_customer", "unknown")))
        if isinstance(customer, dict):
            customer = customer.get("customer_name", customer.get("name", "unknown"))
        customer_count[customer] = customer_count.get(customer, 0) + 1
        
        if open_date_str:
            try:
                for fmt in ["%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f"]:
                    try:
                        open_date = datetime.strptime(open_date_str[:19], fmt[:len(open_date_str)])
                        break
                    except ValueError:
                        continue
                else:
                    open_date = datetime.fromisoformat(open_date_str.replace("Z", "+00:00").split("+")[0])
                
                if open_date >= cutoff_30d:
                    cases_last_30d += 1
                    if close_date_str:
                        closed_last_30d += 1
                
                if close_date_str:
                    for fmt in ["%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f"]:
                        try:
                            close_date = datetime.strptime(close_date_str[:19], fmt[:len(close_date_str)])
                            break
                        except ValueError:
                            continue
                    else:
                        close_date = datetime.fromisoformat(close_date_str.replace("Z", "+00:00").split("+")[0])
                    
                    resolution_time = (close_date - open_date).total_seconds() / 3600
                    if resolution_time >= 0:
                        resolution_times.append(resolution_time)
                        
            except Exception:
                pass
    
    if resolution_times:
        avg_mttr = sum(resolution_times) / len(resolution_times)
        if avg_mttr < 24:
            mttr_readable = f"{avg_mttr:.1f} hours"
        else:
            mttr_readable = f"{avg_mttr/24:.1f} days"
    else:
        avg_mttr = None
        mttr_readable = "N/A"
    
    top_analysts = sorted(analyst_count.items(), key=lambda x: x[1], reverse=True)[:5]
    top_customers = sorted(customer_count.items(), key=lambda x: x[1], reverse=True)[:5]
    
    dashboard = {
        "generated_at": datetime.now().isoformat(),
        "summary": {
            "total_cases": total_cases,
            "open_cases": open_cases,
            "closed_cases": closed_cases,
            "open_rate": f"{(open_cases/total_cases*100):.1f}%" if total_cases else "0%",
            "close_rate": f"{(closed_cases/total_cases*100):.1f}%" if total_cases else "0%"
        },
        "last_30_days": {
            "new_cases": cases_last_30d,
            "closed_cases": closed_last_30d,
            "net_change": cases_last_30d - closed_last_30d
        },
        "mttr": {
            "hours": round(avg_mttr, 2) if avg_mttr else None,
            "readable": mttr_readable,
            "cases_analyzed": len(resolution_times)
        },
        "by_severity": severity_count,
        "top_analysts": [{"analyst": a, "cases": c} for a, c in top_analysts],
        "top_customers": [{"customer": c, "cases": n} for c, n in top_customers]
    }
    
    return json.dumps(dashboard, indent=2)


@mcp.tool()
def get_ioc_statistics(case_id: Optional[int] = None) -> str:
    """Get IOC statistics for a specific case."""
    if case_id:
        result = make_request("GET", "/case/ioc/list", params={"cid": case_id})
        if isinstance(result, dict) and "error" in result:
            return f"Error: {result['error']}"
        
        iocs = safe_get_data(result, "data", "ioc")
        
        type_count = {}
        tlp_count = {}
        
        for ioc in iocs:
            ioc_type = ioc.get("ioc_type", "unknown")
            type_count[ioc_type] = type_count.get(ioc_type, 0) + 1
            
            tlp = ioc.get("tlp_name", "unknown")
            tlp_count[tlp] = tlp_count.get(tlp, 0) + 1
        
        return json.dumps({
            "case_id": case_id,
            "total_iocs": len(iocs),
            "by_type": type_count,
            "by_tlp": tlp_count
        }, indent=2)
    else:
        return json.dumps({
            "error": "Global IOC statistics require a case_id parameter",
            "suggestion": "Provide a case_id to get IOC statistics for that case"
        }, indent=2)


@mcp.tool()
def get_asset_statistics(case_id: int) -> str:
    """Get asset statistics for a specific case."""
    result = make_request("GET", "/case/assets/list", params={"cid": case_id})
    if isinstance(result, dict) and "error" in result:
        return f"Error: {result['error']}"
    
    assets = safe_get_data(result, "data", "assets")
    
    type_count = {}
    compromise_count = {
        "compromised": 0,
        "not_compromised": 0,
        "suspected": 0,
        "unknown": 0
    }
    
    for asset in assets:
        asset_type = asset.get("asset_type", "unknown")
        type_count[asset_type] = type_count.get(asset_type, 0) + 1
        
        status_id = asset.get("asset_compromise_status_id", 0)
        if status_id == 1:
            compromise_count["compromised"] += 1
        elif status_id == 2:
            compromise_count["not_compromised"] += 1
        elif status_id == 3:
            compromise_count["suspected"] += 1
        else:
            compromise_count["unknown"] += 1
    
    return json.dumps({
        "case_id": case_id,
        "total_assets": len(assets),
        "by_type": type_count,
        "by_compromise_status": compromise_count
    }, indent=2)


# ==================== MAIN ====================

if __name__ == "__main__":
    print("Starting DFIR-IRIS MCP Server...")
    print(f"IRIS URL: {IRIS_URL}")
    print(f"SSL Verify: {IRIS_VERIFY_SSL}")
    
    # Check if running in SSE mode (for Docker/HTTP)
    if "--sse" in sys.argv or os.getenv("MCP_TRANSPORT") == "sse":
        print("Running in SSE mode with uvicorn...")
        try:
            import uvicorn
            from starlette.applications import Starlette
            from starlette.routing import Route, Mount
            from starlette.responses import JSONResponse
            from mcp.server.sse import SseServerTransport
            
            # Create SSE transport
            sse = SseServerTransport("/messages")
            
            async def handle_sse(request):
                async with sse.connect_sse(
                    request.scope, request.receive, request._send
                ) as streams:
                    await mcp._mcp_server.run(
                        streams[0], streams[1], mcp._mcp_server.create_initialization_options()
                    )
            
            async def handle_messages(request):
                await sse.handle_post_message(request.scope, request.receive, request._send)
            
            async def health_check(request):
                return JSONResponse({"status": "ok", "service": "iris-mcp"})
            
            app = Starlette(
                debug=True,
                routes=[
                    Route("/", endpoint=health_check),
                    Route("/health", endpoint=health_check),
                    Route("/sse", endpoint=handle_sse),
                    Route("/messages", endpoint=handle_messages, methods=["POST"]),
                ],
            )
            
            uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
            
        except ImportError as e:
            print(f"Error: Missing dependencies for SSE mode: {e}")
            print("Install with: pip install uvicorn starlette")
            sys.exit(1)
    else:
        # STDIO mode for local/Claude Desktop direct
        print("Running in STDIO mode...")
        mcp.run(transport="stdio")
