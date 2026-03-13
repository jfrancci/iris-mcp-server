# DFIR-IRIS MCP Server

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![MCP Protocol](https://img.shields.io/badge/MCP-1.0-green.svg)](https://modelcontextprotocol.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![DFIR-IRIS](https://img.shields.io/badge/DFIR--IRIS-v2.4+-purple.svg)](https://dfir-iris.org/)

**MCP Server for DFIR-IRIS** — Interact with the DFIR-IRIS incident response platform using natural language through Claude AI or any MCP-compatible client.

> Part of the [DFIR-MESI Project](https://github.com/dfirmesi) — Digital Forensics & Incident Response platform combining Wazuh, DFIR-IRIS, and Velociraptor with AI-powered operations.

---

## Overview

This server implements the [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) to expose **35 functions + KPI metrics** from DFIR-IRIS, enabling security analysts to manage incident response cases, IOCs, assets, timelines, and operational metrics through natural language conversations.

```
You: "Show me all open critical cases"
Claude: [Uses list_cases] Found 3 critical cases...

You: "What's our average time to respond?"
Claude: [Uses calculate_mttr] MTTR over the last 30 days is 4.2 hours...

You: "Add the suspicious IP 192.168.1.100 to case #285"
Claude: [Uses add_ioc] IOC added successfully to case #285...
```

## Features

### Case Management (8 functions)
| Function | Description |
|----------|-------------|
| `list_cases` | List all cases with optional status/severity filters |
| `get_case_details` | Get full details of a specific case |
| `filter_cases_by_severity` | Filter cases by severity level |
| `get_case_timeline` | Get chronological timeline of a case |
| `get_case_tasks` | List all tasks in a case |
| `get_case_notes` | Get investigation notes |
| `get_case_evidences` | List evidence items |
| `get_case_summary` | Get case summary with all related data |

### IOC Management (6 functions)
| Function | Description |
|----------|-------------|
| `list_iocs` | List all IOCs across cases |
| `add_ioc` | Add a new IOC to a case |
| `get_ioc_details` | Get details of a specific IOC |
| `get_ioc_types` | List available IOC types |
| `get_ioc_statistics` | IOC statistics by type and case |
| `extract_iocs_for_hunting` | Extract IOCs in hunting-ready format |

### Asset Management (5 functions)
| Function | Description |
|----------|-------------|
| `list_assets` | List all assets in a case |
| `add_asset` | Add an asset to a case |
| `get_asset_details` | Get details of a specific asset |
| `get_asset_types` | List available asset types |
| `get_asset_statistics` | Asset statistics by type |

### KPIs & Metrics (11 functions)
| Function | Description |
|----------|-------------|
| `calculate_mttd` | Mean Time To Detect |
| `calculate_mtta` | Mean Time To Acknowledge |
| `calculate_mttc` | Mean Time To Contain |
| `calculate_mttr` | Mean Time To Respond/Resolve |
| `get_severity_breakdown` | Cases grouped by severity |
| `get_kpi_dashboard` | Comprehensive KPI dashboard |
| `get_cases_by_analyst` | Case distribution by analyst |
| `get_cases_trend` | Case trend over time period |
| `get_open_cases_aging` | Aging analysis of open cases |
| `get_sla_compliance` | SLA compliance metrics |
| `get_operational_summary` | Full operational summary |

### System (5 functions)
| Function | Description |
|----------|-------------|
| `test_connection` | Test connectivity to IRIS |
| `get_iris_version` | Get IRIS version info |
| `list_customers` | List configured customers |
| `get_alerts` | Get recent alerts |
| `get_global_timeline` | Cross-case timeline |

## Quick Start

### Docker (Recommended)

```bash
git clone https://github.com/dfirmesi/iris-mcp-server.git
cd iris-mcp-server
cp .env.example .env
# Edit .env with your IRIS URL and API Key
nano .env
docker compose up -d
```

### Local Development

```bash
git clone https://github.com/dfirmesi/iris-mcp-server.git
cd iris-mcp-server
pip install mcp httpx python-dotenv uvicorn starlette
cp .env.example .env
nano .env
python -m mcp run server.py --transport sse --host 0.0.0.0 --port 8000
```

## Configuration

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `IRIS_URL` | Yes | — | DFIR-IRIS URL (e.g., `https://iris.yourdomain.com`) |
| `IRIS_API_KEY` | Yes | — | API Key from IRIS Service Account |
| `IRIS_VERIFY_SSL` | No | `true` | Verify SSL certificates |
| `LOG_LEVEL` | No | `INFO` | Logging level |

### IRIS API Key

Generate the API Key in DFIR-IRIS:

1. Go to **Advanced → Access control → Users → Add User**
2. Set **Full name**, **Login**, **Email**
3. Check **Use as service account**
4. Click **Save**
5. Edit the user → **Info** tab → Copy the **User API Key**

## Claude Desktop Integration

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "iris": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "https://mcp-iris.yourdomain.com/sse"]
    }
  }
}
```

## Architecture

```
┌─────────────────┐     HTTPS/SSE      ┌──────────────────┐     HTTPS API     ┌──────────────┐
│   Claude AI     │ ──────────────────► │  IRIS MCP Server │ ────────────────► │  DFIR-IRIS   │
│  (MCP Client)   │ ◄────────────────── │  (FastMCP/Python) │ ◄──────────────── │  (Port 8443) │
└─────────────────┘                     └──────────────────┘                   └──────────────┘
                                               │
                                          Docker Network
                                         (iris_frontend)
```

### Docker Deployment

The server runs as a lightweight Python container connecting to IRIS via Docker internal network:

```yaml
# docker-compose.yml
services:
  iris-mcp:
    build: .
    container_name: iris-mcp-server
    ports:
      - "127.0.0.1:3003:8000"
    networks:
      - iris_frontend
```

### Nginx Reverse Proxy

For external access with SSL (handled by `install-mcp-servers.sh`):

```
https://mcp-iris.yourdomain.com → Nginx (SSL) → 127.0.0.1:3003 → container :8000
```

## DFIR-MESI Integration

This MCP Server is part of the DFIR-MESI platform and works alongside:

| Component | MCP Server | Source |
|-----------|-----------|--------|
| **Wazuh** (SIEM/XDR) | [GenSecAI Wazuh MCP](https://github.com/gensecaihq/Wazuh-MCP-Server) | Open-source |
| **Velociraptor** (Forensics) | [SOCFortress Velociraptor MCP](https://github.com/socfortress/velociraptor-mcp-server) | Open-source |
| **DFIR-IRIS** (Case Management) | **This repository** | DFIR-MESI |

### Multi-MCP Workflow Example

```
1. [Wazuh MCP]       → "Show critical alerts from last 24h"
2. [IRIS MCP]         → "Create case for ransomware incident on VADER"
3. [Velociraptor MCP] → "Collect forensic triage from VADER"
4. [IRIS MCP]         → "Add IOCs and update timeline for case #285"
5. [IRIS MCP]         → "What's our MTTR for ransomware cases?"
```

## Development

### Project Structure

```
iris-mcp-server/
├── server.py              # MCP Server (35 functions + KPIs)
├── docker-compose.yml     # Docker Compose
├── .env.example           # Environment template
├── requirements.txt       # Python dependencies
├── LICENSE                # MIT License
├── CHANGELOG.md           # Version history
└── docs/
    ├── INSTALL.md         # Detailed installation guide
    └── ARCHITECTURE.md    # Architecture documentation
```

### Running Tests

```bash
# Test IRIS connectivity
curl -sk -H "Authorization: Bearer YOUR_API_KEY" https://iris.yourdomain.com/api/ping

# Test MCP SSE endpoint
curl -s --http1.1 -H "Accept: text/event-stream" http://localhost:8000/sse | head -3
```

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history.

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [DFIR-IRIS](https://dfir-iris.org/) — Open-source incident response platform
- [Anthropic](https://anthropic.com/) — Model Context Protocol specification
- [FastMCP](https://github.com/jlowin/fastmcp) — Python MCP framework

---

**Made with ❤️ by the DFIR-MESI Project**
