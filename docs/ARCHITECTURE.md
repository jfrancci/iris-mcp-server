# Architecture

## System Overview

```
                          ┌─────────────────────┐
                          │    Claude Desktop    │
                          │    (MCP Client)      │
                          └──────────┬───────────┘
                                     │ HTTPS/SSE
                                     ▼
                          ┌─────────────────────┐
                          │   Nginx Reverse      │
                          │   Proxy (SSL)        │
                          │   :443 → :3003       │
                          └──────────┬───────────┘
                                     │ HTTP
                                     ▼
┌──────────────────────────────────────────────────────────┐
│                    Docker Environment                     │
│                                                          │
│  ┌──────────────────┐         ┌──────────────────────┐   │
│  │ iris-mcp-server  │  HTTPS  │  iriswebapp_nginx    │   │
│  │ (FastMCP/Python) │────────►│  (DFIR-IRIS :8443)   │   │
│  │ Port: 8000       │         │                      │   │
│  └──────────────────┘         └──────────────────────┘   │
│         │                              │                  │
│    iris_frontend                  iris_backend            │
│    + dfir-network                                        │
└──────────────────────────────────────────────────────────┘
```

## Communication Flow

1. **Claude Desktop** connects to the MCP server via SSE (Server-Sent Events) through Nginx
2. **Nginx** terminates SSL and proxies to the container on port 3003
3. **IRIS MCP Server** receives MCP tool calls and translates them to IRIS API requests
4. **DFIR-IRIS** processes the requests and returns data
5. Results flow back through the same chain to Claude

## Docker Networks

| Network | Purpose |
|---------|---------|
| `iris_frontend` | Communication between MCP server and IRIS Nginx |
| `dfir-network` | Shared network for all DFIR-MESI components |

## Port Mapping

| Service | Container Port | Host Port | Access |
|---------|---------------|-----------|--------|
| IRIS MCP Server | 8000 | 127.0.0.1:3003 | Nginx proxy |
| DFIR-IRIS | 8443 | 0.0.0.0:8443 | Direct + Nginx |

## Authentication

The MCP server authenticates with IRIS using a **Service Account API Key** passed via the `IRIS_API_KEY` environment variable. All requests include the `Authorization: Bearer <key>` header.

No authentication is required between Claude and the MCP server itself — access control is handled at the Nginx level (SSL + network restrictions).
