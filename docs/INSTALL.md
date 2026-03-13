# Installation Guide

## Prerequisites

- Docker Engine 20.10+ and Docker Compose
- DFIR-IRIS v2.4+ running (with API access)
- IRIS Service Account with API Key

## Docker Installation (Recommended)

### 1. Clone the repository

```bash
git clone https://github.com/dfirmesi/iris-mcp-server.git
cd iris-mcp-server
```

### 2. Configure environment

```bash
cp .env.example .env
nano .env
```

Set the following variables:

```env
IRIS_URL=https://iriswebapp_nginx:8443
IRIS_API_KEY=your_api_key_here
IRIS_VERIFY_SSL=false
```

**Note:** When running in Docker alongside IRIS, use the internal container name (`iriswebapp_nginx:8443`) instead of the external URL. Set `IRIS_VERIFY_SSL=false` for Docker internal communication.

### 3. Create required Docker networks

```bash
docker network create iris_frontend 2>/dev/null || true
docker network create dfir-network 2>/dev/null || true
```

If IRIS is already running, the `iris_frontend` network already exists.

### 4. Start the server

```bash
docker compose up -d
```

### 5. Verify

```bash
# Check container status
docker ps | grep iris-mcp

# Check logs
docker logs iris-mcp-server --tail 10

# Test SSE endpoint
timeout 3 curl -s --http1.1 -H "Accept: text/event-stream" http://localhost:3003/sse | head -3
```

## DFIR-MESI Platform Installation

If deploying as part of the DFIR-MESI platform, use the automated script:

```bash
chmod +x install-mcp-servers.sh
sudo ./install-mcp-servers.sh
```

The script handles Docker network creation, Nginx reverse proxy with SSL, and integration with the other MCP servers.

## Nginx Reverse Proxy (for external access)

If you need external HTTPS access (e.g., for Claude Desktop via `mcp-remote`):

```nginx
server {
    listen 443 ssl http2;
    server_name mcp-iris.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/mcp-iris.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/mcp-iris.yourdomain.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:3003;
        proxy_http_version 1.1;
        proxy_set_header Host localhost:3003;
        proxy_set_header Connection "";
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
    }
}
```

**Important:** The `Host` header must be `localhost:PORT` (not the external domain) because FastMCP rejects connections with external hostnames.

## Troubleshooting

### Container restarts immediately

Check logs:
```bash
docker logs iris-mcp-server --tail 20
```

Common causes:
- Missing or invalid `IRIS_API_KEY` in `.env`
- IRIS not reachable from the container (check Docker network)
- Missing Python dependencies

### SSE endpoint returns error

Test IRIS connectivity from inside the container:
```bash
docker exec iris-mcp-server python -c "
import httpx, os
r = httpx.get(os.environ['IRIS_URL'] + '/api/ping',
    headers={'Authorization': 'Bearer ' + os.environ['IRIS_API_KEY']},
    verify=False)
print(r.status_code, r.text[:200])
"
```

### FastMCP rejects external hostname

Ensure Nginx uses `proxy_set_header Host localhost:3003` (not `$host`).
