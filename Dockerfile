FROM python:3.13-slim

LABEL maintainer="DFIR-MESI Project"
LABEL description="DFIR-IRIS MCP Server - Model Context Protocol for incident response"

WORKDIR /app

# Install Python dependencies
RUN pip install --no-cache-dir \
    mcp \
    httpx \
    python-dotenv \
    uvicorn \
    starlette

# Copy server code
COPY server.py /app/
COPY .env* /app/

EXPOSE 8000

CMD ["python", "-m", "mcp", "run", "server.py:mcp", "--transport", "sse", "--host", "0.0.0.0", "--port", "8000"]
