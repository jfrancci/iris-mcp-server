# IRIS MCP Server - Instalação no Servidor DFIR-MESI

## Passo a Passo de Instalação

### Pré-requisitos
- Docker e Docker Compose instalados
- IRIS rodando (porta 8443)
- API Key do IRIS

---

## PASSO 1: Criar diretório do IRIS MCP

```bash
mkdir -p ~/mcp-servers/iris-mcp
cd ~/mcp-servers/iris-mcp
```

## PASSO 2: Copiar os arquivos

Copie os 3 arquivos para o diretório:
- `server.py`
- `docker-compose.yml`
- `.env.example`

```bash
# Se baixou o pacote ZIP:
cp /path/to/iris-mcp-docker/* ~/mcp-servers/iris-mcp/
```

## PASSO 3: Configurar credenciais

```bash
cd ~/mcp-servers/iris-mcp

# Criar arquivo .env a partir do exemplo
cp .env.example .env

# Editar com suas credenciais
nano .env
```

Conteúdo do `.env`:
```
IRIS_URL=https://localhost:8443
IRIS_API_KEY=SUA_API_KEY_AQUI
IRIS_VERIFY_SSL=false
```

### Onde obter a API Key:
1. Acesse o IRIS: https://SEU_IP:8443
2. Clique no seu usuário (canto superior direito)
3. Vá em **My Settings**
4. Copie a **API Key**

## PASSO 4: Iniciar o container

```bash
cd ~/mcp-servers/iris-mcp
docker-compose up -d
```

## PASSO 5: Verificar se está rodando

```bash
# Ver status do container
docker ps | grep iris-mcp

# Ver logs
docker logs iris-mcp-server

# Testar conexão (deve retornar algo)
curl http://localhost:3003/
```

---

## Configuração do Claude Desktop (na sua máquina local)

Após o container estar rodando no servidor, configure o Claude Desktop na sua máquina:

### Arquivo: claude_desktop_config.json

**Linux:** `~/.config/claude/claude_desktop_config.json`
**macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

Adicione a seção `iris` ao seu arquivo existente:

```json
{
  "mcpServers": {
    "wazuh": {
      ... (manter configuração existente)
    },
    "velociraptor": {
      ... (manter configuração existente)
    },
    "iris": {
      "url": "http://SEU_SERVIDOR_IP:3003/sse"
    }
  }
}
```

**Substitua `SEU_SERVIDOR_IP` pelo IP do servidor dfirmesi (ex: 103.63.30.212)**

---

## Verificação Final

### No servidor:
```bash
# Verificar os 3 MCPs rodando
docker ps --format "table {{.Names}}\t{{.Ports}}\t{{.Status}}" | grep mcp

# Saída esperada:
# iris-mcp-server         127.0.0.1:3003->8000/tcp   Up X minutes
# velociraptor-mcp-server 127.0.0.1:3001->8000/tcp   Up X days
# wazuh-mcp-wrapper       127.0.0.1:3002->8000/tcp   Up X weeks
```

### No Claude Desktop:
Reinicie o Claude Desktop e teste com:
- "Liste os cases do IRIS"
- "Mostre o dashboard do SOC"

---

## Troubleshooting

### Container não inicia
```bash
docker logs iris-mcp-server
```

### Erro de conexão com IRIS
```bash
# Testar se o container consegue acessar o IRIS
docker exec iris-mcp-server curl -k https://localhost:8443/api/ping
```

Se não funcionar com localhost, use o IP da bridge Docker:
```bash
# Descobrir IP do host dentro do Docker
docker exec iris-mcp-server ip route | grep default | awk '{print $3}'

# Atualizar .env com esse IP
IRIS_URL=https://172.17.0.1:8443
```

### Reiniciar container após mudanças no .env
```bash
docker-compose down
docker-compose up -d
```

---

## Estrutura Final

```
~/mcp-servers/
├── wazuh-mcp/              # Wazuh MCP (local venv)
├── Wazuh-MCP-Server/       # Repo clonado
└── iris-mcp/               # NOVO!
    ├── server.py
    ├── docker-compose.yml
    └── .env

Docker containers:
- wazuh-mcp-wrapper       → porta 3002
- velociraptor-mcp-server → porta 3001
- iris-mcp-server         → porta 3003  ← NOVO!
```
