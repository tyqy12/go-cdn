# AI CDN 一键部署节点功能设计

## 1. 概述

### 1.1 目标
实现从主控Web界面一键生成节点部署脚本，节点管理员只需复制脚本执行即可完成部署，无需手动下载源码编译。

### 1.2 核心特性
- **Web界面生成脚本**：在管理界面选择节点参数，一键生成部署命令
- **预编译二进制**：从GitHub Releases或OSS下载预编译的二进制文件
- **自动化配置**：脚本自动完成所有配置，包括环境变量、systemd服务等
- **节点注册**：部署完成后自动向Master注册

## 2. 系统架构

```
┌─────────────────────────────────────────────────────────────────┐
│                        Web Admin UI                              │
│  ┌─────────────┐    ┌──────────────┐    ┌─────────────────┐    │
│  │ 节点列表页   │→   │ 生成部署脚本  │→   │ 复制/下载脚本    │    │
│  └─────────────┘    └──────────────┘    └─────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                        Master API                                │
│  ┌─────────────┐    ┌──────────────┐    ┌─────────────────┐    │
│  │ 参数验证    │    │ 脚本生成器   │    │ 配置模板管理    │    │
│  └─────────────┘    └──────────────┘    └─────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     节点执行脚本                                  │
│  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐   │
│  │ 下载二进制 │→ │ 安装依赖  │→ │ 配置生成  │→ │ 启动服务  │   │
│  └───────────┘  └───────────┘  └───────────┘  └───────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## 3. API设计

### 3.1 生成部署脚本
```http
POST /api/nodes/deploy-script
Content-Type: application/json

{
  "nodeName": "hk-edge-001",
  "nodeType": "edge",        // edge | l2 | core
  "region": "hk",            // hk | cn | us | sg
  "masterAddr": "master.ai-cdn.com:50051",
  "tags": ["production"],
  "options": {
    "installGost": true,
    "installAgent": true,
    "installNodeExporter": true,
    "enableTLS": true
  }
}
```

**响应：**
```json
{
  "success": true,
  "scriptId": "script_abc123",
  "scriptUrl": "/api/nodes/deploy-script/script_abc123/download",
  "expiresAt": "2026-01-04T12:00:00Z"
}
```

### 3.2 获取脚本内容
```http
GET /api/nodes/deploy-script/:scriptId
```

**响应：**
```bash
#!/bin/bash
# AI CDN 一键部署脚本
# 节点名称: hk-edge-001
# 节点类型: edge
# 地区: hk

set -e

# 配置变量
MASTER_ADDR="master.ai-cdn.com:50051"
NODE_TYPE="edge"
REGION="hk"
NODE_NAME="hk-edge-001"
MASTER_TOKEN="generated_token_here"
NODE_ID=""

# 下载预编译二进制
echo "[INFO] 下载AI CDN Agent..."
curl -fsSL "https://releases.ai-cdn.com/v1.0.0/ai-cdn-agent-linux-amd64" \
  -o /usr/local/bin/ai-cdn-agent
chmod +x /usr/local/bin/ai-cdn-agent

# 安装 gost (如需要)
echo "[INFO] 安装gost..."
curl -fsSL "https://github.com/go-gost/gost/releases/download/v3.0.17/gost_3.0.17_linux-amd64.tar.gz" \
  | tar xz -C /tmp
mv /tmp/gost /usr/local/bin/gost

# 创建配置目录
mkdir -p /etc/ai-cdn/agent
mkdir -p /var/lib/ai-cdn/agent
mkdir -p /var/log/ai-cdn/agent

# 生成配置文件
cat > /etc/ai-cdn/agent/agent.yml << 'AGENT_EOF'
# AI CDN Agent 配置
master_addr: ${MASTER_ADDR}
node_type: ${NODE_TYPE}
region: ${REGION}
node_name: ${NODE_NAME}
token: ${MASTER_TOKEN}
AGENT_EOF

# 生成 systemd 服务
cat > /etc/systemd/system/ai-cdn-agent.service << 'SERVICE_EOF'
[Unit]
Description=AI CDN Agent Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ai-cdn-agent -config /etc/ai-cdn/agent/agent.yml
Restart=always
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
SERVICE_EOF

# 启动服务
systemctl daemon-reload
systemctl enable ai-cdn-agent
systemctl start ai-cdn-agent

echo "[INFO] 部署完成！"
echo "[INFO] 节点将在几秒后向Master注册..."
```

### 3.3 下载脚本文件
```http
GET /api/nodes/deploy-script/:scriptId/download
```
返回完整的shell脚本文件下载。

### 3.4 快速安装命令
```http
POST /api/nodes/quick-install
Content-Type: application/json

{
  "masterAddr": "master.ai-cdn.com:50051",
  "nodeType": "edge",
  "region": "hk"
}
```

**响应：**
```json
{
  "success": true,
  "command": "curl -fsSL https://install.ai-cdn.com/agent.sh | bash -s -- --master master.ai-cdn.com:50051 --type edge --region hk"
}
```

## 4. 脚本生成器设计

### 4.1 脚本模板结构
```go
// scripts/deploy-template.sh
// 这是一个模板，实际使用时通过Go模板引擎填充变量

#!/bin/bash
# AI CDN Agent 一键部署脚本
# Generated at: {{ .GeneratedAt }}
# Node Type: {{ .NodeType }}
# Region: {{ .Region }}

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# ==================== 配置 ====================
MASTER_ADDR="{{ .MasterAddr }}"
NODE_TYPE="{{ .NodeType }}"
REGION="{{ .Region }}"
NODE_NAME="{{ .NodeName }}"
MASTER_TOKEN="{{ .MasterToken }}"
CONFIG_DIR="/etc/ai-cdn/agent"
DATA_DIR="/var/lib/ai-cdn/agent"
LOG_DIR="/var/log/ai-cdn/agent"

# ==================== 安装AI CDN Agent ====================
log_info "安装AI CDN Agent..."
AGENT_VERSION="{{ .AgentVersion }}"
AGENT_URL="{{ .BinaryDownloadURL }}/ai-cdn-agent-v${AGENT_VERSION}-linux-amd64"

curl -fsSL "$AGENT_URL" -o /usr/local/bin/ai-cdn-agent
chmod +x /usr/local/bin/ai-cdn-agent
log_info "Agent安装完成: $(ai-cdn-agent -V)"

# ==================== 安装 gost ====================
{{ if .InstallGost }}
log_info "安装gost代理..."
GOST_VERSION="3.0.17"
GOST_URL="https://github.com/go-gost/gost/releases/download/v${GOST_VERSION}/gost_${GOST_VERSION}_linux-amd64.tar.gz"
curl -fsSL "$GOST_URL" | tar xz -C /tmp
mv /tmp/gost /usr/local/bin/gost
chmod +x /usr/local/bin/gost
log_info "gost安装完成: $(gost -V)"
{{ end }}

# ==================== 创建目录 ====================
mkdir -p "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR"

# ==================== 生成配置文件 ====================
cat > "$CONFIG_DIR/agent.yml" << 'EOF'
master_addr: ${MASTER_ADDR}
node_type: ${NODE_TYPE}
region: ${REGION}
node_name: ${NODE_NAME}
token: ${MASTER_TOKEN}
{{ if .InstallGost }}
gost_config: ${CONFIG_DIR}/gost.yml
{{ end }}
EOF

{{ if .InstallGost }}
# gost配置
cat > "$CONFIG_DIR/gost.yml" << 'EOF'
{{ .GostConfigTemplate }}
EOF
{{ end }}

# ==================== 创建 systemd 服务 ====================
cat > /etc/systemd/system/ai-cdn-agent.service << 'EOF'
[Unit]
Description=AI CDN Agent Service
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/local/bin/ai-cdn-agent -config ${CONFIG_DIR}/agent.yml
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=5
StandardOutput=append:${LOG_DIR}/agent.log
StandardError=append:${LOG_DIR}/agent.error.log
LimitNOFILE=1048576
LimitNPROC=65536

[Install]
WantedBy=multi-user.target
EOF

# ==================== 优化系统参数 ====================
cat >> /etc/sysctl.conf << 'EOF'
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_congestion_control = bbr
EOF

cat >> /etc/security/limits.conf << 'EOF'
* soft nofile 1048576
* hard nofile 1048576
EOF

# ==================== 启动服务 ====================
systemctl daemon-reload
systemctl enable ai-cdn-agent
systemctl start ai-cdn-agent

# ==================== 验证 ====================
sleep 2
systemctl status ai-cdn-agent --no-pager

log_info "========================================"
log_info "部署完成!"
log_info "========================================"
log_info "Master地址: ${MASTER_ADDR}"
log_info "节点名称: ${NODE_NAME}"
log_info "节点类型: ${NODE_TYPE}"
log_info "地区: ${REGION}"
log_info ""
log_info "查看日志: journalctl -u ai-cdn-agent -f"
log_info "重启服务: systemctl restart ai-cdn-agent"
log_info "========================================"

# 等待节点注册
log_info "等待节点向Master注册..."
sleep 5

# 检查节点状态
if systemctl is-active --quiet ai-cdn-agent; then
    log_info "Agent服务运行正常，请检查Master控制台确认节点已上线"
else
    log_error "Agent服务启动失败，请查看日志排查问题"
fi
```

### 4.2 配置模板
不同的节点类型和地区有不同的gost配置模板：

```go
// templates/gost-configs.go

package templates

// Edge节点配置 (香港)
var EdgeHKConfig = `
services:
  - name: quic-edge
    addr: :443
    handler:
      type: http3
      chain: upstream
    listener:
      type: quic
      config:
        max-connections: 100000
        max-incoming-streams: 10000
        handshake-timeout: 10s

  - name: websocket
    addr: :8080
    handler:
      type: ws
      chain: upstream
    listener:
      type: tcp
`

// Core节点配置 (大陆)
var CoreCNConfig = `
services:
  - name: relay
    addr: :50051
    handler:
      type: relay
      chain: upstream
    listener:
      type: tcp
      config:
        max-connections: 100000
`

// L2节点配置
var L2Config = `
services:
  - name: l2-relay
    addr: :50052
    handler:
      type: relay
    listener:
      type: tcp
`
```

## 5. 预编译二进制管理

### 5.1 二进制发布流程
```
1. CI/CD 构建
   ├── 编译 Linux AMD64
   ├── 编译 Linux ARM64
   ├── 编译 Darwin AMD64
   └── 编译 Darwin ARM64

2. 上传到 GitHub Releases
   └── 或上传到内部 OSS

3. 更新安装脚本
   └── 自动检测最新版本
```

### 5.2 二进制下载URL结构
```
# GitHub Releases
https://releases.ai-cdn.com/v{version}/ai-cdn-agent-linux-amd64
https://releases.ai-cdn.com/v{version}/ai-cdn-agent-linux-arm64
https://releases.ai-cdn.com/v{version}/ai-cdn-agent-darwin-amd64

# CDN加速
https://cdn.ai-cdn.com/releases/v{version}/ai-cdn-agent-linux-amd64
```

## 6. 前端界面设计

### 6.1 节点列表页增强

在现有 [`Nodes.vue`](web-admin/src/views/Nodes.vue) 基础上添加：

```vue
<template>
  <div class="space-y-6">
    <!-- 工具栏 -->
    <el-card>
      <el-row :gutter="20" justify="end">
        <el-col :span="12">
          <el-button type="primary" @click="showDeployDialog">
            <el-icon><Plus /></el-icon> 添加节点
          </el-button>
        </el-col>
        <el-col :span="12" style="text-align: right">
          <el-button @click="showQuickInstallDialog">
            <el-icon><Download /></el-icon> 快速安装命令
          </el-button>
        </el-col>
      </el-row>
    </el-card>
    
    <!-- 节点表格... -->
  </div>
</template>
```

### 6.2 部署脚本对话框

```vue
<el-dialog v-model="deployDialogVisible" title="生成部署脚本" width="600px">
  <el-form :model="deployForm" label-width="120px">
    <el-form-item label="节点名称">
      <el-input v-model="deployForm.nodeName" placeholder="例如: hk-edge-001" />
    </el-form-item>
    <el-form-item label="节点类型">
      <el-select v-model="deployForm.nodeType">
        <el-option label="边缘节点 (Edge)" value="edge" />
        <el-option label="L2中转节点 (L2)" value="l2" />
        <el-option label="核心节点 (Core)" value="core" />
      </el-select>
    </el-form-item>
    <el-form-item label="地区">
      <el-select v-model="deployForm.region">
        <el-option label="香港" value="hk" />
        <el-option label="大陆" value="cn" />
        <el-option label="新加坡" value="sg" />
        <el-option label="美国" value="us" />
      </el-select>
    </el-form-item>
    <el-form-item label="Master地址">
      <el-input v-model="deployForm.masterAddr" placeholder="master.example.com:50051" />
    </el-form-item>
    <el-form-item label="可选组件">
      <el-checkbox v-model="deployForm.installGost">安装gost代理</el-checkbox>
      <el-checkbox v-model="deployForm.installNodeExporter">安装监控组件</el-checkbox>
    </el-form-item>
  </el-form>
  
  <template #footer>
    <el-button @click="deployDialogVisible = false">取消</el-button>
    <el-button type="primary" @click="generateScript" :loading="generating">
      生成脚本
    </el-button>
  </template>
</el-dialog>

<!-- 脚本展示对话框 -->
<el-dialog v-model="scriptDialogVisible" title="部署脚本" width="800px">
  <el-input
    type="textarea"
    v-model="generatedScript"
    :rows="20"
    readonly
  />
  <template #footer>
    <el-button @click="copyScript">复制脚本</el-button>
    <el-button type="primary" @click="downloadScript">下载脚本</el-button>
  </template>
</el-dialog>
```

### 6.3 快速安装对话框

```vue
<el-dialog v-model="quickInstallDialogVisible" title="快速安装" width="500px">
  <el-alert
    title="使用方法"
    type="info"
    description="在目标服务器上执行以下命令即可完成部署"
    show-icon
  />
  
  <el-input
    type="textarea"
    v-model="quickInstallCommand"
    readonly
    class="mt-4"
  />
  
  <template #footer>
    <el-button @click="quickInstallDialogVisible = false">关闭</el-button>
    <el-button type="primary" @click="copyInstallCommand">复制命令</el</template>
</el-dialog>
```

##-button>
   7. 后端实现

### 7.1 Handler实现

```go
// master/handler/deploy_handler.go

package handler

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"text/template"
	"bytes"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

type DeployRequest struct {
	NodeName   string            `json:"nodeName" binding:"required"`
	NodeType   string            `json:"nodeType" binding:"required,oneof=edge l2 core"`
	Region     string            `json:"region" binding:"required"`
	MasterAddr string            `json:"masterAddr" binding:"required"`
	Tags       []string          `json:"tags"`
	Options    DeployOptions     `json:"options"`
}

type DeployOptions struct {
	InstallGost        bool `json:"installGost"`
	InstallAgent       bool `json:"installAgent"`
	InstallNodeExporter bool `json:"installNodeExporter"`
	EnableTLS          bool `json:"enableTLS"`
}

type ScriptResponse struct {
	Success    bool      `json:"success"`
	ScriptID   string    `json:"scriptId"`
	ScriptURL  string    `json:"scriptUrl"`
	ExpiresAt  time.Time `json:"expiresAt"`
}

// GenerateDeployScript 生成部署脚本
func (s *AgentServer) GenerateDeployScript(c *gin.Context) {
	var req DeployRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 生成token
	token, _ := generateToken()

	// 填充模板数据
	data := &DeployScriptData{
		GeneratedAt:      time.Now().Format(time.RFC3339),
		NodeName:         req.NodeName,
		NodeType:         req.NodeType,
		Region:           req.Region,
		MasterAddr:       req.MasterAddr,
		MasterToken:      token,
		AgentVersion:     "v1.0.0",
		BinaryDownloadURL: "https://releases.ai-cdn.com",
		InstallGost:      req.Options.InstallGost,
		GostConfigTemplate: getGostConfigTemplate(req.NodeType, req.Region),
	}

	// 生成脚本
	script, err := renderDeployScript(data)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 生成脚本ID (简化处理，实际应存储到数据库)
	scriptID := fmt.Sprintf("script_%d", time.Now().UnixNano())

	c.JSON(http.StatusOK, ScriptResponse{
		Success:   true,
		ScriptID:  scriptID,
		ScriptURL: fmt.Sprintf("/api/nodes/deploy-script/%s", scriptID),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	})
}

// GetDeployScript 获取脚本内容
func (s *AgentServer) GetDeployScript(c *gin.Context) {
	scriptID := c.Param("scriptID")
	
	// 从数据库或缓存获取脚本内容
	script, err := getScriptFromStorage(scriptID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "script not found"})
		return
	}

	c.Header("Content-Type", "text/plain")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=deploy-%s.sh", scriptID))
	c.String(http.StatusOK, script)
}

func generateToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func renderDeployScript(data *DeployScriptData) (string, error) {
	tmpl, err := template.New("deploy").Parse(deployScriptTemplate)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}

	return buf.String(), nil
}

func getGostConfigTemplate(nodeType, region string) string {
	// 根据节点类型和地区返回对应配置
	configs := map[string]string{
		"edge-hk": templates.EdgeHKConfig,
		"core-cn": templates.CoreCNConfig,
		"l2-sg":   templates.L2Config,
	}
	return configs[nodeType+"-"+region]
}
```

### 7.2 API路由注册

```go
// master/routes/routes.go

func SetupRoutes(r *gin.Engine, nodeMgr *node.Manager) {
	// 部署脚本相关
	deploy := r.Group("/api/nodes/deploy-script")
	{
		deploy.POST("", handler.GenerateDeployScript)
		deploy.GET("/:scriptId", handler.GetDeployScript)
		deploy.GET("/:scriptId/download", handler.DownloadScript)
	}

	// 快速安装
	quickInstall := r.Group("/api/nodes")
	{
		quickInstall.POST("/quick-install", handler.QuickInstall)
	}
}
```

## 8. 一键安装脚本 (install.sh)

```bash
#!/bin/bash

# AI CDN Agent 一键安装脚本
# 用法: curl -fsSL https://install.ai-cdn.com/agent.sh | bash -s -- [OPTIONS]

set -e

# 默认配置
MASTER_ADDR=""
NODE_TYPE="edge"
REGION="hk"
NODE_NAME=""
AUTO_REGISTER=true

# 安装参数解析
while [[ $# -gt 0 ]]; do
    case $1 in
        --master)
            MASTER_ADDR="$2"
            shift 2
            ;;
        --type)
            NODE_TYPE="$2"
            shift 2
            ;;
        --region)
            REGION="$2"
            shift 2
            ;;
        --name)
            NODE_NAME="$2"
            shift 2
            ;;
        --no-register)
            AUTO_REGISTER=false
            shift
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# 验证参数
if [[ -z "$MASTER_ADDR" ]]; then
    echo "Error: --master 参数必须指定"
    exit 1
fi

# 自动生成节点名称
if [[ -z "$NODE_NAME" ]]; then
    NODE_NAME="${NODE_TYPE}-${REGION}-$(hostname)"
fi

echo "========================================"
echo "AI CDN Agent 一键安装"
echo "========================================"
echo "Master地址: $MASTER_ADDR"
echo "节点类型: $NODE_TYPE"
echo "地区: $REGION"
echo "节点名称: $NODE_NAME"
echo "========================================"

# 安装依赖
echo "[1/6] 检查系统依赖..."
if ! command -v curl &> /dev/null; then
    apt-get update && apt-get install -y curl
fi

# 下载Agent
echo "[2/6] 下载AI CDN Agent..."
AGENT_VERSION="v1.0.0"
AGENT_URL="https://releases.ai-cdn.com/${AGENT_VERSION}/ai-cdn-agent-linux-amd64"

curl -fsSL "$AGENT_URL" -o /usr/local/bin/ai-cdn-agent
chmod +x /usr/local/bin/ai-cdn-agent

echo "Agent版本: $(ai-cdn-agent -V)"

# 创建配置目录
echo "[3/6] 创建配置目录..."
mkdir -p /etc/ai-cdn/agent
mkdir -p /var/lib/ai-cdn/agent
mkdir -p /var/log/ai-cdn/agent

# 生成配置
echo "[4/6] 生成配置文件..."
cat > /etc/ai-cdn/agent/agent.yml << EOF
master_addr: $MASTER_ADDR
node_type: $NODE_TYPE
region: $REGION
node_name: $NODE_NAME
EOF

# 创建服务
echo "[5/6] 创建systemd服务..."
cat > /etc/systemd/system/ai-cdn-agent.service << 'EOF'
[Unit]
Description=AI CDN Agent Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ai-cdn-agent -config /etc/ai-cdn/agent/agent.yml
Restart=always
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload

# 启动服务
echo "[6/6] 启动服务..."
systemctl enable ai-cdn-agent
systemctl start ai-cdn-agent

echo ""
echo "========================================"
echo "安装完成!"
echo "========================================"
echo "服务状态: systemctl status ai-cdn-agent"
echo "查看日志: journalctl -u ai-cdn-agent -f"
echo ""
echo "Agent将在几秒后自动注册到Master: $MASTER_ADDR"
echo "========================================"
```

## 9. 实施计划

### Phase 1: 后端API开发
- [ ] 实现部署脚本生成器
- [ ] 实现脚本存储和获取API
- [ ] 实现快速安装命令API
- [ ] 添加配置模板管理

### Phase 2: 前端界面开发
- [ ] 添加节点部署对话框
- [ ] 添加脚本预览和下载功能
- [ ] 添加快速安装命令展示
- [ ] 完善节点状态展示

### Phase 3: 脚本优化
- [ ] 完善错误处理
- [ ] 添加安装进度反馈
- [ ] 支持安装回滚
- [ ] 支持批量安装

### Phase 4: 基础设施
- [ ] 配置GitHub Actions自动构建
- [ ] 设置CDN分发
- [ ] 添加健康检查脚本
- [ ] 添加卸载脚本

## 10. 注意事项

1. **安全性**
   - 生成的token需要安全存储
   - 脚本下载链接应设置过期时间
   - 考虑使用一次性下载链接

2. **兼容性**
   - 支持Ubuntu 18.04+
   - 支持CentOS 7+
   - 支持Debian 10+
   - 支持ARM64架构

3. **可观测性**
   - 安装日志输出到文件
   - 支持安装过程实时输出
   - 失败时提供错误信息和解决建议

4. **用户体验**
   - 安装过程有清晰的进度提示
   - 安装完成后有检查验证步骤
   - 提供常用操作命令提示
