package scripts

import (
	"strings"
	"text/template"
)
const DeployScriptTemplate = `#!/bin/bash
# AI CDN Agent 一键部署脚本
# Generated at: {{ .GeneratedAt }}
# Node Type: {{ .NodeType }}
# Region: {{ .Region }}

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $(date '+%Y-%m-%d %H:%M:%S') $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $(date '+%Y-%m-%d %H:%M:%S') $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') $1"; }
log_step() { echo -e "${BLUE}[STEP]${NC} $(date '+%Y-%m-%d %H:%M:%S') $1"; }

# ==================== 配置变量 ====================
MASTER_ADDR="{{ .MasterAddr }}"
NODE_TYPE="{{ .NodeType }}"
REGION="{{ .Region }}"
NODE_NAME="{{ .NodeName }}"
MASTER_TOKEN="{{ .MasterToken }}"
CONFIG_DIR="/etc/ai-cdn/agent"
DATA_DIR="/var/lib/ai-cdn/agent"
LOG_DIR="/var/log/ai-cdn/agent"
AGENT_VERSION="{{ .AgentVersion }}"
BINARY_URL="{{ .BinaryDownloadURL }}"

# 检测系统架构
ARCH=$(uname -m)
if [ "$ARCH" = "x86_64" ]; then
    ARCH="amd64"
elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
    ARCH="arm64"
else
    log_error "不支持的架构: $ARCH"
    exit 1
fi

# ==================== 前置检查 ====================
log_step "开始前置检查..."

# 检查root权限
if [ "$EUID" -ne 0 ]; then
    log_error "请使用root权限运行此脚本"
    exit 1
fi

# 检查curl
if ! command -v curl &> /dev/null; then
    log_warn "curl未安装，尝试安装..."
    if command -v apt-get &> /dev/null; then
        apt-get update && apt-get install -y curl
    elif command -v yum &> /dev/null; then
        yum install -y curl
    elif command -v apk &> /dev/null; then
        apk add curl
    else
        log_error "无法安装curl，请手动安装"
        exit 1
    fi
fi

# 检查系统类型
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_TYPE="$ID"
    OS_VERSION="$VERSION_ID"
    log_info "检测到系统: $OS_TYPE $OS_VERSION"
else
    OS_TYPE="unknown"
fi

log_info "系统检查完成"
log_info "  架构: $ARCH"
log_info "  系统: $OS_TYPE"

# ==================== 安装AI CDN Agent ====================
log_step "安装AI CDN Agent..."

AGENT_URL="$BINARY_URL/v${AGENT_VERSION}/ai-cdn-agent-linux-${ARCH}"
AGENT_BIN="/usr/local/bin/ai-cdn-agent"

log_info "下载Agent: $AGENT_URL"
if ! curl -fsSL "$AGENT_URL" -o "$AGENT_BIN"; then
    log_error "下载Agent失败，请检查网络或版本"
    exit 1
fi

chmod +x "$AGENT_BIN"
log_info "Agent安装完成: $(ai-cdn-agent -V 2>&1 || echo 'version unknown')"

{{ if .InstallNodeExporter }}
# ==================== 安装Node Exporter ====================
log_step "安装Node Exporter..."

EXPORTER_VERSION="1.7.0"
EXPORTER_URL="https://github.com/prometheus/node_exporter/releases/download/v${EXPORTER_VERSION}/node_exporter-${EXPORTER_VERSION}.linux-${ARCH}.tar.gz"
EXPORTER_BIN="/usr/local/bin/node_exporter"

log_info "下载Node Exporter: $EXPORTER_URL"
curl -fsSL "$EXPORTER_URL" | tar xz -C /tmp
mv /tmp/node_exporter-${EXPORTER_VERSION}.linux-${ARCH}/node_exporter "$EXPORTER_BIN"
chmod +x "$EXPORTER_BIN"
rm -rf /tmp/node_exporter-${EXPORTER_VERSION}*

log_info "Node Exporter安装完成"
{{ end }}

{{ if .InstallGost }}
# ==================== 安装 gost ====================
log_step "安装gost代理..."

GOST_VERSION="3.0.17"
GOST_URL="https://github.com/go-gost/gost/releases/download/v${GOST_VERSION}/gost_${GOST_VERSION}_linux-${ARCH}.tar.gz"
GOST_BIN="/usr/local/bin/gost"

log_info "下载gost: $GOST_URL"
curl -fsSL "$GOST_URL" | tar xz -C /tmp
mv /tmp/gost "$GOST_BIN"
chmod +x "$GOST_BIN"
rm -rf /tmp/gost*

log_info "gost安装完成: $(gost -V 2>&1 || echo 'version unknown')"
{{ end }}

# ==================== 创建目录 ====================
log_step "创建目录结构..."

mkdir -p "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR"
chmod 755 "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR"

# ==================== 生成配置文件 ====================
log_step "生成配置文件..."

cat > "$CONFIG_DIR/agent.yml" << EOF
# AI CDN Agent 配置
master_addr: ${MASTER_ADDR}
node_type: ${NODE_TYPE}
region: ${REGION}
node_name: ${NODE_NAME}
token: ${MASTER_TOKEN}

# 高级配置
connection:
  max_idle_conns: 100
  max_idle_conns_per_host: 10
  idle_conn_timeout: 90s

# 健康检查
health_check:
  interval: 30s
  timeout: 10s

# 重试配置
retry:
  max_attempts: 3
  initial_delay: 1s
  max_delay: 30s

{{ if .EnableTLS }}
# TLS配置
tls:
  enabled: true
  skip_verify: false
{{ end }}

{{ if .InstallNodeExporter }}
# 监控配置
metrics:
  enabled: true
  port: 9100
{{ end }}
EOF

{{ if .InstallGost }}
# gost配置
cat > "$CONFIG_DIR/gost.yml" << 'EOF'
# gost代理配置
{{ .GostConfigTemplate }}
EOF
log_info "gost配置已生成"
{{ end }}

{{ if .InstallNodeExporter }}
# node_exporter服务配置
cat > "$CONFIG_DIR/node_exporter.yml" << 'EOF'
# node_exporter配置
collectors:
  enabled:
    - cpu
    - mem
    - disk
    - net
    - loadavg
    - filefd
    - filesystem
    - stat
    - time
    - uname
    - vmstat
    - diskstats
EOF
{{ end }}

log_info "配置文件已生成"

# ==================== 创建 systemd 服务 ====================
log_step "创建systemd服务..."

cat > /etc/systemd/system/ai-cdn-agent.service << 'EOF'
[Unit]
Description=AI CDN Agent Service
Documentation=https://docs.ai-cdn.com
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/local/bin/ai-cdn-agent -config ${CONFIG_DIR}/agent.yml
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=5
StartLimitBurst=5
StartLimitInterval=60s

# 日志配置
StandardOutput=append:${LOG_DIR}/agent.log
StandardError=append:${LOG_DIR}/agent.error.log

# 文件描述符限制
LimitNOFILE=1048576
LimitNPROC=65536

# 内存限制
MemoryMax=1G
MemoryHigh=800M

# 环境变量
Environment=CONFIG_DIR=${CONFIG_DIR}
Environment=LOG_DIR=${LOG_DIR}

[Install]
WantedBy=multi-user.target
EOF

{{ if .InstallNodeExporter }}
# node_exporter服务
cat > /etc/systemd/system/node-exporter.service << 'EOF'
[Unit]
Description=Node Exporter for Prometheus
After=network.target

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/local/bin/node_exporter --config.file=${CONFIG_DIR}/node_exporter.yml
Restart=always
RestartSec=5

StandardOutput=append:${LOG_DIR}/node_exporter.log
StandardError=append:${LOG_DIR}/node_exporter.error.log

[Install]
WantedBy=multi-user.target
EOF
{{ end }}

log_info "systemd服务配置完成"

# ==================== 系统优化 ====================
log_step "应用系统优化..."

# 文件描述符
if ! grep -q "fs.file-max" /etc/sysctl.conf 2>/dev/null; then
    echo "fs.file-max = 1048576" >> /etc/sysctl.conf
fi

if ! grep -q "fs.nr_open" /etc/sysctl.conf 2>/dev/null; then
    echo "fs.nr_open = 1048576" >> /etc/sysctl.conf
fi

# TCP优化
if ! grep -q "net.core.somaxconn" /etc/sysctl.conf 2>/dev/null; then
    echo "net.core.somaxconn = 65535" >> /etc/sysctl.conf
fi

if ! grep -q "net.ipv4.tcp_max_syn_backlog" /etc/sysctl.conf 2>/dev/null; then
    echo "net.ipv4.tcp_max_syn_backlog = 65535" >> /etc/sysctl.conf
fi

# BBR拥塞控制
if [ -f /proc/sys/net/ipv4/tcp_congestion_control ]; then
    if ! grep -q "net.ipv4.tcp_congestion_control = bbr" /etc/sysctl.conf 2>/dev/null; then
        echo "net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.conf
    fi
fi

# 应用sysctl
sysctl -p >/dev/null 2>&1 || true

# 进程限制
if ! grep -q "root soft nofile" /etc/security/limits.conf 2>/dev/null; then
    cat >> /etc/security/limits.conf << 'EOF'
root soft nofile 1048576
root hard nofile 1048576
root soft nproc 65536
root hard nproc 65536
EOF
fi

log_info "系统优化完成"

# ==================== 启动服务 ====================
log_step "启动服务..."

systemctl daemon-reload

{{ if .InstallNodeExporter }}
systemctl enable node-exporter
systemctl start node-exporter
{{ end }}

systemctl enable ai-cdn-agent
systemctl start ai-cdn-agent

# 等待服务启动
sleep 3

# ==================== 验证 ====================
log_step "验证服务状态..."

# 检查Agent状态
if systemctl is-active --quiet ai-cdn-agent; then
    log_info "AI CDN Agent服务运行正常"
else
    log_error "AI CDN Agent服务启动失败"
    log_error "查看日志: journalctl -u ai-cdn-agent -xe"
    exit 1
fi

{{ if .InstallNodeExporter }}
# 检查Node Exporter状态
if systemctl is-active --quiet node-exporter; then
    log_info "Node Exporter服务运行正常"
else
    log_warn "Node Exporter服务启动失败"
fi
{{ end }}

# 显示服务状态
systemctl status ai-cdn-agent --no-pager --lines=5 || true

log_info "========================================"
log_info "  部署完成!"
log_info "========================================"
log_info "Master地址: ${MASTER_ADDR}"
log_info "节点名称: ${NODE_NAME}"
log_info "节点类型: ${NODE_TYPE}"
log_info "地区: ${REGION}"
log_info ""
log_info "常用命令:"
log_info "  查看日志: journalctl -u ai-cdn-agent -f"
log_info "  重启服务: systemctl restart ai-cdn-agent"
log_info "  查看状态: systemctl status ai-cdn-agent"
log_info "========================================"

# 等待节点注册
log_info "等待节点向Master注册..."
for i in {1..10}; do
    sleep 2
    if systemctl is-active --quiet ai-cdn-agent; then
        log_info "Agent运行正常，请检查Master控制台确认节点已上线"
        break
    fi
    if [ $i -eq 10 ]; then
        log_warn "等待超时，但Agent服务仍在运行"
    fi
done

log_info "部署脚本执行完毕"
`

// RenderDeployScript 渲染部署脚本
func RenderDeployScript(data map[string]interface{}) (string, error) {
	tmpl, err := template.New("deploy").Parse(DeployScriptTemplate)
	if err != nil {
		return "", err
	}

	var buf strings.Builder
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}

	return buf.String(), nil
}

// GetDeployScriptContent 获取完整的部署脚本内容
func GetDeployScriptContent(data map[string]interface{}) (string, error) {
	return RenderDeployScript(data)
}
