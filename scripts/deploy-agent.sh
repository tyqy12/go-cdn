#!/bin/bash

# AI CDN Tunnel - Agent 被控节点部署脚本

set -e

# 颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step() { echo -e "${BLUE}[STEP]${NC} $1"; }

# 配置
CONFIG_DIR="/etc/ai-cdn/agent"
DATA_DIR="/var/lib/ai-cdn/agent"
LOG_DIR="/var/log/ai-cdn/agent"
MASTER_ADDR="${1:-master.ai-cdn.local:50051}"

# 命令行参数
NODE_TYPE="${2:-edge}"
REGION="${3:-hk}"
NODE_NAME="${4:-}"

echo "========================================"
echo " AI CDN Tunnel - Agent 部署脚本"
echo "========================================"
echo "Master地址: $MASTER_ADDR"
echo "节点类型: $NODE_TYPE"
echo "地区: $REGION"
echo "节点名称: $NODE_NAME"
echo "========================================"

# 1. 检查依赖
log_step "1. 检查系统依赖..."
if ! command -v curl &> /dev/null; then
    apt-get update && apt-get install -y curl wget
fi

# 2. 创建目录
log_step "2. 创建目录结构..."
mkdir -p "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR"

# 3. 安装gost
log_step "3. 安装gost..."
GOST_VERSION="${GOST_VERSION:-3.0.17}"
GOST_ARCH="linux-amd64"

if [[ ! -f "/usr/local/bin/gost" ]]; then
    log_info "下载gost v${GOST_VERSION}..."
    curl -fsSL "https://github.com/go-gost/gost/releases/download/v${GOST_VERSION}/gost_${GOST_VERSION}_${GOST_ARCH}.tar.gz" | tar xz -C /tmp
    chmod +x /tmp/gost
    mv /tmp/gost /usr/local/bin/gost
    log_info "gost安装完成: $(gost -V)"
else
    log_info "gost已安装: $(gost -V)"
fi

# 4. 安装Agent
log_step "4. 安装Agent..."
# 编译Agent (如果有源码)
if [[ -f "cmd/agent/main.go" ]]; then
    log_info "编译Agent..."
    go build -o /usr/local/bin/ai-cdn-agent ./cmd/agent
    log_info "Agent编译完成"
else
    log_warn "未找到Agent源码，跳过编译"
    log_info "请先编译Agent: go build -o ai-cdn-agent ./cmd/agent"
fi

# 5. 复制Agent配置
log_step "5. 复制Agent配置..."
if [[ -f "config/agent.yml" ]]; then
    cp config/agent.yml "$CONFIG_DIR/agent.yml"
    log_info "配置文件已复制到 $CONFIG_DIR/agent.yml"
fi

# 6. 生成环境变量文件
log_step "6. 生成环境变量文件..."
cat > "$CONFIG_DIR/.env" << EOF
# AI CDN Agent 环境变量
MASTER_ADDR=$MASTER_ADDR
NODE_TYPE=$NODE_TYPE
REGION=$REGION
NODE_NAME=$NODE_NAME
NODE_ID=
MASTER_TOKEN=${MASTER_TOKEN:-$(openssl rand -base64 32)}

# gost配置
GOST_CONFIG_PATH=$CONFIG_DIR/gost.yml
EOF

log_warn "请确保Master节点的NODE_TOKEN与这里的MASTER_TOKEN一致!"

# 7. 复制gost配置
log_step "7. 复制gost配置..."
if [[ "$NODE_TYPE" == "edge" ]]; then
    if [[ -f "config/gost-edge-hk.yml" ]]; then
        cp config/gost-edge-hk.yml "$CONFIG_DIR/gost.yml"
        log_info "复制边缘节点配置"
    fi
elif [[ "$NODE_TYPE" == "core" ]]; then
    if [[ -f "config/gost-core-cn.yml" ]]; then
        cp config/gost-core-cn.yml "$CONFIG_DIR/gost.yml"
        log_info "复制核心节点配置"
    fi
fi

# 8. 优化系统参数
log_step "8. 优化系统参数..."
cat >> /etc/sysctl.conf << EOF

# AI CDN Agent 优化
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_congestion_control = bbr
EOF

sysctl -p > /dev/null 2>&1 || true

# 9. 配置文件描述符
cat >> /etc/security/limits.conf << EOF

# AI CDN Agent
* soft nofile 1048576
* hard nofile 1048576
EOF

# 10. 创建systemd服务
log_step "10. 创建systemd服务..."
cat > /etc/systemd/system/ai-cdn-agent.service << EOF
[Unit]
Description=AI CDN Tunnel - Agent Service
Documentation=https://github.com/ai-cdn-tunnel
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/local/bin/ai-cdn-agent -config $CONFIG_DIR/agent.yml
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=5
StandardOutput=append:$LOG_DIR/agent.log
StandardError=append:$LOG_DIR/agent.error.log

# 资源限制
LimitNOFILE=1048576
LimitNPROC=65536

# 环境变量
Environment=NODE_TYPE=$NODE_TYPE
Environment=REGION=$REGION
Environment=MASTER_ADDR=$MASTER_ADDR

# 性能优化
Nice=-10
CPUSchedulingPolicy=fifo
CPUSchedulingPriority=50

[Install]
WantedBy=multi-user.target
EOF

# 同时创建gost服务
cat > /etc/systemd/system/gost.service << EOF
[Unit]
Description=AI CDN Tunnel - GOST Service
After=network.target

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/local/bin/gost -C $CONFIG_DIR/gost.yml
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=5
StandardOutput=append:$LOG_DIR/gost.log
StandardError=append:$LOG_DIR/gost.error.log
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload

# 11. 启动服务
log_step "11. 启动服务..."
systemctl enable ai-cdn-agent
systemctl start ai-cdn-agent

systemctl enable gost
systemctl start gost

# 12. 检查状态
log_step "12. 检查服务状态..."
sleep 3
systemctl status ai-cdn-agent --no-pager
systemctl status gost --no-pager

# 显示监听端口
echo ""
log_info "监听端口:"
ss -tlnp | grep -E '(443|8080|80|50051|9090)' || true

# 13. 显示连接信息
echo ""
log_info "========================================"
log_info " Agent 被控节点部署完成!"
log_info "========================================"
log_info ""
log_info "服务状态:"
log_info "  - Agent: systemctl status ai-cdn-agent"
log_info "  - GOST:  systemctl status gost"
log_info ""
log_info "日志查看:"
log_info "  - Agent: journalctl -u ai-cdn-agent -f"
log_info "  - GOST:  journalctl -u gost -f"
log_info ""
log_info "配置文件:"
log_info "  - $CONFIG_DIR/agent.yml"
log_info "  - $CONFIG_DIR/gost.yml"
log_info "  - $CONFIG_DIR/.env"
log_info ""
log_warn "请确保Master节点已启动并配置正确的NODE_TOKEN!"
