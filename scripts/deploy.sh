#!/bin/bash

# AI CDN Tunnel - 一键部署脚本
# 支持边缘节点和核心节点部署

set -e

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

# 默认配置
NODE_TYPE="${NODE_TYPE:-edge}"
REGION="${REGION:-hk}"
CONFIG_DIR="/etc/gost"
DATA_DIR="/var/lib/gost"
LOG_DIR="/var/log/gost"

# 使用命令行参数覆盖
while [[ $# -gt 0 ]]; do
    case $1 in
        --node-type)
            NODE_TYPE="$2"
            shift 2
            ;;
        --region)
            REGION="$2"
            shift 2
            ;;
        --config-dir)
            CONFIG_DIR="$2"
            shift 2
            ;;
        *)
            log_error "未知参数: $1"
            exit 1
            ;;
    esac
done

echo "========================================"
echo "AI CDN Tunnel - 部署脚本"
echo "========================================"
echo "节点类型: $NODE_TYPE"
echo "地区: $REGION"
echo "配置目录: $CONFIG_DIR"
echo "========================================"

# 检查root权限
if [[ $EUID -ne 0 ]]; then
    log_warn "建议使用root权限运行 (sudo $0)"
fi

# 1. 安装依赖
log_step "1. 检查并安装依赖..."
if ! command -v curl &> /dev/null; then
    log_info "安装curl..."
    apt-get update && apt-get install -y curl
fi

if ! command -v wget &> /dev/null; then
    log_info "安装wget..."
    apt-get install -y wget
fi

# 2. 安装gost
log_step "2. 安装gost..."
GOST_VERSION="${GOST_VERSION:-3.0.17}"
GOST_ARCH="linux-amd64"

if [[ ! -f "/usr/local/bin/gost" ]]; then
    log_info "下载gost v${GOST_VERSION}..."
    curl -fsSL "https://github.com/go-gost/gost/releases/download/v${GOST_VERSION}/gost_${GOST_VERSION}_${GOST_ARCH}.tar.gz" | tar xz -C /tmp
    
    log_info "安装gost到 /usr/local/bin..."
    chmod +x /tmp/gost
    mv /tmp/gost /usr/local/bin/gost
    
    log_info "gost安装完成: $(gost -V)"
else
    log_info "gost已安装: $(gost -V)"
fi

# 3. 创建目录结构
log_step "3. 创建目录结构..."
mkdir -p "$CONFIG_DIR" "{TLS_CERT_PATH%/server.crt}"
mkdir -p "$DATA_DIR"
mkdir -p "$LOG_DIR"

# 4. 生成配置
log_step "4. 生成配置文件..."

# 复制环境配置模板
if [[ ! -f "$CONFIG_DIR/.env" ]]; then
    log_info "复制环境配置模板..."
    if [[ -f "config/env.example" ]]; then
        cp config/env.example "$CONFIG_DIR/.env"
        log_info "请修改 $CONFIG_DIR/.env 中的配置"
    else
        log_error "找不到配置文件模板: config/env.example"
    fi
fi

# 复制gost配置
if [[ "$NODE_TYPE" == "edge" ]]; then
    CONFIG_FILE="$CONFIG_DIR/gost.yml"
    if [[ -f "config/gost-edge-hk.yml" ]]; then
        cp config/gost-edge-hk.yml "$CONFIG_FILE"
        log_info "复制边缘节点配置到 $CONFIG_FILE"
    fi
elif [[ "$NODE_TYPE" == "core" ]]; then
    CONFIG_FILE="$CONFIG_DIR/gost.yml"
    if [[ -f "config/gost-core-cn.yml" ]]; then
        cp config/gost-core-cn.yml "$CONFIG_FILE"
        log_info "复制核心节点配置到 $CONFIG_FILE"
    fi
else
    log_error "未知节点类型: $NODE_TYPE"
    exit 1
fi

# 5. 生成自签名证书（如果没有）
if [[ ! -f "$CONFIG_DIR/certs/server.crt" ]]; then
    log_step "5. 生成自签名TLS证书..."
    mkdir -p "$CONFIG_DIR/certs"
    
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "$CONFIG_DIR/certs/server.key" \
        -out "$CONFIG_DIR/certs/server.crt" \
        -subj "/C=CN/ST=Beijing/L=Beijing/O=AI CDN/CN=*.ai-cdn.local"
    
    log_info "TLS证书生成完成"
fi

# 6. 配置系统参数
log_step "6. 优化系统参数..."

# TCP优化
cat >> /etc/sysctl.conf << EOF

# AI CDN Tunnel 优化
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_max_tw_buckets = 5000
net.ipv4.tcp_tw_reuse = 1
net.ipv4.ip_local_port_range = 1024 65535
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.tcp_congestion_control = bbr
EOF

sysctl -p > /dev/null 2>&1 || log_warn "无法应用sysctl配置"

# 文件描述符限制
if [[ -f "/etc/security/limits.conf" ]]; then
    cat >> /etc/security/limits.conf << EOF

# AI CDN Tunnel
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
EOF
    log_info "文件描述符限制已配置"
fi

# 7. 创建systemd服务
log_step "7. 创建systemd服务..."

SERVICE_FILE="/etc/systemd/system/gost.service"
cat > "$SERVICE_FILE" << EOF
[Unit]
Description=AI CDN Tunnel -Gost Service
Documentation=https://gost.run
After=network.target network-online.target
Wants=network-online.target

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

# 资源限制
LimitNOFILE=1048576
LimitNPROC=65536

# 环境变量
Environment=NODE_TYPE=$NODE_TYPE
Environment=REGION=$REGION
Environment=GOGC=50

# 性能优化
Nice=-10
CPUSchedulingPolicy=fifo
CPUSchedulingPriority=50

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload

# 8. 安装监控组件（可选）
log_step "8. 安装监控组件..."
read -p "是否安装Node Exporter? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    if ! command -v node_exporter &> /dev/null; then
        log_info "安装Node Exporter..."
        curl -fsSL "https://github.com/prometheus/node_exporter/releases/download/v1.8.2/node_exporter-1.8.2.linux-amd64.tar.gz" | tar xz -C /tmp
        cp /tmp/node_exporter-1.8.2.linux-amd64/node_exporter /usr/local/bin/
        log_info "Node Exporter安装完成"
        
        # 创建node_exporter服务
        cat > /etc/systemd/system/node_exporter.service << 'EOF'
[Unit]
Description=Node Exporter

[Service]
Type=simple
ExecStart=/usr/local/bin/node_exporter --collector.disable-defaults --collector.cpu --collector.mem --collector.disk --collector.netdev --collector.uname
Restart=always

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable node_exporter
        systemctl start node_exporter
        log_info "Node Exporter已启动"
    else
        log_info "Node Exporter已安装"
    fi
fi

# 9. 启动服务
log_step "9. 启动服务..."
systemctl enable gost
systemctl start gost

# 10. 检查状态
log_step "10. 检查服务状态..."
sleep 2
systemctl status gost --no-pager

# 11. 显示连接信息
log_info "========================================"
log_info "部署完成!"
log_info "========================================"
log_info "服务状态: systemctl status gost"
log_info "查看日志: journalctl -u gost -f"
log_info "配置文件: $CONFIG_DIR/gost.yml"
log_info "环境配置: $CONFIG_DIR/.env"
log_info "日志目录: $LOG_DIR"
log_info "========================================"

# 显示监听端口
log_info "监听端口:"
ss -tlnp | grep -E '(443|8080|80|18080|9090)' || netstat -tlnp | grep -E '(443|8080|80|18080|9090)' || true

log_info ""
log_warn "请务必修改以下配置:"
log_warn "1. $CONFIG_DIR/.env 中的API_KEYS"
log_warn "2. $CONFIG_DIR/.env 中的认证密码"
log_warn "3. $CONFIG_DIR/certs/server.crt 替换为正式证书"
