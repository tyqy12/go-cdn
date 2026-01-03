#!/bin/bash

# Go-CDN 一键部署脚本
# 从 GitHub Release 下载并部署

set -e

# 颜色输出
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
OWNER="${OWNER:-tyqy12}"
REPO="${REPO:-go-cdn}"
TAG="${TAG:-latest}"
INSTALL_DIR="/opt/go-cdn"
CONFIG_DIR="/etc/go-cdn"
LOG_DIR="/var/log/go-cdn"
SYSTEMD_DIR="/etc/systemd/system"

# 参数解析
while [[ $# -gt 0 ]]; do
    case $1 in
        --owner) OWNER="$2"; shift 2 ;;
        --repo) REPO="$2"; shift 2 ;;
        --tag) TAG="$2"; shift 2 ;;
        --install-dir) INSTALL_DIR="$2"; shift 2 ;;
        --type) NODE_TYPE="$2"; shift 2 ;;
        *) log_error "未知参数: $1"; exit 1 ;;
    esac
done

echo "========================================"
echo "Go-CDN 一键部署"
echo "========================================"
echo "仓库: $OWNER/$REPO"
echo "版本: $TAG"
echo "安装目录: $INSTALL_DIR"
echo "========================================"

# 检查 root 权限
if [[ $EUID -ne 0 ]]; then
    log_warn "建议使用 root 权限运行 (sudo $0)"
fi

# 1. 获取最新版本
log_step "1. 获取版本信息..."
if [[ "$TAG" == "latest" ]]; then
    TAG=$(curl -fsSL "https://api.github.com/repos/$OWNER/$REPO/releases/latest" | grep '"tag_name"' | sed 's/.*": "//;s/".*//')
    log_info "最新版本: $TAG"
fi

# 去掉 tag 中的 v 前缀用于文件名
VERSION=${TAG#v}

# 2. 下载构建产物
log_step "2. 下载构建产物..."
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

# 下载 CDN
log_info "下载 cdn-${VERSION}.tar.gz..."
curl -fsSL "https://github.com/$OWNER/$REPO/releases/download/$TAG/cdn-${VERSION}.tar.gz" -o cdn.tar.gz
tar -xzf cdn.tar.gz
rm -f cdn.tar.gz
mv cdn-linux-amd64 cdn

# 下载 Master
log_info "下载 master-${VERSION}.tar.gz..."
curl -fsSL "https://github.com/$OWNER/$REPO/releases/download/$TAG/master-${VERSION}.tar.gz" -o master.tar.gz
tar -xzf master.tar.gz
rm -f master.tar.gz
mv master-linux-amd64 master

# 下载 Agent
log_info "下载 agent-${VERSION}.tar.gz..."
curl -fsSL "https://github.com/$OWNER/$REPO/releases/download/$TAG/agent-${VERSION}.tar.gz" -o agent.tar.gz
tar -xzf agent.tar.gz
rm -f agent.tar.gz
mv agent-linux-amd64 agent

# 3. 创建目录结构
log_step "3. 创建目录结构..."
mkdir -p "$CONFIG_DIR" "$LOG_DIR"
chmod +x cdn master agent

# 4. 创建 systemd 服务
log_step "4. 创建 systemd 服务..."

# CDN 服务
cat > "$SYSTEMD_DIR/go-cdn.service" << EOF
[Unit]
Description=Go-CDN Node Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/cdn -config $CONFIG_DIR/cdn.yml
Restart=always
RestartSec=5
StandardOutput=append:$LOG_DIR/cdn.log
StandardError=append:$LOG_DIR/cdn.error.log

[Install]
WantedBy=multi-user.target
EOF

# Master 服务
cat > "$SYSTEMD_DIR/go-master.service" << EOF
[Unit]
Description=Go-CDN Master Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/master -config $CONFIG_DIR/master.yml
Restart=always
RestartSec=5
StandardOutput=append:$LOG_DIR/master.log
StandardError=append:$LOG_DIR/master.error.log

[Install]
WantedBy=multi-user.target
EOF

# Agent 服务
cat > "$SYSTEMD_DIR/go-agent.service" << EOF
[Unit]
Description=Go-CDN Agent Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/agent -config $CONFIG_DIR/agent.yml
Restart=always
RestartSec=5
StandardOutput=append:$LOG_DIR/agent.log
StandardError=append:$LOG_DIR/agent.error.log

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload

# 5. 启动服务
log_step "5. 启动服务..."
read -p "启动哪个服务? (c/m/a/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Cc]$ ]] || [[ $REPLY =~ ^[Aa]$ ]]; then
    systemctl enable go-cdn
    systemctl start go-cdn
    log_info "CDN 服务已启动"
fi
if [[ $REPLY =~ ^[Mm]$ ]] || [[ $REPLY =~ ^[Aa]$ ]]; then
    systemctl enable go-master
    systemctl start go-master
    log_info "Master 服务已启动"
fi
if [[ $REPLY =~ ^[Aa]$ ]]; then
    systemctl enable go-agent
    systemctl start go-agent
    log_info "Agent 服务已启动"
fi

# 6. 显示状态
log_step "6. 服务状态..."
if systemctl is-active --quiet go-cdn 2>/dev/null; then
    log_info "CDN: 运行中"
    systemctl status go-cdn --no-pager --lines=1
fi
if systemctl is-active --quiet go-master 2>/dev/null; then
    log_info "Master: 运行中"
    systemctl status go-master --no-pager --lines=1
fi
if systemctl is-active --quiet go-agent 2>/dev/null; then
    log_info "Agent: 运行中"
    systemctl status go-agent --no-pager --lines=1
fi

log_info "========================================"
log_info "部署完成!"
log_info "========================================"
log_info "安装目录: $INSTALL_DIR"
log_info "配置目录: $CONFIG_DIR"
log_info "日志目录: $LOG_DIR"
log_info ""
log_info "常用命令:"
log_info "  查看状态: systemctl status go-cdn"
log_info "  查看日志: journalctl -u go-cdn -f"
log_info "  重启服务: systemctl restart go-cdn"
log_info "========================================"
