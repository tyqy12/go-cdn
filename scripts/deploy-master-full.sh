#!/bin/bash

# Go-CDN Master 主控部署脚本
# 从 GitHub Release 下载并部署 Master + 前端 + MongoDB
# 无需 Docker，直接运行

set -e

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step() { echo -e "${BLUE}[STEP]${NC} $1"; }
log_section() { echo -e "\n${CYAN}======================================== $1 ========================================${NC}"; }

# 默认配置
OWNER="${OWNER:-tyqy12}"
REPO="${REPO:-go-cdn}"
TAG="${TAG:-latest}"
INSTALL_DIR="/opt/go-cdn"
CONFIG_DIR="/etc/go-cdn"
LOG_DIR="/var/log/go-cdn"
DATA_DIR="/var/lib/go-cdn"
SYSTEMD_DIR="/etc/systemd/system"
MONGO_DATA_DIR="$DATA_DIR/mongodb"
WEB_DIST_DIR="$INSTALL_DIR/web"

# MongoDB 配置
MONGO_PORT="${MONGO_PORT:-27017}"
MONGO_USER="${MONGO_USER:-admin}"
MONGO_PASS="${MONGO_PASS:-go-cdn-admin}"

# 前端 API 地址
API_BASE_URL="${API_BASE_URL:-http://localhost:8080}"

# HTTP 服务端口
HTTP_PORT="${HTTP_PORT:-8080}"
GRPC_PORT="${GRPC_PORT:-50051}"
WEB_PORT="${WEB_PORT:-80}"

# 参数解析
while [[ $# -gt 0 ]]; do
    case $1 in
        --owner) OWNER="$2"; shift 2 ;;
        --repo) REPO="$2"; shift 2 ;;
        --tag) TAG="$2"; shift 2 ;;
        --install-dir) INSTALL_DIR="$2"; shift 2 ;;
        --http-port) HTTP_PORT="$2"; shift 2 ;;
        --web-port) WEB_PORT="$2"; shift 2 ;;
        --mongo-port) MONGO_PORT="$2"; shift 2 ;;
        --mongo-user) MONGO_USER="$2"; shift 2 ;;
        --mongo-pass) MONGO_PASS="$2"; shift 2 ;;
        --api-url) API_BASE_URL="$2"; shift 2 ;;
        --skip-mongo) SKIP_MONGO=1; shift ;;
        --skip-web) SKIP_WEB=1; shift ;;
        -h|--help) 
            echo "用法: $0 [选项]"
            echo ""
            echo "选项:"
            echo "  --owner <owner>         GitHub 仓库所有者 (默认: tyqy12)"
            echo "  --repo <repo>           GitHub 仓库名称 (默认: go-cdn)"
            echo "  --tag <tag>             版本标签 (默认: latest)"
            echo "  --install-dir <dir>     安装目录 (默认: /opt/go-cdn)"
            echo "  --http-port <port>      HTTP 服务端口 (默认: 8080)"
            echo "  --web-port <port>       Web 前端端口 (默认: 80)"
            echo "  --mongo-port <port>     MongoDB 端口 (默认: 27017)"
            echo "  --mongo-user <user>     MongoDB 用户名 (默认: admin)"
            echo "  --mongo-pass <pass>     MongoDB 密码 (默认: go-cdn-admin)"
            echo "  --api-url <url>         API 基础地址 (默认: http://localhost:8080)"
            echo "  --skip-mongo            跳过 MongoDB 安装"
            echo "  --skip-web              跳过前端构建"
            echo "  -h, --help              显示帮助信息"
            exit 0
            ;;
        *) log_error "未知参数: $1"; exit 1 ;;
    esac
done

echo ""
log_section "Go-CDN Master 部署脚本"
echo ""
echo "  仓库: $OWNER/$REPO"
echo "  版本: $TAG"
echo "  安装目录: $INSTALL_DIR"
echo "  HTTP端口: $HTTP_PORT"
echo "  Web端口: $WEB_PORT"
echo "  MongoDB端口: $MONGO_PORT"
echo "  配置目录: $CONFIG_DIR"
echo "  日志目录: $LOG_DIR"
echo ""
log_section "开始部署"

# 检查 root 权限
if [[ $EUID -ne 0 ]]; then
    log_warn "建议使用 root 权限运行 (sudo $0)"
fi

# 1. 获取版本信息
log_step "1. 获取版本信息..."
if [[ "$TAG" == "latest" ]]; then
    TAG=$(curl -fsSL "https://api.github.com/repos/$OWNER/$REPO/releases/latest" | grep '"tag_name"' | sed 's/.*": "//;s/".*//')
    log_info "最新版本: $TAG"
fi

# 去掉 tag 中的 v 前缀用于文件名
VERSION=${TAG#v}

# 2. 安装系统依赖
log_step "2. 安装系统依赖..."
if ! command -v curl &> /dev/null; then
    log_info "安装 curl..."
    apt-get update && apt-get install -y curl wget gnupg apt-transport-https ca-certificates
fi

if ! command -v tar &> /dev/null; then
    apt-get install -y tar
fi

if ! command -v unzip &> /dev/null; then
    apt-get install -y unzip
fi

# 3. 创建目录结构
log_step "3. 创建目录结构..."
mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR" "$MONGO_DATA_DIR" "$WEB_DIST_DIR"
chmod +x "$INSTALL_DIR"

# 4. 下载 Master 二进制
log_step "4. 下载 Master 构建产物..."
cd "$INSTALL_DIR"

if [[ ! -f "master" ]]; then
    log_info "下载 master-${VERSION}.tar.gz..."
    curl -fsSL "https://github.com/$OWNER/$REPO/releases/download/$TAG/master-${VERSION}.tar.gz" -o master.tar.gz
    tar -xzf master.tar.gz
    rm -f master.tar.gz
    mv master-linux-amd64 master 2>/dev/null || mv master-* master 2>/dev/null || true
    chmod +x master
    log_info "Master 下载完成"
else
    log_info "Master 已存在，跳过下载"
fi

# 5. 安装 MongoDB (如果需要)
if [[ -z "$SKIP_MONGO" ]]; then
    log_step "5. 安装 MongoDB..."
    
    # 检查是否已安装
    if command -v mongod &> /dev/null; then
        log_info "MongoDB 已安装"
    else
        log_info "安装 MongoDB Community Edition..."
        
        # 添加 MongoDB GPG 密钥
        curl -fsSL "https://www.mongodb.org/static/pgp/server-7.0.asc" | gpg -o /usr/share/keyrings/mongodb-server-7.0.gpg --dearmor
        
        # 添加 MongoDB 仓库
        echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-7.0.gpg ] https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/7.0 multiverse" | tee /etc/apt/sources.list.d/mongodb-org-7.0.list
        
        apt-get update
        apt-get install -y mongodb-org
        
        log_info "MongoDB 安装完成"
    fi
    
    # 创建 MongoDB 配置
    log_info "创建 MongoDB 配置..."
    cat > "$CONFIG_DIR/mongodb.yml" << EOF
storage:
  dbPath: $MONGO_DATA_DIR
  journal:
    enabled: true

systemLog:
  destination: file
  logAppend: true
  path: $LOG_DIR/mongodb.log

net:
  port: $MONGO_PORT
  bindIp: 127.0.0.1

processManagement:
  timeZoneInfo: /usr/share/zoneinfo

security:
  authorization: enabled
EOF
    
    # 创建 MongoDB 用户
    log_info "配置 MongoDB 用户..."
    cat > /tmp/mongo-init.js << EOF
use admin
db.createUser({
    user: "$MONGO_USER",
    pwd: "$MONGO_PASS",
    roles: [
        { role: "root", db: "admin" },
        { role: "readWriteAnyDatabase", db: "admin" }
    ]
})

use ai-cdn
db.createCollection("system.profile")
EOF
    
    # 启动 MongoDB
    log_info "启动 MongoDB..."
    
    # 创建 systemd 服务
    cat > "$SYSTEMD_DIR/go-mongodb.service" << EOF
[Unit]
Description=Go-CDN MongoDB Service
Documentation=https://docs.mongodb.org
After=network.target

[Service]
User=mongodb
Group=mongodb
ExecStart=/usr/bin/mongod -f $CONFIG_DIR/mongodb.yml
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=5
StandardOutput=append:$LOG_DIR/mongodb.log
StandardError=append:$LOG_DIR/mongodb.error.log

# 资源限制
LimitNOFILE=65536
LimitNPROC=65536

# 存储
Environment=DBPATH=$MONGO_DATA_DIR

[Install]
WantedBy=multi-user.target
EOF
    
    mkdir -p "$MONGO_DATA_DIR"
    chown -R mongodb:mongodb "$MONGO_DATA_DIR" 2>/dev/null || true
    
    systemctl daemon-reload
    systemctl enable go-mongodb
    systemctl start go-mongodb
    
    # 等待 MongoDB 启动
    log_info "等待 MongoDB 启动..."
    for i in {1..30}; do
        if mongosh --eval "db.adminCommand('ping')" --quiet 2>/dev/null || mongosh --port "$MONGO_PORT" --eval "db.adminCommand('ping')" --quiet 2>/dev/null || mongo --eval "db.adminCommand('ping')" --quiet 2>/dev/null || mongod --version &>/dev/null; then
            sleep 2
            break
        fi
        sleep 1
    done
    
    # 初始化用户
    log_info "初始化 MongoDB 用户..."
    sleep 3
    if mongosh --quiet --eval "db.adminCommand('usersInfo').users.length" 2>/dev/null | grep -q "0"; then
        mongosh --quiet --file /tmp/mongo-init.js 2>/dev/null || \
        mongo --quiet --file /tmp/mongo-init.js 2>/dev/null || \
        mongosh "mongodb://localhost:$MONGO_PORT/admin" --quiet --file /tmp/mongo-init.js 2>/dev/null || \
        log_warn "MongoDB 用户初始化失败，请手动执行 /tmp/mongo-init.js"
    fi
    rm -f /tmp/mongo-init.js
    
    log_info "MongoDB 安装完成"
fi

# 6. 构建前端 (如果需要)
if [[ -z "$SKIP_WEB" ]]; then
    log_step "6. 构建前端..."
    
    # 检查是否已有构建好的前端
    if [[ -f "web.tar.gz" ]]; then
        log_info "使用已下载的前端包..."
        tar -xzf web.tar.gz -C "$WEB_DIST_DIR"
    else
        # 检查 Node.js
        if ! command -v node &> /dev/null; then
            log_info "安装 Node.js..."
            curl -fsSL "https://deb.nodesource.com/setup_20.x" | bash -
            apt-get install -y nodejs
        fi
        
        # 检查 npm
        if ! command -v npm &> /dev/null; then
            apt-get install -y npm
        fi
        
        # 构建前端
        if [[ -d "web-admin" ]]; then
            log_info "构建前端 (Vue + Vite)..."
            cd web-admin
            
            # 安装依赖
            if [[ ! -d "node_modules" ]]; then
                npm install
            fi
            
            # 设置 API 地址
            export VITE_API_BASE="$API_BASE_URL"
            
            # 构建
            npm run build
            
            # 复制到安装目录
            cd ..
            cp -r web-admin/dist/* "$WEB_DIST_DIR" 2>/dev/null || cp -r web-admin/build/* "$WEB_DIST_DIR" 2>/dev/null || \
            cp -r web-admin/dist/. "$WEB_DIST_DIR" 2>/dev/null || \
            log_warn "前端构建完成，但未找到构建产物，请手动复制"
            
            log_info "前端构建完成"
        else
            log_warn "未找到 web-admin 目录，跳过前端构建"
            log_info "请手动构建前端并复制到 $WEB_DIST_DIR"
        fi
    fi
fi

# 7. 创建 Master 配置
log_step "7. 创建 Master 配置..."
cat > "$CONFIG_DIR/master.yml" << EOF
# Go-CDN Master 配置
# MongoDB 连接配置
mongo:
  uri: "mongodb://${MONGO_USER}:${MONGO_PASS}@127.0.0.1:${MONGO_PORT}/ai-cdn?authSource=admin"

# JWT 密钥配置
jwt:
  secret: "$(openssl rand -base64 32 2>/dev/null || head -c 32 /dev/urandom | base64)"

# API 服务配置
api:
  host: "0.0.0.0"
  port: ${HTTP_PORT}
  cors:
    enabled: true
    origins:
      - "*"

# gRPC 服务配置
grpc:
  host: "0.0.0.0"
  port: ${GRPC_PORT}
  max-connections: 1000

# 监控配置
monitor:
  collect-interval: 10
  retention-days: 7

# 高可用配置
ha:
  enabled: false
  election-name: "go-cdn-master"
  leader-id: "$(hostname)-$(date +%s)"

# 日志配置
logging:
  level: "info"
  format: "json"
EOF

chmod 600 "$CONFIG_DIR/master.yml"

# 8. 创建 Nginx 配置 (用于前端)
log_step "8. 创建 Nginx 配置..."
if command -v nginx &> /dev/null; then
    cat > "$CONFIG_DIR/nginx.conf" << EOF
server {
    listen ${WEB_PORT};
    server_name _;
    root $WEB_DIST_DIR;
    index index.html;

    # Gzip 压缩
    gzip on;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml;
    gzip_min_length 1000;

    # 前端路由支持
    location / {
        try_files \$uri \$uri/ /index.html;
    }

    # API 代理
    location /api/ {
        proxy_pass http://127.0.0.1:${HTTP_PORT}/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
    }

    # gRPC 代理
    location /grpc/ {
        grpc_pass 127.0.0.1:${GRPC_PORT};
        grpc_set_header Host \$host;
        grpc_set_header X-Real-IP \$remote_addr;
    }

    # 健康检查
    location /health {
        proxy_pass http://127.0.0.1:${HTTP_PORT}/health;
    }

    # 静态资源缓存
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
    }

    # 安全头
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
}
EOF
    
    # 创建 Nginx systemd 服务
    cat > "$SYSTEMD_DIR/go-nginx.service" << EOF
[Unit]
Description=Go-CDN Nginx Frontend Service
After=network.target

[Service]
Type=forking
User=root
ExecStart=/usr/sbin/nginx -c $CONFIG_DIR/nginx.conf
ExecReload=/bin/kill -HUP \$MAINPID
ExecStop=/usr/sbin/nginx -s quit
Restart=always
RestartSec=5
StandardOutput=append:$LOG_DIR/nginx.log
StandardError=append:$LOG_DIR/nginx.error.log

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable go-nginx
    
    log_info "Nginx 配置创建完成"
else
    log_warn "Nginx 未安装，前端将无法通过 Web 访问"
    log_info "请安装 Nginx 或使用其他 Web 服务器提供 $WEB_DIST_DIR 目录"
fi

# 9. 创建 Master systemd 服务
log_step "9. 创建 Master 服务..."
cat > "$SYSTEMD_DIR/go-master.service" << EOF
[Unit]
Description=Go-CDN Master Service
After=network.target go-mongodb.service
Wants=go-mongodb.service

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/master -config $CONFIG_DIR/master.yml -http :$HTTP_PORT -grpc :$GRPC_PORT
Restart=always
RestartSec=5
StandardOutput=append:$LOG_DIR/master.log
StandardError=append:$LOG_DIR/master.error.log

# 环境变量
Environment=GOGC=100
Environment=GOMAXPROCS=4

# 资源限制
LimitNOFILE=65536
LimitNPROC=65536

# 健康检查
ExecStartPost=/bin/sleep 2

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable go-master

# 10. 启动服务
log_step "10. 启动服务..."

# 启动 Nginx
if command -v nginx &> /dev/null; then
    systemctl start go-nginx
    log_info "Nginx 服务已启动 (端口: $WEB_PORT)"
fi

# 启动 Master
systemctl start go-master
log_info "Master 服务已启动 (HTTP: $HTTP_PORT, gRPC: $GRPC_PORT)"

# 11. 等待服务启动
log_step "11. 检查服务状态..."
sleep 3

# 12. 显示状态
log_section "部署完成!"

echo ""
log_info "服务状态:"
echo ""

# 检查各服务状态
services=("go-master" "go-mongodb" "go-nginx")
for svc in "${services[@]}"; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        echo -e "  ${GREEN}✓${NC} $svc: 运行中"
        systemctl status "$svc" --no-pager --lines=1 2>/dev/null | sed 's/^/    /'
    elif systemctl list-unit-files "$svc" &>/dev/null; then
        echo -e "  ${YELLOW}○${NC} $svc: 已安装但未运行"
    fi
done

echo ""
log_info "访问地址:"
echo "  - Web 管理界面: http://<你的IP>:${WEB_PORT}"
echo "  - API 接口: http://<你的IP>:${HTTP_PORT}"
echo "  - gRPC 接口: <你的IP>:${GRPC_PORT}"
echo ""

log_info "配置文件: $CONFIG_DIR/master.yml"
log_info "日志目录: $LOG_DIR"
log_info "Web 资源目录: $WEB_DIST_DIR"
log_info "MongoDB 数据目录: $MONGO_DATA_DIR"

echo ""
log_info "常用命令:"
echo "  - 查看 Master 日志: journalctl -u go-master -f"
echo "  - 查看 MongoDB 日志: journalctl -u go-mongodb -f"
echo "  - 查看 Nginx 日志: journalctl -u go-nginx -f"
echo "  - 重启 Master: systemctl restart go-master"
echo "  - 重启所有服务: systemctl restart go-master go-nginx go-mongodb"

echo ""
log_warn "安全建议:"
echo "  1. 修改 $CONFIG_DIR/master.yml 中的 JWT 密钥"
echo "  2. 修改 MongoDB 用户密码"
echo "  3. 配置防火墙只开放必要端口"
echo "  4. 生产环境请使用 HTTPS"

log_section "部署完成!"
