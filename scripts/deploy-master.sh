#!/bin/bash

# AI CDN Tunnel - Master 主控节点部署脚本

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

# 默认配置
CONFIG_DIR="/etc/ai-cdn/master"
DATA_DIR="/var/lib/ai-cdn"
LOG_DIR="/var/log/ai-cdn"
MASTER_VERSION="${MASTER_VERSION:-v1.0.0}"

echo "========================================"
echo " AI CDN Tunnel - Master 部署脚本"
echo "========================================"
echo "版本: $MASTER_VERSION"
echo "配置目录: $CONFIG_DIR"
echo "========================================"

# 1. 检查依赖
log_step "1. 检查系统依赖..."
if ! command -v docker &> /dev/null; then
    log_info "安装Docker..."
    curl -fsSL https://get.docker.com | sh
fi

if ! command -v docker-compose &> /dev/null; then
    log_info "安装Docker Compose..."
    curl -fsSL https://github.com/docker/compose/releases/download/v2.24.0/docker-compose-$(uname -s)-$(uname -m) -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose
fi

# 2. 创建目录
log_step "2. 创建目录结构..."
mkdir -p "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR"

# 3. 复制配置
log_step "3. 复制配置文件..."
if [[ -f "config/master.yml" ]]; then
    cp config/master.yml "$CONFIG_DIR/master.yml"
    log_info "配置文件已复制到 $CONFIG_DIR/master.yml"
else
    log_error "找不到配置文件: config/master.yml"
    exit 1
fi

# 4. 生成环境变量文件
log_step "4. 生成环境变量文件..."
cat > "$CONFIG_DIR/.env" << EOF
# AI CDN Master 环境变量
# 请修改以下配置

# JWT密钥 (必须修改!)
JWT_SECRET=$(openssl rand -base64 32)

# MongoDB
MONGO_URI=mongodb://mongo:27017/ai-cdn

# Redis
REDIS_URL=redis://redis:6379

# 管理员账号
ADMIN_USERNAME=admin
ADMIN_PASSWORD=$(openssl rand -base64 12)

# 节点注册Token
NODE_TOKEN=$(openssl rand -base64 32)
EOF

log_warn "请修改 $CONFIG_DIR/.env 中的配置!"

# 5. 创建docker-compose配置
log_step "5. 创建Docker Compose配置..."
cat > "$CONFIG_DIR/docker-compose.yml" << 'EOF'
version: '3.8'

services:
  master:
    image: ai-cdn/master:${MASTER_VERSION:-latest}
    container_name: ai-cdn-master
    restart: unless-stopped
    ports:
      - "8080:8080"  # HTTP API
      - "50051:50051"  # gRPC
      - "9090:9090"  # Metrics
    volumes:
      - ${CONFIG_DIR}/master.yml:/etc/ai-cdn/master/master.yml:ro
      - ${CONFIG_DIR}/.env:/etc/ai-cdn/master/.env:ro
      - ${DATA_DIR}:/var/lib/ai-cdn
      - ${LOG_DIR}:/var/log/ai-cdn
    environment:
      - CONFIG_PATH=/etc/ai-cdn/master/master.yml
    networks:
      - ai-cdn-network
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
    deploy:
      resources:
        limits:
          memory: 2G
        reservations:
          memory: 1G

  mongo:
    image: mongo:6
    container_name: ai-cdn-mongo
    restart: unless-stopped
    volumes:
      - mongo_data:/data/db
    networks:
      - ai-cdn-network
    environment:
      - MONGO_INITDB_DATABASE=ai-cdn
    healthcheck:
      test: ["CMD", "mongo", "--eval", "db.adminCommand('ping')"]
      interval: 30s
      timeout: 10s
      retries: 3

  redis:
    image: redis:7-alpine
    container_name: ai-cdn-redis
    restart: unless-stopped
    volumes:
      - redis_data:/data
    networks:
      - ai-cdn-network
    command: redis-server --appendonly yes
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 30s
      timeout: 10s
      retries: 3

  # 可选的Grafana
  grafana:
    image: grafana/grafana:10
    container_name: ai-cdn-grafana
    restart: unless-stopped
    ports:
      - "3000:3000"
    volumes:
      - grafana_data:/var/lib/grafana
    networks:
      - ai-cdn-network
    environment:
      - GF_SECURITY_ADMIN_USER=admin
      - GF_SECURITY_ADMIN_PASSWORD=${GF_PASSWORD:-admin123}
      - GF_USERS_ALLOW_SIGN_UP=false
    depends_on:
      - prometheus

  # Prometheus
  prometheus:
    image: prom/prometheus:v2.48
    container_name: ai-cdn-prometheus
    restart: unless-stopped
    ports:
      - "9091:9090"
    volumes:
      - ${CONFIG_DIR}/prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - prometheus_data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--storage.tsdb.retention.time=7d'
      - '--web.enable-lifecycle'
    networks:
      - ai-cdn-network
    depends_on:
      - master

networks:
  ai-cdn-network:
    driver: bridge

volumes:
  mongo_data:
  redis_data:
  grafana_data:
  prometheus_data:
EOF

# 6. 复制Prometheus配置
log_step "6. 复制Prometheus配置..."
if [[ -f "config/prometheus.yml" ]]; then
    cp config/prometheus.yml "$CONFIG_DIR/prometheus.yml"
fi

# 7. 启动服务
log_step "7. 启动服务..."
cd "$CONFIG_DIR"

echo ""
log_warn "开始启动服务，请等待..."
docker-compose up -d

# 8. 等待服务启动
log_step "8. 等待服务启动..."
sleep 10

# 9. 检查服务状态
log_step "9. 检查服务状态..."
docker-compose ps

# 10. 显示访问信息
echo ""
log_info "========================================"
log_info " Master 主控节点部署完成!"
log_info "========================================"
log_info ""
log_info "访问地址:"
log_info "  - Web API: http://localhost:8080"
log_info "  - gRPC: localhost:50051"
log_info "  - Metrics: http://localhost:9091"
log_info "  - Grafana: http://localhost:3000 (admin/admin123)"
log_info ""
log_info "配置文件:"
log_info "  - $CONFIG_DIR/master.yml"
log_info "  - $CONFIG_DIR/.env (请修改密码!)"
log_info ""
log_info "日志查看:"
log_info "  - docker-compose logs -f master"
log_info ""
log_warn "重要: 请立即修改以下密码:"
log_warn "  1. $CONFIG_DIR/.env 中的JWT_SECRET"
log_warn "  2. $CONFIG_DIR/.env 中的ADMIN_PASSWORD"
log_warn "  3. Grafana admin密码"
