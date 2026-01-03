#!/bin/bash

# AI CDN Tunnel - 性能压测脚本

set -e

# 配置
HOST="${1:-localhost}"
PORT="${2:-443}"
DURATION="${3:-30s}"
CONNECTIONS="${3:-1000}"
REQUESTS="${4:-10000}"

# 颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }

echo "========================================"
echo " AI CDN Tunnel - 性能压测"
echo "========================================"
echo "测试目标: $HOST:$PORT"
echo "测试时长: $DURATION"
echo "========================================"

# 安装压测工具
if ! command -v hey &> /dev/null; then
    log_info "安装hey压测工具..."
    go install github.com/rakyll/hey@latest
fi

if ! command -v wrk &> /dev/null; then
    log_warn "wrk未安装, 使用hey进行测试"
fi

# 1. 健康检查
log_info "1. 健康检查..."
if curl -sf "http://$HOST:$PORT/health" > /dev/null; then
    log_info "服务健康检查通过"
else
    log_warn "健康检查失败, 但继续测试"
fi

# 2. 连接数测试
log_info "2. 连接数测试 (1000并发, 30秒)..."
hey -n 50000 -c 1000 -d 30s "http://$HOST:$PORT/health" 2>&1 | tee /tmp/benchmark-connections.log

# 3. 吞吐量测试
log_info "3. 吞吐量测试 (500并发, 30秒)..."
hey -n 100000 -c 500 -d 30s "http://$HOST:$PORT/api/v1/nodes" 2>&1 | tee /tmp/benchmark-throughput.log

# 4. 延迟测试
log_info "4. 延迟测试 (100并发, 10000请求)..."
hey -n 10000 -c 100 -q 10 "http://$HOST:$PORT/health" 2>&1 | tee /tmp/benchmark-latency.log

# 5. 持久连接测试
log_info "5. 持久连接测试..."
hey -n 50000 -c 200 -d 30s -keep-alive "http://$HOST:$PORT/health" 2>&1 | tee /tmp/benchmark-keepalive.log

# 分析结果
echo ""
echo "========================================"
echo " 压测结果汇总"
echo "========================================"

# 解析结果
for log in /tmp/benchmark-*.log; do
    if [[ -f "$log" ]]; then
        echo ""
        echo "--- $(basename $log) ---"
        grep -E "(Status code distribution|Response time histogram|Percentiles)" "$log" | head -10
    fi
done

echo ""
log_info "压测日志保存在 /tmp/benchmark-*.log"
log_info "建议使用专业工具进行更详细的压测:"
log_info "  - wrk: wrk -t10 -c500 -d30s http://$HOST:$PORT"
log_info "  - vegeta: echo 'GET http://$HOST:$PORT' | vegeta attack -duration=30s | vegeta report"
log_info "  - h2load: h2load -n 10000 -c 100 https://$HOST:$PORT"
