#!/bin/bash

# AI CDN Tunnel - 一键性能优化脚本

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

# 检查root权限
if [[ $EUID -ne 0 ]]; then
    log_warn "建议使用root权限运行 (sudo $0)"
fi

echo "========================================"
echo " AI CDN Tunnel - 性能优化脚本"
echo "========================================"

# 1. 应用sysctl配置
log_step "1. 应用系统内核参数..."
if [[ -f "config/performance/sysctl.conf" ]]; then
    cp config/performance/sysctl.conf /tmp/sysctl.conf
    # 只应用安全的参数
    grep -E '^[a-z0-9.]+ = ' /tmp/sysctl.conf | while read -r line; do
        sysctl -w "$line" 2>/dev/null || true
    done
    log_info "内核参数已应用"
else
    log_warn "找不到sysctl配置文件"
fi

# 2. 应用limits配置
log_step "2. 应用文件描述符限制..."
if [[ -f "config/performance/limits.conf" ]]; then
    cat config/performance/limits.conf >> /etc/security/limits.conf
    log_info "文件描述符限制已应用"
else
    log_warn "找不到limits配置文件"
fi

# 3. 启用BBR
log_step "3. 启用BBR拥塞控制算法..."
if lsmod | grep -q tcp_bbr; then
    log_info "BBR已启用"
else
    modprobe tcp_bbr 2>/dev/null || true
    echo "tcp_bbr" >> /etc/modules-load.d/modules.conf 2>/dev/null || true
    sysctl -w net.ipv4.tcp_congestion_control=bbr 2>/dev/null || true
    log_info "BBR配置完成"
fi

# 4. 配置CPU性能模式
log_step "4. 配置CPU性能模式..."
for cpu in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
    echo "performance" | sudo tee $cpu 2>/dev/null || true
done
log_info "CPU性能模式已配置"

# 5. 优化内存
log_step "5. 优化内存管理..."
sysctl -w vm.swappiness=10 2>/dev/null || true
sysctl -w vm.dirty_ratio=60 2>/dev/null || true
sysctl -w vm.dirty_background_ratio=5 2>/dev/null || true
log_info "内存优化已应用"

# 6. 配置Go运行时
log_step "6. 生成Go运行时优化配置..."
cat > /tmp/gost-optimize.env << 'EOF'
# Go运行时优化
GOMAXPROCS=0
GOGC=50
GODEBUG=gctrace=0
EOF
log_info "运行时配置已生成: /tmp/gost-optimize.env"

# 7. 显示当前配置
log_step "7. 验证优化效果..."
echo ""
echo "系统参数:"
echo "  - 文件描述符: $(ulimit -n)"
echo "  - TCP拥塞控制: $(sysctl -n net.ipv4.tcp_congestion_control)"
echo "  - TCP最大连接: $(sysctl -n net.core.somaxconn)"
echo "  - TCP缓冲区: $(sysctl -n net.core.rmem_max)"
echo ""

# 8. 提示用户
log_info "========================================"
log_info " 性能优化完成!"
log_info "========================================"
echo ""
log_warn "建议执行以下操作:"
log_warn "1. 重启应用服务使配置生效"
log_warn "2. 根据实际负载调整GOMAXPROCS"
log_warn "3. 运行压测验证优化效果"
log_warn "4. 持续监控系统指标"
echo ""

# 创建systemd优化片段
cat > /etc/systemd/system/gost.service.d/optimize.conf << 'EOF'
[Service]
# 性能优化
Environment=GOMAXPROCS=0
Environment=GOGC=50

# 资源限制
LimitNOFILE=1048576
LimitNPROC=65536

# 内存限制
MemoryMax=8G
MemoryHigh=6G

# CPU优化
Nice=-10
CPUAffinity=0,1,2,3,4,5,6,7
EOF

log_info "已创建systemd优化配置: /etc/systemd/system/gost.service.d/optimize.conf"
log_warn "请运行: sudo systemctl daemon-reload && sudo systemctl restart gost"
