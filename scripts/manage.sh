#!/bin/bash

# AI CDN Tunnel - 管理脚本
# 用法: ./manage.sh {start|stop|restart|status|logs|reload|monitor}

set -e

SERVICE_NAME="gost"
CONFIG_DIR="${CONFIG_DIR:-/etc/gost}"
LOG_DIR="${LOG_DIR:-/var/log/gost}"

# 颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

ACTION="${1:-status}"

case "$ACTION" in
    start)
        log_info "启动 $SERVICE_NAME 服务..."
        systemctl start "$SERVICE_NAME"
        log_info "服务已启动"
        ;;
    
    stop)
        log_info "停止 $SERVICE_NAME 服务..."
        systemctl stop "$SERVICE_NAME"
        log_info "服务已停止"
        ;;
    
    restart)
        log_info "重启 $SERVICE_NAME 服务..."
        systemctl restart "$SERVICE_NAME"
        log_info "服务已重启"
        ;;
    
    status)
        echo "========================================"
        echo " $SERVICE_NAME 服务状态"
        echo "========================================"
        systemctl status "$SERVICE_NAME" --no-pager
        echo ""
        echo "监听端口:"
        ss -tlnp 2>/dev/null | grep -E '(443|8080|80|18080|9090)' || \
        netstat -tlnp 2>/dev/null | grep -E '(443|8080|80|18080|9090)' || echo "无监听端口"
        ;;
    
    logs)
        log_info "查看 $SERVICE_NAME 日志 (Ctrl+C 退出)..."
        journalctl -u "$SERVICE_NAME" -f --since "1 hour ago"
        ;;
    
    reload)
        log_info "重新加载配置..."
        systemctl reload "$SERVICE_NAME"
        log_info "配置已重新加载"
        ;;
    
    monitor)
        log_info "监控模式 - 实时指标 (Ctrl+C 退出)"
        echo ""
        
        while true; do
            clear
            echo "========================================"
            echo " AI CDN Tunnel - 实时监控"
            echo "========================================"
            echo "时间: $(date '+%Y-%m-%d %H:%M:%S')"
            echo ""
            
            # 连接数
            echo "连接数统计:"
            ss -s 2>/dev/null | head -5 || echo "无法获取连接统计"
            echo ""
            
            # 端口监听
            echo "监听端口:"
            ss -tlnp 2>/dev/null | grep -E '(443|8080|80)' || echo "无监听"
            echo ""
            
            # 系统资源
            echo "系统资源:"
            echo "CPU: $(top -bn1 | grep 'Cpu(s)' | awk '{print $2}')%"
            echo "内存: $(free -h | grep Mem | awk '{print $3 "/" $2}')"
            echo "负载: $(uptime | awk -F'load average:' '{print $2}')"
            echo ""
            
            # 进程状态
            echo "进程状态:"
            ps aux | grep -E "[g]ost|[n]ode_exporter" | head -5
            echo ""
            
            # 服务状态
            echo "服务状态:"
            systemctl is-active "$SERVICE_NAME" >/dev/null 2>&1 && \
                echo -e "${GREEN}●${NC} $SERVICE_NAME 运行中" || \
                echo -e "${RED}●${NC} $SERVICE_NAME 未运行"
            
            sleep 5
        done
        ;;
    
    config-check)
        log_info "检查配置文件..."
        if [[ -f "$CONFIG_DIR/gost.yml" ]]; then
            log_info "配置文件存在: $CONFIG_DIR/gost.yml"
            if command -v gost &> /dev/null; then
                log_info "测试配置语法..."
                gost -C "$CONFIG_DIR/gost.yml" -O yaml 2>&1 | head -20
            fi
        else
            log_error "配置文件不存在: $CONFIG_DIR/gost.yml"
        fi
        ;;
    
    backup)
        log_info "备份配置..."
        BACKUP_DIR="/backup/gost-$(date +%Y%m%d-%H%M%S)"
        mkdir -p "$BACKUP_DIR"
        cp -r "$CONFIG_DIR" "$BACKUP_DIR/"
        cp -r "$LOG_DIR" "$BACKUP_DIR/" 2>/dev/null || true
        log_info "备份完成: $BACKUP_DIR"
        ;;
    
    help|*)
        echo "AI CDN Tunnel 管理脚本"
        echo ""
        echo "用法: $0 {命令}"
        echo ""
        echo "可用命令:"
        echo "  start       启动服务"
        echo "  stop        停止服务"
        echo "  restart     重启服务"
        echo "  status      查看状态"
        echo "  logs        查看日志"
        echo "  reload      重新加载配置"
        echo "  monitor     实时监控模式"
        echo "  config-check 检查配置文件"
        echo "  backup      备份配置"
        echo ""
        ;;
esac
