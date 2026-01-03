#!/bin/bash

# AI CDN Tunnel - 负载均衡配置
# 用于在多个边缘节点之间进行负载均衡

set -e

# 配置
EDGE_NODES=(
    "hk-1.ai-cdn.local:443"
    "hk-2.ai-cdn.local:443"
    "hk-3.ai-cdn.local:443"
    "sg-1.ai-cdn.local:443"
)

HEALTH_CHECK_INTERVAL=10
ALGORITHM="round_robin"  # round_robin, least_conn, ip_hash, random

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }

# 健康检查
health_check() {
    local node="$1"
    local host=$(echo "$node" | cut -d: -f1)
    local port=$(echo "$node" | cut -d: -f2)
    
    # 简单TCP健康检查
    if timeout 2 bash -c "echo > /dev/tcp/$host/$port" 2>/dev/null; then
        return 0
    else
        return 1
    fi
}

# 更新节点状态
update_node_status() {
    local healthy_nodes=()
    local unhealthy_nodes=()
    
    for node in "${EDGE_NODES[@]}"; do
        if health_check "$node"; then
            healthy_nodes+=("$node")
        else
            unhealthy_nodes+=("$node")
        fi
    done
    
    echo "健康节点: ${#healthy_nodes[@]}"
    echo "不健康节点: ${#unhealthy_nodes[@]}"
    
    return 0
}

# 选择节点（负载均衡算法）
select_node() {
    local healthy_nodes=()
    
    for node in "${EDGE_NODES[@]}"; do
        if health_check "$node"; then
            healthy_nodes+=("$node")
        fi
    done
    
    if [[ ${#healthy_nodes[@]} -eq 0 ]]; then
        log_warn "没有健康的节点可用"
        return 1
    fi
    
    case "$ALGORITHM" in
        round_robin)
            # 简单轮询
            echo "${healthy_nodes[$((RANDOM % ${#healthy_nodes[@]}))]}"
            ;;
        least_conn)
            # 连接数最少（需要获取连接数）
            echo "${healthy_nodes[0]}"
            ;;
        ip_hash)
            # 基于客户端IP
            local client_ip="${CLIENT_IP:-127.0.0.1}"
            local hash=$(echo "$client_ip" | md5sum | cut -c1-8)
            local index=$((16#$hash % ${#healthy_nodes[@]}))
            echo "${healthy_nodes[$index]}"
            ;;
        random)
            # 随机选择
            echo "${healthy_nodes[$RANDOM % ${#healthy_nodes[@]}]}"
            ;;
        *)
            echo "${healthy_nodes[0]}"
            ;;
    esac
}

# 生成Nginx负载均衡配置
generate_nginx_config() {
    cat > /tmp/gost-nginx-lb.conf << EOF
# AI CDN Tunnel - Nginx负载均衡配置
# 生成时间: $(date)

upstream gost_edge {
    least_conn;
    
EOF
    
    for node in "${EDGE_NODES[@]}"; do
        echo "    server $node weight=1;" >> /tmp/gost-nginx-lb.conf
    done
    
    cat >> /tmp/gost-nginx-lb.conf << EOF
    keepalive 32;
}

server {
    listen 443 ssl http2;
    server_name ai-cdn.local;
    
    ssl_certificate /etc/nginx/ssl/server.crt;
    ssl_certificate_key /etc/nginx/ssl/server.key;
    ssl_protocols TLSv1.3;
    ssl_ciphers TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384;
    
    location / {
        proxy_pass https://gost_edge;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        # QUIC/WebSocket支持
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # 超时配置
        proxy_connect_timeout 10s;
        proxy_send_timeout 300s;
        proxy_read_timeout 300s;
        
        # SSL
        proxy_ssl_verify off;
    }
}
EOF
    
    log_info "Nginx配置已生成: /tmp/gost-nginx-lb.conf"
}

# 生成HAProxy配置
generate_haproxy_config() {
    cat > /tmp/gost-haproxy.cfg << EOF
# AI CDN Tunnel - HAProxy负载均衡配置
# 生成时间: $(date)

global
    daemon
    maxconn 100000
    nbthread 4
    
defaults
    mode http
    timeout connect 5s
    timeout client 300s
    timeout server 300s
    timeout check 10s

frontend ai_cdn_frontend
    bind :443 ssl crt /etc/haproxy/serts/server.pem alpn h3,http/1.1
    mode http
    option httpclose
    
    # 路由规则
    acl is_quic hdr_cnt(Alt-Svc) -m gt 0
    use_backend gost_edge if is_quic
    default_backend gost_edge

backend gost_edge
    mode http
    balance roundrobin
    
    # 健康检查
    option httpchk GET /health
    http-check expect status 200
    
EOF
    
    for node in "${EDGE_NODES[@]}"; do
        local host=$(echo "$node" | cut -d: -f1)
        local port=$(echo "$node" | cut -d: -f2)
        echo "    server $host $host:$port check port 80 inter 10s rise 2 fall 3" >> /tmp/gost-haproxy.cfg
    done
    
    log_info "HAProxy配置已生成: /tmp/gost-haproxy.cfg"
}

# 主逻辑
case "${1:-help}" in
    health)
        update_node_status
        ;;
    select)
        select_node
        ;;
    nginx)
        generate_nginx_config
        ;;
    haproxy)
        generate_haproxy_config
        ;;
    monitor)
        while true; do
            echo "========================================"
            echo " 节点健康检查 - $(date '+%Y-%m-%d %H:%M:%S')"
            echo "========================================"
            update_node_status
            echo ""
            sleep "$HEALTH_CHECK_INTERVAL"
        done
        ;;
    help|*)
        echo "AI CDN Tunnel - 负载均衡工具"
        echo ""
        echo "用法: $0 {命令}"
        echo ""
        echo "命令:"
        echo "  health   检查所有节点健康状态"
        echo "  select   选择一个节点（用于测试）"
        echo "  nginx    生成Nginx负载均衡配置"
        echo "  haproxy  生成HAProxy负载均衡配置"
        echo "  monitor  持续监控节点状态"
        echo ""
        ;;
esac
