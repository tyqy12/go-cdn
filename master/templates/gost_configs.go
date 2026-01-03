package templates

import "strings"

// GostConfig gost代理配置
type GostConfig struct {
	Name     string
	Services string
}

// GetAllGostConfigs 获取所有gost配置模板
func GetAllGostConfigs() map[string]string {
	return map[string]string{
		// Edge节点 - 香港
		"edge-hk": EdgeHKConfig,
		// Edge节点 - 大陆
		"edge-cn": EdgeCNConfig,
		// Edge节点 - 新加坡
		"edge-sg": EdgeSGConfig,
		// Edge节点 - 美国
		"edge-us": EdgeUSConfig,
		// L2节点 - 香港
		"l2-hk": L2HKConfig,
		// L2节点 - 大陆
		"l2-cn": L2CNConfig,
		// L2节点 - 新加坡
		"l2-sg": L2SGConfig,
		// L2节点 - 美国
		"l2-us": L2USConfig,
		// Core节点 - 香港
		"core-hk": CoreHKConfig,
		// Core节点 - 大陆
		"core-cn": CoreCNConfig,
		// Core节点 - 新加坡
		"core-sg": CoreSGConfig,
		// Core节点 - 美国
		"core-us": CoreUSConfig,
	}
}

// EdgeHKConfig 边缘节点 - 香港配置
// 支持HTTP/3 QUIC和WebSocket
const EdgeHKConfig = `# AI CDN Edge Node - Hong Kong
# 支持HTTP/3 QUIC, WebSocket, HTTP/2

services:
  # QUIC/HTTP3 服务 - 端口443
  - name: quic-edge
    addr: :443
    handler:
      type: http3
      chain: upstream
    listener:
      type: quic
      config:
        max-connections: 100000
        max-incoming-streams: 10000
        handshake-timeout: 10s
        keepalive-period: 30s
        disable-reuse-port: false

  # WebSocket 服务 - 端口8080
  - name: websocket
    addr: :8080
    handler:
      type: ws
      chain: upstream
    listener:
      type: tcp
      config:
        max-connections: 100000
        read-buffer-size: 8192
        write-buffer-size: 8192

  # HTTP/2 服务 - 端口8443
  - name: http2-edge
    addr: :8443
    handler:
      type: http2
      chain: upstream
    listener:
      type: tcp
      config:
        max-connections: 100000

  # SOCKS5 服务 - 端口1080
  - name: socks5
    addr: :1080
    handler:
      type: socks5
      chain: upstream
    listener:
      type: tcp
      config:
        max-connections: 50000

# 链配置 - 上游代理
chains:
  - name: upstream
    hops:
      - name: h1
        nodes:
          - name: master
            addr: ${MASTER_ADDR}
            connector:
              type: http
            dialer:
              type: tcp
            tls:
              enabled: true
              server-name: ${MASTER_ADDR}

# 入口配置
ingress:
  - name: edge-ingress
    entry:
      - :443
      - :8080
      - :8443
      - :1080
    rules:
      - host: cdn.ai-cdn.com
      - host: "*.ai-cdn.com"
`

// EdgeCNConfig 边缘节点 - 大陆配置
// 优化的大陆网络环境配置
const EdgeCNConfig = `# AI CDN Edge Node - China Mainland
# 优化的大陆网络环境

services:
  # HTTP/HTTPS 服务 - 端口80/443
  - name: http-edge
    addr: :80
    handler:
      type: http
      chain: upstream
    listener:
      type: tcp
      config:
        max-connections: 100000

  - name: https-edge
    addr: :443
    handler:
      type: http
      chain: upstream
    listener:
      type: tcp
      config:
        max-connections: 100000
        tls:
          enabled: true
          cert-file: /etc/ai-cdn/agent/cert.pem
          key-file: /etc/ai-cdn/agent/key.pem

  # WebSocket 服务 - 端口8080
  - name: websocket-cn
    addr: :8080
    handler:
      type: ws
      chain: upstream
    listener:
      type: tcp
      config:
        max-connections: 50000

  # KCP服务 - 端口8444
  - name: kcp-edge
    addr: :8444
    handler:
      type: kcp
      chain: upstream
    listener:
      type: kcp
      config:
        mtu: 1400
        sndwnd: 1024
        rcvwnd: 1024
        datashard: 3
        parityshard: 1
        nocomp: false

chains:
  - name: upstream
    hops:
      - name: h1
        nodes:
          - name: master
            addr: ${MASTER_ADDR}
            connector:
              type: http
            dialer:
              type: tcp
`

// EdgeSGConfig 边缘节点 - 新加坡配置
const EdgeSGConfig = `# AI CDN Edge Node - Singapore
# 新加坡节点配置

services:
  # QUIC/HTTP3 服务
  - name: quic-sg
    addr: :443
    handler:
      type: http3
      chain: upstream
    listener:
      type: quic
      config:
        max-connections: 100000
        max-incoming-streams: 10000

  # HTTP 服务
  - name: http-sg
    addr: :80
    handler:
      type: http
      chain: upstream
    listener:
      type: tcp
      config:
        max-connections: 50000

  # WebSocket 服务
  - name: ws-sg
    addr: :8080
    handler:
      type: ws
      chain: upstream
    listener:
      type: tcp
      config:
        max-connections: 50000

chains:
  - name: upstream
    hops:
      - name: h1
        nodes:
          - name: master
            addr: ${MASTER_ADDR}
            connector:
              type: http
            dialer:
              type: tcp
`

// EdgeUSConfig 边缘节点 - 美国配置
const EdgeUSConfig = `# AI CDN Edge Node - United States
# 美国节点配置

services:
  # QUIC/HTTP3 服务
  - name: quic-us
    addr: :443
    handler:
      type: http3
      chain: upstream
    listener:
      type: quic
      config:
        max-connections: 100000
        max-incoming-streams: 10000

  # HTTP 服务
  - name: http-us
    addr: :80
    handler:
      type: http
      chain: upstream
    listener:
      type: tcp
      config:
        max-connections: 50000

  # gRPC 服务
  - name: grpc-us
    addr: :50051
    handler:
      type: grpc
      chain: upstream
    listener:
      type: tcp
      config:
        max-connections: 50000

chains:
  - name: upstream
    hops:
      - name: h1
        nodes:
          - name: master
            addr: ${MASTER_ADDR}
            connector:
              type: http
            dialer:
              type: tcp
`

// L2HKConfig L2中转节点 - 香港
const L2HKConfig = `# AI CDN L2 Node - Hong Kong
# L2中转节点配置

services:
  # 中继服务 - 端口50051
  - name: l2-relay
    addr: :50051
    handler:
      type: relay
      chain: upstream
    listener:
      type: tcp
      config:
        max-connections: 100000
        read-buffer-size: 8192
        write-buffer-size: 8192
        keepalive: true
        keepalive-period: 30s

  # QUIC中继
  - name: l2-quic
    addr: :50052
    handler:
      type: relay
      chain: upstream-quic
    listener:
      type: quic
      config:
        max-connections: 50000

  # SOCKS5 代理
  - name: l2-socks5
    addr: :1080
    handler:
      type: socks5
      chain: upstream
    listener:
      type: tcp
      config:
        max-connections: 50000

chains:
  - name: upstream
    hops:
      - name: h1
        nodes:
          - name: core
            addr: ${MASTER_ADDR}
            connector:
              type: relay
            dialer:
              type: tcp
            tls:
              enabled: true

  - name: upstream-quic
    hops:
      - name: h1
        nodes:
          - name: core-quic
            addr: ${MASTER_ADDR}
            connector:
              type: relay
            dialer:
              type: quic
`

// L2CNConfig L2中转节点 - 大陆
const L2CNConfig = `# AI CDN L2 Node - China Mainland
# L2中转节点 - 大陆优化

services:
  # TCP中继
  - name: l2-tcp
    addr: :50051
    handler:
      type: relay
      chain: upstream
    listener:
      type: tcp
      config:
        max-connections: 100000
        read-buffer-size: 16384
        write-buffer-size: 16384

  # KCP中继
  - name: l2-kcp
    addr: :50052
    handler:
      type: relay
      chain: upstream
    listener:
      type: kcp
      config:
        mtu: 1400
        sndwnd: 2048
        rcvwnd: 2048
        datashard: 4
        parityshard: 2

chains:
  - name: upstream
    hops:
      - name: h1
        nodes:
          - name: core
            addr: ${MASTER_ADDR}
            connector:
              type: relay
            dialer:
              type: tcp
`

// L2SGConfig L2中转节点 - 新加坡
const L2SGConfig = `# AI CDN L2 Node - Singapore
# L2中转节点 - 新加坡

services:
  - name: l2-sg
    addr: :50051
    handler:
      type: relay
      chain: upstream
    listener:
      type: tcp
      config:
        max-connections: 50000

chains:
  - name: upstream
    hops:
      - name: h1
        nodes:
          - name: core
            addr: ${MASTER_ADDR}
            connector:
              type: relay
            dialer:
              type: tcp
`

// L2USConfig L2中转节点 - 美国
const L2USConfig = `# AI CDN L2 Node - United States
# L2中转节点 - 美国

services:
  - name: l2-us
    addr: :50051
    handler:
      type: relay
      chain: upstream
    listener:
      type: tcp
      config:
        max-connections: 50000

  - name: l2-us-quic
    addr: :50052
    handler:
      type: relay
      chain: upstream
    listener:
      type: quic
      config:
        max-connections: 25000

chains:
  - name: upstream
    hops:
      - name: h1
        nodes:
          - name: core
            addr: ${MASTER_ADDR}
            connector:
              type: relay
            dialer:
              type: tcp
`

// CoreHKConfig Core节点 - 香港
const CoreHKConfig = `# AI CDN Core Node - Hong Kong
# 核心节点配置

services:
  # 主控制服务
  - name: control
    addr: :50051
    handler:
      type: relay
    listener:
      type: tcp
      config:
        max-connections: 200000
        read-buffer-size: 16384
        write-buffer-size: 16384

  # QUIC控制服务
  - name: control-quic
    addr: :50052
    handler:
      type: relay
    listener:
      type: quic
      config:
        max-connections: 100000
        max-incoming-streams: 20000

  # 节点监控服务
  - name: monitor
    addr: :9090
    handler:
      type: http
    listener:
      type: tcp

  # 健康检查服务
  - name: health
    addr: :9091
    handler:
      type: http
    listener:
      type: tcp

# 缓存配置
cache:
  enabled: true
  size: 10737418240  # 10GB
  path: /var/lib/ai-cdn/agent/cache
`

// CoreCNConfig Core节点 - 大陆
const CoreCNConfig = `# AI CDN Core Node - China Mainland
# 核心节点 - 大陆配置

services:
  - name: control
    addr: :50051
    handler:
      type: relay
    listener:
      type: tcp
      config:
        max-connections: 200000

  - name: control-kcp
    addr: :50052
    handler:
      type: relay
    listener:
      type: kcp
      config:
        mtu: 1400
        sndwnd: 2048
        rcvwnd: 2048
        datashard: 4
        parityshard: 2

  - name: monitor
    addr: :9090
    handler:
      type: http
    listener:
      type: tcp
`

// CoreSGConfig Core节点 - 新加坡
const CoreSGConfig = `# AI CDN Core Node - Singapore
# 核心节点 - 新加坡配置

services:
  - name: control
    addr: :50051
    handler:
      type: relay
    listener:
      type: tcp
      config:
        max-connections: 100000

  - name: control-quic
    addr: :50052
    handler:
      type: relay
    listener:
      type: quic
      config:
        max-connections: 50000

  - name: monitor
    addr: :9090
    handler:
      type: http
    listener:
      type: tcp
`

// CoreUSConfig Core节点 - 美国
const CoreUSConfig = `# AI CDN Core Node - United States
# 核心节点 - 美国配置

services:
  - name: control
    addr: :50051
    handler:
      type: relay
    listener:
      type: tcp
      config:
        max-connections: 100000

  - name: control-quic
    addr: :50052
    handler:
      type: relay
    listener:
      type: quic
      config:
        max-connections: 50000

  - name: grpc-api
    addr: :50053
    handler:
      type: grpc
    listener:
      type: tcp

  - name: monitor
    addr: :9090
    handler:
      type: http
    listener:
      type: tcp
`

// GetDefaultGostConfig 获取默认gost配置
func GetDefaultGostConfig() string {
	return strings.TrimSpace(EdgeHKConfig)
}
