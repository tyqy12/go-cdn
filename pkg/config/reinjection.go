package config

import (
	"fmt"
	"net"
	"time"
)

// ReInjectionConfig 回注配置
type ReInjectionConfig struct {
	// 启用回注
	Enabled bool `yaml:"enabled"`

	// 回注模式
	Mode string `yaml:"mode"` // "gre", "ipip", "vxlan", "wireguard", "专线"

	// GRE配置
	GRE *GREConfig `yaml:"gre"`

	// IPIP配置
	IPIP *IPIPConfig `yaml:"ipip"`

	// VXLAN配置
	VXLAN *VXLANConfig `yaml:"vxlan"`

	// WireGuard配置
	WireGuard *WireGuardConfig `yaml:"wireguard"`

	// 回注拓扑
	Topology *ReInjectionTopology `yaml:"topology"`

	// MTU配置
	MTU *MTUConfig `yaml:"mtu"`
}

// GREConfig GRE配置
type GREConfig struct {
	// 本地GRE隧道端点
	LocalIP   string `yaml:"local_ip"`
	LocalPort int    `yaml:"local_port"`

	// 远程GRE隧道端点
	RemoteIP   string `yaml:"remote_ip"`
	RemotePort int    `yaml:"remote_port"`

	// 隧道密钥
	Key uint32 `yaml:"key"`

	// 本地隧道IP
	InnerLocalIP string `yaml:"inner_local_ip"`

	// 远程隧道IP
	InnerRemoteIP string `yaml:"inner_remote_ip"`

	// 隧道网络掩码
	InnerMask string `yaml:"inner_mask"`

	// Keepalive配置
	KeepaliveInterval time.Duration `yaml:"keepalive_interval"`
	KeepaliveCount    int           `yaml:"keepalive_count"`
}

// IPIPConfig IPIP配置
type IPIPConfig struct {
	// IPIP模式
	Mode string `yaml:"mode"` // "ipip", "gre", "ip6gre", "ip6ip"

	// 本地IP
	LocalIP string `yaml:"local_ip"`

	// 远程IP
	RemoteIP string `yaml:"remote_ip"`

	// 隧道IP配置
	InnerLocalIP  string `yaml:"inner_local_ip"`
	InnerRemoteIP string `yaml:"inner_remote_ip"`
	InnerMask     string `yaml:"inner_mask"`

	// TTL
	TTL int `yaml:"ttl"`
}

// VXLANConfig VXLAN配置
type VXLANConfig struct {
	// VNI
	VNI int `yaml:"vni"`

	// 组播组地址
	Group string `yaml:"group"`

	// 本地IP
	LocalIP string `yaml:"local_ip"`

	// 远程IPs
	RemoteIPs []string `yaml:"remote_ips"`

	// 隧道IP配置
	InnerLocalIP  string `yaml:"inner_local_ip"`
	InnerRemoteIP string `yaml:"inner_remote_ip"`
	InnerMask     string `yaml:"inner_mask"`

	// UDP端口
	UDPPort int `yaml:"udp_port"`

	// TTL
	TTL int `yaml:"ttl"`
}

// WireGuardConfig WireGuard配置
type WireGuardConfig struct {
	// 本地私钥
	PrivateKey string `yaml:"private_key"`

	// 本地公钥
	PublicKey string `yaml:"public_key"`

	// 本地监听端口
	ListenPort int `yaml:"listen_port"`

	// 本地隧道IP
	InnerLocalIP string `yaml:"inner_local_ip"`

	// 对等节点配置
	Peers []*WireGuardPeer `yaml:"peers"`

	// Keepalive
	KeepaliveInterval time.Duration `yaml:"keepalive_interval"`
}

// WireGuardPeer WireGuard对等节点
type WireGuardPeer struct {
	PublicKey     string   `yaml:"public_key"`
	EndpointIP    string   `yaml:"endpoint_ip"`
	EndpointPort  int      `yaml:"endpoint_port"`
	InnerRemoteIP string   `yaml:"inner_remote_ip"`
	AllowedIPs    []string `yaml:"allowed_ips"`
}

// ReInjectionTopology 回注拓扑配置
type ReInjectionTopology struct {
	// 清洗中心IP
	ScrubbingCenterIP string `yaml:"scrubbing_center_ip"`

	// 回注目标：edge 或 origin
	Target string `yaml:"target"` // "edge", "origin"

	// 回注网段
	InjectionCIDR string `yaml:"injection_cidr"`

	// 源站网段
	OriginCIDR string `yaml:"origin_cidr"`

	// Edge网段
	EdgeCIDR string `yaml:"edge_cidr"`

	// 路由表配置
	Routes []*Route `yaml:"routes"`
}

// Route 路由配置
type Route struct {
	// 目标网络
	Destination string `yaml:"destination"`

	// 网关
	Gateway string `yaml:"gateway"`

	// 接口
	Interface string `yaml:"interface"`

	// 优先级
	Priority int `yaml:"priority"`

	// 度量
	Metric int `yaml:"metric"`
}

// MTUConfig MTU配置
type MTUConfig struct {
	// 物理接口MTU
	PhysicalMTU int `yaml:"physical_mtu"`

	// 隧道接口MTU
	TunnelMTU int `yaml:"tunnel_mtu"`

	// TCP MSS调整
	EnableMSSClamp bool `yaml:"enable_mss_clamp"`
	MSSValue       int  `yaml:"mss_value"`

	// 自动检测MTU
	AutoDiscovery bool `yaml:"auto_discovery"`
}

// Validate 验证回注配置
func (c *ReInjectionConfig) Validate() error {
	if !c.Enabled {
		return nil
	}

	if c.Mode == "" {
		return fmt.Errorf("回注模式不能为空")
	}

	validModes := map[string]bool{"gre": true, "ipip": true, "vxlan": true, "wireguard": true, "专线": true}
	if !validModes[c.Mode] {
		return fmt.Errorf("无效的回注模式: %s", c.Mode)
	}

	// 验证对应模式的配置
	switch c.Mode {
	case "gre":
		if c.GRE == nil {
			return fmt.Errorf("GRE配置不能为空")
		}
		if err := c.GRE.Validate(); err != nil {
			return err
		}
	case "ipip":
		if c.IPIP == nil {
			return fmt.Errorf("IPIP配置不能为空")
		}
		if err := c.IPIP.Validate(); err != nil {
			return err
		}
	case "vxlan":
		if c.VXLAN == nil {
			return fmt.Errorf("VXLAN配置不能为空")
		}
		if err := c.VXLAN.Validate(); err != nil {
			return err
		}
	case "wireguard":
		if c.WireGuard == nil {
			return fmt.Errorf("WireGuard配置不能为空")
		}
		if err := c.WireGuard.Validate(); err != nil {
			return err
		}
	}

	// 验证拓扑配置
	if c.Topology != nil {
		if err := c.Topology.Validate(); err != nil {
			return err
		}
	}

	// 验证MTU配置
	if c.MTU != nil {
		if err := c.MTU.Validate(); err != nil {
			return err
		}
	}

	return nil
}

// Validate 验证GRE配置
func (c *GREConfig) Validate() error {
	if c.LocalIP == "" {
		return fmt.Errorf("本地IP不能为空")
	}

	if c.RemoteIP == "" {
		return fmt.Errorf("远程IP不能为空")
	}

	if net.ParseIP(c.LocalIP) == nil {
		return fmt.Errorf("无效的本地IP: %s", c.LocalIP)
	}

	if net.ParseIP(c.RemoteIP) == nil {
		return fmt.Errorf("无效的远程IP: %s", c.RemoteIP)
	}

	if c.InnerLocalIP == "" {
		return fmt.Errorf("内部本地IP不能为空")
	}

	if c.InnerRemoteIP == "" {
		return fmt.Errorf("内部远程IP不能为空")
	}

	return nil
}

// Validate 验证IPIP配置
func (c *IPIPConfig) Validate() error {
	if c.LocalIP == "" {
		return fmt.Errorf("本地IP不能为空")
	}

	if c.RemoteIP == "" {
		return fmt.Errorf("远程IP不能为空")
	}

	return nil
}

// Validate 验证VXLAN配置
func (c *VXLANConfig) Validate() error {
	if c.VNI == 0 {
		return fmt.Errorf("VNI不能为空")
	}

	if c.LocalIP == "" {
		return fmt.Errorf("本地IP不能为空")
	}

	return nil
}

// Validate 验证WireGuard配置
func (c *WireGuardConfig) Validate() error {
	if c.PrivateKey == "" {
		return fmt.Errorf("私钥不能为空")
	}

	if c.ListenPort == 0 {
		return fmt.Errorf("监听端口不能为空")
	}

	return nil
}

// Validate 验证拓扑配置
func (c *ReInjectionTopology) Validate() error {
	if c.ScrubbingCenterIP == "" {
		return fmt.Errorf("清洗中心IP不能为空")
	}

	if c.Target == "" {
		return fmt.Errorf("回注目标不能为空")
	}

	if c.InjectionCIDR == "" {
		return fmt.Errorf("回注网段不能为空")
	}

	return nil
}

// Validate 验证MTU配置
func (c *MTUConfig) Validate() error {
	if c.PhysicalMTU == 0 {
		return fmt.Errorf("物理接口MTU不能为空")
	}

	if c.TunnelMTU == 0 {
		return fmt.Errorf("隧道接口MTU不能为空")
	}

	if c.EnableMSSClamp && c.MSSValue == 0 {
		return fmt.Errorf("启用MSS调整时，MSS值不能为空")
	}

	return nil
}
