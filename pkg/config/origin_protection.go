package config

import (
	"fmt"
	"net"
)

// OriginProtectionConfig 源站保护配置
type OriginProtectionConfig struct {
	// 启用源站保护
	Enabled bool `yaml:"enabled"`

	// 保护模式
	Mode string `yaml:"mode"` // "whitelist", "blacklist", "hybrid"

	// 仅允许白名单
	AllowOnlyFrom []*IPRange `yaml:"allow_only_from"`

	// 黑名单
	BlockFrom []*IPRange `yaml:"block_from"`

	// 安全组规则
	SecurityGroups []*SecurityGroupRule `yaml:"security_groups"`

	// 访问控制列表
	ACLs []*ACLRule `yaml:"acls"`

	// 端口限制
	PortRestrictions *PortRestriction `yaml:"port_restrictions"`

	// 防火墙规则
	FirewallRules []*FirewallRule `yaml:"firewall_rules"`

	// 源站隐藏
	HideOrigin *HideOriginConfig `yaml:"hide_origin"`

	// 私有网络配置
	PrivateNetwork *PrivateNetworkConfig `yaml:"private_network"`
}

// IPRange IP范围
type IPRange struct {
	ID      string `yaml:"id"`
	CIDR    string `yaml:"cidr"`
	StartIP string `yaml:"start_ip"`
	EndIP   string `yaml:"end_ip"`
	Name    string `yaml:"name"`
	Type    string `yaml:"type"` // "edge", "reinjection", "admin", "vpn"

	// 时间限制
	EnableTimeWindow bool   `yaml:"enable_time_window"`
	StartTime        string `yaml:"start_time"`
	EndTime          string `yaml:"end_time"`
}

// SecurityGroupRule 安全组规则
type SecurityGroupRule struct {
	ID          string `yaml:"id"`
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	Protocol    string `yaml:"protocol"` // "tcp", "udp", "icmp"
	PortRange   string `yaml:"port_range"`
	Source      string `yaml:"source"` // CIDR or "edge", "reinjection"
	Destination string `yaml:"destination"`
	Action      string `yaml:"action"`    // "allow", "deny"
	Direction   string `yaml:"direction"` // "inbound", "outbound"
	Priority    int    `yaml:"priority"`
	Enabled     bool   `yaml:"enabled"`
}

// ACLRule 访问控制规则
type ACLRule struct {
	ID       string   `yaml:"id"`
	Name     string   `yaml:"name"`
	Match    ACLMatch `yaml:"match"`
	Action   string   `yaml:"action"`
	Priority int      `yaml:"priority"`
	Enabled  bool     `yaml:"enabled"`
}

// ACLRule ACL匹配条件
type ACLMatch struct {
	SourceIP   string `yaml:"source_ip"`
	DestIP     string `yaml:"dest_ip"`
	Protocol   string `yaml:"protocol"`
	Port       int    `yaml:"port"`
	HTTPMethod string `yaml:"http_method"`
	HTTPPath   string `yaml:"http_path"`
	UserAgent  string `yaml:"user_agent"`
}

// PortRestriction 端口限制
type PortRestriction struct {
	// 允许的端口
	AllowedPorts []int `yaml:"allowed_ports"`

	// 禁止的端口
	BlockedPorts []int `yaml:"blocked_ports"`

	// 端口范围
	PortRanges []*PortRange `yaml:"port_ranges"`

	// 默认策略
	DefaultPolicy string `yaml:"default_policy"` // "allow", "deny"
}

// PortRange 端口范围
type PortRange struct {
	Start int `yaml:"start"`
	End   int `yaml:"end"`
}

// FirewallRule 防火墙规则
type FirewallRule struct {
	ID       string        `yaml:"id"`
	Name     string        `yaml:"name"`
	Match    FirewallMatch `yaml:"match"`
	Action   string        `yaml:"action"`
	Priority int           `yaml:"priority"`
	Enabled  bool          `yaml:"enabled"`
}

// FirewallMatch 防火墙匹配条件
type FirewallMatch struct {
	Protocol        string `yaml:"protocol"`
	SourceIP        string `yaml:"source_ip"`
	SourcePort      int    `yaml:"source_port"`
	DestinationIP   string `yaml:"destination_ip"`
	DestinationPort int    `yaml:"destination_port"`
	TCPFlags        string `yaml:"tcp_flags"`
	ICMPType        int    `yaml:"icmp_type"`
}

// HideOriginConfig 源站隐藏配置
type HideOriginConfig struct {
	// 启用源站隐藏
	Enabled bool `yaml:"enabled"`

	// 源站对公网不可达
	OriginUnreachable bool `yaml:"origin_unreachable"`

	// 只能通过Edge访问
	EdgeOnly bool `yaml:"edge_only"`

	// 只能通过回注访问
	ReinjectionOnly bool `yaml:"reinjection_only"`

	// 源站域名不解析到公网
	DisablePublicDNS bool `yaml:"disable_public_dns"`
}

// PrivateNetworkConfig 私有网络配置
type PrivateNetworkConfig struct {
	// VPC配置
	VPC *VPCConfig `yaml:"vpc"`

	// 专线配置
	DedicatedLine *DedicatedLineConfig `yaml:"dedicated_line"`

	// VPN配置
	VPN *VPNConfig `yaml:"vpn"`

	// 防火墙集成
	Firewall *FirewallIntegration `yaml:"firewall"`
}

// VPCConfig VPC配置
type VPCConfig struct {
	Provider           string `yaml:"provider"` // "aws", "aliyun", "tencent", "huawei"
	VPCID              string `yaml:"vpc_id"`
	SubnetID           string `yaml:"subnet_id"`
	SecurityGroupID    string `yaml:"security_group_id"`
	EdgeRouteTableID   string `yaml:"edge_route_table_id"`
	OriginRouteTableID string `yaml:"origin_route_table_id"`
}

// DedicatedLineConfig 专线配置
type DedicatedLineConfig struct {
	Provider        string `yaml:"provider"`
	LineID          string `yaml:"line_id"`
	Bandwidth       int    `yaml:"bandwidth_mbps"`
	EdgeCircuitID   string `yaml:"edge_circuit_id"`
	OriginCircuitID string `yaml:"origin_circuit_id"`
}

// VPNConfig VPN配置
type VPNConfig struct {
	Type           string `yaml:"type"` // "ipsec", "openvpn", "wireguard"
	EdgeEndpoint   string `yaml:"edge_endpoint"`
	OriginEndpoint string `yaml:"origin_endpoint"`
	PresharedKey   string `yaml:"preshared_key"`
	CIDR           string `yaml:"cidr"`
}

// FirewallIntegration 防火墙集成
type FirewallIntegration struct {
	Type     string `yaml:"type"` // "aws_security_group", "aliyun_security_group", "nginx", "iptables"
	Endpoint string `yaml:"endpoint"`
	APIKey   string `yaml:"api_key"`
	AutoSync bool   `yaml:"auto_sync"`
}

// Validate 验证源站保护配置
func (c *OriginProtectionConfig) Validate() error {
	if !c.Enabled {
		return nil
	}

	if c.Mode == "" {
		return fmt.Errorf("保护模式不能为空")
	}

	validModes := map[string]bool{"whitelist": true, "blacklist": true, "hybrid": true}
	if !validModes[c.Mode] {
		return fmt.Errorf("无效的保护模式: %s", c.Mode)
	}

	// 验证IP范围
	for _, ipRange := range c.AllowOnlyFrom {
		if err := ipRange.Validate(); err != nil {
			return err
		}
	}

	for _, ipRange := range c.BlockFrom {
		if err := ipRange.Validate(); err != nil {
			return err
		}
	}

	// 验证私有网络配置
	if c.PrivateNetwork != nil {
		if err := c.PrivateNetwork.Validate(); err != nil {
			return err
		}
	}

	return nil
}

// Validate 验证IP范围
func (c *IPRange) Validate() error {
	if c.CIDR != "" {
		if _, _, err := net.ParseCIDR(c.CIDR); err != nil {
			return fmt.Errorf("无效的CIDR %s: %w", c.CIDR, err)
		}
	}

	if c.StartIP != "" && c.EndIP != "" {
		start := net.ParseIP(c.StartIP)
		end := net.ParseIP(c.EndIP)
		if start == nil {
			return fmt.Errorf("无效的起始IP: %s", c.StartIP)
		}
		if end == nil {
			return fmt.Errorf("无效的结束IP: %s", c.EndIP)
		}
	}

	return nil
}

// Validate 验证私有网络配置
func (c *PrivateNetworkConfig) Validate() error {
	if c.VPC != nil {
		if c.VPC.Provider == "" {
			return fmt.Errorf("VPC提供商不能为空")
		}
	}

	return nil
}
