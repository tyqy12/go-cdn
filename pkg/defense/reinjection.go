package defense

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/ai-cdn-tunnel/pkg/config"
)

// ReInjectionManager 回注管理器
type ReInjectionManager struct {
	config   *config.ReInjectionConfig
	greMgr   *GREManager
	ipipMgr  *IPIPManager
	vxlanMgr *VXLANManager
	wg       sync.WaitGroup
	mu       sync.RWMutex
	ctx      context.Context
	cancel   context.CancelFunc
	logger   Logger
}

// GREManager GRE隧道管理器
type GREManager struct {
	config  *config.GREConfig
	tunnels map[string]*GRETunnel
	mu      sync.RWMutex
	enabled bool
}

// IPIPManager IPIP管理器
type IPIPManager struct {
	config  *config.IPIPConfig
	tunnels map[string]*IPIPTunnel
	mu      sync.RWMutex
	enabled bool
}

// VXLANManager VXLAN管理器
type VXLANManager struct {
	config  *config.VXLANConfig
	tunnels map[string]*VXLANTunnel
	mu      sync.RWMutex
	enabled bool
}

// GRETunnel GRE隧道
type GRETunnel struct {
	ID          string
	LocalIP     string
	LocalPort   int
	RemoteIP    string
	RemotePort  int
	InnerLocal  string
	InnerRemote string
	Key         uint32
	Active      bool
	StartTime   time.Time
}

// IPIPTunnel IPIP隧道
type IPIPTunnel struct {
	ID          string
	Mode        string
	LocalIP     string
	RemoteIP    string
	InnerLocal  string
	InnerRemote string
	InnerMask   string
	TTL         int
	Active      bool
	StartTime   time.Time
}

// VXLANTunnel VXLAN隧道
type VXLANTunnel struct {
	ID          string
	VNI         int
	Group       string
	LocalIP     string
	RemoteIPs   []string
	InnerLocal  string
	InnerRemote string
	InnerMask   string
	UDPPort     int
	TTL         int
	Active      bool
}

// NewReInjectionManager 创建回注管理器
func NewReInjectionManager(cfg *config.ReInjectionConfig) (*ReInjectionManager, error) {
	if cfg == nil {
		return nil, fmt.Errorf("回注配置不能为空")
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("回注配置验证失败: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	rm := &ReInjectionManager{
		config: cfg,
		greMgr: &GREManager{
			config:  cfg.GRE,
			tunnels: make(map[string]*GRETunnel),
			mu:      sync.RWMutex{},
			enabled: cfg.Mode == "gre",
		},
		ipipMgr: &IPIPManager{
			config:  cfg.IPIP,
			tunnels: make(map[string]*IPIPTunnel),
			mu:      sync.RWMutex{},
			enabled: cfg.Mode == "ipip",
		},
		vxlanMgr: &VXLANManager{
			config:  cfg.VXLAN,
			tunnels: make(map[string]*VXLANTunnel),
			mu:      sync.RWMutex{},
			enabled: cfg.Mode == "vxlan",
		},
		logger: newLogger(loggerTypeDefault),
		ctx:    ctx,
		cancel: cancel,
	}

	return rm, nil
}

// Start 启动回注管理器
func (rm *ReInjectionManager) Start() error {
	if !rm.config.Enabled {
		rm.logger.Infof("回注功能未启用")
		return nil
	}

	rm.logger.Infof("启动回注管理器，模式: %s", rm.config.Mode)

	// 根据模式启动对应的管理器
	switch rm.config.Mode {
	case "gre":
		if err := rm.greMgr.Start(); err != nil {
			return fmt.Errorf("启动GRE管理器失败: %w", err)
		}
	case "ipip":
		if err := rm.ipipMgr.Start(); err != nil {
			return fmt.Errorf("启动IPIP管理器失败: %w", err)
		}
	case "vxlan":
		if err := rm.vxlanMgr.Start(); err != nil {
			return fmt.Errorf("启动VXLAN管理器失败: %w", err)
		}
	}

	return nil
}

// Stop 停止回注管理器
func (rm *ReInjectionManager) Stop() error {
	rm.logger.Infof("停止回注管理器")

	if rm.cancel != nil {
		rm.cancel()
	}

	rm.wg.Wait()

	return nil
}

// CreateTunnel 创建隧道
func (rm *ReInjectionManager) CreateTunnel(tunnelName string) error {
	if !rm.config.Enabled {
		return fmt.Errorf("回注功能未启用")
	}

	rm.logger.Infof("创建回注隧道: %s", tunnelName)

	switch rm.config.Mode {
	case "gre":
		return rm.greMgr.CreateTunnel(tunnelName, rm.config.GRE)
	case "ipip":
		return rm.ipipMgr.CreateTunnel(tunnelName, rm.config.IPIP)
	case "vxlan":
		return rm.vxlanMgr.CreateTunnel(tunnelName, rm.config.VXLAN)
	default:
		return fmt.Errorf("不支持的回注模式: %s", rm.config.Mode)
	}
}

// DestroyTunnel 销毁隧道
func (rm *ReInjectionManager) DestroyTunnel(tunnelName string) error {
	rm.logger.Infof("销毁回注隧道: %s", tunnelName)

	switch rm.config.Mode {
	case "gre":
		return rm.greMgr.DestroyTunnel(tunnelName)
	case "ipip":
		return rm.ipipMgr.DestroyTunnel(tunnelName)
	case "vxlan":
		return rm.vxlanMgr.DestroyTunnel(tunnelName)
	default:
		return fmt.Errorf("不支持的回注模式: %s", rm.config.Mode)
	}
}

// GetStatus 获取状态
func (rm *ReInjectionManager) GetStatus() *ReInjectionStatus {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	status := &ReInjectionStatus{
		Enabled:     rm.config.Enabled,
		Mode:        rm.config.Mode,
		TunnelCount: 0,
		ActiveCount: 0,
	}

	switch rm.config.Mode {
	case "gre":
		rm.greMgr.mu.RLock()
		status.TunnelCount = len(rm.greMgr.tunnels)
		for _, tunnel := range rm.greMgr.tunnels {
			if tunnel.Active {
				status.ActiveCount++
			}
		}
		rm.greMgr.mu.RUnlock()
	case "ipip":
		rm.ipipMgr.mu.RLock()
		status.TunnelCount = len(rm.ipipMgr.tunnels)
		for _, tunnel := range rm.ipipMgr.tunnels {
			if tunnel.Active {
				status.ActiveCount++
			}
		}
		rm.ipipMgr.mu.RUnlock()
	case "vxlan":
		rm.vxlanMgr.mu.RLock()
		status.TunnelCount = len(rm.vxlanMgr.tunnels)
		for _, tunnel := range rm.vxlanMgr.tunnels {
			if tunnel.Active {
				status.ActiveCount++
			}
		}
		rm.vxlanMgr.mu.RUnlock()
	}

	return status
}

// ReInjectionStatus 回注状态
type ReInjectionStatus struct {
	Enabled     bool
	Mode        string
	TunnelCount int
	ActiveCount int
}

// GRE管理器方法
func (gm *GREManager) Start() error {
	gm.mu.Lock()
	defer gm.mu.Unlock()
	gm.enabled = true
	return nil
}

func (gm *GREManager) CreateTunnel(name string, cfg *config.GREConfig) error {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	tunnel := &GRETunnel{
		ID:          name,
		LocalIP:     cfg.LocalIP,
		LocalPort:   cfg.LocalPort,
		RemoteIP:    cfg.RemoteIP,
		RemotePort:  cfg.RemotePort,
		InnerLocal:  cfg.InnerLocalIP,
		InnerRemote: cfg.InnerRemoteIP,
		Key:         cfg.Key,
		Active:      false,
		StartTime:   time.Now(),
	}

	gm.tunnels[name] = tunnel
	return nil
}

func (gm *GREManager) DestroyTunnel(name string) error {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	if _, ok := gm.tunnels[name]; !ok {
		return fmt.Errorf("隧道不存在: %s", name)
	}

	delete(gm.tunnels, name)
	return nil
}

// IPIP管理器方法
func (im *IPIPManager) Start() error {
	im.mu.Lock()
	defer im.mu.Unlock()
	im.enabled = true
	return nil
}

func (im *IPIPManager) CreateTunnel(name string, cfg *config.IPIPConfig) error {
	im.mu.Lock()
	defer im.mu.Unlock()

	tunnel := &IPIPTunnel{
		ID:          name,
		Mode:        cfg.Mode,
		LocalIP:     cfg.LocalIP,
		RemoteIP:    cfg.RemoteIP,
		InnerLocal:  cfg.InnerLocalIP,
		InnerRemote: cfg.InnerRemoteIP,
		InnerMask:   cfg.InnerMask,
		TTL:         cfg.TTL,
		Active:      false,
		StartTime:   time.Now(),
	}

	im.tunnels[name] = tunnel
	return nil
}

func (im *IPIPManager) DestroyTunnel(name string) error {
	im.mu.Lock()
	defer im.mu.Unlock()

	if _, ok := im.tunnels[name]; !ok {
		return fmt.Errorf("隧道不存在: %s", name)
	}

	delete(im.tunnels, name)
	return nil
}

// VXLAN管理器方法
func (vm *VXLANManager) Start() error {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	vm.enabled = true
	return nil
}

func (vm *VXLANManager) CreateTunnel(name string, cfg *config.VXLANConfig) error {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	tunnel := &VXLANTunnel{
		ID:          name,
		VNI:         cfg.VNI,
		LocalIP:     cfg.LocalIP,
		RemoteIPs:   cfg.RemoteIPs,
		InnerLocal:  cfg.InnerLocalIP,
		InnerRemote: cfg.InnerRemoteIP,
		InnerMask:   cfg.InnerMask,
		UDPPort:     cfg.UDPPort,
		TTL:         cfg.TTL,
		Active:      false,
	}

	vm.tunnels[name] = tunnel
	return nil
}

func (vm *VXLANManager) DestroyTunnel(name string) error {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	if _, ok := vm.tunnels[name]; !ok {
		return fmt.Errorf("隧道不存在: %s", name)
	}

	delete(vm.tunnels, name)
	return nil
}
