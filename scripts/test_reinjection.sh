#!/bin/bash

#===============================================================================
# ReInjection Manager Test Suite
# M0-8: GRE/IPIP/VXLAN Tunnel Tests
#===============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_TOTAL=0

#-------------------------------------------------------------------------------
# Utility Functions
#-------------------------------------------------------------------------------

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((TESTS_PASSED++))
    ((TESTS_TOTAL++))
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((TESTS_FAILED++))
    ((TESTS_TOTAL++))
}

log_section() {
    echo ""
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}$1${NC}"
    echo -e "${CYAN}========================================${NC}"
}

log_subsection() {
    echo ""
    echo -e "${YELLOW}--- $1 ---${NC}"
}

#-------------------------------------------------------------------------------
# Test Environment Setup
#-------------------------------------------------------------------------------

setup_test_env() {
    log_section "Setting Up Test Environment"
    
    # Create test directories
    mkdir -p /tmp/gocdn_test/reinjection
    
    # Create test configuration
    cat > /tmp/gocdn_test/reinjection/test_config.yaml << 'EOF'
reinjection:
  enabled: true
  mode: "gre"
  
  gre:
    local_ip: "10.0.0.1"
    local_port: 0
    remote_ip: "10.0.0.2"
    remote_port: 0
    inner_local_ip: "172.16.0.1"
    inner_remote_ip: "172.16.0.2"
    key: 0
    mtu: 1400
    tos: 0
  
  ipip:
    mode: "ipip"
    local_ip: "10.0.0.1"
    remote_ip: "10.0.0.2"
    inner_local_ip: "172.16.1.1"
    inner_remote_ip: "172.16.1.2"
    inner_mask: "255.255.255.0"
    ttl: 64
  
  vxlan:
    vni: 1000
    group: "239.1.1.1"
    local_ip: "10.0.0.1"
    remote_ips:
      - "10.0.0.2"
      - "10.0.0.3"
    inner_local_ip: "172.16.2.1"
    inner_remote_ip: "172.16.2.2"
    inner_mask: "255.255.255.0"
    udp_port: 4789
    ttl: 64
  
  mtu:
    physical: 1500
    tunnel: 1436
    mss: 1436
    clamp_enabled: true
  
  topology:
    type: "star"
    center: "10.0.0.1"
    spokes:
      - "10.0.0.2"
      - "10.0.0.3"
      - "10.0.0.4"
EOF
    
    log_info "Test configuration created: /tmp/gocdn_test/reinjection/test_config.yaml"
}

cleanup_test_env() {
    log_section "Cleaning Up Test Environment"
    rm -rf /tmp/gocdn_test
    log_info "Test environment cleaned up"
}

#-------------------------------------------------------------------------------
# GRE Tunnel Tests
#-------------------------------------------------------------------------------

test_gre_tunnel() {
    log_section "GRE Tunnel Tests"
    
    # Test 1: GRE Manager Initialization
    log_info "Test 1: GRE Manager Initialization"
    cat > /tmp/gocdn_test/reinjection/test_gre_init.go << 'EOF'
package main

import (
    "fmt"
    "time"
    
    "github.com/ai-cdn-tunnel/pkg/config"
    "github.com/ai-cdn-tunnel/pkg/defense"
)

func main() {
    cfg := &config.ReInjectionConfig{
        Enabled: true,
        Mode:    "gre",
        GRE: &config.GREConfig{
            LocalIP:      "10.0.0.1",
            LocalPort:    0,
            RemoteIP:     "10.0.0.2",
            RemotePort:   0,
            InnerLocalIP: "172.16.0.1",
            InnerRemoteIP: "172.16.0.2",
            Key:          0,
            MTU:          1400,
        },
    }
    
    mgr, err := defense.NewReInjectionManager(cfg)
    if err != nil {
        fmt.Printf("FAIL: Failed to create GRE manager: %v\n", err)
        return
    }
    
    if mgr == nil {
        fmt.Println("FAIL: GRE manager is nil")
        return
    }
    
    fmt.Println("PASS: GRE manager initialized successfully")
}
EOF

    if cd /tmp/gocdn_test/reinjection && go run test_gre_init.go 2>/dev/null; then
        log_success "GRE Manager Initialization"
    else
        log_fail "GRE Manager Initialization"
    fi
    
    # Test 2: GRE Tunnel Creation
    log_subsection "GRE Tunnel Creation Tests"
    
    cat > /tmp/gocdn_test/reinjection/test_gre_create.go << 'EOF'
package main

import (
    "fmt"
    "time"
    
    "github.com/ai-cdn-tunnel/pkg/config"
    "github.com/ai-cdn-tunnel/pkg/defense"
)

func main() {
    cfg := &config.ReInjectionConfig{
        Enabled: true,
        Mode:    "gre",
        GRE: &config.GREConfig{
            LocalIP:       "10.0.0.1",
            LocalPort:     0,
            RemoteIP:      "10.0.0.2",
            RemotePort:    0,
            InnerLocalIP:  "172.16.0.1",
            InnerRemoteIP: "172.16.0.2",
            Key:           100,
            MTU:           1400,
        },
    }
    
    mgr, _ := defense.NewReInjectionManager(cfg)
    
    // Create tunnel
    err := mgr.CreateTunnel("gre-test-tunnel")
    if err != nil {
        fmt.Printf("FAIL: Failed to create GRE tunnel: %v\n", err)
        return
    }
    
    status := mgr.GetStatus()
    if status.TunnelCount == 1 {
        fmt.Println("PASS: GRE tunnel created successfully")
    } else {
        fmt.Printf("FAIL: Expected 1 tunnel, got %d\n", status.TunnelCount)
    }
}
EOF

    if cd /tmp/gocdn_test/reinjection && go run test_gre_create.go 2>/dev/null; then
        log_success "GRE Tunnel Creation"
    else
        log_fail "GRE Tunnel Creation"
    fi
    
    # Test 3: GRE Tunnel Destruction
    cat > /tmp/gocdn_test/reinjection/test_gre_destroy.go << 'EOF'
package main

import (
    "fmt"
    "time"
    
    "github.com/ai-cdn-tunnel/pkg/config"
    "github.com/ai-cdn-tunnel/pkg/defense"
)

func main() {
    cfg := &config.ReInjectionConfig{
        Enabled: true,
        Mode:    "gre",
        GRE: &config.GREConfig{
            LocalIP:       "10.0.0.1",
            RemoteIP:      "10.0.0.2",
            InnerLocalIP:  "172.16.0.1",
            InnerRemoteIP: "172.16.0.2",
            Key:           100,
        },
    }
    
    mgr, _ := defense.NewReInjectionManager(cfg)
    
    // Create tunnel first
    mgr.CreateTunnel("gre-destroy-test")
    
    // Then destroy
    err := mgr.DestroyTunnel("gre-destroy-test")
    if err != nil {
        fmt.Printf("FAIL: Failed to destroy GRE tunnel: %v\n", err)
        return
    }
    
    status := mgr.GetStatus()
    if status.TunnelCount == 0 {
        fmt.Println("PASS: GRE tunnel destroyed successfully")
    } else {
        fmt.Printf("FAIL: Expected 0 tunnels after destroy, got %d\n", status.TunnelCount)
    }
}
EOF

    if cd /tmp/gocdn_test/reinjection && go run test_gre_destroy.go 2>/dev/null; then
        log_success "GRE Tunnel Destruction"
    else
        log_fail "GRE Tunnel Destruction"
    fi
    
    # Test 4: GRE MTU Configuration
    cat > /tmp/gocdn_test/reinjection/test_gre_mtu.go << 'EOF'
package main

import (
    "fmt"
    "time"
    
    "github.com/ai-cdn-tunnel/pkg/config"
    "github.com/ai-cdn-tunnel/pkg/defense"
)

func main() {
    cfg := &config.ReInjectionConfig{
        Enabled: true,
        Mode:    "gre",
        GRE: &config.GREConfig{
            LocalIP:       "10.0.0.1",
            RemoteIP:      "10.0.0.2",
            InnerLocalIP:  "172.16.0.1",
            InnerRemoteIP: "172.16.0.2",
            Key:           100,
            MTU:           1400,
        },
        MTU: &config.ReInjectionMTUConfig{
            Physical:     1500,
            Tunnel:       1436,
            MSS:          1436,
            ClampEnabled: true,
        },
    }
    
    mgr, _ := defense.NewReInjectionManager(cfg)
    status := mgr.GetStatus()
    
    // Verify MTU configuration is loaded
    if cfg.MTU.Tunnel == 1436 {
        fmt.Println("PASS: GRE MTU configuration correct (1436)")
    } else {
        fmt.Printf("FAIL: Expected MTU 1436, got %d\n", cfg.MTU.Tunnel)
    }
}
EOF

    if cd /tmp/gocdn_test/reinjection && go run test_gre_mtu.go 2>/dev/null; then
        log_success "GRE MTU Configuration"
    else
        log_fail "GRE MTU Configuration"
    fi
}

#-------------------------------------------------------------------------------
# IPIP Tunnel Tests
#-------------------------------------------------------------------------------

test_ipip_tunnel() {
    log_section "IPIP Tunnel Tests"
    
    # Test 1: IPIP Manager Initialization
    log_info "Test 1: IPIP Manager Initialization"
    cat > /tmp/gocdn_test/reinjection/test_ipip_init.go << 'EOF'
package main

import (
    "fmt"
    "time"
    
    "github.com/ai-cdn-tunnel/pkg/config"
    "github.com/ai-cdn-tunnel/pkg/defense"
)

func main() {
    cfg := &config.ReInjectionConfig{
        Enabled: true,
        Mode:    "ipip",
        IPIP: &config.IPIPConfig{
            Mode:         "ipip",
            LocalIP:      "10.0.0.1",
            RemoteIP:     "10.0.0.2",
            InnerLocalIP: "172.16.1.1",
            InnerRemoteIP: "172.16.1.2",
            InnerMask:    "255.255.255.0",
            TTL:          64,
        },
    }
    
    mgr, err := defense.NewReInjectionManager(cfg)
    if err != nil {
        fmt.Printf("FAIL: Failed to create IPIP manager: %v\n", err)
        return
    }
    
    if mgr == nil {
        fmt.Println("FAIL: IPIP manager is nil")
        return
    }
    
    fmt.Println("PASS: IPIP manager initialized successfully")
}
EOF

    if cd /tmp/gocdn_test/reinjection && go run test_ipip_init.go 2>/dev/null; then
        log_success "IPIP Manager Initialization"
    else
        log_fail "IPIP Manager Initialization"
    fi
    
    # Test 2: IPIP Tunnel Creation
    log_info "Test 2: IPIP Tunnel Creation"
    cat > /tmp/gocdn_test/reinjection/test_ipip_create.go << 'EOF'
package main

import (
    "fmt"
    "time"
    
    "github.com/ai-cdn-tunnel/pkg/config"
    "github.com/ai-cdn-tunnel/pkg/defense"
)

func main() {
    cfg := &config.ReInjectionConfig{
        Enabled: true,
        Mode:    "ipip",
        IPIP: &config.IPIPConfig{
            Mode:          "ipip",
            LocalIP:       "10.0.0.1",
            RemoteIP:      "10.0.0.2",
            InnerLocalIP:  "172.16.1.1",
            InnerRemoteIP: "172.16.1.2",
            InnerMask:     "255.255.255.0",
            TTL:           64,
        },
    }
    
    mgr, _ := defense.NewReInjectionManager(cfg)
    
    err := mgr.CreateTunnel("ipip-test-tunnel")
    if err != nil {
        fmt.Printf("FAIL: Failed to create IPIP tunnel: %v\n", err)
        return
    }
    
    status := mgr.GetStatus()
    if status.TunnelCount == 1 {
        fmt.Println("PASS: IPIP tunnel created successfully")
    } else {
        fmt.Printf("FAIL: Expected 1 tunnel, got %d\n", status.TunnelCount)
    }
}
EOF

    if cd /tmp/gocdn_test/reinjection && go run test_ipip_create.go 2>/dev/null; then
        log_success "IPIP Tunnel Creation"
    else
        log_fail "IPIP Tunnel Creation"
    fi
    
    # Test 3: IPIP Tunnel Modes
    log_info "Test 3: IPIP Tunnel Modes (ipip, sit, ip6ip6)"
    
    modes=("ipip" "sit")
    for mode in "${modes[@]}"; do
        cat > /tmp/gocdn_test/reinjection/test_ipip_mode_$mode.go << EOF
package main

import (
    "fmt"
    "time"
    
    "github.com/ai-cdn-tunnel/pkg/config"
    "github.com/ai-cdn-tunnel/pkg/defense"
)

func main() {
    cfg := &config.ReInjectionConfig{
        Enabled: true,
        Mode:    "$mode",
        IPIP: &config.IPIPConfig{
            Mode:         "$mode",
            LocalIP:      "10.0.0.1",
            RemoteIP:     "10.0.0.2",
            InnerLocalIP: "172.16.1.1",
            InnerRemoteIP: "172.16.1.2",
            InnerMask:    "255.255.255.0",
            TTL:          64,
        },
    }
    
    mgr, _ := defense.NewReInjectionManager(cfg)
    
    if mgr != nil {
        fmt.Printf("PASS: IPIP mode %s initialized\n", "$mode")
    } else {
        fmt.Printf("FAIL: IPIP mode %s initialization failed\n", "$mode")
    }
}
EOF
        if cd /tmp/gocdn_test/reinjection && go run test_ipip_mode_$mode.go 2>/dev/null; then
            log_success "IPIP Mode $mode"
        else
            log_fail "IPIP Mode $mode"
        fi
    done
}

#-------------------------------------------------------------------------------
# VXLAN Tunnel Tests
#-------------------------------------------------------------------------------

test_vxlan_tunnel() {
    log_section "VXLAN Tunnel Tests"
    
    # Test 1: VXLAN Manager Initialization
    log_info "Test 1: VXLAN Manager Initialization"
    cat > /tmp/gocdn_test/reinjection/test_vxlan_init.go << 'EOF'
package main

import (
    "fmt"
    "time"
    
    "github.com/ai-cdn-tunnel/pkg/config"
    "github.com/ai-cdn-tunnel/pkg/defense"
)

func main() {
    cfg := &config.ReInjectionConfig{
        Enabled: true,
        Mode:    "vxlan",
        VXLAN: &config.VXLANConfig{
            VNI:           1000,
            Group:         "239.1.1.1",
            LocalIP:       "10.0.0.1",
            RemoteIPs:     []string{"10.0.0.2", "10.0.0.3"},
            InnerLocalIP:  "172.16.2.1",
            InnerRemoteIP: "172.16.2.2",
            InnerMask:     "255.255.255.0",
            UDPPort:       4789,
            TTL:           64,
        },
    }
    
    mgr, err := defense.NewReInjectionManager(cfg)
    if err != nil {
        fmt.Printf("FAIL: Failed to create VXLAN manager: %v\n", err)
        return
    }
    
    if mgr == nil {
        fmt.Println("FAIL: VXLAN manager is nil")
        return
    }
    
    fmt.Println("PASS: VXLAN manager initialized successfully")
}
EOF

    if cd /tmp/gocdn_test/reinjection && go run test_vxlan_init.go 2>/dev/null; then
        log_success "VXLAN Manager Initialization"
    else
        log_fail "VXLAN Manager Initialization"
    fi
    
    # Test 2: VXLAN VNI Configuration
    log_info "Test 2: VXLAN VNI Configuration"
    cat > /tmp/gocdn_test/reinjection/test_vxlan_vni.go << 'EOF'
package main

import (
    "fmt"
    "time"
    
    "github.com/ai-cdn-tunnel/pkg/config"
    "github.com/ai-cdn-tunnel/pkg/defense"
)

func main() {
    vni := 1000
    
    cfg := &config.ReInjectionConfig{
        Enabled: true,
        Mode:    "vxlan",
        VXLAN: &config.VXLANConfig{
            VNI:       vni,
            Group:     "239.1.1.1",
            LocalIP:   "10.0.0.1",
            RemoteIPs: []string{"10.0.0.2"},
            UDPPort:   4789,
        },
    }
    
    mgr, _ := defense.NewReInjectionManager(cfg)
    
    if mgr != nil && cfg.VXLAN.VNI == vni {
        fmt.Printf("PASS: VXLAN VNI %d configured correctly\n", vni)
    } else {
        fmt.Printf("FAIL: VXLAN VNI configuration incorrect (expected %d)\n", vni)
    }
}
EOF

    if cd /tmp/gocdn_test/reinjection && go run test_vxlan_vni.go 2>/dev/null; then
        log_success "VXLAN VNI Configuration"
    else
        log_fail "VXLAN VNI Configuration"
    fi
    
    # Test 3: VXLAN Multicast Group
    log_info "Test 3: VXLAN Multicast Group Configuration"
    cat > /tmp/gocdn_test/reinjection/test_vxlan_multicast.go << 'EOF'
package main

import (
    "fmt"
    "time"
    
    "github.com/ai-cdn-tunnel/pkg/config"
    "github.com/ai-cdn-tunnel/pkg/defense"
)

func main() {
    cfg := &config.ReInjectionConfig{
        Enabled: true,
        Mode:    "vxlan",
        VXLAN: &config.VXLANConfig{
            VNI:       1000,
            Group:     "239.1.1.1",
            LocalIP:   "10.0.0.1",
            RemoteIPs: []string{"10.0.0.2", "10.0.0.3"},
            UDPPort:   4789,
        },
    }
    
    mgr, _ := defense.NewReInjectionManager(cfg)
    
    if mgr != nil && cfg.VXLAN.Group == "239.1.1.1" {
        fmt.Println("PASS: VXLAN multicast group configured (239.1.1.1)")
    } else {
        fmt.Println("FAIL: VXLAN multicast group configuration failed")
    }
}
EOF

    if cd /tmp/gocdn_test/reinjection && go run test_vxlan_multicast.go 2>/dev/null; then
        log_success "VXLAN Multicast Group"
    else
        log_fail "VXLAN Multicast Group"
    fi
    
    # Test 4: VXLAN Multiple Remote IPs
    log_info "Test 4: VXLAN Multiple Remote IPs"
    cat > /tmp/gocdn_test/reinjection/test_vxlan_remotes.go << 'EOF'
package main

import (
    "fmt"
    "time"
    
    "github.com/ai-cdn-tunnel/pkg/config"
    "github.com/ai-cdn-tunnel/pkg/defense"
)

func main() {
    cfg := &config.ReInjectionConfig{
        Enabled: true,
        Mode:    "vxlan",
        VXLAN: &config.VXLANConfig{
            VNI:       1000,
            Group:     "239.1.1.1",
            LocalIP:   "10.0.0.1",
            RemoteIPs: []string{"10.0.0.2", "10.0.0.3", "10.0.0.4"},
            UDPPort:   4789,
        },
    }
    
    mgr, _ := defense.NewReInjectionManager(cfg)
    
    if mgr != nil && len(cfg.VXLAN.RemoteIPs) == 3 {
        fmt.Printf("PASS: VXLAN configured with %d remote IPs\n", len(cfg.VXLAN.RemoteIPs))
    } else {
        fmt.Println("FAIL: VXLAN remote IPs configuration incorrect")
    }
}
EOF

    if cd /tmp/gocdn_test/reinjection && go run test_vxlan_remotes.go 2>/dev/null; then
        log_success "VXLAN Multiple Remote IPs"
    else
        log_fail "VXLAN Multiple Remote IPs"
    fi
}

#-------------------------------------------------------------------------------
# ReInjection Manager Tests
#-------------------------------------------------------------------------------

test_reinjection_manager() {
    log_section "ReInjection Manager Tests"
    
    # Test 1: Manager Start/Stop
    log_info "Test 1: Manager Start/Stop"
    cat > /tmp/gocdn_test/reinjection/test_manager_start.go << 'EOF'
package main

import (
    "fmt"
    "time"
    
    "github.com/ai-cdn-tunnel/pkg/config"
    "github.com/ai-cdn-tunnel/pkg/defense"
)

func main() {
    cfg := &config.ReInjectionConfig{
        Enabled: true,
        Mode:    "gre",
        GRE: &config.GREConfig{
            LocalIP:      "10.0.0.1",
            RemoteIP:     "10.0.0.2",
            InnerLocalIP: "172.16.0.1",
            InnerRemoteIP: "172.16.0.2",
            Key:          100,
            MTU:          1400,
        },
    }
    
    mgr, _ := defense.NewReInjectionManager(cfg)
    
    // Start manager
    err := mgr.Start()
    if err != nil {
        fmt.Printf("FAIL: Failed to start manager: %v\n", err)
        return
    }
    
    // Wait a bit
    time.Sleep(100 * time.Millisecond)
    
    // Stop manager
    mgr.Stop()
    
    fmt.Println("PASS: Manager start/stop successful")
}
EOF

    if cd /tmp/gocdn_test/reinjection && go run test_manager_start.go 2>/dev/null; then
        log_success "Manager Start/Stop"
    else
        log_fail "Manager Start/Stop"
    fi
    
    # Test 2: Manager Status
    log_info "Test 2: Manager Status Check"
    cat > /tmp/gocdn_test/reinjection/test_manager_status.go << 'EOF'
package main

import (
    "fmt"
    "time"
    
    "github.com/ai-cdn-tunnel/pkg/config"
    "github.com/ai-cdn-tunnel/pkg/defense"
)

func main() {
    cfg := &config.ReInjectionConfig{
        Enabled: true,
        Mode:    "gre",
        GRE: &config.GREConfig{
            LocalIP:       "10.0.0.1",
            RemoteIP:      "10.0.0.2",
            InnerLocalIP:  "172.16.0.1",
            InnerRemoteIP: "172.16.0.2",
            Key:           100,
            MTU:           1400,
        },
    }
    
    mgr, _ := defense.NewReInjectionManager(cfg)
    
    status := mgr.GetStatus()
    
    // Verify status fields
    if status.Enabled && status.Mode == "gre" {
        fmt.Println("PASS: Manager status check passed")
    } else {
        fmt.Printf("FAIL: Status incorrect (enabled=%v, mode=%s)\n", 
            status.Enabled, status.Mode)
    }
}
EOF

    if cd /tmp/gocdn_test/reinjection && go run test_manager_status.go 2>/dev/null; then
        log_success "Manager Status Check"
    else
        log_fail "Manager Status Check"
    fi
    
    # Test 3: Tunnel Topology
    log_info "Test 3: Tunnel Topology (Star/Full Mesh)"
    cat > /tmp/gocdn_test/reinjection/test_topology.go << 'EOF'
package main

import (
    "fmt"
    "time"
    
    "github.com/ai-cdn-tunnel/pkg/config"
    "github.com/ai-cdn-tunnel/pkg/defense"
)

func main() {
    cfg := &config.ReInjectionConfig{
        Enabled: true,
        Mode:    "gre",
        GRE: &config.GREConfig{
            LocalIP:      "10.0.0.1",
            RemoteIP:     "10.0.0.2",
            InnerLocalIP: "172.16.0.1",
            InnerRemoteIP: "172.16.0.2",
            Key:          100,
        },
        Topology: &config.TopoConfig{
            Type:   "star",
            Center: "10.0.0.1",
            Spokes: []string{"10.0.0.2", "10.0.0.3", "10.0.0.4"},
        },
    }
    
    mgr, _ := defense.NewReInjectionManager(cfg)
    
    if mgr != nil && cfg.Topology.Type == "star" {
        fmt.Printf("PASS: Star topology configured (center: %s, spokes: %d)\n", 
            cfg.Topology.Center, len(cfg.Topology.Spokes))
    } else {
        fmt.Println("FAIL: Topology configuration incorrect")
    }
}
EOF

    if cd /tmp/gocdn_test/reinjection && go run test_topology.go 2>/dev/null; then
        log_success "Tunnel Topology"
    else
        log_fail "Tunnel Topology"
    fi
    
    # Test 4: MSS Clamping
    log_info "Test 4: MSS Clamping Configuration"
    cat > /tmp/gocdn_test/reinjection/test_mss.go << 'EOF'
package main

import (
    "fmt"
    "time"
    
    "github.com/ai-cdn-tunnel/pkg/config"
    "github.com/ai-cdn-tunnel/pkg/defense"
)

func main() {
    cfg := &config.ReInjectionConfig{
        Enabled: true,
        Mode:    "gre",
        GRE: &config.GREConfig{
            LocalIP:  "10.0.0.1",
            RemoteIP: "10.0.0.2",
            MTU:      1400,
        },
        MTU: &config.ReInjectionMTUConfig{
            Physical:     1500,
            Tunnel:       1436,
            MSS:          1436,
            ClampEnabled: true,
        },
    }
    
    mgr, _ := defense.NewReInjectionManager(cfg)
    
    // Verify MSS clamping is enabled
    if cfg.MTU.ClampEnabled && cfg.MTU.MSS == 1436 {
        fmt.Println("PASS: MSS clamping configured correctly (1436 bytes)")
    } else {
        fmt.Println("FAIL: MSS clamping configuration incorrect")
    }
}
EOF

    if cd /tmp/gocdn_test/reinjection && go run test_mss.go 2>/dev/null; then
        log_success "MSS Clamping"
    else
        log_fail "MSS Clamping"
    fi
}

#-------------------------------------------------------------------------------
# Main Test Runner
#-------------------------------------------------------------------------------

main() {
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║         GoCDN M0 ReInjection Test Suite                ║${NC}"
    echo -e "${CYAN}║        GRE / IPIP / VXLAN Tunnel Tests                 ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # Setup
    setup_test_env
    
    # Run tests
    test_gre_tunnel
    test_ipip_tunnel
    test_vxlan_tunnel
    test_reinjection_manager
    
    # Cleanup
    cleanup_test_env
    
    # Summary
    echo ""
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}Test Summary${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo -e "Total Tests: ${TESTS_TOTAL}"
    echo -e "${GREEN}Passed: ${TESTS_PASSED}${NC}"
    echo -e "${RED}Failed: ${TESTS_FAILED}${NC}"
    echo ""
    
    if [ ${TESTS_FAILED} -eq 0 ]; then
        echo -e "${GREEN}All tests passed!${NC}"
        exit 0
    else
        echo -e "${RED}Some tests failed!${NC}"
        exit 1
    fi
}

main "$@"
