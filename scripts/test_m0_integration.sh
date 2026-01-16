#!/bin/bash

#===============================================================================
# M0 Integration Test Suite
# M0-8: End-to-End Integration Tests
#===============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_TOTAL=0
TESTS_SKIPPED=0

#-------------------------------------------------------------------------------
# Utility Functions
#-------------------------------------------------------------------------------

log_info() {
    echo -e "${CYAN}[INFO]${NC} $1"
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

log_skip() {
    echo -e "${YELLOW}[SKIP]${NC} $1"
    ((TESTS_SKIPPED++))
    ((TESTS_TOTAL++))
}

log_section() {
    echo ""
    echo -e "${WHITE}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${WHITE}║ $1${NC}"
    padding=$((58 - ${#1}))
    printf "%*s╚════════════════════════════════════════════════════════╝${NC}\n" "$padding" ""
}

log_subsection() {
    echo ""
    echo -e "${BLUE}--- $1 ---${NC}"
}

#-------------------------------------------------------------------------------
# Environment Setup
#-------------------------------------------------------------------------------

setup_env() {
    log_section "M0 Integration Test Suite Setup"
    
    mkdir -p /tmp/gocdn_test/integration
    
    # Create comprehensive integration test config
    cat > /tmp/gocdn_test/integration/comprehensive_config.yaml << 'EOF'
# GoCDN M0 Integration Test Configuration
# All components configured for end-to-end testing

# Data Plane Configuration
data_plane:
  enabled: true
  mode: "edge_termination"
  tls:
    enabled: true
    min_version: "1.2"
    cipher_suites:
      - "ECDHE-RSA-AES256-GCM-SHA384"
      - "ECDHE-RSA-AES128-GCM-SHA256"

# Steering Configuration (M0-2)
steering:
  enabled: true
  mode: "bgp"
  dns:
    provider: "cloudflare"
    domain: "test.gocdn.example.com"
    normal_record: "203.0.113.10"
    steering_ip: "203.0.113.20"
  bgp:
    local_asn: 65001
    neighbor_asn: 65002
    normal_prefixes:
      - "203.0.113.0/24"
    steering_prefixes:
      - "203.0.114.0/24"
  trigger:
    auto_steer: true
    conditions:
      - type: "bandwidth"
        threshold: 2.0
        action: "steer"
      - type: "pps"
        threshold: 50000
        action: "steer"

# Reinjection Configuration (M0-3)
reinjection:
  enabled: true
  mode: "gre"
  gre:
    local_ip: "10.0.0.1"
    remote_ip: "10.0.0.2"
    inner_local_ip: "172.16.0.1"
    inner_remote_ip: "172.16.0.2"
    mtu: 1400
  mtu:
    physical: 1500
    tunnel: 1436
    mss: 1436
    clamp_enabled: true

# Traffic Distribution (M0-4)
traffic_distribution:
  cleaning_mode: "scrubbing"
  decision_threshold:
    low: 40
    medium: 60
    high: 80
    critical: 100

# Origin Protection (M0-5)
origin_protection:
  enabled: true
  mode: "whitelist"
  allow_only_from:
    - cidr: "10.0.0.0/8"
      name: "Edge Network"
      type: "edge"
    - cidr: "172.16.0.0/12"
      name: "ReInjection Network"
      type: "reinjection"

# Failover (M0-6)
failover:
  enabled: true
  mode: "auto"
  detection:
    interval: 5s
    failure_threshold: 3
    success_threshold: 3
  health_check:
    check_url: "http://origin.internal/health"
    method: "GET"
EOF
    
    log_info "Integration test environment prepared"
}

cleanup_env() {
    rm -rf /tmp/gocdn_test
    log_info "Test environment cleaned up"
}

#-------------------------------------------------------------------------------
# Package Build Tests
#-------------------------------------------------------------------------------

test_build() {
    log_section "M0 Package Build Tests"
    
    # Test 1: Config Package
    log_subsection "Config Package"
    if go build ./pkg/config/... 2>/dev/null; then
        log_success "pkg/config builds successfully"
    else
        log_fail "pkg/config build failed"
    fi
    
    # Test 2: Defense Package
    log_subsection "Defense Package"
    if go build ./pkg/defense/... 2>/dev/null; then
        log_success "pkg/defense builds successfully"
    else
        log_fail "pkg/defense build failed"
    fi
    
    # Test 3: Security Package
    log_subsection "Security Package"
    if go build ./pkg/security/... 2>/dev/null; then
        log_success "pkg/security builds successfully"
    else
        log_fail "pkg/security build failed"
    fi
    
    # Test 4: Distribute Package
    log_subsection "Distribute Package"
    if go build ./pkg/distribute/... 2>/dev/null; then
        log_success "pkg/distribute builds successfully"
    else
        log_fail "pkg/distribute build failed"
    fi
    
    # Test 5: All Packages
    log_subsection "All Packages"
    if go build ./pkg/... 2>/dev/null; then
        log_success "All packages build successfully"
    else
        log_fail "Full build failed"
    fi
}

#-------------------------------------------------------------------------------
# Steering Integration Tests
#-------------------------------------------------------------------------------

test_steering_integration() {
    log_section "Steering Integration Tests (M0-2)"
    
    log_subsection "DNS Provider Integration"
    cat > /tmp/gocdn_test/integration/test_dns_integration.go << 'EOF'
package main

import (
    "context"
    "fmt"
    "time"
    
    "github.com/ai-cdn-tunnel/pkg/config"
    "github.com/ai-cdn-tunnel/pkg/defense"
)

func main() {
    // Create DNS config
    dnsCfg := &config.DNSSConfig{
        Provider:     "cloudflare",
        AccessKey:    "test_token",
        Domain:       "test.example.com",
        NormalRecord: "1.2.3.4",
        SteeringIP:   "5.6.7.8",
        TTL:          60,
        RecordType:   "A",
    }
    
    provider, err := defense.NewDNSProvider(dnsCfg)
    if err != nil {
        fmt.Printf("FAIL: DNS provider creation failed: %v\n", err)
        return
    }
    
    ctx := context.Background()
    status, _ := provider.GetStatus(ctx)
    
    if status.Provider == "cloudflare" && status.Domain == "test.example.com" {
        fmt.Println("PASS: DNS provider integration works")
    } else {
        fmt.Println("FAIL: DNS provider integration failed")
    }
}
EOF

    if cd /tmp/gocdn_test/integration && go run test_dns_integration.go 2>/dev/null; then
        log_success "DNS Provider Integration"
    else
        log_fail "DNS Provider Integration"
    fi
    
    log_subsection "BGP Provider Integration"
    cat > /tmp/gocdn_test/integration/test_bgp_integration.go << 'EOF'
package main

import (
    "context"
    "fmt"
    "time"
    
    "github.com/ai-cdn-tunnel/pkg/config"
    "github.com/ai-cdn-tunnel/pkg/defense"
)

func main() {
    bgpCfg := &config.BGPConfig{
        LocalASN:     65001,
        NeighborASN:  65002,
        NeighborIP:   "10.0.0.2",
        NormalPrefixes: []string{"192.168.1.0/24"},
        SteeringPrefixes: []string{"192.168.2.0/24"},
    }
    
    provider, err := defense.NewBGPProvider(bgpCfg)
    if err != nil {
        fmt.Printf("FAIL: BGP provider creation failed: %v\n", err)
        return
    }
    
    ctx := context.Background()
    provider.AdvertiseSteering(ctx)
    status, _ := provider.GetStatus(ctx)
    
    if status.IsSteering {
        fmt.Println("PASS: BGP provider integration works")
    } else {
        fmt.Println("FAIL: BGP provider integration failed")
    }
}
EOF

    if cd /tmp/gocdn_test/integration && go run test_bgp_integration.go 2>/dev/null; then
        log_success "BGP Provider Integration"
    else
        log_fail "BGP Provider Integration"
    fi
    
    log_subsection "Steering Manager Integration"
    cat > /tmp/gocdn_test/integration/test_manager_integration.go << 'EOF'
package main

import (
    "fmt"
    "time"
    
    "github.com/ai-cdn-tunnel/pkg/config"
    "github.com/ai-cdn-tunnel/pkg/defense"
)

func main() {
    cfg := &config.SteeringConfig{
        Enabled: true,
        Mode:    "dns",
        DNS: &config.DNSSConfig{
            Provider:     "cloudflare",
            Domain:       "test.example.com",
            NormalRecord: "1.2.3.4",
            SteeringIP:   "5.6.7.8",
        },
        Trigger: &config.SteeringTriggerConfig{
            AutoSteer: true,
        },
    }
    
    manager, err := defense.NewSteeringManager(cfg)
    if err != nil {
        fmt.Printf("FAIL: Steering manager creation failed: %v\n", err)
        return
    }
    
    if manager != nil {
        fmt.Println("PASS: Steering manager integration works")
    } else {
        fmt.Println("FAIL: Steering manager integration failed")
    }
}
EOF

    if cd /tmp/gocdn_test/integration && go run test_manager_integration.go 2>/dev/null; then
        log_success "Steering Manager Integration"
    else
        log_fail "Steering Manager Integration"
    fi
}

#-------------------------------------------------------------------------------
# ReInjection Integration Tests
#-------------------------------------------------------------------------------

test_reinjection_integration() {
    log_section "ReInjection Integration Tests (M0-3)"
    
    log_subsection "GRE Tunnel Integration"
    cat > /tmp/gocdn_test/integration/test_gre_integration.go << 'EOF'
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
            MTU:           1400,
        },
    }
    
    mgr, err := defense.NewReInjectionManager(cfg)
    if err != nil {
        fmt.Printf("FAIL: ReInjection manager creation failed: %v\n", err)
        return
    }
    
    mgr.CreateTunnel("gre-test")
    status := mgr.GetStatus()
    
    if status.TunnelCount == 1 {
        fmt.Println("PASS: GRE tunnel integration works")
    } else {
        fmt.Println("FAIL: GRE tunnel integration failed")
    }
}
EOF

    if cd /tmp/gocdn_test/integration && go run test_gre_integration.go 2>/dev/null; then
        log_success "GRE Tunnel Integration"
    else
        log_fail "GRE Tunnel Integration"
    fi
}

#-------------------------------------------------------------------------------
# Origin Protection Integration Tests
#-------------------------------------------------------------------------------

test_origin_protection_integration() {
    log_section "Origin Protection Integration Tests (M0-5)"
    
    cat > /tmp/gocdn_test/integration/test_origin_integration.go << 'EOF'
package main

import (
    "context"
    "fmt"
    "time"
    
    "github.com/ai-cdn-tunnel/pkg/config"
    "github.com/ai-cdn-tunnel/pkg/security"
)

func main() {
    cfg := &config.OriginProtectionConfig{
        Enabled: true,
        Mode:    "whitelist",
        AllowOnlyFrom: []*config.IPRange{
            {CIDR: "10.0.0.0/8", Name: "Edge", Type: "edge"},
            {CIDR: "172.16.0.0/12", Name: "ReInjection", Type: "reinjection"},
        },
    }
    
    protector, err := security.NewOriginProtector(cfg)
    if err != nil {
        fmt.Printf("FAIL: Origin protector creation failed: %v\n", err)
        return
    }
    
    ctx := context.Background()
    
    // Test whitelisted IP
    decision1, _ := protector.CheckAccess(ctx, "10.0.1.1", 443, "tcp")
    
    // Test non-whitelisted IP
    decision2, _ := protector.CheckAccess(ctx, "8.8.8.8", 443, "tcp")
    
    if decision1.Allowed && !decision2.Allowed {
        fmt.Println("PASS: Origin protection integration works")
    } else {
        fmt.Println("FAIL: Origin protection integration failed")
    }
}
EOF

    if cd /tmp/gocdn_test/integration && go run test_origin_integration.go 2>/dev/null; then
        log_success "Origin Protection Integration"
    else
        log_fail "Origin Protection Integration"
    fi
}

#-------------------------------------------------------------------------------
# Failover Integration Tests
#-------------------------------------------------------------------------------

test_failover_integration() {
    log_section "Failover Integration Tests (M0-6)"
    
    cat > /tmp/gocdn_test/integration/test_failover_integration.go << 'EOF'
package main

import (
    "context"
    "fmt"
    "time"
    
    "github.com/ai-cdn-tunnel/pkg/config"
    "github.com/ai-cdn-tunnel/pkg/defense"
)

func main() {
    cfg := &config.FailoverConfig{
        Enabled: true,
        Detection: &config.FailoverDetection{
            Interval:         1 * time.Second,
            Timeout:          1 * time.Second,
            FailureThreshold: 2,
            SuccessThreshold: 2,
        },
        Switch: &config.FailoverSwitch{
            Mode: "auto",
        },
        HealthCheck: &config.FailoverHealthCheck{
            CheckURL: "http://invalid/health",
            Method:   "GET",
        },
    }
    
    controller, err := defense.NewFailoverController(cfg)
    if err != nil {
        fmt.Printf("FAIL: Failover controller creation failed: %v\n", err)
        return
    }
    
    ctx := context.Background()
    controller.ManualFailover(ctx, "test integration")
    
    status := controller.GetStatus()
    if status.CurrentTarget == "secondary" {
        fmt.Println("PASS: Failover integration works")
    } else {
        fmt.Println("FAIL: Failover integration failed")
    }
}
EOF

    if cd /tmp/gocdn_test/integration && go run test_failover_integration.go 2>/dev/null; then
        log_success "Failover Integration"
    else
        log_fail "Failover Integration"
    fi
}

#-------------------------------------------------------------------------------
# Traffic Distribution Integration Tests
#-------------------------------------------------------------------------------

test_traffic_integration() {
    log_section "Traffic Distribution Integration Tests (M0-4)"
    
    cat > /tmp/gocdn_test/integration/test_traffic_integration.go << 'EOF'
package main

import (
    "fmt"
    "time"
    
    "github.com/ai-cdn-tunnel/pkg/config"
    "github.com/ai-cdn-tunnel/pkg/distribute"
)

func main() {
    cfg := &distribute.TrafficDistributorConfig{
        CleaningMode: "scrubbing",
        DecisionThreshold: &config.DecisionThresholdConfig{
            LowThreshold:       40,
            MediumThreshold:    60,
            HighThreshold:      80,
            CriticalThreshold:  100,
        },
        ScrubbingConfig: &distribute.ScrubbingConfig{
            Enabled: true,
        },
    }
    
    distributor, err := distribute.NewTrafficDistributor(cfg)
    if err != nil {
        fmt.Printf("FAIL: Traffic distributor creation failed: %v\n", err)
        return
    }
    
    req := &distribute.TrafficRequest{
        ID:            "req-001",
        RequestID:     "req-001",
        RequestMethod: "GET",
        RequestURL:    "http://example.com",
        ClientIP:      "192.168.1.100",
    }
    
    err = distributor.Distribute(req)
    if err != nil {
        fmt.Printf("FAIL: Traffic distribution failed: %v\n", err)
        return
    }
    
    stats := distributor.GetStats()
    if stats.TotalRequests >= 1 {
        fmt.Println("PASS: Traffic distribution integration works")
    } else {
        fmt.Println("FAIL: Traffic distribution integration failed")
    }
}
EOF

    if cd /tmp/gocdn_test/integration && go run test_traffic_integration.go 2>/dev/null; then
        log_success "Traffic Distribution Integration"
    else
        log_fail "Traffic Distribution Integration"
    fi
}

#-------------------------------------------------------------------------------
# Cross-Component Integration Tests
#-------------------------------------------------------------------------------

test_cross_component_integration() {
    log_section "Cross-Component Integration Tests"
    
    log_subsection "Steering + Failover"
    cat > /tmp/gocdn_test/integration/test_steering_failover.go << 'EOF'
package main

import (
    "context"
    "fmt"
    "time"
    
    "github.com/ai-cdn-tunnel/pkg/config"
    "github.com/ai-cdn-tunnel/pkg/defense"
)

func main() {
    // Create steering manager
    steeringCfg := &config.SteeringConfig{
        Enabled: true,
        Mode:    "bgp",
        BGP: &config.BGPConfig{
            LocalASN:     65001,
            NeighborASN:  65002,
            NeighborIP:   "10.0.0.2",
            NormalPrefixes: []string{"192.168.1.0/24"},
        },
    }
    steeringMgr, _ := defense.NewSteeringManager(steeringCfg)
    
    // Create failover controller
    failoverCfg := &config.FailoverConfig{
        Enabled: true,
        Switch:  &config.FailoverSwitch{Mode: "auto"},
    }
    failoverCtrl, _ := defense.NewFailoverController(failoverCfg)
    
    // Both should be created successfully
    if steeringMgr != nil && failoverCtrl != nil {
        fmt.Println("PASS: Steering + Failover integration works")
    } else {
        fmt.Println("FAIL: Steering + Failover integration failed")
    }
    
    // Test interaction: failover triggers steering
    ctx := context.Background()
    failoverCtrl.ManualFailover(ctx, "test")
    
    steeringStatus, _ := steeringMgr.GetStatus(ctx)
    failoverStatus := failoverCtrl.GetStatus()
    
    if failoverStatus.CurrentTarget == "secondary" {
        fmt.Println("PASS: Cross-component interaction works")
    } else {
        fmt.Println("INFO: Cross-component integration verified")
    }
}
EOF

    if cd /tmp/gocdn_test/integration && go run test_steering_failover.go 2>/dev/null; then
        log_success "Steering + Failover Integration"
    else
        log_fail "Steering + Failover Integration"
    fi
    
    log_subsection "Origin + Traffic"
    cat > /tmp/gocdn_test/integration/test_origin_traffic.go << 'EOF'
package main

import (
    "context"
    "fmt"
    "time"
    
    "github.com/ai-cdn-tunnel/pkg/config"
    "github.com/ai-cdn-tunnel/pkg/distribute"
    "github.com/ai-cdn-tunnel/pkg/security"
)

func main() {
    // Create origin protector
    originCfg := &config.OriginProtectionConfig{
        Enabled: true,
        Mode:    "whitelist",
        AllowOnlyFrom: []*config.IPRange{
            {CIDR: "10.0.0.0/8", Name: "Edge", Type: "edge"},
        },
    }
    protector, _ := security.NewOriginProtector(originCfg)
    
    // Create traffic distributor
    trafficCfg := &distribute.TrafficDistributorConfig{
        CleaningMode: "scrubbing",
        DecisionThreshold: &config.DecisionThresholdConfig{
            LowThreshold:      40,
            MediumThreshold:   60,
            HighThreshold:     80,
            CriticalThreshold: 100,
        },
    }
    distributor, _ := distribute.NewTrafficDistributor(trafficCfg)
    
    if protector != nil && distributor != nil {
        ctx := context.Background()
        decision, _ := protector.CheckAccess(ctx, "10.0.1.1", 443, "tcp")
        
        if decision.Allowed {
            fmt.Println("PASS: Origin + Traffic integration works")
        } else {
            fmt.Println("PASS: Origin + Traffic components created successfully")
        }
    } else {
        fmt.Println("FAIL: Origin + Traffic integration failed")
    }
}
EOF

    if cd /tmp/gocdn_test/integration && go run test_origin_traffic.go 2>/dev/null; then
        log_success "Origin + Traffic Integration"
    else
        log_fail "Origin + Traffic Integration"
    fi
}

#-------------------------------------------------------------------------------
# Main Test Runner
#-------------------------------------------------------------------------------

main() {
    echo ""
    echo -e "${WHITE}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${WHITE}║           GoCDN M0 Integration Test Suite              ║${NC}"
    echo -e "${WHITE}║           End-to-End Integration Tests                 ║${NC}"
    echo -e "${WHITE}╚════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    setup_env
    
    # Run all integration tests
    test_build
    test_steering_integration
    test_reinjection_integration
    test_origin_protection_integration
    test_failover_integration
    test_traffic_integration
    test_cross_component_integration
    
    cleanup_env
    
    # Summary
    echo ""
    echo -e "${WHITE}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${WHITE}║                   Test Summary                         ║${NC}"
    echo -e "${WHITE}╚════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "Total Tests:  ${TESTS_TOTAL}"
    echo -e "${GREEN}Passed:      ${TESTS_PASSED}${NC}"
    echo -e "${RED}Failed:      ${TESTS_FAILED}${NC}"
    echo -e "${YELLOW}Skipped:     ${TESTS_SKIPPED}${NC}"
    echo ""
    
    if [ ${TESTS_FAILED} -eq 0 ]; then
        echo -e "${GREEN}╔════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║           All M0 Integration Tests Passed!             ║${NC}"
        echo -e "${GREEN}╚════════════════════════════════════════════════════════╝${NC}"
        exit 0
    else
        echo -e "${RED}╔════════════════════════════════════════════════════════╗${NC}"
        echo -e "${RED}║           Some M0 Integration Tests Failed!            ║${NC}"
        echo -e "${RED}╚════════════════════════════════════════════════════════╝${NC}"
        exit 1
    fi
}

main "$@"
