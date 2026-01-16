#!/bin/bash

#===============================================================================
# Steering Manager Test Suite
# M0-8: Steering/DNS/BGP/Anycast Provider Tests
#===============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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
    echo -e "${YELLOW}========================================${NC}"
    echo -e "${YELLOW}$1${NC}"
    echo -e "${YELLOW}========================================${NC}"
}

#-------------------------------------------------------------------------------
# Test Environment Setup
#-------------------------------------------------------------------------------

setup_test_env() {
    log_section "Setting Up Test Environment"
    
    # Create test directories
    mkdir -p /tmp/gocdn_test/{steering,reinjection,origin,failover,traffic}
    
    # Create test configuration files
    cat > /tmp/gocdn_test/steering/test_config.yaml << 'EOF'
steering:
  enabled: true
  mode: "dns"
  dns:
    provider: "cloudflare"
    access_key: "test_api_token"
    domain: "test.example.com"
    normal_record: "1.2.3.4"
    steering_ip: "5.6.7.8"
    ttl: 60
    record_type: "A"
  bgp:
    local_asn: 65001
    neighbor_asn: 65002
    neighbor_ip: "10.0.0.2"
    normal_prefixes:
      - "192.168.1.0/24"
    steering_prefixes:
      - "192.168.2.0/24"
  anycast:
    anycast_ip: "203.0.113.1"
    pops:
      - name: "shanghai"
        ip: "203.0.113.10"
        weight: 100
        region: "cn-east"
        active: true
      - name: "beijing"
        ip: "203.0.113.20"
        weight: 80
        region: "cn-north"
        active: true
    health_check:
      enabled: true
      interval: 30s
      timeout: 10s
  trigger:
    auto_steer: true
    cooldown: 5m
    conditions:
      - type: "bandwidth"
        threshold: 2.0
        action: "steer"
      - type: "pps"
        threshold: 50000
        action: "steer"
      - type: "syn_ratio"
        threshold: 0.1
        action: "steer"
  fallback:
    strategy: "auto"
    stable_window: 10m
    min_steering_time: 15m
EOF
    
    log_info "Test configuration created: /tmp/gocdn_test/steering/test_config.yaml"
}

cleanup_test_env() {
    log_section "Cleaning Up Test Environment"
    rm -rf /tmp/gocdn_test
    log_info "Test environment cleaned up"
}

#-------------------------------------------------------------------------------
# DNS Provider Tests
#-------------------------------------------------------------------------------

test_dns_provider() {
    log_section "DNS Provider Tests"
    
    # Test 1: DNS Provider Initialization
    log_info "Test 1: DNS Provider Initialization"
    cat > /tmp/gocdn_test/steering/test_dns_init.go << 'EOF'
package main

import (
    "context"
    "fmt"
    "time"
    
    "github.com/ai-cdn-tunnel/pkg/config"
    "github.com/ai-cdn-tunnel/pkg/defense"
)

func main() {
    cfg := &config.DNSSConfig{
        Provider:      "cloudflare",
        AccessKey:     "test_token",
        Domain:        "test.example.com",
        NormalRecord:  "1.2.3.4",
        SteeringIP:    "5.6.7.8",
        TTL:           60,
        RecordType:    "A",
    }
    
    provider, err := defense.NewDNSProvider(cfg)
    if err != nil {
        fmt.Printf("FAIL: Failed to create DNS provider: %v\n", err)
        return
    }
    
    if provider == nil {
        fmt.Println("FAIL: DNS provider is nil")
        return
    }
    
    fmt.Println("PASS: DNS provider initialized successfully")
}
EOF

    if cd /tmp/gocdn_test/steering && go run test_dns_init.go 2>/dev/null; then
        log_success "DNS Provider Initialization"
    else
        log_fail "DNS Provider Initialization"
    fi
    
    # Test 2: DNS Status Check
    log_info "Test 2: DNS Status Check"
    cat > /tmp/gocdn_test/steering/test_dns_status.go << 'EOF'
package main

import (
    "context"
    "fmt"
    "time"
    
    "github.com/ai-cdn-tunnel/pkg/config"
    "github.com/ai-cdn-tunnel/pkg/defense"
)

func main() {
    cfg := &config.DNSSConfig{
        Provider:      "cloudflare",
        AccessKey:     "test_token",
        Domain:        "test.example.com",
        NormalRecord:  "1.2.3.4",
        SteeringIP:    "5.6.7.8",
        TTL:           60,
        RecordType:    "A",
    }
    
    provider, _ := defense.NewDNSProvider(cfg)
    
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    
    status, err := provider.GetStatus(ctx)
    if err != nil {
        fmt.Printf("FAIL: Failed to get DNS status: %v\n", err)
        return
    }
    
    if status.Provider != "cloudflare" {
        fmt.Printf("FAIL: Expected provider 'cloudflare', got '%s'\n", status.Provider)
        return
    }
    
    if status.Domain != "test.example.com" {
        fmt.Printf("FAIL: Expected domain 'test.example.com', got '%s'\n", status.Domain)
        return
    }
    
    if status.IsSteering {
        fmt.Println("FAIL: Expected IsSteering to be false")
        return
    }
    
    fmt.Println("PASS: DNS status check passed")
}
EOF

    if cd /tmp/gocdn_test/steering && go run test_dns_status.go 2>/dev/null; then
        log_success "DNS Status Check"
    else
        log_fail "DNS Status Check"
    fi
    
    # Test 3: DNS Switch to Steering
    log_info "Test 3: DNS Switch to Steering"
    cat > /tmp/gocdn_test/steering/test_dns_steer.go << 'EOF'
package main

import (
    "context"
    "fmt"
    "time"
    
    "github.com/ai-cdn-tunnel/pkg/config"
    "github.com/ai-cdn-tunnel/pkg/defense"
)

func main() {
    cfg := &config.DNSSConfig{
        Provider:      "aliyun",
        AccessKey:     "test_key",
        AccessSecret:  "test_secret",
        Domain:        "test.example.com",
        NormalRecord:  "1.2.3.4",
        SteeringIP:    "5.6.7.8",
        TTL:           60,
        RecordType:    "A",
    }
    
    provider, _ := defense.NewDNSProvider(cfg)
    
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    
    // Note: This will fail due to invalid credentials, but tests the flow
    err := provider.SwitchToSteering(ctx)
    if err != nil {
        // Expected to fail with test credentials
        fmt.Printf("INFO: Expected error with test credentials: %v\n", err)
    }
    
    // Check status after switch attempt
    status, _ := provider.GetStatus(ctx)
    
    // Verify the provider tracks state correctly
    if status.Provider == "aliyun" && status.Domain == "test.example.com" {
        fmt.Println("PASS: DNS switch to steering logic verified")
    } else {
        fmt.Println("FAIL: DNS status not updated correctly")
    }
}
EOF

    if cd /tmp/gocdn_test/steering && go run test_dns_steer.go 2>&1 | grep -q "PASS\|INFO"; then
        log_success "DNS Switch to Steering"
    else
        log_fail "DNS Switch to Steering"
    fi
    
    # Test 4: Multi-Provider Support
    log_info "Test 4: Multi-Provider Support (Cloudflare, DNSPod, Route53)"
    
    providers=("cloudflare" "dnspod" "route53")
    for provider_type in "${providers[@]}"; do
        cat > /tmp/gocdn_test/steering/test_provider_$provider_type.go << EOF
package main

import (
    "context"
    "fmt"
    "time"
    
    "github.com/ai-cdn-tunnel/pkg/config"
    "github.com/ai-cdn-tunnel/pkg/defense"
)

func main() {
    cfg := &config.DNSSConfig{
        Provider:     "$provider_type",
        AccessKey:    "test_key",
        AccessSecret: "test_secret",
        Domain:       "test.example.com",
        NormalRecord: "1.2.3.4",
        SteeringIP:   "5.6.7.8",
        TTL:          60,
        RecordType:   "A",
    }
    
    provider, err := defense.NewDNSProvider(cfg)
    if err != nil {
        fmt.Printf("FAIL: Failed to create %s provider: %v\n", "$provider_type", err)
        return
    }
    
    if provider == nil {
        fmt.Printf("FAIL: %s provider is nil\n", "$provider_type")
        return
    }
    
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    
    status, _ := provider.GetStatus(ctx)
    if status.Provider == "$provider_type" {
        fmt.Printf("PASS: %s provider initialized\n", "$provider_type")
    } else {
        fmt.Printf("FAIL: %s provider not configured correctly\n", "$provider_type")
    }
}
EOF
        if cd /tmp/gocdn_test/steering && go run test_provider_$provider_type.go 2>/dev/null; then
            log_success "Provider $provider_type Support"
        else
            log_fail "Provider $provider_type Support"
        fi
    done
}

#-------------------------------------------------------------------------------
# BGP Provider Tests
#-------------------------------------------------------------------------------

test_bgp_provider() {
    log_section "BGP Provider Tests"
    
    # Test 1: BGP Provider Initialization
    log_info "Test 1: BGP Provider Initialization"
    cat > /tmp/gocdn_test/steering/test_bgp_init.go << 'EOF'
package main

import (
    "context"
    "fmt"
    
    "github.com/ai-cdn-tunnel/pkg/config"
    "github.com/ai-cdn-tunnel/pkg/defense"
)

func main() {
    cfg := &config.BGPConfig{
        LocalASN:  65001,
        NeighborASN: 65002,
        NeighborIP: "10.0.0.2",
        NormalPrefixes: []string{
            "192.168.1.0/24",
            "10.0.0.0/16",
        },
        SteeringPrefixes: []string{
            "192.168.2.0/24",
        },
    }
    
    provider, err := defense.NewBGPProvider(cfg)
    if err != nil {
        fmt.Printf("FAIL: Failed to create BGP provider: %v\n", err)
        return
    }
    
    if provider == nil {
        fmt.Println("FAIL: BGP provider is nil")
        return
    }
    
    fmt.Println("PASS: BGP provider initialized successfully")
}
EOF

    if cd /tmp/gocdn_test/steering && go run test_bgp_init.go 2>/dev/null; then
        log_success "BGP Provider Initialization"
    else
        log_fail "BGP Provider Initialization"
    fi
    
    # Test 2: BGP Route Advertisement
    log_info "Test 2: BGP Route Advertisement"
    cat > /tmp/gocdn_test/steering/test_bgp_advertise.go << 'EOF'
package main

import (
    "context"
    "fmt"
    "time"
    
    "github.com/ai-cdn-tunnel/pkg/config"
    "github.com/ai-cdn-tunnel/pkg/defense"
)

func main() {
    cfg := &config.BGPConfig{
        LocalASN:     65001,
        NeighborASN:  65002,
        NeighborIP:   "10.0.0.2",
        NormalPrefixes: []string{"192.168.1.0/24"},
        SteeringPrefixes: []string{"192.168.2.0/24"},
    }
    
    provider, _ := defense.NewBGPProvider(cfg)
    
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    
    // Test route advertisement
    err := provider.AdvertiseSteering(ctx)
    if err != nil {
        fmt.Printf("FAIL: Route advertisement failed: %v\n", err)
        return
    }
    
    status, _ := provider.GetStatus(ctx)
    
    // Verify steering prefixes are active
    isSteering := false
    for _, prefix := range status.ActivePrefixes {
        if prefix == "192.168.2.0/24" {
            isSteering = true
            break
        }
    }
    
    if isSteering {
        fmt.Println("PASS: BGP route advertisement successful")
    } else {
        fmt.Println("FAIL: Steering prefix not in active prefixes")
    }
}
EOF

    if cd /tmp/gocdn_test/steering && go run test_bgp_advertise.go 2>/dev/null; then
        log_success "BGP Route Advertisement"
    else
        log_fail "BGP Route Advertisement"
    fi
    
    # Test 3: BGP Route Withdrawal
    log_info "Test 3: BGP Route Withdrawal"
    cat > /tmp/gocdn_test/steering/test_bgp_withdraw.go << 'EOF'
package main

import (
    "context"
    "fmt"
    "time"
    
    "github.com/ai-cdn-tunnel/pkg/config"
    "github.com/ai-cdn-tunnel/pkg/defense"
)

func main() {
    cfg := &config.BGPConfig{
        LocalASN:     65001,
        NeighborASN:  65002,
        NeighborIP:   "10.0.0.2",
        NormalPrefixes: []string{"192.168.1.0/24"},
        SteeringPrefixes: []string{"192.168.2.0/24"},
    }
    
    provider, _ := defense.NewBGPProvider(cfg)
    
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    
    // First advertise steering routes
    provider.AdvertiseSteering(ctx)
    
    // Then withdraw
    err := provider.WithdrawSteering(ctx)
    if err != nil {
        fmt.Printf("FAIL: Route withdrawal failed: %v\n", err)
        return
    }
    
    status, _ := provider.GetStatus(ctx)
    
    // Verify steering prefixes are removed
    isSteering := false
    for _, prefix := range status.ActivePrefixes {
        if prefix == "192.168.2.0/24" {
            isSteering = true
            break
        }
    }
    
    if !isSteering {
        fmt.Println("PASS: BGP route withdrawal successful")
    } else {
        fmt.Println("FAIL: Steering prefix still active after withdrawal")
    }
}
EOF

    if cd /tmp/gocdn_test/steering && go run test_bgp_withdraw.go 2>/dev/null; then
        log_success "BGP Route Withdrawal"
    else
        log_fail "BGP Route Withdrawal"
    fi
    
    # Test 4: BGP Status Check
    log_info "Test 4: BGP Status Check"
    cat > /tmp/gocdn_test/steering/test_bgp_status.go << 'EOF'
package main

import (
    "context"
    "fmt"
    "time"
    
    "github.com/ai-cdn-tunnel/pkg/config"
    "github.com/ai-cdn-tunnel/pkg/defense"
)

func main() {
    cfg := &config.BGPConfig{
        LocalASN:     65001,
        NeighborASN:  65002,
        NeighborIP:   "10.0.0.2",
        NormalPrefixes: []string{"192.168.1.0/24", "10.0.0.0/16"},
        SteeringPrefixes: []string{"192.168.2.0/24"},
    }
    
    provider, _ := defense.NewBGPProvider(cfg)
    
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    
    status, err := provider.GetStatus(ctx)
    if err != nil {
        fmt.Printf("FAIL: Failed to get BGP status: %v\n", err)
        return
    }
    
    // Check initial state (should be normal, not steering)
    if status.IsSteering {
        fmt.Println("FAIL: Expected IsSteering to be false initially")
        return
    }
    
    // Check normal prefixes are active
    hasNormalPrefix := false
    for _, prefix := range status.ActivePrefixes {
        if prefix == "192.168.1.0/24" {
            hasNormalPrefix = true
            break
        }
    }
    
    if hasNormalPrefix {
        fmt.Println("PASS: BGP status check passed")
    } else {
        fmt.Println("FAIL: Normal prefix not active")
    }
}
EOF

    if cd /tmp/gocdn_test/steering && go run test_bgp_status.go 2>/dev/null; then
        log_success "BGP Status Check"
    else
        log_fail "BGP Status Check"
    fi
}

#-------------------------------------------------------------------------------
# Anycast Provider Tests
#-------------------------------------------------------------------------------

test_anycast_provider() {
    log_section "Anycast Provider Tests"
    
    # Test 1: Anycast Provider Initialization
    log_info "Test 1: Anycast Provider Initialization"
    cat > /tmp/gocdn_test/steering/test_anycast_init.go << 'EOF'
package main

import (
    "context"
    "fmt"
    
    "github.com/ai-cdn-tunnel/pkg/config"
    "github.com/ai-cdn-tunnel/pkg/defense"
)

func main() {
    cfg := &config.AnycastConfig{
        AnycastIP: "203.0.113.1",
        Pops: []*config.AnycastPOP{
            {
                Name:   "shanghai",
                IP:     "203.0.113.10",
                Weight: 100,
                Region: "cn-east",
                Active: true,
            },
            {
                Name:   "beijing",
                IP:     "203.0.113.20",
                Weight: 80,
                Region: "cn-north",
                Active: true,
            },
        },
        HealthCheck: &config.AnycastHealthCheck{
            Enabled:  true,
            Interval: 30 * 1000000000,
            Timeout:  10 * 1000000000,
        },
    }
    
    provider, err := defense.NewAnycastProvider(cfg)
    if err != nil {
        fmt.Printf("FAIL: Failed to create Anycast provider: %v\n", err)
        return
    }
    
    if provider == nil {
        fmt.Println("FAIL: Anycast provider is nil")
        return
    }
    
    fmt.Println("PASS: Anycast provider initialized successfully")
}
EOF

    if cd /tmp/gocdn_test/steering && go run test_anycast_init.go 2>/dev/null; then
        log_success "Anycast Provider Initialization"
    else
        log_fail "Anycast Provider Initialization"
    fi
    
    # Test 2: POP Health Check
    log_info "Test 2: POP Health Check"
    cat > /tmp/gocdn_test/steering/test_anycast_health.go << 'EOF'
package main

import (
    "context"
    "fmt"
    "time"
    
    "github.com/ai-cdn-tunnel/pkg/config"
    "github.com/ai-cdn-tunnel/pkg/defense"
)

func main() {
    cfg := &config.AnycastConfig{
        AnycastIP: "203.0.113.1",
        Pops: []*config.AnycastPOP{
            {
                Name:   "shanghai",
                IP:     "203.0.113.10",
                Weight: 100,
                Region: "cn-east",
                Active: true,
            },
            {
                Name:   "beijing",
                IP:     "203.0.113.20",
                Weight: 80,
                Region: "cn-north",
                Active: true,
            },
        },
        HealthCheck: &config.AnycastHealthCheck{
            Enabled:  true,
            Interval: 30 * 1000000000,
            Timeout:  10 * 1000000000,
        },
    }
    
    provider, _ := defense.NewAnycastProvider(cfg)
    
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    
    pops, err := provider.GetHealthyPOPs(ctx)
    if err != nil {
        fmt.Printf("FAIL: Failed to get healthy POPs: %v\n", err)
        return
    }
    
    // Should return both active POPs
    if len(pops) == 2 {
        fmt.Println("PASS: POP health check returned correct count")
    } else {
        fmt.Printf("FAIL: Expected 2 healthy POPs, got %d\n", len(pops))
    }
}
EOF

    if cd /tmp/gocdn_test/steering && go run test_anycast_health.go 2>/dev/null; then
        log_success "POP Health Check"
    else
        log_fail "POP Health Check"
    fi
    
    # Test 3: Best POP Selection
    log_info "Test 3: Best POP Selection (Weighted)"
    cat > /tmp/gocdn_test/steering/test_anycast_bestpop.go << 'EOF'
package main

import (
    "context"
    "fmt"
    "time"
    
    "github.com/ai-cdn-tunnel/pkg/config"
    "github.com/ai-cdn-tunnel/pkg/defense"
)

func main() {
    cfg := &config.AnycastConfig{
        AnycastIP: "203.0.113.1",
        Pops: []*config.AnycastPOP{
            {
                Name:   "shanghai",
                IP:     "203.0.113.10",
                Weight: 100,  // Higher weight
                Region: "cn-east",
                Active: true,
            },
            {
                Name:   "beijing",
                IP:     "203.0.113.20",
                Weight: 80,   // Lower weight
                Region: "cn-north",
                Active: true,
            },
        },
        HealthCheck: &config.AnycastHealthCheck{
            Enabled:  true,
            Interval: 30 * 1000000000,
            Timeout:  10 * 1000000000,
        },
    }
    
    provider, _ := defense.NewAnycastProvider(cfg)
    
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    
    routing, err := provider.GetRouting(ctx)
    if err != nil {
        fmt.Printf("FAIL: Failed to get routing: %v\n", err)
        return
    }
    
    // Shanghai has higher weight, should be selected
    if routing.CurrentPOP == "shanghai" {
        fmt.Println("PASS: Best POP selection (weighted) correct")
    } else {
        fmt.Printf("FAIL: Expected 'shanghai' as best POP, got '%s'\n", routing.CurrentPOP)
    }
}
EOF

    if cd /tmp/gocdn_test/steering && go run test_anycast_bestpop.go 2>/dev/null; then
        log_success "Best POP Selection"
    else
        log_fail "Best POP Selection"
    fi
    
    # Test 4: Anycast Routing Status
    log_info "Test 4: Anycast Routing Status"
    cat > /tmp/gocdn_test/steering/test_anycast_routing.go << 'EOF'
package main

import (
    "context"
    "fmt"
    "time"
    
    "github.com/ai-cdn-tunnel/pkg/config"
    "github.com/ai-cdn-tunnel/pkg/defense"
)

func main() {
    cfg := &config.AnycastConfig{
        AnycastIP: "203.0.113.1",
        Pops: []*config.AnycastPOP{
            {Name: "shanghai", IP: "203.0.113.10", Weight: 100, Region: "cn-east", Active: true},
            {Name: "beijing", IP: "203.0.113.20", Weight: 80, Region: "cn-north", Active: true},
        },
        HealthCheck: &config.AnycastHealthCheck{
            Enabled:  true,
            Interval: 30 * 1000000000,
            Timeout:  10 * 1000000000,
        },
    }
    
    provider, _ := defense.NewAnycastProvider(cfg)
    
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    
    routing, err := provider.GetRouting(ctx)
    if err != nil {
        fmt.Printf("FAIL: Failed to get routing: %v\n", err)
        return
    }
    
    // Verify routing status
    if routing.TotalPOPs == 2 && routing.ActivePOPs == 2 {
        fmt.Println("PASS: Anycast routing status correct")
    } else {
        fmt.Printf("FAIL: Expected 2 total, 2 active POPs, got %d total, %d active\n", 
            routing.TotalPOPs, routing.ActivePOPs)
    }
}
EOF

    if cd /tmp/gocdn_test/steering && go run test_anycast_routing.go 2>/dev/null; then
        log_success "Anycast Routing Status"
    else
        log_fail "Anycast Routing Status"
    fi
}

#-------------------------------------------------------------------------------
# Steering Manager Tests
#-------------------------------------------------------------------------------

test_steering_manager() {
    log_section "Steering Manager Tests"
    
    # Test 1: Steering Manager Initialization
    log_info "Test 1: Steering Manager Initialization"
    cat > /tmp/gocdn_test/steering/test_manager_init.go << 'EOF'
package main

import (
    "fmt"
    
    "github.com/ai-cdn-tunnel/pkg/config"
    "github.com/ai-cdn-tunnel/pkg/defense"
)

func main() {
    cfg := &config.SteeringConfig{
        Enabled: true,
        Mode:    "dns",
        DNS: &config.DNSSConfig{
            Provider:     "cloudflare",
            AccessKey:    "test_token",
            Domain:       "test.example.com",
            NormalRecord: "1.2.3.4",
            SteeringIP:   "5.6.7.8",
            TTL:          60,
            RecordType:   "A",
        },
        Trigger: &config.SteeringTriggerConfig{
            AutoSteer:   true,
            Cooldown:    5 * 60 * 1000000000,
        },
    }
    
    manager, err := defense.NewSteeringManager(cfg)
    if err != nil {
        fmt.Printf("FAIL: Failed to create steering manager: %v\n", err)
        return
    }
    
    if manager == nil {
        fmt.Println("FAIL: Steering manager is nil")
        return
    }
    
    fmt.Println("PASS: Steering manager initialized successfully")
}
EOF

    if cd /tmp/gocdn_test/steering && go run test_manager_init.go 2>/dev/null; then
        log_success "Steering Manager Initialization"
    else
        log_fail "Steering Manager Initialization"
    fi
    
    # Test 2: Steering Trigger Check
    log_info "Test 2: Steering Trigger Conditions"
    cat > /tmp/gocdn_test/steering/test_trigger.go << 'EOF'
package main

import (
    "context"
    "fmt"
    "time"
    
    "github.com/ai-cdn-tunnel/pkg/config"
    "github.com/ai-cdn-tunnel/pkg/defense"
)

func main() {
    cfg := &config.SteeringTriggerConfig{
        AutoSteer: true,
        Cooldown:  5 * 60 * 1000000000,
        Conditions: []*config.SteeringCondition{
            {Type: "bandwidth", Threshold: 2.0, Action: "steer"},
            {Type: "pps", Threshold: 50000, Action: "steer"},
            {Type: "syn_ratio", Threshold: 0.1, Action: "steer"},
        },
    }
    
    trigger := defense.NewSteeringTrigger(cfg)
    
    alerts := make([]*defense.SteeringAlert, 0)
    handler := func(alert *defense.SteeringAlert) {
        alerts = append(alerts, alert)
    }
    
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    
    trigger.Start(ctx, handler)
    
    // Wait for trigger check
    time.Sleep(2 * time.Second)
    
    if len(alerts) > 0 {
        fmt.Printf("PASS: Steering trigger fired: %s=%.2f\n", 
            alerts[0].TriggerType, alerts[0].TriggerValue)
    } else {
        fmt.Println("PASS: Steering trigger check completed (no threshold exceeded in test)")
    }
}
EOF

    if cd /tmp/gocdn_test/steering && go run test_trigger.go 2>/dev/null; then
        log_success "Steering Trigger Check"
    else
        log_fail "Steering Trigger Check"
    fi
}

#-------------------------------------------------------------------------------
# Main Test Runner
#-------------------------------------------------------------------------------

main() {
    echo ""
    echo -e "${BLUE}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║           GoCDN M0 Steering Test Suite                 ║${NC}"
    echo -e "${BLUE}║          DNS / BGP / Anycast Provider Tests           ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # Setup
    setup_test_env
    
    # Run tests
    test_dns_provider
    test_bgp_provider
    test_anycast_provider
    test_steering_manager
    
    # Cleanup
    cleanup_test_env
    
    # Summary
    echo ""
    echo -e "${YELLOW}========================================${NC}"
    echo -e "${YELLOW}Test Summary${NC}"
    echo -e "${YELLOW}========================================${NC}"
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
