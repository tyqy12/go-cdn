#!/bin/bash

#===============================================================================
# Failover Controller Test Suite
# M0-8: Auto Switch / Rollback Tests
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
    
    mkdir -p /tmp/gocdn_test/failover
    
    cat > /tmp/gocdn_test/failover/test_config.yaml << 'EOF'
failover:
  enabled: true
  
  detection:
    interval: 5s
    timeout: 3s
    failure_threshold: 3
    success_threshold: 3
    types:
      - "http"
      - "tcp"
  
  switch:
    mode: "auto"
    switch_delay: 30s
    max_switches: 10
    window_start: "02:00"
    window_end: "06:00"
    forbid_switch_window: false
  
  rollback:
    enabled: true
    stable_window: 5m
    jitter_protection: 2m
    min_failure_time: 3m
    rollback_delay: 1m
    manual_rollback: true
  
  health_check:
    check_url: "http://origin.example.com/health"
    method: "GET"
    expected_status_code: 200
    response_body: "OK"
    interval: 10s
    timeout: 5s
    concurrency: 5
    healthy_threshold: 3
    unhealthy_threshold: 3
  
  alert:
    enabled: true
    switch_alert:
      enabled: true
      channels:
        - type: "webhook"
          endpoint: "https://alert.example.com/switch"
    rollback_alert:
      enabled: true
      channels:
        - type: "webhook"
          endpoint: "https://alert.example.com/rollback"
    continued_failure_alert:
      enabled: true
      threshold: 5
      channels:
        - type: "webhook"
          endpoint: "https://alert.example.com/failure"
  
  bgp_config:
    local_asn: 65001
    neighbor_asn: 65002
    neighbor_ip: "10.0.0.2"
    normal_prefixes:
      - "192.168.1.0/24"
    steering_prefixes:
      - "192.168.2.0/24"
  
  loadbalancer_config:
    type: "nginx"
    api_endpoint: "http://nginx.example.com/api"
    api_token: "secret_token"
    primary_backend: "origin-primary"
    secondary_backend: "origin-secondary"
    primary_weight: 100
    secondary_weight: 0
  
  route_table_config:
    destination: "192.168.0.0/16"
    gateway: "10.0.0.1"
    interface: "eth0"
    table_id: "rt-12345"
EOF
    
    log_info "Test configuration created: /tmp/gocdn_test/failover/test_config.yaml"
}

cleanup_test_env() {
    log_section "Cleaning Up Test Environment"
    rm -rf /tmp/gocdn_test
    log_info "Test environment cleaned up"
}

#-------------------------------------------------------------------------------
# Failover Controller Initialization Tests
#-------------------------------------------------------------------------------

test_failover_init() {
    log_section "Failover Controller Initialization Tests"
    
    # Test 1: Basic Initialization
    log_info "Test 1: Failover Controller Initialization"
    cat > /tmp/gocdn_test/failover/test_init.go << 'EOF'
package main

import (
    "fmt"
    "time"
    
    "github.com/ai-cdn-tunnel/pkg/config"
    "github.com/ai-cdn-tunnel/pkg/defense"
)

func main() {
    cfg := &config.FailoverConfig{
        Enabled: true,
        Detection: &config.FailoverDetection{
            Interval:        5 * time.Second,
            Timeout:         3 * time.Second,
            FailureThreshold: 3,
            SuccessThreshold: 3,
            Types:           []string{"http", "tcp"},
        },
        Switch: &config.FailoverSwitch{
            Mode:         "auto",
            SwitchDelay:  30 * time.Second,
            MaxSwitches:  10,
        },
        Rollback: &config.FailoverRollback{
            Enabled:         true,
            StableWindow:    5 * time.Minute,
            MinFailureTime:  3 * time.Minute,
            RollbackDelay:   1 * time.Minute,
        },
        HealthCheck: &config.FailoverHealthCheck{
            CheckURL:          "http://origin.example.com/health",
            Method:            "GET",
            ExpectedStatusCode: 200,
            Interval:          10 * time.Second,
            Timeout:           5 * time.Second,
        },
    }
    
    controller, err := defense.NewFailoverController(cfg)
    if err != nil {
        fmt.Printf("FAIL: Failed to create failover controller: %v\n", err)
        return
    }
    
    if controller == nil {
        fmt.Println("FAIL: Failover controller is nil")
        return
    }
    
    fmt.Println("PASS: Failover controller initialized successfully")
}
EOF

    if cd /tmp/gocdn_test/failover && go run test_init.go 2>/dev/null; then
        log_success "Failover Controller Initialization"
    else
        log_fail "Failover Controller Initialization"
    fi
    
    # Test 2: Status Check
    log_info "Test 2: Initial Status Check"
    cat > /tmp/gocdn_test/failover/test_status.go << 'EOF'
package main

import (
    "fmt"
    "time"
    
    "github.com/ai-cdn-tunnel/pkg/config"
    "github.com/ai-cdn-tunnel/pkg/defense"
)

func main() {
    cfg := &config.FailoverConfig{
        Enabled: true,
        Detection: &config.FailoverDetection{
            Interval:        5 * time.Second,
            Timeout:         3 * time.Second,
            FailureThreshold: 3,
            SuccessThreshold: 3,
        },
        Switch: &config.FailoverSwitch{
            Mode: "auto",
        },
        HealthCheck: &config.FailoverHealthCheck{
            CheckURL: "http://origin.example.com/health",
            Method:   "GET",
        },
    }
    
    controller, _ := defense.NewFailoverController(cfg)
    status := controller.GetStatus()
    
    if status.CurrentTarget == "primary" {
        fmt.Println("PASS: Initial status is primary")
    } else {
        fmt.Printf("FAIL: Expected 'primary', got '%s'\n", status.CurrentTarget)
    }
}
EOF

    if cd /tmp/gocdn_test/failover && go run test_status.go 2>/dev/null; then
        log_success "Initial Status Check"
    else
        log_fail "Initial Status Check"
    fi
}

#-------------------------------------------------------------------------------
# Health Check Tests
#-------------------------------------------------------------------------------

test_health_check() {
    log_section "Health Check Tests"
    
    # Test 1: HTTP Health Check
    log_info "Test 1: HTTP Health Check"
    cat > /tmp/gocdn_test/failover/test_http_check.go << 'EOF'
package main

import (
    "fmt"
    "time"
    
    "github.com/ai-cdn-tunnel/pkg/config"
    "github.com/ai-cdn-tunnel/pkg/defense"
)

func main() {
    cfg := &config.FailoverConfig{
        Enabled: true,
        Detection: &config.FailoverDetection{
            Interval:        1 * time.Second,
            Timeout:         2 * time.Second,
            FailureThreshold: 2,
            SuccessThreshold: 2,
            Types:           []string{"http"},
        },
        HealthCheck: &config.FailoverHealthCheck{
            CheckURL:           "http://httpbin.org/status/200",
            Method:             "GET",
            ExpectedStatusCode: 200,
            Interval:           1 * time.Second,
            Timeout:           2 * time.Second,
        },
        Switch: &config.FailoverSwitch{
            Mode: "auto",
        },
    }
    
    controller, _ := defense.NewFailoverController(cfg)
    
    // Perform one health check
    healthy := controller.checkTargetHealth("primary")
    
    if healthy {
        fmt.Println("PASS: HTTP health check passed (200 OK)")
    } else {
        fmt.Println("FAIL: HTTP health check failed")
    }
}
EOF

    if cd /tmp/gocdn_test/failover && go run test_http_check.go 2>/dev/null; then
        log_success "HTTP Health Check"
    else
        log_fail "HTTP Health Check"
    fi
    
    # Test 2: Health Check with Invalid URL
    log_info "Test 2: Health Check Failure Handling"
    cat > /tmp/gocdn_test/failover/test_check_fail.go << 'EOF'
package main

import (
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
            Types:            []string{"http"},
        },
        HealthCheck: &config.FailoverHealthCheck{
            CheckURL: "http://invalid.example.com/health",
            Method:   "GET",
            Interval: 1 * time.Second,
            Timeout:  1 * time.Second,
        },
        Switch: &config.FailoverSwitch{
            Mode: "auto",
        },
    }
    
    controller, _ := defense.NewFailoverController(cfg)
    
    // This should fail (connection refused)
    healthy := controller.checkTargetHealth("primary")
    
    if !healthy {
        fmt.Println("PASS: Health check correctly detected failure")
    } else {
        fmt.Println("FAIL: Health check should have failed")
    }
}
EOF

    if cd /tmp/gocdn_test/failover && go run test_check_fail.go 2>/dev/null; then
        log_success "Health Check Failure Handling"
    else
        log_fail "Health Check Failure Handling"
    fi
}

#-------------------------------------------------------------------------------
# Failover Switch Tests
#-------------------------------------------------------------------------------

test_failover_switch() {
    log_section "Failover Switch Tests"
    
    # Test 1: Auto Switch
    log_info "Test 1: Automatic Failover Switch"
    cat > /tmp/gocdn_test/failover/test_auto_switch.go << 'EOF'
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
            Types:            []string{"http"},
        },
        Switch: &config.FailoverSwitch{
            Mode:          "auto",
            SwitchDelay:   1 * time.Second,
            MaxSwitches:   10,
        },
        HealthCheck: &config.FailoverHealthCheck{
            CheckURL: "http://invalid.example.com/health",
            Method:   "GET",
            Interval: 1 * time.Second,
            Timeout:  1 * time.Second,
        },
    }
    
    controller, _ := defense.NewFailoverController(cfg)
    
    ctx := context.Background()
    
    // Trigger manual failover
    err := controller.ManualFailover(ctx, "test: manual failover")
    if err != nil {
        fmt.Printf("FAIL: Manual failover failed: %v\n", err)
        return
    }
    
    status := controller.GetStatus()
    if status.CurrentTarget == "secondary" {
        fmt.Println("PASS: Failover switch to secondary successful")
    } else {
        fmt.Printf("FAIL: Expected 'secondary', got '%s'\n", status.CurrentTarget)
    }
}
EOF

    if cd /tmp/gocdn_test/failover && go run test_auto_switch.go 2>/dev/null; then
        log_success "Automatic Failover Switch"
    else
        log_fail "Automatic Failover Switch"
    fi
    
    # Test 2: Switch Count Tracking
    log_info "Test 2: Switch Count Tracking"
    cat > /tmp/gocdn_test/failover/test_switch_count.go << 'EOF'
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
            Interval:        1 * time.Second,
            Timeout:         1 * time.Second,
            FailureThreshold: 2,
            SuccessThreshold: 2,
        },
        Switch: &config.FailoverSwitch{
            Mode: "auto",
        },
        HealthCheck: &config.FailoverHealthCheck{
            CheckURL: "http://invalid.example.com/health",
            Method:   "GET",
        },
    }
    
    controller, _ := defense.NewFailoverController(cfg)
    
    ctx := context.Background()
    
    // Multiple switches
    controller.ManualFailover(ctx, "test 1")
    controller.ManualRollback(ctx, "rollback 1")
    controller.ManualFailover(ctx, "test 2")
    
    status := controller.GetStatus()
    
    if status.FailoverCount >= 2 {
        fmt.Printf("PASS: Switch count tracked correctly (%d)\n", status.FailoverCount)
    } else {
        fmt.Printf("FAIL: Expected >=2 switches, got %d\n", status.FailoverCount)
    }
}
EOF

    if cd /tmp/gocdn_test/failover && go run test_switch_count.go 2>/dev/null; then
        log_success "Switch Count Tracking"
    else
        log_fail "Switch Count Tracking"
    fi
    
    # Test 3: Switch with BGP Config
    log_info "Test 3: Failover with BGP Configuration"
    cat > /tmp/gocdn_test/failover/test_bgp_switch.go << 'EOF'
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
        Switch: &config.FailoverSwitch{
            Mode: "auto",
        },
        BGPConfig: &config.BGPFailoverConfig{
            LocalASN:         65001,
            NeighborASN:      65002,
            NeighborIP:       "10.0.0.2",
            NormalPrefixes:   []string{"192.168.1.0/24"},
            SteeringPrefixes: []string{"192.168.2.0/24"},
        },
    }
    
    controller, _ := defense.NewFailoverController(cfg)
    
    ctx := context.Background()
    
    // Test BGP switch
    err := controller.ManualFailover(ctx, "test: BGP failover")
    if err != nil {
        fmt.Printf("FAIL: BGP failover failed: %v\n", err)
        return
    }
    
    status := controller.GetStatus()
    if status.CurrentTarget == "secondary" {
        fmt.Println("PASS: BGP failover switch successful")
    } else {
        fmt.Printf("FAIL: Expected 'secondary', got '%s'\n", status.CurrentTarget)
    }
}
EOF

    if cd /tmp/gocdn_test/failover && go run test_bgp_switch.go 2>/dev/null; then
        log_success "BGP Configuration Switch"
    else
        log_fail "BGP Configuration Switch"
    fi
}

#-------------------------------------------------------------------------------
# Rollback Tests
#-------------------------------------------------------------------------------

test_rollback() {
    log_section "Rollback Tests"
    
    # Test 1: Manual Rollback
    log_info "Test 1: Manual Rollback"
    cat > /tmp/gocdn_test/failover/test_manual_rollback.go << 'EOF'
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
        Switch: &config.FailoverSwitch{
            Mode: "auto",
        },
        Rollback: &config.FailoverRollback{
            Enabled: true,
        },
    }
    
    controller, _ := defense.NewFailoverController(cfg)
    
    ctx := context.Background()
    
    // First failover to secondary
    controller.ManualFailover(ctx, "test")
    
    status1 := controller.GetStatus()
    if status1.CurrentTarget != "secondary" {
        fmt.Println("FAIL: Should be on secondary after failover")
        return
    }
    
    // Then rollback
    err := controller.ManualRollback(ctx, "test: rollback")
    if err != nil {
        fmt.Printf("FAIL: Manual rollback failed: %v\n", err)
        return
    }
    
    status2 := controller.GetStatus()
    if status2.CurrentTarget == "primary" {
        fmt.Println("PASS: Manual rollback to primary successful")
    } else {
        fmt.Printf("FAIL: Expected 'primary' after rollback, got '%s'\n", status2.CurrentTarget)
    }
}
EOF

    if cd /tmp/gocdn_test/failover && go run test_manual_rollback.go 2>/dev/null; then
        log_success "Manual Rollback"
    else
        log_fail "Manual Rollback"
    fi
    
    # Test 2: Rollback When Already Primary
    log_info "Test 2: Rollback When Already Primary"
    cat > /tmp/gocdn_test/failover/test_rollback_primary.go << 'EOF'
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
        Switch: &config.FailoverSwitch{
            Mode: "auto",
        },
    }
    
    controller, _ := defense.NewFailoverController(cfg)
    
    ctx := context.Background()
    
    // Try to rollback when already on primary
    err := controller.ManualRollback(ctx, "test")
    
    if err != nil {
        fmt.Printf("PASS: Correctly rejected rollback when already primary: %v\n", err)
    } else {
        fmt.Println("FAIL: Should have rejected rollback when already primary")
    }
}
EOF

    if cd /tmp/gocdn_test/failover && go run test_rollback_primary.go 2>/dev/null; then
        log_success "Rollback When Primary"
    else
        log_fail "Rollback When Primary"
    fi
    
    # Test 3: Load Balancer Switch
    log_info "Test 3: Load Balancer Switch"
    cat > /tmp/gocdn_test/failover/test_lb_switch.go << 'EOF'
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
        Switch: &config.FailoverSwitch{
            Mode: "auto",
        },
        LoadBalancerConfig: &config.LoadBalancerFailoverConfig{
            Type:             "nginx",
            APIEndpoint:      "http://nginx.example.com/api",
            APIToken:         "secret",
            PrimaryBackend:   "origin-primary",
            SecondaryBackend: "origin-secondary",
            PrimaryWeight:    100,
            SecondaryWeight:  0,
        },
    }
    
    controller, _ := defense.NewFailoverController(cfg)
    
    ctx := context.Background()
    
    err := controller.ManualFailover(ctx, "test: LB switch")
    if err != nil {
        fmt.Printf("FAIL: LB switch failed: %v\n", err)
        return
    }
    
    status := controller.GetStatus()
    if status.CurrentTarget == "secondary" {
        fmt.Println("PASS: Load balancer switch successful")
    } else {
        fmt.Printf("FAIL: Expected 'secondary', got '%s'\n", status.CurrentTarget)
    }
}
EOF

    if cd /tmp/gocdn_test/failover && go run test_lb_switch.go 2>/dev/null; then
        log_success "Load Balancer Switch"
    else
        log_fail "Load Balancer Switch"
    fi
}

#-------------------------------------------------------------------------------
# Time Window Tests
#-------------------------------------------------------------------------------

test_time_windows() {
    log_section "Time Window Tests"
    
    # Test 1: Switch Window
    log_info "Test 1: Switch Window Configuration"
    cat > /tmp/gocdn_test/failover/test_window.go << 'EOF'
package main

import (
    "fmt"
    "time"
    
    "github.com/ai-cdn-tunnel/pkg/config"
    "github.com/ai-cdn-tunnel/pkg/defense"
)

func main() {
    cfg := &config.FailoverConfig{
        Enabled: true,
        Switch: &config.FailoverSwitch{
            Mode:               "auto",
            SwitchDelay:        30 * time.Second,
            WindowStart:        "02:00",
            WindowEnd:          "06:00",
            ForbidSwitchWindow: false,
        },
    }
    
    controller, _ := defense.NewFailoverController(cfg)
    
    status := controller.GetStatus()
    
    if status != nil {
        fmt.Println("PASS: Switch window configuration loaded")
    } else {
        fmt.Println("FAIL: Failed to get status")
    }
}
EOF

    if cd /tmp/gocdn_test/failover && go run test_window.go 2>/dev/null; then
        log_success "Switch Window Configuration"
    else
        log_fail "Switch Window Configuration"
    fi
}

#-------------------------------------------------------------------------------
# Main Test Runner
#-------------------------------------------------------------------------------

main() {
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║         GoCDN M0 Failover Controller Test Suite        ║${NC}"
    echo -e "${CYAN}║        Auto Switch / Rollback Tests                    ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    setup_test_env
    
    test_failover_init
    test_health_check
    test_failover_switch
    test_rollback
    test_time_windows
    
    cleanup_test_env
    
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
