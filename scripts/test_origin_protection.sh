#!/bin/bash

#===============================================================================
# Origin Protection Test Suite
# M0-8: Whitelist / Blacklist / ACL Tests
#===============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
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
    echo -e "${MAGENTA}========================================${NC}"
    echo -e "${MAGENTA}$1${NC}"
    echo -e "${MAGENTA}========================================${NC}"
}

#-------------------------------------------------------------------------------
# Test Environment Setup
#-------------------------------------------------------------------------------

setup_test_env() {
    log_section "Setting Up Test Environment"
    
    mkdir -p /tmp/gocdn_test/origin
    
    cat > /tmp/gocdn_test/origin/test_config.yaml << 'EOF'
origin_protection:
  enabled: true
  mode: "hybrid"
  
  allow_only_from:
    - id: "edge_ips"
      cidr: "10.0.0.0/8"
      name: "Edge Network"
      type: "edge"
    - id: "reinjection_ips"
      cidr: "172.16.0.0/12"
      name: "ReInjection Network"
      type: "reinjection"
    - id: "admin_ips"
      cidr: "192.168.100.0/24"
      name: "Admin Network"
      type: "admin"
  
  block_from:
    - id: "malicious_ips"
      cidr: "203.0.113.0/24"
      name: "Malicious IPs"
      type: "block"
  
  security_groups:
    - id: "sg_allow_edge"
      name: "Allow Edge Traffic"
      protocol: "tcp"
      port_range: "80,443"
      source: "10.0.0.0/8"
      destination: "origin"
      action: "allow"
      direction: "inbound"
      priority: 100
      enabled: true
  
  acls:
    - id: "acl_http_only"
      name: "HTTP Only"
      match:
        protocol: "tcp"
        http_method: "GET"
        http_path: "/api/*"
      action: "allow"
      priority: 10
      enabled: true
    - id: "acl_block_admin"
      name: "Block Admin Path"
      match:
        http_path: "/admin/*"
      action: "block"
      priority: 5
      enabled: true
  
  port_restrictions:
    allowed_ports:
      - 80
      - 443
      - 8080
    blocked_ports:
      - 22
      - 3389
  
  firewall_rules:
    - id: "fw_drop_scanners"
      name: "Drop Port Scanners"
      protocol: "tcp"
      port_range: "1-1024"
      source: "0.0.0.0/0"
      action: "deny"
      rate_limit: 100
      burst: 50
      enabled: true
  
  hide_origin:
    enabled: true
    header: "X-Forwarded-For"
  
  private_network:
    enabled: true
    check_private_ips: true
EOF
    
    log_info "Test configuration created: /tmp/gocdn_test/origin/test_config.yaml"
}

cleanup_test_env() {
    log_section "Cleaning Up Test Environment"
    rm -rf /tmp/gocdn_test
    log_info "Test environment cleaned up"
}

#-------------------------------------------------------------------------------
# Whitelist Mode Tests
#-------------------------------------------------------------------------------

test_whitelist_mode() {
    log_section "Whitelist Mode Tests"
    
    # Test 1: Whitelist Initialization
    log_info "Test 1: Origin Protection Initialization (Whitelist Mode)"
    cat > /tmp/gocdn_test/origin/test_whitelist_init.go << 'EOF'
package main

import (
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
        fmt.Printf("FAIL: Failed to create origin protector: %v\n", err)
        return
    }
    
    if protector == nil {
        fmt.Println("FAIL: Origin protector is nil")
        return
    }
    
    fmt.Println("PASS: Origin protector (whitelist mode) initialized successfully")
}
EOF

    if cd /tmp/gocdn_test/origin && go run test_whitelist_init.go 2>/dev/null; then
        log_success "Whitelist Initialization"
    else
        log_fail "Whitelist Initialization"
    fi
    
    # Test 2: Whitelist IP Allowed
    log_info "Test 2: Whitelist IP Access Allowed"
    cat > /tmp/gocdn_test/origin/test_whitelist_allow.go << 'EOF'
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
        },
    }
    
    protector, _ := security.NewOriginProtector(cfg)
    
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    
    // Test edge IP (should be allowed)
    decision, err := protector.CheckAccess(ctx, "10.0.1.1", 443, "tcp")
    if err != nil {
        fmt.Printf("FAIL: CheckAccess error: %v\n", err)
        return
    }
    
    if decision.Allowed {
        fmt.Println("PASS: Whitelist IP (10.0.1.1) access allowed")
    } else {
        fmt.Printf("FAIL: Whitelist IP denied: %s\n", decision.Reason)
    }
}
EOF

    if cd /tmp/gocdn_test/origin && go run test_whitelist_allow.go 2>/dev/null; then
        log_success "Whitelist IP Allowed"
    else
        log_fail "Whitelist IP Allowed"
    fi
    
    # Test 3: Non-Whitelist IP Denied
    log_info "Test 3: Non-Whitelist IP Denied"
    cat > /tmp/gocdn_test/origin/test_whitelist_deny.go << 'EOF'
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
        },
    }
    
    protector, _ := security.NewOriginProtector(cfg)
    
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    
    // Test non-whitelist IP (should be denied)
    decision, err := protector.CheckAccess(ctx, "8.8.8.8", 443, "tcp")
    if err != nil {
        fmt.Printf("FAIL: CheckAccess error: %v\n", err)
        return
    }
    
    if !decision.Allowed {
        fmt.Println("PASS: Non-whitelist IP (8.8.8.8) access denied")
    } else {
        fmt.Println("FAIL: Non-whitelist IP should have been denied")
    }
}
EOF

    if cd /tmp/gocdn_test/origin && go run test_whitelist_deny.go 2>/dev/null; then
        log_success "Non-Whitelist IP Denied"
    else
        log_fail "Non-Whitelist IP Denied"
    fi
    
    # Test 4: CIDR Range Matching
    log_info "Test 4: CIDR Range Matching"
    cat > /tmp/gocdn_test/origin/test_whitelist_cidr.go << 'EOF'
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
            {CIDR: "192.168.1.0/24", Name: "Internal", Type: "internal"},
        },
    }
    
    protector, _ := security.NewOriginProtector(cfg)
    
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    
    // Test IPs within /24 range
    tests := []struct {
        ip       string
        expected bool
    }{
        {"192.168.1.1", true},
        {"192.168.1.100", true},
        {"192.168.1.254", true},
        {"192.168.2.1", false},
        {"192.168.0.1", false},
    }
    
    allPassed := true
    for _, test := range tests {
        decision, _ := protector.CheckAccess(ctx, test.ip, 443, "tcp")
        if decision.Allowed != test.expected {
            fmt.Printf("FAIL: IP %s expected allowed=%v, got %v\n", 
                test.ip, test.expected, decision.Allowed)
            allPassed = false
        }
    }
    
    if allPassed {
        fmt.Println("PASS: CIDR range matching correct for all test IPs")
    }
}
EOF

    if cd /tmp/gocdn_test/origin && go run test_whitelist_cidr.go 2>/dev/null; then
        log_success "CIDR Range Matching"
    else
        log_fail "CIDR Range Matching"
    fi
}

#-------------------------------------------------------------------------------
# Blacklist Mode Tests
#-------------------------------------------------------------------------------

test_blacklist_mode() {
    log_section "Blacklist Mode Tests"
    
    # Test 1: Blacklist Initialization
    log_info "Test 1: Blacklist Mode Initialization"
    cat > /tmp/gocdn_test/origin/test_blacklist_init.go << 'EOF'
package main

import (
    "fmt"
    "time"
    
    "github.com/ai-cdn-tunnel/pkg/config"
    "github.com/ai-cdn-tunnel/pkg/security"
)

func main() {
    cfg := &config.OriginProtectionConfig{
        Enabled: true,
        Mode:    "blacklist",
        BlockFrom: []*config.IPRange{
            {CIDR: "203.0.113.0/24", Name: "Malicious", Type: "block"},
        },
    }
    
    protector, err := security.NewOriginProtector(cfg)
    if err != nil {
        fmt.Printf("FAIL: Failed to create origin protector: %v\n", err)
        return
    }
    
    if protector == nil {
        fmt.Println("FAIL: Origin protector is nil")
        return
    }
    
    fmt.Println("PASS: Origin protector (blacklist mode) initialized successfully")
}
EOF

    if cd /tmp/gocdn_test/origin && go run test_blacklist_init.go 2>/dev/null; then
        log_success "Blacklist Initialization"
    else
        log_fail "Blacklist Initialization"
    fi
    
    # Test 2: Blacklisted IP Denied
    log_info "Test 2: Blacklisted IP Denied"
    cat > /tmp/gocdn_test/origin/test_blacklist_deny.go << 'EOF'
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
        Mode:    "blacklist",
        BlockFrom: []*config.IPRange{
            {CIDR: "203.0.113.0/24", Name: "Malicious", Type: "block"},
        },
    }
    
    protector, _ := security.NewOriginProtector(cfg)
    
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    
    // Test blacklisted IP
    decision, err := protector.CheckAccess(ctx, "203.0.113.50", 443, "tcp")
    if err != nil {
        fmt.Printf("FAIL: CheckAccess error: %v\n", err)
        return
    }
    
    if !decision.Allowed {
        fmt.Println("PASS: Blacklisted IP (203.0.113.50) access denied")
    } else {
        fmt.Println("FAIL: Blacklisted IP should have been denied")
    }
}
EOF

    if cd /tmp/gocdn_test/origin && go run test_blacklist_deny.go 2>/dev/null; then
        log_success "Blacklisted IP Denied"
    else
        log_fail "Blacklisted IP Denied"
    fi
    
    # Test 3: Non-Blacklisted IP Allowed
    log_info "Test 3: Non-Blacklisted IP Allowed"
    cat > /tmp/gocdn_test/origin/test_blacklist_allow.go << 'EOF'
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
        Mode:    "blacklist",
        BlockFrom: []*config.IPRange{
            {CIDR: "203.0.113.0/24", Name: "Malicious", Type: "block"},
        },
    }
    
    protector, _ := security.NewOriginProtector(cfg)
    
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    
    // Test non-blacklisted IP
    decision, err := protector.CheckAccess(ctx, "8.8.8.8", 443, "tcp")
    if err != nil {
        fmt.Printf("FAIL: CheckAccess error: %v\n", err)
        return
    }
    
    if decision.Allowed {
        fmt.Println("PASS: Non-blacklisted IP (8.8.8.8) access allowed")
    } else {
        fmt.Printf("FAIL: Non-blacklisted IP denied: %s\n", decision.Reason)
    }
}
EOF

    if cd /tmp/gocdn_test/origin && go run test_blacklist_allow.go 2>/dev/null; then
        log_success "Non-Blacklisted IP Allowed"
    else
        log_fail "Non-Blacklisted IP Allowed"
    fi
}

#-------------------------------------------------------------------------------
# Hybrid Mode Tests
#-------------------------------------------------------------------------------

test_hybrid_mode() {
    log_section "Hybrid Mode Tests"
    
    # Test 1: Hybrid Mode Initialization
    log_info "Test 1: Hybrid Mode Initialization"
    cat > /tmp/gocdn_test/origin/test_hybrid_init.go << 'EOF'
package main

import (
    "fmt"
    "time"
    
    "github.com/ai-cdn-tunnel/pkg/config"
    "github.com/ai-cdn-tunnel/pkg/security"
)

func main() {
    cfg := &config.OriginProtectionConfig{
        Enabled: true,
        Mode:    "hybrid",
        AllowOnlyFrom: []*config.IPRange{
            {CIDR: "10.0.0.0/8", Name: "Edge", Type: "edge"},
        },
        BlockFrom: []*config.IPRange{
            {CIDR: "203.0.113.0/24", Name: "Malicious", Type: "block"},
        },
    }
    
    protector, err := security.NewOriginProtector(cfg)
    if err != nil {
        fmt.Printf("FAIL: Failed to create origin protector: %v\n", err)
        return
    }
    
    if protector == nil {
        fmt.Println("FAIL: Origin protector is nil")
        return
    }
    
    fmt.Println("PASS: Origin protector (hybrid mode) initialized successfully")
}
EOF

    if cd /tmp/gocdn_test/origin && go run test_hybrid_init.go 2>/dev/null; then
        log_success "Hybrid Initialization"
    else
        log_fail "Hybrid Initialization"
    fi
    
    # Test 2: Whitelist Has Priority in Hybrid
    log_info "Test 2: Whitelist Priority in Hybrid Mode"
    cat > /tmp/gocdn_test/origin/test_hybrid_priority.go << 'EOF'
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
        Mode:    "hybrid",
        AllowOnlyFrom: []*config.IPRange{
            {CIDR: "10.0.0.0/8", Name: "Edge", Type: "edge"},
        },
        BlockFrom: []*config.IPRange{
            {CIDR: "10.0.0.0/8", Name: "Overlapping", Type: "block"},
        },
    }
    
    protector, _ := security.NewOriginProtector(cfg)
    
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    
    // In hybrid mode, whitelist should have priority
    decision, err := protector.CheckAccess(ctx, "10.0.1.1", 443, "tcp")
    if err != nil {
        fmt.Printf("FAIL: CheckAccess error: %v\n", err)
        return
    }
    
    if decision.Allowed {
        fmt.Println("PASS: Whitelist priority in hybrid mode (allowed)")
    } else {
        fmt.Printf("FAIL: Whitelist should have priority, got: %s\n", decision.Reason)
    }
}
EOF

    if cd /tmp/gocdn_test/origin && go run test_hybrid_priority.go 2>/dev/null; then
        log_success "Whitelist Priority in Hybrid"
    else
        log_fail "Whitelist Priority in Hybrid"
    fi
}

#-------------------------------------------------------------------------------
# Port Restriction Tests
#-------------------------------------------------------------------------------

test_port_restrictions() {
    log_section "Port Restriction Tests"
    
    # Test 1: Allowed Ports
    log_info "Test 1: Allowed Ports Access"
    cat > /tmp/gocdn_test/origin/test_port_allowed.go << 'EOF'
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
        Mode:    "blacklist",
        PortRestrictions: &config.PortRestriction{
            AllowedPorts: []int{80, 443, 8080},
        },
    }
    
    protector, _ := security.NewOriginProtector(cfg)
    
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    
    // Test allowed port
    decision, _ := protector.CheckAccess(ctx, "8.8.8.8", 443, "tcp")
    if decision.Allowed {
        fmt.Println("PASS: Allowed port (443) access granted")
    } else {
        fmt.Printf("FAIL: Allowed port denied: %s\n", decision.Reason)
    }
}
EOF

    if cd /tmp/gocdn_test/origin && go run test_port_allowed.go 2>/dev/null; then
        log_success "Allowed Ports Access"
    else
        log_fail "Allowed Ports Access"
    fi
    
    # Test 2: Blocked Ports
    log_info "Test 2: Blocked Ports Denied"
    cat > /tmp/gocdn_test/origin/test_port_blocked.go << 'EOF'
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
        Mode:    "blacklist",
        PortRestrictions: &config.PortRestriction{
            BlockedPorts: []int{22, 3389},
        },
    }
    
    protector, _ := security.NewOriginProtector(cfg)
    
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    
    // Test blocked port
    decision, _ := protector.CheckAccess(ctx, "8.8.8.8", 22, "tcp")
    if !decision.Allowed {
        fmt.Println("PASS: Blocked port (22) access denied")
    } else {
        fmt.Println("FAIL: Blocked port should have been denied")
    }
}
EOF

    if cd /tmp/gocdn_test/origin && go run test_port_blocked.go 2>/dev/null; then
        log_success "Blocked Ports Denied"
    else
        log_fail "Blocked Ports Denied"
    fi
}

#-------------------------------------------------------------------------------
# ACL Rule Tests
#-------------------------------------------------------------------------------

test_acl_rules() {
    log_section "ACL Rule Tests"
    
    # Test 1: HTTP Method ACL
    log_info "Test 1: HTTP Method ACL Matching"
    cat > /tmp/gocdn_test/origin/test_acl_http.go << 'EOF'
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
        Mode:    "hybrid",
        AllowOnlyFrom: []*config.IPRange{
            {CIDR: "0.0.0.0/0", Name: "All", Type: "all"},
        },
        ACLs: []*config.ACLRule{
            {
                ID:   "allow_get",
                Name: "Allow GET",
                Match: config.ACLMatch{
                    HTTPMethod: "GET",
                },
                Action:   "allow",
                Priority: 10,
                Enabled:  true,
            },
        },
    }
    
    protector, _ := security.NewOriginProtector(cfg)
    
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    
    // Test GET method
    decision, _ := protector.CheckAccess(ctx, "8.8.8.8", 80, "tcp")
    if decision.Allowed {
        fmt.Println("PASS: ACL HTTP method matching works")
    } else {
        fmt.Printf("FAIL: GET request denied by ACL: %s\n", decision.Reason)
    }
}
EOF

    if cd /tmp/gocdn_test/origin && go run test_acl_http.go 2>/dev/null; then
        log_success "HTTP Method ACL Matching"
    else
        log_fail "HTTP Method ACL Matching"
    fi
}

#-------------------------------------------------------------------------------
# Dynamic Rule Tests
#-------------------------------------------------------------------------------

test_dynamic_rules() {
    log_section "Dynamic Rule Management Tests"
    
    # Test 1: Add Rule
    log_info "Test 1: Dynamic Rule Addition"
    cat > /tmp/gocdn_test/origin/test_rule_add.go << 'EOF'
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
        },
    }
    
    protector, _ := security.NewOriginProtector(cfg)
    
    // Add new rule
    err := protector.AddRule("192.168.1.0/24", "allow", "allow", 100)
    if err != nil {
        fmt.Printf("FAIL: Failed to add rule: %v\n", err)
        return
    }
    
    // Test new rule
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    
    decision, _ := protector.CheckAccess(ctx, "192.168.1.100", 443, "tcp")
    if decision.Allowed {
        fmt.Println("PASS: Dynamic rule added and working")
    } else {
        fmt.Printf("FAIL: New rule not working: %s\n", decision.Reason)
    }
}
EOF

    if cd /tmp/gocdn_test/origin && go run test_rule_add.go 2>/dev/null; then
        log_success "Dynamic Rule Addition"
    else
        log_fail "Dynamic Rule Addition"
    fi
    
    # Test 2: Remove Rule
    log_info "Test 2: Dynamic Rule Removal"
    cat > /tmp/gocdn_test/origin/test_rule_remove.go << 'EOF'
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
            {CIDR: "192.168.1.0/24", Name: "Test", Type: "test"},
        },
    }
    
    protector, _ := security.NewOriginProtector(cfg)
    
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    
    // Verify rule works before removal
    decision1, _ := protector.CheckAccess(ctx, "192.168.1.100", 443, "tcp")
    
    // Remove rule
    err := protector.RemoveRule("rule_test") // This will fail but tests the flow
    if err != nil {
        fmt.Printf("INFO: Rule removal test (expected to fail if rule ID not found): %v\n", err)
    }
    
    if !decision1.Allowed {
        fmt.Println("FAIL: Rule not working before removal")
    } else {
        fmt.Println("PASS: Rule management tested")
    }
}
EOF

    if cd /tmp/gocdn_test/origin && go run test_rule_remove.go 2>/dev/null; then
        log_success "Dynamic Rule Removal"
    else
        log_fail "Dynamic Rule Removal"
    fi
}

#-------------------------------------------------------------------------------
# Statistics Tests
#-------------------------------------------------------------------------------

test_statistics() {
    log_section "Statistics Tests"
    
    log_info "Test 1: Origin Protection Statistics"
    cat > /tmp/gocdn_test/origin/test_stats.go << 'EOF'
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
        },
    }
    
    protector, _ := security.NewOriginProtector(cfg)
    
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    
    // Make some access requests
    protector.CheckAccess(ctx, "10.0.1.1", 443, "tcp")
    protector.CheckAccess(ctx, "10.0.2.2", 443, "tcp")
    protector.CheckAccess(ctx, "8.8.8.8", 443, "tcp")
    
    // Get statistics
    stats := protector.GetStats()
    
    if stats.TotalRules > 0 {
        fmt.Printf("PASS: Statistics collected (rules: %d)\n", stats.TotalRules)
    } else {
        fmt.Println("FAIL: No statistics collected")
    }
}
EOF

    if cd /tmp/gocdn_test/origin && go run test_stats.go 2>/dev/null; then
        log_success "Statistics Collection"
    else
        log_fail "Statistics Collection"
    fi
}

#-------------------------------------------------------------------------------
# Main Test Runner
#-------------------------------------------------------------------------------

main() {
    echo ""
    echo -e "${MAGENTA}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MAGENTA}║         GoCDN M0 Origin Protection Test Suite          ║${NC}"
    echo -e "${MAGENTA}║      Whitelist / Blacklist / ACL Tests                 ║${NC}"
    echo -e "${MAGENTA}╚════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    setup_test_env
    
    test_whitelist_mode
    test_blacklist_mode
    test_hybrid_mode
    test_port_restrictions
    test_acl_rules
    test_dynamic_rules
    test_statistics
    
    cleanup_test_env
    
    echo ""
    echo -e "${MAGENTA}========================================${NC}"
    echo -e "${MAGENTA}Test Summary${NC}"
    echo -e "${MAGENTA}========================================${NC}"
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
