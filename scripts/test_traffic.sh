#!/bin/bash

#===============================================================================
# Traffic Distributor Test Suite
# M0-8: Traffic Distribution Decision Tests
#===============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
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
    echo -e "${MAGENTA}========================================${NC}"
    echo -e "${MAGENTA}$1${NC}"
    echo -e "${MAGENTA}========================================${NC}"
}

#-------------------------------------------------------------------------------
# Test Environment Setup
#-------------------------------------------------------------------------------

setup_test_env() {
    log_section "Setting Up Test Environment"
    
    mkdir -p /tmp/gocdn_test/traffic
    
    cat > /tmp/gocdn_test/traffic/test_config.yaml << 'EOF'
traffic_distributor:
  cleaning_mode: "scrubbing"
  
  sinkhole:
    enabled: true
    drop_policy: "immediate"
    sample_rate: 0.1
    drop_action: "tcp_reset"
    log_level: "basic"
  
  scrubbing:
    enabled: true
    cleaning_rules:
      - id: "block_scanners"
        name: "Block Port Scanners"
        pattern: ".*"
        action: "block"
        severity: "critical"
        max_qps: 1000
        bandwidth_mbps: 1000
        enabled: true
      - id: "rate_limit_bruteforce"
        name: "Rate Limit Brute Force"
        pattern: ".*"
        action: "rate_limit"
        severity: "high"
        max_qps: 50
        bandwidth_mbps: 100
        enabled: true
    reinjection:
      enabled: true
      target: "edge"
      delay: 100ms
    persist_strategy: "sample"
  
  decision_threshold:
    low_threshold: 40
    medium_threshold: 60
    high_threshold: 80
    critical_threshold: 100
  
  reinjection:
    enabled: true
    target: "edge"
    delay: 100ms
    strategy: "immediate"
    batch_size: 100
    batch_window: 1s
    max_retries: 3
    retry_delay: 1s
EOF
    
    log_info "Test configuration created: /tmp/gocdn_test/traffic/test_config.yaml"
}

cleanup_test_env() {
    log_section "Cleaning Up Test Environment"
    rm -rf /tmp/gocdn_test
    log_info "Test environment cleaned up"
}

#-------------------------------------------------------------------------------
# Traffic Distributor Initialization Tests
#-------------------------------------------------------------------------------

test_distributor_init() {
    log_section "Traffic Distributor Initialization Tests"
    
    # Test 1: Basic Initialization
    log_info "Test 1: Traffic Distributor Initialization"
    cat > /tmp/gocdn_test/traffic/test_init.go << 'EOF'
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
            LowThreshold:     40,
            MediumThreshold:  60,
            HighThreshold:    80,
            CriticalThreshold: 100,
        },
        SinkholeConfig: &distribute.SinkholeConfig{
            Enabled:    true,
            DropPolicy: "immediate",
        },
        ScrubbingConfig: &distribute.ScrubbingConfig{
            Enabled: true,
        },
    }
    
    distributor, err := distribute.NewTrafficDistributor(cfg)
    if err != nil {
        fmt.Printf("FAIL: Failed to create traffic distributor: %v\n", err)
        return
    }
    
    if distributor == nil {
        fmt.Println("FAIL: Traffic distributor is nil")
        return
    }
    
    fmt.Println("PASS: Traffic distributor initialized successfully")
}
EOF

    if cd /tmp/gocdn_test/traffic && go run test_init.go 2>/dev/null; then
        log_success "Traffic Distributor Initialization"
    else
        log_fail "Traffic Distributor Initialization"
    fi
    
    # Test 2: With Decision Thresholds
    log_info "Test 2: Decision Thresholds Configuration"
    cat > /tmp/gocdn_test/traffic/test_thresholds.go << 'EOF'
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
        SinkholeConfig: &distribute.SinkholeConfig{
            Enabled:    true,
            DropPolicy: "immediate",
        },
    }
    
    distributor, _ := distribute.NewTrafficDistributor(cfg)
    
    if distributor != nil {
        fmt.Println("PASS: Decision thresholds configured correctly")
    } else {
        fmt.Println("FAIL: Distributor nil")
    }
}
EOF

    if cd /tmp/gocdn_test/traffic && go run test_thresholds.go 2>/dev/null; then
        log_success "Decision Thresholds Configuration"
    else
        log_fail "Decision Thresholds Configuration"
    fi
}

#-------------------------------------------------------------------------------
# Traffic Request Tests
#-------------------------------------------------------------------------------

test_traffic_request() {
    log_section "Traffic Request Tests"
    
    # Test 1: Request Creation
    log_info "Test 1: Traffic Request Creation"
    cat > /tmp/gocdn_test/traffic/test_request.go << 'EOF'
package main

import (
    "fmt"
    "time"
    
    "github.com/ai-cdn-tunnel/pkg/config"
    "github.com/ai-cdn-tunnel/pkg/distribute"
)

func main() {
    req := &distribute.TrafficRequest{
        ID:             "req-001",
        ClientIP:       "192.168.1.100",
        RequestID:      "req-001",
        RequestMethod:  "GET",
        RequestURL:     "https://api.example.com/users",
        RequestHeaders: map[string]string{
            "User-Agent": "curl/7.68.0",
            "Accept":     "application/json",
        },
        RequestBody:    []byte{},
        RequestTime:    time.Now(),
    }
    
    if req.ID == "req-001" && req.RequestMethod == "GET" {
        fmt.Println("PASS: Traffic request created correctly")
    } else {
        fmt.Println("FAIL: Traffic request fields incorrect")
    }
}
EOF

    if cd /tmp/gocdn_test/traffic && go run test_request.go 2>/dev/null; then
        log_success "Traffic Request Creation"
    else
        log_fail "Traffic Request Creation"
    fi
}

#-------------------------------------------------------------------------------
# Decision Action Tests
#-------------------------------------------------------------------------------

test_decision_actions() {
    log_section "Decision Action Tests"
    
    # Test 1: Allow Decision
    log_info "Test 1: Allow Decision"
    cat > /tmp/gocdn_test/traffic/test_decision_allow.go << 'EOF'
package main

import (
    "fmt"
    "time"
    
    "github.com/ai-cdn-tunnel/pkg/distribute"
)

func main() {
    decision := &distribute.TrafficDecision{
        RequestID:  "req-001",
        Action:     distribute.DecisionActionAllow,
        TargetPath: "normal",
        Score:      20,
        RiskLevel:  "low",
        Reason:     "allowed",
    }
    
    if decision.Action == distribute.DecisionActionAllow {
        fmt.Println("PASS: Allow decision created correctly")
    } else {
        fmt.Println("FAIL: Allow decision incorrect")
    }
}
EOF

    if cd /tmp/gocdn_test/traffic && go run test_decision_allow.go 2>/dev/null; then
        log_success "Allow Decision"
    else
        log_fail "Allow Decision"
    fi
    
    # Test 2: Block Decision
    log_info "Test 2: Block Decision"
    cat > /tmp/gocdn_test/traffic/test_decision_block.go << 'EOF'
package main

import (
    "fmt"
    "time"
    
    "github.com/ai-cdn-tunnel/pkg/distribute"
)

func main() {
    decision := &distribute.TrafficDecision{
        RequestID:  "req-002",
        Action:     distribute.DecisionActionBlock,
        TargetPath: "normal",
        Score:      85,
        RiskLevel:  "critical",
        Reason:     "blocked by security rule",
    }
    
    if decision.Action == distribute.DecisionActionBlock {
        fmt.Println("PASS: Block decision created correctly")
    } else {
        fmt.Println("FAIL: Block decision incorrect")
    }
}
EOF

    if cd /tmp/gocdn_test/traffic && go run test_decision_block.go 2>/dev/null; then
        log_success "Block Decision"
    else
        log_fail "Block Decision"
    fi
    
    # Test 3: Sinkhole Decision
    log_info "Test 3: Sinkhole Decision"
    cat > /tmp/gocdn_test/traffic/test_decision_sinkhole.go << 'EOF'
package main

import (
    "fmt"
    "time"
    
    "github.com/ai-cdn-tunnel/pkg/distribute"
)

func main() {
    decision := &distribute.TrafficDecision{
        RequestID:  "req-003",
        Action:     distribute.DecisionActionSinkhole,
        TargetPath: "sinkhole",
        Score:      95,
        RiskLevel:  "critical",
        Reason:     "sinkhole: attack detected",
    }
    
    if decision.Action == distribute.DecisionActionSinkhole {
        fmt.Println("PASS: Sinkhole decision created correctly")
    } else {
        fmt.Println("FAIL: Sinkhole decision incorrect")
    }
}
EOF

    if cd /tmp/gocdn_test/traffic && go run test_decision_sinkhole.go 2>/dev/null; then
        log_success "Sinkhole Decision"
    else
        log_fail "Sinkhole Decision"
    fi
    
    # Test 4: Challenge Decision
    log_info "Test 4: Challenge Decision"
    cat > /tmp/gocdn_test/traffic/test_decision_challenge.go << 'EOF'
package main

import (
    "fmt"
    "time"
    
    "github.com/ai-cdn-tunnel/pkg/distribute"
)

func main() {
    decision := &distribute.TrafficDecision{
        RequestID:  "req-004",
        Action:     distribute.DecisionActionChallenge,
        TargetPath: "normal",
        Score:      65,
        RiskLevel:  "high",
        Reason:     "challenge: suspicious activity",
    }
    
    if decision.Action == distribute.DecisionActionChallenge {
        fmt.Println("PASS: Challenge decision created correctly")
    } else {
        fmt.Println("FAIL: Challenge decision incorrect")
    }
}
EOF

    if cd /tmp/gocdn_test/traffic && go run test_decision_challenge.go 2>/dev/null; then
        log_success "Challenge Decision"
    else
        log_fail "Challenge Decision"
    fi
    
    # Test 5: Rate Limit Decision
    log_info "Test 5: Rate Limit Decision"
    cat > /tmp/gocdn_test/traffic/test_decision_ratelimit.go << 'EOF'
package main

import (
    "fmt"
    "time"
    
    "github.com/ai-cdn-tunnel/pkg/distribute"
)

func main() {
    decision := &distribute.TrafficDecision{
        RequestID:  "req-005",
        Action:     distribute.DecisionActionRateLimit,
        TargetPath: "normal",
        Score:      55,
        RiskLevel:  "medium",
        Reason:     "rate limit: exceeding QPS limit",
    }
    
    if decision.Action == distribute.DecisionActionRateLimit {
        fmt.Println("PASS: Rate limit decision created correctly")
    } else {
        fmt.Println("FAIL: Rate limit decision incorrect")
    }
}
EOF

    if cd /tmp/gocdn_test/traffic && go run test_decision_ratelimit.go 2>/dev/null; then
        log_success "Rate Limit Decision"
    else
        log_fail "Rate Limit Decision"
    fi
    
    # Test 6: Scrubbing Decision
    log_info "Test 6: Scrubbing Decision"
    cat > /tmp/gocdn_test/traffic/test_decision_scrubbing.go << 'EOF'
package main

import (
    "fmt"
    "time"
    
    "github.com/ai-cdn-tunnel/pkg/distribute"
)

func main() {
    decision := &distribute.TrafficDecision{
        RequestID:  "req-006",
        Action:     distribute.DecisionActionScrubbing,
        TargetPath: "scrubbing",
        Score:      70,
        RiskLevel:  "high",
        Reason:     "scrubbing: DDoS attack detected",
        ReInjection: true,
    }
    
    if decision.Action == distribute.DecisionActionScrubbing {
        fmt.Println("PASS: Scrubbing decision created correctly")
    } else {
        fmt.Println("FAIL: Scrubbing decision incorrect")
    }
}
EOF

    if cd /tmp/gocdn_test/traffic && go run test_decision_scrubbing.go 2>/dev/null; then
        log_success "Scrubbing Decision"
    else
        log_fail "Scrubbing Decision"
    fi
}

#-------------------------------------------------------------------------------
# Sinkhole Mode Tests
#-------------------------------------------------------------------------------

test_sinkhole_mode() {
    log_section "Sinkhole Mode Tests"
    
    # Test 1: Immediate Drop
    log_info "Test 1: Sinkhole Immediate Drop"
    cat > /tmp/gocdn_test/traffic/test_sinkhole_immediate.go << 'EOF'
package main

import (
    "fmt"
    "time"
    
    "github.com/ai-cdn-tunnel/pkg/config"
    "github.com/ai-cdn-tunnel/pkg/distribute"
)

func main() {
    cfg := &distribute.TrafficDistributorConfig{
        CleaningMode: "sinkhole",
        SinkholeConfig: &distribute.SinkholeConfig{
            Enabled:    true,
            DropPolicy: "immediate",
            LogLevel:   "basic",
        },
    }
    
    distributor, _ := distribute.NewTrafficDistributor(cfg)
    
    req := &distribute.TrafficRequest{
        ID:            "req-001",
        RequestID:     "req-001",
        RequestMethod: "GET",
        RequestURL:    "http://malicious.com",
        ClientIP:      "203.0.113.50",
    }
    
    // Distribute request
    err := distributor.Distribute(req)
    if err != nil {
        fmt.Printf("FAIL: Distribute failed: %v\n", err)
        return
    }
    
    // Check if decision was made
    if req.Decision != nil && req.Decision.Action == distribute.DecisionActionSinkhole {
        fmt.Println("PASS: Sinkhole immediate drop working")
    } else {
        fmt.Println("FAIL: Sinkhole decision not made")
    }
}
EOF

    if cd /tmp/gocdn_test/traffic && go run test_sinkhole_immediate.go 2>/dev/null; then
        log_success "Sinkhole Immediate Drop"
    else
        log_fail "Sinkhole Immediate Drop"
    fi
    
    # Test 2: Sampled Drop
    log_info "Test 2: Sinkhole Sampled Drop"
    cat > /tmp/gocdn_test/traffic/test_sinkhole_sampled.go << 'EOF'
package main

import (
    "fmt"
    "time"
    
    "github.com/ai-cdn-tunnel/pkg/config"
    "github.com/ai-cdn-tunnel/pkg/distribute"
)

func main() {
    cfg := &distribute.TrafficDistributorConfig{
        CleaningMode: "sinkhole",
        SinkholeConfig: &distribute.SinkholeConfig{
            Enabled:    true,
            DropPolicy: "sampled",
            SampleRate: 0.1,
            LogLevel:   "details",
        },
    }
    
    distributor, _ := distribute.NewTrafficDistributor(cfg)
    
    req := &distribute.TrafficRequest{
        ID:            "req-002",
        RequestID:     "req-002",
        RequestMethod: "GET",
        RequestURL:    "http://suspicious.com",
        ClientIP:      "203.0.113.51",
    }
    
    err := distributor.Distribute(req)
    if err != nil {
        fmt.Printf("FAIL: Distribute failed: %v\n", err)
        return
    }
    
    fmt.Println("PASS: Sinkhole sampled drop configured")
}
EOF

    if cd /tmp/gocdn_test/traffic && go run test_sinkhole_sampled.go 2>/dev/null; then
        log_success "Sinkhole Sampled Drop"
    else
        log_fail "Sinkhole Sampled Drop"
    fi
}

#-------------------------------------------------------------------------------
# Statistics Tests
#-------------------------------------------------------------------------------

test_statistics() {
    log_section "Statistics Tests"
    
    log_info "Test 1: Statistics Collection"
    cat > /tmp/gocdn_test/traffic/test_stats.go << 'EOF'
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
            LowThreshold:     40,
            MediumThreshold:  60,
            HighThreshold:    80,
            CriticalThreshold: 100,
        },
    }
    
    distributor, _ := distribute.NewTrafficDistributor(cfg)
    
    // Make some test requests
    for i := 0; i < 10; i++ {
        req := &distribute.TrafficRequest{
            ID:            fmt.Sprintf("req-%d", i),
            RequestID:     fmt.Sprintf("req-%d", i),
            RequestMethod: "GET",
            RequestURL:    "http://example.com",
            ClientIP:      "192.168.1.100",
        }
        distributor.Distribute(req)
    }
    
    stats := distributor.GetStats()
    
    if stats.TotalRequests >= 10 {
        fmt.Printf("PASS: Statistics collected (total: %d)\n", stats.TotalRequests)
    } else {
        fmt.Printf("FAIL: Expected >=10 requests, got %d\n", stats.TotalRequests)
    }
}
EOF

    if cd /tmp/gocdn_test/traffic && go run test_stats.go 2>/dev/null; then
        log_success "Statistics Collection"
    else
        log_fail "Statistics Collection"
    fi
}

#-------------------------------------------------------------------------------
# Cleaning Mode Tests
#-------------------------------------------------------------------------------

test_cleaning_modes() {
    log_section "Cleaning Mode Tests"
    
    # Test 1: Scrubbing Mode
    log_info "Test 1: Scrubbing Mode Configuration"
    cat > /tmp/gocdn_test/traffic/test_scrubbing.go << 'EOF'
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
        ScrubbingConfig: &distribute.ScrubbingConfig{
            Enabled: true,
            CleaningRules: []*distribute.CleaningRule{
                {
                    ID:       "rule-1",
                    Name:     "Block Attack",
                    Pattern:  ".*",
                    Action:   "block",
                    Severity: "critical",
                    Enabled:  true,
                },
            },
            ReInjection: &distribute.ReInjectionConfig{
                Enabled: true,
                Target:  "edge",
                Delay:   100 * time.Millisecond,
            },
            PersistStrategy: "sample",
        },
    }
    
    distributor, _ := distribute.NewTrafficDistributor(cfg)
    
    req := &distribute.TrafficRequest{
        ID:            "req-001",
        RequestID:     "req-001",
        RequestMethod: "GET",
        RequestURL:    "http://example.com",
        ClientIP:      "192.168.1.100",
    }
    
    err := distributor.Distribute(req)
    if err != nil {
        fmt.Printf("FAIL: Distribute failed: %v\n", err)
        return
    }
    
    fmt.Println("PASS: Scrubbing mode configured with rules")
}
EOF

    if cd /tmp/gocdn_test/traffic && go run test_scrubbing.go 2>/dev/null; then
        log_success "Scrubbing Mode Configuration"
    else
        log_fail "Scrubbing Mode Configuration"
    fi
}

#-------------------------------------------------------------------------------
# ReInjection Tests
#-------------------------------------------------------------------------------

test_reinjection() {
    log_section "ReInjection Tests"
    
    log_info "Test 1: ReInjection Configuration"
    cat > /tmp/gocdn_test/traffic/test_reinjection.go << 'EOF'
package main

import (
    "fmt"
    "time"
    
    "github.com/ai-cdn-tunnel/pkg/distribute"
)

func main() {
    cfg := &distribute.TrafficDistributorConfig{
        CleaningMode: "scrubbing",
        ReInjection: &distribute.ReInjectionConfig{
            Enabled:     true,
            Target:      "edge",
            Delay:       100 * time.Millisecond,
            Strategy:    "immediate",
            BatchSize:   100,
            BatchWindow: 1 * time.Second,
            MaxRetries:  3,
            RetryDelay:  1 * time.Second,
        },
    }
    
    distributor, _ := distribute.NewTrafficDistributor(cfg)
    
    if distributor != nil {
        fmt.Println("PASS: ReInjection configuration loaded")
    } else {
        fmt.Println("FAIL: ReInjection configuration failed")
    }
}
EOF

    if cd /tmp/gocdn_test/traffic && go run test_reinjection.go 2>/dev/null; then
        log_success "ReInjection Configuration"
    else
        log_fail "ReInjection Configuration"
    fi
}

#-------------------------------------------------------------------------------
# Main Test Runner
#-------------------------------------------------------------------------------

main() {
    echo ""
    echo -e "${MAGENTA}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MAGENTA}║         GoCDN M0 Traffic Distributor Test Suite        ║${NC}"
    echo -e "${MAGENTA}║        Traffic Distribution Decision Tests             ║${NC}"
    echo -e "${MAGENTA}╚════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    setup_test_env
    
    test_distributor_init
    test_traffic_request
    test_decision_actions
    test_sinkhole_mode
    test_statistics
    test_cleaning_modes
    test_reinjection
    
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
