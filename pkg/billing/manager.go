package billing

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// BillingManager 计费管理服务
type BillingManager struct {
	config    *BillingConfig
	plans     map[string]*Plan
	users     map[string]*UserAccount
	usageDB   UsageDatabase
	paymentDB PaymentDatabase
	mu        sync.RWMutex
	stats     *BillingStats
	ctx       context.Context
	cancel    context.CancelFunc
}

// BillingConfig 计费配置
type BillingConfig struct {
	// 启用状态
	Enabled bool `yaml:"enabled"`

	// 计费模式
	BillingMode string `yaml:"billing_mode"` // "prepaid", "postpaid", "hybrid"

	// 结算周期
	BillingCycle string `yaml:"billing_cycle"` // "daily", "weekly", "monthly"

	// 结算日
	BillingDay int `yaml:"billing_day"` // 每月几号结算

	// 货币
	Currency string `yaml:"currency"` // "CNY", "USD"

	// 税费配置
	TaxConfig TaxConfig `yaml:"tax_config"`

	// 欠费策略
	ArrearsConfig ArrearsConfig `yaml:"arrears_config"`

	// 促销配置
	PromotionConfig PromotionConfig `yaml:"promotion_config"`
}

// TaxConfig 税费配置
type TaxConfig struct {
	// 启用税费
	Enabled bool `yaml:"enabled"`

	// 税率
	Rate float64 `yaml:"rate"` // 0.06 表示6%

	// 税费名称
	Name string `yaml:"name"` // "增值税"
}

// ArrearsConfig 欠费配置
type ArrearsConfig struct {
	// 欠费阈值
	Threshold float64 `yaml:"threshold"`

	// 宽限期
	GracePeriod time.Duration `yaml:"grace_period"`

	// 暂停服务阈值
	SuspendThreshold float64 `yaml:"suspend_threshold"`

	// 暂停服务延迟
	SuspendDelay time.Duration `yaml:"suspend_delay"`

	// 恢复服务费用
	RecoveryFee float64 `yaml:"recovery_fee"`
}

// PromotionConfig 促销配置
type PromotionConfig struct {
	// 新用户优惠
	NewUserDiscount float64 `yaml:"new_user_discount"` // 0.8 表示8折

	// 新用户优惠时长
	NewUserPeriod time.Duration `yaml:"new_user_period"`

	// 充值优惠
	RechargeBonus map[float64]float64 `yaml:"recharge_bonus"` // 充值金额 -> 赠送比例
}

// Plan 套餐
type Plan struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Type        string `json:"type"` // "basic", "pro", "enterprise", "custom"

	// 流量配额
	MonthlyBandwidth int64 `json:"monthly_bandwidth"` // GB
	PeakBandwidth    int64 `json:"peak_bandwidth"`    // Mbps
	StorageQuota     int64 `json:"storage_quota"`     // GB

	// 功能限制
	FeatureLimits FeatureLimits `json:"feature_limits"`

	// 价格
	Price       float64 `json:"price"`
	AnnualPrice float64 `json:"annual_price"`

	// 有效期
	ValidityPeriod time.Duration `json:"validity_period"`

	// 附加服务
	AddOnServices []AddOnService `json:"add_on_services"`

	// 状态
	Status string `json:"status"` // "active", "inactive", "deprecated"

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// FeatureLimits 功能限制
type FeatureLimits struct {
	// 节点数量
	NodeCount int `json:"node_count"`

	// 域名数量
	DomainCount int `json:"domain_count"`

	// 请求次数
	RequestLimit int64 `json:"request_limit"`

	// SSL证书数量
	SSLCertCount int `json:"ssl_cert_count"`

	// 带宽限制
	BandwidthLimit int64 `json:"bandwidth_limit"` // Mbps

	// 存储限制
	StorageLimit int64 `json:"storage_limit"` // GB

	// 是否支持高级功能
	SupportHTTP3 bool `json:"support_http3"`
	SupportCC    bool `json:"support_cc"`
	SupportWAF   bool `json:"support_waf"`
	SupportDDoS  bool `json:"support_ddos"`
}

// AddOnService 附加服务
type AddOnService struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Description string  `json:"description"`
	UnitPrice   float64 `json:"unit_price"`
	Unit        string  `json:"unit"` // "GB", "次", "个"
}

// UserAccount 用户账户
type UserAccount struct {
	ID     string `json:"id"`
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	PlanID string `json:"plan_id"`

	// 余额
	Balance       float64 `json:"balance"`
	FrozenBalance float64 `json:"frozen_balance"`
	CreditLimit   float64 `json:"credit_limit"` // 信用额度

	// 使用量
	CurrentMonthUsage *MonthlyUsage  `json:"current_month_usage"`
	HistoricalUsage   []MonthlyUsage `json:"historical_usage"`

	// 状态
	Status string `json:"status"` // "active", "suspended", "overdue"

	// 结算信息
	BillingInfo *BillingInfo `json:"billing_info"`

	// 促销活动
	PromotionUsed bool `json:"promotion_used"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// MonthlyUsage 月度使用量
type MonthlyUsage struct {
	Month         string             `json:"month"`          // "2024-01"
	BandwidthUsed int64              `json:"bandwidth_used"` // GB
	StorageUsed   int64              `json:"storage_used"`   // GB
	RequestCount  int64              `json:"request_count"`
	PeakBandwidth int64              `json:"peak_bandwidth"` // Mbps
	CostBreakdown map[string]float64 `json:"cost_breakdown"` // 费用明细
	TotalCost     float64            `json:"total_cost"`
	PaidAmount    float64            `json:"paid_amount"`
	PaymentStatus string             `json:"payment_status"` // "pending", "paid", "overdue"
}

// BillingInfo 结算信息
type BillingInfo struct {
	// 结算周期
	BillingCycle string `json:"billing_cycle"`

	// 下次结算时间
	NextBillingDate time.Time `json:"next_billing_date"`

	// 自动续费
	AutoRenew bool `json:"auto_renew"`

	// 发票信息
	InvoiceInfo *InvoiceInfo `json:"invoice_info"`
}

// InvoiceInfo 发票信息
type InvoiceInfo struct {
	Type      string `json:"type"` // "personal", "company"
	Title     string `json:"title"`
	TaxNumber string `json:"tax_number"`
	Address   string `json:"address"`
	Phone     string `json:"phone"`
	Bank      string `json:"bank"`
	Account   string `json:"account"`
}

// UsageDatabase 使用量数据库接口
type UsageDatabase interface {
	RecordUsage(userID string, usage *UsageRecord) error
	GetUsage(userID, month string) (*MonthlyUsage, error)
	GetUsageHistory(userID string, limit int) ([]MonthlyUsage, error)
}

// PaymentDatabase 支付数据库接口
type PaymentDatabase interface {
	CreatePayment(payment *Payment) error
	GetPayment(id string) (*Payment, error)
	GetPaymentsByUser(userID string, limit int) ([]Payment, error)
	ProcessRefund(paymentID string, amount float64, reason string) error
}

// UsageRecord 使用量记录
type UsageRecord struct {
	UserID        string    `json:"user_id"`
	Timestamp     time.Time `json:"timestamp"`
	Bandwidth     int64     `json:"bandwidth"` // bytes
	Storage       int64     `json:"storage"`   // bytes
	Requests      int64     `json:"requests"`
	BandwidthPeak int64     `json:"bandwidth_peak"` // bps
}

// Payment 支付记录
type Payment struct {
	ID            string    `json:"id"`
	UserID        string    `json:"user_id"`
	Type          string    `json:"type"` // "recharge", "billing", "refund"
	Amount        float64   `json:"amount"`
	Currency      string    `json:"currency"`
	Status        string    `json:"status"`         // "pending", "completed", "failed", "refunded"
	PaymentMethod string    `json:"payment_method"` // "alipay", "wechat", "bank", "paypal"
	TransactionID string    `json:"transaction_id"`
	Description   string    `json:"description"`
	InvoiceID     string    `json:"invoice_id"`
	CreatedAt     time.Time `json:"created_at"`
	CompletedAt   time.Time `json:"completed_at"`
}

// BillingStats 计费统计
type BillingStats struct {
	TotalRevenue    float64            `json:"total_revenue"`
	RevenueByPlan   map[string]float64 `json:"revenue_by_plan"`
	RevenueByDay    map[string]float64 `json:"revenue_by_day"`
	ActiveUsers     int                `json:"active_users"`
	OverdueUsers    int                `json:"overdue_users"`
	PendingPayments int                `json:"pending_payments"`
	TotalBalance    float64            `json:"total_balance"`
	mu              sync.RWMutex
}

// NewBillingManager 创建计费管理器
func NewBillingManager(config *BillingConfig) *BillingManager {
	if config == nil {
		config = &BillingConfig{
			Enabled:      true,
			BillingMode:  "prepaid",
			BillingCycle: "monthly",
			Currency:     "CNY",
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &BillingManager{
		config: config,
		plans:  make(map[string]*Plan),
		users:  make(map[string]*UserAccount),
		stats:  &BillingStats{RevenueByPlan: make(map[string]float64), RevenueByDay: make(map[string]float64)},
		ctx:    ctx,
		cancel: cancel,
	}
}

// AddPlan 添加套餐
func (m *BillingManager) AddPlan(plan *Plan) {
	m.mu.Lock()
	defer m.mu.Unlock()

	plan.CreatedAt = time.Now()
	plan.UpdatedAt = time.Now()
	m.plans[plan.ID] = plan
}

// GetPlan 获取套餐
func (m *BillingManager) GetPlan(planID string) (*Plan, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	plan, ok := m.plans[planID]
	if !ok {
		return nil, fmt.Errorf("套餐不存在: %s", planID)
	}

	return plan, nil
}

// ListPlans 列出所有套餐
func (m *BillingManager) ListPlans() []*Plan {
	m.mu.RLock()
	defer m.mu.RUnlock()

	plans := make([]*Plan, 0, len(m.plans))
	for _, plan := range m.plans {
		if plan.Status == "active" {
			plans = append(plans, plan)
		}
	}

	return plans
}

// CreateUserAccount 创建用户账户
func (m *BillingManager) CreateUserAccount(userID, email, planID string) (*UserAccount, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 检查套餐是否存在
	_, ok := m.plans[planID]
	if !ok {
		return nil, fmt.Errorf("套餐不存在: %s", planID)
	}

	account := &UserAccount{
		ID:      fmt.Sprintf("acc_%s", userID),
		UserID:  userID,
		Email:   email,
		PlanID:  planID,
		Balance: 0,
		Status:  "active",
		CurrentMonthUsage: &MonthlyUsage{
			Month:         time.Now().Format("2006-01"),
			CostBreakdown: make(map[string]float64),
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// 新用户优惠
	if m.config.PromotionConfig.NewUserDiscount > 0 {
		account.PromotionUsed = false
	}

	m.users[userID] = account

	return account, nil
}

// GetUserAccount 获取用户账户
func (m *BillingManager) GetUserAccount(userID string) (*UserAccount, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	account, ok := m.users[userID]
	if !ok {
		return nil, fmt.Errorf("用户账户不存在: %s", userID)
	}

	return account, nil
}

// Recharge 充值
func (m *BillingManager) Recharge(userID string, amount float64, method string) (*Payment, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	account, ok := m.users[userID]
	if !ok {
		return nil, fmt.Errorf("用户账户不存在: %s", userID)
	}

	// 计算赠送金额
	bonus := m.calculateRechargeBonus(amount)
	totalAmount := amount + bonus

	// 创建支付记录
	payment := &Payment{
		ID:            fmt.Sprintf("pay_%d", time.Now().UnixNano()),
		UserID:        userID,
		Type:          "recharge",
		Amount:        totalAmount,
		Currency:      m.config.Currency,
		Status:        "completed",
		PaymentMethod: method,
		Description:   fmt.Sprintf("账户充值: %.2f (赠送: %.2f)", amount, bonus),
		CompletedAt:   time.Now(),
	}

	// 更新余额
	account.Balance += totalAmount
	account.UpdatedAt = time.Now()

	// 更新统计
	m.stats.mu.Lock()
	m.stats.TotalRevenue += amount
	m.stats.TotalBalance += totalAmount
	m.stats.RevenueByDay[time.Now().Format("2006-01-02")] += amount
	m.stats.mu.Unlock()

	return payment, nil
}

// calculateRechargeBonus 计算充值赠送
func (m *BillingManager) calculateRechargeBonus(amount float64) float64 {
	if m.config.PromotionConfig.RechargeBonus == nil {
		return 0
	}

	var maxBonus float64
	for threshold, bonus := range m.config.PromotionConfig.RechargeBonus {
		if amount >= threshold {
			bonusAmount := amount * bonus
			if bonusAmount > maxBonus {
				maxBonus = bonusAmount
			}
		}
	}

	return maxBonus
}

// RecordUsage 记录使用量
func (m *BillingManager) RecordUsage(userID string, usage *UsageRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	account, ok := m.users[userID]
	if !ok {
		return fmt.Errorf("用户账户不存在: %s", userID)
	}

	// 更新当前月度使用量
	if account.CurrentMonthUsage == nil {
		account.CurrentMonthUsage = &MonthlyUsage{
			Month:         time.Now().Format("2006-01"),
			CostBreakdown: make(map[string]float64),
		}
	}

	account.CurrentMonthUsage.BandwidthUsed += usage.Bandwidth / (1024 * 1024 * 1024) // 转换为GB
	account.CurrentMonthUsage.StorageUsed += usage.Storage / (1024 * 1024 * 1024)
	account.CurrentMonthUsage.RequestCount += usage.Requests

	if usage.BandwidthPeak > account.CurrentMonthUsage.PeakBandwidth {
		account.CurrentMonthUsage.PeakBandwidth = usage.BandwidthPeak
	}

	return nil
}

// CalculateCost 计算费用
func (m *BillingManager) CalculateCost(userID string) (*CostBreakdown, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	account, ok := m.users[userID]
	if !ok {
		return nil, fmt.Errorf("用户账户不存在: %s", userID)
	}

	plan, ok := m.plans[account.PlanID]
	if !ok {
		return nil, fmt.Errorf("套餐不存在: %s", account.PlanID)
	}

	breakdown := &CostBreakdown{
		BasePrice: plan.Price,
		UsageCost: make(map[string]float64),
		Subtotal:  plan.Price,
	}

	// 计算超出配额的费用
	usage := account.CurrentMonthUsage

	// 流量超出
	if usage.BandwidthUsed > plan.MonthlyBandwidth {
		excess := usage.BandwidthUsed - plan.MonthlyBandwidth
		breakdown.UsageCost["bandwidth_excess"] = float64(excess) * 0.5 // 超出部分0.5元/GB
		breakdown.Subtotal += breakdown.UsageCost["bandwidth_excess"]
	}

	// 计算税费
	if m.config.TaxConfig.Enabled {
		breakdown.Tax = breakdown.Subtotal * m.config.TaxConfig.Rate
		breakdown.Total = breakdown.Subtotal + breakdown.Tax
	} else {
		breakdown.Total = breakdown.Subtotal
	}

	return breakdown, nil
}

// CostBreakdown 费用明细
type CostBreakdown struct {
	BasePrice float64            `json:"base_price"`
	UsageCost map[string]float64 `json:"usage_cost"`
	Subtotal  float64            `json:"subtotal"`
	Tax       float64            `json:"tax"`
	Discount  float64            `json:"discount"`
	Total     float64            `json:"total"`
}

// GenerateInvoice 生成账单
func (m *BillingManager) GenerateInvoice(userID, month string) (*Invoice, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	account, ok := m.users[userID]
	if !ok {
		return nil, fmt.Errorf("用户账户不存在: %s", userID)
	}

	// 计算费用
	cost, err := m.CalculateCost(userID)
	if err != nil {
		return nil, err
	}

	invoice := &Invoice{
		ID:        fmt.Sprintf("inv_%s_%s", userID, month),
		UserID:    userID,
		Month:     month,
		Amount:    cost.Total,
		Usage:     account.CurrentMonthUsage,
		Status:    "pending",
		CreatedAt: time.Now(),
		DueDate:   time.Now().Add(30 * 24 * time.Hour),
	}

	return invoice, nil
}

// Invoice 账单
type Invoice struct {
	ID        string        `json:"id"`
	UserID    string        `json:"user_id"`
	Month     string        `json:"month"`
	Amount    float64       `json:"amount"`
	Usage     *MonthlyUsage `json:"usage"`
	Status    string        `json:"status"` // "pending", "paid", "overdue"
	CreatedAt time.Time     `json:"created_at"`
	DueDate   time.Time     `json:"due_date"`
	PaidAt    time.Time     `json:"paid_at"`
}

// GetStats 获取统计
func (m *BillingManager) GetStats() *BillingStats {
	m.stats.mu.RLock()
	defer m.stats.mu.RUnlock()

	return m.stats
}

// StartBillingCycle 开始结算周期
func (m *BillingManager) StartBillingCycle() {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case now := <-ticker.C:
			if now.Day() == m.config.BillingDay {
				m.processBilling()
			}
		}
	}
}

// processBilling 处理结算
func (m *BillingManager) processBilling() {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for userID, account := range m.users {
		// 生成账单
		invoice, _ := m.GenerateInvoice(userID, time.Now().Format("2006-01"))

		// 扣费
		if account.Balance >= invoice.Amount {
			account.Balance -= invoice.Amount
			invoice.Status = "paid"
			invoice.PaidAt = time.Now()
		} else {
			// 余额不足
			account.Status = "overdue"
			invoice.Status = "overdue"

			m.stats.mu.Lock()
			m.stats.OverdueUsers++
			m.stats.mu.Unlock()
		}

		// 重置使用量
		account.HistoricalUsage = append(account.HistoricalUsage, *account.CurrentMonthUsage)
		account.CurrentMonthUsage = &MonthlyUsage{
			Month:         time.Now().Format("2006-01"),
			CostBreakdown: make(map[string]float64),
		}

		m.stats.mu.Lock()
		m.stats.RevenueByPlan[account.PlanID] += invoice.Amount
		m.stats.mu.Unlock()
	}
}
