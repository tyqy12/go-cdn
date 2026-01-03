package ha

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/ai-cdn-tunnel/master/db"
)

// LeaderElection 领导者选举
type LeaderElection struct {
	config      *ElectionConfig
	store       db.Store
	leaderID    string
	isLeader    bool
	leaseTTL    time.Duration
	stopCh      chan struct{}
	wg          sync.WaitGroup
	mu          sync.RWMutex

	// 回调函数
	onElected  func()
	onRevoked  func()
}

// ElectionConfig 选举配置
type ElectionConfig struct {
	// 选举名称
	ElectionName string

	// 节点ID
	NodeID string

	// 候选人列表
	Candidates []string

	// 租约时间
	LeaseTTL time.Duration

	// 重试间隔
	RetryInterval time.Duration

	// 超时时间
	Timeout time.Duration
}

type ElectionMember = db.ElectionMember

// DefaultElectionConfig 默认配置
func DefaultElectionConfig(nodeID string) *ElectionConfig {
	return &ElectionConfig{
		ElectionName: "gocdn-master",
		NodeID:       nodeID,
		LeaseTTL:     15 * time.Second,
		RetryInterval: 1 * time.Second,
		Timeout:      5 * time.Second,
	}
}

// NewLeaderElection 创建领导者选举
func NewLeaderElection(cfg *ElectionConfig, store db.Store) *LeaderElection {
	if cfg.LeaseTTL == 0 {
		cfg.LeaseTTL = 15 * time.Second
	}

	return &LeaderElection{
		config:   cfg,
		store:    store,
		leaderID: "",
		isLeader: false,
		leaseTTL: cfg.LeaseTTL,
		stopCh:   make(chan struct{}),
	}
}

// OnElected 设置当选回调
func (e *LeaderElection) OnElected(fn func()) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.onElected = fn
}

// OnRevoked 设置撤销回调
func (e *LeaderElection) OnRevoked(fn func()) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.onRevoked = fn
}

// Start 启动选举
func (e *LeaderElection) Start() {
	e.wg.Add(1)
	go e.runElection()

	log.Printf("Leader election started for %s, node: %s", e.config.ElectionName, e.config.NodeID)
}

// Stop 停止选举
func (e *LeaderElection) Stop() {
	// 主动放弃领导者身份
	if e.isLeader {
		e.revokeLeadership()
	}

	close(e.stopCh)
	e.wg.Wait()

	log.Printf("Leader election stopped for %s", e.config.ElectionName)
}

// runElection 运行选举
func (e *LeaderElection) runElection() {
	defer e.wg.Done()

	ticker := time.NewTicker(e.config.RetryInterval)
	defer ticker.Stop()

	for {
		select {
		case <-e.stopCh:
			return
		case <-ticker.C:
			e.tryAcquireLeadership()
		}
	}
}

// tryAcquireLeadership 尝试获取领导者身份
func (e *LeaderElection) tryAcquireLeadership() {
	ctx, cancel := context.WithTimeout(context.Background(), e.config.Timeout)
	defer cancel()

	// 尝试在存储中创建领导者记录
	leader := &db.LeaderRecord{
		ElectionName: e.config.ElectionName,
		LeaderID:     e.config.NodeID,
		ExpiresAt:    time.Now().Add(e.leaseTTL),
	}

	err := e.store.TryAcquireLeadership(ctx, leader)
	if err != nil {
		// 获取当前领导者
		currentLeader, err := e.store.GetLeader(ctx, e.config.ElectionName)
		if err == nil && currentLeader != nil {
			e.updateLeader(currentLeader.LeaderID)
		}
		return
	}

	// 成功获取领导者身份
	e.becomeLeader()
}

// becomeLeader 成为领导者
func (e *LeaderElection) becomeLeader() {
	e.mu.Lock()
	wasLeader := e.isLeader
	e.isLeader = true
	e.leaderID = e.config.NodeID
	onElected := e.onElected
	e.mu.Unlock()

	if !wasLeader {
		log.Printf("Node %s became leader for %s", e.config.NodeID, e.config.ElectionName)

		if onElected != nil {
			go onElected()
		}

		// 启动续租协程
		e.wg.Add(1)
		go e.runLeaseRenewal()
	}
}

// runLeaseRenewal 运行租约续租
func (e *LeaderElection) runLeaseRenewal() {
	defer e.wg.Done()

	ticker := time.NewTicker(e.leaseTTL / 2)
	defer ticker.Stop()

	for {
		select {
		case <-e.stopCh:
			return
		case <-ticker.C:
			e.renewLease()
		}
	}
}

// renewLease 续租
func (e *LeaderElection) renewLease() {
	ctx, cancel := context.WithTimeout(context.Background(), e.config.Timeout)
	defer cancel()

	err := e.store.RenewLeadership(ctx, e.config.ElectionName, e.config.NodeID, time.Now().Add(e.leaseTTL))
	if err != nil {
		log.Printf("Failed to renew leadership: %v", err)
		e.loseLeadership()
	}
}

// loseLeadership 失去领导者身份
func (e *LeaderElection) loseLeadership() {
	e.mu.Lock()
	wasLeader := e.isLeader
	e.isLeader = false
	onRevoked := e.onRevoked
	e.mu.Unlock()

	if wasLeader {
		log.Printf("Node %s lost leadership for %s", e.config.NodeID, e.config.ElectionName)

		if onRevoked != nil {
			go onRevoked()
		}
	}
}

// revokeLeadership 主动放弃领导者身份
func (e *LeaderElection) revokeLeadership() {
	ctx, cancel := context.WithTimeout(context.Background(), e.config.Timeout)
	defer cancel()

	err := e.store.ReleaseLeadership(ctx, e.config.ElectionName, e.config.NodeID)
	if err != nil {
		log.Printf("Failed to release leadership: %v", err)
	}

	e.loseLeadership()
}

// updateLeader 更新领导者信息
func (e *LeaderElection) updateLeader(leaderID string) {
	e.mu.Lock()
	changed := e.leaderID != leaderID
	e.leaderID = leaderID
	e.mu.Unlock()

	if changed {
		if leaderID == e.config.NodeID {
			e.becomeLeader()
		} else {
			log.Printf("Current leader for %s is %s", e.config.ElectionName, leaderID)
		}
	}
}

// IsLeader 检查是否是领导者
func (e *LeaderElection) IsLeader() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.isLeader
}

// GetLeaderID 获取领导者ID
func (e *LeaderElection) GetLeaderID() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.leaderID
}

// GetMembers 获取选举成员列表
func (e *LeaderElection) GetMembers() []*ElectionMember {
	ctx, cancel := context.WithTimeout(context.Background(), e.config.Timeout)
	defer cancel()

	members, err := e.store.GetElectionMembers(ctx, e.config.ElectionName)
	if err != nil {
		log.Printf("Failed to get election members: %v", err)
		return nil
	}

	return members
}
