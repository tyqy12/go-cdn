package node

import (
	"context"
	"sync"
	"time"

	"github.com/ai-cdn-tunnel/master/db"
)

// Node 节点信息
type Node struct {
	ID         string
	Name       string
	Type       string // "edge", "l2", "master"
	Addr       string
	Port       int
	Region     string
	Status     string // "online", "offline", "pending", "maintenance"
	Tags       []string
	Metadata   map[string]string
	Version    string
	Online     bool
	LastBeatAt time.Time
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// Manager 节点管理器
type Manager struct {
	mu      sync.RWMutex
	nodes   map[string]*Node
	db      *db.MongoDB
	version int64
}

// NewManager 创建节点管理器
func NewManager(database *db.MongoDB) *Manager {
	mgr := &Manager{
		nodes: make(map[string]*Node),
		db:    database,
	}
	
	// 从数据库加载节点
	if database != nil {
		mgr.loadNodesFromDB()
	}
	
	return mgr
}

// loadNodesFromDB 从数据库加载节点
func (m *Manager) loadNodesFromDB() {
	if m.db == nil {
		return
	}
	
	nodes, err := m.db.ListNodes(context.Background())
	if err != nil {
		return
	}
	
	m.mu.Lock()
	for _, n := range nodes {
		m.nodes[n.ID] = &Node{
			ID:         n.ID,
			Name:       n.Name,
			Type:       n.Type,
			Addr:       n.Addr,
			Port:       n.Port,
			Region:     n.Region,
			Status:     n.Status,
			Tags:       n.Tags,
			Metadata:   n.Metadata,
			Version:    n.Version,
			Online:     n.Status == "online",
			LastBeatAt: n.LastSeen,
			CreatedAt:  n.CreatedAt,
			UpdatedAt:  n.UpdatedAt,
		}
	}
	m.mu.Unlock()
}

// GetAllNodes 获取所有节点
func (m *Manager) GetAllNodes() []*Node {
	m.mu.RLock()
	defer m.mu.RUnlock()

	nodes := make([]*Node, 0, len(m.nodes))
	for _, node := range m.nodes {
		nodes = append(nodes, node)
	}
	return nodes
}

// GetOnlineNodes 获取在线节点
func (m *Manager) GetOnlineNodes() []*Node {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var nodes []*Node
	for _, node := range m.nodes {
		if node.Online {
			nodes = append(nodes, node)
		}
	}
	return nodes
}

// GetNodesByRegion 获取指定区域的节点
func (m *Manager) GetNodesByRegion(region string) []*Node {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var nodes []*Node
	for _, node := range m.nodes {
		if node.Region == region && node.Online {
			nodes = append(nodes, node)
		}
	}
	return nodes
}

// GetNodesByType 获取指定类型的节点
func (m *Manager) GetNodesByType(nodeType string) []*Node {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var nodes []*Node
	for _, node := range m.nodes {
		if node.Type == nodeType {
			nodes = append(nodes, node)
		}
	}
	return nodes
}

// GetNode 获取单个节点
func (m *Manager) GetNode(id string) *Node {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.nodes[id]
}

// AddNode 添加节点
func (m *Manager) AddNode(node *Node) {
	m.mu.Lock()
	defer m.mu.Unlock()

	node.CreatedAt = time.Now()
	node.UpdatedAt = time.Now()
	m.nodes[node.ID] = node
	
	// 持久化到数据库
	if m.db != nil {
		m.db.SaveNode(context.Background(), &db.Node{
			ID:        node.ID,
			Name:      node.Name,
			Type:      node.Type,
			Region:    node.Region,
			Addr:      node.Addr,
			Port:      node.Port,
			Status:    node.Status,
			Tags:      node.Tags,
			Metadata:  node.Metadata,
			Version:   node.Version,
			CreatedAt: node.CreatedAt,
			UpdatedAt: node.UpdatedAt,
			LastSeen:  node.LastBeatAt,
		})
	}
}

// RemoveNode 移除节点
func (m *Manager) RemoveNode(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.nodes, id)
	
	// 从数据库删除
	if m.db != nil {
		m.db.DeleteNode(context.Background(), id)
	}
}

// UpdateNode 更新节点
func (m *Manager) UpdateNode(id string, update func(*Node)) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if node, ok := m.nodes[id]; ok {
		update(node)
		node.UpdatedAt = time.Now()
		
		// 持久化到数据库
		if m.db != nil {
			m.db.SaveNode(context.Background(), &db.Node{
				ID:        node.ID,
				Name:      node.Name,
				Type:      node.Type,
				Region:    node.Region,
				Addr:      node.Addr,
				Port:      node.Port,
				Status:    node.Status,
				Tags:      node.Tags,
				Metadata:  node.Metadata,
				Version:   node.Version,
				CreatedAt: node.CreatedAt,
				UpdatedAt: node.UpdatedAt,
				LastSeen:  node.LastBeatAt,
			})
		}
	}
}

// MarkOffline 标记离线
func (m *Manager) MarkOffline(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if node, ok := m.nodes[id]; ok {
		node.Online = false
		node.Status = "offline"
		node.UpdatedAt = time.Now()
	}
}

// MarkOnline 标记在线
func (m *Manager) MarkOnline(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if node, ok := m.nodes[id]; ok {
		node.Online = true
		node.Status = "online"
		node.LastBeatAt = time.Now()
		node.UpdatedAt = time.Now()
	}
}

// Heartbeat 心跳
func (m *Manager) Heartbeat(id string) bool {
	m.mu.RLock()
	node, exists := m.nodes[id]
	m.mu.RUnlock()

	if !exists {
		return false
	}

	m.mu.Lock()
	node.LastBeatAt = time.Now()
	node.Online = true
	node.Status = "online"
	node.UpdatedAt = time.Now()
	m.mu.Unlock()

	return true
}

// GetStats 获取统计信息
func (m *Manager) GetStats() NodeStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := NodeStats{
		Total:    len(m.nodes),
		ByRegion: make(map[string]int),
		ByType:   make(map[string]int),
	}

	for _, node := range m.nodes {
		if node.Online {
			stats.Online++
		} else {
			stats.Offline++
		}
		stats.ByRegion[node.Region]++
		stats.ByType[node.Type]++
	}

	return stats
}

// NodeStats 节点统计
type NodeStats struct {
	Total    int
	Online   int
	Offline  int
	ByRegion map[string]int
	ByType   map[string]int
}
