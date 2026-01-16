package monitor

import (
	"context"
	"log"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/ai-cdn-tunnel/master/db"
	"github.com/ai-cdn-tunnel/proto/agent"
)

type Monitor struct {
	db          *db.MongoDB
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	mu          sync.RWMutex
	nodes       map[string]*NodeMetrics
	collectors  map[string]*StatusCollector
	metricsChan chan *agent.StatusReport
}

type NodeMetrics struct {
	NodeID      string
	LastUpdate  time.Time
	System      *SystemMetrics
	Network     *NetworkMetrics
	CDN         *CDNMetrics
	Connections *ConnectionMetrics
	Security    *SecurityMetrics
}

type SystemMetrics struct {
	CPUUsage    float64
	MemoryUsage float64
	DiskUsage   float64
	Goroutines  int32
	Uptime      int64
}

type NetworkMetrics struct {
	BandwidthIn  float64
	BandwidthOut float64
	BytesIn      int64
	BytesOut     int64
}

type CDNMetrics struct {
	QPS             float64
	TotalRequests   int64
	SuccessRequests int64
	ErrorRequests   int64
	P50Latency      float64
	P95Latency      float64
	P99Latency      float64
}

type ConnectionMetrics struct {
	ActiveConnections int64
	TotalConnections  int64
	ClosedConnections int64
	IdleConnections   int64
}

type SecurityMetrics struct {
	BlockedConnections  int64
	SlowConnections     int64
	RateLimitedRequests int64
	CCBlocked           int64
}

type StatusCollector struct {
	nodeID string
	status *agent.StatusReport
	mu     sync.RWMutex
}

type MetricsData struct {
	NodeID      string                 `bson:"node_id"`
	Timestamp   time.Time              `bson:"timestamp"`
	System      *agent.SystemMetrics   `bson:"system,omitempty"`
	Network     *agent.NetworkMetrics  `bson:"network,omitempty"`
	CDN         *agent.CDNMetrics      `bson:"cdn,omitempty"`
	Connections *agent.ConnectionMetrics `bson:"connections,omitempty"`
	Security    *agent.SecurityMetrics `bson:"security,omitempty"`
}

func NewMonitor(database *db.MongoDB) *Monitor {
	return &Monitor{
		db:          database,
		nodes:       make(map[string]*NodeMetrics),
		collectors:  make(map[string]*StatusCollector),
		metricsChan: make(chan *agent.StatusReport, 1000),
	}
}

func (m *Monitor) StartCollecting() {
	m.ctx, m.cancel = context.WithCancel(context.Background())

	m.wg.Add(1)
	go m.collectLoop()

	m.wg.Add(1)
	go m.metricsProcessor()

	log.Println("Monitor started collecting metrics")
}

func (m *Monitor) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
	m.wg.Wait()
	close(m.metricsChan)
	log.Println("Monitor stopped")
}

func (m *Monitor) collectLoop() {
	defer m.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.collectAllNodes()
		}
	}
}

func (m *Monitor) collectAllNodes() {
	nodes, err := m.db.ListNodes(m.ctx)
	if err != nil {
		log.Printf("Failed to list nodes: %v", err)
		return
	}

	for _, node := range nodes {
		if node.Status == "online" {
			m.collectNodeMetrics(node.ID)
		}
	}
}

func (m *Monitor) collectNodeMetrics(nodeID string) {
	m.mu.RLock()
	collector, exists := m.collectors[nodeID]
	m.mu.RUnlock()

	if exists {
		report := collector.GetStatus()
		if report != nil {
			m.processStatusReport(report)
		}
	}
}

func (m *Monitor) metricsProcessor() {
	defer m.wg.Done()

	for {
		select {
		case <-m.ctx.Done():
			return
		case report, ok := <-m.metricsChan:
			if !ok {
				return
			}
			m.processStatusReport(report)
		}
	}
}

func (m *Monitor) processStatusReport(report *agent.StatusReport) {
	if report == nil {
		return
	}

	nodeID := report.NodeId
	timestamp := time.Unix(report.Timestamp, 0)

	metrics := &MetricsData{
		NodeID:    nodeID,
		Timestamp: timestamp,
	}

	if report.System != nil {
		metrics.System = report.System
	}
	if report.Network != nil {
		metrics.Network = report.Network
	}
	if report.CDN != nil {
		metrics.CDN = report.CDN
	}
	if report.Connections != nil {
		metrics.Connections = report.Connections
	}
	if report.Security != nil {
		metrics.Security = report.Security
	}

	m.updateNodeMetrics(nodeID, metrics)

	if err := m.saveMetrics(metrics); err != nil {
		log.Printf("Failed to save metrics for node %s: %v", nodeID, err)
	}
}

func (m *Monitor) updateNodeMetrics(nodeID string, metrics *MetricsData) {
	m.mu.Lock()
	defer m.mu.Unlock()

	nodeMetrics := &NodeMetrics{
		NodeID:     nodeID,
		LastUpdate: metrics.Timestamp,
	}

	if metrics.System != nil {
		nodeMetrics.System = &SystemMetrics{
			CPUUsage:    metrics.System.CpuUsage,
			MemoryUsage: metrics.System.CpuUsage,
			DiskUsage:   metrics.System.DiskUsage,
			Goroutines:  int32(metrics.System.Goroutines),
			Uptime:      metrics.System.Uptime,
		}
	}

	if metrics.Network != nil {
		nodeMetrics.Network = &NetworkMetrics{
			BandwidthIn:  metrics.Network.BandwidthIn,
			BandwidthOut: metrics.Network.BandwidthOut,
			BytesIn:      metrics.Network.BytesIn,
			BytesOut:     metrics.Network.BytesOut,
		}
	}

	if metrics.CDN != nil {
		nodeMetrics.CDN = &CDNMetrics{
			QPS:             metrics.CDN.Qps,
			TotalRequests:   metrics.CDN.TotalRequests,
			SuccessRequests: metrics.CDN.SuccessRequests,
			ErrorRequests:   metrics.CDN.ErrorRequests,
			P50Latency:      metrics.CDN.P50Latency,
			P95Latency:      metrics.CDN.P95Latency,
			P99Latency:      metrics.CDN.P99Latency,
		}
	}

	if metrics.Connections != nil {
		nodeMetrics.Connections = &ConnectionMetrics{
			ActiveConnections: metrics.Connections.ActiveConnections,
			TotalConnections:  metrics.Connections.TotalConnections,
			ClosedConnections: metrics.Connections.ClosedConnections,
			IdleConnections:   metrics.Connections.IdleConnections,
		}
	}

	if metrics.Security != nil {
		nodeMetrics.Security = &SecurityMetrics{
			BlockedConnections:  metrics.Security.BlockedConnections,
			SlowConnections:     metrics.Security.SlowConnections,
			RateLimitedRequests: metrics.Security.RateLimitedRequests,
			CCBlocked:           metrics.Security.CCBlocked,
		}
	}

	m.nodes[nodeID] = nodeMetrics
}

func (m *Monitor) saveMetrics(metrics *MetricsData) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := m.db.GetClient().Database("ai-cdn").Collection("metrics").InsertOne(ctx, metrics)
	return err
}

func (m *Monitor) RegisterNode(nodeID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.collectors[nodeID]; !exists {
		m.collectors[nodeID] = &StatusCollector{
			nodeID: nodeID,
		}
	}
}

func (m *Monitor) UpdateNodeStatus(nodeID string, status *agent.StatusReport) {
	m.mu.Lock()
	defer m.mu.Unlock()

	collector, exists := m.collectors[nodeID]
	if !exists {
		collector = &StatusCollector{nodeID: nodeID}
		m.collectors[nodeID] = collector
	}

	collector.UpdateStatus(status)
}

func (m *Monitor) GetNodeMetrics(nodeID string) (*NodeMetrics, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	metrics, exists := m.nodes[nodeID]
	return metrics, exists
}

func (m *Monitor) GetAllMetrics() map[string]*NodeMetrics {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]*NodeMetrics)
	for k, v := range m.nodes {
		result[k] = v
	}
	return result
}

func (m *Monitor) QueryMetrics(nodeID string, startTime, endTime time.Time) ([]*MetricsData, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	filter := bson.M{
		"node_id": nodeID,
		"timestamp": bson.M{
			"$gte": startTime,
			"$lte": endTime,
		},
	}

	opts := options.Find().SetSort(bson.D{{Key: "timestamp", Value: 1}})
	cursor, err := m.db.GetClient().Database("ai-cdn").Collection("metrics").Find(ctx, filter, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var metrics []*MetricsData
	for cursor.Next(ctx) {
		var metric MetricsData
		if err := cursor.Decode(&metric); err != nil {
			continue
		}
		metrics = append(metrics, &metric)
	}

	return metrics, nil
}

func (m *Monitor) GetNodeStatus(nodeID string) (*agent.StatusData, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	metrics, exists := m.nodes[nodeID]
	if !exists {
		return nil, nil
	}

	status := &agent.StatusData{
		NodeId:    nodeID,
		Status:    "online",
		Timestamp: metrics.LastUpdate.Unix(),
	}

	if metrics.System != nil {
		status.System = &agent.SystemMetrics{
			CpuUsage:   metrics.System.CPUUsage,
			MemUsage:   metrics.System.MemoryUsage,
			DiskUsage:  metrics.System.DiskUsage,
			Goroutines: int(metrics.System.Goroutines),
			Uptime:     metrics.System.Uptime,
		}
	}

	if metrics.Network != nil {
		status.Network = &agent.NetworkMetrics{
			BandwidthIn:  metrics.Network.BandwidthIn,
			BandwidthOut: metrics.Network.BandwidthOut,
			BytesIn:      metrics.Network.BytesIn,
			BytesOut:     metrics.Network.BytesOut,
		}
	}

	if metrics.CDN != nil {
		status.CDN = &agent.CDNMetrics{
			Qps:             metrics.CDN.QPS,
			TotalRequests:   metrics.CDN.TotalRequests,
			SuccessRequests: metrics.CDN.SuccessRequests,
			ErrorRequests:   metrics.CDN.ErrorRequests,
			P50Latency:      metrics.CDN.P50Latency,
			P95Latency:      metrics.CDN.P95Latency,
			P99Latency:      metrics.CDN.P99Latency,
		}
	}

	if metrics.Connections != nil {
		status.Connections = &agent.ConnectionMetrics{
			ActiveConnections: metrics.Connections.ActiveConnections,
			TotalConnections:  metrics.Connections.TotalConnections,
			ClosedConnections: metrics.Connections.ClosedConnections,
			IdleConnections:   metrics.Connections.IdleConnections,
		}
	}

	if metrics.Security != nil {
		status.Security = &agent.SecurityMetrics{
			BlockedConnections:  metrics.Security.BlockedConnections,
			SlowConnections:     metrics.Security.SlowConnections,
			RateLimitedRequests: metrics.Security.RateLimitedRequests,
			CCBlocked:           metrics.Security.CCBlocked,
		}
	}

	return status, nil
}

func (m *Monitor) GetStats() *MonitorStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := &MonitorStats{
		TotalNodes:  len(m.nodes),
		Collectors:  len(m.collectors),
		OnlineNodes: 0,
	}

	for _, metrics := range m.nodes {
		if time.Since(metrics.LastUpdate) < 2*time.Minute {
			stats.OnlineNodes++
		}
	}

	return stats
}

type MonitorStats struct {
	TotalNodes  int
	Collectors  int
	OnlineNodes int
}

func (sc *StatusCollector) UpdateStatus(status *agent.StatusReport) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.status = status
}

func (sc *StatusCollector) GetStatus() *agent.StatusReport {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	return sc.status
}
