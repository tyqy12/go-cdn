package heartbeat

import (
	"context"
	"log"
	"sync"
	"time"

	pb "github.com/ai-cdn-tunnel/proto/agent"
)

type Config struct {
	Interval time.Duration
	Timeout  time.Duration
}

type Sender struct {
	client     pb.AgentServiceClient
	nodeID     string
	cfg        Config
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	mu         sync.RWMutex
	running    bool
	status     string
	attributes map[string]string
}

func NewSender(client pb.AgentServiceClient, nodeID string, cfg Config) *Sender {
	return &Sender{
		client:     client,
		nodeID:     nodeID,
		cfg:        cfg,
		status:     "online",
		attributes: make(map[string]string),
	}
}

func (s *Sender) Start() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return
	}

	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.running = true

	s.wg.Add(1)
	go s.heartbeatLoop()
}

func (s *Sender) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return
	}

	s.cancel()
	s.wg.Wait()
	s.running = false
}

func (s *Sender) heartbeatLoop() {
	defer s.wg.Done()

	ticker := time.NewTicker(s.cfg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.sendHeartbeat()
		}
	}
}

func (s *Sender) sendHeartbeat() {
	s.mu.RLock()
	nodeID := s.nodeID
	status := s.status
	attributes := make(map[string]string)
	for k, v := range s.attributes {
		attributes[k] = v
	}
	s.mu.RUnlock()

	ctx, cancel := context.WithTimeout(s.ctx, s.cfg.Timeout)
	defer cancel()

	req := &pb.HeartbeatRequest{
		NodeId:     nodeID,
		Timestamp:  time.Now().Unix(),
		Status:     status,
		Attributes: attributes,
		TLSInfo: &pb.TLSInfo{
			Version:         "1.3",
			Cipher:          "TLS_AES_256_GCM_SHA384",
			CertFingerprint: "",
		},
	}

	resp, err := s.client.Heartbeat(ctx, req)
	if err != nil {
		log.Printf("Heartbeat failed: %v", err)
		return
	}

	if !resp.Success {
		log.Printf("Heartbeat rejected: %s", resp.Message)
		return
	}

	log.Printf("Heartbeat sent successfully, master status: %s", resp.MasterStatus)
}

func (s *Sender) UpdateStatus(status string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status = status
}

func (s *Sender) UpdateAttribute(key, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attributes[key] = value
}

func (s *Sender) IsRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running
}
