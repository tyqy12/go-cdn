package heartbeat

import (
	"time"

	pb "github.com/ai-cdn-tunnel/proto/agent"
)

type Config struct {
	Interval time.Duration
	Timeout  time.Duration
}

type Sender struct {
	client pb.AgentServiceClient
	nodeID string
	cfg    Config
}

func NewSender(client pb.AgentServiceClient, nodeID string, cfg Config) *Sender {
	return &Sender{client: client, nodeID: nodeID, cfg: cfg}
}

func (s *Sender) Start() {}

func (s *Sender) Stop() {}
