package status

import (
	"time"

	pb "github.com/ai-cdn-tunnel/proto/agent"
)

type Config struct {
	CollectInterval time.Duration
}

type Reporter struct {
	client pb.AgentServiceClient
	nodeID string
	cfg    Config
}

func NewReporter(client pb.AgentServiceClient, nodeID string, cfg Config) *Reporter {
	return &Reporter{client: client, nodeID: nodeID, cfg: cfg}
}

func (r *Reporter) Start() {}

func (r *Reporter) Stop() {}
