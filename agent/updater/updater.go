package updater

import (
	"context"
	"time"

	"github.com/ai-cdn-tunnel/agent/config"
	pb "github.com/ai-cdn-tunnel/proto/agent"
)

type Config struct {
	ConfigPath   string
	RestartDelay time.Duration
}

type ConfigUpdater struct {
	client pb.AgentServiceClient
	nodeID string
	cfg    *config.Config
	opts   Config
}

func NewConfigUpdater(client pb.AgentServiceClient, nodeID string, cfg *config.Config, opts Config) *ConfigUpdater {
	return &ConfigUpdater{client: client, nodeID: nodeID, cfg: cfg, opts: opts}
}

func (u *ConfigUpdater) Listen(ctx context.Context) {}
