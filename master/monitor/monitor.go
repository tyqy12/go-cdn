package monitor

import "github.com/ai-cdn-tunnel/master/db"

type Monitor struct{}

func NewMonitor(database *db.MongoDB) *Monitor {
	return &Monitor{}
}

func (m *Monitor) StartCollecting() {}
