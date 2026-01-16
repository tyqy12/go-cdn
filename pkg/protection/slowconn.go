package protection

import (
	"sync"
	"time"
)

// SlowConnectionDetector 慢连接检测器
type SlowConnectionDetector struct {
	threshold time.Duration
	tracker   *ConnectionTracker
}

// ConnectionTracker 连接跟踪器
type ConnectionTracker struct {
	mu         sync.RWMutex
	thresholds map[time.Duration]int64
}

// NewSlowConnectionDetector 创建慢连接检测器
func NewSlowConnectionDetector(threshold time.Duration) *SlowConnectionDetector {
	return &SlowConnectionDetector{
		threshold: threshold,
		tracker: &ConnectionTracker{
			thresholds: map[time.Duration]int64{
				threshold: 0,
			},
		},
	}
}

// Detect 检测慢连接
func (d *SlowConnectionDetector) Detect(elapsed time.Duration, bytesRead int64) bool {
	if elapsed < d.threshold {
		return false
	}

	rate := float64(bytesRead) / elapsed.Seconds()
	expectedRate := float64(1024) // 1KB/s 基准

	return rate < expectedRate
}

// SetThreshold 设置阈值
func (d *SlowConnectionDetector) SetThreshold(threshold time.Duration) {
	d.threshold = threshold
}
