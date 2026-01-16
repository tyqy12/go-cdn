package health

import "errors"

var (
	// ErrTargetNotFound 检查目标不存在
	ErrTargetNotFound = errors.New("health check target not found")
	// ErrCheckTimeout 检查超时
	ErrCheckTimeout = errors.New("health check timeout")
	// ErrCheckFailed 检查失败
	ErrCheckFailed = errors.New("health check failed")
	// ErrCheckerNotFound 检查器不存在
	ErrCheckerNotFound = errors.New("health checker not found")
)
