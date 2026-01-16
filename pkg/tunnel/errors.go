package tunnel

import "errors"

var (
	// ErrTunnelNotFound 隧道不存在
	ErrTunnelNotFound = errors.New("tunnel not found")
	// ErrTunnelAlreadyExists 隧道已存在
	ErrTunnelAlreadyExists = errors.New("tunnel already exists")
	// ErrTunnelInvalidConfig 隧道配置无效
	ErrTunnelInvalidConfig = errors.New("invalid tunnel config")
	// ErrTunnelStartFailed 隧道启动失败
	ErrTunnelStartFailed = errors.New("failed to start tunnel")
	// ErrTunnelStopFailed 隧道停止失败
	ErrTunnelStopFailed = errors.New("failed to stop tunnel")
)
