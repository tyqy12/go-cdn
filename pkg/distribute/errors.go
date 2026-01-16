package distribute

import "errors"

var (
	// ErrRouteNotFound 路由不存在
	ErrRouteNotFound = errors.New("route not found")
	// ErrNoMatchingRoute 无匹配路由
	ErrNoMatchingRoute = errors.New("no matching route")
	// ErrForwarderNotConfigured 转发器未配置
	ErrForwarderNotConfigured = errors.New("forwarder not configured")
	// ErrInvalidRouteConfig 无效路由配置
	ErrInvalidRouteConfig = errors.New("invalid route config")
	// ErrRouteDisabled 路由已禁用
	ErrRouteDisabled = errors.New("route is disabled")
	// ErrActionNotSupported 不支持的动作
	ErrActionNotSupported = errors.New("unsupported action")
	// ErrTargetPoolNotFound 目标池不存在
	ErrTargetPoolNotFound = errors.New("target pool not found")
)
