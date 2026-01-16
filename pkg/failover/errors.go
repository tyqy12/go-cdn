package failover

import "errors"

var (
	// ErrGroupAlreadyExists 组已存在
	ErrGroupAlreadyExists = errors.New("failover group already exists")
	// ErrGroupNotFound 组不存在
	ErrGroupNotFound = errors.New("failover group not found")
	// ErrNoAvailableNode 无可用节点
	ErrNoAvailableNode = errors.New("no available node")
	// ErrSameNode 相同节点
	ErrSameNode = errors.New("same node")
	// ErrNodeNotFound 节点不存在
	ErrNodeNotFound = errors.New("node not found")
	// ErrSwitchFailed 切换失败
	ErrSwitchFailed = errors.New("failover switch failed")
)
