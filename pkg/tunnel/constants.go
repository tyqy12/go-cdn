package tunnel

// TunnelState 隧道状态
type TunnelState string

const (
	TunnelStateInitializing TunnelState = "initializing"
	TunnelStateActive       TunnelState = "active"
	TunnelStateDegraded     TunnelState = "degraded"
	TunnelStateDraining     TunnelState = "draining"
	TunnelStateTerminated   TunnelState = "terminated"
)

// TunnelEvent 隧道事件
type TunnelEvent string

const (
	EventCreate     TunnelEvent = "create"
	EventStart      TunnelEvent = "start"
	EventStop       TunnelEvent = "stop"
	EventDrain      TunnelEvent = "drain"
	EventTerminate  TunnelEvent = "terminate"
	EventHealthUp   TunnelEvent = "health_up"
	EventHealthDown TunnelEvent = "health_down"
)

// StateTransitions 状态转换规则
var StateTransitions = map[TunnelState][]TunnelState{
	TunnelStateInitializing: {TunnelStateActive, TunnelStateTerminated},
	TunnelStateActive:       {TunnelStateDegraded, TunnelStateDraining, TunnelStateTerminated},
	TunnelStateDegraded:     {TunnelStateActive, TunnelStateDraining, TunnelStateTerminated},
	TunnelStateDraining:     {TunnelStateTerminated},
	TunnelStateTerminated:   {},
}

// CanTransition 检查状态转换是否合法
func CanTransition(from, to TunnelState) bool {
	allowed, exists := StateTransitions[from]
	if !exists {
		return false
	}
	for _, state := range allowed {
		if state == to {
			return true
		}
	}
	return false
}
