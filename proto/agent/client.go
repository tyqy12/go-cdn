package agent

import "context"

// AgentServiceClient Agent服务客户端接口
type AgentServiceClient interface {
	// Register 节点注册
	Register(ctx context.Context, req *RegisterRequest, opts ...interface{}) (*RegisterResponse, error)

	// Heartbeat 心跳
	Heartbeat(ctx context.Context, req *HeartbeatRequest, opts ...interface{}) (*HeartbeatResponse, error)

	// GetStatus 获取状态
	GetStatus(ctx context.Context, req *StatusRequest, opts ...interface{}) (*StatusResponse, error)

	// PushConfig 推送配置
	PushConfig(ctx context.Context, req *PushConfigRequest, opts ...interface{}) (*PushConfigResponse, error)

	// WatchConfig 配置监听（流式）
	WatchConfig(ctx context.Context, req *ConfigWatchRequest, opts ...interface{}) (AgentService_WatchConfigClient, error)

	// ReportStatus 上报状态
	ReportStatus(ctx context.Context, req *StatusRequest, opts ...interface{}) (*StatusResponse, error)

	// ExecuteCommand 执行命令（流式）
	ExecuteCommand(ctx context.Context, req interface{}, opts ...interface{}) (AgentService_ExecuteCommandClient, error)
}

// AgentService_ExecuteCommandClient 命令流客户端
type AgentService_ExecuteCommandClient interface {
	Recv() (*CommandRequest, error)
	Send(*CommandRequest) error
	CloseSend() error
}

// AgentService_WatchConfigClient 配置监听流客户端
type AgentService_WatchConfigClient interface {
	Recv() (*ConfigWatchResponse, error)
	CloseSend() error
}

// AgentServiceServer Agent服务服务端接口
type AgentServiceServer interface {
	// Register 节点注册
	Register(ctx context.Context, req *RegisterRequest) (*RegisterResponse, error)

	// Heartbeat 心跳
	Heartbeat(ctx context.Context, req *HeartbeatRequest) (*HeartbeatResponse, error)

	// GetStatus 获取状态
	GetStatus(ctx context.Context, req *StatusRequest) (*StatusResponse, error)

	// PushConfig 推送配置
	PushConfig(ctx context.Context, req *PushConfigRequest) (*PushConfigResponse, error)

	// WatchConfig 配置监听（流式）
	WatchConfig(req *ConfigWatchRequest, server AgentService_WatchConfigServer) error

	// ReportStatus 上报状态
	ReportStatus(ctx context.Context, req *StatusRequest) (*StatusResponse, error)

	// ExecuteCommand 执行命令（流式）
	ExecuteCommand(req *CommandRequest, server AgentService_ExecuteCommandServer) error
}

// AgentService_ExecuteCommandServer 命令流服务端
type AgentService_ExecuteCommandServer interface {
	Send(*CommandRequest) error
	Context() interface{}
}

// AgentService_WatchConfigServer 配置监听流服务端
type AgentService_WatchConfigServer interface {
	Send(*ConfigWatchResponse) error
	Context() interface{}
}

// MockAgentServiceClient Mock客户端（用于测试）
type MockAgentServiceClient struct{}

func (c *MockAgentServiceClient) Register(ctx context.Context, req *RegisterRequest, opts ...interface{}) (*RegisterResponse, error) {
	return &RegisterResponse{Success: true}, nil
}

func (c *MockAgentServiceClient) Heartbeat(ctx context.Context, req *HeartbeatRequest, opts ...interface{}) (*HeartbeatResponse, error) {
	return &HeartbeatResponse{Success: true}, nil
}

func (c *MockAgentServiceClient) GetStatus(ctx context.Context, req *StatusRequest, opts ...interface{}) (*StatusResponse, error) {
	return &StatusResponse{Success: true}, nil
}

func (c *MockAgentServiceClient) PushConfig(ctx context.Context, req *PushConfigRequest, opts ...interface{}) (*PushConfigResponse, error) {
	return &PushConfigResponse{Success: true}, nil
}

func (c *MockAgentServiceClient) WatchConfig(ctx context.Context, req *ConfigWatchRequest, opts ...interface{}) (AgentService_WatchConfigClient, error) {
	return &MockConfigWatchClient{}, nil
}

func (c *MockAgentServiceClient) ReportStatus(ctx context.Context, req *StatusRequest, opts ...interface{}) (*StatusResponse, error) {
	return &StatusResponse{Success: true}, nil
}

func (c *MockAgentServiceClient) ExecuteCommand(ctx context.Context, req interface{}, opts ...interface{}) (AgentService_ExecuteCommandClient, error) {
	return &MockCommandStreamClient{}, nil
}

// MockCommandStreamClient Mock命令流客户端
type MockCommandStreamClient struct{}

func (c *MockCommandStreamClient) Recv() (*CommandRequest, error) {
	return nil, nil
}

func (c *MockCommandStreamClient) Send(req *CommandRequest) error {
	return nil
}

func (c *MockCommandStreamClient) CloseSend() error {
	return nil
}

// MockConfigWatchClient Mock配置监听流客户端
type MockConfigWatchClient struct{}

func (c *MockConfigWatchClient) Recv() (*ConfigWatchResponse, error) {
	return nil, nil
}

func (c *MockConfigWatchClient) CloseSend() error {
	return nil
}

// NewAgentServiceClient 创建gRPC客户端（占位实现）
func NewAgentServiceClient(conn interface{}) AgentServiceClient {
	return &MockAgentServiceClient{}
}

// RegisterAgentServiceServer 注册gRPC服务（占位实现）
func RegisterAgentServiceServer(srv interface{}, server AgentServiceServer) {
	// TODO: 实现实际的gRPC注册
}
