package master

import (
	"context"

	"google.golang.org/grpc"
)

type UpdateConfigRequest struct {
	AgentId    string
	ConfigType string
	ConfigData []byte
	Version    int64
}

type UpdateConfigResponse struct {
	Success bool
	Message string
}

type CommandRequest struct {
	AgentId  string
	Command  string
	Params   map[string]string
	TimeoutS int64
}

type CommandResponse struct {
	Success bool
	Message string
	Output  string
}

type StatusRequest struct {
	AgentId string
}

type StatusResponse struct {
	Status       string
	Uptime       int64
	CpuUsage     float64
	MemoryUsage  float64
	BandwidthIn  float64
	BandwidthOut float64
	Qps          float64
	Connections  int64
}

type AgentServiceClient interface {
	UpdateConfig(ctx context.Context, in *UpdateConfigRequest, opts ...grpc.CallOption) (*UpdateConfigResponse, error)
	ExecuteCommand(ctx context.Context, in *CommandRequest, opts ...grpc.CallOption) (*CommandResponse, error)
	GetStatus(ctx context.Context, in *StatusRequest, opts ...grpc.CallOption) (*StatusResponse, error)
	CommandStream(ctx context.Context, opts ...grpc.CallOption) (AgentService_CommandStreamClient, error)
}

type agentServiceClient struct{}

func NewAgentServiceClient(conn *grpc.ClientConn) AgentServiceClient {
	return &agentServiceClient{}
}

func (c *agentServiceClient) UpdateConfig(ctx context.Context, in *UpdateConfigRequest, opts ...grpc.CallOption) (*UpdateConfigResponse, error) {
	return &UpdateConfigResponse{Success: true}, nil
}

func (c *agentServiceClient) ExecuteCommand(ctx context.Context, in *CommandRequest, opts ...grpc.CallOption) (*CommandResponse, error) {
	return &CommandResponse{Success: true}, nil
}

func (c *agentServiceClient) GetStatus(ctx context.Context, in *StatusRequest, opts ...grpc.CallOption) (*StatusResponse, error) {
	return &StatusResponse{Status: "unknown"}, nil
}

func (c *agentServiceClient) CommandStream(ctx context.Context, opts ...grpc.CallOption) (AgentService_CommandStreamClient, error) {
	return &agentServiceCommandStreamClient{}, nil
}

type AgentService_CommandStreamClient interface {
	Recv() (*CommandResponse, error)
	CloseSend() error
}

type agentServiceCommandStreamClient struct{}

func (c *agentServiceCommandStreamClient) Recv() (*CommandResponse, error) {
	return nil, nil
}

func (c *agentServiceCommandStreamClient) CloseSend() error {
	return nil
}
