package agent

import (
	"context"

	"google.golang.org/grpc"
)

type RegisterRequest struct {
	NodeId   string
	NodeName string
	NodeType string
	Region   string
	Ip       string
	Metadata map[string]string
}

type RegisterResponse struct {
	Success       bool
	Message       string
	MasterVersion string
}

type CommandRequest struct {
	CommandId string
	NodeId    string
	AgentId   string
	Command   string
	Params    map[string]string
}

type CommandResponse struct {
	CommandId string
	Success   bool
	Output    string
	Error     string
}

type HeartbeatRequest struct {
	NodeId     string
	Timestamp  int64
	Status     string
	Attributes map[string]string
	TLSInfo    *TLSInfo
}

type HeartbeatResponse struct {
	Success bool
	Message string
	Status  string
}

type PushConfigRequest struct {
	NodeId     string
	ConfigType string
	ConfigData []byte
	Version    int64
}

type PushConfigResponse struct {
	Success bool
	Message string
}

type StatusData struct {
	CpuUsage     float64
	MemoryUsage  float64
	BandwidthIn  float64
	BandwidthOut float64
	Qps          float64
	Connections  int64
	Uptime       int64
}

type TLSInfo struct {
	Version string
	Cipher  string
}

type StatusRequest struct {
	NodeId  string
	AgentId string
	Status  *StatusData
}

type StatusResponse struct {
	Success bool
	Message string
	Status  string
}

type AgentServiceClient interface {
	Register(ctx context.Context, in *RegisterRequest, opts ...grpc.CallOption) (*RegisterResponse, error)
	ExecuteCommand(ctx context.Context, in interface{}, opts ...grpc.CallOption) (AgentService_ExecuteCommandClient, error)
	Heartbeat(ctx context.Context, in *HeartbeatRequest, opts ...grpc.CallOption) (*HeartbeatResponse, error)
	GetStatus(ctx context.Context, in *StatusRequest, opts ...grpc.CallOption) (*StatusResponse, error)
	PushConfig(ctx context.Context, in *PushConfigRequest, opts ...grpc.CallOption) (*PushConfigResponse, error)
	ReportStatus(ctx context.Context, in *StatusRequest, opts ...grpc.CallOption) (*StatusResponse, error)
}

type agentServiceClient struct {
	conn *grpc.ClientConn
}

func NewAgentServiceClient(conn *grpc.ClientConn) AgentServiceClient {
	return &agentServiceClient{conn: conn}
}

func (c *agentServiceClient) Register(ctx context.Context, in *RegisterRequest, opts ...grpc.CallOption) (*RegisterResponse, error) {
	return &RegisterResponse{Success: true}, nil
}

func (c *agentServiceClient) ExecuteCommand(ctx context.Context, in interface{}, opts ...grpc.CallOption) (AgentService_ExecuteCommandClient, error) {
	return &agentServiceExecuteCommandClient{}, nil
}

func (c *agentServiceClient) Heartbeat(ctx context.Context, in *HeartbeatRequest, opts ...grpc.CallOption) (*HeartbeatResponse, error) {
	return &HeartbeatResponse{Success: true}, nil
}

func (c *agentServiceClient) GetStatus(ctx context.Context, in *StatusRequest, opts ...grpc.CallOption) (*StatusResponse, error) {
	return &StatusResponse{Success: true, Status: "ok"}, nil
}

func (c *agentServiceClient) PushConfig(ctx context.Context, in *PushConfigRequest, opts ...grpc.CallOption) (*PushConfigResponse, error) {
	return &PushConfigResponse{Success: true}, nil
}

func (c *agentServiceClient) ReportStatus(ctx context.Context, in *StatusRequest, opts ...grpc.CallOption) (*StatusResponse, error) {
	return &StatusResponse{Success: true}, nil
}

type AgentService_ExecuteCommandClient interface {
	Recv() (*CommandRequest, error)
	Send(*CommandRequest) error
	SendMsg(m interface{}) error
	CloseSend() error
}

type agentServiceExecuteCommandClient struct{}

func (c *agentServiceExecuteCommandClient) Recv() (*CommandRequest, error) {
	return nil, nil
}

func (c *agentServiceExecuteCommandClient) Send(req *CommandRequest) error {
	return nil
}

func (c *agentServiceExecuteCommandClient) SendMsg(m interface{}) error {
	return nil
}

func (c *agentServiceExecuteCommandClient) CloseSend() error {
	return nil
}

type AgentServiceServer interface {
	Register(context.Context, *RegisterRequest) (*RegisterResponse, error)
	ExecuteCommand(*CommandRequest, AgentService_ExecuteCommandServer) error
	Heartbeat(context.Context, *HeartbeatRequest) (*HeartbeatResponse, error)
	GetStatus(context.Context, *StatusRequest) (*StatusResponse, error)
	PushConfig(context.Context, *PushConfigRequest) (*PushConfigResponse, error)
	ReportStatus(context.Context, *StatusRequest) (*StatusResponse, error)
}

type AgentService_ExecuteCommandServer interface {
	Send(*CommandRequest) error
	Context() context.Context
}

func RegisterAgentServiceServer(s *grpc.Server, srv AgentServiceServer) {}
