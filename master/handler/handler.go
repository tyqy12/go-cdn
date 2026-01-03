package handler

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"

	pb "github.com/ai-cdn-tunnel/proto/agent"
	"github.com/ai-cdn-tunnel/master/monitor"
	"github.com/ai-cdn-tunnel/master/node"
)

func CORS() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
	}
}

func Logger() gin.HandlerFunc {
	return gin.Logger()
}

func JWTAuth(secret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
	}
}

func ListNodes(nodeMgr *node.Manager) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"nodes": []string{}})
	}
}

func GetNode(nodeMgr *node.Manager) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"node": nil})
	}
}

func UpdateNode(nodeMgr *node.Manager) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "updated"})
	}
}

func DeleteNode(nodeMgr *node.Manager) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "deleted"})
	}
}

func UpdateNodeTags(nodeMgr *node.Manager) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "tags_updated"})
	}
}

func OnlineNode(nodeMgr *node.Manager) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "online"})
	}
}

func OfflineNode(nodeMgr *node.Manager) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "offline"})
	}
}

func ListConfigs(nodeMgr *node.Manager) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"configs": []string{}})
	}
}

func GetConfig(nodeMgr *node.Manager) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"config": nil})
	}
}

func CreateConfig(nodeMgr *node.Manager) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusCreated, gin.H{"status": "created"})
	}
}

func PublishConfig(nodeMgr *node.Manager) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "published"})
	}
}

func RollbackConfig(nodeMgr *node.Manager) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "rolled_back"})
	}
}

func ExecuteCommand(nodeMgr *node.Manager) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusAccepted, gin.H{"status": "queued"})
	}
}

func GetCommandStatus(nodeMgr *node.Manager) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "unknown"})
	}
}

func GetNodeMetrics(monitorMgr *monitor.Monitor) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"metrics": nil})
	}
}

func GetAggregateMetrics(monitorMgr *monitor.Monitor) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"metrics": nil})
	}
}

func ListAlerts(monitorMgr *monitor.Monitor) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"alerts": []string{}})
	}
}

func GetAlert(monitorMgr *monitor.Monitor) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"alert": nil})
	}
}

func SilenceAlert(monitorMgr *monitor.Monitor) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "silenced"})
	}
}

type AgentServer struct {
	nodeMgr    *node.Manager
	monitorMgr *monitor.Monitor
}

func NewAgentServer(nodeMgr *node.Manager, monitorMgr *monitor.Monitor) *AgentServer {
	return &AgentServer{nodeMgr: nodeMgr, monitorMgr: monitorMgr}
}

func (s *AgentServer) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	return &pb.RegisterResponse{Success: true, MasterVersion: "dev"}, nil
}

func (s *AgentServer) ExecuteCommand(req *pb.CommandRequest, stream pb.AgentService_ExecuteCommandServer) error {
	return nil
}

func (s *AgentServer) Heartbeat(ctx context.Context, req *pb.HeartbeatRequest) (*pb.HeartbeatResponse, error) {
	return &pb.HeartbeatResponse{Success: true}, nil
}

func (s *AgentServer) GetStatus(ctx context.Context, req *pb.StatusRequest) (*pb.StatusResponse, error) {
	return &pb.StatusResponse{Success: true, Status: "ok"}, nil
}

func (s *AgentServer) PushConfig(ctx context.Context, req *pb.PushConfigRequest) (*pb.PushConfigResponse, error) {
	return &pb.PushConfigResponse{Success: true}, nil
}

func (s *AgentServer) ReportStatus(ctx context.Context, req *pb.StatusRequest) (*pb.StatusResponse, error) {
	return &pb.StatusResponse{Success: true}, nil
}
