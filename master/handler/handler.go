package handler

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	pb "github.com/ai-cdn-tunnel/proto/agent"
	"github.com/ai-cdn-tunnel/master/monitor"
	"github.com/ai-cdn-tunnel/master/node"
)

func CORS() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
		c.Header("Access-Control-Max-Age", "86400")
		c.Header("Access-Control-Allow-Credentials", "true")
		c.Header("Access-Control-Expose-Headers", "Content-Length, Content-Range")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

func Logger() gin.HandlerFunc {
	return gin.Logger()
}

func JWTAuth(secret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 从 Authorization header 获取 token
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "missing_authorization_header",
				"message": "Authorization header is required",
			})
			c.Abort()
			return
		}

		// 检查 Bearer 格式
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "invalid_authorization_header",
				"message": "Authorization header must be in format: Bearer <token>",
			})
			c.Abort()
			return
		}

		tokenString := parts[1]

		// 解析和验证 token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// 验证签名方法
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, errors.New("unexpected signing method")
			}
			return []byte(secret), nil
		})

		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "invalid_token",
				"message": "Invalid or expired token: " + err.Error(),
			})
			c.Abort()
			return
		}

		// 检查 token 是否有效
		if !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "token_not_valid",
				"message": "Token is not valid",
			})
			c.Abort()
			return
		}

		// 提取 claims 并设置到上下文
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "invalid_token_claims",
				"message": "Invalid token claims",
			})
			c.Abort()
			return
		}

		// 检查过期时间
		if exp, ok := claims["exp"].(float64); ok {
			expTime := time.Unix(int64(exp), 0)
			if time.Now().After(expTime) {
				c.JSON(http.StatusUnauthorized, gin.H{
					"error":   "token_expired",
					"message": "Token has expired",
				})
				c.Abort()
				return
			}
		}

		// 设置用户信息到上下文
		c.Set("user_id", claims["sub"])
		c.Set("user_role", claims["role"])
		c.Set("token_claims", claims)

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
