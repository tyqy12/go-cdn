package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"github.com/ai-cdn-tunnel/master/db"
	"github.com/ai-cdn-tunnel/master/monitor"
	"github.com/ai-cdn-tunnel/master/node"
	pb "github.com/ai-cdn-tunnel/proto/agent"
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
		nodes := nodeMgr.GetAllNodes()
		result := make([]gin.H, 0, len(nodes))
		for _, n := range nodes {
			result = append(result, gin.H{
				"id":         n.ID,
				"name":       n.Name,
				"type":       n.Type,
				"addr":       n.Addr,
				"port":       n.Port,
				"region":     n.Region,
				"status":     n.Status,
				"tags":       n.Tags,
				"metadata":   n.Metadata,
				"version":    n.Version,
				"online":     n.Online,
				"last_beat":  n.LastBeatAt,
				"created_at": n.CreatedAt,
			})
		}

		c.JSON(http.StatusOK, gin.H{
			"nodes": result,
			"total": len(result),
		})
	}
}

// GetNode 获取单个节点详情
func GetNode(nodeMgr *node.Manager) gin.HandlerFunc {
	return func(c *gin.Context) {
		nodeID := c.Param("id")

		if nodeID == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "missing_node_id",
				"message": "Node ID is required",
			})
			return
		}

		node := nodeMgr.GetNode(nodeID)
		if node == nil {
			c.JSON(http.StatusNotFound, gin.H{
				"error":   "node_not_found",
				"message": fmt.Sprintf("Node %s not found", nodeID),
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"id":         node.ID,
			"name":       node.Name,
			"type":       node.Type,
			"addr":       node.Addr,
			"port":       node.Port,
			"region":     node.Region,
			"status":     node.Status,
			"tags":       node.Tags,
			"metadata":   node.Metadata,
			"version":    node.Version,
			"online":     node.Online,
			"last_beat":  node.LastBeatAt,
			"created_at": node.CreatedAt,
			"updated_at": node.UpdatedAt,
		})
	}
}

// UpdateNodeRequest 更新节点请求
type UpdateNodeRequest struct {
	Name     string            `json:"name"`
	Addr     string            `json:"addr"`
	Port     int               `json:"port"`
	Region   string            `json:"region"`
	Tags     []string          `json:"tags"`
	Metadata map[string]string `json:"metadata"`
}

// UpdateNode 更新节点信息
func UpdateNode(nodeMgr *node.Manager) gin.HandlerFunc {
	return func(c *gin.Context) {
		nodeID := c.Param("id")

		if nodeID == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "missing_node_id",
				"message": "Node ID is required",
			})
			return
		}

		currNode := nodeMgr.GetNode(nodeID)
		if currNode == nil {
			c.JSON(http.StatusNotFound, gin.H{
				"error":   "node_not_found",
				"message": fmt.Sprintf("Node %s not found", nodeID),
			})
			return
		}

		var req UpdateNodeRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "invalid_request",
				"message": err.Error(),
			})
			return
		}

		// 更新节点信息
		nodeMgr.UpdateNode(nodeID, func(n *node.Node) {
			if req.Name != "" {
				n.Name = req.Name
			}
			if req.Addr != "" {
				n.Addr = req.Addr
			}
			if req.Port > 0 {
				n.Port = req.Port
			}
			if req.Region != "" {
				n.Region = req.Region
			}
			if req.Tags != nil {
				n.Tags = req.Tags
			}
			if req.Metadata != nil {
				n.Metadata = req.Metadata
			}
		})

		userID, _ := c.Get("user_id")
		log.Printf("[Handler] Node %s updated by %v", nodeID, userID)

		c.JSON(http.StatusOK, gin.H{
			"status":  "updated",
			"node_id": nodeID,
			"message": "Node updated successfully",
		})
	}
}

// DeleteNode 删除节点
func DeleteNode(nodeMgr *node.Manager) gin.HandlerFunc {
	return func(c *gin.Context) {
		nodeID := c.Param("id")

		if nodeID == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "missing_node_id",
				"message": "Node ID is required",
			})
			return
		}

		node := nodeMgr.GetNode(nodeID)
		if node == nil {
			c.JSON(http.StatusNotFound, gin.H{
				"error":   "node_not_found",
				"message": fmt.Sprintf("Node %s not found", nodeID),
			})
			return
		}

		// 从节点管理器中删除
		nodeMgr.RemoveNode(nodeID)

		userID, _ := c.Get("user_id")
		log.Printf("[Handler] Node %s deleted by %v", nodeID, userID)

		c.JSON(http.StatusOK, gin.H{
			"status":  "deleted",
			"node_id": nodeID,
			"message": "Node deleted successfully",
		})
	}
}

// GetNodeStatus 获取节点状态
func GetNodeStatus(nodeMgr *node.Manager) gin.HandlerFunc {
	return func(c *gin.Context) {
		nodeID := c.Param("id")

		if nodeID == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "missing_node_id",
				"message": "Node ID is required",
			})
			return
		}

		node := nodeMgr.GetNode(nodeID)
		if node == nil {
			c.JSON(http.StatusNotFound, gin.H{
				"error":   "node_not_found",
				"message": fmt.Sprintf("Node %s not found", nodeID),
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"node_id":   node.ID,
			"node_name": node.Name,
			"status":    node.Status,
			"online":    node.Online,
			"last_seen": node.LastBeatAt,
			"region":    node.Region,
			"type":      node.Type,
		})
	}
}

// RestartNode 重启节点
func RestartNode(nodeMgr *node.Manager) gin.HandlerFunc {
	return func(c *gin.Context) {
		nodeID := c.Param("id")

		if nodeID == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "missing_node_id",
				"message": "Node ID is required",
			})
			return
		}

		node := nodeMgr.GetNode(nodeID)
		if node == nil {
			c.JSON(http.StatusNotFound, gin.H{
				"error":   "node_not_found",
				"message": fmt.Sprintf("Node %s not found", nodeID),
			})
			return
		}

		// TODO: 发送重启命令到节点
		log.Printf("[Handler] Restart command sent to node %s", nodeID)

		c.JSON(http.StatusOK, gin.H{
			"status":   "restarting",
			"node_id":  nodeID,
			"message":  "Restart command has been sent",
			"queued_at": time.Now().Unix(),
		})
	}
}

// ListCommandHistory 获取命令历史
func ListCommandHistory(database *db.MongoDB) gin.HandlerFunc {
	return func(c *gin.Context) {
		nodeID := c.DefaultQuery("node_id", "")
		status := c.DefaultQuery("status", "")
		limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
		if limit < 1 || limit > 500 {
			limit = 50
		}
		offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

		if database == nil {
			c.JSON(http.StatusOK, gin.H{
				"commands": []gin.H{},
				"total":    0,
			})
			return
		}

		filter := &db.TaskFilter{
			NodeID: nodeID,
			Status: status,
			Limit:  limit,
			Offset: offset,
		}

		tasks, err := database.ListTasks(c.Request.Context(), filter)
		if err != nil {
			log.Printf("[Handler] Failed to list tasks: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "list_failed",
				"message": err.Error(),
			})
			return
		}

		result := make([]gin.H, 0, len(tasks))
		for _, task := range tasks {
			result = append(result, gin.H{
				"task_id":      task.TaskID,
				"node_id":      task.NodeID,
				"command":      task.Command,
				"status":       task.Status,
				"params":       task.Params,
				"output":       task.Output,
				"error":        task.Error,
				"requested_by": task.RequestedBy,
				"started_at":   task.StartedAt,
				"completed_at": task.CompletedAt,
				"created_at":   task.CreatedAt,
			})
		}

		c.JSON(http.StatusOK, gin.H{
			"commands": result,
			"total":    len(result),
			"limit":    limit,
			"offset":   offset,
		})
	}
}

// CommandRequest 命令执行请求
type CommandRequest struct {
	NodeID      string            `json:"node_id" binding:"required"`
	Command     string            `json:"command" binding:"required,oneof=reload restart stop status logs restart_gost restart_agent"`
	Params      map[string]string `json:"params"`
	RequestedBy string            `json:"requested_by"`
}

// CommandResponse 命令执行响应
type CommandResponse struct {
	TaskID    string    `json:"task_id"`
	Status    string    `json:"status"`
	Message   string    `json:"message"`
	CreatedAt time.Time `json:"created_at"`
}

// ExecuteCommand 执行命令
func ExecuteCommand(nodeMgr *node.Manager, database *db.MongoDB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req CommandRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "invalid_request",
				"message": err.Error(),
			})
			return
		}

		// 验证节点是否存在
		node := nodeMgr.GetNode(req.NodeID)
		if node == nil {
			c.JSON(http.StatusNotFound, gin.H{
				"error":   "node_not_found",
				"message": fmt.Sprintf("Node %s not found", req.NodeID),
			})
			return
		}

		// 检查节点是否在线
		if node.Status != "online" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "node_offline",
				"message": fmt.Sprintf("Node %s is %s, not online", req.NodeID, node.Status),
			})
			return
		}

		// 生成任务ID
		taskID := generateTaskID()

		// 获取请求用户
		requestedBy := "api"
		if userID, exists := c.Get("user_id"); exists {
			requestedBy = userID.(string)
		} else if req.RequestedBy != "" {
			requestedBy = req.RequestedBy
		}

		// 创建任务
		task := &db.Task{
			TaskID:      taskID,
			Command:     req.Command,
			NodeID:      req.NodeID,
			Status:      "pending",
			Params:      req.Params,
			RequestedBy: requestedBy,
			CreatedAt:   time.Now(),
		}

		// 保存任务到数据库
		if database != nil {
			if err := database.SaveTask(c.Request.Context(), task); err != nil {
				log.Printf("[Handler] Failed to save task: %v", err)
			}
		}

		// TODO: 通过 gRPC 将命令发送到节点执行
		log.Printf("[Handler] Command %s sent to node %s, task_id: %s", req.Command, req.NodeID, taskID)

		c.JSON(http.StatusAccepted, CommandResponse{
			TaskID:    taskID,
			Status:    "pending",
			Message:   fmt.Sprintf("Command %s has been queued for execution", req.Command),
			CreatedAt: time.Now(),
		})
	}
}

func GetCommandStatus(nodeMgr *node.Manager, database *db.MongoDB) gin.HandlerFunc {
	return func(c *gin.Context) {
		taskID := c.Param("task_id")

		if taskID == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "missing_task_id",
				"message": "Task ID is required",
			})
			return
		}

		// 从数据库获取任务状态
		if database != nil {
			task, err := database.GetTask(c.Request.Context(), taskID)
			if err != nil {
				log.Printf("[Handler] Failed to get task from database: %v", err)
			} else if task != nil {
				c.JSON(http.StatusOK, gin.H{
					"task_id":      task.TaskID,
					"command":      task.Command,
					"node_id":      task.NodeID,
					"status":       task.Status,
					"output":       task.Output,
					"error":        task.Error,
					"requested_by": task.RequestedBy,
					"started_at":   task.StartedAt,
					"completed_at": task.CompletedAt,
					"created_at":   task.CreatedAt,
				})
				return
			}
		}

		// 如果数据库中没有，从内存中查找
		// 返回任务不存在
		c.JSON(http.StatusNotFound, gin.H{
			"error":   "task_not_found",
			"message": fmt.Sprintf("Task %s not found", taskID),
		})
	}
}

func GetNodeMetrics(monitorMgr *monitor.Monitor) gin.HandlerFunc {
	return func(c *gin.Context) {
		nodeID := c.Param("id")

		if nodeID == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "missing_node_id",
				"message": "Node ID is required",
			})
			return
		}

		// 从监控器获取节点指标
		metrics, exists := monitorMgr.GetNodeMetrics(nodeID)
		if !exists {
			c.JSON(http.StatusNotFound, gin.H{
				"error":   "node_not_found",
				"message": fmt.Sprintf("Node %s not found or no metrics available", nodeID),
			})
			return
		}

		// 构建响应
		response := gin.H{
			"node_id":   nodeID,
			"metrics":   gin.H{},
			"timestamp": time.Now().Unix(),
		}

		if metrics.System != nil {
			response["metrics"].(gin.H)["system"] = gin.H{
				"cpu_usage":    metrics.System.CPUUsage,
				"memory_usage": metrics.System.MemoryUsage,
				"disk_usage":   metrics.System.DiskUsage,
				"goroutines":   metrics.System.Goroutines,
				"uptime":       metrics.System.Uptime,
			}
		}

		if metrics.Network != nil {
			response["metrics"].(gin.H)["network"] = gin.H{
				"rx":            metrics.Network.BytesIn,
				"tx":            metrics.Network.BytesOut,
				"bandwidth_mbps": metrics.Network.BandwidthIn,
			}
		}

		if metrics.CDN != nil {
			response["metrics"].(gin.H)["cdn"] = gin.H{
				"total_requests":   metrics.CDN.TotalRequests,
				"success_requests": metrics.CDN.SuccessRequests,
				"error_requests":   metrics.CDN.ErrorRequests,
				"qps":              metrics.CDN.QPS,
				"p50_latency":      metrics.CDN.P50Latency,
				"p95_latency":      metrics.CDN.P95Latency,
				"p99_latency":      metrics.CDN.P99Latency,
			}
		}

		if metrics.Connections != nil {
			response["metrics"].(gin.H)["connections"] = gin.H{
				"active_connections": metrics.Connections.ActiveConnections,
				"total_connections":  metrics.Connections.TotalConnections,
				"closed_connections": metrics.Connections.ClosedConnections,
				"idle_connections":   metrics.Connections.IdleConnections,
			}
		}

		if metrics.Security != nil {
			response["metrics"].(gin.H)["security"] = gin.H{
				"blocked_connections":  metrics.Security.BlockedConnections,
				"slow_connections":     metrics.Security.SlowConnections,
				"rate_limited_requests": metrics.Security.RateLimitedRequests,
				"cc_blocked":           metrics.Security.CCBlocked,
			}
		}

		c.JSON(http.StatusOK, response)
	}
}

func GetAggregateMetrics(monitorMgr *monitor.Monitor) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 从监控器获取所有节点的指标
		allMetrics := monitorMgr.GetAllMetrics()

		totalNodes := len(allMetrics)
		onlineNodes := 0
		var totalRequests int64 = 0
		var successRequests int64 = 0
		var errorRequests int64 = 0
		var totalQPS float64 = 0
		var totalLatency float64 = 0
		var totalBandwidthIn float64 = 0
		var totalBandwidthOut float64 = 0

		for _, metrics := range allMetrics {
			// 检查节点是否在线（最近2分钟有更新）
			if time.Since(metrics.LastUpdate) < 2*time.Minute {
				onlineNodes++
			}

			// 聚合 CDN 指标
			if metrics.CDN != nil {
				totalRequests += metrics.CDN.TotalRequests
				successRequests += metrics.CDN.SuccessRequests
				errorRequests += metrics.CDN.ErrorRequests
				totalQPS += metrics.CDN.QPS
				if metrics.CDN.P95Latency > 0 {
					totalLatency += metrics.CDN.P95Latency
				}
			}

			// 聚合网络指标
			if metrics.Network != nil {
				totalBandwidthIn += metrics.Network.BandwidthIn
				totalBandwidthOut += metrics.Network.BandwidthOut
			}
		}

		// 计算平均延迟
		avgLatency := float64(0)
		if onlineNodes > 0 {
			avgLatency = totalLatency / float64(onlineNodes)
		}

		// 计算缓存命中率（如果有数据）
		cacheHitRate := float64(0)
		if totalRequests > 0 {
			cacheHitRate = float64(successRequests) / float64(totalRequests)
		}

		// 计算 QPS
		qps := float64(0)
		if onlineNodes > 0 {
			qps = totalQPS
		}

		metrics := gin.H{
			"total_nodes":       totalNodes,
			"online_nodes":      onlineNodes,
			"offline_nodes":     totalNodes - onlineNodes,
			"total_requests":    totalRequests,
			"success_requests":  successRequests,
			"error_requests":    errorRequests,
			"cache_hit_rate":    cacheHitRate,
			"average_latency":   avgLatency,
			"qps":               qps,
			"bandwidth_mbps_in":  totalBandwidthIn,
			"bandwidth_mbps_out": totalBandwidthOut,
			"timestamp":         time.Now().Unix(),
		}

		c.JSON(http.StatusOK, gin.H{
			"metrics": metrics,
		})
	}
}

func ListAlerts(database *db.MongoDB) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 获取查询参数
		severity := c.DefaultQuery("severity", "")
		status := c.DefaultQuery("status", "")
		nodeID := c.DefaultQuery("node_id", "")
		limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
		if limit < 1 || limit > 1000 {
			limit = 100
		}
		offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

		// 从数据库获取告警列表
		if database != nil {
			filter := &db.AlertFilter{
				Severity: severity,
				Status:   status,
				NodeID:   nodeID,
				Limit:    limit,
				Offset:   offset,
			}
			alerts, err := database.ListAlerts(c.Request.Context(), filter)
			if err != nil {
				log.Printf("[Handler] Failed to list alerts from database: %v", err)
			} else {
				result := make([]gin.H, 0, len(alerts))
				for _, alert := range alerts {
					result = append(result, gin.H{
						"id":           alert.AlertID,
						"type":         alert.Type,
						"severity":     alert.Severity,
						"node_id":      alert.NodeID,
						"message":      alert.Message,
						"details":      alert.Details,
						"status":       alert.Status,
						"silenced":     alert.Silenced,
						"silenced_by":  alert.SilencedBy,
						"repeat_count": alert.RepeatCount,
						"first_seen":   alert.FirstSeen.Unix(),
						"last_seen":    alert.LastSeen.Unix(),
						"created_at":   alert.CreatedAt.Unix(),
					})
				}

				c.JSON(http.StatusOK, gin.H{
					"alerts":   result,
					"total":    len(result),
					"severity": severity,
					"status":   status,
					"limit":    limit,
					"offset":   offset,
				})
				return
			}
		}

		// 如果数据库不可用，返回空列表
		c.JSON(http.StatusOK, gin.H{
			"alerts":   []gin.H{},
			"total":    0,
			"severity": severity,
			"status":   status,
		})
	}
}

func GetAlert(database *db.MongoDB) gin.HandlerFunc {
	return func(c *gin.Context) {
		alertID := c.Param("id")

		if alertID == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "missing_alert_id",
				"message": "Alert ID is required",
			})
			return
		}

		// 从数据库获取告警详情
		if database != nil {
			alert, err := database.GetAlert(c.Request.Context(), alertID)
			if err != nil {
				log.Printf("[Handler] Failed to get alert from database: %v", err)
			} else if alert != nil {
				c.JSON(http.StatusOK, gin.H{
					"alert": gin.H{
						"id":            alert.AlertID,
						"type":          alert.Type,
						"severity":      alert.Severity,
						"node_id":       alert.NodeID,
						"message":       alert.Message,
						"details":       alert.Details,
						"status":        alert.Status,
						"silenced":      alert.Silenced,
						"silenced_by":   alert.SilencedBy,
						"silenced_at":   alert.SilencedAt.Unix(),
						"silenced_until": alert.SilencedUntil.Unix(),
						"repeat_count":  alert.RepeatCount,
						"first_seen":    alert.FirstSeen.Unix(),
						"last_seen":     alert.LastSeen.Unix(),
						"resolved_at":   alert.ResolvedAt.Unix(),
						"created_at":    alert.CreatedAt.Unix(),
					},
				})
				return
			}
		}

		// 告警不存在
		c.JSON(http.StatusNotFound, gin.H{
			"error":   "alert_not_found",
			"message": fmt.Sprintf("Alert %s not found", alertID),
		})
	}
}

func SilenceAlert(database *db.MongoDB) gin.HandlerFunc {
	return func(c *gin.Context) {
		alertID := c.Param("id")

		if alertID == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "missing_alert_id",
				"message": "Alert ID is required",
			})
			return
		}

		// 获取请求用户
		silencedBy := "system"
		if userID, exists := c.Get("user_id"); exists {
			silencedBy = userID.(string)
		}

		// 从数据库静音告警
		if database != nil {
			err := database.SilenceAlert(c.Request.Context(), alertID, true, silencedBy)
			if err != nil {
				log.Printf("[Handler] Failed to silence alert: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{
					"error":   "silence_failed",
					"message": fmt.Sprintf("Failed to silence alert: %v", err),
				})
				return
			}

			log.Printf("[Alert] Alert %s silenced by %s", alertID, silencedBy)
			c.JSON(http.StatusOK, gin.H{
				"status":       "silenced",
				"alert_id":     alertID,
				"silenced_by":  silencedBy,
				"silenced_at":  time.Now().Unix(),
				"silenced_until": time.Now().Add(24 * time.Hour).Unix(),
				"message":     "Alert has been silenced for 24 hours",
			})
			return
		}

		// 数据库不可用
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error":   "database_unavailable",
			"message": "Database is not available",
		})
	}
}

// generateTaskID 生成任务 ID
func generateTaskID() string {
	return time.Now().Format("20060102150405") + "-" + randomString(8)
}

// randomString 生成随机字符串
func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[time.Now().UnixNano()%int64(len(letters))]
	}
	return string(b)
}

type AgentServer struct {
	nodeMgr       *node.Manager
	monitorMgr    *monitor.Monitor
	db            *db.MongoDB
	configVersion int64
	configs       map[string]*pb.CDNConfig
	configSubs    map[string][]chan *pb.ConfigWatchResponse
	subsMu        sync.RWMutex
	agentClients  map[string]pb.AgentServiceClient
	clientsMu     sync.RWMutex
	tasks         map[string]*db.Task
	tasksMu       sync.RWMutex
}

func NewAgentServer(nodeMgr *node.Manager, monitorMgr *monitor.Monitor) *AgentServer {
	return &AgentServer{
		nodeMgr:       nodeMgr,
		monitorMgr:    monitorMgr,
		configVersion: 1,
		configs:       make(map[string]*pb.CDNConfig),
		configSubs:    make(map[string][]chan *pb.ConfigWatchResponse),
		agentClients:  make(map[string]pb.AgentServiceClient),
		tasks:         make(map[string]*db.Task),
	}
}

// SetDatabase 设置数据库实例
func (s *AgentServer) SetDatabase(database *db.MongoDB) {
	s.db = database
}

// RegisterAgentClient 注册 Agent 客户端
func (s *AgentServer) RegisterAgentClient(nodeID string, client pb.AgentServiceClient) {
	s.clientsMu.Lock()
	defer s.clientsMu.Unlock()
	s.agentClients[nodeID] = client
	log.Printf("[AgentServer] Registered client for node: %s", nodeID)
}

// UnregisterAgentClient 注销 Agent 客户端
func (s *AgentServer) UnregisterAgentClient(nodeID string) {
	s.clientsMu.Lock()
	defer s.clientsMu.Unlock()
	delete(s.agentClients, nodeID)
	log.Printf("[AgentServer] Unregistered client for node: %s", nodeID)
}

func (s *AgentServer) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	// 创建节点
	newNode := &node.Node{
		ID:       req.NodeId,
		Name:     req.NodeName,
		Type:     req.NodeType,
		Addr:     req.Ip,
		Port:     0, // 需要从注册请求获取
		Region:   req.Region,
		Status:   "online",
		Tags:     []string{},
		Metadata: req.Metadata,
		Version:  "",
		Online:   true,
	}

	// 检查节点是否已存在
	existing := s.nodeMgr.GetNode(req.NodeId)
	if existing != nil {
		// 更新现有节点
		s.nodeMgr.UpdateNode(req.NodeId, func(n *node.Node) {
			n.Status = "online"
			n.Online = true
			n.Addr = req.Ip
			n.Region = req.Region
			n.Metadata = req.Metadata
		})
	} else {
		// 添加新节点
		s.nodeMgr.AddNode(newNode)
	}

	return &pb.RegisterResponse{
		Success:       true,
		MasterVersion: "dev",
		Message:       "registered successfully",
	}, nil
}

func (s *AgentServer) ExecuteCommand(req *pb.CommandRequest, stream pb.AgentService_ExecuteCommandServer) error {
	// TODO: 实现命令执行流
	return nil
}

func (s *AgentServer) Heartbeat(ctx context.Context, req *pb.HeartbeatRequest) (*pb.HeartbeatResponse, error) {
	if req.NodeId == "" {
		return &pb.HeartbeatResponse{
			Success: false,
			Message: "node_id is required",
		}, nil
	}

	// 更新节点心跳
	success := s.nodeMgr.Heartbeat(req.NodeId)

	return &pb.HeartbeatResponse{
		Success: success,
		Message: "heartbeat received",
	}, nil
}

func (s *AgentServer) GetStatus(ctx context.Context, req *pb.StatusRequest) (*pb.StatusResponse, error) {
	n := s.nodeMgr.GetNode(req.NodeId)
	if n == nil {
		return &pb.StatusResponse{
			Success: false,
			Status:  "unknown",
			Message: "node not found",
		}, nil
	}

	return &pb.StatusResponse{
		Success: true,
		Status:  n.Status,
	}, nil
}

func (s *AgentServer) PushConfig(ctx context.Context, req *pb.PushConfigRequest) (*pb.PushConfigResponse, error) {
	// TODO: 实现配置推送
	return &pb.PushConfigResponse{
		Success: true,
		Message: "config received",
	}, nil
}

func (s *AgentServer) ReportStatus(ctx context.Context, req *pb.StatusRequest) (*pb.StatusResponse, error) {
	if req.NodeId == "" {
		return &pb.StatusResponse{
			Success: false,
			Message: "node_id is required",
		}, nil
	}

	// 更新节点状态
	s.nodeMgr.UpdateNode(req.NodeId, func(n *node.Node) {
		// StatusData 包含监控数据
		if req.Status != nil {
			// 可以在这里更新监控数据
			_ = req.Status
		}
	})

	// 获取更新后的节点状态
	n := s.nodeMgr.GetNode(req.NodeId)
	if n == nil {
		return &pb.StatusResponse{
			Success: false,
			Message: "node not found after update",
		}, nil
	}

	return &pb.StatusResponse{
		Success: true,
		Status:  n.Status,
	}, nil
}

func (s *AgentServer) WatchConfig(req *pb.ConfigWatchRequest, stream pb.AgentService_WatchConfigServer) error {
	nodeID := req.NodeId

	if nodeID == "" {
		return errors.New("node_id is required")
	}

	log.Printf("[Config] Node %s watching for config updates (last version: %d)", nodeID, req.LastVersion)

	ctx, _ := stream.Context().(context.Context)
	configChan := make(chan *pb.ConfigWatchResponse, 10)

	s.subsMu.Lock()
	s.configSubs[nodeID] = append(s.configSubs[nodeID], configChan)
	s.subsMu.Unlock()

	defer func() {
		s.subsMu.Lock()
		for i, ch := range s.configSubs[nodeID] {
			if ch == configChan {
				s.configSubs[nodeID] = append(s.configSubs[nodeID][:i], s.configSubs[nodeID][i+1:]...)
				break
			}
		}
		s.subsMu.Unlock()
		close(configChan)
	}()

	if req.LastVersion < s.configVersion {
		configData, err := json.Marshal(s.configs[nodeID])
		if err == nil {
			resp := &pb.ConfigWatchResponse{
				Version:     s.configVersion,
				ConfigType:  "cdn",
				ConfigData:  configData,
				Checksum:    "",
				Timestamp:   time.Now().Unix(),
				ForceReload: true,
				Message:     "Initial config",
			}
			if err := stream.Send(resp); err != nil {
				return err
			}
		}
	}

	for {
		select {
		case <-ctx.Done():
			log.Printf("[Config] Node %s stopped watching", nodeID)
			return ctx.Err()
		case resp := <-configChan:
			if err := stream.Send(resp); err != nil {
				log.Printf("[Config] Failed to send config to node %s: %v", nodeID, err)
				return err
			}
		}
	}
}

func (s *AgentServer) BroadcastConfig(configType string, configData []byte) {
	s.configVersion++
	resp := &pb.ConfigWatchResponse{
		Version:     s.configVersion,
		ConfigType:  configType,
		ConfigData:  configData,
		Checksum:    "",
		Timestamp:   time.Now().Unix(),
		ForceReload: true,
		Message:     "Config updated",
	}

	s.subsMu.RLock()
	defer s.subsMu.RUnlock()

	for nodeID, chans := range s.configSubs {
		for _, ch := range chans {
			select {
			case ch <- resp:
			default:
				log.Printf("[Config] Failed to send config to node %s: channel full", nodeID)
			}
		}
	}

	log.Printf("[Config] Broadcasted config version %d to %d nodes", s.configVersion, len(s.configSubs))
}
