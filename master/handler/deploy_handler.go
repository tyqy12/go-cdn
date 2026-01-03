package handler

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/ai-cdn-tunnel/master/scripts"
	"github.com/ai-cdn-tunnel/master/templates"
)

// DeployScriptData 部署脚本模板数据
type DeployScriptData struct {
	GeneratedAt       string
	NodeName          string
	NodeType          string
	Region            string
	MasterAddr        string
	MasterToken       string
	AgentVersion      string
	BinaryDownloadURL string
	InstallGost       bool
	InstallAgent      bool
	InstallNodeExporter bool
	EnableTLS         bool
	GostConfigTemplate string
	Tags              []string
}

// DeployRequest 部署脚本生成请求
type DeployRequest struct {
	NodeName   string        `json:"nodeName" binding:"required,min=3,max=64"`
	NodeType   string        `json:"nodeType" binding:"required,oneof=edge l2 core"`
	Region     string        `json:"region" binding:"required"`
	MasterAddr string        `json:"masterAddr" binding:"required"`
	Tags       []string      `json:"tags"`
	Options    DeployOptions `json:"options"`
}

// DeployOptions 部署选项
type DeployOptions struct {
	InstallGost        bool `json:"installGost"`
	InstallAgent       bool `json:"installAgent"`
	InstallNodeExporter bool `json:"installNodeExporter"`
	EnableTLS          bool `json:"enableTLS"`
}

// QuickInstallRequest 快速安装请求
type QuickInstallRequest struct {
	MasterAddr string `json:"masterAddr" binding:"required"`
	NodeType   string `json:"nodeType" binding:"required,oneof=edge l2 core"`
	Region     string `json:"region" binding:"required"`
}

// ScriptResponse 脚本生成响应
type ScriptResponse struct {
	Success    bool      `json:"success"`
	ScriptID   string    `json:"scriptId"`
	ScriptURL  string    `json:"scriptUrl"`
	ExpiresAt  time.Time `json:"expiresAt"`
}

// QuickInstallResponse 快速安装响应
type QuickInstallResponse struct {
	Success  bool   `json:"success"`
	Command  string `json:"command"`
	MasterAddr string `json:"masterAddr"`
}

// ScriptInfo 脚本信息
type ScriptInfo struct {
	ID        string
	Content   string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// ScriptStore 脚本存储
type ScriptStore struct {
	sync.RWMutex
	scripts map[string]*ScriptInfo
}

// NewScriptStore 创建脚本存储
func NewScriptStore() *ScriptStore {
	return &ScriptStore{
		scripts: make(map[string]*ScriptInfo),
	}
}

// Store 存储脚本
func (s *ScriptStore) Store(id string, content string, ttl time.Duration) {
	s.Lock()
	defer s.Unlock()
	s.scripts[id] = &ScriptInfo{
		ID:        id,
		Content:   content,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(ttl),
	}
}

// Get 获取脚本
func (s *ScriptStore) Get(id string) (*ScriptInfo, error) {
	s.RLock()
	defer s.RUnlock()
	info, ok := s.scripts[id]
	if !ok {
		return nil, fmt.Errorf("script not found")
	}
	if time.Now().After(info.ExpiresAt) {
		return nil, fmt.Errorf("script expired")
	}
	return info, nil
}

// Cleanup 清理过期脚本
func (s *ScriptStore) Cleanup() {
	s.Lock()
	defer s.Unlock()
	now := time.Now()
	for id, info := range s.scripts {
		if now.After(info.ExpiresAt) {
			delete(s.scripts, id)
		}
	}
}

var globalScriptStore = NewScriptStore()

// GenerateDeployScript 生成部署脚本
func GenerateDeployScript(c *gin.Context) {
	var req DeployRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 生成token
	token := generateToken()

	// 填充模板数据
	data := &DeployScriptData{
		GeneratedAt:        time.Now().Format(time.RFC3339),
		NodeName:           req.NodeName,
		NodeType:           req.NodeType,
		Region:             req.Region,
		MasterAddr:         req.MasterAddr,
		MasterToken:        token,
		AgentVersion:       "v1.0.0",
		BinaryDownloadURL:  "https://releases.ai-cdn.com",
		InstallGost:        req.Options.InstallGost,
		InstallAgent:       req.Options.InstallAgent,
		InstallNodeExporter: req.Options.InstallNodeExporter,
		EnableTLS:          req.Options.EnableTLS,
		GostConfigTemplate: GetGostConfigTemplate(req.NodeType, req.Region),
		Tags:               req.Tags,
	}

	// 生成脚本
	script, err := RenderDeployScript(data)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to render script: %v", err)})
		return
	}

	// 生成脚本ID
	scriptID := generateScriptID(req.NodeName)

	// 存储脚本，24小时过期
	globalScriptStore.Store(scriptID, script, 24*time.Hour)

	c.JSON(http.StatusOK, ScriptResponse{
		Success:    true,
		ScriptID:   scriptID,
		ScriptURL:  fmt.Sprintf("/api/v1/nodes/deploy-script/%s/download", scriptID),
		ExpiresAt:  time.Now().Add(24 * time.Hour),
	})
}

// GetDeployScript 获取脚本内容
func GetDeployScript(c *gin.Context) {
	scriptID := c.Param("scriptID")

	info, err := globalScriptStore.Get(scriptID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.Header("Content-Type", "text/plain")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=deploy-%s.sh", scriptID))
	c.String(http.StatusOK, info.Content)
}

// DownloadScript 下载脚本文件
func DownloadScript(c *gin.Context) {
	scriptID := c.Param("scriptID")

	info, err := globalScriptStore.Get(scriptID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.Header("Content-Type", "application/octet-stream")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=deploy-%s.sh", scriptID))
	c.Header("Content-Length", fmt.Sprintf("%d", len(info.Content)))
	c.String(http.StatusOK, info.Content)
}

// QuickInstall 快速安装命令
func QuickInstall(c *gin.Context) {
	var req QuickInstallRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	command := fmt.Sprintf(
		"curl -fsSL https://install.ai-cdn.com/agent.sh | bash -s -- --master %s --type %s --region %s",
		req.MasterAddr,
		req.NodeType,
		req.Region,
	)

	c.JSON(http.StatusOK, QuickInstallResponse{
		Success:    true,
		Command:    command,
		MasterAddr: req.MasterAddr,
	})
}

// RenderDeployScript 渲染部署脚本
func RenderDeployScript(data *DeployScriptData) (string, error) {
	// 构建模板数据
	templateData := map[string]interface{}{
		"GeneratedAt":        data.GeneratedAt,
		"NodeName":           data.NodeName,
		"NodeType":           data.NodeType,
		"Region":             data.Region,
		"MasterAddr":         data.MasterAddr,
		"MasterToken":        data.MasterToken,
		"AgentVersion":       data.AgentVersion,
		"BinaryDownloadURL":  data.BinaryDownloadURL,
		"InstallGost":        data.InstallGost,
		"InstallAgent":       data.InstallAgent,
		"InstallNodeExporter": data.InstallNodeExporter,
		"EnableTLS":          data.EnableTLS,
		"GostConfigTemplate": data.GostConfigTemplate,
		"Tags":               data.Tags,
	}

	return scripts.GetDeployScriptContent(templateData)
}

// GetGostConfigTemplate 获取gost配置模板
func GetGostConfigTemplate(nodeType, region string) string {
	key := nodeType + "-" + region
	configs := templates.GetAllGostConfigs()
	if config, ok := configs[key]; ok {
		return config
	}
	// 返回默认配置
	return configs["edge-hk"]
}

func generateToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func generateScriptID(nodeName string) string {
	hash := sha256.Sum256([]byte(nodeName + time.Now().Format(time.RFC3339Nano)))
	return "script_" + hex.EncodeToString(hash[:8])
}
