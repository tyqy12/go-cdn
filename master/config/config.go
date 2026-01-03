package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config Master 配置结构
type Config struct {
	// MongoDB 配置
	MongoURI string `json:"mongo_uri" yaml:"mongo_uri"`
	MongoDB  string `json:"mongo_db" yaml:"mongo_db"`

	// JWT 配置
	JWTSecret string `json:"jwt_secret" yaml:"jwt_secret"`
	JWTExpiry int    `json:"jwt_expiry" yaml:"jwt_expiry"` // 小时

	// 服务器配置
	HTTPPort    int `json:"http_port" yaml:"http_port"`
	GRPCPort    int `json:"grpc_port" yaml:"grpc_port"`
	MetricsPort int `json:"metrics_port" yaml:"metrics_port"`

	// TLS 配置
	TLSEnabled  bool   `json:"tls_enabled" yaml:"tls_enabled"`
	TLSCertFile string `json:"tls_cert_file" yaml:"tls_cert_file"`
	TLSKeyFile  string `json:"tls_key_file" yaml:"tls_key_file"`

	// 日志配置
	LogLevel string `json:"log_level" yaml:"log_level"`
	LogFile  string `json:"log_file" yaml:"log_file"`

	// 功能开关
	Features *FeaturesConfig `json:"features" yaml:"features"`
}

// FeaturesConfig 功能配置
type FeaturesConfig struct {
	EnableAuth       bool `json:"enable_auth" yaml:"enable_auth"`
	EnableRateLimit  bool `json:"enable_rate_limit" yaml:"enable_rate_limit"`
	EnableMonitoring bool `json:"enable_monitoring" yaml:"enable_monitoring"`
	EnableAutoScale  bool `json:"enable_auto_scale" yaml:"enable_auto_scale"`
	EnableFailover   bool `json:"enable_failover" yaml:"enable_failover"`
}

// Load 加载配置文件
func Load(path string) (*Config, error) {
	// 如果路径为空，使用默认路径
	if path == "" {
		path = getDefaultConfigPath()
	}

	// 检查文件是否存在
	if _, err := os.Stat(path); os.IsNotExist(err) {
		// 尝试查找配置文件
		altPath := findConfigFile(path)
		if altPath == "" {
			// 返回默认配置
			return getDefaultConfig(), nil
		}
		path = altPath
	}

	// 读取配置文件
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// 确定配置文件格式
	cfg := &Config{}
	switch getFileExtension(path) {
	case ".json":
		if err := json.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("failed to parse JSON config: %w", err)
		}
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("failed to parse YAML config: %w", err)
		}
	default:
		// 尝试 JSON，然后 YAML
		if err := json.Unmarshal(data, cfg); err != nil {
			if err := yaml.Unmarshal(data, cfg); err != nil {
				return nil, fmt.Errorf("failed to parse config file: %w", err)
			}
		}
	}

	// 应用环境变量覆盖
	applyEnvOverrides(cfg)

	// 验证配置
	if err := validateConfig(cfg); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return cfg, nil
}

// getDefaultConfigPath 获取默认配置文件路径
func getDefaultConfigPath() string {
	// 检查常见位置
	paths := []string{
		"config.yaml",
		"config.yml",
		"config.json",
		"master.yaml",
		"master.yml",
		"/etc/ai-cdn/master.yaml",
		"/etc/ai-cdn/master.yml",
	}

	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	return "config.yaml"
}

// findConfigFile 查找配置文件
func findConfigFile(path string) string {
	// 检查相对路径
	if _, err := os.Stat(path); err == nil {
		return path
	}

	// 检查带扩展名的变体
	extensions := []string{".yaml", ".yml", ".json"}
	base := strings.TrimSuffix(path, filepath.Ext(path))

	for _, ext := range extensions {
		if _, err := os.Stat(base + ext); err == nil {
			return base + ext
		}
	}

	return ""
}

// getFileExtension 获取文件扩展名
func getFileExtension(path string) string {
	ext := filepath.Ext(path)
	return strings.ToLower(ext)
}

// getDefaultConfig 获取默认配置
func getDefaultConfig() *Config {
	return &Config{
		MongoURI:    "mongodb://localhost:27017/ai-cdn",
		MongoDB:     "ai-cdn",
		JWTSecret:   "",
		JWTExpiry:   24,
		HTTPPort:    8080,
		GRPCPort:    50051,
		MetricsPort: 9090,
		TLSEnabled:  false,
		LogLevel:    "info",
		LogFile:     "",
		Features: &FeaturesConfig{
			EnableAuth:       true,
			EnableRateLimit:  true,
			EnableMonitoring: true,
			EnableAutoScale:  false,
			EnableFailover:   false,
		},
	}
}

// applyEnvOverrides 应用环境变量覆盖
func applyEnvOverrides(cfg *Config) {
	// MongoDB
	if v := os.Getenv("MONGODB_URI"); v != "" {
		cfg.MongoURI = v
	}
	if v := os.Getenv("MONGODB_DATABASE"); v != "" {
		cfg.MongoDB = v
	}

	// JWT
	if v := os.Getenv("JWT_SECRET"); v != "" {
		cfg.JWTSecret = v
	}
	if v := os.Getenv("JWT_EXPIRY"); v != "" {
		var expiry int
		if _, err := fmt.Sscanf(v, "%d", &expiry); err == nil {
			cfg.JWTExpiry = expiry
		}
	}

	// 服务器端口
	if v := os.Getenv("HTTP_PORT"); v != "" {
		var port int
		if _, err := fmt.Sscanf(v, "%d", &port); err == nil {
			cfg.HTTPPort = port
		}
	}
	if v := os.Getenv("GRPC_PORT"); v != "" {
		var port int
		if _, err := fmt.Sscanf(v, "%d", &port); err == nil {
			cfg.GRPCPort = port
		}
	}

	// TLS
	if v := os.Getenv("TLS_ENABLED"); v == "true" || v == "1" {
		cfg.TLSEnabled = true
	}
	if v := os.Getenv("TLS_CERT_FILE"); v != "" {
		cfg.TLSCertFile = v
	}
	if v := os.Getenv("TLS_KEY_FILE"); v != "" {
		cfg.TLSKeyFile = v
	}

	// 日志
	if v := os.Getenv("LOG_LEVEL"); v != "" {
		cfg.LogLevel = v
	}
}

// validateConfig 验证配置
func validateConfig(cfg *Config) error {
	// 验证 MongoDB URI
	if cfg.MongoURI == "" {
		return fmt.Errorf("MongoDB URI is required")
	}

	// 验证端口
	if cfg.HTTPPort < 1 || cfg.HTTPPort > 65535 {
		return fmt.Errorf("invalid HTTP port: %d", cfg.HTTPPort)
	}
	if cfg.GRPCPort < 1 || cfg.GRPCPort > 65535 {
		return fmt.Errorf("invalid gRPC port: %d", cfg.GRPCPort)
	}

	// 验证 JWT 配置
	if cfg.JWTSecret == "" && cfg.Features.EnableAuth {
		return fmt.Errorf("JWT secret is required when authentication is enabled")
	}

	// 验证 TLS 配置
	if cfg.TLSEnabled {
		if cfg.TLSCertFile == "" {
			return fmt.Errorf("TLS certificate file is required when TLS is enabled")
		}
		if cfg.TLSKeyFile == "" {
			return fmt.Errorf("TLS key file is required when TLS is enabled")
		}
	}

	return nil
}

// Save 保存配置到文件
func Save(cfg *Config, path string) error {
	// 如果路径为空，使用默认路径
	if path == "" {
		path = "config.yaml"
	}

	// 确定格式
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// 创建目录（如果不存在）
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create config directory: %w", err)
		}
	}

	// 写入文件
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// LoadWithDefaults 带默认值的配置加载
func LoadWithDefaults(path string, defaults *Config) (*Config, error) {
	cfg, err := Load(path)
	if err != nil {
		return nil, err
	}

	// 应用默认值
	if defaults != nil {
		if cfg.MongoURI == "" {
			cfg.MongoURI = defaults.MongoURI
		}
		if cfg.MongoDB == "" {
			cfg.MongoDB = defaults.MongoDB
		}
		if cfg.JWTSecret == "" {
			cfg.JWTSecret = defaults.JWTSecret
		}
		if cfg.JWTExpiry == 0 {
			cfg.JWTExpiry = defaults.JWTExpiry
		}
		if cfg.HTTPPort == 0 {
			cfg.HTTPPort = defaults.HTTPPort
		}
		if cfg.GRPCPort == 0 {
			cfg.GRPCPort = defaults.GRPCPort
		}
		if cfg.MetricsPort == 0 {
			cfg.MetricsPort = defaults.MetricsPort
		}
		if cfg.LogLevel == "" {
			cfg.LogLevel = defaults.LogLevel
		}
		if cfg.Features == nil {
			cfg.Features = defaults.Features
		}
	}

	return cfg, nil
}
