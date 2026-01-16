package cache

import (
	"context"
	"fmt"
	"log"
	"regexp"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// AdvancedCache 高级缓存管理器
type AdvancedCache struct {
	config      *CacheConfig
	stores      map[string]*CacheStore
	rules       []*CacheRule
	ruleMatcher *RuleMatcher
	purger      *CachePurger
	prefetcher  *CachePrefetcher
	stats       *CacheStats
	redisClient *redis.Client
	mu          sync.RWMutex
	ctx         context.Context
	cancel      context.CancelFunc
}

// CacheConfig 缓存配置
type CacheConfig struct {
	// 启用状态
	Enabled bool `yaml:"enabled"`

	// 缓存引擎
	Engine string `yaml:"engine"` // "memory", "redis", "file"

	// 全局配置
	Global *GlobalCacheConfig `yaml:"global"`

	// 规则配置
	Rules []CacheRuleConfig `yaml:"rules"`

	// 预热配置
	Prefetch *PrefetchConfig `yaml:"prefetch"`

	// 压缩配置
	Compression *CompressionConfig `yaml:"compression"`

	// 分层配置
	TieredConfig *TieredCacheConfig `yaml:"tiered"`

	// 存储配置
	Storage *StorageConfig `yaml:"storage"`
}

// GlobalCacheConfig 全局缓存配置
type GlobalCacheConfig struct {
	// 默认TTL
	DefaultTTL time.Duration `yaml:"default_ttl"`

	// 最大TTL
	MaxTTL time.Duration `yaml:"max_ttl"`

	// 最小TTL
	MinTTL time.Duration `yaml:"min_ttl"`

	// 最大缓存大小 (GB)
	MaxSize int64 `yaml:"max_size"`

	// 最大条目数
	MaxEntries int64 `yaml:"max_entries"`

	// 清理间隔
	CleanupInterval time.Duration `yaml:"cleanup_interval"`

	// 清理百分比
	CleanupPercent float64 `yaml:"cleanup_percent"`

	// 压缩最小大小
	CompressionMinSize int `yaml:"compression_min_size"`

	// 压缩级别
	CompressionLevel int `yaml:"compression_level"`
}

// CacheRuleConfig 缓存规则配置
type CacheRuleConfig struct {
	// 规则名称
	Name string `yaml:"name"`

	// 规则类型
	RuleType string `yaml:"rule_type"` // "extension", "path", "full_path", "regex", "header", "query"

	// 匹配模式
	Pattern string `yaml:"pattern"`

	// 是否缓存
	Cache bool `yaml:"cache"`

	// TTL
	TTL time.Duration `yaml:"ttl"`

	// 优先级
	Priority int `yaml:"priority"`

	// 缓存键
	CacheKey *CacheKeyConfig `yaml:"cache_key"`

	// 条件
	Conditions []CacheConditionConfig `yaml:"conditions"`

	// 排除条件
	Exclusions []CacheExclusionConfig `yaml:"exclusions"`

	// 状态码过滤
	StatusCodes []int `yaml:"status_codes"`

	// 方法过滤
	Methods []string `yaml:"methods"`

	// 启用状态
	Enabled bool `yaml:"enabled"`
}

// CacheKeyConfig 缓存键配置
type CacheKeyConfig struct {
	// 包含的查询参数
	IncludeQueryParams []string `yaml:"include_query_params"`

	// 排除的查询参数
	ExcludeQueryParams []string `yaml:"exclude_query_params"`

	// 包含的请求头
	IncludeHeaders []string `yaml:"include_headers"`

	// 自定义变量
	CustomVars map[string]string `yaml:"custom_vars"`

	// 忽略大小写
	IgnoreCase bool `yaml:"ignore_case"`
}

// CacheConditionConfig 缓存条件配置
type CacheConditionConfig struct {
	// 条件类型
	Type string `yaml:"type"` // "header", "cookie", "query", "method"

	// 匹配键
	Key string `yaml:"key"`

	// 操作符
	Operator string `yaml:"operator"` // "eq", "ne", "contains", "exists", "not_exists"

	// 值
	Value string `yaml:"value"`
}

// CacheExclusionConfig 缓存排除配置
type CacheExclusionConfig struct {
	// 排除类型
	Type string `yaml:"type"` // "extension", "path", "query", "cookie"

	// 匹配模式
	Pattern string `yaml:"pattern"`
}

// CacheRule 缓存规则
type CacheRule struct {
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	RuleType     string                 `json:"rule_type"`
	Pattern      string                 `json:"pattern"`
	PatternRegex *regexp.Regexp         `json:"-"`
	Cache        bool                   `json:"cache"`
	TTL          time.Duration          `json:"ttl"`
	Priority     int                    `json:"priority"`
	CacheKey     *CacheKeyConfig        `json:"cache_key"`
	Conditions   []CacheConditionConfig `json:"conditions"`
	Exclusions   []CacheExclusionConfig `json:"exclusions"`
	StatusCodes  []int                  `json:"status_codes"`
	Methods      []string               `json:"methods"`
	Enabled      bool                   `json:"enabled"`
	CreatedAt    time.Time              `json:"created_at"`
	UpdatedAt    time.Time              `json:"updated_at"`
}

// CacheStore 缓存存储
type CacheStore struct {
	ID        string                `json:"id"`
	Name      string                `json:"name"`
	Type      string                `json:"type"` // "memory", "redis", "file"
	Items     int64                 `json:"items"`
	ItemsMap  map[string]*CacheItem `json:"-"`
	ItemsList []string              `json:"-"`
	Size      int64                 `json:"size"`
	Hits      int64                 `json:"hits"`
	Misses    int64                 `json:"misses"`
	Evictions int64                 `json:"evictions"`
	mu        sync.RWMutex
}

// CacheItem 缓存项
type CacheItem struct {
	Key        string            `json:"key"`
	Value      []byte            `json:"value"`
	Headers    map[string]string `json:"headers"`
	StatusCode int               `json:"status_code"`
	TTL        time.Duration     `json:"ttl"`
	CreatedAt  time.Time         `json:"created_at"`
	ExpiresAt  time.Time         `json:"expires_at"`
	Size       int               `json:"size"`
	Hits       int64             `json:"hits"`
	LastHitAt  time.Time         `json:"last_hit_at"`
	// LRU 链表指针
	prev *CacheItem
	next *CacheItem
}

// LRUNode LRU 链表节点包装
type LRUNode struct {
	key   string
	item  *CacheItem
}

// LRUCache LRU 缓存实现
type LRUCache struct {
	capacity   int64
	size       int64
	items      map[string]*CacheItem
	head       *CacheItem  // 头部是最近使用的
	tail       *CacheItem  // 尾部是最久未使用的
	mu         sync.Mutex
}

// CacheStats 缓存统计
type CacheStats struct {
	TotalRequests    int64            `json:"total_requests"`
	CacheHits        int64            `json:"cache_hits"`
	CacheMisses      int64            `json:"cache_misses"`
	CacheHitRate     float64          `json:"cache_hit_rate"`
	TotalSize        int64            `json:"total_size"`
	TotalItems       int64            `json:"total_items"`
	Evictions        int64            `json:"evictions"`
	ExpiredItems     int64            `json:"expired_items"`
	BandwidthSaved   int64            `json:"bandwidth_saved"`
	ByContentType    map[string]int64 `json:"by_content_type"`
	TopRequestedURLs []URLStats       `json:"top_requested_urls"`
	mu               sync.RWMutex
}

// URLStats URL统计
type URLStats struct {
	URL       string `json:"url"`
	Hits      int64  `json:"hits"`
	Bandwidth int64  `json:"bandwidth"`
}

// PrefetchConfig 预热配置
type PrefetchConfig struct {
	// 启用预热
	Enabled bool `yaml:"enabled"`

	// 预热策略
	Strategy string `yaml:"strategy"` // "manual", "scheduled", "predictive"

	// 预热间隔
	Interval time.Duration `yaml:"interval"`

	// 最大并行预热数
	MaxConcurrency int `yaml:"max_concurrency"`

	// 预热深度
	Depth int `yaml:"depth"`

	// 预热URL列表
	URLs []string `yaml:"urls"`

	// 调度时间
	Schedule []string `yaml:"schedule"`
}

// CachePrefetcher 缓存预热器
type CachePrefetcher struct {
	config  *PrefetchConfig
	queue   []string
	mu      sync.RWMutex
	running bool
}

// CompressionConfig 压缩配置
type CompressionConfig struct {
	// 启用压缩
	Enabled bool `yaml:"enabled"`

	// 压缩算法
	Algorithm string `yaml:"algorithm"` // "gzip", "brotli", "zstd"

	// 最小压缩大小
	MinSize int `yaml:"min_size"`

	// 压缩级别
	Level int `yaml:"level"`

	// 内容类型
	ContentTypes []string `json:"content_types"`
}

// TieredCacheConfig 分层缓存配置
type TieredCacheConfig struct {
	// 启用分层缓存
	Enabled bool `yaml:"enabled"`

	// L1配置 (内存)
	L1 *TierConfig `yaml:"l1"`

	// L2配置 (SSD/文件)
	L2 *TierConfig `yaml:"l2"`

	// L3配置 (远程)
	L3 *TierConfig `yaml:"l3"`
}

// TierConfig 分层配置
type TierConfig struct {
	// 类型
	Type string `yaml:"type"` // "memory", "file", "redis"

	// 大小
	Size int64 `yaml:"size"`

	// TTL
	TTL time.Duration `yaml:"ttl"`
}

// StorageConfig 存储配置
type StorageConfig struct {
	// 存储类型
	Type string `yaml:"type"` // "local", "s3", "oss"

	// 存储路径
	Path string `yaml:"path"`

	// 存储后端配置
	Backend *BackendConfig `yaml:"backend"`
}

// BackendConfig 后端配置
type BackendConfig struct {
	// 类型
	Type string `yaml:"type"` // "local", "s3", "azure", "gcs"

	// 端点
	Endpoint string `yaml:"endpoint"`

	// 访问密钥
	AccessKey string `yaml:"access_key"`

	// 密钥
	SecretKey string `yaml:"secret_key"`

	// 桶名
	Bucket string `yaml:"bucket"`

	// 区域
	Region string `yaml:"region"`
}

// CachePurger 缓存清除器
type CachePurger struct {
	config  *CacheConfig
	mu      sync.RWMutex
	pending []PurgeRequest
}

// PurgeRequest 清除请求
type PurgeRequest struct {
	Pattern  string   `json:"pattern"`
	Type     string   `json:"type"` // "url", "regex", "tag"
	Tags     []string `json:"tags"`
	PurgeAll bool     `json:"purge_all"`
}

// RuleMatcher 规则匹配器
type RuleMatcher struct {
	mu         sync.RWMutex
	rules      []*CacheRule
	exclusions []CacheExclusionConfig
}

// CacheRequest 缓存请求
type CacheRequest struct {
	URL         string            `json:"url"`
	Method      string            `json:"method"`
	Headers     map[string]string `json:"headers"`
	QueryParams map[string]string `json:"query_params"`
	Cookies     map[string]string `json:"cookies"`
	ClientIP    string            `json:"client_ip"`
	Timestamp   time.Time         `json:"timestamp"`
}

// CacheResponse 缓存响应
type CacheResponse struct {
	// 是否命中缓存
	Hit bool `json:"hit"`

	// 缓存键
	CacheKey string `json:"cache_key"`

	// 缓存项
	Item *CacheItem `json:"item,omitempty"`

	// TTL剩余时间
	TTLRemaining time.Duration `json:"ttl_remaining"`

	// 处理时间
	ProcessingTime time.Duration `json:"processing_time"`
}

// NewAdvancedCache 创建高级缓存
func NewAdvancedCache(config *CacheConfig) *AdvancedCache {
	if config == nil {
		config = &CacheConfig{
			Enabled: true,
			Global: &GlobalCacheConfig{
				DefaultTTL:      3600 * time.Second,
				MaxTTL:          86400 * time.Second,
				MaxSize:         10 * 1024 * 1024 * 1024,
				MaxEntries:      1000000,
				CleanupInterval: 300 * time.Second,
			},
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	cache := &AdvancedCache{
		config:      config,
		stores:      make(map[string]*CacheStore),
		rules:       make([]*CacheRule, 0),
		ruleMatcher: &RuleMatcher{},
		purger:      &CachePurger{config: config, pending: make([]PurgeRequest, 0)},
		prefetcher:  &CachePrefetcher{},
		stats:       &CacheStats{ByContentType: make(map[string]int64)},
		ctx:         ctx,
		cancel:      cancel,
	}

	// 初始化存储
	cache.initStores()

	// 加载规则
	cache.loadRules()

	// 启动后台任务
	go cache.runBackgroundTasks()

	return cache
}

// initStores 初始化存储
func (c *AdvancedCache) initStores() {
	c.mu.Lock()
	defer c.mu.Unlock()

	// 默认内存存储
	c.stores["memory"] = &CacheStore{
		ID:        "memory",
		Name:      "内存缓存",
		Type:      "memory",
		ItemsMap:  make(map[string]*CacheItem),
		ItemsList: make([]string, 0),
	}

	// 如果配置了Redis后端
	if c.config.Storage != nil && c.config.Storage.Backend != nil {
		backend := c.config.Storage.Backend

		// 创建Redis客户端
		redisConfig := &redis.Options{
			Addr:     backend.Endpoint,
			Password: backend.SecretKey,
			DB:       0,
		}

		// 如果有自定义配置
		if c.config.Global != nil {
			// 可以根据配置调整Redis参数
		}

		client := redis.NewClient(redisConfig)

		// 测试连接
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := client.Ping(ctx).Err(); err != nil {
			// Redis连接失败，使用内存存储
			log.Printf("WARN: Redis connection failed, falling back to memory storage: %v", err)
			client.Close()
			return
		}

		c.redisClient = client

		// 添加Redis存储
		c.stores["redis"] = &CacheStore{
			ID:   "redis",
			Name: "Redis缓存",
			Type: "redis",
		}

		log.Println("INFO: Redis cache storage initialized successfully")
	}
}

// GetRedisClient 获取Redis客户端
func (c *AdvancedCache) GetRedisClient() *redis.Client {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.redisClient
}

// SetToRedis 设置缓存到Redis
func (c *AdvancedCache) SetToRedis(key string, value []byte, ttl time.Duration) error {
	c.mu.RLock()
	client := c.redisClient
	c.mu.RUnlock()

	if client == nil {
		return fmt.Errorf("Redis客户端未初始化")
	}

	ctx := context.Background()
	return client.Set(ctx, key, value, ttl).Err()
}

// GetFromRedis 从Redis获取缓存
func (c *AdvancedCache) GetFromRedis(key string) ([]byte, error) {
	c.mu.RLock()
	client := c.redisClient
	c.mu.RUnlock()

	if client == nil {
		return nil, fmt.Errorf("Redis客户端未初始化")
	}

	ctx := context.Background()
	data, err := client.Get(ctx, key).Bytes()
	if err == redis.Nil {
		return nil, nil
	}
	return data, err
}

// DeleteFromRedis 从Redis删除缓存
func (c *AdvancedCache) DeleteFromRedis(key string) error {
	c.mu.RLock()
	client := c.redisClient
	c.mu.RUnlock()

	if client == nil {
		return fmt.Errorf("Redis客户端未初始化")
	}

	ctx := context.Background()
	return client.Del(ctx, key).Err()
}

// CloseRedis 关闭Redis连接
func (c *AdvancedCache) CloseRedis() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.redisClient != nil {
		return c.redisClient.Close()
	}
	return nil
}

// loadRules 加载规则
func (c *AdvancedCache) loadRules() {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, ruleConfig := range c.config.Rules {
		rule := c.createRule(ruleConfig)
		if rule != nil {
			c.rules = append(c.rules, rule)
		}
	}
}

// createRule 创建规则
func (c *AdvancedCache) createRule(config CacheRuleConfig) *CacheRule {
	if !config.Enabled {
		return nil
	}

	rule := &CacheRule{
		ID:          fmt.Sprintf("rule_%d", len(c.rules)+1),
		Name:        config.Name,
		RuleType:    config.RuleType,
		Pattern:     config.Pattern,
		Cache:       config.Cache,
		TTL:         config.TTL,
		Priority:    config.Priority,
		CacheKey:    config.CacheKey,
		Conditions:  config.Conditions,
		Exclusions:  config.Exclusions,
		StatusCodes: config.StatusCodes,
		Methods:     config.Methods,
		Enabled:     true,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	// 编译正则
	if config.RuleType == "regex" && config.Pattern != "" {
		re, err := regexp.Compile(config.Pattern)
		if err == nil {
			rule.PatternRegex = re
		}
	}

	return rule
}

// Get 获取缓存
func (c *AdvancedCache) Get(req *CacheRequest) *CacheResponse {
	startTime := time.Now()

	c.mu.RLock()
	defer c.mu.RUnlock()

	// 1. 匹配规则
	rule := c.matchRule(req)
	if rule == nil || !rule.Cache {
		return &CacheResponse{
			Hit:            false,
			ProcessingTime: time.Since(startTime),
		}
	}

	// 2. 生成缓存键
	cacheKey := c.generateCacheKey(req, rule)

	// 3. 查找缓存
	store := c.stores["memory"]
	if store == nil {
		return &CacheResponse{
			Hit:            false,
			ProcessingTime: time.Since(startTime),
		}
	}

	// 实际从存储获取缓存数据
	store.mu.RLock()
	item, exists := store.ItemsMap[cacheKey]
	store.mu.RUnlock()

	if !exists {
		return &CacheResponse{
			Hit:            false,
			ProcessingTime: time.Since(startTime),
		}
	}

	// 检查是否过期
	if time.Now().After(item.ExpiresAt) {
		store.mu.Lock()
		delete(store.ItemsMap, cacheKey)
		store.Items--
		store.mu.Unlock()
		return &CacheResponse{
			Hit:            false,
			ProcessingTime: time.Since(startTime),
		}
	}

	// 更新统计
	c.updateStats(true, item)

	return &CacheResponse{
		Hit:            true,
		CacheKey:       cacheKey,
		Item:           item,
		TTLRemaining:   time.Until(item.ExpiresAt),
		ProcessingTime: time.Since(startTime),
	}
}

// Set 设置缓存
func (c *AdvancedCache) Set(req *CacheRequest, value []byte, headers map[string]string, statusCode int) string {
	c.mu.RLock()

	// 1. 匹配规则
	rule := c.matchRule(req)
	if rule == nil || !rule.Cache {
		c.mu.RUnlock()
		return ""
	}

	// 2. 生成缓存键
	cacheKey := c.generateCacheKey(req, rule)

	// 3. 创建缓存项
	item := &CacheItem{
		Key:        cacheKey,
		Value:      value,
		Headers:    headers,
		StatusCode: statusCode,
		TTL:        rule.TTL,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(rule.TTL),
		Size:       len(value),
	}

	// 4. 存储缓存
	store := c.stores["memory"]
	c.mu.RUnlock()

	if store != nil {
		store.mu.Lock()
		store.ItemsMap[cacheKey] = item
		store.ItemsList = append(store.ItemsList, cacheKey)
		store.Items++
		store.Size += int64(item.Size)
		store.mu.Unlock()
	}

	return cacheKey
}

// matchRule 匹配规则
func (c *AdvancedCache) matchRule(req *CacheRequest) *CacheRule {
	for _, rule := range c.rules {
		if !rule.Enabled || !rule.Cache {
			continue
		}

		// 检查排除条件
		if c.isExcluded(req, rule) {
			continue
		}

		// 检查方法
		if len(rule.Methods) > 0 {
			matched := false
			for _, method := range rule.Methods {
				if method == req.Method {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}

		// 匹配规则
		if c.matchPattern(rule, req) {
			return rule
		}
	}

	return nil
}

// isExcluded 检查是否排除
func (c *AdvancedCache) isExcluded(req *CacheRequest, rule *CacheRule) bool {
	for _, exclusion := range rule.Exclusions {
		switch exclusion.Type {
		case "extension":
			if c.matchExtension(exclusion.Pattern, req.URL) {
				return true
			}
		case "path":
			if c.matchPath(exclusion.Pattern, req.URL) {
				return true
			}
		}
	}
	return false
}

func (c *AdvancedCache) matchExtension(pattern, url string) bool {
	for i := len(url) - 1; i >= 0; i-- {
		if url[i] == '.' {
			return url[i+1:] == pattern
		}
		if url[i] == '/' {
			break
		}
	}
	return false
}

func (c *AdvancedCache) matchPath(pattern, url string) bool {
	return len(url) >= len(pattern) && url[:len(pattern)] == pattern
}

// matchPattern 匹配模式
func (c *AdvancedCache) matchPattern(rule *CacheRule, req *CacheRequest) bool {
	switch rule.RuleType {
	case "extension":
		return c.matchExtension(rule.Pattern, req.URL)
	case "path":
		return c.matchPath(rule.Pattern, req.URL)
	case "full_path":
		return req.URL == rule.Pattern
	case "regex":
		if rule.PatternRegex != nil {
			return rule.PatternRegex.MatchString(req.URL)
		}
	}
	return false
}

// generateCacheKey 生成缓存键
func (c *AdvancedCache) generateCacheKey(req *CacheRequest, rule *CacheRule) string {
	key := req.URL

	// 如果有缓存键配置
	if rule.CacheKey != nil {
		// 添加查询参数
		if len(rule.CacheKey.IncludeQueryParams) > 0 {
			params := ""
			for _, param := range rule.CacheKey.IncludeQueryParams {
				if value, ok := req.QueryParams[param]; ok {
					params += fmt.Sprintf("&%s=%s", param, value)
				}
			}
			if params != "" {
				key += "?" + params[1:]
			}
		}
	}

	return key
}

// updateStats 更新统计
func (c *AdvancedCache) updateStats(hit bool, item *CacheItem) {
	c.stats.mu.Lock()
	defer c.stats.mu.Unlock()

	c.stats.TotalRequests++

	if hit {
		c.stats.CacheHits++
		item.Hits++
		item.LastHitAt = time.Now()
	} else {
		c.stats.CacheMisses++
	}

	// 计算命中率
	if c.stats.TotalRequests > 0 {
		c.stats.CacheHitRate = float64(c.stats.CacheHits) / float64(c.stats.TotalRequests) * 100
	}

	c.stats.TotalItems = int64(len(c.stores))
}

// Delete 删除缓存
func (c *AdvancedCache) Delete(pattern string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// 添加到清除队列
	c.purger.pending = append(c.purger.pending, PurgeRequest{
		Pattern: pattern,
		Type:    "regex",
	})

	return nil
}

// Purge 清除缓存
func (c *AdvancedCache) Purge(request PurgeRequest) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.purger.pending = append(c.purger.pending, request)

	return nil
}

// PurgeAll 清除所有缓存
func (c *AdvancedCache) PurgeAll() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, store := range c.stores {
		store.mu.Lock()
		store.ItemsMap = make(map[string]*CacheItem)
		store.ItemsList = make([]string, 0)
		store.Items = 0
		store.Size = 0
		store.mu.Unlock()
	}

	c.stats.TotalItems = 0
	c.stats.TotalSize = 0

	return nil
}

// Invalidate 失效缓存
func (c *AdvancedCache) Invalidate(tags []string) error {
	return c.Purge(PurgeRequest{
		Tags: tags,
		Type: "tag",
	})
}

// GetStats 获取统计
func (c *AdvancedCache) GetStats() *CacheStats {
	c.stats.mu.RLock()
	defer c.stats.mu.RUnlock()

	return c.stats
}

// GetStores 获取存储列表
func (c *AdvancedCache) GetStores() []*CacheStore {
	c.mu.RLock()
	defer c.mu.RUnlock()

	stores := make([]*CacheStore, 0)
	for _, store := range c.stores {
		stores = append(stores, store)
	}

	return stores
}

// GetRules 获取规则列表
func (c *AdvancedCache) GetRules() []*CacheRule {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.rules
}

// AddRule 添加规则
func (c *AdvancedCache) AddRule(rule *CacheRule) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	rule.CreatedAt = time.Now()
	rule.UpdatedAt = time.Now()

	// 编译正则
	if rule.RuleType == "regex" && rule.Pattern != "" {
		re, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return fmt.Errorf("正则表达式编译失败: %v", err)
		}
		rule.PatternRegex = re
	}

	c.rules = append(c.rules, rule)

	return nil
}

// RemoveRule 移除规则
func (c *AdvancedCache) RemoveRule(ruleID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	for i, rule := range c.rules {
		if rule.ID == ruleID {
			c.rules = append(c.rules[:i], c.rules[i+1:]...)
			return nil
		}
	}

	return fmt.Errorf("规则不存在: %s", ruleID)
}

// runBackgroundTasks 运行后台任务
func (c *AdvancedCache) runBackgroundTasks() {
	interval := 5 * time.Minute
	if c.config.Global != nil && c.config.Global.CleanupInterval > 0 {
		interval = c.config.Global.CleanupInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.cleanup()
			c.processPurgeQueue()
		}
	}
}

// cleanup 清理过期缓存
func (c *AdvancedCache) cleanup() {
	c.mu.RLock()
	stores := make([]*CacheStore, 0, len(c.stores))
	for _, store := range c.stores {
		stores = append(stores, store)
	}
	c.mu.RUnlock()

	now := time.Now()
	totalExpired := int64(0)
	totalEvicted := int64(0)

	for _, store := range stores {
		store.mu.Lock()

		if store.Type == "memory" && store.ItemsMap != nil {
			itemsToDelete := make([]string, 0)

			// 查找过期项目
			for key, item := range store.ItemsMap {
				if now.After(item.ExpiresAt) {
					itemsToDelete = append(itemsToDelete, key)
					totalExpired++
				}
			}

			// 删除过期项目
			for _, key := range itemsToDelete {
				if item, exists := store.ItemsMap[key]; exists {
					store.Size -= int64(item.Size)
					delete(store.ItemsMap, key)
					store.Items--
					totalEvicted++
				}
			}

			// 如果启用了 LRU 淘汰，当缓存满时删除最久未使用的项目
			if c.config.Global != nil && c.config.Global.MaxSize > 0 {
				for store.Size > c.config.Global.MaxSize && len(store.ItemsList) > 0 {
					// 使用 ItemsList 作为简单的 LRU 队列
					lruKey := store.ItemsList[0]
					store.ItemsList = store.ItemsList[1:]

					if item, exists := store.ItemsMap[lruKey]; exists {
						store.Size -= int64(item.Size)
						delete(store.ItemsMap, lruKey)
						store.Items--
						totalEvicted++
					}
				}
			}
		}

		store.mu.Unlock()
	}

	// 更新统计
	if totalExpired > 0 || totalEvicted > 0 {
		c.stats.mu.Lock()
		c.stats.ExpiredItems += totalExpired
		c.stats.Evictions += totalEvicted
		c.stats.TotalSize = 0
		for _, store := range stores {
			c.stats.TotalSize += store.Size
		}
		c.stats.TotalItems = 0
		for _, store := range stores {
			c.stats.TotalItems += store.Items
		}
		c.stats.mu.Unlock()
	}
}

// processPurgeQueue 处理清除队列
func (c *AdvancedCache) processPurgeQueue() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.purger.pending) == 0 {
		return
	}

	// 处理清除请求
	c.purger.pending = make([]PurgeRequest, 0)
}

// StartPrefetch 启动预热
func (c *AdvancedCache) StartPrefetch() {
	if c.config.Prefetch == nil || !c.config.Prefetch.Enabled {
		return
	}

	go func() {
		for {
			select {
			case <-c.ctx.Done():
				return
			default:
				// 预热逻辑
				time.Sleep(c.config.Prefetch.Interval)
			}
		}
	}()
}

// StopPrefetch 停止预热
func (c *AdvancedCache) StopPrefetch() {
	c.prefetcher.mu.Lock()
	c.prefetcher.running = false
	c.prefetcher.mu.Unlock()
}

// NewLRUCache 创建 LRU 缓存
func NewLRUCache(capacity int64) *LRUCache {
	return &LRUCache{
		capacity: capacity,
		items:    make(map[string]*CacheItem),
		head:     &CacheItem{},
		tail:     &CacheItem{},
	}
}

// init 初始化链表
func (l *LRUCache) init() {
	l.head.next = l.tail
	l.tail.prev = l.head
}

// Get 获取缓存项（将访问的项移到头部）
func (l *LRUCache) Get(key string) *CacheItem {
	l.mu.Lock()
	defer l.mu.Unlock()

	if item, ok := l.items[key]; ok {
		l.moveToHead(item)
		return item
	}
	return nil
}

// Put 添加缓存项（如果已存在则更新）
func (l *LRUCache) Put(key string, item *CacheItem) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if existing, ok := l.items[key]; ok {
		// 更新现有项
		l.removeNode(existing)
		l.size -= int64(existing.Size)
	}

	l.items[key] = item
	l.addNode(item)
	l.size += int64(item.Size)

	// 如果超过容量，删除最久未使用的项
	for l.size > l.capacity && l.tail.prev != l.head {
		l.removeNode(l.tail.prev)
		delete(l.items, l.tail.prev.Key)
		l.size -= int64(l.tail.prev.Size)
	}
}

// Remove 删除缓存项
func (l *LRUCache) Remove(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	if item, ok := l.items[key]; ok {
		l.removeNode(item)
		delete(l.items, key)
		l.size -= int64(item.Size)
		return true
	}
	return false
}

// Size 获取当前大小
func (l *LRUCache) Size() int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.size
}

// Capacity 获取容量
func (l *LRUCache) Capacity() int64 {
	return l.capacity
}

// Len 获取项数
func (l *LRUCache) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.items)
}

// addNode 将节点添加到头部（最近使用）
func (l *LRUCache) addNode(item *CacheItem) {
	item.prev = l.head
	item.next = l.head.next

	l.head.next.prev = item
	l.head.next = item
}

// removeNode 从链表中移除节点
func (l *LRUCache) removeNode(item *CacheItem) {
	item.prev.next = item.next
	item.next.prev = item.prev
	item.prev = nil
	item.next = nil
}

// moveToHead 将节点移到头部
func (l *LRUCache) moveToHead(item *CacheItem) {
	l.removeNode(item)
	l.addNode(item)
}

// GetLRUItem 获取最久未使用的项
func (l *LRUCache) GetLRUItem() *CacheItem {
	if l.tail.prev != l.head {
		return l.tail.prev
	}
	return nil
}
