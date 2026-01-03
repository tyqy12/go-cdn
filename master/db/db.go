package db

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

// Store 数据存储接口
type Store interface {
	// 领导者选举相关
	TryAcquireLeadership(ctx context.Context, leader *LeaderRecord) error
	RenewLeadership(ctx context.Context, electionName, leaderID string, expiresAt time.Time) error
	ReleaseLeadership(ctx context.Context, electionName, leaderID string) error
	GetLeader(ctx context.Context, electionName string) (*LeaderRecord, error)
	GetElectionMembers(ctx context.Context, electionName string) ([]*ElectionMember, error)

	// 配置版本管理
	SaveConfigVersion(ctx context.Context, config *ConfigVersion) error
	GetConfigVersion(ctx context.Context, version string) (*ConfigVersion, error)
	ListConfigVersions(ctx context.Context) ([]*ConfigVersion, error)
	DeleteConfigVersion(ctx context.Context, version string) error
	GetConfigVersions(ctx context.Context, configType string) ([]*ConfigVersion, error)
	UpdateConfigVersion(ctx context.Context, config *ConfigVersion) error
	SaveConfigRollback(ctx context.Context, rollback *ConfigRollback) error
	GetConfigRollbacks(ctx context.Context, status string) ([]*ConfigRollback, error)
	GetConfigHistory(ctx context.Context, configType string, limit int) ([]*ConfigHistory, error)
	SaveConfigHistory(ctx context.Context, history *ConfigHistory) error

	// 节点管理
	SaveNode(ctx context.Context, node *Node) error
	GetNode(ctx context.Context, nodeID string) (*Node, error)
	ListNodes(ctx context.Context) ([]*Node, error)
	DeleteNode(ctx context.Context, nodeID string) error
	UpdateNodeStatus(ctx context.Context, nodeID string, status string) error
}

// MongoDB MongoDB实现
type MongoDB struct {
	client          *mongo.Client
	db              *mongo.Database
	leaders         *mongo.Collection
	electionMembers *mongo.Collection
	configVersions  *mongo.Collection
	configRollbacks *mongo.Collection
	configHistory   *mongo.Collection
	nodes           *mongo.Collection
}

// LeaderRecord 领导者记录
type LeaderRecord struct {
	ElectionName string    `bson:"election_name"`
	LeaderID     string    `bson:"leader_id"`
	ExpiresAt    time.Time `bson:"expires_at"`
	CreatedAt    time.Time `bson:"created_at"`
}

// ElectionMember 选举成员
type ElectionMember struct {
	ID       string    `bson:"_id"`
	Name     string    `bson:"name"`
	Address  string    `bson:"address"`
	Port     int       `bson:"port"`
	IsLeader bool      `bson:"is_leader"`
	JoinedAt time.Time `bson:"joined_at"`
}

// ConfigVersion 配置版本
type ConfigVersion struct {
	VersionID   int64     `bson:"version_id"`
	Version     string    `bson:"version"`
	ConfigType  string    `bson:"config_type"`
	ConfigData  []byte    `bson:"config_data"`
	Checksum    string    `bson:"checksum"`
	Description string    `bson:"description"`
	CreatedAt   time.Time `bson:"created_at"`
	CreatedBy   string    `bson:"created_by"`
	IsActive    bool      `bson:"is_active"`
	NodeType    string    `bson:"node_type"`
	Regions     []string  `bson:"regions"`
	Status      string    `bson:"status"`
	PublishedAt time.Time `bson:"published_at"`
}

// ConfigHistory 配置历史
type ConfigHistory struct {
	VersionID   int64     `bson:"version_id"`
	ConfigType  string    `bson:"config_type"`
	Checksum    string    `bson:"checksum"`
	Description string    `bson:"description"`
	CreatedAt   time.Time `bson:"created_at"`
	CreatedBy   string    `bson:"created_by"`
	Action      string    `bson:"action"`
	FromVersion int64     `bson:"from_version"`
	ToVersion   int64     `bson:"to_version"`
}

// ConfigRollback 回滚请求
type ConfigRollback struct {
	ConfigType  string    `bson:"config_type"`
	FromVersion int64     `bson:"from_version"`
	ToVersion   int64     `bson:"to_version"`
	Reason      string    `bson:"reason"`
	RequestedBy string    `bson:"requested_by"`
	ApprovedBy  string    `bson:"approved_by"`
	ApprovedAt  time.Time `bson:"approved_at"`
	Status      string    `bson:"status"`
	CreatedAt   time.Time `bson:"created_at"`
}

// Node 节点
type Node struct {
	ID        string            `bson:"_id"`
	Name      string            `bson:"name"`
	Type      string            `bson:"type"`
	Region    string            `bson:"region"`
	Addr      string            `bson:"addr"`
	Port      int               `bson:"port"`
	Status    string            `bson:"status"`
	Tags      []string          `bson:"tags"`
	Metadata  map[string]string `bson:"metadata"`
	Version   string            `bson:"version"`
	CreatedAt time.Time         `bson:"created_at"`
	UpdatedAt time.Time         `bson:"updated_at"`
	LastSeen  time.Time         `bson:"last_seen"`
}

// NewMongoDB 创建MongoDB实例
func NewMongoDB(uri string) (*MongoDB, error) {
	if strings.TrimSpace(uri) == "" {
		return nil, errors.New("mongo uri不能为空")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		return nil, fmt.Errorf("连接MongoDB失败: %w", err)
	}

	if err := client.Ping(ctx, readpref.Primary()); err != nil {
		_ = client.Disconnect(context.Background())
		return nil, fmt.Errorf("MongoDB ping失败: %w", err)
	}

	dbName := parseDatabaseName(uri)
	if dbName == "" {
		dbName = "ai-cdn"
	}

	database := client.Database(dbName)
	store := &MongoDB{
		client:          client,
		db:              database,
		leaders:         database.Collection("leaders"),
		electionMembers: database.Collection("election_members"),
		configVersions:  database.Collection("config_versions"),
		configRollbacks: database.Collection("config_rollbacks"),
		configHistory:   database.Collection("config_history"),
		nodes:           database.Collection("nodes"),
	}

	if err := store.ensureIndexes(ctx); err != nil {
		_ = client.Disconnect(context.Background())
		return nil, fmt.Errorf("创建MongoDB索引失败: %w", err)
	}

	return store, nil
}

// Close 关闭连接
func (m *MongoDB) Close() error {
	if m == nil || m.client == nil {
		return nil
	}
	return m.client.Disconnect(context.Background())
}

// TryAcquireLeadership 尝试获取领导者身份
func (m *MongoDB) TryAcquireLeadership(ctx context.Context, leader *LeaderRecord) error {
	if m == nil || m.leaders == nil {
		return errors.New("mongo连接未初始化")
	}
	if leader == nil {
		return errors.New("leader记录不能为空")
	}
	if strings.TrimSpace(leader.ElectionName) == "" || strings.TrimSpace(leader.LeaderID) == "" {
		return errors.New("选举名称和leaderID不能为空")
	}

	now := time.Now()
	if leader.ExpiresAt.IsZero() {
		leader.ExpiresAt = now
	}

	filter := bson.M{
		"election_name": leader.ElectionName,
		"$or": bson.A{
			bson.M{"expires_at": bson.M{"$lte": now}},
			bson.M{"expires_at": bson.M{"$exists": false}},
			bson.M{"leader_id": leader.LeaderID},
		},
	}
	update := bson.M{
		"$set": bson.M{
			"election_name": leader.ElectionName,
			"leader_id":     leader.LeaderID,
			"expires_at":    leader.ExpiresAt,
			"created_at":    now,
		},
	}

	opts := options.FindOneAndUpdate().SetUpsert(true).SetReturnDocument(options.After)
	return m.leaders.FindOneAndUpdate(ctx, filter, update, opts).Err()
}

// RenewLeadership 续租领导者身份
func (m *MongoDB) RenewLeadership(ctx context.Context, electionName, leaderID string, expiresAt time.Time) error {
	if m == nil || m.leaders == nil {
		return errors.New("mongo连接未初始化")
	}
	if strings.TrimSpace(electionName) == "" || strings.TrimSpace(leaderID) == "" {
		return errors.New("选举名称和leaderID不能为空")
	}
	if expiresAt.IsZero() {
		return errors.New("过期时间不能为空")
	}

	filter := bson.M{
		"election_name": electionName,
		"leader_id":     leaderID,
	}
	update := bson.M{
		"$set": bson.M{
			"expires_at": expiresAt,
		},
	}

	result, err := m.leaders.UpdateOne(ctx, filter, update)
	if err != nil {
		return err
	}
	if result.MatchedCount == 0 {
		return fmt.Errorf("未找到领导者记录: %s", electionName)
	}
	return nil
}

// ReleaseLeadership 释放领导者身份
func (m *MongoDB) ReleaseLeadership(ctx context.Context, electionName, leaderID string) error {
	if m == nil || m.leaders == nil {
		return errors.New("mongo连接未初始化")
	}
	if strings.TrimSpace(electionName) == "" || strings.TrimSpace(leaderID) == "" {
		return errors.New("选举名称和leaderID不能为空")
	}

	_, err := m.leaders.DeleteOne(ctx, bson.M{
		"election_name": electionName,
		"leader_id":     leaderID,
	})
	return err
}

// GetLeader 获取当前领导者
func (m *MongoDB) GetLeader(ctx context.Context, electionName string) (*LeaderRecord, error) {
	if m == nil || m.leaders == nil {
		return nil, errors.New("mongo连接未初始化")
	}
	if strings.TrimSpace(electionName) == "" {
		return nil, errors.New("选举名称不能为空")
	}

	filter := bson.M{
		"election_name": electionName,
		"expires_at":    bson.M{"$gt": time.Now()},
	}
	opts := options.FindOne().SetSort(bson.D{{Key: "expires_at", Value: -1}})

	var leader LeaderRecord
	err := m.leaders.FindOne(ctx, filter, opts).Decode(&leader)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &leader, nil
}

// GetElectionMembers 获取选举成员列表
func (m *MongoDB) GetElectionMembers(ctx context.Context, electionName string) ([]*ElectionMember, error) {
	if m == nil || m.electionMembers == nil {
		return nil, errors.New("mongo连接未初始化")
	}

	filter := bson.M{}
	if strings.TrimSpace(electionName) != "" {
		filter["election_name"] = electionName
	}

	cursor, err := m.electionMembers.Find(ctx, filter)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var members []*ElectionMember
	for cursor.Next(ctx) {
		var member ElectionMember
		if err := cursor.Decode(&member); err != nil {
			return nil, err
		}
		members = append(members, &member)
	}
	if err := cursor.Err(); err != nil {
		return nil, err
	}
	return members, nil
}

// SaveConfigVersion 保存配置版本
func (m *MongoDB) SaveConfigVersion(ctx context.Context, config *ConfigVersion) error {
	if m == nil || m.configVersions == nil {
		return errors.New("mongo连接未初始化")
	}
	if config == nil {
		return errors.New("配置版本不能为空")
	}
	if config.VersionID == 0 && strings.TrimSpace(config.Version) == "" {
		return errors.New("配置版本号不能为空")
	}
	if strings.TrimSpace(config.Version) == "" && config.VersionID != 0 {
		config.Version = fmt.Sprintf("%d", config.VersionID)
	}
	now := time.Now()
	if config.CreatedAt.IsZero() {
		config.CreatedAt = now
	}

	filter := bson.M{}
	if config.VersionID != 0 {
		filter["version_id"] = config.VersionID
	} else {
		filter["version"] = config.Version
	}
	_, err := m.configVersions.ReplaceOne(ctx, filter, config, options.Replace().SetUpsert(true))
	return err
}

// GetConfigVersion 获取配置版本
func (m *MongoDB) GetConfigVersion(ctx context.Context, version string) (*ConfigVersion, error) {
	if m == nil || m.configVersions == nil {
		return nil, errors.New("mongo连接未初始化")
	}
	if strings.TrimSpace(version) == "" {
		return nil, errors.New("配置版本号不能为空")
	}

	var config ConfigVersion
	err := m.configVersions.FindOne(ctx, bson.M{"version": version}).Decode(&config)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &config, nil
}

// ListConfigVersions 列出所有配置版本
func (m *MongoDB) ListConfigVersions(ctx context.Context) ([]*ConfigVersion, error) {
	if m == nil || m.configVersions == nil {
		return nil, errors.New("mongo连接未初始化")
	}

	opts := options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}})
	cursor, err := m.configVersions.Find(ctx, bson.M{}, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var configs []*ConfigVersion
	for cursor.Next(ctx) {
		var config ConfigVersion
		if err := cursor.Decode(&config); err != nil {
			return nil, err
		}
		configs = append(configs, &config)
	}
	if err := cursor.Err(); err != nil {
		return nil, err
	}
	return configs, nil
}

// DeleteConfigVersion 删除配置版本
func (m *MongoDB) DeleteConfigVersion(ctx context.Context, version string) error {
	if m == nil || m.configVersions == nil {
		return errors.New("mongo连接未初始化")
	}
	if strings.TrimSpace(version) == "" {
		return errors.New("配置版本号不能为空")
	}

	_, err := m.configVersions.DeleteOne(ctx, bson.M{"version": version})
	return err
}

// GetConfigVersions 获取配置版本列表
func (m *MongoDB) GetConfigVersions(ctx context.Context, configType string) ([]*ConfigVersion, error) {
	if m == nil || m.configVersions == nil {
		return nil, errors.New("mongo连接未初始化")
	}

	filter := bson.M{}
	if strings.TrimSpace(configType) != "" {
		filter["config_type"] = configType
	}

	opts := options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}})
	cursor, err := m.configVersions.Find(ctx, filter, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var configs []*ConfigVersion
	for cursor.Next(ctx) {
		var config ConfigVersion
		if err := cursor.Decode(&config); err != nil {
			return nil, err
		}
		configs = append(configs, &config)
	}
	if err := cursor.Err(); err != nil {
		return nil, err
	}
	return configs, nil
}

// UpdateConfigVersion 更新配置版本
func (m *MongoDB) UpdateConfigVersion(ctx context.Context, config *ConfigVersion) error {
	if m == nil || m.configVersions == nil {
		return errors.New("mongo连接未初始化")
	}
	if config == nil {
		return errors.New("配置版本不能为空")
	}
	if config.VersionID == 0 && strings.TrimSpace(config.Version) == "" {
		return errors.New("配置版本号不能为空")
	}

	filter := bson.M{}
	if config.VersionID != 0 {
		filter["version_id"] = config.VersionID
	} else {
		filter["version"] = config.Version
	}

	_, err := m.configVersions.ReplaceOne(ctx, filter, config)
	return err
}

// SaveConfigRollback 保存回滚请求
func (m *MongoDB) SaveConfigRollback(ctx context.Context, rollback *ConfigRollback) error {
	if m == nil || m.configRollbacks == nil {
		return errors.New("mongo连接未初始化")
	}
	if rollback == nil {
		return errors.New("回滚请求不能为空")
	}
	if rollback.CreatedAt.IsZero() {
		rollback.CreatedAt = time.Now()
	}
	_, err := m.configRollbacks.InsertOne(ctx, rollback)
	return err
}

// GetConfigRollbacks 获取回滚请求列表
func (m *MongoDB) GetConfigRollbacks(ctx context.Context, status string) ([]*ConfigRollback, error) {
	if m == nil || m.configRollbacks == nil {
		return nil, errors.New("mongo连接未初始化")
	}

	filter := bson.M{}
	if strings.TrimSpace(status) != "" {
		filter["status"] = status
	}

	opts := options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}})
	cursor, err := m.configRollbacks.Find(ctx, filter, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var rollbacks []*ConfigRollback
	for cursor.Next(ctx) {
		var rollback ConfigRollback
		if err := cursor.Decode(&rollback); err != nil {
			return nil, err
		}
		rollbacks = append(rollbacks, &rollback)
	}
	if err := cursor.Err(); err != nil {
		return nil, err
	}
	return rollbacks, nil
}

// GetConfigHistory 获取配置历史
func (m *MongoDB) GetConfigHistory(ctx context.Context, configType string, limit int) ([]*ConfigHistory, error) {
	if m == nil || m.configHistory == nil {
		return nil, errors.New("mongo连接未初始化")
	}

	filter := bson.M{}
	if strings.TrimSpace(configType) != "" {
		filter["config_type"] = configType
	}

	opts := options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}})
	if limit > 0 {
		opts.SetLimit(int64(limit))
	}

	cursor, err := m.configHistory.Find(ctx, filter, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var histories []*ConfigHistory
	for cursor.Next(ctx) {
		var history ConfigHistory
		if err := cursor.Decode(&history); err != nil {
			return nil, err
		}
		histories = append(histories, &history)
	}
	if err := cursor.Err(); err != nil {
		return nil, err
	}
	return histories, nil
}

// SaveConfigHistory 保存配置历史
func (m *MongoDB) SaveConfigHistory(ctx context.Context, history *ConfigHistory) error {
	if m == nil || m.configHistory == nil {
		return errors.New("mongo连接未初始化")
	}
	if history == nil {
		return errors.New("配置历史不能为空")
	}
	if history.CreatedAt.IsZero() {
		history.CreatedAt = time.Now()
	}
	_, err := m.configHistory.InsertOne(ctx, history)
	return err
}

// SaveNode 保存节点
func (m *MongoDB) SaveNode(ctx context.Context, node *Node) error {
	if m == nil || m.nodes == nil {
		return errors.New("mongo连接未初始化")
	}
	if node == nil {
		return errors.New("节点不能为空")
	}
	if strings.TrimSpace(node.ID) == "" {
		return errors.New("节点ID不能为空")
	}

	now := time.Now()
	if node.CreatedAt.IsZero() {
		node.CreatedAt = now
	}
	node.UpdatedAt = now
	if node.LastSeen.IsZero() {
		node.LastSeen = now
	}

	_, err := m.nodes.ReplaceOne(ctx, bson.M{"_id": node.ID}, node, options.Replace().SetUpsert(true))
	return err
}

// GetNode 获取节点
func (m *MongoDB) GetNode(ctx context.Context, nodeID string) (*Node, error) {
	if m == nil || m.nodes == nil {
		return nil, errors.New("mongo连接未初始化")
	}
	if strings.TrimSpace(nodeID) == "" {
		return nil, errors.New("节点ID不能为空")
	}

	var node Node
	err := m.nodes.FindOne(ctx, bson.M{"_id": nodeID}).Decode(&node)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &node, nil
}

// ListNodes 列出所有节点
func (m *MongoDB) ListNodes(ctx context.Context) ([]*Node, error) {
	if m == nil || m.nodes == nil {
		return nil, errors.New("mongo连接未初始化")
	}

	opts := options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}})
	cursor, err := m.nodes.Find(ctx, bson.M{}, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var nodes []*Node
	for cursor.Next(ctx) {
		var node Node
		if err := cursor.Decode(&node); err != nil {
			return nil, err
		}
		nodes = append(nodes, &node)
	}
	if err := cursor.Err(); err != nil {
		return nil, err
	}
	return nodes, nil
}

// DeleteNode 删除节点
func (m *MongoDB) DeleteNode(ctx context.Context, nodeID string) error {
	if m == nil || m.nodes == nil {
		return errors.New("mongo连接未初始化")
	}
	if strings.TrimSpace(nodeID) == "" {
		return errors.New("节点ID不能为空")
	}

	_, err := m.nodes.DeleteOne(ctx, bson.M{"_id": nodeID})
	return err
}

// UpdateNodeStatus 更新节点状态
func (m *MongoDB) UpdateNodeStatus(ctx context.Context, nodeID string, status string) error {
	if m == nil || m.nodes == nil {
		return errors.New("mongo连接未初始化")
	}
	if strings.TrimSpace(nodeID) == "" {
		return errors.New("节点ID不能为空")
	}
	if strings.TrimSpace(status) == "" {
		return errors.New("节点状态不能为空")
	}

	update := bson.M{
		"$set": bson.M{
			"status":     status,
			"updated_at": time.Now(),
			"last_seen":  time.Now(),
		},
	}
	result, err := m.nodes.UpdateOne(ctx, bson.M{"_id": nodeID}, update)
	if err != nil {
		return err
	}
	if result.MatchedCount == 0 {
		return fmt.Errorf("节点不存在: %s", nodeID)
	}
	return nil
}

func (m *MongoDB) ensureIndexes(ctx context.Context) error {
	leaderIndexes := []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "election_name", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
		{
			Keys:    bson.D{{Key: "expires_at", Value: 1}},
			Options: options.Index().SetExpireAfterSeconds(0),
		},
	}
	if _, err := m.leaders.Indexes().CreateMany(ctx, leaderIndexes); err != nil {
		return err
	}

	memberIndexes := []mongo.IndexModel{
		{
			Keys: bson.D{{Key: "election_name", Value: 1}},
		},
	}
	if _, err := m.electionMembers.Indexes().CreateMany(ctx, memberIndexes); err != nil {
		return err
	}

	configIndexes := []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "version", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
	}
	if _, err := m.configVersions.Indexes().CreateMany(ctx, configIndexes); err != nil {
		return err
	}

	rollbackIndexes := []mongo.IndexModel{
		{
			Keys: bson.D{{Key: "status", Value: 1}},
		},
		{
			Keys: bson.D{{Key: "config_type", Value: 1}},
		},
	}
	if m.configRollbacks != nil {
		if _, err := m.configRollbacks.Indexes().CreateMany(ctx, rollbackIndexes); err != nil {
			return err
		}
	}

	historyIndexes := []mongo.IndexModel{
		{
			Keys: bson.D{{Key: "config_type", Value: 1}},
		},
	}
	if m.configHistory != nil {
		if _, err := m.configHistory.Indexes().CreateMany(ctx, historyIndexes); err != nil {
			return err
		}
	}

	nodeIndexes := []mongo.IndexModel{
		{
			Keys: bson.D{{Key: "status", Value: 1}},
		},
		{
			Keys: bson.D{{Key: "region", Value: 1}},
		},
	}
	if _, err := m.nodes.Indexes().CreateMany(ctx, nodeIndexes); err != nil {
		return err
	}

	return nil
}

func parseDatabaseName(uri string) string {
	parsed, err := url.Parse(uri)
	if err != nil {
		return ""
	}
	return strings.Trim(parsed.Path, "/")
}
