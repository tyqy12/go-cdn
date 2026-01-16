package health

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
)

// CloudProvider 云平台提供商接口
type CloudProvider interface {
	// CreateInstance 创建云实例
	CreateInstance(ctx context.Context, req *CreateInstanceRequest) (*CreateInstanceResponse, error)

	// TerminateInstance 终止云实例
	TerminateInstance(ctx context.Context, instanceID string) error

	// GetInstanceStatus 获取实例状态
	GetInstanceStatus(ctx context.Context, instanceID string) (*InstanceStatus, error)

	// ListInstances 列出所有实例
	ListInstances(ctx context.Context, filters *InstanceFilters) ([]*Instance, error)
}

// CreateInstanceRequest 创建实例请求
type CreateInstanceRequest struct {
	// 实例名称
	Name string

	// 实例类型
	InstanceType string

	// 镜像ID
	ImageID string

	// 区域
	Region string

	// 可用区
	Zone string

	// CPU配置
	CPU int

	// 内存配置 (GB)
	MemoryGB int

	// 磁盘配置
	Disks []*DiskConfig

	// 网络配置
	Network *NetworkConfig

	// 安全组ID
	SecurityGroupIDs []string

	// 密钥对名称
	KeyPairName string

	// 用户数据（启动脚本）
	UserData string

	// 标签
	Tags map[string]string
}

// DiskConfig 磁盘配置
type DiskConfig struct {
	// 磁盘类型
	Type string // "system", "data"

	// 大小 (GB)
	SizeGB int

	// 磁盘类型
	DiskType string // "cloud_ssd", "cloud_efficiency"
}

// NetworkConfig 网络配置
type NetworkConfig struct {
	// VPC ID
	VPCID string

	// 交换机ID
	VSwitchID string

	// 公网带宽 (Mbps)
	PublicBandwidth int

	// 是否分配公网IP
	AssignPublicIP bool
}

// CreateInstanceResponse 创建实例响应
type CreateInstanceResponse struct {
	// 实例ID
	InstanceID string

	// 实例名称
	InstanceName string

	// 公网IP
	PublicIP string

	// 私网IP
	PrivateIP string

	// 状态
	Status string

	// 创建时间
	CreatedAt time.Time
}

// InstanceStatus 实例状态
type InstanceStatus struct {
	// 实例ID
	InstanceID string

	// 状态
	Status string // "pending", "running", "stopped", "terminated"

	// 公网IP
	PublicIP string

	// 私网IP
	PrivateIP string

	// CPU使用率
	CPUUsage float64

	// 内存使用率
	MemoryUsage float64

	// 更新时间
	UpdatedAt time.Time
}

// Instance 实例信息
type Instance struct {
	// 实例ID
	InstanceID string

	// 实例名称
	Name string

	// 实例类型
	InstanceType string

	// 区域
	Region string

	// 可用区
	Zone string

	// 状态
	Status string

	// 公网IP
	PublicIP string

	// 私网IP
	PrivateIP string

	// 创建时间
	CreatedAt time.Time

	// 标签
	Tags map[string]string
}

// InstanceFilters 实例筛选条件
type InstanceFilters struct {
	// 状态
	Status string

	// 区域
	Region string

	// 标签
	Tags map[string]string
}

// MockCloudProvider Mock云平台提供商
type MockCloudProvider struct{}

// CreateInstance 创建云实例（模拟）
func (m *MockCloudProvider) CreateInstance(ctx context.Context, req *CreateInstanceRequest) (*CreateInstanceResponse, error) {
	instanceID := fmt.Sprintf("i-%s", generateNodeID())

	return &CreateInstanceResponse{
		InstanceID:   instanceID,
		InstanceName: req.Name,
		PublicIP:     fmt.Sprintf("47.100.%d.%d", time.Now().Unix()%256, time.Now().UnixNano()%256),
		PrivateIP:    fmt.Sprintf("172.16.%d.%d", time.Now().Unix()%256, time.Now().UnixNano()%256),
		Status:       "pending",
		CreatedAt:    time.Now(),
	}, nil
}

// TerminateInstance 终止云实例（模拟）
func (m *MockCloudProvider) TerminateInstance(ctx context.Context, instanceID string) error {
	return nil
}

// GetInstanceStatus 获取实例状态（模拟）
func (m *MockCloudProvider) GetInstanceStatus(ctx context.Context, instanceID string) (*InstanceStatus, error) {
	return &InstanceStatus{
		InstanceID:  instanceID,
		Status:      "running",
		PublicIP:    fmt.Sprintf("47.100.%d.%d", time.Now().Unix()%256, time.Now().UnixNano()%256),
		PrivateIP:   fmt.Sprintf("172.16.%d.%d", time.Now().Unix()%256, time.Now().UnixNano()%256),
		CPUUsage:    0.3,
		MemoryUsage: 0.4,
		UpdatedAt:   time.Now(),
	}, nil
}

// ListInstances 列出所有实例（模拟）
func (m *MockCloudProvider) ListInstances(ctx context.Context, filters *InstanceFilters) ([]*Instance, error) {
	return []*Instance{}, nil
}

// NewMockCloudProvider 创建Mock云平台提供商
func NewMockCloudProvider() CloudProvider {
	return &MockCloudProvider{}
}

// ========== AWS 云提供商实现 ==========

// AWSCloudProvider AWS云平台提供商
type AWSCloudProvider struct {
	region   string
	ec2      *ec2.EC2
	instance *ec2.Instance
}

// AWSConfig AWS配置
type AWSConfig struct {
	// AWS访问密钥
	AccessKeyID string

	// AWS密钥
	SecretAccessKey string

	// AWS区域
	Region string

	// 实例类型
	InstanceType string

	// AMI ID
	AMIID string

	// SSH密钥对名称
	KeyPairName string

	// 安全组ID列表
	SecurityGroupIDs []string

	// IAM实例配置文件
	IAMProfile string

	// 子网ID
	SubnetID string
}

// NewAWSCloudProvider 创建AWS云平台提供商
func NewAWSCloudProvider(cfg *AWSConfig) (CloudProvider, error) {
	if cfg == nil {
		cfg = &AWSConfig{
			Region:        "us-east-1",
			InstanceType:  "t3.medium",
			AMIID:         "ami-0c02fb55956c7d316", // Amazon Linux 2
			KeyPairName:   "cdn-key-pair",
			SecurityGroupIDs: []string{"sg-cdn-security-group"},
		}
	}

	// 创建AWS会话
	var sess *session.Session
	var err error

	if cfg.AccessKeyID != "" && cfg.SecretAccessKey != "" {
		// 使用访问密钥
		cred := credentials.NewStaticCredentials(cfg.AccessKeyID, cfg.SecretAccessKey, "")
		sess, err = session.NewSession(&aws.Config{
			Region:      aws.String(cfg.Region),
			Credentials: cred,
		})
	} else {
		// 使用默认凭证链（环境变量、配置文件、ECS任务角色等）
		sess, err = session.NewSession(&aws.Config{
			Region: aws.String(cfg.Region),
		})
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create AWS session: %w", err)
	}

	// 创建EC2客户端
	ec2Client := ec2.New(sess)

	return &AWSCloudProvider{
		region:   cfg.Region,
		ec2:      ec2Client,
		instance: nil,
	}, nil
}

// CreateInstance 创建AWS EC2实例
func (a *AWSCloudProvider) CreateInstance(ctx context.Context, req *CreateInstanceRequest) (*CreateInstanceResponse, error) {
	log.Printf("[AWS] Creating instance: %s in %s", req.Name, req.Region)

	// 设置实例类型
	instanceType := req.InstanceType
	if instanceType == "" {
		instanceType = "t3.medium"
	}

	// 设置AMI ID
	amiID := req.ImageID
	if amiID == "" {
		amiID = "ami-0c02fb55956c7d316" // 默认Amazon Linux 2
	}

	// 创建RunInstances输入
	input := &ec2.RunInstancesInput{
		ImageId:      aws.String(amiID),
		InstanceType: aws.String(instanceType),
		MaxCount:     aws.Int64(1),
		MinCount:     aws.Int64(1),
	}

	// 设置密钥对
	if req.KeyPairName != "" {
		input.KeyName = aws.String(req.KeyPairName)
	}

	// 设置安全组
	if len(req.SecurityGroupIDs) > 0 {
		input.SecurityGroupIds = aws.StringSlice(req.SecurityGroupIDs)
	}

	// 设置子网
	if req.Network != nil && req.Network.VSwitchID != "" {
		input.SubnetId = aws.String(req.Network.VSwitchID)
	}

	// 设置标签
	if req.Name != "" {
		input.TagSpecifications = []*ec2.TagSpecification{
			{
				ResourceType: aws.String("instance"),
				Tags: []*ec2.Tag{
					{
						Key:   aws.String("Name"),
						Value: aws.String(req.Name),
					},
					{
						Key:   aws.String("ManagedBy"),
						Value: aws.String("GoCDN"),
					},
				},
			},
		}
	}

	// 设置用户数据（启动脚本）
	if req.UserData != "" {
		input.UserData = aws.String(req.UserData)
	}

	// 检查是否需要监控
	input.Monitoring = &ec2.RunInstancesMonitoringEnabled{
		Enabled: aws.Bool(true),
	}

	// 执行创建实例
	output, err := a.ec2.RunInstancesWithContext(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to create instance: %w", err)
	}

	if len(output.Instances) == 0 {
		return nil, fmt.Errorf("no instance returned after creation")
	}

	instance := output.Instances[0]
	instanceID := aws.StringValue(instance.InstanceId)

	// 等待实例运行
	log.Printf("[AWS] Waiting for instance %s to be running...", instanceID)
	if waitErr := a.ec2.WaitUntilInstanceRunningWithContext(ctx, &ec2.DescribeInstancesInput{
		InstanceIds: []*string{instance.InstanceId},
	}); waitErr != nil {
		log.Printf("[AWS] Warning: failed to wait for instance running: %v", waitErr)
	}

	// 获取实例详细信息
	descInput := &ec2.DescribeInstancesInput{
		InstanceIds: []*string{aws.String(instanceID)},
	}

	descOutput, err := a.ec2.DescribeInstancesWithContext(ctx, descInput)
	if err != nil {
		log.Printf("[AWS] Warning: failed to describe instance: %v", err)
	}

	var publicIP, privateIP string
	if len(descOutput.Reservations) > 0 && len(descOutput.Reservations[0].Instances) > 0 {
		inst := descOutput.Reservations[0].Instances[0]
		if inst.PublicIpAddress != nil {
			publicIP = aws.StringValue(inst.PublicIpAddress)
		}
		if inst.PrivateIpAddress != nil {
			privateIP = aws.StringValue(inst.PrivateIpAddress)
		}
	}

	log.Printf("[AWS] Instance %s created successfully", instanceID)

	return &CreateInstanceResponse{
		InstanceID:   instanceID,
		InstanceName: req.Name,
		PublicIP:     publicIP,
		PrivateIP:    privateIP,
		Status:       "running",
		CreatedAt:    time.Now(),
	}, nil
}

// TerminateInstance 终止AWS EC2实例
func (a *AWSCloudProvider) TerminateInstance(ctx context.Context, instanceID string) error {
	log.Printf("[AWS] Terminating instance: %s", instanceID)

	input := &ec2.TerminateInstancesInput{
		InstanceIds: []*string{aws.String(instanceID)},
	}

	output, err := a.ec2.TerminateInstancesWithContext(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to terminate instance: %w", err)
	}

	// 等待实例终止
	log.Printf("[AWS] Waiting for instance %s to be terminated...", instanceID)
	if waitErr := a.ec2.WaitUntilInstanceTerminatedWithContext(ctx, &ec2.DescribeInstancesInput{
		InstanceIds: []*string{aws.String(instanceID)},
	}); waitErr != nil {
		log.Printf("[AWS] Warning: failed to wait for instance termination: %v", waitErr)
	}

	log.Printf("[AWS] Instance %s terminated successfully. Previous state: %s",
		instanceID, aws.StringValue(output.TerminatingInstances[0].PreviousState.Name))

	return nil
}

// GetInstanceStatus 获取AWS EC2实例状态
func (a *AWSCloudProvider) GetInstanceStatus(ctx context.Context, instanceID string) (*InstanceStatus, error) {
	input := &ec2.DescribeInstancesInput{
		InstanceIds: []*string{aws.String(instanceID)},
	}

	output, err := a.ec2.DescribeInstancesWithContext(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to describe instance: %w", err)
	}

	if len(output.Reservations) == 0 || len(output.Reservations[0].Instances) == 0 {
		return nil, fmt.Errorf("instance not found: %s", instanceID)
	}

	instance := output.Reservations[0].Instances[0]

	// 获取实例状态
	status := aws.StringValue(instance.State.Name)

	// 获取公网IP
	var publicIP, privateIP string
	if instance.PublicIpAddress != nil {
		publicIP = aws.StringValue(instance.PublicIpAddress)
	}
	if instance.PrivateIpAddress != nil {
		privateIP = aws.StringValue(instance.PrivateIpAddress)
	}

	return &InstanceStatus{
		InstanceID:  instanceID,
		Status:      status,
		PublicIP:    publicIP,
		PrivateIP:   privateIP,
		CPUUsage:    0, // 需要CloudWatch获取
		MemoryUsage: 0,
		UpdatedAt:   time.Now(),
	}, nil
}

// ListInstances 列出所有AWS EC2实例
func (a *AWSCloudProvider) ListInstances(ctx context.Context, filters *InstanceFilters) ([]*Instance, error) {
	input := &ec2.DescribeInstancesInput{}

	// 应用过滤器
	if filters != nil {
		if filters.Region != "" {
			input.Filters = append(input.Filters, &ec2.Filter{
				Name:   aws.String("availability-zone"),
				Values: []*string{aws.String(filters.Region + "a")},
			})
		}
	}

	output, err := a.ec2.DescribeInstancesWithContext(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to describe instances: %w", err)
	}

	var instances []*Instance
	for _, reservation := range output.Reservations {
		for _, ec2Inst := range reservation.Instances {
			// 检查状态过滤
			if filters != nil && filters.Status != "" {
				if aws.StringValue(ec2Inst.State.Name) != filters.Status {
					continue
				}
			}

			instance := &Instance{
				InstanceID:   aws.StringValue(ec2Inst.InstanceId),
				Name:         getTagValue(ec2Inst.Tags, "Name"),
				InstanceType: aws.StringValue(ec2Inst.InstanceType),
				Region:       a.region,
				Status:       aws.StringValue(ec2Inst.State.Name),
				CreatedAt:    aws.TimeValue(ec2Inst.LaunchTime),
				Tags:         make(map[string]string),
			}

			if ec2Inst.PublicIpAddress != nil {
				instance.PublicIP = aws.StringValue(ec2Inst.PublicIpAddress)
			}
			if ec2Inst.PrivateIpAddress != nil {
				instance.PrivateIP = aws.StringValue(ec2Inst.PrivateIpAddress)
			}

			// 解析标签
			for _, tag := range ec2Inst.Tags {
				if tag.Key != nil && tag.Value != nil {
					instance.Tags[aws.StringValue(tag.Key)] = aws.StringValue(tag.Value)
				}
			}

			// 提取可用区
			if ec2Inst.Placement != nil && ec2Inst.Placement.AvailabilityZone != nil {
				instance.Zone = aws.StringValue(ec2Inst.Placement.AvailabilityZone)
			}

			instances = append(instances, instance)
		}
	}

	return instances, nil
}

// getTagValue 从标签列表中获取指定键的值
func getTagValue(tags []*ec2.Tag, key string) string {
	for _, tag := range tags {
		if tag != nil && tag.Key != nil && aws.StringValue(tag.Key) == key {
			if tag.Value != nil {
				return aws.StringValue(tag.Value)
			}
		}
	}
	return ""
}

// ========== 华为云提供商实现 ==========

// HuaweiCloudProvider 华为云平台提供商
type HuaweiCloudProvider struct {
	region string
	// 实际实现需要华为云SDK
}

// NewHuaweiCloudProvider 创建华为云平台提供商
func NewHuaweiCloudProvider(accessKey, secretKey, region string) (CloudProvider, error) {
	// 华为云SDK实现（需要单独集成）
	log.Printf("[HuaweiCloud] Provider created for region: %s (SDK integration pending)", region)
	return &HuaweiCloudProvider{region: region}, nil
}

// CreateInstance 创建华为云实例
func (h *HuaweiCloudProvider) CreateInstance(ctx context.Context, req *CreateInstanceRequest) (*CreateInstanceResponse, error) {
	log.Printf("[HuaweiCloud] Creating instance: %s in %s (placeholder)", req.Name, req.Region)
	return nil, fmt.Errorf("HuaweiCloud SDK not integrated yet")
}

// TerminateInstance 终止华为云实例
func (h *HuaweiCloudProvider) TerminateInstance(ctx context.Context, instanceID string) error {
	return fmt.Errorf("HuaweiCloud SDK not integrated yet")
}

// GetInstanceStatus 获取华为云实例状态
func (h *HuaweiCloudProvider) GetInstanceStatus(ctx context.Context, instanceID string) (*InstanceStatus, error) {
	return nil, fmt.Errorf("HuaweiCloud SDK not integrated yet")
}

// ListInstances 列出所有华为云实例
func (h *HuaweiCloudProvider) ListInstances(ctx context.Context, filters *InstanceFilters) ([]*Instance, error) {
	return nil, fmt.Errorf("HuaweiCloud SDK not integrated yet")
}
