package iplib

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

// IPLib 专业IP库接口
type IPLib interface {
	// 初始化加载IP数据库
	Init(databasePath string) error
	// 查询IP信息
	Query(ip net.IP) (*IPInfo, error)
	// 批量查询
	BatchQuery(ips []net.IP) map[string]*IPInfo
	// 获取库信息
	GetLibraryInfo() *LibraryInfo
}

// IPInfo IP地址信息
type IPInfo struct {
	IP            string        `json:"ip"`
	Country       string        `json:"country"`        // 国家
	CountryCode   string        `json:"country_code"`   // 国家代码 CN, US, HK
	Region        string        `json:"region"`         // 地区/省份
	City          string        `json:"city"`           // 城市
	District      string        `json:"district"`       // 区县
	Latitude      float64       `json:"latitude"`       // 纬度
	Longitude     float64       `json:"longitude"`      // 经度
	ISP           string        `json:"isp"`            // 运营商
	ISPType       string        `json:"isp_type"`       // 运营商类型
	ASN           string        `json:"asn"`            // 自治系统号
	ASOrg         string        `json:"as_org"`         // AS组织
	Timezone      string        `json:"timezone"`       // 时区
	ZipCode       string        `json:"zip_code"`       // 邮编
	Mobile        bool          `json:"mobile"`         // 是否移动运营商
	Proxy         bool          `json:"proxy"`          // 是否代理/VPN
	Hosting       bool          `json:"hosting"`        // 是否托管/数据中心
	AbuseVelocity AbuseVelocity `json:"abuse_velocity"` // 滥用速度评分
	RiskLevel     RiskLevel     `json:"risk_level"`     // 风险等级
	CreatedAt     time.Time     `json:"created_at"`
	UpdatedAt     time.Time     `json:"updated_at"`
}

// AbuseVelocity 滥用速度评分
type AbuseVelocity struct {
	Score        int       `json:"score"`         // 0-100 评分
	RecentAbuses int       `json:"recent_abuses"` // 最近滥用次数
	LastAbuse    time.Time `json:"last_abuse"`    // 最近滥用时间
}

// RiskLevel 风险等级
type RiskLevel string

const (
	RiskLow      RiskLevel = "low"
	RiskMedium   RiskLevel = "medium"
	RiskHigh     RiskLevel = "high"
	RiskCritical RiskLevel = "critical"
)

// LibraryInfo 库信息
type LibraryInfo struct {
	Name         string    `json:"name"`
	Version      string    `json:"version"`
	BuildDate    time.Time `json:"build_date"`
	TotalRecords int       `json:"total_records"`
	DatabaseSize int64     `json:"database_size"`
}

// ProfessionalIPLib 专业IP库实现
type ProfessionalIPLib struct {
	mu       sync.RWMutex
	database map[string]*IPInfo // IP段 -> 信息
	ipv4Mask int
	ipv6Mask int
	info     *LibraryInfo
}

// NewProfessionalIPLib 创建专业IP库
func NewProfessionalIPLib() *ProfessionalIPLib {
	return &ProfessionalIPLib{
		database: make(map[string]*IPInfo),
		ipv4Mask: 24,
		ipv6Mask: 48,
	}
}

// Init 初始化IP库
func (lib *ProfessionalIPLib) Init(databasePath string) error {
	lib.mu.Lock()
	defer lib.mu.Unlock()

	// 加载IP数据库文件
	// 支持格式：CSV, JSON, MMDB
	if err := lib.loadDatabase(databasePath); err != nil {
		return fmt.Errorf("加载IP数据库失败: %w", err)
	}

	lib.info = &LibraryInfo{
		Name:         "Professional IP Database",
		Version:      "2.0.0",
		BuildDate:    time.Now(),
		TotalRecords: len(lib.database),
	}

	return nil
}

// loadDatabase 加载数据库文件
func (lib *ProfessionalIPLib) loadDatabase(path string) error {
	// 支持格式：CSV, JSON, MMDB
	// 检测文件格式并加载
	switch {
	case strings.HasSuffix(path, ".csv"):
		return lib.loadCSV(path)
	case strings.HasSuffix(path, ".json"):
		return lib.loadJSON(path)
	case strings.HasSuffix(path, ".mmdb"):
		return lib.loadMMDB(path)
	default:
		// 默认使用示例数据
		return lib.loadDefaultData()
	}
}

// loadCSV 加载CSV格式数据库
func (lib *ProfessionalIPLib) loadCSV(path string) error {
	// CSV格式：ip_start,ip_end,country,region,city,isp,asn
	// 实际实现需要读取文件并解析
	// 这里使用默认数据作为占位
	return lib.loadDefaultData()
}

// loadJSON 加载JSON格式数据库
func (lib *ProfessionalIPLib) loadJSON(path string) error {
	// JSON格式：[{ip_range: {...}, info: {...}}]
	// 实际实现需要读取文件并解析
	return lib.loadDefaultData()
}

// loadMMDB 加载MMDB格式数据库
func (lib *ProfessionalIPLib) loadMMDB(path string) error {
	// 打开MaxMind数据库
	db, err := maxminddb.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open MaxMind database: %w", err)
	}
	defer db.Close()

	// 获取数据库元数据
	metadata := db.Metadata
	lib.info = &LibraryInfo{
		Name:         "MaxMind GeoIP2",
		DatabaseSize: int64(metadata.BinaryFormatMajorVersion),
		TotalRecords: int(metadata.NodeCount),
		Version:      fmt.Sprintf("%s.%s", metadata.DatabaseType, metadata.Description["en"]),
	}

	if metadata.BuildEpoch > 0 {
		lib.info.BuildDate = time.Unix(int64(metadata.BuildEpoch), 0)
	}

	// 注意：MaxMind DB是高效的二进制格式，不需要全部加载到内存
	// 我们在Query时直接查询数据库，而不是预加载
	// 这里只是标记数据库已加载，保存数据库路径
	lib.database["__maxmind_mmdb_path__"] = &IPInfo{
		IP:        path,
		Country:   "MaxMind",
		RiskLevel: RiskLow,
	}

	return nil
}

// loadDefaultData 加载默认数据
func (lib *ProfessionalIPLib) loadDefaultData() error {
	sampleData := map[string]*IPInfo{
		"192.168.0.0/24": {
			IP:          "192.168.0.0",
			Country:     "中国",
			CountryCode: "CN",
			Region:      "北京",
			City:        "北京",
			ISP:         "阿里云",
			ISPType:     "云计算",
			ASN:         "AS37963",
			ASOrg:       "Hangzhou Alibaba Advertising Co.,Ltd.",
			Mobile:      false,
			Proxy:       false,
			Hosting:     true,
			RiskLevel:   RiskLow,
		},
		"10.0.0.0/8": {
			IP:          "10.0.0.0",
			Country:     "中国",
			CountryCode: "CN",
			Region:      "上海",
			City:        "上海",
			ISP:         "腾讯云",
			ISPType:     "云计算",
			ASN:         "AS45090",
			ASOrg:       "Shenzhen Tencent Computer Systems Company Limited",
			Mobile:      false,
			Proxy:       false,
			Hosting:     true,
			RiskLevel:   RiskLow,
		},
		"172.16.0.0/12": {
			IP:          "172.16.0.0",
			Country:     "美国",
			CountryCode: "US",
			Region:      "加利福尼亚",
			City:        "旧金山",
			ISP:         "AWS",
			ISPType:     "云计算",
			ASN:         "AS16509",
			ASOrg:       "Amazon.com, Inc.",
			Mobile:      false,
			Proxy:       false,
			Hosting:     true,
			RiskLevel:   RiskLow,
		},
		"114.114.114.0/24": {
			IP:          "114.114.114.0",
			Country:     "中国",
			CountryCode: "CN",
			Region:      "江苏",
			City:        "南京",
			ISP:         "电信",
			ISPType:     "电信运营商",
			ASN:         "AS4134",
			ASOrg:       "Chinanet",
			Mobile:      false,
			Proxy:       false,
			Hosting:     false,
			RiskLevel:   RiskLow,
		},
		"8.8.8.0/24": {
			IP:          "8.8.8.0",
			Country:     "美国",
			CountryCode: "US",
			Region:      "加利福尼亚",
			City:        "山景城",
			ISP:         "Google",
			ISPType:     "科技公司",
			ASN:         "AS15169",
			ASOrg:       "Google LLC",
			Mobile:      false,
			Proxy:       false,
			Hosting:     true,
			RiskLevel:   RiskLow,
		},
	}

	for ipRange, info := range sampleData {
		lib.database[ipRange] = info
	}

	return nil
}

// Query 查询单个IP信息
func (lib *ProfessionalIPLib) Query(ip net.IP) (*IPInfo, error) {
	lib.mu.RLock()
	defer lib.mu.RUnlock()

	// 转换为字符串
	ipStr := ip.String()

	// 查询精确IP
	if info, ok := lib.database[ipStr]; ok {
		return info, nil
	}

	// 查询MaxMind数据库
	if mmdbPathInfo, ok := lib.database["__maxmind_mmdb_path__"]; ok {
		if info := lib.queryMaxMindDB(mmdbPathInfo.IP, ip); info != nil {
			return info, nil
		}
	}

	// 查询IP段
	ipMask := lib.getIPMask(ip)
	if info, ok := lib.database[ipMask]; ok {
		return info, nil
	}

	// 返回默认未知信息
	return &IPInfo{
		IP:          ipStr,
		Country:     "未知",
		CountryCode: "XX",
		RiskLevel:   RiskMedium,
	}, nil
}

// queryMaxMindDB 查询MaxMind数据库
func (lib *ProfessionalIPLib) queryMaxMindDB(dbPath string, ip net.IP) *IPInfo {
	// 打开MaxMind数据库
	db, err := maxminddb.Open(dbPath)
	if err != nil {
		return nil
	}
	defer db.Close()

	// 查询IP信息
	var record struct {
		Country struct {
			IsoCode string `maxminddb:"iso_code"`
			Names   struct {
				ZhCN string `maxminddb:"zh-CN"`
				En   string `maxminddb:"en"`
			} `maxminddb:"names"`
		} `maxminddb:"country"`
		Subdivisions []struct {
			IsoCode string `maxminddb:"iso_code"`
			Names   struct {
				ZhCN string `maxminddb:"zh-CN"`
				En   string `maxminddb:"en"`
			} `maxminddb:"names"`
		} `maxminddb:"subdivisions"`
		City struct {
			Names struct {
				ZhCN string `maxminddb:"zh-CN"`
				En   string `maxminddb:"en"`
			} `maxminddb:"names"`
		} `maxminddb:"city"`
		Location struct {
			Latitude  float64 `maxminddb:"latitude"`
			Longitude float64 `maxminddb:"longitude"`
			TimeZone  string  `maxminddb:"time_zone"`
		} `maxminddb:"location"`
		Traits struct {
			IsAnonymousProxy    bool `maxminddb:"is_anonymous_proxy"`
			IsSatelliteProvider bool `maxminddb:"is_satellite_provider"`
		} `maxminddb:"traits"`
	}

	err = db.Lookup(ip, &record)
	if err != nil {
		return nil
	}

	// 构建IPInfo
	info := &IPInfo{
		IP:          ip.String(),
		CountryCode: record.Country.IsoCode,
		Latitude:    record.Location.Latitude,
		Longitude:   record.Location.Longitude,
		Timezone:    record.Location.TimeZone,
		Proxy:       record.Traits.IsAnonymousProxy,
		Hosting:     record.Traits.IsSatelliteProvider,
		RiskLevel:   RiskLow,
	}

	// 设置国家名称
	if record.Country.Names.ZhCN != "" {
		info.Country = record.Country.Names.ZhCN
	} else if record.Country.Names.En != "" {
		info.Country = record.Country.Names.En
	}

	// 设置省份/地区
	if len(record.Subdivisions) > 0 {
		if record.Subdivisions[0].Names.ZhCN != "" {
			info.Region = record.Subdivisions[0].Names.ZhCN
		} else if record.Subdivisions[0].Names.En != "" {
			info.Region = record.Subdivisions[0].Names.En
		}
	}

	// 设置城市
	if record.City.Names.ZhCN != "" {
		info.City = record.City.Names.ZhCN
	} else if record.City.Names.En != "" {
		info.City = record.City.Names.En
	}

	return info
}

// BatchQuery 批量查询IP信息
func (lib *ProfessionalIPLib) BatchQuery(ips []net.IP) map[string]*IPInfo {
	result := make(map[string]*IPInfo)
	for _, ip := range ips {
		info, _ := lib.Query(ip)
		result[ip.String()] = info
	}
	return result
}

// GetLibraryInfo 获取库信息
func (lib *ProfessionalIPLib) GetLibraryInfo() *LibraryInfo {
	return lib.info
}

// getIPMask 获取IP对应的网段
func (lib *ProfessionalIPLib) getIPMask(ip net.IP) string {
	if ip.To4() != nil {
		return fmt.Sprintf("%s/%d", ip.Mask(net.CIDRMask(lib.ipv4Mask, 32)), lib.ipv4Mask)
	}
	return fmt.Sprintf("%s/%d", ip.Mask(net.CIDRMask(lib.ipv6Mask, 128)), lib.ipv6Mask)
}

// ParseIPRange 解析IP段
func ParseIPRange(ipRange string) (net.IP, net.IP, error) {
	// 格式: "192.168.1.0/24" 或 "192.168.1.0 - 192.168.1.255"
	ip, ipNet, err := net.ParseCIDR(ipRange)
	if err != nil {
		return nil, nil, err
	}
	maskSize, _ := ipNet.Mask.Size()
	return ip, ip.Mask(net.CIDRMask(maskSize, 32)), nil
}

// IPLookupResult IP查询结果
type IPLookupResult struct {
	Success   bool      `json:"success"`
	IP        string    `json:"ip"`
	Info      *IPInfo   `json:"info"`
	QueryTime time.Time `json:"query_time"`
	CacheHit  bool      `json:"cache_hit"`
}

// ToJSON 转换为JSON
func (r *IPLookupResult) ToJSON() (string, error) {
	data, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
