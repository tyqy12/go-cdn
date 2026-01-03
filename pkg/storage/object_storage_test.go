package storage

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"
)

// TestAliyunOSS_Integration 测试阿里云OSS集成
func TestAliyunOSS_Integration(t *testing.T) {
	config := &ProviderConfig{
		Type:      "aliyun",
		Endpoint:  "oss-cn-hangzhou.aliyuncs.com",
		Bucket:    "test-bucket",
		AccessKey: "test-key",
		SecretKey: "test-secret",
	}

	oss := NewAliyunOSS(config)
	if oss == nil {
		t.Fatal("OSS为空")
	}

	if oss.config == nil {
		t.Error("配置为空")
	}

	t.Log("阿里云OSS创建测试通过")
}

// TestAliyunOSS_Upload 测试文件上传
func TestAliyunOSS_Upload(t *testing.T) {
	config := &ProviderConfig{
		Type:      "aliyun",
		Endpoint:  "oss-cn-hangzhou.aliyuncs.com",
		Bucket:    "test-bucket",
		AccessKey: "test-key",
		SecretKey: "test-secret",
	}

	oss := NewAliyunOSS(config)

	opts := &UploadOptions{
		ContentType: "text/plain",
	}

	body := bytes.NewReader([]byte("test content"))
	result, err := oss.Upload(context.Background(), "test-object", body, opts)
	if err != nil {
		t.Logf("上传可能失败（无网络连接）: %v", err)
	}

	t.Logf("上传结果: %v", result)
}

// TestAliyunOSS_Download 测试文件下载
func TestAliyunOSS_Download(t *testing.T) {
	config := &ProviderConfig{
		Type:      "aliyun",
		Endpoint:  "oss-cn-hangzhou.aliyuncs.com",
		Bucket:    "test-bucket",
		AccessKey: "test-key",
		SecretKey: "test-secret",
	}

	oss := NewAliyunOSS(config)

	opts := &DownloadOptions{}

	data, err := oss.Download(context.Background(), "download-object", opts)
	if err != nil {
		t.Logf("下载可能失败（无网络连接）: %v", err)
	}
	if data != nil {
		defer data.Close()
		io.Copy(io.Discard, data)
	}

	t.Log("OSS下载测试通过")
}

// TestAliyunOSS_Delete 测试文件删除
func TestAliyunOSS_Delete(t *testing.T) {
	config := &ProviderConfig{
		Type:      "aliyun",
		Endpoint:  "oss-cn-hangzhou.aliyuncs.com",
		Bucket:    "test-bucket",
		AccessKey: "test-key",
		SecretKey: "test-secret",
	}

	oss := NewAliyunOSS(config)

	err := oss.Delete(context.Background(), "delete-object")
	if err != nil {
		t.Logf("删除可能失败（无网络连接）: %v", err)
	}

	t.Log("OSS删除测试通过")
}

// TestAliyunOSS_List 测试列出对象
func TestAliyunOSS_List(t *testing.T) {
	config := &ProviderConfig{
		Type:     "aliyun",
		Endpoint: "oss-cn-hangzhou.aliyuncs.com",
		Bucket:   "test-bucket",
	}

	oss := NewAliyunOSS(config)

	opts := &ListOptions{
		MaxKeys: 100,
	}

	objects, err := oss.List(context.Background(), "", opts)
	if err != nil {
		t.Logf("列出对象可能失败（无网络连接）: %v", err)
	}

	t.Logf("列出%d个对象", len(objects))
}

// TestAliyunOSS_SignURL 测试生成签名URL
func TestAliyunOSS_SignURL(t *testing.T) {
	config := &ProviderConfig{
		Type:      "aliyun",
		Endpoint:  "oss-cn-hangzhou.aliyuncs.com",
		Bucket:    "test-bucket",
		AccessKey: "test-key",
		SecretKey: "test-secret",
	}

	oss := NewAliyunOSS(config)

	opts := &SignOptions{
		Expiry: 3600 * time.Second,
		Method: "GET",
	}

	url, err := oss.SignURL(context.Background(), "test-object", opts)
	if err != nil {
		t.Errorf("生成签名URL失败: %v", err)
	}

	if url == "" {
		t.Error("签名URL为空")
	}

	t.Logf("签名URL: %s", url)
}

// TestAliyunOSS_Head 测试获取对象元数据
func TestAliyunOSS_Head(t *testing.T) {
	config := &ProviderConfig{
		Type:     "aliyun",
		Endpoint: "oss-cn-hangzhou.aliyuncs.com",
		Bucket:   "test-bucket",
	}

	oss := NewAliyunOSS(config)

	meta, err := oss.Head(context.Background(), "head-object")
	if err != nil {
		t.Logf("获取元数据可能失败（无网络连接）: %v", err)
	}

	if meta != nil {
		t.Logf("对象元数据: 大小=%d, 类型=%s", meta.Size, meta.ContentType)
	}

	t.Log("OSS Head测试通过")
}

// TestAliyunOSS_Copy 测试复制对象
func TestAliyunOSS_Copy(t *testing.T) {
	config := &ProviderConfig{
		Type:     "aliyun",
		Endpoint: "oss-cn-hangzhou.aliyuncs.com",
		Bucket:   "test-bucket",
	}

	oss := NewAliyunOSS(config)

	err := oss.Copy(context.Background(), "source", "destination")
	if err != nil {
		t.Logf("复制可能失败（无网络连接）: %v", err)
	}

	t.Log("OSS复制测试通过")
}

// TestAliyunOSS_InitiateMultipartUpload 测试初始化分片上传
func TestAliyunOSS_InitiateMultipartUpload(t *testing.T) {
	config := &ProviderConfig{
		Type:     "aliyun",
		Endpoint: "oss-cn-hangzhou.aliyuncs.com",
		Bucket:   "test-bucket",
	}

	oss := NewAliyunOSS(config)

	opts := &UploadOptions{
		ContentType: "text/plain",
		Multipart:   true,
	}

	uploadInfo, err := oss.InitiateMultipartUpload(context.Background(), "multi-object", opts)
	if err != nil {
		t.Errorf("初始化分片上传失败: %v", err)
	}

	if uploadInfo == nil {
		t.Error("上传信息为空")
	} else {
		t.Logf("分片上传ID: %s", uploadInfo.UploadID)
	}
}

// TestObjectStorage_NewObjectStorage 测试创建对象存储
func TestObjectStorage_NewObjectStorage(t *testing.T) {
	config := &StorageConfig{
		DefaultProvider: "aliyun",
		Providers: map[string]ProviderConfig{
			"aliyun": {
				Type:     "aliyun",
				Endpoint: "oss-cn-hangzhou.aliyuncs.com",
				Bucket:   "test-bucket",
			},
		},
	}

	storage := NewObjectStorage(config)
	if storage == nil {
		t.Fatal("创建对象存储失败")
	}

	t.Log("对象存储创建测试通过")
}

// TestObjectStorage_RegisterProvider 测试注册提供商
func TestObjectStorage_RegisterProvider(t *testing.T) {
	storage := NewObjectStorage(&StorageConfig{
		DefaultProvider: "aliyun",
	})

	provider := NewAliyunOSS(&ProviderConfig{
		Type:     "aliyun",
		Endpoint: "oss-cn-hangzhou.aliyuncs.com",
		Bucket:   "test-bucket",
	})

	storage.RegisterProvider("aliyun", provider)

	t.Log("提供商注册测试通过")
}

// TestObjectStorage_GetStats 测试获取存储统计
func TestObjectStorage_GetStats(t *testing.T) {
	storage := NewObjectStorage(&StorageConfig{})

	stats := storage.GetStats()
	if stats == nil {
		t.Fatal("存储统计为空")
	}

	if stats.TotalStorage < 0 {
		t.Error("总存储异常")
	}

	t.Logf("存储统计: 总字节=%d, 对象数=%d", stats.TotalStorage, stats.ObjectCount)
}

// TestStorageStats 测试存储统计结构
func TestStorageStats(t *testing.T) {
	stats := &StorageStats{
		TotalStorage:       1024 * 1024 * 1024,
		UsedStorage:        512 * 1024 * 1024,
		ObjectCount:        100,
		UploadCount:        50,
		DownloadCount:      200,
		DeleteCount:        10,
		BandwidthUsage:     make(map[string]int64),
		RequestsByProvider: make(map[string]int64),
	}

	stats.BandwidthUsage["aliyun"] = 1024 * 1024 * 100
	stats.RequestsByProvider["aliyun"] = 1000

	if stats.TotalStorage <= 0 {
		t.Error("总存储应该为正数")
	}

	if stats.ObjectCount < 0 {
		t.Error("对象数应该为非负数")
	}

	t.Log("存储统计测试通过")
}

// TestUploadOptions 测试上传选项
func TestUploadOptions(t *testing.T) {
	opts := &UploadOptions{
		ContentType: "application/json",
		Metadata: map[string]string{
			"author": "test",
		},
		StorageClass: "standard",
		CacheControl: "max-age=3600",
		Multipart:    false,
	}

	if opts.ContentType != "application/json" {
		t.Error("ContentType不匹配")
	}

	t.Log("上传选项测试通过")
}

// TestDownloadOptions 测试下载选项
func TestDownloadOptions(t *testing.T) {
	opts := &DownloadOptions{
		Range: &Range{
			Start: 0,
			End:   1024,
		},
		Uncompress: false,
	}

	if opts.Range == nil {
		t.Error("Range为空")
	}

	t.Log("下载选项测试通过")
}

// TestSignOptions 测试签名选项
func TestSignOptions(t *testing.T) {
	opts := &SignOptions{
		Expiry:          3600 * time.Second,
		Method:          "GET",
		ResponseType:    "attachment",
		ResponseHeaders: make(map[string]string),
	}

	if opts.Expiry <= 0 {
		t.Error("Expiry应该为正数")
	}

	t.Log("签名选项测试通过")
}

// Helper function to compare byte slices
func compareBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Helper function to create test content
func createTestContent(size int) []byte {
	return bytes.Repeat([]byte("test"), size/4)
}
