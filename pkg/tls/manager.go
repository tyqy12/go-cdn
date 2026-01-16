package tls

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"sync"
	"time"

	"github.com/go-gost/core/logger"
)

// CertManager 证书管理器
type CertManager struct {
	mu          sync.RWMutex
	certs       map[string]*tls.Certificate
	logger      logger.Logger
	autoRenewal bool
	renewalChan chan *tls.Certificate
	stopCh      chan struct{}
	wg          sync.WaitGroup
}

// CertificateInfo 证书信息
type CertificateInfo struct {
	Domain       string
	NotBefore    time.Time
	NotAfter     time.Time
	Issuer       string
	Subject      string
	SerialNumber string
}

// NewCertManager 创建证书管理器
func NewCertManager(opts ...Option) *CertManager {
	m := &CertManager{
		certs:       make(map[string]*tls.Certificate),
		logger:      logger.Default(),
		autoRenewal: false,
		renewalChan: make(chan *tls.Certificate, 10),
		stopCh:      make(chan struct{}),
	}

	for _, opt := range opts {
		opt(m)
	}

	return m
}

// Option 选项
type Option func(*CertManager)

// WithLogger 设置日志
func WithLogger(l logger.Logger) Option {
	return func(m *CertManager) {
		m.logger = l
	}
}

// WithAutoRenewal 启用自动续期
func WithAutoRenewal(enabled bool) Option {
	return func(m *CertManager) {
		m.autoRenewal = enabled
	}
}

// LoadCertificate 加载证书
func (m *CertManager) LoadCertificate(domain, certFile, keyFile string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("load certificate failed: %w", err)
	}

	m.certs[domain] = &cert
	m.logger.Infof("certificate loaded for domain: %s", domain)
	return nil
}

// LoadCertificateFromMemory 从内存加载证书
func (m *CertManager) LoadCertificateFromMemory(domain string, certPEM, keyPEM []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("parse certificate failed: %w", err)
	}

	m.certs[domain] = &cert
	m.logger.Infof("certificate loaded from memory for domain: %s", domain)
	return nil
}

// GetCertificate 获取证书
func (m *CertManager) GetCertificate(domain string) (*tls.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	cert, ok := m.certs[domain]
	if !ok {
		return nil, ErrCertificateNotFound
	}

	return cert, nil
}

// GetCertificateInfo 获取证书信息
func (m *CertManager) GetCertificateInfo(domain string) (*CertificateInfo, error) {
	cert, err := m.GetCertificate(domain)
	if err != nil {
		return nil, err
	}

	leaf := cert.Leaf
	if leaf == nil {
		var err error
		leaf, err = x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("parse certificate failed: %w", err)
		}
	}

	return &CertificateInfo{
		Domain:       domain,
		NotBefore:    leaf.NotBefore,
		NotAfter:     leaf.NotAfter,
		Issuer:       leaf.Issuer.CommonName,
		Subject:      leaf.Subject.CommonName,
		SerialNumber: leaf.SerialNumber.String(),
	}, nil
}

// RemoveCertificate 移除证书
func (m *CertManager) RemoveCertificate(domain string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.certs[domain]; !ok {
		return ErrCertificateNotFound
	}

	delete(m.certs, domain)
	m.logger.Infof("certificate removed for domain: %s", domain)
	return nil
}

// ListCertificates 列出所有证书
func (m *CertManager) ListCertificates() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	domains := make([]string, 0, len(m.certs))
	for domain := range m.certs {
		domains = append(domains, domain)
	}

	return domains
}

// GenerateSelfSigned 生成自签名证书
func (m *CertManager) GenerateSelfSigned(domain string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 生成 RSA 私钥
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate private key failed: %w", err)
	}

	// 创建证书模板
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"GoCDN"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // 1年有效期
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{domain, "www." + domain},
	}

	// 创建证书
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("create certificate failed: %w", err)
	}

	// 编码私钥
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	// 编码证书
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("create TLS certificate failed: %w", err)
	}

	m.certs[domain] = &cert
	m.logger.Infof("self-signed certificate generated for domain: %s", domain)
	return nil
}

// GetConfig 获取 TLS 配置
func (m *CertManager) GetConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: m.getCertificateFunc(),
		NextProtos:     []string{"h2", "http/1.1"},
		MinVersion:     tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
			tls.X25519,
		},
	}
}

// getCertificateFunc 获取证书函数
func (m *CertManager) getCertificateFunc() func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
		domain := info.ServerName
		if domain == "" {
			// 使用默认证书
			m.mu.RLock()
			for _, cert := range m.certs {
				m.mu.RUnlock()
				return cert, nil
			}
			m.mu.RUnlock()
			return nil, ErrNoDefaultCertificate
		}

		cert, err := m.GetCertificate(domain)
		if err == nil {
			return cert, nil
		}

		// 尝试通配符证书
		m.mu.RLock()
		for d, c := range m.certs {
			if matchWildcard(domain, d) {
				m.mu.RUnlock()
				return c, nil
			}
		}
		m.mu.RUnlock()

		return nil, err
	}
}

// StartAutoRenewal 启动自动续期检查
func (m *CertManager) StartAutoRenewal(ctx context.Context) {
	if !m.autoRenewal {
		return
	}

	m.wg.Add(1)
	go func() {
		defer m.wg.Done()

		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-m.stopCh:
				return
			case <-ticker.C:
				m.checkAndRenew()
			}
		}
	}()

	m.logger.Info("certificate auto-renewal started")
}

// Stop 停止
func (m *CertManager) Stop() {
	close(m.stopCh)
	m.wg.Wait()
	m.logger.Info("certificate manager stopped")
}

// checkAndRenew 检查并续期证书
func (m *CertManager) checkAndRenew() {
	m.mu.RLock()
	domains := make([]string, 0, len(m.certs))
	for domain := range m.certs {
		domains = append(domains, domain)
	}
	m.mu.RUnlock()

	for _, domain := range domains {
		info, err := m.GetCertificateInfo(domain)
		if err != nil {
			m.logger.Warnf("get certificate info for %s failed: %v", domain, err)
			continue
		}

		// 检查是否即将过期（30天内）
		if time.Until(info.NotAfter) < 30*24*time.Hour {
			m.logger.Infof("certificate for %s expires soon, regenerating", domain)
			if err := m.GenerateSelfSigned(domain); err != nil {
				m.logger.Errorf("renew certificate for %s failed: %v", domain, err)
				continue
			}

			// 通知证书已更新
			cert, _ := m.GetCertificate(domain)
			select {
			case m.renewalChan <- cert:
			default:
			}
		}
	}
}

// SaveToFile 保存证书到文件
func (m *CertManager) SaveToFile(domain, certFile, keyFile string) error {
	cert, err := m.GetCertificate(domain)
	if err != nil {
		return err
	}

	// 保存证书
	if err := os.WriteFile(certFile, cert.Certificate[0], 0644); err != nil {
		return fmt.Errorf("write certificate file failed: %w", err)
	}

	// 保存私钥
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(cert.PrivateKey.(*rsa.PrivateKey)),
	})

	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		return fmt.Errorf("write key file failed: %w", err)
	}

	return nil
}

// matchWildcard 通配符匹配
func matchWildcard(domain, pattern string) bool {
	if len(pattern) < 2 || pattern[0] != '*' {
		return false
	}

	pattern = pattern[2:] // 去掉 *. 前缀
	return len(domain) > len(pattern) && domain[len(domain)-len(pattern):] == pattern
}
