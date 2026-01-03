package tlsutil

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
)

// TLSCertManager TLS证书管理器
type TLSCertManager struct {
	caCert     *x509.Certificate
	caKey      *rsa.PrivateKey
	certExpiry time.Duration
}

// TLSCertConfig TLS证书配置
type TLSCertConfig struct {
	CommonName   string
	Organization string
	ValidFrom    time.Time
	ValidFor     time.Duration
	EmailAddress string
	IPAddresses  []string
	DNSNames     []string
	IsCA         bool
	KeyUsage     x509.KeyUsage
	ExtKeyUsage  []x509.ExtKeyUsage
}

// DefaultConfig 默认证书配置
func DefaultConfig() *TLSCertConfig {
	return &TLSCertConfig{
		CommonName:   "gocdn",
		Organization: "GoCDN",
		ValidFrom:    time.Now(),
		ValidFor:     365 * 24 * time.Hour,
		IsCA:         false,
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
}

// NewTLSCertManager 创建TLS证书管理器
func NewTLSCertManager() *TLSCertManager {
	return &TLSCertManager{
		certExpiry: 365 * 24 * time.Hour,
	}
}

// GenerateCA 生成CA证书
func (m *TLSCertManager) GenerateCA(cfg *TLSCertConfig) (tls.Certificate, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	cfg.IsCA = true
	cfg.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	cfg.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}

	// 生成CA密钥
	caKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("生成CA密钥失败: %v", err)
	}

	// 生成CA证书
	orgs := make([]string, 0, 1)
	if cfg.Organization != "" {
		orgs = append(orgs, cfg.Organization)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:         cfg.CommonName + " CA",
			Organization:       orgs,
			OrganizationalUnit: []string{"Certificate Authority"},
		},
		NotBefore:             cfg.ValidFrom,
		NotAfter:              cfg.ValidFrom.Add(cfg.ValidFor),
		KeyUsage:              cfg.KeyUsage,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
		IPAddresses:           parseIPs(cfg.IPAddresses),
		DNSNames:              cfg.DNSNames,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &caKey.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("生成CA证书失败: %v", err)
	}

	// 保存CA证书和密钥
	m.caCert = &template
	m.caKey = caKey

	// 返回PEM格式的证书
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(caKey)})

	return tls.X509KeyPair(certPEM, keyPEM)
}

// GenerateCert 生成服务端/客户端证书
func (m *TLSCertManager) GenerateCert(cfg *TLSCertConfig) (tls.Certificate, error) {
	if m.caCert == nil || m.caKey == nil {
		return tls.Certificate{}, fmt.Errorf("CA证书未初始化")
	}

	if cfg == nil {
		cfg = DefaultConfig()
	}

	// 生成密钥
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("生成密钥失败: %v", err)
	}

	// 生成证书模板
	orgs := make([]string, 0, 1)
	if cfg.Organization != "" {
		orgs = append(orgs, cfg.Organization)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:         cfg.CommonName,
			Organization:       orgs,
			OrganizationalUnit: []string{"GoCDN"},
		},
		NotBefore:             cfg.ValidFrom,
		NotAfter:              cfg.ValidFrom.Add(cfg.ValidFor),
		KeyUsage:              cfg.KeyUsage,
		ExtKeyUsage:           cfg.ExtKeyUsage,
		BasicConstraintsValid: true,
		IPAddresses:           parseIPs(cfg.IPAddresses),
		DNSNames:              cfg.DNSNames,
	}

	// 使用CA签名
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, m.caCert, &key.PublicKey, m.caKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("生成证书失败: %v", err)
	}

	// 返回PEM格式的证书
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	return tls.X509KeyPair(certPEM, keyPEM)
}

// LoadCertFromFile 从文件加载证书
func LoadCertFromFile(certFile, keyFile string) (tls.Certificate, error) {
	return tls.LoadX509KeyPair(certFile, keyFile)
}

// LoadCertFromPEM 从PEM字符串加载证书
func LoadCertFromPEM(certPEM, keyPEM string) (tls.Certificate, error) {
	return tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
}

// SaveCertToFile 保存证书到文件
func SaveCertToFile(cert tls.Certificate, certFile, keyFile string) error {
	// 保存证书
	certOut, err := os.Create(certFile)
	if err != nil {
		return fmt.Errorf("创建证书文件失败: %v", err)
	}
	defer certOut.Close()

	for _, cert := range cert.Certificate {
		if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert}); err != nil {
			return fmt.Errorf("写入证书失败: %v", err)
		}
	}

	// 保存私钥
	keyOut, err := os.Create(keyFile)
	if err != nil {
		return fmt.Errorf("创建密钥文件失败: %v", err)
	}
	defer keyOut.Close()

	keyBytes, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return fmt.Errorf("序列化私钥失败: %v", err)
	}

	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}); err != nil {
		return fmt.Errorf("写入私钥失败: %v", err)
	}

	return nil
}

// GetCACertPool 获取CA证书池
func (m *TLSCertManager) GetCACertPool() (*x509.CertPool, error) {
	if m.caCert == nil {
		return nil, fmt.Errorf("CA证书未初始化")
	}

	pool := x509.NewCertPool()
	pool.AddCert(m.caCert)
	return pool, nil
}

func parseIPs(values []string) []net.IP {
	ips := make([]net.IP, 0, len(values))
	for _, value := range values {
		if ip := net.ParseIP(value); ip != nil {
			ips = append(ips, ip)
		}
	}
	return ips
}

// CreateServerTLSConfig 创建服务端TLS配置
func CreateServerTLSConfig(cert tls.Certificate, clientAuthType tls.ClientAuthType, caPool *x509.CertPool) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   clientAuthType,
		ClientCAs:    caPool,
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP384,
		},
		NextProtos: []string{"h2", "http/1.1"},
	}
}

// CreateClientTLSConfig 创建客户端TLS配置
func CreateClientTLSConfig(cert tls.Certificate, serverName string, caPool *x509.CertPool) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ServerName:   serverName,
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP384,
		},
	}
}
