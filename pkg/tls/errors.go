package tls

import "errors"

var (
	// ErrCertificateNotFound 证书不存在
	ErrCertificateNotFound = errors.New("certificate not found")
	// ErrCertificateExpired 证书已过期
	ErrCertificateExpired = errors.New("certificate expired")
	// ErrNoDefaultCertificate 无默认证书
	ErrNoDefaultCertificate = errors.New("no default certificate available")
	// ErrInvalidCertificate 证书无效
	ErrInvalidCertificate = errors.New("invalid certificate")
	// ErrCertificateLoadFailed 证书加载失败
	ErrCertificateLoadFailed = errors.New("failed to load certificate")
)
