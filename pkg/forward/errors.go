package forward

import "errors"

var (
	// 集群相关错误
	ErrClusterAlreadyExists = errors.New("cluster already exists")
	ErrClusterNotFound      = errors.New("cluster not found")

	// 后端相关错误
	ErrNoBackends          = errors.New("no backends available")
	ErrNoHealthyBackends   = errors.New("no healthy backends available")

	// 连接池相关错误
	ErrPoolClosed = errors.New("connection pool is closed")
	ErrPoolFull   = errors.New("connection pool is full")
)
