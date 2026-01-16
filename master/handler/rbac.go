package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// 角色常量定义
const (
	RoleSuperAdmin = "super_admin" // 超级管理员 - 拥有所有权限
	RoleAdmin      = "admin"       // 管理员 - 管理所有资源
	RoleOperator   = "operator"    // 操作员 - 可以执行操作但不能管理用户
	RoleViewer     = "viewer"      // 查看者 - 只读权限
)

// 权限常量定义
const (
	PermissionNodesView    = "nodes:view"
	PermissionNodesManage  = "nodes:manage"
	PermissionNodesDeploy  = "nodes:deploy"
	PermissionConfigsView  = "configs:view"
	PermissionConfigsManage = "configs:manage"
	PermissionCommandsView = "commands:view"
	PermissionCommandsExec = "commands:exec"
	PermissionMetricsView  = "metrics:view"
	PermissionAlertsView   = "alerts:view"
	PermissionAlertsManage = "alerts:manage"
	PermissionUsersView    = "users:view"
	PermissionUsersManage  = "users:manage"
	PermissionSystemView   = "system:view"
	PermissionSystemManage = "system:manage"
)

// 角色权限映射
var rolePermissions = map[string][]string{
	RoleSuperAdmin: {
		PermissionNodesView, PermissionNodesManage, PermissionNodesDeploy,
		PermissionConfigsView, PermissionConfigsManage,
		PermissionCommandsView, PermissionCommandsExec,
		PermissionMetricsView,
		PermissionAlertsView, PermissionAlertsManage,
		PermissionUsersView, PermissionUsersManage,
		PermissionSystemView, PermissionSystemManage,
	},
	RoleAdmin: {
		PermissionNodesView, PermissionNodesManage, PermissionNodesDeploy,
		PermissionConfigsView, PermissionConfigsManage,
		PermissionCommandsView, PermissionCommandsExec,
		PermissionMetricsView,
		PermissionAlertsView, PermissionAlertsManage,
		PermissionUsersView, PermissionUsersManage,
		PermissionSystemView, PermissionSystemManage,
	},
	RoleOperator: {
		PermissionNodesView, PermissionNodesDeploy,
		PermissionConfigsView,
		PermissionCommandsView, PermissionCommandsExec,
		PermissionMetricsView,
		PermissionAlertsView,
	},
	RoleViewer: {
		PermissionNodesView,
		PermissionConfigsView,
		PermissionMetricsView,
		PermissionAlertsView,
	},
}

// HasPermission 检查用户是否拥有指定权限
func HasPermission(c *gin.Context, permission string) bool {
	role, exists := c.Get("user_role")
	if !exists {
		return false
	}

	roleStr, ok := role.(string)
	if !ok {
		return false
	}

	permissions, ok := rolePermissions[roleStr]
	if !ok {
		return false
	}

	for _, p := range permissions {
		if p == permission {
			return true
		}
	}

	return false
}

// RequirePermission 权限检查中间件
func RequirePermission(permission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !HasPermission(c, permission) {
			c.JSON(http.StatusForbidden, gin.H{
				"error":   "insufficient_permissions",
				"message": "You don't have permission to access this resource",
				"required": permission,
			})
			c.Abort()
			return
		}
		c.Next()
	}
}

// RequireAnyPermission 检查用户是否拥有任一指定权限
func RequireAnyPermission(permissions ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		for _, permission := range permissions {
			if HasPermission(c, permission) {
				c.Next()
				return
			}
		}
		c.JSON(http.StatusForbidden, gin.H{
			"error":   "insufficient_permissions",
			"message": "You don't have permission to access this resource",
			"required": permissions,
		})
		c.Abort()
	}
}

// RequireAllPermissions 检查用户是否拥有所有指定权限
func RequireAllPermissions(permissions ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		for _, permission := range permissions {
			if !HasPermission(c, permission) {
				c.JSON(http.StatusForbidden, gin.H{
					"error":   "insufficient_permissions",
					"message": "You don't have permission to access this resource",
					"required": permission,
				})
				c.Abort()
				return
			}
		}
		c.Next()
	}
}

// RequireRole 角色检查中间件 - 检查用户是否拥有指定角色或更高角色
func RequireRole(requiredRole string) gin.HandlerFunc {
	return func(c *gin.Context) {
		role, exists := c.Get("user_role")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "unauthorized",
				"message": "Authentication required",
			})
			c.Abort()
			return
		}

		roleStr, ok := role.(string)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "invalid_role",
				"message": "Invalid role format",
			})
			c.Abort()
			return
		}

		if !hasRole(roleStr, requiredRole) {
			c.JSON(http.StatusForbidden, gin.H{
				"error":   "insufficient_role",
				"message": "Insufficient role privileges",
				"required": requiredRole,
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// hasRole 检查角色等级 - 更高等级的角色包含低等级角色的权限
func hasRole(userRole, requiredRole string) bool {
	roleHierarchy := map[string]int{
		RoleSuperAdmin: 100,
		RoleAdmin:      80,
		RoleOperator:   60,
		RoleViewer:     40,
	}

	userLevel, userOk := roleHierarchy[userRole]
	requiredLevel, requiredOk := roleHierarchy[requiredRole]

	if !userOk || !requiredOk {
		// 如果角色不在层级中，直接比较是否相等
		return userRole == requiredRole
	}

	return userLevel >= requiredLevel
}

// GetUserID 获取当前用户ID
func GetUserID(c *gin.Context) string {
	if userID, exists := c.Get("user_id"); exists {
		if id, ok := userID.(string); ok {
			return id
		}
	}
	return ""
}

// GetUserRole 获取当前用户角色
func GetUserRole(c *gin.Context) string {
	if role, exists := c.Get("user_role"); exists {
		if r, ok := role.(string); ok {
			return r
		}
	}
	return ""
}

// GetUserClaims 获取当前用户的所有claims
func GetUserClaims(c *gin.Context) map[string]interface{} {
	if claims, exists := c.Get("token_claims"); exists {
		if c, ok := claims.(map[string]interface{}); ok {
			return c
		}
	}
	return nil
}

// IsSuperAdmin 检查是否为超级管理员
func IsSuperAdmin(c *gin.Context) bool {
	return GetUserRole(c) == RoleSuperAdmin
}

// IsAdmin 检查是否为管理员或更高角色
func IsAdmin(c *gin.Context) bool {
	role := GetUserRole(c)
	return role == RoleSuperAdmin || role == RoleAdmin
}

// RateLimitOptions 速率限制选项
type RateLimitOptions struct {
	RequestsPerMinute int
	RequestsPerHour   int
	Burst            int
}

// DefaultRateLimitOptions 默认速率限制选项
var DefaultRateLimitOptions = RateLimitOptions{
	RequestsPerMinute: 60,
	RequestsPerHour:   1000,
	Burst:            10,
}
