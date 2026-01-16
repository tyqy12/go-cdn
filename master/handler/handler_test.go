package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestCORS(t *testing.T) {
	r := gin.New()
	r.Use(CORS())
	r.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("OPTIONS", "/test", nil)
	r.ServeHTTP(w, req)

	if w.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Errorf("Expected Access-Control-Allow-Origin to be *, got %s", w.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestJWTAuth_MissingHeader(t *testing.T) {
	r := gin.New()
	r.Use(JWTAuth("test-secret"))
	r.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestJWTAuth_InvalidFormat(t *testing.T) {
	r := gin.New()
	r.Use(JWTAuth("test-secret"))
	r.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "InvalidFormat token123")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestJWTAuth_ValidToken(t *testing.T) {
	// 创建有效 token 的测试
	r := gin.New()
	secret := "test-secret"

	r.Use(JWTAuth(secret))
	r.GET("/test", func(c *gin.Context) {
		userID, _ := c.Get("user_id")
		c.JSON(http.StatusOK, gin.H{"user_id": userID})
	})

	// 生成测试 token (使用有效的 JWT 格式)
	token := generateTestToken(secret, map[string]interface{}{
		"sub": "test-user",
		"role": "admin",
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}
}

// generateTestToken 生成测试用的 JWT Token
func generateTestToken(secret string, claims map[string]interface{}) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(claims))
	tokenString, _ := token.SignedString([]byte(secret))
	return tokenString
}

func TestHasPermission(t *testing.T) {
	r := gin.New()
	r.Use(JWTAuth("test-secret"))
	r.GET("/test", func(c *gin.Context) {
		// 设置测试角色
		c.Set("user_role", "admin")
		c.JSON(http.StatusOK, gin.H{"has_permission": HasPermission(c, "nodes:view")})
	})

	token := generateTestToken("test-secret", map[string]interface{}{
		"sub":   "test-user",
		"role":  "admin",
		"exp":   9999999999,
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	r.ServeHTTP(w, req)
}

func TestRequirePermission(t *testing.T) {
	r := gin.New()
	r.Use(JWTAuth("test-secret"))
	r.Use(RequirePermission("nodes:manage"))
	r.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})

	// 测试没有权限的情况
	token := generateTestToken("test-secret", map[string]interface{}{
		"sub":   "test-user",
		"role":  "viewer", // viewer 没有 nodes:manage 权限
		"exp":   9999999999,
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status %d, got %d", http.StatusForbidden, w.Code)
	}
}

func TestRequireRole(t *testing.T) {
	r := gin.New()
	r.Use(JWTAuth("test-secret"))
	r.Use(RequireRole("admin"))
	r.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})

	// 测试角色不足
	token := generateTestToken("test-secret", map[string]interface{}{
		"sub":   "test-user",
		"role":  "viewer",
		"exp":   9999999999,
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status %d, got %d", http.StatusForbidden, w.Code)
	}
}

func TestIsAdmin(t *testing.T) {
	r := gin.New()
	r.Use(JWTAuth("test-secret"))
	r.GET("/test", func(c *gin.Context) {
		c.Set("user_role", "admin")
		c.JSON(http.StatusOK, gin.H{"is_admin": IsAdmin(c)})
	})

	token := generateTestToken("test-secret", map[string]interface{}{
		"sub":   "test-user",
		"role":  "admin",
		"exp":   9999999999,
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	r.ServeHTTP(w, req)
}

func TestGetUserID(t *testing.T) {
	r := gin.New()
	r.Use(JWTAuth("test-secret"))
	r.GET("/test", func(c *gin.Context) {
		c.Set("user_id", "user123")
		userID := GetUserID(c)
		if userID != "user123" {
			t.Errorf("Expected user_id 'user123', got '%s'", userID)
		}
		c.JSON(http.StatusOK, gin.H{"user_id": userID})
	})

	token := generateTestToken("test-secret", map[string]interface{}{
		"sub": "user123",
		"exp": 9999999999,
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	r.ServeHTTP(w, req)
}

func TestRolePermissions(t *testing.T) {
	tests := []struct {
		role       string
		permission string
		expected   bool
	}{
		{"super_admin", "nodes:manage", true},
		{"admin", "nodes:manage", true},
		{"operator", "nodes:manage", false},
		{"viewer", "nodes:manage", false},
		{"admin", "users:manage", true},
		{"operator", "users:manage", false},
	}

	for _, tt := range tests {
		t.Run(tt.role+"_"+tt.permission, func(t *testing.T) {
			// 临时修改 rolePermissions 用于测试
			r := gin.New()
			r.Use(JWTAuth("test-secret"))
			r.GET("/test", func(c *gin.Context) {
				c.Set("user_role", tt.role)
				result := HasPermission(c, tt.permission)
				if result != tt.expected {
					t.Errorf("HasPermission(%s, %s) = %v, expected %v",
						tt.role, tt.permission, result, tt.expected)
				}
			})

			token := generateTestToken("test-secret", map[string]interface{}{
				"sub":  "test-user",
				"role": tt.role,
				"exp":  9999999999,
			})

			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/test", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			r.ServeHTTP(w, req)
		})
	}
}
