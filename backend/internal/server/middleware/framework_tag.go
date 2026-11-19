package middleware

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

// FrameworkRoutePrefix 框架接口前缀（领取令牌），API Key 鉴权但跳过计费执行与标识识别。
const FrameworkRoutePrefix = "/framework/v1/"

// IsFrameworkRoute 是否为框架接口。
func IsFrameworkRoute(path string) bool { return strings.HasPrefix(path, FrameworkRoutePrefix) }

// FrameworkTagStatusHeader 响应头：请求带了框架令牌时，告诉框架令牌校验结果（ok / expired / invalid）。
const FrameworkTagStatusHeader = "X-Sub2API-Framework-Tag"

// applyFrameworkTag 识别请求是否来自运营方自己的框架，并把结果写入请求 context。
//
// 请求头 cfg.FrameworkAuth.HeaderName 携带服务端派发的框架令牌（POST /framework/v1/token），
// 令牌属于当前 API Key 及其分组且未过期即视为带标识；分组未配置密钥时一律视为不带标识。
// 校验失败按不带标识处理，不拒绝请求。无论结果如何，都会从请求中删除该请求头，避免透传到上游。
func applyFrameworkTag(c *gin.Context, cfg *config.Config, apiKey *service.APIKey) {
	var authCfg config.FrameworkAuthConfig
	if cfg != nil {
		authCfg = cfg.FrameworkAuth
	}
	headerName := authCfg.EffectiveHeaderName()
	provided := strings.TrimSpace(c.GetHeader(headerName))
	c.Request.Header.Del(headerName)

	var group *service.Group
	var apiKeyID int64
	if apiKey != nil {
		group, apiKeyID = apiKey.Group, apiKey.ID
	}
	tagged := false
	if provided != "" && group != nil && strings.TrimSpace(group.FrameworkTagSecret) != "" {
		err := service.VerifyFrameworkTagToken(group, apiKeyID, provided, time.Now())
		switch {
		case err == nil:
			tagged = true
			c.Header(FrameworkTagStatusHeader, "ok")
		case errors.Is(err, service.ErrFrameworkTagTokenExpired):
			c.Header(FrameworkTagStatusHeader, "expired")
		default:
			c.Header(FrameworkTagStatusHeader, "invalid")
		}
	}
	c.Request = c.Request.WithContext(service.SetFrameworkTagged(c.Request.Context(), tagged))
}

// FrameworkIssueToken 处理 POST /framework/v1/token：为当前 API Key 派发短期框架令牌。
//
// 成功返回 {"token","expires_at","expires_in","header"}；分组未配置框架标识密钥时返回 400 FRAMEWORK_NOT_ENABLED。
func FrameworkIssueToken(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		apiKey, ok := GetAPIKeyFromContext(c)
		if !ok || apiKey == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": gin.H{"code": "INVALID_API_KEY", "message": "Invalid API key"}})
			return
		}
		var authCfg config.FrameworkAuthConfig
		if cfg != nil {
			authCfg = cfg.FrameworkAuth
		}
		ttl := authCfg.EffectiveTokenTTL()
		token, expiresAt, err := service.IssueFrameworkTagToken(apiKey.Group, apiKey.ID, ttl, time.Now())
		if errors.Is(err, service.ErrFrameworkTagSecretMissing) {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "FRAMEWORK_NOT_ENABLED", "message": "framework tag is not enabled for this group"}})
			return
		}
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": gin.H{"code": "FRAMEWORK_TOKEN_FAILED", "message": "failed to issue framework token"}})
			return
		}
		c.Header("Cache-Control", "no-store")
		c.JSON(http.StatusOK, gin.H{
			"token":      token,
			"expires_at": expiresAt.UTC(),
			"expires_in": int64(ttl.Seconds()),
			"header":     authCfg.EffectiveHeaderName(),
		})
	}
}
