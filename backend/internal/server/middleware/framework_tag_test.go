//go:build unit

package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

const testFrameworkHeader = "X-Sub2API-Framework-Token"

func runFrameworkTag(t *testing.T, cfg *config.Config, apiKey *service.APIKey, headerName, headerValue string) (tagged bool, headerLeft string, status string) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/", func(c *gin.Context) {
		applyFrameworkTag(c, cfg, apiKey)
		tagged = service.IsFrameworkTagged(c.Request.Context())
		headerLeft = c.Request.Header.Get(headerName)
		c.Status(http.StatusNoContent)
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if headerValue != "" {
		req.Header.Set(headerName, headerValue)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return tagged, headerLeft, rec.Header().Get(FrameworkTagStatusHeader)
}

func groupWithSecret(id int64, secret string) *service.APIKey {
	return &service.APIKey{ID: 100 + id, Group: &service.Group{ID: id, FrameworkTagSecret: secret}}
}

func issueToken(t *testing.T, k *service.APIKey, ttl time.Duration, now time.Time) string {
	t.Helper()
	tok, _, err := service.IssueFrameworkTagToken(k.Group, k.ID, ttl, now)
	require.NoError(t, err)
	return tok
}

func TestApplyFrameworkTag_ValidTokenTagsAndStripsHeader(t *testing.T) {
	g := groupWithSecret(1, "s3cret")
	tagged, left, status := runFrameworkTag(t, &config.Config{}, g, testFrameworkHeader, issueToken(t, g, time.Hour, time.Now()))
	require.True(t, tagged)
	require.Equal(t, "ok", status)
	require.Empty(t, left, "framework token must not be forwarded upstream")
}

func TestApplyFrameworkTag_RawSecretNoLongerTags(t *testing.T) {
	tagged, left, status := runFrameworkTag(t, &config.Config{}, groupWithSecret(1, "s3cret"), testFrameworkHeader, "s3cret")
	require.False(t, tagged)
	require.Equal(t, "invalid", status)
	require.Empty(t, left)
}

func TestApplyFrameworkTag_ExpiredTokenIsUntagged(t *testing.T) {
	g := groupWithSecret(1, "s3cret")
	tok := issueToken(t, g, time.Hour, time.Now().Add(-2*time.Hour))
	tagged, _, status := runFrameworkTag(t, &config.Config{}, g, testFrameworkHeader, tok)
	require.False(t, tagged)
	require.Equal(t, "expired", status)
}

func TestApplyFrameworkTag_MissingHeaderIsUntagged(t *testing.T) {
	tagged, _, status := runFrameworkTag(t, &config.Config{}, groupWithSecret(1, "s3cret"), testFrameworkHeader, "")
	require.False(t, tagged)
	require.Empty(t, status)
}

func TestApplyFrameworkTag_GroupWithoutSecretNeverTags(t *testing.T) {
	tagged, left, _ := runFrameworkTag(t, &config.Config{}, groupWithSecret(1, ""), testFrameworkHeader, "anything")
	require.False(t, tagged)
	require.Empty(t, left, "header is stripped even when the group has no secret")
}

func TestApplyFrameworkTag_OtherGroupTokenDoesNotTag(t *testing.T) {
	tok := issueToken(t, groupWithSecret(2, "group-b"), time.Hour, time.Now())
	tagged, _, _ := runFrameworkTag(t, &config.Config{}, groupWithSecret(1, "group-a"), testFrameworkHeader, tok)
	require.False(t, tagged)
}

func TestApplyFrameworkTag_CustomHeaderName(t *testing.T) {
	g := groupWithSecret(1, "s3cret")
	cfg := &config.Config{FrameworkAuth: config.FrameworkAuthConfig{HeaderName: "X-My-Framework"}}
	tagged, left, _ := runFrameworkTag(t, cfg, g, "X-My-Framework", issueToken(t, g, time.Hour, time.Now()))
	require.True(t, tagged)
	require.Empty(t, left)
}

func TestApplyFrameworkTag_OtherAPIKeyTokenDoesNotTag(t *testing.T) {
	k := groupWithSecret(1, "s3cret")
	other := &service.APIKey{ID: 999, Group: k.Group}
	tagged, _, status := runFrameworkTag(t, &config.Config{}, k, testFrameworkHeader, issueToken(t, other, time.Hour, time.Now()))
	require.False(t, tagged)
	require.Equal(t, "invalid", status)
}

func TestFrameworkIssueToken_IssuesVerifiableToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	k := groupWithSecret(1, "s3cret")
	cfg := &config.Config{FrameworkAuth: config.FrameworkAuthConfig{TokenTTLSeconds: 600}}
	router := gin.New()
	router.POST("/framework/v1/token", func(c *gin.Context) {
		c.Set(string(ContextKeyAPIKey), k)
		c.Next()
	}, FrameworkIssueToken(cfg))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/framework/v1/token", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	var body struct {
		Token     string `json:"token"`
		ExpiresIn int64  `json:"expires_in"`
		Header    string `json:"header"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, int64(600), body.ExpiresIn)
	require.Equal(t, testFrameworkHeader, body.Header)
	require.NoError(t, service.VerifyFrameworkTagToken(k.Group, k.ID, body.Token, time.Now()))
	require.NotContains(t, rec.Body.String(), "s3cret")
}

func TestFrameworkIssueToken_GroupWithoutSecret(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/framework/v1/token", func(c *gin.Context) {
		c.Set(string(ContextKeyAPIKey), groupWithSecret(1, ""))
		c.Next()
	}, FrameworkIssueToken(&config.Config{}))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/framework/v1/token", nil))
	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.Contains(t, rec.Body.String(), "FRAMEWORK_NOT_ENABLED")
}
