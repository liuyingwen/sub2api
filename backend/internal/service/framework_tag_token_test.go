//go:build unit

package service

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestFrameworkTagToken_RoundTrip(t *testing.T) {
	now := time.Now()
	g := &Group{ID: 9, FrameworkTagSecret: "group-secret"}
	tok, exp, err := IssueFrameworkTagToken(g, 5, 24*time.Hour, now)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(tok, "fwt1."))
	require.NotContains(t, tok, "group-secret")
	require.WithinDuration(t, now.Add(24*time.Hour), exp, time.Second)
	require.NoError(t, VerifyFrameworkTagToken(g, 5, tok, now))
	require.NoError(t, VerifyFrameworkTagToken(g, 5, "  "+tok+" ", now.Add(23*time.Hour)))
}

func TestFrameworkTagToken_Expired(t *testing.T) {
	now := time.Now()
	g := &Group{ID: 9, FrameworkTagSecret: "group-secret"}
	tok, _, err := IssueFrameworkTagToken(g, 5, time.Hour, now)
	require.NoError(t, err)
	require.ErrorIs(t, VerifyFrameworkTagToken(g, 5, tok, now.Add(time.Hour+time.Second)), ErrFrameworkTagTokenExpired)
}

func TestFrameworkTagToken_Rejections(t *testing.T) {
	now := time.Now()
	g := &Group{ID: 9, FrameworkTagSecret: "group-secret"}
	tok, _, err := IssueFrameworkTagToken(g, 5, time.Hour, now)
	require.NoError(t, err)

	// 其他分组（即使密钥相同）
	require.ErrorIs(t, VerifyFrameworkTagToken(&Group{ID: 10, FrameworkTagSecret: "group-secret"}, 5, tok, now), ErrFrameworkTagTokenInvalid)
	// 同分组的其他 API Key
	require.ErrorIs(t, VerifyFrameworkTagToken(g, 6, tok, now), ErrFrameworkTagTokenInvalid)
	// 密钥轮换后旧令牌失效
	require.ErrorIs(t, VerifyFrameworkTagToken(&Group{ID: 9, FrameworkTagSecret: "rotated"}, 5, tok, now), ErrFrameworkTagTokenInvalid)
	// 直接发送原始密钥不再有效
	require.ErrorIs(t, VerifyFrameworkTagToken(g, 5, "group-secret", now), ErrFrameworkTagTokenInvalid)
	// 篡改
	b := []byte(tok)
	b[len(b)-3] ^= 1
	require.ErrorIs(t, VerifyFrameworkTagToken(g, 5, string(b), now), ErrFrameworkTagTokenInvalid)
	require.ErrorIs(t, VerifyFrameworkTagToken(g, 5, "fwt1.!!!", now), ErrFrameworkTagTokenInvalid)
	// 分组未配置密钥
	require.ErrorIs(t, VerifyFrameworkTagToken(&Group{ID: 9}, 5, tok, now), ErrFrameworkTagSecretMissing)
	_, _, err = IssueFrameworkTagToken(&Group{ID: 9}, 5, time.Hour, now)
	require.ErrorIs(t, err, ErrFrameworkTagSecretMissing)
}

func TestFrameworkTagToken_TTLDefault(t *testing.T) {
	now := time.Now()
	g := &Group{ID: 1, FrameworkTagSecret: "s"}
	_, exp, err := IssueFrameworkTagToken(g, 5, 0, now)
	require.NoError(t, err)
	require.WithinDuration(t, now.Add(FrameworkTagTokenDefaultTTL), exp, time.Second)
}
