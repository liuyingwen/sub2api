package service

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// 框架令牌：框架用 API Key 向服务端领取（POST /framework/v1/token），请求大模型时携带。
// 分组密钥只留在服务端，派发的是用它加密出来的、绑定 API Key 与分组、带过期时间的令牌。
//
//	token = "fwt1." + base64url(nonce(12B) || AES-256-GCM(key, {"g":分组ID,"k":API Key ID,"e":过期Unix秒}))
//	key   = HMAC-SHA256(分组密钥, "sub2api-fw-tag-key-v1")
//
// 修改分组密钥后，所有已发出的令牌立即失效。
const (
	frameworkTagTokenPrefix = "fwt1."
	frameworkTagTokenAAD    = "sub2api-fw-tag-v1"

	// FrameworkTagTokenDefaultTTL 未指定时的令牌有效期。
	FrameworkTagTokenDefaultTTL = time.Hour
)

var (
	ErrFrameworkTagSecretMissing = errors.New("group has no framework tag secret")
	ErrFrameworkTagTokenInvalid  = errors.New("invalid framework tag token")
	ErrFrameworkTagTokenExpired  = errors.New("framework tag token expired")
)

type frameworkTagTokenClaims struct {
	GroupID   int64 `json:"g"`
	APIKeyID  int64 `json:"k"`
	ExpiresAt int64 `json:"e"`
}

func frameworkTagAEAD(secret string) (cipher.AEAD, error) {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("sub2api-fw-tag-key-v1"))
	block, err := aes.NewCipher(mac.Sum(nil))
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// IssueFrameworkTagToken 用分组密钥为某个 API Key 签发框架令牌；ttl<=0 取默认值。
func IssueFrameworkTagToken(group *Group, apiKeyID int64, ttl time.Duration, now time.Time) (string, time.Time, error) {
	if group == nil || strings.TrimSpace(group.FrameworkTagSecret) == "" {
		return "", time.Time{}, ErrFrameworkTagSecretMissing
	}
	if ttl <= 0 {
		ttl = FrameworkTagTokenDefaultTTL
	}
	expiresAt := now.Add(ttl).Truncate(time.Second)
	plain, err := json.Marshal(frameworkTagTokenClaims{GroupID: group.ID, APIKeyID: apiKeyID, ExpiresAt: expiresAt.Unix()})
	if err != nil {
		return "", time.Time{}, err
	}
	aead, err := frameworkTagAEAD(strings.TrimSpace(group.FrameworkTagSecret))
	if err != nil {
		return "", time.Time{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", time.Time{}, err
	}
	sealed := aead.Seal(nonce, nonce, plain, []byte(frameworkTagTokenAAD))
	return frameworkTagTokenPrefix + base64.RawURLEncoding.EncodeToString(sealed), expiresAt, nil
}

// VerifyFrameworkTagToken 校验令牌是否由该分组当前的密钥签发、属于该分组和该 API Key，且未过期。
func VerifyFrameworkTagToken(group *Group, apiKeyID int64, token string, now time.Time) error {
	if group == nil || strings.TrimSpace(group.FrameworkTagSecret) == "" {
		return ErrFrameworkTagSecretMissing
	}
	token = strings.TrimSpace(token)
	if !strings.HasPrefix(token, frameworkTagTokenPrefix) || len(token) > 512 {
		return ErrFrameworkTagTokenInvalid
	}
	sealed, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(token, frameworkTagTokenPrefix))
	if err != nil {
		return ErrFrameworkTagTokenInvalid
	}
	aead, err := frameworkTagAEAD(strings.TrimSpace(group.FrameworkTagSecret))
	if err != nil || len(sealed) < aead.NonceSize()+aead.Overhead() {
		return ErrFrameworkTagTokenInvalid
	}
	plain, err := aead.Open(nil, sealed[:aead.NonceSize()], sealed[aead.NonceSize():], []byte(frameworkTagTokenAAD))
	if err != nil {
		return ErrFrameworkTagTokenInvalid
	}
	var claims frameworkTagTokenClaims
	if err := json.Unmarshal(plain, &claims); err != nil || claims.GroupID != group.ID || claims.APIKeyID != apiKeyID {
		return ErrFrameworkTagTokenInvalid
	}
	if now.Unix() >= claims.ExpiresAt {
		return ErrFrameworkTagTokenExpired
	}
	return nil
}
