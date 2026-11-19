package service

import (
	"context"
	"errors"

	"github.com/Wei-Shaw/sub2api/internal/pkg/ctxkey"
)

// ErrUntaggedDailyLimitExceeded 表示请求未携带框架标识，且订阅当日的无标识用量已达分组上限。
var ErrUntaggedDailyLimitExceeded = errors.New("daily usage limit for requests without framework tag exceeded")

// IsFrameworkTagged 报告当前请求是否携带了合法的框架标识。
func IsFrameworkTagged(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	v, ok := ctx.Value(ctxkey.FrameworkTagged).(bool)
	return ok && v
}

// SetFrameworkTagged 把框架标识结果写入 context。
func SetFrameworkTagged(ctx context.Context, tagged bool) context.Context {
	return context.WithValue(ctx, ctxkey.FrameworkTagged, tagged)
}

// UntaggedCostForContext 返回本次请求应计入「无标识用量」的金额：带标识请求为 0。
func UntaggedCostForContext(ctx context.Context, cost float64) float64 {
	if IsFrameworkTagged(ctx) {
		return 0
	}
	return cost
}
