//go:build unit

package service

import (
	"context"
	"errors"
	"testing"
)

func untaggedGroup(limit *float64) *Group {
	daily := 60.0
	return &Group{
		SubscriptionType:      SubscriptionTypeSubscription,
		DailyLimitUSD:         &daily,
		UntaggedDailyLimitUSD: limit,
	}
}

func f64(v float64) *float64 { return &v }

func TestCheckUntaggedDailyLimit(t *testing.T) {
	svc := &SubscriptionService{}
	tagged := SetFrameworkTagged(context.Background(), true)
	untagged := context.Background()

	cases := []struct {
		name    string
		ctx     context.Context
		limit   *float64
		usage   float64
		wantErr bool
	}{
		{"no separate limit", untagged, nil, 100, false},
		{"untagged under limit", untagged, f64(20), 19.99, false},
		{"untagged at limit", untagged, f64(20), 20, true},
		{"untagged over limit", untagged, f64(20), 25, true},
		{"tagged ignores untagged limit", tagged, f64(20), 25, false},
		{"zero limit requires tag", untagged, f64(0), 0, true},
		{"zero limit allows tagged", tagged, f64(0), 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sub := &UserSubscription{DailyUntaggedUsageUSD: tc.usage}
			err := svc.CheckUntaggedDailyLimit(tc.ctx, sub, untaggedGroup(tc.limit))
			if tc.wantErr != errors.Is(err, ErrUntaggedDailyLimitExceeded) {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestUntaggedCostForContext(t *testing.T) {
	if got := UntaggedCostForContext(context.Background(), 1.5); got != 1.5 {
		t.Fatalf("untagged request should count full cost, got %v", got)
	}
	if got := UntaggedCostForContext(SetFrameworkTagged(context.Background(), true), 1.5); got != 0 {
		t.Fatalf("tagged request should count zero untagged cost, got %v", got)
	}
}
