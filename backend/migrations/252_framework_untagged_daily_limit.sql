ALTER TABLE groups
    ADD COLUMN IF NOT EXISTS untagged_daily_limit_usd DECIMAL(20,8) NULL;

COMMENT ON COLUMN groups.untagged_daily_limit_usd IS
    'Daily USD cap for subscription requests that do not carry a valid framework tag header; NULL means no separate cap';

ALTER TABLE user_subscriptions
    ADD COLUMN IF NOT EXISTS daily_untagged_usage_usd DECIMAL(20,10) NOT NULL DEFAULT 0;

COMMENT ON COLUMN user_subscriptions.daily_untagged_usage_usd IS
    'Usage within the current daily window from requests without a valid framework tag; reset together with daily_usage_usd';

ALTER TABLE groups
    ADD COLUMN IF NOT EXISTS framework_tag_secret VARCHAR(256) NOT NULL DEFAULT '';

COMMENT ON COLUMN groups.framework_tag_secret IS
    'Per-group framework tag secret; a request whose framework tag header equals it is treated as tagged. Empty disables tagging for the group';
