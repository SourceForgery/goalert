
-- +migrate Up notransaction
-- Add new integration key type 'gkeAlertingMonitoring'

ALTER TYPE enum_integration_keys_type ADD VALUE IF NOT EXISTS 'gkeAlertingMonitoring';
ALTER TYPE enum_alert_source ADD VALUE IF NOT EXISTS 'gkeAlertingMonitoring';

-- +migrate Down
