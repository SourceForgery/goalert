
-- +migrate Up notransaction
-- Add new integration key type 'mxToolBox'

ALTER TYPE enum_integration_keys_type ADD VALUE IF NOT EXISTS 'mxToolBox';
ALTER TYPE enum_alert_source ADD VALUE IF NOT EXISTS 'mxToolBox';

-- +migrate Down
