-- Change languages_json from JSONB to JSON to preserve key ordering.
-- JSONB normalizes/reorders object keys; JSON preserves the original order.
ALTER TABLE base_modules ALTER COLUMN languages_json TYPE JSON USING languages_json::text::json;
