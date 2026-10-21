-- Reference schema only. Take a backup and inspect the existing table first.
-- Do NOT drop or truncate any existing tables.
CREATE TABLE IF NOT EXISTS app_data (
  id TINYINT UNSIGNED NOT NULL PRIMARY KEY,
  data JSON NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- The existing imported app_data row should remain intact. Verify it with:
-- SELECT id, JSON_LENGTH(data) AS top_level_keys FROM app_data;
-- Do not INSERT an empty/default row over your real record.
