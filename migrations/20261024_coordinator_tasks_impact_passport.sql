-- Nisha Seva Foundation: additive migration for Coordinator Task Management + Student Impact Passport
-- REVIEW FIRST. This migration only creates new tables and indexes; it does not alter/delete existing records.
-- Apply to the PostgreSQL database used by DATABASE_URL after backup and staging verification.

BEGIN;

CREATE TABLE IF NOT EXISTS nsf_tasks (
  id BIGSERIAL PRIMARY KEY,
  title TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  assigned_student_account_id BIGINT,
  assigned_team TEXT NOT NULL DEFAULT '',
  priority TEXT NOT NULL DEFAULT 'normal'
    CHECK (priority IN ('low','normal','high','urgent')),
  status TEXT NOT NULL DEFAULT 'todo'
    CHECK (status IN ('todo','in_progress','blocked','review','done','cancelled')),
  due_date DATE,
  created_by_role TEXT NOT NULL DEFAULT 'admin'
    CHECK (created_by_role IN ('admin','coordinator')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS nsf_tasks_assigned_student_idx
  ON nsf_tasks (assigned_student_account_id, due_date);

CREATE INDEX IF NOT EXISTS nsf_tasks_status_due_idx
  ON nsf_tasks (status, due_date);

CREATE TABLE IF NOT EXISTS nsf_impact_passport_entries (
  id BIGSERIAL PRIMARY KEY,
  student_account_id BIGINT NOT NULL,
  entry_type TEXT NOT NULL DEFAULT 'achievement'
    CHECK (entry_type IN ('achievement','skill','service_hours','project','certificate')),
  title TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  evidence_url TEXT,
  metric_value NUMERIC(10,2),
  metric_unit TEXT,
  verification_status TEXT NOT NULL DEFAULT 'pending'
    CHECK (verification_status IN ('pending','verified','rejected')),
  reviewed_by_role TEXT,
  reviewed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS nsf_impact_passport_student_idx
  ON nsf_impact_passport_entries (student_account_id, created_at DESC);

CREATE INDEX IF NOT EXISTS nsf_impact_passport_verification_idx
  ON nsf_impact_passport_entries (verification_status, created_at DESC);

COMMIT;
