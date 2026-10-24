-- NSF Impact Platform expansion (additive only)
-- Run against the PostgreSQL database used by DATABASE_URL only after backup/staging test.
BEGIN;
CREATE TABLE IF NOT EXISTS nsf_villages (
 id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL, district TEXT NOT NULL DEFAULT 'Jaipur',
 public_description TEXT NOT NULL DEFAULT '', latitude NUMERIC(10,7), longitude NUMERIC(10,7),
 visibility TEXT NOT NULL DEFAULT 'public' CHECK (visibility IN ('public','private')),
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS nsf_village_projects (
 id BIGSERIAL PRIMARY KEY, village_id BIGINT NOT NULL REFERENCES nsf_villages(id) ON DELETE RESTRICT,
 title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'planned'
 CHECK(status IN ('planned','in_progress','completed','paused')),
 public_summary TEXT NOT NULL DEFAULT '', verified BOOLEAN NOT NULL DEFAULT FALSE,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS nsf_impact_transactions (
 id BIGSERIAL PRIMARY KEY, kind TEXT NOT NULL CHECK(kind IN ('donation','expense','allocation')),
 amount_paise BIGINT NOT NULL CHECK(amount_paise > 0), village_id BIGINT REFERENCES nsf_villages(id) ON DELETE RESTRICT,
 project_id BIGINT REFERENCES nsf_village_projects(id) ON DELETE RESTRICT,
 description TEXT NOT NULL DEFAULT '', public_note TEXT NOT NULL DEFAULT '',
 approved BOOLEAN NOT NULL DEFAULT FALSE, created_by_role TEXT NOT NULL DEFAULT 'admin',
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS nsf_seva_opportunities (
 id BIGSERIAL PRIMARY KEY, title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
 village_id BIGINT REFERENCES nsf_villages(id) ON DELETE RESTRICT,
 skills TEXT[] NOT NULL DEFAULT '{}', slots INTEGER NOT NULL DEFAULT 1 CHECK(slots BETWEEN 1 AND 10000),
 status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('draft','open','closed')),
 start_date DATE, end_date DATE, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS nsf_opportunity_applications (
 id BIGSERIAL PRIMARY KEY, opportunity_id BIGINT NOT NULL REFERENCES nsf_seva_opportunities(id) ON DELETE RESTRICT,
 student_account_id BIGINT NOT NULL, note TEXT NOT NULL DEFAULT '',
 status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','accepted','rejected','completed')),
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 UNIQUE(opportunity_id, student_account_id)
);
CREATE TABLE IF NOT EXISTS nsf_90day_challenges (
 id BIGSERIAL PRIMARY KEY, title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
 start_date DATE NOT NULL, end_date DATE NOT NULL, status TEXT NOT NULL DEFAULT 'active'
 CHECK(status IN ('draft','active','completed','archived')), created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS nsf_challenge_enrollments (
 id BIGSERIAL PRIMARY KEY, challenge_id BIGINT NOT NULL REFERENCES nsf_90day_challenges(id) ON DELETE RESTRICT,
 student_account_id BIGINT NOT NULL, goal TEXT NOT NULL DEFAULT '', created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 UNIQUE(challenge_id, student_account_id)
);
CREATE TABLE IF NOT EXISTS nsf_challenge_checkins (
 id BIGSERIAL PRIMARY KEY, enrollment_id BIGINT NOT NULL REFERENCES nsf_challenge_enrollments(id) ON DELETE RESTRICT,
 checkin_date DATE NOT NULL DEFAULT CURRENT_DATE, progress_note TEXT NOT NULL DEFAULT '',
 progress_value NUMERIC(10,2), evidence_url TEXT, reviewed BOOLEAN NOT NULL DEFAULT FALSE,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), UNIQUE(enrollment_id, checkin_date)
);
CREATE TABLE IF NOT EXISTS nsf_community_issues (
 id BIGSERIAL PRIMARY KEY, village_id BIGINT REFERENCES nsf_villages(id) ON DELETE RESTRICT,
 title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', category TEXT NOT NULL DEFAULT 'general',
 status TEXT NOT NULL DEFAULT 'submitted' CHECK(status IN ('submitted','reviewing','in_progress','resolved','rejected')),
 public_reference TEXT NOT NULL UNIQUE, public_visible BOOLEAN NOT NULL DEFAULT TRUE,
 reporter_name TEXT, reporter_contact TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS nsf_issue_timeline (
 id BIGSERIAL PRIMARY KEY, issue_id BIGINT NOT NULL REFERENCES nsf_community_issues(id) ON DELETE RESTRICT,
 status TEXT NOT NULL, public_note TEXT NOT NULL DEFAULT '', created_by_role TEXT NOT NULL DEFAULT 'admin',
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS nsf_development_indicators (
 id BIGSERIAL PRIMARY KEY, village_id BIGINT NOT NULL REFERENCES nsf_villages(id) ON DELETE RESTRICT,
 indicator_key TEXT NOT NULL, label TEXT NOT NULL, value NUMERIC(12,2), unit TEXT NOT NULL DEFAULT '',
 evidence_url TEXT, verified BOOLEAN NOT NULL DEFAULT FALSE, public_note TEXT NOT NULL DEFAULT '',
 measured_on DATE NOT NULL DEFAULT CURRENT_DATE, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS nsf_ai_research_sessions (
 id BIGSERIAL PRIMARY KEY, created_by_role TEXT NOT NULL, village_id BIGINT REFERENCES nsf_villages(id) ON DELETE RESTRICT,
 topic TEXT NOT NULL, language TEXT NOT NULL DEFAULT 'hi', input_notes TEXT NOT NULL DEFAULT '',
 draft_output TEXT NOT NULL DEFAULT '', reviewed BOOLEAN NOT NULL DEFAULT FALSE,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS nsf_voice_submissions (
 id BIGSERIAL PRIMARY KEY, student_account_id BIGINT, purpose TEXT NOT NULL DEFAULT 'general',
 transcript TEXT NOT NULL, reviewed BOOLEAN NOT NULL DEFAULT FALSE, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS nsf_impact_dna_profiles (
 id BIGSERIAL PRIMARY KEY, student_account_id BIGINT NOT NULL UNIQUE,
 strengths TEXT[] NOT NULL DEFAULT '{}', interests TEXT[] NOT NULL DEFAULT '{}',
 verified_hours NUMERIC(10,2) NOT NULL DEFAULT 0, completed_projects INTEGER NOT NULL DEFAULT 0,
 last_calculated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS nsf_village_projects_village_idx ON nsf_village_projects(village_id,status);
CREATE INDEX IF NOT EXISTS nsf_impact_transactions_public_idx ON nsf_impact_transactions(approved,kind,created_at DESC);
CREATE INDEX IF NOT EXISTS nsf_opportunities_status_idx ON nsf_seva_opportunities(status,start_date);
CREATE INDEX IF NOT EXISTS nsf_issues_public_ref_idx ON nsf_community_issues(public_reference,public_visible);
CREATE INDEX IF NOT EXISTS nsf_issue_timeline_issue_idx ON nsf_issue_timeline(issue_id,created_at);
CREATE INDEX IF NOT EXISTS nsf_indicators_village_idx ON nsf_development_indicators(village_id,verified,measured_on DESC);
COMMIT;
