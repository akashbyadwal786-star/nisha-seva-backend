const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');

const server = fs.readFileSync('server.js', 'utf8');
const admin = fs.readFileSync('admin/index.html', 'utf8');
const student = fs.readFileSync('student-portal.html', 'utf8');
const schemaFiles = [
  'migrations/20261024_coordinator_tasks_impact_passport.sql',
  'migrations/20261024_impact_platform_expansion.sql'
];
const schemas = schemaFiles.map(file => fs.readFileSync(file, 'utf8'));

test('task management endpoints exist', () => {
  for (const route of [
    "app.get('/api/tasks'",
    "app.post('/api/tasks'",
    "app.patch('/api/tasks/:id/status'",
    "app.get('/api/student/tasks'",
    "app.patch('/api/student/tasks/:id/status'"
  ]) assert.ok(server.includes(route), 'Missing route: ' + route);
});

test('impact passport endpoints exist and require authentication', () => {
  assert.match(server, /app\.get\('\/api\/impact-passport\/me',studentAuth/);
  assert.match(server, /app\.get\('\/api\/impact-passport\/:studentAccountId',requireAdmin/);
  assert.match(server, /app\.post\('\/api\/impact-passport\/:studentAccountId\/entries',requireAdmin/);
  assert.match(server, /app\.patch\('\/api\/impact-passport\/entries\/:entryId\/review',requireAdmin/);
});

test('all requested feature API foundations exist', () => {
  for (const route of [
    '/api/ai/research/draft','/api/public/impact-map','/api/public/impact-report',
    '/api/opportunities','/api/opportunities/:id/apply','/api/challenges',
    '/api/challenges/:id/checkins','/api/voice/transcript','/api/issues',
    '/api/issues/:reference/timeline','/api/public/villages/:id/scorecard',
    '/api/impact-profile/me','/api/admin/impact-transactions',
    '/api/admin/indicators','/api/admin/indicators/:id/verify',
    '/api/admin/villages/:id/projects','/api/public/villages/:id/scorecard'
  ]) assert.ok(server.includes(route), 'Missing feature API: ' + route);
});

test('admin and student portals include their feature sections', () => {
  for (const name of ['Coordinator Task Management','Student Impact Passport','NSF Impact Platform','Village Projects & Verification','Village Development Scorecard Indicators'])
    assert.ok(admin.includes(name), 'Missing admin UI section: ' + name);
  for (const id of ['studentTasksList','studentPassportList','studentOpportunities',
    'studentChallenges','studentVoiceForm','studentIssueForm','studentImpactDNA'])
    assert.ok(student.includes(id), 'Missing student UI section: ' + id);
});

test('migrations are additive and include all expected new tables', () => {
  const sql = schemas.join('\n');
  assert.doesNotMatch(sql, /\b(DROP\s+TABLE|TRUNCATE\s+TABLE|DROP\s+COLUMN|DELETE\s+FROM)\b/i);
  for (const table of ['nsf_tasks','nsf_impact_passport_entries','nsf_villages',
    'nsf_village_projects','nsf_impact_transactions','nsf_seva_opportunities',
    'nsf_opportunity_applications','nsf_90day_challenges','nsf_challenge_enrollments',
    'nsf_challenge_checkins','nsf_community_issues','nsf_issue_timeline',
    'nsf_development_indicators','nsf_ai_research_sessions','nsf_voice_submissions',
    'nsf_impact_dna_profiles'])
    assert.match(sql, new RegExp('CREATE TABLE IF NOT EXISTS\\s+' + table + '\\b'));
});
