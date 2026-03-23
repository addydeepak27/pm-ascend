const Database = require('better-sqlite3');
const path = require('path');

const db = new Database(path.join(__dirname, 'pm-ascend.db'));

// WAL mode for better concurrent access
db.pragma('journal_mode = WAL');

// Initialize tables
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    role TEXT,
    password_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS analyses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    analysis_json TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS problem_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    problem_id TEXT NOT NULL,
    answer TEXT NOT NULL,
    feedback_json TEXT NOT NULL,
    score INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS roadmap_progress (
    user_id INTEGER NOT NULL,
    phase_index INTEGER NOT NULL,
    completed INTEGER DEFAULT 0,
    completed_at DATETIME,
    PRIMARY KEY (user_id, phase_index),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);

// --- User helpers ---

function createUser({ name, email, role, passwordHash }) {
  const stmt = db.prepare(
    'INSERT INTO users (name, email, role, password_hash) VALUES (?, ?, ?, ?)'
  );
  const result = stmt.run(name, email, role || null, passwordHash);
  return db.prepare('SELECT id, name, email, role, created_at FROM users WHERE id = ?').get(result.lastInsertRowid);
}

function findUserByEmail(email) {
  return db.prepare('SELECT * FROM users WHERE email = ?').get(email);
}

// --- Analysis helpers ---

function saveAnalysis(userId, analysisJson) {
  db.prepare('INSERT INTO analyses (user_id, analysis_json) VALUES (?, ?)').run(userId, analysisJson);
}

function getLatestAnalysis(userId) {
  const row = db.prepare(
    'SELECT analysis_json FROM analyses WHERE user_id = ? ORDER BY created_at DESC LIMIT 1'
  ).get(userId);
  if (!row) return null;
  try {
    return JSON.parse(row.analysis_json);
  } catch {
    return null;
  }
}

// --- Problem attempt helpers ---

function saveProblemAttempt(userId, problemId, answer, feedbackJson, score) {
  db.prepare(
    'INSERT INTO problem_attempts (user_id, problem_id, answer, feedback_json, score) VALUES (?, ?, ?, ?, ?)'
  ).run(userId, String(problemId), answer, feedbackJson, score);
}

function getProblemAttempts(userId) {
  const rows = db.prepare(
    'SELECT problem_id, score, feedback_json, created_at FROM problem_attempts WHERE user_id = ? ORDER BY created_at DESC'
  ).all(userId);
  return rows.map(r => {
    let feedback = null;
    try { feedback = JSON.parse(r.feedback_json); } catch {}
    return { problem_id: r.problem_id, score: r.score, feedback, created_at: r.created_at };
  });
}

// --- Roadmap progress helpers ---

function upsertRoadmapProgress(userId, phaseIndex, completed) {
  const completedAt = completed ? new Date().toISOString() : null;
  db.prepare(`
    INSERT INTO roadmap_progress (user_id, phase_index, completed, completed_at)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(user_id, phase_index) DO UPDATE SET
      completed = excluded.completed,
      completed_at = excluded.completed_at
  `).run(userId, phaseIndex, completed ? 1 : 0, completedAt);
}

function getRoadmapProgress(userId) {
  return db.prepare(
    'SELECT phase_index, completed, completed_at FROM roadmap_progress WHERE user_id = ?'
  ).all(userId);
}

module.exports = {
  createUser,
  findUserByEmail,
  saveAnalysis,
  getLatestAnalysis,
  saveProblemAttempt,
  getProblemAttempts,
  upsertRoadmapProgress,
  getRoadmapProgress,
};
