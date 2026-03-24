const { createClient } = require('@supabase/supabase-js');

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

// --- User helpers ---

async function createUser({ name, email, role, passwordHash }) {
  const { data, error } = await supabase
    .from('users')
    .insert({ name, email, role: role || null, password_hash: passwordHash || null })
    .select('id, name, email, role, created_at')
    .single();
  if (error) throw error;
  return data;
}

async function findUserByEmail(email) {
  const { data } = await supabase
    .from('users')
    .select('*')
    .eq('email', email)
    .single();
  return data || null;
}

async function findUserById(id) {
  const { data } = await supabase
    .from('users')
    .select('id, name, email, role')
    .eq('id', id)
    .single();
  return data || null;
}

// --- Analysis helpers ---

async function saveAnalysis(userId, analysisJson) {
  const { data, error } = await supabase
    .from('analyses')
    .insert({ user_id: userId, analysis_json: analysisJson })
    .select('id')
    .single();
  if (error) throw error;
  return data.id;
}

async function getLatestAnalysis(userId) {
  const { data } = await supabase
    .from('analyses')
    .select('analysis_json')
    .eq('user_id', userId)
    .order('created_at', { ascending: false })
    .limit(1)
    .single();
  if (!data) return null;
  try { return JSON.parse(data.analysis_json); } catch { return null; }
}

async function getAnalysisHistory(userId) {
  const { data } = await supabase
    .from('analyses')
    .select('id, analysis_json, created_at')
    .eq('user_id', userId)
    .order('created_at', { ascending: false });
  if (!data) return [];
  return data.map(r => {
    let parsed = {};
    try { parsed = JSON.parse(r.analysis_json); } catch {}
    return { id: r.id, score: parsed.score, background: parsed.background, summary: parsed.summary, created_at: r.created_at };
  });
}

async function getAnalysisById(userId, id) {
  const { data } = await supabase
    .from('analyses')
    .select('analysis_json')
    .eq('id', id)
    .eq('user_id', userId)
    .single();
  if (!data) return null;
  try { return JSON.parse(data.analysis_json); } catch { return null; }
}

async function getAnalysisByShareToken(token) {
  const { data } = await supabase
    .from('analyses')
    .select('id, analysis_json, created_at')
    .eq('share_token', token)
    .single();
  if (!data) return null;
  try {
    return { id: data.id, analysis: JSON.parse(data.analysis_json), created_at: data.created_at };
  } catch { return null; }
}

async function setShareToken(analysisId, userId, token) {
  const { error } = await supabase
    .from('analyses')
    .update({ share_token: token })
    .eq('id', analysisId)
    .eq('user_id', userId);
  if (error) throw error;
}

async function getShareToken(analysisId, userId) {
  const { data } = await supabase
    .from('analyses')
    .select('share_token')
    .eq('id', analysisId)
    .eq('user_id', userId)
    .single();
  return data ? data.share_token : null;
}

// --- Problem attempt helpers ---

async function saveProblemAttempt(userId, problemId, answer, feedbackJson, score) {
  await supabase
    .from('problem_attempts')
    .insert({ user_id: userId, problem_id: String(problemId), answer, feedback_json: feedbackJson, score });
}

async function getProblemAttempts(userId) {
  const { data } = await supabase
    .from('problem_attempts')
    .select('problem_id, score, feedback_json, created_at')
    .eq('user_id', userId)
    .order('created_at', { ascending: false });
  if (!data) return [];
  return data.map(r => {
    let feedback = null;
    try { feedback = JSON.parse(r.feedback_json); } catch {}
    return { problem_id: r.problem_id, score: r.score, feedback, created_at: r.created_at };
  });
}

// --- Roadmap progress helpers ---

async function upsertRoadmapProgress(userId, phaseIndex, completed) {
  const completedAt = completed ? new Date().toISOString() : null;
  await supabase
    .from('roadmap_progress')
    .upsert({
      user_id: userId,
      phase_index: phaseIndex,
      completed: completed ? 1 : 0,
      completed_at: completedAt,
    }, { onConflict: 'user_id,phase_index' });
}

async function getRoadmapProgress(userId) {
  const { data } = await supabase
    .from('roadmap_progress')
    .select('phase_index, completed, completed_at')
    .eq('user_id', userId);
  return data || [];
}

// --- Newsletter ---

async function saveSubscriber(email) {
  const { error } = await supabase
    .from('subscribers')
    .upsert({ email }, { onConflict: 'email', ignoreDuplicates: true });
  if (error && !error.message.includes('duplicate')) throw error;
}

module.exports = {
  createUser,
  findUserByEmail,
  findUserById,
  saveAnalysis,
  getLatestAnalysis,
  getAnalysisHistory,
  getAnalysisById,
  getAnalysisByShareToken,
  setShareToken,
  getShareToken,
  saveProblemAttempt,
  getProblemAttempts,
  upsertRoadmapProgress,
  getRoadmapProgress,
  saveSubscriber,
};
