require('dotenv').config();
const express = require('express');
const multer = require('multer');
const path = require('path');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const Anthropic = require('@anthropic-ai/sdk');
const { createClient } = require('@supabase/supabase-js');
const db = require('./db');

// Supabase client for verifying OAuth tokens (uses service key)
const supabaseAuth = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);

const app = express();
const PORT = process.env.PORT || 3000;

// In-memory storage for uploaded files
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
  fileFilter: (req, file, cb) => {
    const allowed = ['application/pdf', 'text/plain',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document'];
    if (allowed.includes(file.mimetype) || file.originalname.match(/\.(pdf|txt|docx)$/i)) {
      cb(null, true);
    } else {
      cb(new Error('Only PDF, TXT, and DOCX files are allowed'));
    }
  }
});

const anthropic = new Anthropic({
  apiKey: process.env.ANTHROPIC_API_KEY,
});

// Serve static files
app.use(express.static(path.join(__dirname)));
app.use(express.json());

// Session middleware (kept in SQLite — sessions are ephemeral, no migration needed)
app.use(session({
  store: new SQLiteStore({ db: 'sessions.db', dir: __dirname }),
  secret: process.env.SESSION_SECRET || 'dev-secret-change-in-production',
  resave: false,
  saveUninitialized: false,
  rolling: true, // reset maxAge on every response so active users stay logged in
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: false, // localhost is HTTP; set to true only behind HTTPS in production
    maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days
  }
}));

// Dummy hash used to equalize login response time when email not found (prevents timing attacks)
const DUMMY_HASH = '$2b$12$K8GpYbFbvjNjHNEb8tB8Buxf6t6LKBD3yKfPl9H4jkJLxUFh8k5lW';

// --- Auth routes ---

app.post('/api/auth/signup', async (req, res) => {
  try {
    const { name, email, role, password } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Name, email, and password are required.' });
    }
    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters.' });
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: 'Please enter a valid email address.' });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const user = await db.createUser({ name, email: email.toLowerCase(), role, passwordHash });

    req.session.userId = user.id;
    req.session.userName = user.name;
    req.session.userEmail = user.email;
    req.session.userRole = user.role || null;

    await new Promise((resolve, reject) => req.session.save(err => err ? reject(err) : resolve()));
    res.json({ success: true, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
  } catch (err) {
    if (err.message && (err.message.includes('unique') || err.message.includes('duplicate') || err.message.includes('already exists'))) {
      return res.status(409).json({ error: 'An account with this email already exists. Try logging in.' });
    }
    console.error('Signup error:', err);
    res.status(500).json({ error: 'Signup failed. Please try again.' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required.' });
    }

    const user = await db.findUserByEmail(email.toLowerCase());
    // Always compare (even with dummy hash) to prevent timing-based email enumeration
    const hash = user ? user.password_hash : DUMMY_HASH;
    const match = await bcrypt.compare(password, hash);

    if (!user || !match) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    req.session.userId = user.id;
    req.session.userName = user.name;
    req.session.userEmail = user.email;
    req.session.userRole = user.role || null;

    await new Promise((resolve, reject) => req.session.save(err => err ? reject(err) : resolve()));

    const [analysis, attempts, roadmapProgress] = await Promise.all([
      db.getLatestAnalysis(user.id),
      db.getProblemAttempts(user.id),
      db.getRoadmapProgress(user.id),
    ]);

    res.json({
      success: true,
      user: { id: user.id, name: user.name, email: user.email, role: user.role },
      analysis,
      attempts,
      roadmapProgress,
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed. Please try again.' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('connect.sid');
    res.json({ success: true });
  });
});

// POST /api/auth/oauth — verify Supabase OAuth token, create/find user, set session
app.post('/api/auth/oauth', async (req, res) => {
  try {
    const { access_token } = req.body;
    if (!access_token) return res.status(400).json({ error: 'access_token required' });

    // Verify the token with Supabase and get user info
    const { data: { user: sbUser }, error } = await supabaseAuth.auth.getUser(access_token);
    if (error || !sbUser) return res.status(401).json({ error: 'Invalid or expired token' });

    const email = sbUser.email;
    const name  = sbUser.user_metadata?.full_name || sbUser.user_metadata?.name || email.split('@')[0];

    // Find existing user or create new one (no password for OAuth users)
    let user = await db.findUserByEmail(email.toLowerCase());
    if (!user) {
      user = await db.createUser({ name, email: email.toLowerCase(), role: null, passwordHash: null });
    }

    req.session.userId    = user.id;
    req.session.userName  = user.name;
    req.session.userEmail = user.email;
    req.session.userRole  = user.role || null;

    await new Promise((resolve, reject) => req.session.save(err => err ? reject(err) : resolve()));

    const [analysis, attempts, roadmapProgress] = await Promise.all([
      db.getLatestAnalysis(user.id),
      db.getProblemAttempts(user.id),
      db.getRoadmapProgress(user.id),
    ]);

    res.json({
      success: true,
      user: { id: user.id, name: user.name, email: user.email, role: user.role },
      analysis, attempts, roadmapProgress,
    });
  } catch (err) {
    console.error('OAuth error:', err);
    res.status(500).json({ error: 'OAuth sign-in failed. Please try again.' });
  }
});

// GET /auth/callback — OAuth redirect target; serve index.html, frontend handles the hash tokens
app.get('/auth/callback', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/api/auth/me', async (req, res) => {
  if (!req.session.userId) {
    return res.json({ user: null });
  }

  // Build user from session first (available instantly, no DB needed)
  const sessionUser = {
    id:    req.session.userId,
    name:  req.session.userName  || 'User',
    email: req.session.userEmail || '',
    role:  req.session.userRole  || null,
  };

  try {
    const userRow = await db.findUserById(req.session.userId);
    if (!userRow) {
      req.session.destroy(() => {});
      return res.json({ user: null });
    }

    const [analysis, attempts, roadmapProgress] = await Promise.all([
      db.getLatestAnalysis(req.session.userId),
      db.getProblemAttempts(req.session.userId),
      db.getRoadmapProgress(req.session.userId),
    ]);

    return res.json({
      user: { id: userRow.id, name: userRow.name, email: userRow.email, role: userRow.role },
      analysis,
      attempts,
      roadmapProgress,
    });
  } catch (err) {
    // DB unavailable (e.g. Supabase cold start) — return session user so UI doesn't log them out
    console.error('/api/auth/me db error (using session fallback):', err.message);
    return res.json({ user: sessionUser, analysis: null, attempts: [], roadmapProgress: [] });
  }
});

app.post('/api/user/roadmap/progress', async (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Not authenticated.' });
  }
  const { phaseIndex, completed } = req.body;
  if (phaseIndex === undefined || completed === undefined) {
    return res.status(400).json({ error: 'phaseIndex and completed are required.' });
  }
  await db.upsertRoadmapProgress(req.session.userId, phaseIndex, completed);
  res.json({ success: true });
});

// --- File text extraction ---

async function extractText(file) {
  const { mimetype, buffer, originalname } = file;

  if (mimetype === 'text/plain') {
    return buffer.toString('utf-8');
  }

  if (mimetype === 'application/pdf' || originalname.toLowerCase().endsWith('.pdf')) {
    try {
      const pdfParse = require('pdf-parse');
      const data = await pdfParse(buffer);
      return data.text;
    } catch (err) {
      console.error('PDF parse error:', err.message);
      return '';
    }
  }

  if (
    mimetype === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' ||
    originalname.toLowerCase().endsWith('.docx')
  ) {
    try {
      const mammoth = require('mammoth');
      const result = await mammoth.extractRawText({ buffer });
      return result.value;
    } catch (err) {
      console.error('DOCX parse error:', err.message);
      return '';
    }
  }

  return '';
}

// --- Text preprocessing ---

function preprocessText(raw) {
  if (!raw) return '';
  return raw
    .replace(/\r\n/g, '\n').replace(/\r/g, '\n')
    .replace(/[^\x20-\x7E\n]/g, ' ')   // strip non-ASCII garbage from PDF OCR
    .replace(/[ \t]{3,}/g, '  ')        // collapse excessive spaces
    .replace(/\n{4,}/g, '\n\n\n')       // max 3 consecutive blank lines
    .trim()
    .slice(0, 6500);                     // cap at 6500 chars — top of resume has all signal
}

// --- Resume quality assessment ---

function assessResumeQuality(text) {
  if (!text || text.length < 150) return 'low';
  const words = text.trim().split(/\s+/).length;
  const hasYears  = /20\d\d/.test(text);
  const hasVerbs  = /\b(led|built|managed|developed|designed|created|implemented|launched|increased|reduced|improved|owned|drove|shipped)\b/i.test(text);
  const hasNums   = /\d+%|\$[\d,.]+|\d+[KMBk]\b|\d+\s*(users|customers|engineers|team members|markets)/i.test(text);
  if (words < 100 || !hasYears) return 'low';
  if (words > 200 && hasVerbs && hasNums) return 'high';
  return 'medium';
}

// --- In-memory analysis cache (keyed by hash of resume text + context) ---
const analysisCache = new Map();
const CACHE_MAX = 200; // evict oldest when full

function cacheKey(text, context) {
  const raw = text + JSON.stringify(context || {});
  let hash = 0;
  for (let i = 0; i < raw.length; i++) {
    hash = (Math.imul(31, hash) + raw.charCodeAt(i)) | 0;
  }
  return String(hash >>> 0);
}

// --- Claude JSON helper — with auto-retry on parse failure ---

async function callClaudeJson(prompt, maxTokens = 4500, model = 'claude-opus-4-6') {
  for (let attempt = 0; attempt < 2; attempt++) {
    const response = await anthropic.messages.create({
      model,
      max_tokens: maxTokens,
      temperature: 0.3,
      messages: [{ role: 'user', content: prompt }],
    });
    const raw = response.content[0].type === 'text' ? response.content[0].text : '';
    const cleaned = raw.replace(/^```json?\s*/i, '').replace(/\s*```$/i, '').trim();
    try {
      return JSON.parse(cleaned);
    } catch (err) {
      if (attempt === 1) throw new Error('AI returned malformed JSON after retry. Please try again.');
      console.warn('JSON parse failed on attempt 1, retrying:', err.message);
    }
  }
}


// --- Output validation & safe defaults ---

function validateOutput(result) {
  if (typeof result.score !== 'number' || isNaN(result.score)) result.score = 50;
  result.score = Math.max(0, Math.min(100, Math.round(result.score)));

  if (!['engineer','data','business','designer','other'].includes(result.background)) result.background = 'other';
  if (!['high','medium','low'].includes(result.confidence)) result.confidence = 'medium';
  if (!['high','medium','low'].includes(result.resumeQuality)) result.resumeQuality = 'medium';

  if (!Array.isArray(result.skills) || result.skills.length < 3) {
    result.skills = (result.skills || []).concat([
      { name: 'PM Fundamentals', score: 50, importance: 'critical' },
      { name: 'AI/ML Knowledge', score: 40, importance: 'critical' },
      { name: 'Communication',   score: 55, importance: 'high'     },
    ]).slice(0, 5);
  }
  result.skills = result.skills.map(s => ({
    name:       s.name || 'Skill',
    score:      Math.max(0, Math.min(100, Number(s.score) || 50)),
    importance: ['critical','high','medium','low'].includes(s.importance) ? s.importance : 'medium',
  }));

  if (!Array.isArray(result.strengths)) result.strengths = [];
  if (!Array.isArray(result.gaps)) result.gaps = [];
  result.gaps = result.gaps.slice(0, 5).map(g => ({
    gap:      g.gap || 'Gap',
    severity: ['high','medium','low'].includes(g.severity) ? g.severity : 'medium',
    fix:      g.fix || '',
  }));

  if (!Array.isArray(result.roadmap)) result.roadmap = [];
  result.roadmap = result.roadmap.map(r => ({
    phase:     r.phase || '',
    focus:     r.focus || '',
    milestone: r.milestone || '',
    steps:     Array.isArray(r.steps) ? r.steps.filter(s => typeof s === 'string') : [],
  }));
  if (!result.timeline || typeof result.timeline !== 'object') result.timeline = {};
  if (!Array.isArray(result.quickWins)) result.quickWins = [];
  if (typeof result.topAdvice !== 'string') result.topAdvice = '';
  return result;
}

// --- Timeline clamping (hard 12-month ceiling) ---

function clampTimeline(timeline) {
  const clamp = v => {
    if (!v) return v;
    const nums = String(v).match(/\d+/g);
    if (!nums || Math.max(...nums.map(Number)) <= 12) return v;
    return String(v).replace(/\d+/g, n => Math.min(Number(n), 12));
  };
  return { ...timeline, optimistic: clamp(timeline.optimistic), realistic: clamp(timeline.realistic), conservative: clamp(timeline.conservative) };
}

// --- Build analysis prompt (shared by streaming + non-streaming paths) ---

function buildAnalysisPrompt(resumeText, additionalContext = {}, resumeQuality = 'medium') {
  const { level, company, hours, geo, attempts } = additionalContext;

  const contextBlock = [
    level    ? `Target role level: ${level}` : '',
    company  ? `Target company type: ${company}` : '',
    hours    ? `Hours per week available for prep: ${hours}` : '',
    geo      ? `Job market / geography: ${geo}` : '',
    attempts ? `Prior PM interview attempts: ${attempts}` : '',
  ].filter(Boolean).join('\n');

  const hoursPacing = !hours ? '' :
    hours.includes('Less than 5') ? 'PACING: fewer than 5h/week — push timelines toward conservative range, compress milestones.' :
    hours.includes('20+')         ? 'PACING: 20+ hours/week (full-time) — use optimistic timelines, pack more deliverables per phase.' :
    hours.includes('10–20')       ? 'PACING: 10–20h/week — use realistic timelines.' :
                                    'PACING: 5–10h/week — use mid-to-conservative timelines.';

  const resumeBlock = resumeText && resumeText.length > 50
    ? `Candidate's resume:\n${resumeText}`
    : '(No resume provided — provide best-effort analysis based on context only and set confidence to low)';

  const prompt = `You are an expert AI Product Manager career coach conducting a deep, personalised readiness analysis. Read the resume carefully and extract all relevant facts yourself before analysing.

${resumeBlock}

Resume quality: ${resumeQuality} (${
    resumeQuality === 'low'  ? 'sparse or unformatted PDF — lower your confidence score' :
    resumeQuality === 'high' ? 'well-structured with quantified achievements' :
                               'moderate detail'})

${contextBlock ? `Candidate-provided context:\n${contextBlock}` : ''}
${hoursPacing ? `\n${hoursPacing}` : ''}

ABSOLUTE TIMELINE RULE — hard ceiling of 12 months on every timeline field, no exceptions:
Per-background benchmarks:
- Software Engineers/Developers:    optimistic 4, realistic 5–7,  conservative 8
- Data Scientists/Analysts:         optimistic 4, realistic 5–7,  conservative 8
- Business Analysts/Consultants:    optimistic 5, realistic 6–8,  conservative 9
- Finance/Banking:                  optimistic 6, realistic 8–10, conservative 11
- Marketing/Operations/non-tech:    optimistic 5, realistic 6–9,  conservative 10
- Students/Recent Graduates:        optimistic 5, realistic 7–9,  conservative 11
- Career changers (no corp exp):    optimistic 6, realistic 9–10, conservative 12
- Existing PMs (non-AI):            optimistic 3, realistic 4–6,  conservative 8
- UX Designers/Researchers:         optimistic 4, realistic 6–8,  conservative 9

ADDITIONAL CONTEXT RULES:
- APM/entry-level target → emphasise APM programs (Google APM, Meta RPM) and portfolio-building.
- Senior PM target → leadership artifacts, org influence, system design decisions.
- Big Tech target → STAR/metrics frameworks, data-driven storytelling.
- AI startup target → scrappy outcome-focused narratives, speed of execution.
- Enterprise target → stakeholder management, change management, compliance awareness.
- US market → FAANG-style structured case interviews, heavy metrics.
- India market → reference Flipkart, Razorpay, Meesho, CRED as target co examples.
- Europe market → privacy/GDPR/regulatory angle, stakeholder alignment.
- SEA market → localisation, growth hacking, emerging-market product thinking.
- 3+ failed interviews → diagnose likely failure mode from their profile, front-load interview prep in roadmap.

PERSONALIZATION RULES (every field must pass these):
- Strengths: name the specific project, company, tool, or achievement from their resume. No generic statements.
- Gaps: name what is specifically absent — not a category. If no quantified achievements found, flag that explicitly.
- Gap fixes: one concrete action tied to their industry/domain.
- Roadmap milestones: name their actual industry or domain — not generic "AI startup" filler.
- quickWins: 3 things completable in 48 hours that build real momentum.
- topAdvice: the single highest-leverage action in the next 7 days — name what, with whom, producing what output.

STRICTLY FORBIDDEN:
- Generic course names (Reforge, Exponent, Product School, Coursera, Udemy, LinkedIn Learning)
- Book titles as standalone milestones
- "Study X" without a paired artifact
- Vague verbs: explore, learn about, familiarise, research, look into
- Milestones a coach could write without reading the resume

REQUIRED milestone verbs: Interview, Write, Build, Publish, Pitch, Redesign, Analyse, Map, Prototype, Critique, Present, Submit

ROADMAP QUALITY BAR — every milestone AND every step must pass all 3:
1. Person knows exactly what to do Monday morning?
2. Produces something showable to a hiring manager?
3. Specific to their background — not generic advice any PM candidate could follow?

STEPS RULES — each step in the "steps" array must:
- Start with a time label (e.g. "Week 1:", "Week 2:", "Week 3–4:")
- Use a concrete verb (Write, Build, Interview, Publish, Analyse, Pitch, Prototype, Map, Submit)
- Name the specific output produced (not "research X" — name what you'll have at end of the week)
- Reference their actual background, industry, or prior experience where possible
- Never duplicate the milestone — steps are the path to it, not a restatement

Respond ONLY with valid JSON (no markdown, no extra text):
{
  "background": "engineer|data|business|designer|other",
  "resumeQuality": "high|medium|low",
  "score": <0–100>,
  "summary": "<2–3 sentences: name their actual role, biggest AI PM asset, and single most important gap>",
  "timeline": {
    "optimistic": "<e.g. 4 months>",
    "realistic": "<e.g. 6–8 months>",
    "conservative": "<e.g. 9 months — hard max 12>",
    "explanation": "<1–2 sentences: specific factor that most accelerates or delays their timeline>"
  },
  "confidence": "high|medium|low",
  "skills": [
    {"name": "<skill>", "score": <0–100>, "importance": "critical|high|medium"},
    {"name": "<skill>", "score": <0–100>, "importance": "critical|high|medium"},
    {"name": "<skill>", "score": <0–100>, "importance": "critical|high|medium"},
    {"name": "<skill>", "score": <0–100>, "importance": "critical|high|medium"},
    {"name": "<skill>", "score": <0–100>, "importance": "critical|high|medium"}
  ],
  "strengths": [
    "<specific project/role/achievement from resume + why it matters for AI PM>",
    "<second specific transferable asset with direct AI PM relevance>",
    "<third specific transferable asset>"
  ],
  "gaps": [
    {"gap": "<specific missing skill — name what is absent, not a category>", "severity": "high",         "fix": "<one concrete action tied to their domain>"},
    {"gap": "<second gap>",                                                   "severity": "high|medium",  "fix": "<one concrete action>"},
    {"gap": "<third gap>",                                                    "severity": "high|medium",  "fix": "<one concrete action>"},
    {"gap": "<fourth gap>",                                                   "severity": "medium|low",   "fix": "<one concrete action>"},
    {"gap": "<fifth gap>",                                                    "severity": "medium|low",   "fix": "<one concrete action>"}
  ],
  "roadmap": [
    {
      "phase": "Month 1–2",
      "focus": "<capability being built>",
      "milestone": "<EXACT: end-state artifact produced by end of this phase>",
      "steps": [
        "Week 1: <concrete action — verb + object + output. e.g. 'List 5 real friction points from your time at [company], pick the sharpest one, write a 300-word problem statement'>",
        "Week 2: <concrete action — different type of output from Week 1>",
        "Week 3: <concrete action — builds on prior weeks, moves toward milestone>",
        "Week 4–8: <concrete action — final push to milestone, plus one stretch action that signals momentum to hiring managers>"
      ]
    },
    {
      "phase": "Month 3–4",
      "focus": "<capability>",
      "milestone": "<EXACT: different artifact type from Month 1–2>",
      "steps": [
        "Week 1: <concrete action>",
        "Week 2: <concrete action>",
        "Week 3: <concrete action>",
        "Week 4–8: <concrete action — produces the milestone>"
      ]
    },
    {
      "phase": "Month 5–6",
      "focus": "<capability>",
      "milestone": "<EXACT: portfolio piece showable in interviews>",
      "steps": [
        "Week 1: <concrete action>",
        "Week 2: <concrete action>",
        "Week 3: <concrete action>",
        "Week 4–8: <concrete action — produces the milestone>"
      ]
    },
    {
      "phase": "Month 7–9",
      "focus": "Active job search and interview preparation",
      "milestone": "<EXACT: roles count, company types, specific interview types to prep for>",
      "steps": [
        "Week 1: <concrete action — first applications or outreach>",
        "Week 2: <concrete action — interview prep or referral ask>",
        "Week 3: <concrete action — live practice or portfolio polish>",
        "Week 4–12: <concrete action — sustain cadence, handle rejections, iterate>"
      ]
    }
  ],
  "quickWins": [
    "<action completable in 48 hours that produces something tangible>",
    "<second 48-hour action>",
    "<third 48-hour action>"
  ],
  "topAdvice": "<single highest-leverage action for this person in the next 7 days — what, with whom, producing what output>"
}`;

  return prompt;
}

// --- Finalize and cache a parsed analysis result ---

function finalizeAnalysis(result, resumeQuality, resumeText, additionalContext) {
  if (!result.resumeQuality) result.resumeQuality = resumeQuality;
  if (result.timeline) result.timeline = clampTimeline(result.timeline);
  const validated = validateOutput(result);
  const key = cacheKey(resumeText, additionalContext);
  if (analysisCache.size >= CACHE_MAX) analysisCache.delete(analysisCache.keys().next().value);
  analysisCache.set(key, validated);
  return validated;
}

// --- Non-streaming analysis (used by /analyze-text) ---

async function analyzeResume(resumeText, filename, additionalContext = {}, resumeQuality = 'medium') {
  const key = cacheKey(resumeText, additionalContext);
  if (analysisCache.has(key)) { console.log('Cache hit'); return analysisCache.get(key); }
  const prompt = buildAnalysisPrompt(resumeText, additionalContext, resumeQuality);
  const result = await callClaudeJson(prompt, 4500, 'claude-sonnet-4-6');
  return finalizeAnalysis(result, resumeQuality, resumeText, additionalContext);
}

// POST /analyze-resume-stream — SSE streaming endpoint (fast perceived performance)
app.post('/analyze-resume-stream', upload.single('resume'), async (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  const send = (obj) => res.write(`data: ${JSON.stringify(obj)}\n\n`);

  try {
    if (!req.file) return send({ type: 'error', error: 'No file uploaded' }) || res.end();
    if (!process.env.ANTHROPIC_API_KEY) return send({ type: 'error', error: 'API key not set' }) || res.end();

    const rawText = await extractText(req.file);
    const resumeText = preprocessText(rawText);
    if (resumeText.length < 150) return send({ type: 'error', error: 'Could not extract enough text. Please try PDF, DOCX, or TXT.' }) || res.end();

    const quality = assessResumeQuality(resumeText);
    let additionalContext = {};
    try { additionalContext = JSON.parse(req.body.additionalContext || '{}'); } catch (_) {}

    // Cache hit — instant response
    const key = cacheKey(resumeText, additionalContext);
    if (analysisCache.has(key)) {
      const cached = analysisCache.get(key);
      let analysisId = null;
      if (req.session.userId) analysisId = await db.saveAnalysis(req.session.userId, JSON.stringify(cached));
      send({ type: 'done', analysis: cached, analysisId });
      return res.end();
    }

    send({ type: 'start' });

    const prompt = buildAnalysisPrompt(resumeText, additionalContext, quality);
    let fullText = '';

    const stream = anthropic.messages.stream({
      model: 'claude-sonnet-4-6',
      max_tokens: 4500,
      temperature: 0.3,
      messages: [{ role: 'user', content: prompt }],
    });

    stream.on('text', (chunk) => { fullText += chunk; });

    await stream.finalMessage();

    const cleaned = fullText.replace(/^```json?\s*/i, '').replace(/\s*```$/i, '').trim();
    let result;
    try { result = JSON.parse(cleaned); } catch {
      // Retry once without streaming
      result = await callClaudeJson(prompt, 4500, 'claude-sonnet-4-6');
    }

    const validated = finalizeAnalysis(result, quality, resumeText, additionalContext);
    let analysisId = null;
    if (req.session.userId) analysisId = await db.saveAnalysis(req.session.userId, JSON.stringify(validated));

    send({ type: 'done', analysis: validated, analysisId });
    res.end();
  } catch (err) {
    console.error('Stream error:', err);
    send({ type: 'error', error: err.message || 'Analysis failed. Please try again.' });
    res.end();
  }
});

// POST /analyze-resume
app.post('/analyze-resume', upload.single('resume'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    if (!process.env.ANTHROPIC_API_KEY) {
      return res.status(500).json({ error: 'Server not configured with API key. Please set ANTHROPIC_API_KEY.' });
    }

    const rawText = await extractText(req.file);
    const resumeText = preprocessText(rawText);

    if (resumeText.length < 150) {
      return res.status(400).json({ error: 'Could not extract enough text from your resume. Please try a different file format (PDF, DOCX, or TXT).' });
    }

    const quality = assessResumeQuality(resumeText);

    let additionalContext = {};
    if (req.body && req.body.additionalContext) {
      try { additionalContext = JSON.parse(req.body.additionalContext); } catch (_) {}
    }
    const analysis = await analyzeResume(resumeText, req.file.originalname, additionalContext, quality);

    let analysisId = null;
    if (req.session.userId) {
      analysisId = await db.saveAnalysis(req.session.userId, JSON.stringify(analysis));
    }

    res.json({ success: true, analysis, analysisId });
  } catch (err) {
    console.error('Analysis error:', err);
    if (err.message && err.message.includes('JSON')) {
      res.status(500).json({ error: 'Failed to parse AI response. Please try again.' });
    } else if (err.status === 401) {
      res.status(500).json({ error: 'Invalid API key. Please check your ANTHROPIC_API_KEY.' });
    } else {
      res.status(500).json({ error: err.message || 'Analysis failed. Please try again.' });
    }
  }
});

// --- Answer evaluation ---

async function evaluateAnswer({ problemTitle, problemStatement, category, difficulty, answer, resumeContext }) {
  const resumeBlock = resumeContext ? `
Candidate background (from their resume analysis — use this to personalise your feedback):
- Background type: ${resumeContext.background || 'unknown'}
- Readiness score: ${resumeContext.score || 'unknown'}/100
- Summary: ${resumeContext.summary || 'not available'}
- Key strengths: ${(resumeContext.strengths || []).join(' | ') || 'not available'}
- Key gaps identified: ${(resumeContext.gaps || []).join(', ') || 'not available'}
- Skills assessed: ${(resumeContext.skills || []).map(s => `${s.name} (${s.score}/100)`).join(', ') || 'not available'}

Tailor your feedback to their specific background. Reference their actual profile when noting strengths or gaps. For example, if they are an engineer, acknowledge how their technical background helps or hurts their answer. If they have a specific gap from their resume analysis, note whether this answer addresses it or makes it worse.` : '';

  const prompt = `You are an experienced AI PM hiring manager and coach evaluating a practice answer from someone aspiring to become a Product Manager.
${resumeBlock}

Problem: ${problemTitle}
Category: ${category}
Difficulty: ${difficulty}

Problem Statement:
${problemStatement}

Candidate's Answer:
${answer}

Evaluate this answer honestly and constructively. Personalise feedback based on the candidate's background above if available. Respond ONLY with valid JSON (no markdown):
{
  "score": <integer 0-100>,
  "verdict": "<Excellent|Good|Developing|Needs Work>",
  "headline": "<one sentence summary — reference their specific background if known>",
  "strengths": [
    "<specific thing they did well — tie to their background if relevant>",
    "<specific thing they did well>"
  ],
  "improvements": [
    {"issue": "<specific gap — tie to their resume gaps if relevant>", "tip": "<concrete actionable fix specific to their background>"},
    {"issue": "<specific gap or weakness>", "tip": "<concrete actionable fix>"}
  ],
  "keyFrameworks": ["<framework name>", "<framework name>"],
  "modelAnswerHint": "<2-3 sentences on what a strong answer covers — don't write it for them, just guide>",
  "nextStep": "<single most important thing to practice — MUST be specific to their background and produce a real artifact, never a course or book>"
}

IMPORTANT — nextStep rule: The next step must always be a concrete action that produces something real, tailored to who this person is. Never recommend courses, certifications, or books as the next step.`;

  const response = await anthropic.messages.create({
    model: 'claude-opus-4-6',
    max_tokens: 1000,
    messages: [{ role: 'user', content: prompt }],
  });

  const text = response.content[0].type === 'text' ? response.content[0].text : '';
  const cleaned = text.replace(/^```json?\s*/i, '').replace(/\s*```$/i, '').trim();
  return JSON.parse(cleaned);
}

// POST /evaluate-answer
app.post('/evaluate-answer', async (req, res) => {
  try {
    const { problemTitle, problemStatement, category, difficulty, answer, problemId, resumeContext } = req.body;

    if (!answer || answer.trim().length < 30) {
      return res.status(400).json({ error: 'Please write a more complete answer before submitting.' });
    }

    if (!process.env.ANTHROPIC_API_KEY) {
      return res.status(500).json({ error: 'Server not configured with API key.' });
    }

    const feedback = await evaluateAnswer({ problemTitle, problemStatement, category, difficulty, answer, resumeContext });

    if (req.session.userId && problemId !== undefined) {
      await db.saveProblemAttempt(req.session.userId, String(problemId), answer, JSON.stringify(feedback), feedback.score);
    }

    res.json({ success: true, feedback });
  } catch (err) {
    console.error('Evaluation error:', err);
    if (err.message && err.message.includes('JSON')) {
      res.status(500).json({ error: 'Failed to parse AI response. Please try again.' });
    } else {
      res.status(500).json({ error: err.message || 'Evaluation failed. Please try again.' });
    }
  }
});

// POST /analyze-text — analyze pasted resume text (same pipeline as file upload)
app.post('/analyze-text', async (req, res) => {
  try {
    const { text, additionalContext: ctxRaw } = req.body;
    if (!text || typeof text !== 'string') {
      return res.status(400).json({ error: 'No text provided.' });
    }
    if (!process.env.ANTHROPIC_API_KEY) {
      return res.status(500).json({ error: 'Server not configured with API key. Please set ANTHROPIC_API_KEY.' });
    }
    const resumeText = preprocessText(text);
    if (resumeText.length < 150) {
      return res.status(400).json({ error: 'Not enough text to analyze. Please paste more of your resume.' });
    }
    const quality = assessResumeQuality(resumeText);
    let additionalContext = {};
    if (ctxRaw) {
      try { additionalContext = JSON.parse(ctxRaw); } catch (_) {}
    }
    const analysis = await analyzeResume(resumeText, 'pasted-resume.txt', additionalContext, quality);
    let analysisId = null;
    if (req.session.userId) {
      analysisId = await db.saveAnalysis(req.session.userId, JSON.stringify(analysis));
    }
    res.json({ success: true, analysis, analysisId });
  } catch (err) {
    console.error('Text analysis error:', err);
    if (err.message && err.message.includes('JSON')) {
      res.status(500).json({ error: 'Failed to parse AI response. Please try again.' });
    } else if (err.status === 401) {
      res.status(500).json({ error: 'Invalid API key. Please check your ANTHROPIC_API_KEY.' });
    } else {
      res.status(500).json({ error: err.message || 'Analysis failed. Please try again.' });
    }
  }
});

// POST /api/roadmap/enrich-steps — generate week-by-week steps for phases that lack them
app.post('/api/roadmap/enrich-steps', async (req, res) => {
  try {
    const { roadmap, background, summary, gaps } = req.body;
    if (!Array.isArray(roadmap) || roadmap.length === 0) {
      return res.status(400).json({ error: 'roadmap array required' });
    }

    const gapList = Array.isArray(gaps) ? gaps.map(g => g.gap || g).join('; ') : '';
    const prompt = `You are generating specific, week-by-week action steps for an AI PM career roadmap.

Candidate profile:
- Background: ${background || 'general'}
- Summary: ${summary || ''}
- Key gaps to address: ${gapList || 'Not specified'}

Below are the roadmap phases. For EVERY phase, generate exactly 4 concrete action steps. Each step must:
1. Start with a time label: "Week 1:", "Week 2:", "Week 3:", "Week 4+:"
2. Use an action verb: Write, Build, Analyse, Interview, Publish, Prototype, Submit, Map, Pitch, Redesign, Present
3. Name a SPECIFIC output the candidate will have at the end of that week (not "research X" — say what they produce)
4. Be directly tied to THIS candidate's background, industry experience, and the gap being addressed in this phase
5. Never duplicate the milestone — steps are the weekly path to it

Roadmap phases:
${roadmap.map((r, i) => `Phase ${i} — ${r.phase}: ${r.focus}\nMilestone: ${r.milestone}`).join('\n\n')}

Return ONLY valid JSON, no markdown:
{
  "phases": [
    { "phaseIndex": 0, "steps": ["Week 1: ...", "Week 2: ...", "Week 3: ...", "Week 4+: ..."] },
    { "phaseIndex": 1, "steps": ["Week 1: ...", "Week 2: ...", "Week 3: ...", "Week 4+: ..."] },
    { "phaseIndex": 2, "steps": ["Week 1: ...", "Week 2: ...", "Week 3: ...", "Week 4+: ..."] },
    { "phaseIndex": 3, "steps": ["Week 1: ...", "Week 2: ...", "Week 3: ...", "Week 4+: ..."] }
  ]
}`;

    const result = await callClaudeJson(prompt, 1800, 'claude-sonnet-4-6');
    if (!Array.isArray(result.phases)) return res.status(500).json({ error: 'Invalid AI response' });

    // Merge steps back into roadmap phases
    const enriched = roadmap.map((r, i) => {
      const match = result.phases.find(p => p.phaseIndex === i);
      return { ...r, steps: match ? match.steps : (r.steps || []) };
    });

    // If user is logged in, update the stored analysis
    if (req.session.userId) {
      try {
        const latest = await db.getLatestAnalysis(req.session.userId);
        if (latest) {
          latest.roadmap = enriched;
          await db.saveAnalysis(req.session.userId, JSON.stringify(latest));
        }
      } catch (e) { /* non-fatal */ }
    }

    res.json({ success: true, roadmap: enriched });
  } catch (err) {
    console.error('Enrich steps error:', err);
    res.status(500).json({ error: 'Failed to generate steps. Please try again.' });
  }
});

// GET /api/analyses — history list for logged-in user
app.get('/api/analyses', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Not authenticated.' });
  const history = await db.getAnalysisHistory(req.session.userId);
  res.json({ success: true, analyses: history });
});

// GET /api/analyses/:id — full analysis for logged-in user
app.get('/api/analyses/:id', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Not authenticated.' });
  const analysis = await db.getAnalysisById(req.session.userId, parseInt(req.params.id));
  if (!analysis) return res.status(404).json({ error: 'Analysis not found.' });
  res.json({ success: true, analysis });
});

// POST /api/analyses/:id/share — generate shareable token
app.post('/api/analyses/:id/share', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Not authenticated.' });
  const id = parseInt(req.params.id);
  try {
    // Check if token already exists
    const existing = await db.getShareToken(id, req.session.userId);
    if (existing) {
      const shareUrl = `${req.protocol}://${req.get('host')}/report/${existing}`;
      return res.json({ success: true, shareUrl });
    }
    const token = crypto.randomUUID();
    await db.setShareToken(id, req.session.userId, token);
    const shareUrl = `${req.protocol}://${req.get('host')}/report/${token}`;
    res.json({ success: true, shareUrl });
  } catch (err) {
    console.error('Share error:', err);
    res.status(500).json({ error: 'Could not generate share link.' });
  }
});

// GET /api/share/:token — public endpoint to fetch a shared analysis
app.get('/api/share/:token', async (req, res) => {
  const result = await db.getAnalysisByShareToken(req.params.token);
  if (!result) return res.status(404).json({ error: 'Report not found.' });
  res.json({ success: true, analysis: result.analysis, createdAt: result.created_at });
});

// Newsletter subscription — save to Supabase
app.post('/subscribe', express.json(), async (req, res) => {
  const { email } = req.body || {};
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Invalid email' });
  }
  try {
    await db.saveSubscriber(email);
    res.json({ success: true });
  } catch (err) {
    console.error('Subscribe error:', err);
    res.status(500).json({ error: 'Subscription failed.' });
  }
});

// Serve index.html for all other routes (must be last)
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`✅ PM Ascend server running at http://localhost:${PORT}`);
  if (!process.env.ANTHROPIC_API_KEY) {
    console.warn('⚠️  ANTHROPIC_API_KEY not set — resume analysis will fail.');
  }
  if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_KEY) {
    console.warn('⚠️  SUPABASE_URL or SUPABASE_SERVICE_KEY not set — database will fail.');
  }
});
