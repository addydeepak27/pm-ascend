require('dotenv').config();
const express = require('express');
const multer = require('multer');
const path = require('path');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const bcrypt = require('bcrypt');
const Anthropic = require('@anthropic-ai/sdk');
const db = require('./db');

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

// Session middleware
app.use(session({
  store: new SQLiteStore({ db: 'sessions.db', dir: __dirname }),
  secret: process.env.SESSION_SECRET || 'dev-secret-change-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
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
    const user = db.createUser({ name, email: email.toLowerCase(), role, passwordHash });

    req.session.userId = user.id;
    req.session.userName = user.name;

    res.json({ success: true, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
  } catch (err) {
    if (err.message && err.message.includes('UNIQUE constraint failed')) {
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

    const user = db.findUserByEmail(email.toLowerCase());
    // Always compare (even with dummy hash) to prevent timing-based email enumeration
    const hash = user ? user.password_hash : DUMMY_HASH;
    const match = await bcrypt.compare(password, hash);

    if (!user || !match) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    req.session.userId = user.id;
    req.session.userName = user.name;

    const analysis = db.getLatestAnalysis(user.id);
    const attempts = db.getProblemAttempts(user.id);
    const roadmapProgress = db.getRoadmapProgress(user.id);

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

app.get('/api/auth/me', (req, res) => {
  if (!req.session.userId) {
    return res.json({ user: null });
  }
  const user = db.findUserByEmail('_placeholder_'); // We'll look up by id instead
  const userRow = require('better-sqlite3')(path.join(__dirname, 'pm-ascend.db'))
    .prepare('SELECT id, name, email, role FROM users WHERE id = ?')
    .get(req.session.userId);

  if (!userRow) {
    req.session.destroy(() => {});
    return res.json({ user: null });
  }

  const analysis = db.getLatestAnalysis(req.session.userId);
  const attempts = db.getProblemAttempts(req.session.userId);
  const roadmapProgress = db.getRoadmapProgress(req.session.userId);

  res.json({
    user: { id: userRow.id, name: userRow.name, email: userRow.email, role: userRow.role },
    analysis,
    attempts,
    roadmapProgress,
  });
});

app.post('/api/user/roadmap/progress', (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Not authenticated.' });
  }
  const { phaseIndex, completed } = req.body;
  if (phaseIndex === undefined || completed === undefined) {
    return res.status(400).json({ error: 'phaseIndex and completed are required.' });
  }
  db.upsertRoadmapProgress(req.session.userId, phaseIndex, completed);
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

// --- Claude JSON helper — with auto-retry on parse failure ---

async function callClaudeJson(prompt, maxTokens = 4500) {
  for (let attempt = 0; attempt < 2; attempt++) {
    const response = await anthropic.messages.create({
      model: 'claude-opus-4-6',
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

// --- Pass 1: Structured fact extraction ---

async function extractFacts(resumeText, filename) {
  const prompt = `Extract structured facts from this resume. Return ONLY valid JSON — no markdown fences, no explanation.

Resume filename: ${filename}
Resume:
${resumeText}

Return exactly this JSON:
{
  "currentRole": "<most recent job title>",
  "yearsExperience": "<total work experience, e.g. '4 years'>",
  "industry": "<primary industry, e.g. fintech, healthcare, edtech, SaaS>",
  "companies": ["<employer 1>", "<employer 2>"],
  "tools": ["<specific tool, language, or framework explicitly mentioned>"],
  "quantifiedAchievements": ["<any bullet that includes a number, %, or $ figure>"],
  "pmAdjacentWork": ["<product decisions, user research, specs, roadmaps, strategy, or cross-functional work found>"],
  "education": "<highest degree and field>",
  "background": "engineer|data|business|designer|other"
}`;
  return callClaudeJson(prompt, 1000);
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

  if (!Array.isArray(result.roadmap))   result.roadmap = [];
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

// --- Resume analysis (two-pass) ---

async function analyzeResume(resumeText, filename, additionalContext = {}, resumeQuality = 'medium') {
  // Pass 1: extract structured facts from the resume
  let facts = {};
  if (resumeText && resumeText.length > 50) {
    try { facts = await extractFacts(resumeText, filename); } catch (e) { console.warn('Fact extraction failed:', e.message); }
  }

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

  const factsBlock = Object.keys(facts).length > 0
    ? `Structured facts extracted from their resume (use these as ground truth):
- Current role: ${facts.currentRole || 'Unknown'}
- Years experience: ${facts.yearsExperience || 'Unknown'}
- Industry: ${facts.industry || 'Unknown'}
- Companies: ${(facts.companies || []).join(', ') || 'Unknown'}
- Tools / skills: ${(facts.tools || []).join(', ') || 'Unknown'}
- Quantified achievements: ${(facts.quantifiedAchievements || []).join(' | ') || 'None found — flag as a gap'}
- PM-adjacent work: ${(facts.pmAdjacentWork || []).join(' | ') || 'None found'}
- Education: ${facts.education || 'Unknown'}`
    : '(Resume could not be fully parsed — provide best-effort analysis and lower confidence score accordingly)';

  // Pass 2: full analysis prompt using structured facts
  const prompt = `You are an expert AI Product Manager career coach conducting a deep, personalised readiness analysis.

${factsBlock}

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

ROADMAP QUALITY BAR — every milestone must pass all 3:
1. Person knows exactly what to do Monday morning?
2. Produces something showable to a hiring manager?
3. Specific to their background — not generic advice any PM candidate could follow?

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
    {"phase": "Month 1–2", "focus": "<capability being built>",                         "milestone": "<EXACT: action + object + standard, tied to their industry>"},
    {"phase": "Month 3–4", "focus": "<capability>",                                     "milestone": "<EXACT: different artifact type from Month 1–2>"},
    {"phase": "Month 5–6", "focus": "<capability>",                                     "milestone": "<EXACT: portfolio piece showable in interviews>"},
    {"phase": "Month 7–9", "focus": "Active job search and interview preparation",       "milestone": "<EXACT: roles count, company types, specific interview types to prep for>"}
  ],
  "quickWins": [
    "<action completable in 48 hours that produces something tangible>",
    "<second 48-hour action>",
    "<third 48-hour action>"
  ],
  "topAdvice": "<single highest-leverage action for this person in the next 7 days — what, with whom, producing what output>"
}`;

  const result = await callClaudeJson(prompt, 4500);
  if (!result.resumeQuality) result.resumeQuality = resumeQuality;
  if (result.timeline) result.timeline = clampTimeline(result.timeline);
  return validateOutput(result);
}

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

    // Persist analysis if user is logged in
    if (req.session.userId) {
      db.saveAnalysis(req.session.userId, JSON.stringify(analysis));
    }

    res.json({ success: true, analysis });
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

async function evaluateAnswer({ problemTitle, problemStatement, category, difficulty, answer }) {
  const prompt = `You are an experienced AI PM hiring manager and coach evaluating a practice answer from someone aspiring to become a Product Manager.

Problem: ${problemTitle}
Category: ${category}
Difficulty: ${difficulty}

Problem Statement:
${problemStatement}

Candidate's Answer:
${answer}

Evaluate this answer honestly and constructively. Respond ONLY with valid JSON (no markdown):
{
  "score": <integer 0-100>,
  "verdict": "<Excellent|Good|Developing|Needs Work>",
  "headline": "<one sentence summary of overall quality>",
  "strengths": [
    "<specific thing they did well>",
    "<specific thing they did well>"
  ],
  "improvements": [
    {"issue": "<specific gap or weakness>", "tip": "<concrete actionable fix>"},
    {"issue": "<specific gap or weakness>", "tip": "<concrete actionable fix>"}
  ],
  "keyFrameworks": ["<framework name>", "<framework name>"],
  "modelAnswerHint": "<2-3 sentences on what a strong answer covers — don't write it for them, just guide>",
  "nextStep": "<single most important thing to practice — MUST be a specific hands-on action or artifact to produce, never a course, book, or passive study task>"
}

IMPORTANT — nextStep rule: The next step must always be a concrete action that produces something real. Examples of good next steps: "Pick a real AI product and write a 1-page critique of one specific decision the PM team made", "Find one person with this problem and interview them for 15 minutes — write up what you learned", "Rewrite your answer using the CIRCLES framework and post it for peer feedback". Never recommend courses, certifications, or books as the next step.`;

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
    const { problemTitle, problemStatement, category, difficulty, answer, problemId } = req.body;

    if (!answer || answer.trim().length < 30) {
      return res.status(400).json({ error: 'Please write a more complete answer before submitting.' });
    }

    if (!process.env.ANTHROPIC_API_KEY) {
      return res.status(500).json({ error: 'Server not configured with API key.' });
    }

    const feedback = await evaluateAnswer({ problemTitle, problemStatement, category, difficulty, answer });

    // Persist attempt if user is logged in and problemId provided
    if (req.session.userId && problemId !== undefined) {
      db.saveProblemAttempt(req.session.userId, String(problemId), answer, JSON.stringify(feedback), feedback.score);
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

// Newsletter subscription — save email to subscribers.json
const fs = require('fs');
app.post('/subscribe', express.json(), (req, res) => {
  const { email } = req.body || {};
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Invalid email' });
  }
  const file = path.join(__dirname, 'subscribers.json');
  let list = [];
  try { list = JSON.parse(fs.readFileSync(file, 'utf8')); } catch (_) {}
  if (!list.includes(email)) {
    list.push(email);
    fs.writeFileSync(file, JSON.stringify(list, null, 2));
  }
  res.json({ success: true });
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
});
