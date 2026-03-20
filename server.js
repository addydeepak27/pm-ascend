require('dotenv').config();
const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const Anthropic = require('@anthropic-ai/sdk');

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

// Extract text from uploaded file
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

// Analyze resume with Claude
async function analyzeResume(resumeText, filename) {
  const prompt = `You are an expert AI Product Manager career coach. Analyze the following resume and provide honest, actionable feedback for someone aspiring to become an AI Product Manager.

Resume filename: ${filename}
Resume content:
${resumeText || '(Resume text could not be extracted — base your analysis on the filename and any context available, or provide general guidance for the most common background type)'}

ABSOLUTE TIMELINE RULE — this overrides everything else, including your own judgment:
The maximum value you may ever output for ANY timeline field is 12 months.
This applies even if the readiness score is 0/100. Even if the person has zero relevant experience.
Even if you believe more time is needed. 12 months is the ceiling. No exceptions. No rounding up.
Any number above 12 in any timeline field is a hallucination and must not appear.

- Optimistic: 3–6 months for most backgrounds. Never exceed 8.
- Realistic: 6–10 months for most backgrounds. Never exceed 11.
- Conservative: 8–12 months for most backgrounds. Hard cap at 12. Always.

Per-background benchmarks (stay within these ranges):
- Software Engineers / Developers: optimistic 4, realistic 5–7, conservative 8
- Data Scientists / Analysts: optimistic 4, realistic 5–7, conservative 8
- Business Analysts / Consultants: optimistic 5, realistic 6–8, conservative 9
- Finance / Banking: optimistic 6, realistic 8–10, conservative 11
- Marketing / Operations / non-technical: optimistic 5, realistic 6–9, conservative 10
- Students / Recent Graduates: optimistic 5, realistic 7–9, conservative 11
- Complete career changers (no corporate experience): optimistic 6, realistic 9–10, conservative 12
- Existing Product Managers (non-AI): optimistic 3, realistic 4–6, conservative 8
- UX Designers / Researchers: optimistic 4, realistic 6–8, conservative 9

PERSONALIZATION RULES — every part of your response must be specific to THIS person:
- Reference their actual job title, company type, industry, or specific skills from their resume
- Strengths must name something concrete from their resume (e.g. "Your 4 years building recommendation systems at a fintech startup..." not "Your technical background...")
- Gaps must name the specific missing thing relative to AI PM roles (e.g. "No evidence of user interviews or discovery work despite 6 years in product-adjacent roles" not "lacks PM experience")
- Gap fixes must be a single concrete action tied to their industry (e.g. "Interview 3 loan officers about how they use AI tools today — write up the findings as a 1-page discovery brief")
- Roadmap phases must reference their actual industry, tools, or domain — not generic AI products
- topAdvice must be the ONE thing most specific and highest-leverage for this exact person right now

Respond ONLY with a valid JSON object in this exact format (no markdown, no extra text):
{
  "background": "engineer|data|business|designer|other",
  "score": <integer 0-100 representing PM readiness>,
  "summary": "<2-3 sentences — name their actual role/background, their biggest asset for AI PM, and the single most important gap standing between them and a role>",
  "timeline": {
    "optimistic": "<e.g. 4 months>",
    "realistic": "<e.g. 6-8 months — MUST be within the benchmark above for their background>",
    "conservative": "<e.g. 9 months — HARD MAX 12 months>",
    "explanation": "<1-2 sentences — name the specific factor from their background that most accelerates or delays their timeline>"
  },
  "confidence": "<high|medium|low> — how confident you are in this analysis based on resume quality",
  "skills": [
    {"name": "<skill most relevant to their background>", "score": <0-100>, "importance": "<critical|high|medium>"},
    {"name": "<skill>", "score": <0-100>, "importance": "<critical|high|medium>"},
    {"name": "<skill>", "score": <0-100>, "importance": "<critical|high|medium>"},
    {"name": "<skill>", "score": <0-100>, "importance": "<critical|high|medium>"},
    {"name": "<skill>", "score": <0-100>, "importance": "<critical|high|medium>"}
  ],
  "strengths": [
    "<name a specific project, role, or skill from their resume and explain exactly why it matters for AI PM>",
    "<name a second specific thing from their background and its direct relevance to AI PM hiring>",
    "<name a third specific transferable asset — be concrete, not generic>"
  ],
  "gaps": [
    {"gap": "<specific missing skill or experience — name what is absent, not just a category>", "severity": "high", "fix": "<one concrete action tied to their industry — e.g. 'Interview 3 [their domain] professionals about their biggest workflow frustration with AI tools and write a 1-page discovery brief'>"},
    {"gap": "<second specific gap>", "severity": "<high|medium>", "fix": "<one concrete action>"},
    {"gap": "<third specific gap>", "severity": "<medium|low>", "fix": "<one concrete action>"}
  ],
  "roadmap": [
    {
      "phase": "Month 1-2",
      "focus": "<theme for this phase — what capability they are building>",
      "milestone": "<EXACT deliverable: describe precisely what they will create, who they will talk to, what they will publish — name the specific industry, product, or domain from their background. Format: ACTION + OBJECT + STANDARD. E.g. 'Interview 5 [their role] professionals about how AI has changed their workflow, synthesise findings into a 1-page opportunity brief, and post it on LinkedIn for feedback'>"
    },
    {
      "phase": "Month 3-4",
      "focus": "<theme>",
      "milestone": "<EXACT deliverable with the same specificity — must be a different type of artifact from Month 1-2>"
    },
    {
      "phase": "Month 5-6",
      "focus": "<theme>",
      "milestone": "<EXACT deliverable — by this phase they should have a portfolio piece they can show in interviews>"
    },
    {
      "phase": "Month 7-9",
      "focus": "Active job search and interview preparation",
      "milestone": "<EXACT actions: how many roles to apply to, what type of companies match their background, what specific interview question types to prepare for given their gaps>"
    }
  ],
  "topAdvice": "<The single highest-leverage action for THIS specific person in the next 7 days — be precise: name what they should do, with whom, producing what output>"
}

ROADMAP QUALITY BAR — each milestone must pass ALL of these tests:
1. Could I hand this to the person and they know exactly what to do on Monday morning? (yes/no)
2. Does it produce something they can show a hiring manager? (yes/no)
3. Is it specific to their industry or background — not something any PM candidate could do? (yes/no)
If any answer is no, rewrite the milestone until all three are yes.

STRICTLY FORBIDDEN in any field:
- Generic course names (Reforge, Exponent, Product School, Udemy, Coursera, etc.)
- Book recommendations as standalone milestones
- "Study X framework" without a paired artifact
- Vague verbs: "explore", "learn about", "familiarise yourself with", "research", "look into"
- Any milestone a career coach could have written without reading the resume

REQUIRED milestone verbs: Interview, Write, Build, Publish, Pitch, Redesign, Analyse, Map, Prototype, Critique, Present, Submit`;

  const response = await anthropic.messages.create({
    model: 'claude-opus-4-6',
    max_tokens: 3000,
    messages: [{ role: 'user', content: prompt }],
  });

  const text = response.content[0].type === 'text' ? response.content[0].text : '';

  // Parse JSON — strip any accidental markdown fences
  const cleaned = text.replace(/^```json?\s*/i, '').replace(/\s*```$/i, '').trim();
  const result = JSON.parse(cleaned);

  // Safety clamp: enforce 12-month ceiling on all timeline fields regardless of model output
  if (result.timeline && typeof result.timeline === 'object') {
    const clampMonths = (val) => {
      if (!val) return val;
      // Extract the largest number from strings like "9 months", "10-12 months", "24 months"
      const nums = String(val).match(/\d+/g);
      if (!nums) return val;
      const max = Math.max(...nums.map(Number));
      if (max <= 12) return val;
      // Replace all numbers above 12 with clamped equivalents
      return String(val).replace(/\d+/g, n => Math.min(Number(n), 12));
    };
    result.timeline.optimistic = clampMonths(result.timeline.optimistic);
    result.timeline.realistic = clampMonths(result.timeline.realistic);
    result.timeline.conservative = clampMonths(result.timeline.conservative);
  }

  return result;
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

    const resumeText = await extractText(req.file);
    const analysis = await analyzeResume(resumeText, req.file.originalname);

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

// Evaluate a practice problem answer with Claude
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
app.post('/evaluate-answer', express.json(), async (req, res) => {
  try {
    const { problemTitle, problemStatement, category, difficulty, answer } = req.body;

    if (!answer || answer.trim().length < 30) {
      return res.status(400).json({ error: 'Please write a more complete answer before submitting.' });
    }

    if (!process.env.ANTHROPIC_API_KEY) {
      return res.status(500).json({ error: 'Server not configured with API key.' });
    }

    const feedback = await evaluateAnswer({ problemTitle, problemStatement, category, difficulty, answer });
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

// Serve index.html for all other routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`✅ PM Ascend server running at http://localhost:${PORT}`);
  if (!process.env.ANTHROPIC_API_KEY) {
    console.warn('⚠️  ANTHROPIC_API_KEY not set — resume analysis will fail.');
  }
});
