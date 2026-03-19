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

Respond ONLY with a valid JSON object in this exact format (no markdown, no extra text):
{
  "background": "engineer|data|business|designer|other",
  "score": <integer 0-100 representing PM readiness>,
  "summary": "<2-3 sentence honest assessment of their PM potential>",
  "timeline": {
    "optimistic": "<e.g. 6 months>",
    "realistic": "<e.g. 12 months>",
    "conservative": "<e.g. 18-24 months>",
    "explanation": "<1-2 sentences explaining what drives the timeline>"
  },
  "confidence": "<high|medium|low> — how confident you are in this analysis based on resume quality",
  "skills": [
    {"name": "<skill>", "score": <0-100>, "importance": "<critical|high|medium>"},
    {"name": "<skill>", "score": <0-100>, "importance": "<critical|high|medium>"},
    {"name": "<skill>", "score": <0-100>, "importance": "<critical|high|medium>"},
    {"name": "<skill>", "score": <0-100>, "importance": "<critical|high|medium>"},
    {"name": "<skill>", "score": <0-100>, "importance": "<critical|high|medium>"}
  ],
  "strengths": [
    "<specific strength from their background>",
    "<specific strength from their background>",
    "<specific strength from their background>"
  ],
  "gaps": [
    {"gap": "<specific gap>", "severity": "<high|medium|low>", "fix": "<actionable 1-line fix>"},
    {"gap": "<specific gap>", "severity": "<high|medium|low>", "fix": "<actionable 1-line fix>"},
    {"gap": "<specific gap>", "severity": "<high|medium|low>", "fix": "<actionable 1-line fix>"}
  ],
  "roadmap": [
    {"phase": "Month 1-2", "focus": "<what to work on>", "milestone": "<concrete deliverable>"},
    {"phase": "Month 3-4", "focus": "<what to work on>", "milestone": "<concrete deliverable>"},
    {"phase": "Month 5-6", "focus": "<what to work on>", "milestone": "<concrete deliverable>"},
    {"phase": "Month 7+", "focus": "<what to work on>", "milestone": "<concrete deliverable>"}
  ],
  "topAdvice": "<The single most important thing they should do in the next 30 days>"
}

Be specific to their background. Be honest — if they have a long road ahead, say so clearly. Focus on AI PM roles specifically (not generic PM roles).`;

  const response = await anthropic.messages.create({
    model: 'claude-opus-4-6',
    max_tokens: 2000,
    messages: [{ role: 'user', content: prompt }],
  });

  const text = response.content[0].type === 'text' ? response.content[0].text : '';

  // Parse JSON — strip any accidental markdown fences
  const cleaned = text.replace(/^```json?\s*/i, '').replace(/\s*```$/i, '').trim();
  return JSON.parse(cleaned);
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
