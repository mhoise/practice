require('dotenv').config();
const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const session = require('express-session');
const nodemailer = require('nodemailer');
const { execSync } = require('child_process');
const { MongoClient } = require('mongodb');

const app = express();
const PORT = process.env.PORT || 3001;

// Configuration - set these in environment variables
const CONFIG = {
  WEDDING_DATE: new Date('2025-07-25'),
  PAYPAL_ME_USERNAME: process.env.PAYPAL_ME_USERNAME || 'YOUR_PAYPAL_USERNAME',
  CONSEQUENCE_AMOUNT: 5,
  SESSION_SECRET: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  CODE_SECRET: process.env.CODE_SECRET || crypto.randomBytes(32).toString('hex'),
  ADMIN_EMAIL: process.env.ADMIN_EMAIL || '',
  FRIEND_EMAIL: process.env.FRIEND_EMAIL || '',
  SMTP_HOST: process.env.SMTP_HOST || 'smtp.gmail.com',
  SMTP_PORT: process.env.SMTP_PORT || 587,
  SMTP_USER: process.env.SMTP_USER || '',
  SMTP_PASS: process.env.SMTP_PASS || '',
};

// MongoDB connection
let db;
async function connectDB() {
  const uri = process.env.MONGODB_URI;
  if (!uri) {
    console.error('ERROR: MONGODB_URI not set');
    process.exit(1);
  }
  const client = new MongoClient(uri);
  await client.connect();
  db = client.db('practice');
  console.log('Connected to MongoDB');
}

// Data helpers using MongoDB
async function getData() {
  const appData = await db.collection('appData').findOne({ _id: 'main' });
  if (!appData) {
    const initial = {
      _id: 'main',
      users: {},
      submissions: [],
      streak: 0,
      consequencesTriggered: [],
    };
    await db.collection('appData').insertOne(initial);
    return initial;
  }
  return appData;
}

async function saveData(data) {
  await db.collection('appData').replaceOne({ _id: 'main' }, data, { upsert: true });
}

// Email transporter
let emailTransporter = null;
if (CONFIG.SMTP_USER && CONFIG.SMTP_PASS) {
  emailTransporter = nodemailer.createTransport({
    host: CONFIG.SMTP_HOST,
    port: CONFIG.SMTP_PORT,
    secure: false,
    auth: {
      user: CONFIG.SMTP_USER,
      pass: CONFIG.SMTP_PASS,
    },
  });
}

async function sendEmail(to, subject, html) {
  if (!emailTransporter) {
    console.log(`[EMAIL NOT CONFIGURED] To: ${to}, Subject: ${subject}`);
    return false;
  }
  try {
    await emailTransporter.sendMail({
      from: CONFIG.SMTP_USER,
      to,
      subject,
      html,
    });
    console.log(`Email sent to ${to}: ${subject}`);
    return true;
  } catch (err) {
    console.error('Email error:', err);
    return false;
  }
}

// Session setup
app.use(session({
  secret: CONFIG.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 7 * 24 * 60 * 60 * 1000, // 1 week
  },
}));

// Video storage
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, 'uploads');
    if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    cb(null, `practice-${Date.now()}${path.extname(file.originalname)}`);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 100 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('video/')) cb(null, true);
    else cb(new Error('Only video files allowed'));
  },
});

app.use(express.static('public'));
app.use(express.json());

// Secure weekly code generation using HMAC
function getWeeklyCode() {
  const now = new Date();
  const year = now.getFullYear();
  const startOfYear = new Date(year, 0, 1);
  const weekNum = Math.ceil(((now - startOfYear) / 86400000 + startOfYear.getDay() + 1) / 7);

  const hmac = crypto.createHmac('sha256', CONFIG.CODE_SECRET);
  hmac.update(`${year}-${weekNum}`);
  const hash = hmac.digest('hex').substring(0, 6).toUpperCase();

  return `VIOLIN-${hash}`;
}

function getCurrentWeek() {
  const now = new Date();
  const year = now.getFullYear();
  const startOfYear = new Date(year, 0, 1);
  const weekNum = Math.ceil(((now - startOfYear) / 86400000 + startOfYear.getDay() + 1) / 7);
  return `${year}-W${weekNum}`;
}

function getDeadline() {
  // Deadline is Monday 12 AM (Sunday midnight)
  const now = new Date();
  const day = now.getDay(); // 0 = Sunday
  const daysUntilMonday = day === 0 ? 1 : (8 - day) % 7 || 7;
  const deadline = new Date(now);
  deadline.setDate(deadline.getDate() + daysUntilMonday);
  deadline.setHours(0, 0, 0, 0);
  return deadline;
}

async function hasApprovedSubmissionThisWeek() {
  const data = await getData();
  const currentWeek = getCurrentWeek();
  return data.submissions.some(s => s.week === currentWeek && s.status === 'approved');
}

async function hasPendingSubmissionThisWeek() {
  const data = await getData();
  const currentWeek = getCurrentWeek();
  return data.submissions.some(s => s.week === currentWeek && s.status === 'pending');
}

// Auth middleware
function requireAuth(req, res, next) {
  if (req.session && req.session.user) {
    next();
  } else {
    res.status(401).json({ error: 'Not authenticated' });
  }
}

function requireAdmin(req, res, next) {
  if (req.session && req.session.user && req.session.user.role === 'admin') {
    next();
  } else {
    res.status(403).json({ error: 'Admin access required' });
  }
}

// Initialize users from environment variables (run once on first setup)
async function initializeUsers() {
  const data = await getData();
  const adminPassword = process.env.ADMIN_PASSWORD;
  const friendPassword = process.env.FRIEND_PASSWORD;

  let changed = false;

  // Create admin user (elias) if doesn't exist and password is set
  if (!data.users['elias'] && adminPassword) {
    const hash = await bcrypt.hash(adminPassword, 12);
    data.users['elias'] = { hash, role: 'admin', createdAt: new Date().toISOString() };
    console.log('Created admin user: elias');
    changed = true;
  }

  // Create friend user (victor) if doesn't exist and password is set
  if (!data.users['victor'] && friendPassword) {
    const hash = await bcrypt.hash(friendPassword, 12);
    data.users['victor'] = { hash, role: 'friend', createdAt: new Date().toISOString() };
    console.log('Created friend user: victor');
    changed = true;
  }

  if (Object.keys(data.users).length === 0) {
    console.log('WARNING: No users configured. Set ADMIN_PASSWORD and FRIEND_PASSWORD env vars.');
  }

  if (changed) {
    await saveData(data);
  }
}

// Generate secure approval token
function generateApprovalToken(submissionId, action) {
  const data = `${submissionId}:${action}:${CONFIG.CODE_SECRET}`;
  return crypto.createHash('sha256').update(data).digest('hex').substring(0, 32);
}

// Verify approval token
function verifyApprovalToken(submissionId, action, token) {
  const expected = generateApprovalToken(submissionId, action);
  return crypto.timingSafeEqual(Buffer.from(token), Buffer.from(expected));
}

// Auth routes
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  const data = await getData();
  const user = data.users[username];

  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const valid = await bcrypt.compare(password, user.hash);
  if (!valid) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  req.session.user = { username, role: user.role };
  res.json({ success: true, role: user.role });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

app.get('/api/me', (req, res) => {
  if (req.session && req.session.user) {
    res.json(req.session.user);
  } else {
    res.status(401).json({ error: 'Not authenticated' });
  }
});

// Friend routes
app.get('/api/dashboard', requireAuth, async (req, res) => {
  const data = await getData();
  const now = new Date();
  const daysUntilWedding = Math.ceil((CONFIG.WEDDING_DATE - now) / (1000 * 60 * 60 * 24));
  const weeksUntilWedding = Math.ceil(daysUntilWedding / 7);
  const deadline = getDeadline();
  const currentWeek = getCurrentWeek();

  const thisWeekSubmission = data.submissions.find(s => s.week === currentWeek);

  res.json({
    weeklyCode: getWeeklyCode(),
    currentWeek,
    deadline: deadline.toISOString(),
    daysUntilWedding: Math.max(0, daysUntilWedding),
    weeksUntilWedding: Math.max(0, weeksUntilWedding),
    streak: data.streak || 0,
    thisWeekStatus: thisWeekSubmission ? thisWeekSubmission.status : 'not_submitted',
    submissions: data.submissions
      .filter(s => req.session.user.role === 'admin' || s.week === currentWeek)
      .slice(-10)
      .reverse(),
    weddingDate: CONFIG.WEDDING_DATE.toISOString(),
    isSaturday: now.getDay() === 6,
    role: req.session.user.role,
  });
});

// Compress video using ffmpeg
function compressVideo(inputPath, outputPath) {
  try {
    // Compress to 720p, lower bitrate for email attachment (~10-15MB target)
    execSync(`ffmpeg -i "${inputPath}" -vf "scale=-2:720" -c:v libx264 -preset fast -crf 28 -c:a aac -b:a 128k -y "${outputPath}"`, {
      stdio: 'pipe',
      timeout: 120000, // 2 minute timeout
    });
    return true;
  } catch (error) {
    console.error('Video compression failed:', error.message);
    return false;
  }
}

app.post('/api/submit', requireAuth, upload.single('video'), async (req, res) => {
  if (req.session.user.role !== 'friend') {
    return res.status(403).json({ error: 'Only friend can submit' });
  }

  if (!req.file) {
    return res.status(400).json({ error: 'No video uploaded' });
  }

  const currentWeek = getCurrentWeek();
  const weeklyCode = getWeeklyCode();

  // Check if already has pending or approved submission
  const data = await getData();
  const existing = data.submissions.find(s => s.week === currentWeek);
  if (existing && (existing.status === 'approved' || existing.status === 'pending')) {
    fs.unlinkSync(req.file.path);
    return res.status(400).json({
      error: existing.status === 'approved'
        ? 'Already approved for this week'
        : 'Submission pending review'
    });
  }

  try {
    // Generate submission ID and approval tokens
    const submissionId = crypto.randomBytes(8).toString('hex');
    const approveToken = generateApprovalToken(submissionId, 'approve');
    const rejectToken = generateApprovalToken(submissionId, 'reject');

    // Compress video for email
    const compressedPath = req.file.path.replace(/\.[^.]+$/, '_compressed.mp4');
    const compressionSuccess = compressVideo(req.file.path, compressedPath);

    // Save submission as pending (no video path stored since we email it)
    const submission = {
      id: submissionId,
      week: currentWeek,
      submittedAt: new Date().toISOString(),
      status: 'pending',
    };

    // Remove old rejected submission for this week if exists
    data.submissions = data.submissions.filter(s => !(s.week === currentWeek && s.status === 'rejected'));
    data.submissions.push(submission);
    await saveData(data);

    // Build approval links
    const baseUrl = process.env.APP_URL || `http://localhost:${PORT}`;
    const approveLink = `${baseUrl}/api/review?id=${submissionId}&action=approve&token=${approveToken}`;
    const rejectLink = `${baseUrl}/api/review?id=${submissionId}&action=reject&token=${rejectToken}`;

    const emailHtml = `
      <h2>🎻 Practice Video Submitted - ${currentWeek}</h2>
      <p><strong>Week:</strong> ${currentWeek}<br>
      <strong>Expected code:</strong> ${weeklyCode}</p>

      <p>Video is attached. Please verify:</p>
      <ul>
        <li>The code "${weeklyCode}" is visible on paper in the video</li>
        <li>It's a real video of Victor practicing</li>
      </ul>

      <div style="margin:2rem 0;">
        <a href="${approveLink}" style="background:#22c55e;color:white;padding:12px 24px;text-decoration:none;border-radius:6px;margin-right:12px;display:inline-block;">✅ APPROVE</a>
        <a href="${rejectLink}" style="background:#ef4444;color:white;padding:12px 24px;text-decoration:none;border-radius:6px;display:inline-block;">❌ REJECT</a>
      </div>

      <p style="color:#666;font-size:0.875rem;">Click a button above to approve or reject this submission.</p>
    `;

    // Send email with attachment
    const videoToAttach = compressionSuccess && fs.existsSync(compressedPath) ? compressedPath : req.file.path;
    const attachmentSize = fs.statSync(videoToAttach).size;

    if (emailTransporter) {
      try {
        await emailTransporter.sendMail({
          from: CONFIG.SMTP_USER,
          to: CONFIG.ADMIN_EMAIL,
          subject: `🎻 Practice Video - ${currentWeek}`,
          html: emailHtml,
          attachments: attachmentSize < 25 * 1024 * 1024 ? [{ // Only attach if under 25MB
            filename: `practice-${currentWeek}.mp4`,
            path: videoToAttach,
          }] : [],
        });
        console.log(`Email sent to ${CONFIG.ADMIN_EMAIL} with video (${(attachmentSize / 1024 / 1024).toFixed(1)}MB)`);
      } catch (emailErr) {
        console.error('Email error:', emailErr);
      }
    } else {
      console.log(`[EMAIL NOT CONFIGURED] Would send to: ${CONFIG.ADMIN_EMAIL}`);
    }

    // Clean up video files after sending
    try {
      fs.unlinkSync(req.file.path);
      if (compressionSuccess && fs.existsSync(compressedPath)) {
        fs.unlinkSync(compressedPath);
      }
    } catch (cleanupErr) {
      console.error('Cleanup error:', cleanupErr);
    }

    res.json({
      success: true,
      message: 'Submitted for review',
    });

  } catch (error) {
    console.error('Submit error:', error);
    // Clean up on error
    try { fs.unlinkSync(req.file.path); } catch {}
    res.status(500).json({ error: 'Submission failed', details: error.message });
  }
});

// Email-based approval endpoint (no auth required - uses secure token)
app.get('/api/review', async (req, res) => {
  const { id, action, token } = req.query;

  if (!id || !action || !token) {
    return res.status(400).send(htmlResponse('Missing Parameters', 'Invalid approval link.', 'error'));
  }

  if (!['approve', 'reject'].includes(action)) {
    return res.status(400).send(htmlResponse('Invalid Action', 'Invalid action specified.', 'error'));
  }

  // Verify token
  try {
    if (!verifyApprovalToken(id, action, token)) {
      return res.status(403).send(htmlResponse('Invalid Token', 'This approval link is invalid or has been tampered with.', 'error'));
    }
  } catch {
    return res.status(403).send(htmlResponse('Invalid Token', 'This approval link is invalid.', 'error'));
  }

  const data = await getData();
  const submission = data.submissions.find(s => s.id === id);

  if (!submission) {
    return res.status(404).send(htmlResponse('Not Found', 'Submission not found.', 'error'));
  }

  if (submission.status !== 'pending') {
    return res.send(htmlResponse('Already Reviewed', `This submission was already ${submission.status}.`, 'info'));
  }

  submission.status = action === 'approve' ? 'approved' : 'rejected';
  submission.reviewedAt = new Date().toISOString();

  if (action === 'approve') {
    data.streak = (data.streak || 0) + 1;
  }

  await saveData(data);

  // Notify Victor of result
  const resultEmoji = action === 'approve' ? '✅' : '❌';
  const resultText = action === 'approve'
    ? `Great job! Your practice video for ${submission.week} has been approved. Your streak is now ${data.streak} weeks!`
    : `Your practice video for ${submission.week} was rejected. Please submit a new video.`;

  await sendEmail(
    CONFIG.FRIEND_EMAIL,
    `${resultEmoji} Practice Video ${action === 'approve' ? 'Approved' : 'Rejected'} - ${submission.week}`,
    `<p>${resultText}</p>`
  );

  const title = action === 'approve' ? 'Approved!' : 'Rejected';
  const message = action === 'approve'
    ? `Submission approved. Victor's streak is now ${data.streak} weeks.`
    : 'Submission rejected. Victor has been notified to submit again.';

  res.send(htmlResponse(title, message, action === 'approve' ? 'success' : 'warning'));
});

// Simple HTML response helper
function htmlResponse(title, message, type) {
  const colors = {
    success: '#22c55e',
    error: '#ef4444',
    warning: '#f59e0b',
    info: '#3b82f6'
  };
  return `<!DOCTYPE html>
<html><head><title>${title}</title><meta name="viewport" content="width=device-width, initial-scale=1">
<style>body{font-family:system-ui;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;background:#f5f5f5;}
.card{background:white;padding:2rem;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,0.1);text-align:center;max-width:400px;}
h1{color:${colors[type]};margin-bottom:1rem;}p{color:#666;}</style></head>
<body><div class="card"><h1>${title}</h1><p>${message}</p></div></body></html>`;
}

// Admin routes
app.get('/api/admin/deadline-status', requireAdmin, async (req, res) => {
  const data = await getData();
  const currentWeek = getCurrentWeek();
  const deadline = getDeadline();
  const now = new Date();

  const hasApproved = data.submissions.some(s => s.week === currentWeek && s.status === 'approved');
  const hasPending = data.submissions.some(s => s.week === currentWeek && s.status === 'pending');
  const deadlinePassed = now > deadline;

  const canTriggerConsequence = deadlinePassed && !hasApproved;
  const alreadyTriggered = (data.consequencesTriggered || []).includes(currentWeek);

  res.json({
    currentWeek,
    deadline: deadline.toISOString(),
    deadlinePassed,
    hasApproved,
    hasPending,
    canTriggerConsequence: canTriggerConsequence && !alreadyTriggered,
    alreadyTriggered,
    paypalLink: `https://paypal.me/${CONFIG.PAYPAL_ME_USERNAME}/${CONFIG.CONSEQUENCE_AMOUNT}`,
  });
});

app.post('/api/admin/trigger-consequence', requireAdmin, async (req, res) => {
  const data = await getData();
  const currentWeek = getCurrentWeek();

  if (!data.consequencesTriggered) data.consequencesTriggered = [];

  if (data.consequencesTriggered.includes(currentWeek)) {
    return res.status(400).json({ error: 'Already triggered for this week' });
  }

  // Reset streak
  data.streak = 0;
  data.consequencesTriggered.push(currentWeek);
  await saveData(data);

  const paypalLink = `https://paypal.me/${CONFIG.PAYPAL_ME_USERNAME}/${CONFIG.CONSEQUENCE_AMOUNT}`;

  // Email friend about consequence
  await sendEmail(
    CONFIG.FRIEND_EMAIL,
    'Practice Deadline Missed - Consequence Triggered',
    `<p>You missed the practice deadline for ${currentWeek}.</p>
    <p>As agreed, you owe $${CONFIG.CONSEQUENCE_AMOUNT}.</p>
    <p><a href="${paypalLink}" style="background: #0070ba; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px;">Pay $${CONFIG.CONSEQUENCE_AMOUNT} via PayPal</a></p>
    <p>Your streak has been reset to 0. Don't let this happen again!</p>`
  );

  res.json({
    success: true,
    paypalLink,
    message: 'Consequence triggered. Friend has been notified.',
  });
});

// Saturday reminder cron endpoint (call this via external cron service)
app.post('/api/cron/saturday-reminder', async (req, res) => {
  const cronSecret = req.headers['x-cron-secret'];
  if (cronSecret !== process.env.CRON_SECRET) {
    return res.status(403).json({ error: 'Invalid cron secret' });
  }

  const now = new Date();
  if (now.getDay() !== 6) {
    return res.json({ skipped: true, reason: 'Not Saturday' });
  }

  if (await hasApprovedSubmissionThisWeek() || await hasPendingSubmissionThisWeek()) {
    return res.json({ skipped: true, reason: 'Already submitted' });
  }

  const deadline = getDeadline();
  const weeklyCode = getWeeklyCode();

  await sendEmail(
    CONFIG.FRIEND_EMAIL,
    'Reminder: Practice Video Due Monday',
    `<p>This is your Saturday reminder.</p>
    <p>You haven't submitted your practice video yet this week.</p>
    <p><strong>Deadline:</strong> ${deadline.toLocaleDateString('en-US', { weekday: 'long', month: 'long', day: 'numeric' })} at midnight</p>
    <p><strong>This week's code:</strong> <code style="font-size: 18px; background: #f0f0f0; padding: 4px 8px;">${weeklyCode}</code></p>
    <p>Write the code on paper and show it in your video.</p>
    <p><a href="${process.env.APP_URL || 'http://localhost:' + PORT}">Submit your video</a></p>`
  );

  res.json({ success: true, sent: true });
});

// Deadline check cron endpoint
app.post('/api/cron/deadline-check', async (req, res) => {
  const cronSecret = req.headers['x-cron-secret'];
  if (cronSecret !== process.env.CRON_SECRET) {
    return res.status(403).json({ error: 'Invalid cron secret' });
  }

  const deadline = getDeadline();
  const now = new Date();

  // Only alert on Monday after deadline
  if (now.getDay() !== 1) {
    return res.json({ skipped: true, reason: 'Not Monday' });
  }

  if (await hasApprovedSubmissionThisWeek()) {
    return res.json({ skipped: true, reason: 'Already approved' });
  }

  const currentWeek = getCurrentWeek();
  const data = await getData();
  const alreadyTriggered = (data.consequencesTriggered || []).includes(currentWeek);

  if (alreadyTriggered) {
    return res.json({ skipped: true, reason: 'Already triggered' });
  }

  await sendEmail(
    CONFIG.ADMIN_EMAIL,
    'DEADLINE MISSED - Consequence Available',
    `<p>The practice deadline has passed and no video was approved for ${currentWeek}.</p>
    <p><a href="${process.env.APP_URL || 'http://localhost:' + PORT}" style="background: #dc3545; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px;">Trigger Consequence</a></p>`
  );

  res.json({ success: true, alertSent: true });
});

// Initialize and start server
connectDB().then(async () => {
  await initializeUsers();
  app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
    console.log(`Wedding: ${CONFIG.WEDDING_DATE.toDateString()}`);
    console.log(`This week's code: ${getWeeklyCode()}`);
    console.log(`Deadline: ${getDeadline().toISOString()}`);
  });
}).catch(err => {
  console.error('Failed to start:', err);
  process.exit(1);
});
