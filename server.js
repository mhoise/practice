require('dotenv').config();
const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const session = require('express-session');
const MongoStore = require('connect-mongo').default;
const cron = require('node-cron');
const { execSync } = require('child_process');
const { MongoClient, GridFSBucket, ObjectId } = require('mongodb');

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
  DISCORD_WEBHOOK_URL: process.env.DISCORD_WEBHOOK_URL || '',
  VICTOR_DISCORD_ID: process.env.VICTOR_DISCORD_ID || '625081496541331516',
};

// MongoDB connection
let db;
let bucket;
async function connectDB() {
  const uri = process.env.MONGODB_URI;
  if (!uri) {
    console.error('ERROR: MONGODB_URI not set');
    process.exit(1);
  }
  const client = new MongoClient(uri);
  await client.connect();
  db = client.db('practice');
  bucket = new GridFSBucket(db, { bucketName: 'fs' });
  console.log('Connected to MongoDB with GridFS');
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

// Submissions collection data access (separate from appData)
async function getSubmissions(filter = {}) {
  return await db.collection('submissions').find(filter).sort({ submittedAt: -1 }).toArray();
}

async function getSubmissionById(id) {
  return await db.collection('submissions').findOne({ id });
}

async function saveSubmission(submission) {
  await db.collection('submissions').insertOne(submission);
}

async function updateSubmission(id, updates) {
  await db.collection('submissions').updateOne({ id }, { $set: updates });
}

async function deleteSubmission(id) {
  const submission = await getSubmissionById(id);
  if (submission && submission.videoFileId) {
    try {
      await bucket.delete(new ObjectId(submission.videoFileId));
    } catch (err) {
      console.error('Error deleting video from GridFS:', err);
    }
  }
  await db.collection('submissions').deleteOne({ id });
}

async function deleteAllSubmissions() {
  // Delete all videos from GridFS
  const submissions = await getSubmissions();
  for (const sub of submissions) {
    if (sub.videoFileId) {
      try {
        await bucket.delete(new ObjectId(sub.videoFileId));
      } catch (err) {
        console.error('Error deleting video:', err);
      }
    }
  }
  await db.collection('submissions').deleteMany({});
}

async function getStorageStats() {
  const files = await db.collection('fs.files').find({}).toArray();
  const usedBytes = files.reduce((sum, f) => sum + (f.length || 0), 0);
  const totalBytes = 512 * 1024 * 1024; // 512 MB Atlas free tier limit
  return {
    usedBytes,
    totalBytes,
    usedMB: Math.round(usedBytes / (1024 * 1024) * 10) / 10,
    totalMB: 512,
    percentage: Math.round((usedBytes / totalBytes) * 100),
    fileCount: files.length,
  };
}

// Migration: move submissions from appData to separate collection
async function migrateSubmissions() {
  const appData = await db.collection('appData').findOne({ _id: 'main' });
  if (!appData || !appData.submissions || appData.submissions.length === 0) {
    return;
  }

  // Check if we already have submissions in the new collection
  const existingCount = await db.collection('submissions').countDocuments();
  if (existingCount > 0) {
    console.log('Submissions already migrated, skipping');
    return;
  }

  console.log(`Migrating ${appData.submissions.length} submissions to new collection...`);
  for (const sub of appData.submissions) {
    await db.collection('submissions').insertOne({
      ...sub,
      _id: new ObjectId(),
    });
  }

  // Remove submissions from appData (keep other fields)
  await db.collection('appData').updateOne(
    { _id: 'main' },
    { $unset: { submissions: '' } }
  );

  console.log('Migration complete');
}

// Discord notifications
async function sendDiscord(message, mentionVictor = false) {
  if (!CONFIG.DISCORD_WEBHOOK_URL) {
    console.log(`[DISCORD NOT CONFIGURED] ${message}`);
    return false;
  }
  try {
    const content = mentionVictor
      ? `<@${CONFIG.VICTOR_DISCORD_ID}> ${message}`
      : message;

    await fetch(CONFIG.DISCORD_WEBHOOK_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content }),
    });
    console.log(`[DISCORD] Sent: ${message.substring(0, 50)}...`);
    return true;
  } catch (err) {
    console.error('Discord error:', err);
    return false;
  }
}

// Session setup with MongoDB store (persists across server restarts)
app.use(session({
  secret: CONFIG.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.MONGODB_URI,
    ttl: 7 * 24 * 60 * 60, // 1 week in seconds
  }),
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

// Trust proxy for Render (needed for secure cookies)
app.set('trust proxy', 1);

app.use(express.static('public'));
app.use(express.json());

// Health check endpoint for uptime monitoring (e.g., UptimeRobot)
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

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

function getPreviousWeek() {
  const now = new Date();
  const lastWeek = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
  const year = lastWeek.getFullYear();
  const startOfYear = new Date(year, 0, 1);
  const weekNum = Math.ceil(((lastWeek - startOfYear) / 86400000 + startOfYear.getDay() + 1) / 7);
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
  const currentWeek = getCurrentWeek();
  const submission = await db.collection('submissions').findOne({ week: currentWeek, status: 'approved' });
  return !!submission;
}

async function hasPendingSubmissionThisWeek() {
  const currentWeek = getCurrentWeek();
  const submission = await db.collection('submissions').findOne({ week: currentWeek, status: 'pending' });
  return !!submission;
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

  // Get submissions from new collection
  const allSubmissions = await getSubmissions();
  const thisWeekSubmission = allSubmissions.find(s => s.week === currentWeek);

  // Filter submissions based on role
  const visibleSubmissions = req.session.user.role === 'admin'
    ? allSubmissions.slice(0, 10)
    : allSubmissions.filter(s => s.week === currentWeek);

  res.json({
    weeklyCode: getWeeklyCode(),
    currentWeek,
    deadline: deadline.toISOString(),
    daysUntilWedding: Math.max(0, daysUntilWedding),
    weeksUntilWedding: Math.max(0, weeksUntilWedding),
    streak: data.streak || 0,
    thisWeekStatus: thisWeekSubmission ? thisWeekSubmission.status : 'not_submitted',
    submissions: visibleSubmissions,
    weddingDate: CONFIG.WEDDING_DATE.toISOString(),
    isSaturday: now.getDay() === 6,
    role: req.session.user.role,
  });
});

// Check if ffmpeg is available
function ffmpegAvailable() {
  try {
    execSync('which ffmpeg', { stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
}

// Compress video using ffmpeg
function compressVideo(inputPath, outputPath) {
  if (!ffmpegAvailable()) {
    console.log('ffmpeg not available, skipping compression');
    return false;
  }
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
  console.log('[SUBMIT] Starting submission process');

  if (req.session.user.role !== 'friend') {
    console.log('[SUBMIT] Rejected: not friend role');
    return res.status(403).json({ error: 'Only friend can submit' });
  }

  if (!req.file) {
    console.log('[SUBMIT] Rejected: no video file');
    return res.status(400).json({ error: 'No video uploaded' });
  }

  console.log(`[SUBMIT] Video received: ${req.file.filename}, size: ${(req.file.size / 1024 / 1024).toFixed(1)}MB`);

  const currentWeek = getCurrentWeek();
  const weeklyCode = getWeeklyCode();
  console.log(`[SUBMIT] Week: ${currentWeek}, Code: ${weeklyCode}`);

  // Check if already has pending or approved submission (using new collection)
  const existing = await db.collection('submissions').findOne({
    week: currentWeek,
    status: { $in: ['approved', 'pending'] }
  });
  if (existing) {
    console.log(`[SUBMIT] Rejected: already ${existing.status} for this week`);
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
    console.log(`[SUBMIT] Generated submission ID: ${submissionId}`);

    // Compress video
    const compressedPath = req.file.path.replace(/\.[^.]+$/, '_compressed.mp4');
    console.log('[SUBMIT] Starting video compression...');
    const compressionSuccess = compressVideo(req.file.path, compressedPath);
    console.log(`[SUBMIT] Compression ${compressionSuccess ? 'succeeded' : 'failed/skipped'}`);

    // Determine which video file to store (compressed if available)
    const videoToStore = compressionSuccess && fs.existsSync(compressedPath) ? compressedPath : req.file.path;
    const videoSize = fs.statSync(videoToStore).size;
    console.log(`[SUBMIT] Storing video: ${(videoSize / 1024 / 1024).toFixed(1)}MB`);

    // Store video in GridFS
    const videoFileId = new ObjectId();
    const uploadStream = bucket.openUploadStreamWithId(videoFileId, `practice-${currentWeek}.mp4`, {
      contentType: 'video/mp4',
      metadata: { submissionId, week: currentWeek }
    });

    const videoBuffer = fs.readFileSync(videoToStore);
    uploadStream.end(videoBuffer);

    await new Promise((resolve, reject) => {
      uploadStream.on('finish', resolve);
      uploadStream.on('error', reject);
    });
    console.log(`[SUBMIT] Video stored in GridFS: ${videoFileId}`);

    // Remove old rejected submission for this week if exists
    await db.collection('submissions').deleteMany({ week: currentWeek, status: 'rejected' });

    // Save submission to new collection
    const submission = {
      _id: new ObjectId(),
      id: submissionId,
      week: currentWeek,
      submittedAt: new Date(),
      status: 'pending',
      videoFileId: videoFileId.toString(),
      videoSize,
    };
    await saveSubmission(submission);

    // Build approval links
    const baseUrl = process.env.APP_URL || `http://localhost:${PORT}`;
    const approveLink = `${baseUrl}/api/review?id=${submissionId}&action=approve&token=${approveToken}`;
    const rejectLink = `${baseUrl}/api/review?id=${submissionId}&action=reject&token=${rejectToken}`;

    const emailHtml = `
      <h2>🎻 Practice Video Submitted - ${currentWeek}</h2>
      <p><strong>Week:</strong> ${currentWeek}<br>
      <strong>Expected code:</strong> ${weeklyCode}</p>

      <p>Video available in admin dashboard. Please verify:</p>
      <ul>
        <li>The code "${weeklyCode}" is visible on paper in the video</li>
        <li>It's a real video of Victor practicing</li>
      </ul>

      <div style="margin:2rem 0;">
        <a href="${approveLink}" style="background:#22c55e;color:white;padding:12px 24px;text-decoration:none;border-radius:6px;margin-right:12px;display:inline-block;">✅ APPROVE</a>
        <a href="${rejectLink}" style="background:#ef4444;color:white;padding:12px 24px;text-decoration:none;border-radius:6px;display:inline-block;">❌ REJECT</a>
      </div>

      <p style="color:#666;font-size:0.875rem;">Or view the video and approve/reject in the <a href="${baseUrl}">admin dashboard</a>.</p>
    `;

    // Send response immediately so user doesn't wait
    res.json({
      success: true,
      message: 'Submitted for review',
    });

    // Send Discord notification (async, after response)
    console.log('[SUBMIT] Sending Discord notification...');
    await sendDiscord(`🎻 **New Practice Video Submitted** - ${currentWeek}\nReview it here: ${baseUrl}`);

    // Clean up local video files
    try {
      fs.unlinkSync(req.file.path);
      if (compressionSuccess && fs.existsSync(compressedPath)) {
        fs.unlinkSync(compressedPath);
      }
    } catch (cleanupErr) {
      console.error('Cleanup error:', cleanupErr);
    }

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

  // Get submission from new collection
  const submission = await getSubmissionById(id);

  if (!submission) {
    return res.status(404).send(htmlResponse('Not Found', 'Submission not found.', 'error'));
  }

  if (submission.status !== 'pending') {
    return res.send(htmlResponse('Already Reviewed', `This submission was already ${submission.status}.`, 'info'));
  }

  // Update submission status
  await updateSubmission(id, {
    status: action === 'approve' ? 'approved' : 'rejected',
    reviewedAt: new Date(),
  });

  // Update streak in appData
  const data = await getData();
  if (action === 'approve') {
    data.streak = (data.streak || 0) + 1;
  }
  await saveData(data);

  // Notify Victor of result
  const resultEmoji = action === 'approve' ? '✅' : '❌';
  const resultText = action === 'approve'
    ? `Great job! Your practice video for ${submission.week} has been approved. Your streak is now ${data.streak} weeks!`
    : `Your practice video for ${submission.week} was rejected. Please submit a new video.`;

  await sendDiscord(`${resultEmoji} ${resultText}`, true);

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

  const hasApproved = await hasApprovedSubmissionThisWeek();
  const hasPending = await hasPendingSubmissionThisWeek();
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

  // Notify Victor about consequence
  await sendDiscord(`🚨 **DEADLINE MISSED** - ${currentWeek}\n\nYou missed the practice deadline. You owe $${CONFIG.CONSEQUENCE_AMOUNT}.\n\n💰 Pay here: ${paypalLink}\n\nYour streak has been reset to 0. Don't let this happen again!`, true);

  res.json({
    success: true,
    paypalLink,
    message: 'Consequence triggered. Friend has been notified.',
  });
});

// Video streaming endpoint (admin only)
app.get('/api/videos/:id', requireAdmin, async (req, res) => {
  const submissionId = req.params.id;
  const submission = await getSubmissionById(submissionId);

  if (!submission || !submission.videoFileId) {
    return res.status(404).json({ error: 'Video not found' });
  }

  try {
    const fileId = new ObjectId(submission.videoFileId);
    const files = await db.collection('fs.files').find({ _id: fileId }).toArray();

    if (files.length === 0) {
      return res.status(404).json({ error: 'Video file not found' });
    }

    const file = files[0];
    const fileSize = file.length;

    // Handle range requests for video seeking
    const range = req.headers.range;
    if (range) {
      const parts = range.replace(/bytes=/, '').split('-');
      const start = parseInt(parts[0], 10);
      const end = parts[1] ? parseInt(parts[1], 10) : fileSize - 1;
      const chunkSize = end - start + 1;

      res.writeHead(206, {
        'Content-Range': `bytes ${start}-${end}/${fileSize}`,
        'Accept-Ranges': 'bytes',
        'Content-Length': chunkSize,
        'Content-Type': 'video/mp4',
      });

      const downloadStream = bucket.openDownloadStream(fileId, { start, end: end + 1 });
      downloadStream.pipe(res);
    } else {
      res.writeHead(200, {
        'Content-Length': fileSize,
        'Content-Type': 'video/mp4',
      });

      const downloadStream = bucket.openDownloadStream(fileId);
      downloadStream.pipe(res);
    }
  } catch (err) {
    console.error('Video streaming error:', err);
    res.status(500).json({ error: 'Failed to stream video' });
  }
});

// Storage stats endpoint
app.get('/api/admin/storage', requireAdmin, async (req, res) => {
  try {
    const stats = await getStorageStats();
    res.json(stats);
  } catch (err) {
    console.error('Storage stats error:', err);
    res.status(500).json({ error: 'Failed to get storage stats' });
  }
});

// List all submissions (admin only)
app.get('/api/admin/submissions', requireAdmin, async (req, res) => {
  try {
    const submissions = await getSubmissions();
    res.json(submissions);
  } catch (err) {
    console.error('Submissions listing error:', err);
    res.status(500).json({ error: 'Failed to list submissions' });
  }
});

// In-app approve submission
app.post('/api/admin/submissions/:id/approve', requireAdmin, async (req, res) => {
  const submissionId = req.params.id;
  const submission = await getSubmissionById(submissionId);

  if (!submission) {
    return res.status(404).json({ error: 'Submission not found' });
  }

  if (submission.status !== 'pending') {
    return res.status(400).json({ error: `Submission already ${submission.status}` });
  }

  await updateSubmission(submissionId, {
    status: 'approved',
    reviewedAt: new Date(),
  });

  // Update streak
  const data = await getData();
  data.streak = (data.streak || 0) + 1;
  await saveData(data);

  // Notify Victor
  await sendDiscord(`✅ Great job! Your practice video for ${submission.week} has been approved. Your streak is now ${data.streak} weeks!`, true);

  res.json({ success: true, streak: data.streak });
});

// In-app reject submission
app.post('/api/admin/submissions/:id/reject', requireAdmin, async (req, res) => {
  const submissionId = req.params.id;
  const submission = await getSubmissionById(submissionId);

  if (!submission) {
    return res.status(404).json({ error: 'Submission not found' });
  }

  if (submission.status !== 'pending') {
    return res.status(400).json({ error: `Submission already ${submission.status}` });
  }

  await updateSubmission(submissionId, {
    status: 'rejected',
    reviewedAt: new Date(),
  });

  // Notify Victor
  await sendDiscord(`❌ Your practice video for ${submission.week} was rejected. Please submit a new video.`, true);

  res.json({ success: true });
});

// Delete single submission
app.delete('/api/admin/submissions/:id', requireAdmin, async (req, res) => {
  const submissionId = req.params.id;
  const submission = await getSubmissionById(submissionId);

  if (!submission) {
    return res.status(404).json({ error: 'Submission not found' });
  }

  await deleteSubmission(submissionId);
  res.json({ success: true });
});

// Clear all submissions
app.delete('/api/admin/submissions', requireAdmin, async (req, res) => {
  if (req.query.confirm !== 'true') {
    return res.status(400).json({ error: 'Must confirm with ?confirm=true' });
  }

  await deleteAllSubmissions();

  // Reset streak
  const data = await getData();
  data.streak = 0;
  await saveData(data);

  res.json({ success: true, message: 'All submissions cleared' });
});

// Scheduled task: Saturday reminder (10 AM)
async function saturdayReminder() {
  console.log('[CRON] Running Saturday reminder check...');

  if (await hasApprovedSubmissionThisWeek() || await hasPendingSubmissionThisWeek()) {
    console.log('[CRON] Already submitted this week, skipping reminder');
    return;
  }

  const deadline = getDeadline();
  const weeklyCode = getWeeklyCode();
  const appUrl = process.env.APP_URL || `http://localhost:${PORT}`;

  await sendDiscord(`⏰ **Saturday Reminder**\n\nYou haven't submitted your practice video yet this week!\n\n📅 **Deadline:** ${deadline.toLocaleDateString('en-US', { weekday: 'long', month: 'long', day: 'numeric' })} at midnight\n🔑 **This week's code:** \`${weeklyCode}\`\n\nWrite the code on paper and show it in your video.\n\n👉 Submit here: ${appUrl}`, true);

  console.log('[CRON] Saturday reminder sent');
}

// Scheduled task: Monday deadline check & automatic consequence (8 AM)
async function mondayDeadlineCheck() {
  console.log('[CRON] Running Monday deadline check...');

  const previousWeek = getPreviousWeek();
  const data = await getData();

  // Check if already triggered for previous week
  if (!data.consequencesTriggered) data.consequencesTriggered = [];
  if (data.consequencesTriggered.includes(previousWeek)) {
    console.log(`[CRON] Consequence already triggered for ${previousWeek}`);
    return;
  }

  // Check if previous week had an approved submission
  const approvedSubmission = await db.collection('submissions').findOne({
    week: previousWeek,
    status: 'approved'
  });

  if (approvedSubmission) {
    console.log(`[CRON] ${previousWeek} had approved submission, no consequence needed`);
    return;
  }

  // Trigger consequence!
  console.log(`[CRON] Triggering consequence for ${previousWeek}`);

  data.streak = 0;
  data.consequencesTriggered.push(previousWeek);
  await saveData(data);

  const paypalLink = `https://paypal.me/${CONFIG.PAYPAL_ME_USERNAME}/${CONFIG.CONSEQUENCE_AMOUNT}`;

  await sendDiscord(`🚨 **DEADLINE MISSED** - ${previousWeek}\n\nYou missed the practice deadline. You owe $${CONFIG.CONSEQUENCE_AMOUNT}.\n\n💰 Pay here: ${paypalLink}\n\nYour streak has been reset to 0. Don't let this happen again!`, true);

  console.log('[CRON] Consequence triggered and Victor notified');
}

// Initialize and start server
connectDB().then(async () => {
  await migrateSubmissions();
  await initializeUsers();

  // Schedule automatic tasks
  // Saturday at 10:00 AM - reminder
  cron.schedule('0 10 * * 6', saturdayReminder, {
    timezone: 'America/New_York'
  });
  console.log('[CRON] Saturday reminder scheduled for 10:00 AM');

  // Monday at 8:00 AM - deadline check & consequence
  cron.schedule('0 8 * * 1', mondayDeadlineCheck, {
    timezone: 'America/New_York'
  });
  console.log('[CRON] Monday deadline check scheduled for 8:00 AM');

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
