require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const axios = require('axios');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const tls = require('tls');
const net = require('net');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'linksentinel_super_jwt_secret_phrase';

// Middleware
app.use(cors());
app.use(express.json());

// Neon DB connection pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && !process.env.DATABASE_URL.includes('localhost')
    ? { rejectUnauthorized: false }
    : false
});

// Test connection
pool.query('SELECT NOW()', (err, res) => {
  if (err) {
    console.error('Error connecting to Neon Database:', err);
  } else {
    console.log('Successfully connected to Neon Database at:', res.rows[0].now);
  }
});

// ==========================================
// HELPERS
// ==========================================

// Helper to check SSL certificate expiry for HTTPS links
const getSslCertificateExpiry = (urlStr) => {
  return new Promise((resolve) => {
    try {
      const url = new URL(urlStr);
      if (url.protocol !== 'https:') {
        return resolve(null);
      }
      
      const socket = tls.connect({
        host: url.hostname,
        port: 443,
        servername: url.hostname,
        rejectUnauthorized: false // read cert details even if expired or self-signed
      }, () => {
        const cert = socket.getPeerCertificate();
        socket.destroy();
        if (cert && cert.valid_to) {
          resolve(new Date(cert.valid_to));
        } else {
          resolve(null);
        }
      });
      
      socket.on('error', () => {
        socket.destroy();
        resolve(null);
      });
      
      socket.setTimeout(5000, () => {
        socket.destroy();
        resolve(null);
      });
    } catch (e) {
      resolve(null);
    }
  });
};

// Helper to check TCP Port connection
const checkPortConnection = (host, port) => {
  return new Promise((resolve) => {
    const startTime = Date.now();
    const socket = new net.Socket();
    socket.setTimeout(5000);
    
    socket.connect(port, host, () => {
      const latency = Date.now() - startTime;
      socket.destroy();
      resolve({ up: true, latency });
    });
    
    socket.on('error', (err) => {
      socket.destroy();
      resolve({ up: false, error: err.message });
    });
    
    socket.on('timeout', () => {
      socket.destroy();
      resolve({ up: false, error: 'Connection Timeout' });
    });
  });
};

// Helper to check keyword presence on a page
const checkKeywordPresence = async (url, keyword) => {
  const response = await axios.get(url, {
    timeout: 5000,
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    }
  });
  const html = response.data;
  if (typeof html === 'string' && html.includes(keyword)) {
    return { up: true, statusCode: response.status };
  } else {
    return { up: false, statusCode: response.status, error: `Keyword "${keyword}" not found` };
  }
};

// Send user alert notifications dynamically based on link config
const sendTelegramAlert = async (botToken, chatId, linkName, linkUrl, statusCode, errorMessage) => {
  if (!botToken || !chatId) return;
  const message = `🚨 *LinkSentinel Alert* 🚨\n\n` +
                  `Link Name: *${linkName}*\n` +
                  `URL: ${linkUrl}\n` +
                  `Status Code: *${statusCode || 'N/A'}*\n` +
                  `Error: ${errorMessage || 'Outage Detected'}\n` +
                  `Time: ${new Date().toISOString()}`;
  try {
    await axios.post(`https://api.telegram.org/bot${botToken}/sendMessage`, {
      chat_id: chatId,
      text: message,
      parse_mode: 'Markdown'
    });
    console.log(`Telegram alert sent to chat ${chatId} for ${linkName}`);
  } catch (error) {
    console.error('Failed to send Telegram alert:', error.message);
  }
};

const sendSlackAlert = async (webhookUrl, linkName, linkUrl, statusCode, errorMessage) => {
  if (!webhookUrl) return;
  const message = `🚨 *LinkSentinel Alert* 🚨\n\n` +
                  `• *Link Name:* ${linkName}\n` +
                  `• *URL:* ${linkUrl}\n` +
                  `• *Status Code:* ${statusCode || 'N/A'}\n` +
                  `• *Error:* ${errorMessage || 'Outage Detected'}\n` +
                  `• *Time:* ${new Date().toISOString()}`;
  try {
    await axios.post(webhookUrl, { text: message });
    console.log(`Slack alert sent via webhook for ${linkName}`);
  } catch (error) {
    console.error('Failed to send Slack alert:', error.message);
  }
};

const sendEmailAlert = async (emailAddress, linkName, linkUrl, statusCode, errorMessage) => {
  if (!emailAddress) return;
  const host = process.env.SMTP_HOST;
  const port = process.env.SMTP_PORT || 587;
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;
  const from = process.env.SMTP_FROM || 'alerts@linksentinel.com';

  console.log(`[EMAIL ALERT SIMULATION] To: ${emailAddress} | Link: ${linkName} is DOWN: ${errorMessage}`);
  if (!host || !user || !pass) {
    console.log('SMTP not configured. Skipped real email delivery.');
    return;
  }

  try {
    const transporter = nodemailer.createTransport({
      host,
      port,
      secure: port == 465,
      auth: { user, pass }
    });

    const mailOptions = {
      from,
      to: emailAddress,
      subject: `🚨 Outage Alert: ${linkName} is DOWN`,
      text: `🚨 LinkSentinel Alert 🚨\n\nYour monitored service "${linkName}" is DOWN.\nURL: ${linkUrl}\nStatus Code: ${statusCode || 'N/A'}\nError Details: ${errorMessage || 'N/A'}\nTime: ${new Date().toISOString()}`
    };

    await transporter.sendMail(mailOptions);
    console.log(`Real email alert sent to ${emailAddress}`);
  } catch (err) {
    console.error('Failed to send email alert:', err.message);
  }
};

// ==========================================
// MIDDLEWARES
// ==========================================

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Token is invalid or expired' });
    }
    req.user = user;
    next();
  });
};

// ==========================================
// AUTHENTICATION ROUTES
// ==========================================

app.post('/api/auth/signup', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  try {
    const userCheck = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userCheck.rows.length > 0) {
      return res.status(400).json({ error: 'Email is already registered' });
    }

    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);

    const result = await pool.query(
      'INSERT INTO users (email, password_hash, subscription_tier, subscription_status) VALUES ($1, $2, $3, $4) RETURNING id, email, subscription_tier',
      [email, passwordHash, 'FREE', 'ACTIVE']
    );

    const user = result.rows[0];
    const token = jwt.sign({ userId: user.id, email: user.email, tier: user.subscription_tier }, JWT_SECRET, { expiresIn: '7d' });
    res.status(201).json({ message: 'User registered successfully', token, user });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid email or password' });
    }

    const user = result.rows[0];
    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      return res.status(400).json({ error: 'Invalid email or password' });
    }

    const token = jwt.sign({ userId: user.id, email: user.email, tier: user.subscription_tier }, JWT_SECRET, { expiresIn: '7d' });
    res.json({
      message: 'Login successful',
      token,
      user: { id: user.id, email: user.email, subscription_tier: user.subscription_tier, subscription_status: user.subscription_status }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, email, subscription_tier, subscription_status FROM users WHERE id = $1', [req.user.userId]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Auth details fetch error:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// ==========================================
// MONITOR BILLING & SUBSCRIPTIONS
// ==========================================

app.post('/api/billing/subscribe', authenticateToken, async (req, res) => {
  const { tier } = req.body; // PRO or ENTERPRISE
  if (!['FREE', 'PRO', 'ENTERPRISE'].includes(tier)) {
    return res.status(400).json({ error: 'Invalid subscription tier' });
  }

  try {
    // Dynamically upgrade/downgrade subscription in the database (Mock Checkout Success)
    await pool.query(
      'UPDATE users SET subscription_tier = $1, subscription_status = $2 WHERE id = $3',
      [tier, 'ACTIVE', req.user.userId]
    );

    res.json({ message: `Successfully updated subscription to ${tier}`, tier });
  } catch (error) {
    console.error('Billing update error:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// ==========================================
// MONITOR LINKS MANAGEMENT (PROTECTED)
// ==========================================

app.get('/api/links', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM links WHERE user_id = $1 ORDER BY created_at DESC', [req.user.userId]);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching user links:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.post('/api/links', authenticateToken, async (req, res) => {
  const {
    name,
    url,
    check_type = 'HTTP',
    check_interval = 10,
    keyword = null,
    port = null,
    slack_webhook_url = null,
    telegram_bot_token = null,
    telegram_chat_id = null,
    email_alert = null
  } = req.body;

  if (!name || !url) {
    return res.status(400).json({ error: 'Name and URL are required' });
  }

  // Basic validation of URL structure (unless it's just a hostname for port monitoring)
  if (check_type !== 'PORT') {
    try {
      new URL(url);
    } catch (err) {
      return res.status(400).json({ error: 'Invalid URL format. Must include protocol (e.g. https://)' });
    }
  }

  try {
    // 1. Fetch user subscription parameters
    const userRes = await pool.query('SELECT subscription_tier FROM users WHERE id = $1', [req.user.userId]);
    const tier = userRes.rows[0]?.subscription_tier || 'FREE';

    // 2. Enforce link limit constraints
    const countRes = await pool.query('SELECT COUNT(*) FROM links WHERE user_id = $1', [req.user.userId]);
    const monitorCount = parseInt(countRes.rows[0].count);

    let maxMonitors = 3; // Free Tier Limit
    if (tier === 'PRO') maxMonitors = 20;
    if (tier === 'ENTERPRISE') maxMonitors = 9999;

    if (monitorCount >= maxMonitors) {
      return res.status(400).json({
        error: `Tier Monitor limit reached (${maxMonitors}). Upgrade your plan in the Billing tab to create more monitors.`
      });
    }

    // 3. Enforce check interval limits
    let minInterval = 10;
    if (tier === 'PRO' || tier === 'ENTERPRISE') minInterval = 1;

    if (parseInt(check_interval) < minInterval) {
      return res.status(400).json({
        error: `Your current tier (${tier}) only supports a minimum check interval of ${minInterval} minutes.`
      });
    }

    // 4. Insert new link
    const result = await pool.query(
      `INSERT INTO links (
        name, url, user_id, status, check_type, check_interval, keyword, port, 
        slack_webhook_url, telegram_bot_token, telegram_chat_id, email_alert
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING *`,
      [
        name, url, req.user.userId, 'PENDING', check_type, parseInt(check_interval), 
        keyword, port ? parseInt(port) : null, slack_webhook_url, telegram_bot_token, 
        telegram_chat_id, email_alert
      ]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error adding link:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Update/Edit Monitor Route
app.patch('/api/links/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const updates = req.body;

  // Build dynamic SQL update string
  const allowedUpdates = [
    'name', 'url', 'check_type', 'check_interval', 'keyword', 'port',
    'slack_webhook_url', 'telegram_bot_token', 'telegram_chat_id', 'email_alert', 'is_active'
  ];

  const updateFields = [];
  const queryValues = [id, req.user.userId];
  let valIdx = 3;

  for (let key of allowedUpdates) {
    if (updates[key] !== undefined) {
      // Validate active status / intervals
      if (key === 'check_interval') {
        const userRes = await pool.query('SELECT subscription_tier FROM users WHERE id = $1', [req.user.userId]);
        const tier = userRes.rows[0]?.subscription_tier || 'FREE';
        let minInterval = (tier === 'PRO' || tier === 'ENTERPRISE') ? 1 : 10;
        if (parseInt(updates[key]) < minInterval) {
          return res.status(400).json({ error: `Minimum interval for ${tier} tier is ${minInterval} minutes.` });
        }
      }
      
      updateFields.push(`${key} = $${valIdx}`);
      queryValues.push(updates[key]);
      valIdx++;
    }
  }

  if (updateFields.length === 0) {
    return res.status(400).json({ error: 'No valid update parameters provided' });
  }

  try {
    const queryText = `UPDATE links SET ${updateFields.join(', ')} WHERE id = $1 AND user_id = $2 RETURNING *`;
    const result = await pool.query(queryText, queryValues);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Monitor not found or unauthorized' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error modifying link:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.delete('/api/links/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query('DELETE FROM links WHERE id = $1 AND user_id = $2 RETURNING *', [id, req.user.userId]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Link monitor not found or unauthorized' });
    }
    res.json({ message: 'Monitor deleted successfully', link: result.rows[0] });
  } catch (error) {
    console.error('Error deleting link:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// ==========================================
// INCIDENT LOGS (PROTECTED)
// ==========================================

app.get('/api/logs', authenticateToken, async (req, res) => {
  try {
    const queryText = `
      SELECT il.*, l.name as link_name, l.url as link_url 
      FROM incident_logs il 
      JOIN links l ON il.link_id = l.id 
      WHERE l.user_id = $1
      ORDER BY il.detected_at DESC 
      LIMIT 100
    `;
    const result = await pool.query(queryText, [req.user.userId]);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching logs:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// ==========================================
// PUBLIC STATUS PAGE (UNAUTHENTICATED)
// ==========================================

app.get('/api/status/:userId', async (req, res) => {
  const { userId } = req.params;
  try {
    const userRes = await pool.query('SELECT email, subscription_tier FROM users WHERE id = $1', [userId]);
    if (userRes.rows.length === 0) {
      return res.status(404).json({ error: 'Status page not found' });
    }

    const linksRes = await pool.query(
      'SELECT id, name, url, status, last_checked, response_time, history FROM links WHERE user_id = $1 AND is_active = TRUE ORDER BY name ASC',
      [userId]
    );

    res.json({
      user: { email: userRes.rows[0].email, tier: userRes.rows[0].subscription_tier },
      monitors: linksRes.rows
    });
  } catch (error) {
    console.error('Error fetching public status page data:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// ==========================================
// CRON MONITOR CHECK ENGINE
// ==========================================

app.get('/api/cron/check', async (req, res) => {
  const secret = req.query.secret;
  const cronSecret = process.env.CRON_SECRET;

  if (cronSecret && secret !== cronSecret) {
    return res.status(401).json({ error: 'Unauthorized: Invalid cron secret' });
  }

  try {
    // Fetch only active links
    const linksResult = await pool.query('SELECT * FROM links WHERE is_active = TRUE');
    const links = linksResult.rows;

    const summary = {
      total: links.length,
      checked: 0,
      skipped: 0,
      failed: 0,
      details: []
    };

    for (const link of links) {
      // Respect check intervals
      const now = Date.now();
      const minutesSinceLastCheck = link.last_checked
        ? (now - new Date(link.last_checked).getTime()) / 60000
        : Infinity;

      // Allow a 30s buffer for timers pings
      if (minutesSinceLastCheck < link.check_interval - 0.5) {
        summary.skipped++;
        continue;
      }

      summary.checked++;
      let status = 'UP';
      let statusCode = null;
      let errorMessage = null;
      let responseTime = 0;
      let sslExpiryDate = link.ssl_expires_at;

      const startTime = Date.now();

      // Execute checks depending on Monitor check_type
      if (link.check_type === 'PORT') {
        const urlObj = link.url.includes('://') ? new URL(link.url) : null;
        const host = urlObj ? urlObj.hostname : link.url.split(':')[0];
        const port = link.port || (urlObj ? parseInt(urlObj.port) : 80);

        const checkRes = await checkPortConnection(host, port);
        responseTime = checkRes.latency || (Date.now() - startTime);
        
        if (checkRes.up) {
          status = 'UP';
          statusCode = 200;
        } else {
          status = 'DOWN';
          errorMessage = checkRes.error || 'Port connection failed';
        }
      } 
      else if (link.check_type === 'KEYWORD') {
        try {
          const checkRes = await checkKeywordPresence(link.url, link.keyword);
          responseTime = Date.now() - startTime;
          
          if (checkRes.up) {
            status = 'UP';
            statusCode = checkRes.statusCode;
          } else {
            status = 'DOWN';
            statusCode = checkRes.statusCode;
            errorMessage = checkRes.error;
          }
        } catch (error) {
          responseTime = Date.now() - startTime;
          status = 'DOWN';
          statusCode = error.response ? error.response.status : null;
          errorMessage = error.response ? `HTTP Error Code: ${error.response.status}` : error.message;
        }
      } 
      else if (link.check_type === 'SSL_ONLY') {
        try {
          const expiry = await getSslCertificateExpiry(link.url);
          responseTime = Date.now() - startTime;

          if (expiry) {
            sslExpiryDate = expiry;
            if (new Date() > expiry) {
              status = 'DOWN';
              errorMessage = 'SSL Certificate is expired!';
            } else {
              status = 'UP';
              statusCode = 200;
            }
          } else {
            status = 'DOWN';
            errorMessage = 'Could not read SSL Certificate expiry';
          }
        } catch (error) {
          responseTime = Date.now() - startTime;
          status = 'DOWN';
          errorMessage = error.message;
        }
      } 
      else {
        // Default: HTTP Check
        try {
          const response = await axios.get(link.url, {
            timeout: 5000,
            headers: {
              'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            },
            validateStatus: (status) => status < 400
          });
          responseTime = Date.now() - startTime;
          status = 'UP';
          statusCode = response.status;
        } catch (error) {
          responseTime = Date.now() - startTime;
          status = 'DOWN';
          if (error.response) {
            statusCode = error.response.status;
            errorMessage = `HTTP Error Code: ${error.response.status}`;
          } else if (error.request) {
            errorMessage = 'Connection timeout / network error';
          } else {
            errorMessage = error.message;
          }
        }
      }

      // Automatically fetch SSL expiry for all HTTP/KEYWORD check types on HTTPS links
      if (link.url.startsWith('https://') && link.check_type !== 'SSL_ONLY') {
        const fetchedExpiry = await getSslCertificateExpiry(link.url);
        if (fetchedExpiry) {
          sslExpiryDate = fetchedExpiry;
        }
      }

      // Update history logs (max 30 items)
      let history = [];
      try {
        history = Array.isArray(link.history) ? link.history : JSON.parse(link.history || '[]');
      } catch (e) {
        history = [];
      }
      history.push({
        status,
        latency: responseTime,
        time: new Date().toISOString()
      });
      if (history.length > 30) {
        history = history.slice(-30);
      }

      // Update Database
      await pool.query(
        'UPDATE links SET status = $1, last_checked = CURRENT_TIMESTAMP, response_time = $2, history = $3, ssl_expires_at = $4 WHERE id = $5',
        [status, responseTime, JSON.stringify(history), sslExpiryDate, link.id]
      );

      // Trigger Downtime Incident and alert routing if newly DOWN
      if (status === 'DOWN') {
        summary.failed++;

        // Add incident logs
        await pool.query(
          'INSERT INTO incident_logs (link_id, status_code, error_message, response_time) VALUES ($1, $2, $3, $4)',
          [link.id, statusCode, errorMessage, responseTime]
        );

        // Notify customized endpoints
        await sendTelegramAlert(link.telegram_bot_token, link.telegram_chat_id, link.name, link.url, statusCode, errorMessage);
        await sendSlackAlert(link.slack_webhook_url, link.name, link.url, statusCode, errorMessage);
        await sendEmailAlert(link.email_alert, link.name, link.url, statusCode, errorMessage);
      }

      summary.details.push({
        id: link.id,
        name: link.name,
        status,
        latency: responseTime,
        error: errorMessage
      });
    }

    res.json({
      message: 'Cron check completed successfully',
      summary
    });
  } catch (error) {
    console.error('Error during cron check:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Root Route
app.get('/', (req, res) => {
  res.json({ status: 'healthy', service: 'linksentinel-backend-api' });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

module.exports = app;
