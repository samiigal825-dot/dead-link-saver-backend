require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const axios = require('axios');

const app = express();
const PORT = process.env.PORT || 5000;

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

// REST API Endpoints

// 1. GET /api/links - Get all monitored links
app.get('/api/links', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM links ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching links:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// 2. POST /api/links - Add a new monitored link
app.post('/api/links', async (req, res) => {
  const { name, url } = req.body;
  if (!name || !url) {
    return res.status(400).json({ error: 'Name and URL are required' });
  }

  try {
    // Validate URL format basic check
    new URL(url);
  } catch (err) {
    return res.status(400).json({ error: 'Invalid URL format' });
  }

  try {
    // Find the first user in the DB to link this to (or default to NULL)
    const userResult = await pool.query('SELECT id FROM users LIMIT 1');
    const userId = userResult.rows.length > 0 ? userResult.rows[0].id : null;

    const result = await pool.query(
      'INSERT INTO links (name, url, user_id, status) VALUES ($1, $2, $3, $4) RETURNING *',
      [name, url, userId, 'PENDING']
    );
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error adding link:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// 3. DELETE /api/links/:id - Delete a monitored link
app.delete('/api/links/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query('DELETE FROM links WHERE id = $1 RETURNING *', [id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Link not found' });
    }
    res.json({ message: 'Link deleted successfully', link: result.rows[0] });
  } catch (error) {
    console.error('Error deleting link:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// 4. GET /api/logs - Get recent incident logs
app.get('/api/logs', async (req, res) => {
  try {
    const queryText = `
      SELECT il.*, l.name as link_name, l.url as link_url 
      FROM incident_logs il 
      JOIN links l ON il.link_id = l.id 
      ORDER BY il.detected_at DESC 
      LIMIT 100
    `;
    const result = await pool.query(queryText);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching logs:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Optional Telegram notification function
const sendTelegramAlert = async (linkName, linkUrl, statusCode, errorMessage) => {
  const botToken = process.env.TELEGRAM_BOT_TOKEN;
  const chatId = process.env.TELEGRAM_CHAT_ID;

  if (!botToken || !chatId) {
    console.log('Telegram alerts skipped: TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID not configured.');
    return;
  }

  const message = `🚨 *Dead Link Saver Alert* 🚨\n\n` +
                  `Link Name: *${linkName}*\n` +
                  `URL: ${linkUrl}\n` +
                  `Status Code: *${statusCode || 'N/A'}*\n` +
                  `Error: ${errorMessage || 'Unknown Network Error'}\n` +
                  `Time: ${new Date().toISOString()}`;

  try {
    await axios.post(`https://api.telegram.org/bot${botToken}/sendMessage`, {
      chat_id: chatId,
      text: message,
      parse_mode: 'Markdown'
    });
    console.log(`Telegram alert sent for ${linkName}`);
  } catch (error) {
    console.error('Failed to send Telegram alert:', error.message);
  }
};

// Optional Slack notification function
const sendSlackAlert = async (linkName, linkUrl, statusCode, errorMessage) => {
  const webhookUrl = process.env.SLACK_WEBHOOK_URL;

  if (!webhookUrl) {
    console.log('Slack alerts skipped: SLACK_WEBHOOK_URL not configured.');
    return;
  }

  const message = `🚨 *Dead Link Saver Alert* 🚨\n\n` +
                  `• *Link Name:* ${linkName}\n` +
                  `• *URL:* ${linkUrl}\n` +
                  `• *Status Code:* ${statusCode || 'N/A'}\n` +
                  `• *Error:* ${errorMessage || 'Unknown Network Error'}\n` +
                  `• *Time:* ${new Date().toISOString()}`;

  try {
    await axios.post(webhookUrl, { text: message });
    console.log(`Slack alert sent for ${linkName}`);
  } catch (error) {
    console.error('Failed to send Slack alert:', error.message);
  }
};

// 5. GET /api/cron/check - Cron route to ping links
app.get('/api/cron/check', async (req, res) => {
  const secret = req.query.secret;
  const cronSecret = process.env.CRON_SECRET;

  if (cronSecret && secret !== cronSecret) {
    return res.status(401).json({ error: 'Unauthorized: Invalid cron secret' });
  }

  try {
    // Fetch all links to check
    const linksResult = await pool.query('SELECT * FROM links');
    const links = linksResult.rows;

    const summary = {
      total: links.length,
      checked: 0,
      failed: 0,
      details: []
    };

    for (const link of links) {
      summary.checked++;
      let status = 'UP';
      let statusCode = null;
      let errorMessage = null;
      const startTime = Date.now();

      try {
        // Ping url with 5 second timeout
        const response = await axios.get(link.url, {
          timeout: 5000,
          headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
          },
          validateStatus: (status) => status < 400 // treats 400+ as errors
        });
        
        statusCode = response.status;
      } catch (error) {
        status = 'DOWN';
        if (error.response) {
          statusCode = error.response.status;
          errorMessage = `HTTP Error Code: ${error.response.status}`;
        } else if (error.request) {
          errorMessage = 'No response received (Timeout / Network Error)';
        } else {
          errorMessage = error.message;
        }
      }

      const responseTime = Date.now() - startTime;

      // Update rolling history array (max 20 checks)
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
      if (history.length > 20) {
        history = history.slice(-20);
      }

      // Update link check details in database
      await pool.query(
        'UPDATE links SET status = $1, last_checked = CURRENT_TIMESTAMP, response_time = $2, history = $3 WHERE id = $4',
        [status, responseTime, JSON.stringify(history), link.id]
      );

      // If link goes down, log it to incident_logs and send alerts
      if (status === 'DOWN') {
        summary.failed++;
        
        // Log the incident with response_time
        await pool.query(
          'INSERT INTO incident_logs (link_id, status_code, error_message, response_time) VALUES ($1, $2, $3, $4)',
          [link.id, statusCode, errorMessage, responseTime]
        );

        // Send alerts
        await sendTelegramAlert(link.name, link.url, statusCode, errorMessage);
        await sendSlackAlert(link.name, link.url, statusCode, errorMessage);
      }

      summary.details.push({
        id: link.id,
        name: link.name,
        url: link.url,
        status,
        statusCode,
        responseTime,
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

// Root route for healthcheck
app.get('/', (req, res) => {
  res.json({ status: 'healthy', service: 'dead-link-saver-backend' });
});

// Start Express App
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

module.exports = app;
