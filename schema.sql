-- Neon DB Schema for LinkSentinel

-- 1. Users Table
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255),
    subscription_tier VARCHAR(50) DEFAULT 'FREE' NOT NULL,
    subscription_status VARCHAR(50) DEFAULT 'ACTIVE' NOT NULL,
    stripe_customer_id VARCHAR(255),
    stripe_subscription_id VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 2. Links Table
CREATE TABLE IF NOT EXISTS links (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    name VARCHAR(255) NOT NULL,
    status VARCHAR(50) DEFAULT 'PENDING' NOT NULL, -- PENDING, UP, DOWN, PAUSED
    last_checked TIMESTAMP WITH TIME ZONE,
    response_time INTEGER,
    history JSONB DEFAULT '[]'::jsonb,
    is_active BOOLEAN DEFAULT TRUE NOT NULL,
    check_interval INTEGER DEFAULT 10 NOT NULL, -- in minutes
    ssl_expires_at TIMESTAMP WITH TIME ZONE,
    check_type VARCHAR(50) DEFAULT 'HTTP' NOT NULL, -- HTTP, SSL_ONLY, PORT, KEYWORD
    keyword VARCHAR(255),
    port INTEGER,
    slack_webhook_url TEXT,
    telegram_bot_token TEXT,
    telegram_chat_id TEXT,
    email_alert VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 3. Incident Logs Table
CREATE TABLE IF NOT EXISTS incident_logs (
    id SERIAL PRIMARY KEY,
    link_id INTEGER REFERENCES links(id) ON DELETE CASCADE NOT NULL,
    status_code INTEGER,
    error_message TEXT,
    response_time INTEGER,
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 4. API Keys Table
CREATE TABLE IF NOT EXISTS api_keys (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE NOT NULL,
    key_hash VARCHAR(64) UNIQUE NOT NULL, -- SHA-256 hash (64 chars hex)
    key_hint VARCHAR(15) NOT NULL, -- ls_live_xxxx
    name VARCHAR(255) DEFAULT 'Default API Key' NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP WITH TIME ZONE
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_links_user_id ON links(user_id);
CREATE INDEX IF NOT EXISTS idx_incident_logs_link_id ON incident_logs(link_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id);

-- Seed a default user (for simple single-user monitoring to start with)
INSERT INTO users (email) VALUES ('admin@example.com') ON CONFLICT (email) DO NOTHING;
