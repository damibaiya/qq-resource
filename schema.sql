-- 前面的表结构保持不变 (users, codes, categories, resources, daily_usage, unlocked_items, comments, likes)
-- 为了节省篇幅，请保留之前的 SQL，只替换最后的 messages 表部分，或者直接全量覆盖如下：

DROP TABLE IF EXISTS users;
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    username TEXT UNIQUE,
    password_hash TEXT,
    role TEXT DEFAULT 'user',
    daily_limit INTEGER DEFAULT 1,
    last_calc_date TEXT,
    last_unlock_date TEXT,
    temp_quota_config TEXT,
    last_reset_at INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

DROP TABLE IF EXISTS codes;
CREATE TABLE codes (
    email TEXT PRIMARY KEY,
    code TEXT NOT NULL,
    type TEXT DEFAULT 'login',
    expires_at INTEGER NOT NULL
);

DROP TABLE IF EXISTS categories;
CREATE TABLE categories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    sort_order INTEGER DEFAULT 0
);
INSERT INTO categories (name) VALUES ('综合'), ('电视剧'), ('综艺'), ('动漫');

DROP TABLE IF EXISTS resources;
CREATE TABLE resources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    category_id INTEGER,
    content_json TEXT NOT NULL, 
    custom_date TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

DROP TABLE IF EXISTS daily_usage;
CREATE TABLE daily_usage (
    user_id INTEGER NOT NULL,
    date_str TEXT NOT NULL,
    view_count INTEGER DEFAULT 0,
    PRIMARY KEY (user_id, date_str)
);

DROP TABLE IF EXISTS unlocked_items;
CREATE TABLE unlocked_items (
    user_id INTEGER NOT NULL,
    resource_id INTEGER NOT NULL,
    date_str TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, resource_id, date_str)
);

DROP TABLE IF EXISTS comments;
CREATE TABLE comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    resource_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

DROP TABLE IF EXISTS likes;
CREATE TABLE likes (
    user_id INTEGER NOT NULL,
    resource_id INTEGER NOT NULL,
    PRIMARY KEY (user_id, resource_id)
);

-- 9. 私信表 (结构变更)
DROP TABLE IF EXISTS messages;
CREATE TABLE messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,  -- 对话归属的用户ID
    sender TEXT DEFAULT 'user', -- 'user' 表示用户发给管理员, 'admin' 表示管理员回复用户
    content TEXT NOT NULL,
    is_read BOOLEAN DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
