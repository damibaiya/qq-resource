import { Hono } from 'hono';
import { handle } from 'hono/cloudflare-pages';
import { SignJWT, jwtVerify } from 'jose';

const app = new Hono().basePath('/api');

// === 工具函数 ===
async function signToken(payload, secret) {
  const secretKey = new TextEncoder().encode(secret);
  return await new SignJWT(payload).setProtectedHeader({ alg: 'HS256' }).setExpirationTime('7d').sign(secretKey);
}
async function verifyToken(token, secret) {
  try {
    const secretKey = new TextEncoder().encode(secret);
    return (await jwtVerify(token, secretKey)).payload;
  } catch (e) { return null; }
}
async function hashPassword(password) {
  const msgBuffer = new TextEncoder().encode(password);
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
  return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
}
async function sendEmail(env, to, subject, html) {
  await fetch('https://api.brevo.com/v3/smtp/email', {
    method: 'POST',
    headers: { 'accept': 'application/json', 'api-key': env.BREVO_API_KEY, 'content-type': 'application/json' },
    body: JSON.stringify({ sender: { email: env.SENDER_EMAIL, name: "蓝鲸小站" }, to: [{ email: to }], subject, htmlContent: html })
  });
}
function parseDateFromTitle(title) {
  const r1 = /(\d{4})年(\d{1,2})月(\d{1,2})日/;
  const r2 = /(20\d{2})(\d{2})(\d{2})/; 
  const r3 = /(\d{4})年/;
  let m = title.match(r1); if (m) return `${m[1]}年${m[2]}月${m[3]}日`;
  m = title.match(r2); if (m) return `${m[1]}年${parseInt(m[2])}月${parseInt(m[3])}日`;
  m = title.match(r3); if (m) return `${m[1]}年`;
  return "";
}
async function syncUserQuota(env, user, todayStr) {
  if (user.last_calc_date === todayStr) return user;
  let newLimit = 1; 
  const yesterday = new Date(Date.now() - 86400000).toISOString().split('T')[0];
  if (user.last_unlock_date === yesterday) newLimit = Math.min((user.daily_limit || 1) + 1, 3);
  else if (user.last_unlock_date === todayStr) newLimit = user.daily_limit; 
  else newLimit = 1;
  await env.DB.prepare('UPDATE users SET daily_limit = ?, last_calc_date = ? WHERE id = ?').bind(newLimit, todayStr, user.id).run();
  user.daily_limit = newLimit; user.last_calc_date = todayStr;
  return user;
}

// ================= API 路由 =================

// 1-4. 认证相关 (保持不变)
app.post('/auth/send-code', async (c) => {
  const { email, type } = await c.req.json();
  if (!/^[1-9][0-9]{4,}@qq\.com$/.test(email)) return c.json({ error: '仅支持QQ邮箱' }, 400);
  const user = await c.env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email).first();
  if (type === 'register' && user) return c.json({ error: '已注册' }, 400);
  if (type === 'reset' && !user) return c.json({ error: '未注册' }, 400);
  if (type === 'reset' && user && user.last_reset_at && (Date.now() - user.last_reset_at) < 259200000) return c.json({ error: '3天内只能重置一次' }, 400);
  const code = Math.floor(100000 + Math.random() * 900000).toString();
  await c.env.DB.prepare('INSERT OR REPLACE INTO codes (email, code, type, expires_at) VALUES (?, ?, ?, ?)').bind(email, code, type, Date.now() + 300000).run();
  await sendEmail(c.env, email, `【蓝鲸小站】验证码`, `<p>验证码: <b>${code}</b></p>`);
  return c.json({ success: true });
});
app.post('/auth/register', async (c) => {
  const { email, code, username, password } = await c.req.json();
  const rec = await c.env.DB.prepare('SELECT * FROM codes WHERE email = ? AND type = "register"').bind(email).first();
  if (!rec || rec.code !== code || Date.now() > rec.expires_at) return c.json({ error: '验证码无效' }, 400);
  if (await c.env.DB.prepare('SELECT id FROM users WHERE username = ?').bind(username).first()) return c.json({ error: '用户名已存在' }, 400);
  const res = await c.env.DB.prepare('INSERT INTO users (email, username, password_hash, daily_limit, last_calc_date) VALUES (?, ?, ?, 1, ?) RETURNING *')
    .bind(email, username, await hashPassword(password), new Date().toISOString().split('T')[0]).first();
  const token = await signToken({ id: res.id, role: 'user' }, c.env.JWT_SECRET);
  return c.json({ token, user: res });
});
app.post('/auth/login', async (c) => {
  const { loginId, password, isAdmin } = await c.req.json();
  if (isAdmin) {
    if (loginId === c.env.ADMIN_USER && password === c.env.ADMIN_PASSWD) 
      return c.json({ token: await signToken({ id: 0, role: 'admin' }, c.env.JWT_SECRET), user: { username: 'Admin', role: 'admin' } });
    return c.json({ error: '认证失败' }, 400);
  }
  let user = await c.env.DB.prepare('SELECT * FROM users WHERE (email = ? OR username = ?) AND password_hash = ?').bind(loginId, loginId, await hashPassword(password)).first();
  if (!user) return c.json({ error: '账号或密码错误' }, 400);
  user = await syncUserQuota(c.env, user, new Date().toISOString().split('T')[0]);
  const token = await signToken({ id: user.id, role: 'user' }, c.env.JWT_SECRET);
  return c.json({ token, user });
});
app.post('/auth/reset-password', async (c) => {
  const { email, code, newPassword } = await c.req.json();
  const rec = await c.env.DB.prepare('SELECT * FROM codes WHERE email = ? AND type = "reset"').bind(email).first();
  if (!rec || rec.code !== code || Date.now() > rec.expires_at) return c.json({ error: '验证码无效' }, 400);
  await c.env.DB.prepare('UPDATE users SET password_hash = ?, last_reset_at = ? WHERE email = ?').bind(await hashPassword(newPassword), Date.now(), email).run();
  return c.json({ success: true });
});

// 5-8. 资源相关 (保持不变)
app.get('/public/home', async (c) => {
  const q = c.req.query('q');
  const categories = await c.env.DB.prepare('SELECT * FROM categories ORDER BY sort_order').all();
  let sql = `SELECT r.id, r.title, r.category_id, r.content_json, r.custom_date, r.created_at, c.name as category_name, 
             (SELECT COUNT(*) FROM comments WHERE resource_id = r.id) as comment_count,
             (SELECT COUNT(*) FROM likes WHERE resource_id = r.id) as like_count
             FROM resources r LEFT JOIN categories c ON r.category_id = c.id`;
  if (q) sql += ` WHERE r.title LIKE ? OR r.custom_date LIKE ?`;
  sql += ` ORDER BY r.id DESC`;
  const resources = q ? await c.env.DB.prepare(sql).bind(`%${q}%`, `%${q}%`).all() : await c.env.DB.prepare(sql).all();
  const safeResources = resources.results.map(r => {
    let content = []; try { content = JSON.parse(r.content_json); } catch(e){}
    const safeContent = content.map(block => {
      if (block.type === 'link' || block.locked) return { ...block, value: '*** 🔒 限制内容 ***', isLockedMask: true };
      return block;
    });
    return { ...r, content: safeContent };
  });
  return c.json({ categories: categories.results, resources: safeResources });
});
app.get('/user/info', async (c) => {
  const token = c.req.header('Authorization')?.split(' ')[1];
  const payload = await verifyToken(token, c.env.JWT_SECRET);
  if (!payload) return c.json({ error: '未登录' }, 401);
  const today = new Date().toISOString().split('T')[0];
  let user = await c.env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(payload.id).first();
  user = await syncUserQuota(c.env, user, today);
  const used = (await c.env.DB.prepare('SELECT COUNT(*) as count FROM unlocked_items WHERE user_id = ? AND date_str = ?').bind(user.id, today).first()).count;
  let finalLimit = user.daily_limit;
  if (user.temp_quota_config) { try { const conf = JSON.parse(user.temp_quota_config); if (today >= conf.start && today <= conf.end) finalLimit = conf.limit; } catch(e) {} }
  return c.json({ user: { id: user.id, username: user.username, email: user.email }, quota: { total: finalLimit, used: used, remaining: Math.max(0, finalLimit - used) } });
});
app.post('/resource/unlock', async (c) => {
  const token = c.req.header('Authorization')?.split(' ')[1];
  const payload = await verifyToken(token, c.env.JWT_SECRET);
  if (!payload) return c.json({ error: '请登录' }, 401);
  if (payload.role === 'admin') return c.json({ error: '管理员直接看' });
  const { resourceId, blockIndex } = await c.req.json();
  const userId = payload.id;
  const today = new Date().toISOString().split('T')[0];
  const isUnlocked = await c.env.DB.prepare('SELECT 1 FROM unlocked_items WHERE user_id = ? AND resource_id = ? AND date_str = ?').bind(userId, resourceId, today).first();
  if (!isUnlocked) {
    let user = await c.env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(userId).first();
    user = await syncUserQuota(c.env, user, today);
    let limit = user.daily_limit;
    if (user.temp_quota_config) { try { const c = JSON.parse(user.temp_quota_config); if (today >= c.start && today <= c.end) limit = c.limit; } catch(e){} }
    const usedRes = await c.env.DB.prepare('SELECT COUNT(*) as c FROM unlocked_items WHERE user_id = ? AND date_str = ?').bind(userId, today).first();
    if (usedRes.c >= limit) return c.json({ error: `今日解锁次数已用完 (${limit}次)` }, 403);
    await c.env.DB.prepare('INSERT INTO unlocked_items (user_id, resource_id, date_str) VALUES (?, ?, ?)').bind(userId, resourceId, today).run();
    await c.env.DB.prepare('UPDATE users SET last_unlock_date = ? WHERE id = ?').bind(today, userId).run();
  }
  const res = await c.env.DB.prepare('SELECT content_json FROM resources WHERE id = ?').bind(resourceId).first();
  return c.json({ realValue: JSON.parse(res.content_json)[blockIndex].value });
});
app.post('/resource/comment', async (c) => {
  const token = c.req.header('Authorization')?.split(' ')[1];
  const u = await verifyToken(token, c.env.JWT_SECRET);
  if (!u) return c.json({ error: '请登录' }, 401);
  const { resourceId, content } = await c.req.json();
  await c.env.DB.prepare('INSERT INTO comments (user_id, resource_id, content) VALUES (?, ?, ?)').bind(u.id, resourceId, content).run();
  return c.json({ success: true });
});
app.get('/resource/comments/:id', async (c) => {
  const cmts = await c.env.DB.prepare(`SELECT c.content, c.created_at, u.username FROM comments c JOIN users u ON c.user_id = u.id WHERE c.resource_id = ? ORDER BY c.id DESC`).bind(c.req.param('id')).all();
  return c.json(cmts.results);
});
app.post('/resource/like', async (c) => {
  const token = c.req.header('Authorization')?.split(' ')[1];
  const u = await verifyToken(token, c.env.JWT_SECRET);
  if (!u) return c.json({ error: '请登录' }, 401);
  const { resourceId } = await c.req.json();
  const exist = await c.env.DB.prepare('SELECT 1 FROM likes WHERE user_id = ? AND resource_id = ?').bind(u.id, resourceId).first();
  if (exist) await c.env.DB.prepare('DELETE FROM likes WHERE user_id = ? AND resource_id = ?').bind(u.id, resourceId).run();
  else await c.env.DB.prepare('INSERT INTO likes (user_id, resource_id) VALUES (?, ?)').bind(u.id, resourceId).run();
  return c.json({ success: true });
});

// === 9. 私信功能 (大幅升级) ===

// 用户: 发送消息给管理员 (sender='user')
app.post('/user/message/send', async (c) => {
  const token = c.req.header('Authorization')?.split(' ')[1];
  const u = await verifyToken(token, c.env.JWT_SECRET);
  if (!u) return c.json({ error: '请登录' }, 401);
  const { content } = await c.req.json();
  if (!content) return c.json({ error: '内容不能为空' }, 400);
  await c.env.DB.prepare('INSERT INTO messages (user_id, sender, content) VALUES (?, "user", ?)').bind(u.id, content).run();
  return c.json({ success: true });
});

// 用户: 获取自己的聊天记录 (包括管理员回复)
app.get('/user/messages', async (c) => {
  const token = c.req.header('Authorization')?.split(' ')[1];
  const u = await verifyToken(token, c.env.JWT_SECRET);
  if (!u) return c.json({ error: '请登录' }, 401);
  const msgs = await c.env.DB.prepare('SELECT * FROM messages WHERE user_id = ? ORDER BY id ASC').bind(u.id).all();
  return c.json(msgs.results);
});

// 管理员: 获取有私信往来的用户列表 (收件箱列表)
app.get('/admin/inbox', async (c) => {
  const token = c.req.header('Authorization')?.split(' ')[1];
  const u = await verifyToken(token, c.env.JWT_SECRET);
  if (!u || u.role !== 'admin') return c.json({ error: '无权操作' }, 403);
  
  // 查询所有有过对话的用户，并按最后一条消息时间排序
  const list = await c.env.DB.prepare(`
    SELECT DISTINCT u.id, u.username, u.email,
    (SELECT content FROM messages WHERE user_id=u.id ORDER BY id DESC LIMIT 1) as last_msg,
    (SELECT created_at FROM messages WHERE user_id=u.id ORDER BY id DESC LIMIT 1) as last_time
    FROM users u 
    WHERE u.id IN (SELECT DISTINCT user_id FROM messages)
    ORDER BY last_time DESC
  `).all();
  return c.json(list.results);
});

// 管理员: 获取指定用户的聊天记录
app.get('/admin/messages/:userId', async (c) => {
  const token = c.req.header('Authorization')?.split(' ')[1];
  const u = await verifyToken(token, c.env.JWT_SECRET);
  if (!u || u.role !== 'admin') return c.json({ error: '无权操作' }, 403);
  const msgs = await c.env.DB.prepare('SELECT * FROM messages WHERE user_id = ? ORDER BY id ASC').bind(c.req.param('userId')).all();
  return c.json(msgs.results);
});

// 管理员: 回复用户 (sender='admin')
app.post('/admin/message/reply', async (c) => {
  const token = c.req.header('Authorization')?.split(' ')[1];
  const u = await verifyToken(token, c.env.JWT_SECRET);
  if (!u || u.role !== 'admin') return c.json({ error: '无权操作' }, 403);
  const { userId, content } = await c.req.json();
  await c.env.DB.prepare('INSERT INTO messages (user_id, sender, content) VALUES (?, "admin", ?)').bind(userId, content).run();
  return c.json({ success: true });
});

// === 管理员通用 API (保持不变) ===
app.get('/admin/resources', async (c) => {
  const token = c.req.header('Authorization')?.split(' ')[1];
  const u = await verifyToken(token, c.env.JWT_SECRET);
  if (!u || u.role !== 'admin') return c.json({ error: '无权' }, 403);
  const q = c.req.query('q');
  let sql = 'SELECT * FROM resources';
  if (q) sql += ` WHERE title LIKE '%${q}%'`;
  sql += ' ORDER BY id DESC LIMIT 50';
  const res = await c.env.DB.prepare(sql).all();
  return c.json(res.results);
});
app.post('/admin/resource', async (c) => {
  const token = c.req.header('Authorization')?.split(' ')[1];
  const u = await verifyToken(token, c.env.JWT_SECRET);
  if (!u || u.role !== 'admin') return c.json({ error: '无权' }, 403);
  const { id, title, category_id, blocks, manualDate } = await c.req.json();
  let dateStr = manualDate || parseDateFromTitle(title) || "日期不详";
  if (id) await c.env.DB.prepare('UPDATE resources SET title=?, category_id=?, content_json=?, custom_date=? WHERE id=?').bind(title, category_id, JSON.stringify(blocks), dateStr, id).run();
  else await c.env.DB.prepare('INSERT INTO resources (title, category_id, content_json, custom_date) VALUES (?, ?, ?, ?)').bind(title, category_id, JSON.stringify(blocks), dateStr).run();
  return c.json({ success: true });
});
app.get('/admin/resource/:id', async (c) => {
  const token = c.req.header('Authorization')?.split(' ')[1];
  const u = await verifyToken(token, c.env.JWT_SECRET);
  if (!u || u.role !== 'admin') return c.json({ error: '无权' }, 403);
  const r = await c.env.DB.prepare('SELECT * FROM resources WHERE id = ?').bind(c.req.param('id')).first();
  return c.json({ ...r, blocks: JSON.parse(r.content_json) });
});
app.post('/admin/resource/delete', async (c) => {
    const token = c.req.header('Authorization')?.split(' ')[1];
    const u = await verifyToken(token, c.env.JWT_SECRET);
    if (!u || u.role !== 'admin') return c.json({ error: '无权操作' }, 403);
    const { id } = await c.req.json();
    await c.env.DB.prepare('DELETE FROM resources WHERE id = ?').bind(id).run();
    return c.json({ success: true });
});
app.post('/admin/upload', async (c) => {
    const token = c.req.header('Authorization')?.split(' ')[1];
    const user = await verifyToken(token, c.env.JWT_SECRET);
    if (!user || user.role !== 'admin') return c.json({ error: '无权操作' }, 403);
    const body = await c.req.parseBody();
    const file = body['file'];
    if(file && file.name) {
        const fileName = `${Date.now()}-${file.name}`;
        await c.env.BUCKET.put(fileName, await file.arrayBuffer(), { httpMetadata: { contentType: file.type } });
        return c.json({ url: `${c.env.R2_DOMAIN}/${fileName}` });
    }
    return c.json({ error: '文件无效' }, 400);
});
app.post('/admin/category', async (c) => {
  const token = c.req.header('Authorization')?.split(' ')[1];
  const u = await verifyToken(token, c.env.JWT_SECRET);
  if (!u || u.role !== 'admin') return c.json({ error: '无权操作' }, 403);
  const { action, name, id } = await c.req.json();
  if(action === 'add') await c.env.DB.prepare('INSERT INTO categories (name) VALUES (?)').bind(name).run();
  if(action === 'del') await c.env.DB.prepare('DELETE FROM categories WHERE id = ?').bind(id).run();
  return c.json({ success: true });
});
app.get('/admin/users', async (c) => {
  const token = c.req.header('Authorization')?.split(' ')[1];
  const u = await verifyToken(token, c.env.JWT_SECRET);
  if (!u || u.role !== 'admin') return c.json({ error: '无权操作' }, 403);
  const users = await c.env.DB.prepare('SELECT id, username, email, daily_limit, temp_quota_config, created_at FROM users WHERE role != "admin" ORDER BY id DESC').all();
  return c.json(users.results);
});
app.post('/admin/user/quota', async (c) => {
  const token = c.req.header('Authorization')?.split(' ')[1];
  const u = await verifyToken(token, c.env.JWT_SECRET);
  if (!u || u.role !== 'admin') return c.json({ error: '无权操作' }, 403);
  const { userId, config } = await c.req.json();
  await c.env.DB.prepare('UPDATE users SET temp_quota_config = ? WHERE id = ?').bind(config ? JSON.stringify(config) : null, userId).run();
  return c.json({ success: true });
});

export const onRequest = handle(app);
