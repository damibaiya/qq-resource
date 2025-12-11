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
  const r1 = /(\d{4})年(\d{1,2})月(\d{1,2})日/; const r2 = /(20\d{2})(\d{2})(\d{2})/; const r3 = /(\d{4})年/;
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

// 1. 发送验证码
app.post('/auth/send-code', async (c) => {
  const { email, type } = await c.req.json();
  if (!/^[1-9][0-9]{4,}@qq\.com$/.test(email)) return c.json({ error: '仅支持QQ邮箱' }, 400);
  const banned = await c.env.DB.prepare('SELECT email FROM blacklist WHERE email = ?').bind(email).first();
  if (banned) return c.json({ error: '账号封禁中' }, 403);
  const user = await c.env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email).first();
  if (type === 'register' && user) return c.json({ error: '已注册' }, 400);
  if (type === 'reset' && !user) return c.json({ error: '未注册' }, 400);
  const code = Math.floor(100000 + Math.random() * 900000).toString();
  await c.env.DB.prepare('INSERT OR REPLACE INTO codes (email, code, type, expires_at) VALUES (?, ?, ?, ?)').bind(email, code, type, Date.now() + 300000).run();
  await sendEmail(c.env, email, `【蓝鲸小站】验证码`, `<p>验证码: <b>${code}</b></p>`);
  return c.json({ success: true });
});

// 2. 注册
app.post('/auth/register', async (c) => {
  const { email, code, username, password } = await c.req.json();
  const banned = await c.env.DB.prepare('SELECT email FROM blacklist WHERE email = ?').bind(email).first();
  if (banned) return c.json({ error: '账号封禁中' }, 403);
  const rec = await c.env.DB.prepare('SELECT * FROM codes WHERE email = ? AND type = "register"').bind(email).first();
  if (!rec || rec.code !== code || Date.now() > rec.expires_at) return c.json({ error: '验证码无效' }, 400);
  if (await c.env.DB.prepare('SELECT id FROM users WHERE username = ?').bind(username).first()) return c.json({ error: '用户名已存在' }, 400);
  const res = await c.env.DB.prepare('INSERT INTO users (email, username, password_hash, daily_limit, last_calc_date) VALUES (?, ?, ?, 1, ?) RETURNING *')
    .bind(email, username, await hashPassword(password), new Date().toISOString().split('T')[0]).first();
  const token = await signToken({ id: res.id, role: 'user' }, c.env.JWT_SECRET);
  return c.json({ token, user: res });
});

// 3. 登录
app.post('/auth/login', async (c) => {
  const { loginId, password, isAdmin } = await c.req.json();
  if (isAdmin) {
    if (loginId === c.env.ADMIN_USER && password === c.env.ADMIN_PASSWD) 
      return c.json({ token: await signToken({ id: 0, role: 'admin' }, c.env.JWT_SECRET), user: { username: 'Admin', role: 'admin' } });
    return c.json({ error: '认证失败' }, 400);
  }
  let user = await c.env.DB.prepare('SELECT * FROM users WHERE (email = ? OR username = ?) AND password_hash = ?').bind(loginId, loginId, await hashPassword(password)).first();
  if (!user) return c.json({ error: '账号或密码错误' }, 400);
  const banned = await c.env.DB.prepare('SELECT email FROM blacklist WHERE email = ?').bind(user.email).first();
  if (banned) return c.json({ error: '账号已被拉黑' }, 403);
  user = await syncUserQuota(c.env, user, new Date().toISOString().split('T')[0]);
  const token = await signToken({ id: user.id, role: 'user' }, c.env.JWT_SECRET);
  return c.json({ token, user });
});

// 4. 重置密码
app.post('/auth/reset-password', async (c) => {
  const { email, code, newPassword } = await c.req.json();
  const rec = await c.env.DB.prepare('SELECT * FROM codes WHERE email = ? AND type = "reset"').bind(email).first();
  if (!rec || rec.code !== code || Date.now() > rec.expires_at) return c.json({ error: '验证码无效' }, 400);
  await c.env.DB.prepare('UPDATE users SET password_hash = ?, last_reset_at = ? WHERE email = ?').bind(await hashPassword(newPassword), Date.now(), email).run();
  return c.json({ success: true });
});

// 5. 获取公共首页
app.get('/public/home', async (c) => {
  const q = c.req.query('q');
  const tagId = c.req.query('tagId');
  const catId = c.req.query('catId');

  const categories = await c.env.DB.prepare('SELECT * FROM categories ORDER BY sort_order').all();
  
  // 查询资源
  let sql = `SELECT DISTINCT r.id, r.title, r.category_id, r.content_json, r.custom_date, r.created_at, c.name as category_name, 
             (SELECT COUNT(*) FROM comments WHERE resource_id = r.id) as comment_count,
             (SELECT COUNT(*) FROM likes WHERE resource_id = r.id) as like_count
             FROM resources r 
             LEFT JOIN categories c ON r.category_id = c.id
             LEFT JOIN resource_tags rt ON r.id = rt.resource_id`;
  
  let conditions = [];
  let params = [];

  if (q) { conditions.push('(r.title LIKE ? OR r.custom_date LIKE ?)'); params.push(`%${q}%`, `%${q}%`); }
  if (catId) { conditions.push('r.category_id = ?'); params.push(catId); }
  if (tagId) { conditions.push('rt.tag_id = ?'); params.push(tagId); }

  if (conditions.length > 0) sql += ' WHERE ' + conditions.join(' AND ');
  sql += ` ORDER BY r.id DESC LIMIT 100`;

  const resources = await c.env.DB.prepare(sql).bind(...params).all();

  // 获取资源的标签
  const resourceIds = resources.results.map(r => r.id);
  let resTagsMap = {};
  if(resourceIds.length > 0) {
      const tagsData = await c.env.DB.prepare(`
        SELECT rt.resource_id, t.name, t.type 
        FROM resource_tags rt JOIN tags t ON rt.tag_id = t.id 
        WHERE rt.resource_id IN (${resourceIds.join(',')})
      `).all();
      tagsData.results.forEach(t => {
          if(!resTagsMap[t.resource_id]) resTagsMap[t.resource_id] = [];
          resTagsMap[t.resource_id].push(t);
      });
  }

  const safeResources = resources.results.map(r => {
    let content = []; try { content = JSON.parse(r.content_json); } catch(e){}
    const safeContent = content.map(block => {
      if (block.type === 'link' || block.locked) return { ...block, value: '*** 🗝️ 需要钥匙解锁 ***', isLockedMask: true };
      return block;
    });
    return { ...r, content: safeContent, tags: resTagsMap[r.id] || [] };
  });

  return c.json({ categories: categories.results, resources: safeResources });
});

// 6. 【核心修复】获取标签墙 (严格过滤，必须关联真实存在的资源)
app.get('/public/tags', async (c) => {
    const type = c.req.query('type'); 
    if (!type) return c.json([]);
    // 增加 JOIN resources r ON rt.resource_id = r.id，确保资源表里真的有这个ID
    const res = await c.env.DB.prepare(`
        SELECT DISTINCT t.* 
        FROM tags t 
        JOIN resource_tags rt ON t.id = rt.tag_id 
        JOIN resources r ON rt.resource_id = r.id
        WHERE t.type = ? 
        ORDER BY t.id DESC
    `).bind(type).all();
    return c.json(res.results);
});

// 7. 辅助: 查找标签图片
app.get('/public/tag-image', async (c) => {
    const name = c.req.query('name');
    const type = c.req.query('type');
    const tag = await c.env.DB.prepare('SELECT image_url FROM tags WHERE name = ? AND type = ?').bind(name, type).first();
    return c.json({ imageUrl: tag ? tag.image_url : '' });
});

// 8. 用户信息
app.get('/user/info', async (c) => {
  const token = c.req.header('Authorization')?.split(' ')[1];
  const payload = await verifyToken(token, c.env.JWT_SECRET);
  if (!payload) return c.json({ error: '未登录' }, 401);
  const today = new Date().toISOString().split('T')[0];
  let user = await c.env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(payload.id).first();
  if(!user) return c.json({error:'用户不存在'}, 404);
  user = await syncUserQuota(c.env, user, today);
  const used = (await c.env.DB.prepare('SELECT COUNT(*) as count FROM unlocked_items WHERE user_id = ? AND date_str = ?').bind(user.id, today).first()).count;
  let finalLimit = user.daily_limit; let isTemp = false;
  if (user.temp_quota_config) { try { const conf = JSON.parse(user.temp_quota_config); if (today >= conf.start && today <= conf.end) { finalLimit = conf.limit; isTemp = true; } } catch(e) {} }
  return c.json({ user: { id: user.id, username: user.username, email: user.email, is_muted: user.is_muted }, quota: { total: finalLimit, used: used, remaining: Math.max(0, finalLimit - used), isTemp } });
});

// 9. 解锁内容
app.post('/resource/unlock', async (c) => {
  const token = c.req.header('Authorization')?.split(' ')[1];
  const payload = await verifyToken(token, c.env.JWT_SECRET);
  if (!payload) return c.json({ error: '请登录' }, 401);
  if (payload.role === 'admin') return c.json({ error: '管理员无需解锁' });
  const { resourceId } = await c.req.json();
  const userId = payload.id;
  const today = new Date().toISOString().split('T')[0];
  const isUnlocked = await c.env.DB.prepare('SELECT 1 FROM unlocked_items WHERE user_id = ? AND resource_id = ? AND date_str = ?').bind(userId, resourceId, today).first();
  if (!isUnlocked) {
    let user = await c.env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(userId).first();
    user = await syncUserQuota(c.env, user, today);
    let limit = user.daily_limit;
    if (user.temp_quota_config) { try { const c = JSON.parse(user.temp_quota_config); if (today >= c.start && today <= c.end) limit = c.limit; } catch(e){} }
    const usedRes = await c.env.DB.prepare('SELECT COUNT(*) as c FROM unlocked_items WHERE user_id = ? AND date_str = ?').bind(userId, today).first();
    if (usedRes.c >= limit) return c.json({ error: `今日钥匙已用完` }, 403);
    await c.env.DB.prepare('INSERT INTO unlocked_items (user_id, resource_id, date_str) VALUES (?, ?, ?)').bind(userId, resourceId, today).run();
    await c.env.DB.prepare('UPDATE users SET last_unlock_date = ? WHERE id = ?').bind(today, userId).run();
  }
  const res = await c.env.DB.prepare('SELECT content_json FROM resources WHERE id = ?').bind(resourceId).first();
  return c.json({ fullContent: JSON.parse(res.content_json) });
});

// 10. 互动功能
async function checkMute(env, userId) { const u = await env.DB.prepare('SELECT is_muted FROM users WHERE id = ?').bind(userId).first(); return u && u.is_muted === 1; }
app.post('/resource/comment', async (c) => {
  const t = c.req.header('Authorization')?.split(' ')[1]; const u = await verifyToken(t, c.env.JWT_SECRET); if (!u) return c.json({error:'未登录'},401); if(await checkMute(c.env, u.id)) return c.json({error:'禁言中'},403);
  const { resourceId, content } = await c.req.json(); await c.env.DB.prepare('INSERT INTO comments (user_id, resource_id, content) VALUES (?, ?, ?)').bind(u.id, resourceId, content).run(); return c.json({success:true});
});
app.get('/resource/comments/:id', async (c) => { const r = await c.env.DB.prepare(`SELECT c.content, c.created_at, u.username FROM comments c JOIN users u ON c.user_id = u.id WHERE c.resource_id = ? ORDER BY c.id DESC`).bind(c.req.param('id')).all(); return c.json(r.results); });
app.post('/resource/like', async (c) => { const t = c.req.header('Authorization')?.split(' ')[1]; const u = await verifyToken(t, c.env.JWT_SECRET); if (!u) return c.json({error:'未登录'},401); if(await checkMute(c.env, u.id)) return c.json({error:'禁言中'},403); const { resourceId } = await c.req.json(); const ex = await c.env.DB.prepare('SELECT 1 FROM likes WHERE user_id=? AND resource_id=?').bind(u.id, resourceId).first(); if(ex) await c.env.DB.prepare('DELETE FROM likes WHERE user_id=? AND resource_id=?').bind(u.id, resourceId).run(); else await c.env.DB.prepare('INSERT INTO likes (user_id, resource_id) VALUES (?, ?)').bind(u.id, resourceId).run(); return c.json({success:true}); });
app.post('/user/message/send', async (c) => { const t = c.req.header('Authorization')?.split(' ')[1]; const u = await verifyToken(t, c.env.JWT_SECRET); if (!u) return c.json({error:'未登录'},401); if(await checkMute(c.env, u.id)) return c.json({error:'禁言中'},403); const { content } = await c.req.json(); await c.env.DB.prepare('INSERT INTO messages (user_id, sender, content) VALUES (?, "user", ?)').bind(u.id, content).run(); return c.json({success:true}); });
app.get('/user/messages', async (c) => { const t = c.req.header('Authorization')?.split(' ')[1]; const u = await verifyToken(t, c.env.JWT_SECRET); if (!u) return c.json({error:'未登录'},401); const r = await c.env.DB.prepare('SELECT * FROM messages WHERE user_id = ? ORDER BY id ASC').bind(u.id).all(); return c.json(r.results); });

// === 管理员 API ===

// 自动关联
app.get('/admin/tag-keywords', async (c) => {
    const t = c.req.header('Authorization')?.split(' ')[1]; const u = await verifyToken(t, c.env.JWT_SECRET); if(!u||u.role!=='admin') return c.json({error:'无权'},403);
    const res = await c.env.DB.prepare('SELECT * FROM tag_keywords ORDER BY id DESC').all();
    return c.json(res.results);
});
app.post('/admin/tag-keywords', async (c) => {
    const t = c.req.header('Authorization')?.split(' ')[1]; const u = await verifyToken(t, c.env.JWT_SECRET); if(!u||u.role!=='admin') return c.json({error:'无权'},403);
    const { action, id, keyword, tagName, tagType } = await c.req.json();
    if (action === 'add') await c.env.DB.prepare('INSERT INTO tag_keywords (keyword, tag_name, tag_type) VALUES (?, ?, ?)').bind(keyword, tagName, tagType).run();
    else if (action === 'del') await c.env.DB.prepare('DELETE FROM tag_keywords WHERE id = ?').bind(id).run();
    return c.json({ success: true });
});

// 标签列表
app.get('/admin/tags/all', async (c) => {
    const t = c.req.header('Authorization')?.split(' ')[1]; const u = await verifyToken(t, c.env.JWT_SECRET); if(!u||u.role!=='admin') return c.json({error:'无权'},403);
    // 这里也可以加 STRICT 过滤，但管理员可能想看所有标签，所以保持原样，只显示关联数
    const res = await c.env.DB.prepare(`SELECT t.*, (SELECT COUNT(*) FROM resource_tags WHERE tag_id = t.id) as post_count FROM tags t ORDER BY post_count DESC`).all();
    return c.json(res.results);
});

// 发布/修改资源
app.post('/admin/resource', async (c) => {
  const t = c.req.header('Authorization')?.split(' ')[1]; const u = await verifyToken(t, c.env.JWT_SECRET); if(!u||u.role!=='admin') return c.json({error:'无权'},403);
  const { id, title, category_id, blocks, manualDate, tags } = await c.req.json();
  const hasValidLink = blocks.some(b => b.type === 'link' && b.value && b.value.trim() !== '');
  if (!hasValidLink) return c.json({ error: '发布失败：必须包含至少一条有效的链接！' }, 400);

  let dateStr = manualDate || parseDateFromTitle(title) || "日期不详";
  let resourceId = id;
  if (id) {
    await c.env.DB.prepare('UPDATE resources SET title=?, category_id=?, content_json=?, custom_date=? WHERE id=?').bind(title, category_id, JSON.stringify(blocks), dateStr, id).run();
    await c.env.DB.prepare('DELETE FROM resource_tags WHERE resource_id = ?').bind(id).run();
  } else {
    const res = await c.env.DB.prepare('INSERT INTO resources (title, category_id, content_json, custom_date) VALUES (?, ?, ?, ?) RETURNING id').bind(title, category_id, JSON.stringify(blocks), dateStr).first();
    resourceId = res.id;
  }

  // 标签关联
  const rules = await c.env.DB.prepare('SELECT * FROM tag_keywords').all();
  const fullText = title + blocks.filter(b => b.type === 'text').map(b => b.value).join(' ');
  let finalTags = [...(tags || [])];
  for (const rule of rules.results) {
      if (fullText.includes(rule.keyword)) {
          if (!finalTags.find(ft => ft.name === rule.tag_name && ft.type === rule.tag_type)) finalTags.push({ name: rule.tag_name, type: rule.tag_type });
      }
  }

  if (finalTags.length > 0) {
      for (const tag of finalTags) {
          if (!tag.name) continue;
          let existing = await c.env.DB.prepare('SELECT id, image_url FROM tags WHERE name = ? AND type = ?').bind(tag.name, tag.type).first();
          let tagId;
          if (existing) {
              tagId = existing.id;
              if (tag.image_url) await c.env.DB.prepare('UPDATE tags SET image_url = ? WHERE id = ?').bind(tag.image_url, tagId).run();
          } else {
              const newTag = await c.env.DB.prepare('INSERT INTO tags (name, type, image_url) VALUES (?, ?, ?) RETURNING id').bind(tag.name, tag.type, tag.image_url || '').first();
              tagId = newTag.id;
          }
          await c.env.DB.prepare('INSERT INTO resource_tags (resource_id, tag_id) VALUES (?, ?)').bind(resourceId, tagId).run();
      }
  }
  return c.json({ success: true });
});

// 删除资源 (包含清理标签)
app.post('/admin/resource/delete', async (c) => {
    const t = c.req.header('Authorization')?.split(' ')[1]; 
    const u = await verifyToken(t, c.env.JWT_SECRET); 
    if(!u || u.role !== 'admin') return c.json({error:'无权操作'}, 403);
    const { id } = await c.req.json();
    await c.env.DB.prepare('DELETE FROM resource_tags WHERE resource_id = ?').bind(id).run();
    await c.env.DB.prepare('DELETE FROM resources WHERE id = ?').bind(id).run();
    // 清理幽灵标签
    await c.env.DB.prepare('DELETE FROM tags WHERE id NOT IN (SELECT DISTINCT tag_id FROM resource_tags)').run();
    return c.json({ success: true });
});

// 其他管理员 API
app.get('/admin/resource/:id', async (c) => { const t=c.req.header('Authorization')?.split(' ')[1]; const u=await verifyToken(t,c.env.JWT_SECRET); if(!u||u.role!=='admin') return c.json({error:'无权'},403); const r=await c.env.DB.prepare('SELECT * FROM resources WHERE id=?').bind(c.req.param('id')).first(); const tags=await c.env.DB.prepare('SELECT t.name, t.type, t.image_url FROM resource_tags rt JOIN tags t ON rt.tag_id=t.id WHERE rt.resource_id=?').bind(r.id).all(); return c.json({...r, blocks:JSON.parse(r.content_json), tags:tags.results}); });
app.get('/admin/resources', async (c) => { const t=c.req.header('Authorization')?.split(' ')[1]; const u=await verifyToken(t,c.env.JWT_SECRET); if(!u||u.role!=='admin') return c.json({error:'无权'},403); const q=c.req.query('q'); const catId=c.req.query('catId'); const tagId=c.req.query('tagId'); let sql='SELECT * FROM resources'; let p=[]; let k=[]; if(q){k.push("title LIKE ?");p.push(`%${q}%`);} if(catId){k.push("category_id=?");p.push(catId);} if(tagId){sql='SELECT r.* FROM resources r JOIN resource_tags rt ON r.id=rt.resource_id WHERE rt.tag_id=?'; p=[tagId];} if(k.length>0 && !tagId) sql+=' WHERE '+k.join(' AND '); sql+=' ORDER BY id DESC LIMIT 50'; const r=await c.env.DB.prepare(sql).bind(...p).all(); return c.json(r.results); });
app.post('/admin/upload', async (c) => { const t=c.req.header('Authorization')?.split(' ')[1]; const u=await verifyToken(t,c.env.JWT_SECRET); if(!u||u.role!=='admin') return c.json({error:'无权'},403); const b=await c.req.parseBody(); const f=b['file']; if(f&&f.name){ const n=`${Date.now()}-${f.name}`; await c.env.BUCKET.put(n,await f.arrayBuffer(),{httpMetadata:{contentType:f.type}}); return c.json({url:`${c.env.R2_DOMAIN}/${n}`}); } return c.json({error:'无效'},400); });
app.post('/admin/category', async (c) => { const t=c.req.header('Authorization')?.split(' ')[1]; const u=await verifyToken(t,c.env.JWT_SECRET); if(!u||u.role!=='admin') return c.json({error:'无权'},403); const {action,name,id}=await c.req.json(); if(action==='add') await c.env.DB.prepare('INSERT INTO categories(name) VALUES(?)').bind(name).run(); if(action==='del') await c.env.DB.prepare('DELETE FROM categories WHERE id=?').bind(id).run(); return c.json({success:true}); });
app.post('/admin/users/batch', async (c) => { const t=c.req.header('Authorization')?.split(' ')[1]; const u=await verifyToken(t,c.env.JWT_SECRET); if(!u||u.role!=='admin') return c.json({error:'无权'},403); const {userIds,action}=await c.req.json(); const ph=userIds.map(()=>'?').join(','); if(action==='mute') await c.env.DB.prepare(`UPDATE users SET is_muted=1 WHERE id IN (${ph})`).bind(...userIds).run(); else if(action==='unmute') await c.env.DB.prepare(`UPDATE users SET is_muted=0 WHERE id IN (${ph})`).bind(...userIds).run(); else if(action==='delete') await c.env.DB.prepare(`DELETE FROM users WHERE id IN (${ph})`).bind(...userIds).run(); else if(action==='ban'){ const us=await c.env.DB.prepare(`SELECT email FROM users WHERE id IN (${ph})`).bind(...userIds).all(); for(const x of us.results) await c.env.DB.prepare('INSERT OR IGNORE INTO blacklist (email,reason) VALUES (?, "批量")').bind(x.email).run(); await c.env.DB.prepare(`DELETE FROM users WHERE id IN (${ph})`).bind(...userIds).run(); } return c.json({success:true}); });
app.get('/admin/blacklist', async (c) => { const t=c.req.header('Authorization')?.split(' ')[1]; const u=await verifyToken(t,c.env.JWT_SECRET); if(!u||u.role!=='admin') return c.json({error:'无权'},403); const r=await c.env.DB.prepare('SELECT * FROM blacklist ORDER BY created_at DESC').all(); return c.json(r.results); });
app.post('/admin/blacklist/delete', async (c) => { const t=c.req.header('Authorization')?.split(' ')[1]; const u=await verifyToken(t,c.env.JWT_SECRET); if(!u||u.role!=='admin') return c.json({error:'无权'},403); await c.env.DB.prepare('DELETE FROM blacklist WHERE email=?').bind((await c.req.json()).email).run(); return c.json({success:true}); });
app.get('/admin/users', async (c) => { const t=c.req.header('Authorization')?.split(' ')[1]; const u=await verifyToken(t,c.env.JWT_SECRET); if(!u||u.role!=='admin') return c.json({error:'无权'},403); const r=await c.env.DB.prepare('SELECT id,username,email,daily_limit,temp_quota_config,is_muted,created_at FROM users WHERE role!="admin" ORDER BY id DESC').all(); return c.json(r.results); });
app.post('/admin/user/quota', async (c) => { const t=c.req.header('Authorization')?.split(' ')[1]; const u=await verifyToken(t,c.env.JWT_SECRET); if(!u||u.role!=='admin') return c.json({error:'无权'},403); const {userId,config}=await c.req.json(); await c.env.DB.prepare('UPDATE users SET temp_quota_config=? WHERE id=?').bind(config?JSON.stringify(config):null,userId).run(); return c.json({success:true}); });
app.get('/admin/inbox', async (c) => { const t=c.req.header('Authorization')?.split(' ')[1]; const u=await verifyToken(t,c.env.JWT_SECRET); if(!u||u.role!=='admin') return c.json({error:'无权'},403); const r=await c.env.DB.prepare(`SELECT DISTINCT u.id,u.username,u.email,(SELECT content FROM messages WHERE user_id=u.id ORDER BY id DESC LIMIT 1) as last_msg,(SELECT created_at FROM messages WHERE user_id=u.id ORDER BY id DESC LIMIT 1) as last_time FROM users u WHERE u.id IN (SELECT DISTINCT user_id FROM messages) ORDER BY last_time DESC`).all(); return c.json(r.results); });
app.get('/admin/messages/:id', async (c) => { const t=c.req.header('Authorization')?.split(' ')[1]; const u=await verifyToken(t,c.env.JWT_SECRET); if(!u||u.role!=='admin') return c.json({error:'无权'},403); const r=await c.env.DB.prepare('SELECT * FROM messages WHERE user_id=? ORDER BY id ASC').bind(c.req.param('id')).all(); return c.json(r.results); });
app.post('/admin/message/reply', async (c) => { const t=c.req.header('Authorization')?.split(' ')[1]; const u=await verifyToken(t,c.env.JWT_SECRET); if(!u||u.role!=='admin') return c.json({error:'无权'},403); const {userId,content}=await c.req.json(); await c.env.DB.prepare('INSERT INTO messages(user_id,sender,content) VALUES(?,"admin",?)').bind(userId,content).run(); return c.json({success:true}); });

export const onRequest = handle(app);
