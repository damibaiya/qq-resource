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

// 日期识别逻辑 (之前优化的版本)
function parseDateFromTitle(title) {
  const fixYear = (yy) => { const y = parseInt(yy); return y < 70 ? `20${yy}` : `19${yy}`; };
  let m = title.match(/(\d{4})年(\d{1,2})月(\d{1,2})日/);
  if (m) return `${m[1]}年${parseInt(m[2])}月${parseInt(m[3])}日`;
  m = title.match(/(\d{4})\.(\d{1,2})\.(\d{1,2})/);
  if (m) return `${m[1]}年${parseInt(m[2])}月${parseInt(m[3])}日`;
  m = title.match(/(?<!\d)(\d{2})\.(\d{1,2})\.(\d{1,2})(?!\d)/);
  if (m) return `${fixYear(m[1])}年${parseInt(m[2])}月${parseInt(m[3])}日`;
  m = title.match(/(\d{4})\.(\d{1,2})(?!\.\d)/);
  if (m) return `${m[1]}年${parseInt(m[2])}月`;
  m = title.match(/(20\d{2})(\d{2})(\d{2})/); 
  if (m) return `${m[1]}年${parseInt(m[2])}月${parseInt(m[3])}日`;
  m = title.match(/(?<!\d)(\d{2})(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])(?!\d)/);
  if (m) return `${fixYear(m[1])}年${parseInt(m[2])}月${parseInt(m[3])}日`;
  m = title.match(/(\d{4})年/);
  if (m) return `${m[1]}年`;
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
// 认证 (不变)
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
app.post('/auth/register', async (c) => {
  const { email, code, username, password } = await c.req.json();
  const banned = await c.env.DB.prepare('SELECT email FROM blacklist WHERE email = ?').bind(email).first();
  if (banned) return c.json({ error: '账号封禁中' }, 403);
  const rec = await c.env.DB.prepare('SELECT * FROM codes WHERE email = ? AND type = "register"').bind(email).first();
  if (!rec || rec.code !== code || Date.now() > rec.expires_at) return c.json({ error: '验证码无效' }, 400);
  if (await c.env.DB.prepare('SELECT id FROM users WHERE username = ?').bind(username).first()) return c.json({ error: '用户名已存在' }, 400);
  const res = await c.env.DB.prepare('INSERT INTO users (email, username, password_hash, daily_limit, last_calc_date) VALUES (?, ?, ?, 1, ?) RETURNING *').bind(email, username, await hashPassword(password), new Date().toISOString().split('T')[0]).first();
  const token = await signToken({ id: res.id, role: 'user' }, c.env.JWT_SECRET);
  return c.json({ token, user: res });
});
app.post('/auth/login', async (c) => {
  const { loginId, password, isAdmin } = await c.req.json();
  if (isAdmin) { if (loginId === c.env.ADMIN_USER && password === c.env.ADMIN_PASSWD) return c.json({ token: await signToken({ id: 0, role: 'admin' }, c.env.JWT_SECRET), user: { username: 'Admin', role: 'admin' } }); return c.json({ error: '认证失败' }, 400); }
  let user = await c.env.DB.prepare('SELECT * FROM users WHERE (email = ? OR username = ?) AND password_hash = ?').bind(loginId, loginId, await hashPassword(password)).first();
  if (!user) return c.json({ error: '账号或密码错误' }, 400);
  const banned = await c.env.DB.prepare('SELECT email FROM blacklist WHERE email = ?').bind(user.email).first();
  if (banned) return c.json({ error: '账号已被拉黑' }, 403);
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

// 5. 获取公共首页 (分页)
app.get('/public/home', async (c) => {
  const q = c.req.query('q');
  const tagId = c.req.query('tagId');
  const catId = c.req.query('catId');
  const page = parseInt(c.req.query('page') || '1'); 
  const pageSize = 25; 
  const offset = (page - 1) * pageSize;

  const categories = await c.env.DB.prepare('SELECT * FROM categories ORDER BY sort_order').all();
  
  let sql = `SELECT DISTINCT r.id, r.title, r.category_id, r.content_json, r.custom_date, r.created_at, c.name as category_name, 
             (SELECT COUNT(*) FROM comments WHERE resource_id = r.id) as comment_count,
             (SELECT COUNT(*) FROM likes WHERE resource_id = r.id) as like_count
             FROM resources r 
             LEFT JOIN categories c ON r.category_id = c.id
             LEFT JOIN resource_tags rt ON r.id = rt.resource_id
             LEFT JOIN tags t ON rt.tag_id = t.id`;
  
  let conditions = []; let params = [];
  if (q) { conditions.push('(r.title LIKE ? OR r.custom_date LIKE ? OR t.name LIKE ?)'); params.push(`%${q}%`, `%${q}%`, `%${q}%`); }
  if (catId) { conditions.push('r.category_id = ?'); params.push(catId); }
  if (tagId) { conditions.push('rt.tag_id = ?'); params.push(tagId); }

  if (conditions.length > 0) sql += ' WHERE ' + conditions.join(' AND ');
  
  sql += ` ORDER BY r.id DESC LIMIT ? OFFSET ?`;
  params.push(pageSize, offset);

  const resources = await c.env.DB.prepare(sql).bind(...params).all();

  const resourceIds = resources.results.map(r => r.id);
  let resTagsMap = {};
  if(resourceIds.length > 0) {
      const tagsData = await c.env.DB.prepare(`SELECT rt.resource_id, t.name, t.type FROM resource_tags rt JOIN tags t ON rt.tag_id = t.id WHERE rt.resource_id IN (${resourceIds.join(',')})`).all();
      tagsData.results.forEach(t => { if(!resTagsMap[t.resource_id]) resTagsMap[t.resource_id] = []; resTagsMap[t.resource_id].push(t); });
  }
  const safeResources = resources.results.map(r => {
    let content = []; try { content = JSON.parse(r.content_json); } catch(e){}
    const safeContent = content.map(block => { if (block.type === 'link' || block.locked) return { ...block, value: '*** 🗝️ 需要钥匙解锁 ***', isLockedMask: true }; return block; });
    return { ...r, content: safeContent, tags: resTagsMap[r.id] || [] };
  });

  return c.json({ categories: page===1 ? categories.results : [], resources: safeResources, hasMore: safeResources.length === pageSize });
});

// 6-10. 其他用户接口 (保持不变)
app.get('/public/tags', async (c) => { const t=c.req.query('type'); if(!t)return c.json([]); const r=await c.env.DB.prepare(`SELECT DISTINCT t.* FROM tags t JOIN resource_tags rt ON t.id=rt.tag_id WHERE t.type=? ORDER BY t.id DESC`).bind(t).all(); return c.json(r.results); });
app.get('/public/tag-image', async (c) => { const {name,type}=c.req.query(); const t=await c.env.DB.prepare('SELECT image_url FROM tags WHERE name=? AND type=?').bind(name,type).first(); return c.json({imageUrl:t?t.image_url:''}); });
app.get('/user/info', async (c) => { const t=c.req.header('Authorization')?.split(' ')[1]; const p=await verifyToken(t,c.env.JWT_SECRET); if(!p) return c.json({error:'未登录'},401); const today=new Date().toISOString().split('T')[0]; let u=await c.env.DB.prepare('SELECT * FROM users WHERE id=?').bind(p.id).first(); if(!u) return c.json({error:'不存在'},404); u=await syncUserQuota(c.env,u,today); const used=(await c.env.DB.prepare('SELECT COUNT(*) as c FROM unlocked_items WHERE user_id=? AND date_str=?').bind(u.id,today).first()).c; let l=u.daily_limit,isT=false; if(u.temp_quota_config){try{const o=JSON.parse(u.temp_quota_config);if(today>=o.start&&today<=o.end){l=o.limit;isT=true}}catch(e){}} return c.json({user:{id:u.id,username:u.username,email:u.email,is_muted:u.is_muted},quota:{total:l,used,remaining:Math.max(0,l-used),isTemp:isT}}); });
app.post('/resource/unlock', async (c) => { const t=c.req.header('Authorization')?.split(' ')[1]; const p=await verifyToken(t,c.env.JWT_SECRET); if(!p) return c.json({error:'请登录'},401); if(p.role==='admin') return c.json({error:'管理员直接看'}); const {resourceId}=await c.req.json(); const uid=p.id, today=new Date().toISOString().split('T')[0]; const isU=await c.env.DB.prepare('SELECT 1 FROM unlocked_items WHERE user_id=? AND resource_id=? AND date_str=?').bind(uid,resourceId,today).first(); if(!isU){ let u=await c.env.DB.prepare('SELECT * FROM users WHERE id=?').bind(uid).first(); u=await syncUserQuota(c.env,u,today); let l=u.daily_limit; if(u.temp_quota_config){try{const o=JSON.parse(u.temp_quota_config);if(today>=o.start&&today<=o.end)l=o.limit}catch(e){}} const used=(await c.env.DB.prepare('SELECT COUNT(*) as c FROM unlocked_items WHERE user_id=? AND date_str=?').bind(uid,today).first()).c; if(used>=l) return c.json({error:'今日钥匙用完'},403); await c.env.DB.prepare('INSERT INTO unlocked_items(user_id,resource_id,date_str) VALUES(?,?,?)').bind(uid,resourceId,today).run(); await c.env.DB.prepare('UPDATE users SET last_unlock_date=? WHERE id=?').bind(today,uid).run(); } const r=await c.env.DB.prepare('SELECT content_json FROM resources WHERE id=?').bind(resourceId).first(); return c.json({fullContent:JSON.parse(r.content_json)}); });
async function checkMute(env, uid) { const u=await env.DB.prepare('SELECT is_muted FROM users WHERE id=?').bind(uid).first(); return u&&u.is_muted===1; }
app.post('/resource/comment', async (c) => { const t=c.req.header('Authorization')?.split(' ')[1]; const u=await verifyToken(t,c.env.JWT_SECRET); if(!u) return c.json({error:'未登录'},401); if(await checkMute(c.env,u.id)) return c.json({error:'禁言中'},403); const {resourceId,content}=await c.req.json(); await c.env.DB.prepare('INSERT INTO comments(user_id,resource_id,content) VALUES(?,?,?)').bind(u.id,resourceId,content).run(); return c.json({success:true}); });
app.get('/resource/comments/:id', async (c) => { const r=await c.env.DB.prepare(`SELECT c.content,c.created_at,u.username FROM comments c JOIN users u ON c.user_id=u.id WHERE c.resource_id=? ORDER BY c.id DESC`).bind(c.req.param('id')).all(); return c.json(r.results); });
app.post('/resource/like', async (c) => { const t=c.req.header('Authorization')?.split(' ')[1]; const u=await verifyToken(t,c.env.JWT_SECRET); if(!u) return c.json({error:'未登录'},401); if(await checkMute(c.env,u.id)) return c.json({error:'禁言中'},403); const {resourceId}=await c.req.json(); const ex=await c.env.DB.prepare('SELECT 1 FROM likes WHERE user_id=? AND resource_id=?').bind(u.id,resourceId).first(); if(ex) await c.env.DB.prepare('DELETE FROM likes WHERE user_id=? AND resource_id=?').bind(u.id,resourceId).run(); else await c.env.DB.prepare('INSERT INTO likes(user_id,resource_id) VALUES(?,?)').bind(u.id,resourceId).run(); return c.json({success:true}); });
app.post('/user/message/send', async (c) => { const t=c.req.header('Authorization')?.split(' ')[1]; const u=await verifyToken(t,c.env.JWT_SECRET); if(!u) return c.json({error:'未登录'},401); if(await checkMute(c.env,u.id)) return c.json({error:'禁言中'},403); const {content}=await c.req.json(); await c.env.DB.prepare('INSERT INTO messages(user_id,sender,content) VALUES(?,"user",?)').bind(u.id,content).run(); return c.json({success:true}); });
app.get('/user/messages', async (c) => { const t=c.req.header('Authorization')?.split(' ')[1]; const u=await verifyToken(t,c.env.JWT_SECRET); if(!u) return c.json({error:'未登录'},401); const r=await c.env.DB.prepare('SELECT * FROM messages WHERE user_id=? ORDER BY id ASC').bind(u.id).all(); return c.json(r.results); });

// === 管理员 API ===

// 【核心修复】管理员文章列表 (支持分页)
app.get('/admin/resources', async (c) => {
    const t = c.req.header('Authorization')?.split(' ')[1]; const u = await verifyToken(t, c.env.JWT_SECRET); if(!u||u.role!=='admin') return c.json({error:'无权'},403);
    const q = c.req.query('q');
    const catId = c.req.query('catId');
    const tagId = c.req.query('tagId');
    const page = parseInt(c.req.query('page') || '1'); // 增加页码
    const pageSize = 50; // 管理员每页50条
    const offset = (page - 1) * pageSize;

    let sql = 'SELECT DISTINCT r.* FROM resources r LEFT JOIN resource_tags rt ON r.id = rt.resource_id LEFT JOIN tags t ON rt.tag_id = t.id';
    let p = []; let k = [];
    if(q){k.push("(r.title LIKE ? OR t.name LIKE ?)");p.push(`%${q}%`, `%${q}%`);}
    if(catId){k.push("r.category_id=?");p.push(catId);}
    if(tagId){k.push("rt.tag_id=?");p.push(tagId);}
    if(k.length>0) sql+=' WHERE '+k.join(' AND ');
    
    // 增加分页
    sql += ' ORDER BY r.id DESC LIMIT ? OFFSET ?';
    p.push(pageSize, offset);

    const r = await c.env.DB.prepare(sql).bind(...p).all();
    return c.json(r.results);
});

// 其他管理员 API (保持不变)
app.get('/admin/tag-keywords', async (c) => { const t=c.req.header('Authorization')?.split(' ')[1]; const u=await verifyToken(t,c.env.JWT_SECRET); if(!u||u.role!=='admin') return c.json({error:'无权'},403); const r=await c.env.DB.prepare('SELECT * FROM tag_keywords ORDER BY id DESC').all(); return c.json(r.results); });
app.post('/admin/tag-keywords', async (c) => { const t=c.req.header('Authorization')?.split(' ')[1]; const u=await verifyToken(t,c.env.JWT_SECRET); if(!u||u.role!=='admin') return c.json({error:'无权'},403); const {action,id,keyword,tagName,tagType}=await c.req.json(); if(action==='add') await c.env.DB.prepare('INSERT INTO tag_keywords(keyword,tag_name,tag_type) VALUES(?,?,?)').bind(keyword,tagName,tagType).run(); else if(action==='del') await c.env.DB.prepare('DELETE FROM tag_keywords WHERE id=?').bind(id).run(); return c.json({success:true}); });
app.get('/admin/tags/all', async (c) => { const t=c.req.header('Authorization')?.split(' ')[1]; const u=await verifyToken(t,c.env.JWT_SECRET); if(!u||u.role!=='admin') return c.json({error:'无权'},403); const r=await c.env.DB.prepare(`SELECT t.*, (SELECT COUNT(*) FROM resource_tags WHERE tag_id = t.id) as post_count FROM tags t ORDER BY post_count DESC`).all(); return c.json(r.results); });
app.post('/admin/tag/update', async (c) => { const t=c.req.header('Authorization')?.split(' ')[1]; const u=await verifyToken(t,c.env.JWT_SECRET); if(!u||u.role!=='admin') return c.json({error:'无权'},403); const {id,name,type,image_url}=await c.req.json(); try{await c.env.DB.prepare('UPDATE tags SET name=?, type=?, image_url=? WHERE id=?').bind(name,type,image_url,id).run(); return c.json({success:true});}catch(e){return c.json({error:'失败'},400);} });
app.post('/admin/resource', async (c) => { const t=c.req.header('Authorization')?.split(' ')[1]; const u=await verifyToken(t,c.env.JWT_SECRET); if(!u||u.role!=='admin') return c.json({error:'无权'},403); const {id,title,category_id,blocks,manualDate,tags}=await c.req.json(); const hasLink=blocks.some(b=>b.type==='link'&&b.value&&b.value.trim()!==''); if(!hasLink) return c.json({error:'需有效链接'},400); let dateStr=manualDate||parseDateFromTitle(title)||"日期不详"; let resourceId=id; if(id){await c.env.DB.prepare('UPDATE resources SET title=?, category_id=?, content_json=?, custom_date=? WHERE id=?').bind(title,category_id,JSON.stringify(blocks),dateStr,id).run(); await c.env.DB.prepare('DELETE FROM resource_tags WHERE resource_id=?').bind(id).run();}else{const r=await c.env.DB.prepare('INSERT INTO resources(title,category_id,content_json,custom_date) VALUES(?,?,?,?) RETURNING id').bind(title,category_id,JSON.stringify(blocks),dateStr).first(); resourceId=r.id;} const rules=await c.env.DB.prepare('SELECT * FROM tag_keywords').all(); const fullText=title+blocks.filter(b=>b.type==='text').map(b=>b.value).join(' '); let finalTags=[...(tags||[])]; for(const r of rules.results){if(fullText.includes(r.keyword)){if(!finalTags.find(ft=>ft.name===r.tag_name&&ft.type===r.tag_type))finalTags.push({name:r.tag_name,type:r.tag_type});}} if(finalTags.length>0){for(const tag of finalTags){if(!tag.name)continue; let ex=await c.env.DB.prepare('SELECT id,image_url FROM tags WHERE name=? AND type=?').bind(tag.name,tag.type).first(); let tid; if(ex){tid=ex.id; if(tag.image_url) await c.env.DB.prepare('UPDATE tags SET image_url=? WHERE id=?').bind(tag.image_url,tid).run();}else{const n=await c.env.DB.prepare('INSERT INTO tags(name,type,image_url) VALUES(?,?,?) RETURNING id').bind(tag.name,tag.type,tag.image_url||'').first(); tid=n.id;} await c.env.DB.prepare('INSERT OR IGNORE INTO resource_tags(resource_id,tag_id) VALUES(?,?)').bind(resourceId,tid).run();}} return c.json({success:true}); });
app.post('/admin/resource/delete', async (c) => { const t=c.req.header('Authorization')?.split(' ')[1]; const u=await verifyToken(t,c.env.JWT_SECRET); if(!u||u.role!=='admin') return c.json({error:'无权'},403); const {id}=await c.req.json(); await c.env.DB.prepare('DELETE FROM resource_tags WHERE resource_id=?').bind(id).run(); await c.env.DB.prepare('DELETE FROM resources WHERE id=?').bind(id).run(); await c.env.DB.prepare('DELETE FROM tags WHERE id NOT IN (SELECT DISTINCT tag_id FROM resource_tags)').run(); return c.json({success:true}); });
app.get('/admin/resource/:id', async (c) => { const t=c.req.header('Authorization')?.split(' ')[1]; const u=await verifyToken(t,c.env.JWT_SECRET); if(!u||u.role!=='admin') return c.json({error:'无权'},403); const r=await c.env.DB.prepare('SELECT * FROM resources WHERE id=?').bind(c.req.param('id')).first(); const tags=await c.env.DB.prepare('SELECT t.name, t.type, t.image_url FROM resource_tags rt JOIN tags t ON rt.tag_id=t.id WHERE rt.resource_id=?').bind(r.id).all(); return c.json({...r, blocks:JSON.parse(r.content_json), tags:tags.results}); });
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
