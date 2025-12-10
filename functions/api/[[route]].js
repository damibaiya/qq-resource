import { Hono } from 'hono';
import { handle } from 'hono/cloudflare-pages';
import { SignJWT, jwtVerify } from 'jose';

const app = new Hono().basePath('/api');

// === 辅助函数 ===
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

// === Brevo API 发信函数 (无需 Node.js 模块) ===
async function sendEmailByBrevoAPI(env, toEmail, code) {
  const url = 'https://api.brevo.com/v3/smtp/email';
  const senderEmail = env.SENDER_EMAIL || env.SMTP_USER; // 发件人
  
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'accept': 'application/json',
      'api-key': env.BREVO_API_KEY, // 这里使用 API Key 而不是 SMTP 密码
      'content-type': 'application/json'
    },
    body: JSON.stringify({
      sender: { email: senderEmail, name: "ACG资源社" },
      to: [{ email: toEmail }],
      subject: "【ACG资源社】登录验证码",
      htmlContent: `
        <div style="padding: 20px; background: #fff0f5; border-radius: 10px; font-family: sans-serif; border: 1px solid #ffb6c1;">
          <h2 style="color: #ff69b4;">🌸 身份验证</h2>
          <p>您好！您的登录验证码是：</p>
          <div style="background: #fff; padding: 15px; border-radius: 8px; text-align: center; margin: 20px 0;">
              <span style="font-size: 28px; font-weight: bold; color: #ff1493; letter-spacing: 8px;">${code}</span>
          </div>
          <p style="font-size: 12px; color: #999;">(Brevo API 发送)</p>
        </div>
      `
    })
  });

  if (!response.ok) {
    const err = await response.text();
    throw new Error(`Brevo API Error: ${err}`);
  }
}

// 1. 发送验证码
app.post('/auth/send-code', async (c) => {
  try {
    const { email } = await c.req.json();
    
    // 管理员特例
    if (email === c.env.ADMIN_USER) return c.json({ message: '请输入管理员密码' });

    // === 核心限制：必须是 QQ 邮箱 ===
    const qqEmailRegex = /^[a-zA-Z0-9._-]+@qq\.com$/;
    if (!qqEmailRegex.test(email)) {
        return c.json({ error: '本站仅开放 QQ 邮箱注册，请使用 QQ 邮箱' }, 400);
    }
    
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = Date.now() + 5 * 60 * 1000;
    
    await c.env.DB.prepare('INSERT OR REPLACE INTO codes (email, code, expires_at) VALUES (?, ?, ?)').bind(email, code, expiresAt).run();
    
    // 使用 Brevo HTTP API 发送 (最稳)
    await sendEmailByBrevoAPI(c.env, email, code);
    
    return c.json({ message: '验证码已发送至您的 QQ 邮箱' });
  } catch (e) {
    return c.json({ error: '邮件发送失败: ' + e.message }, 500);
  }
});

// 2. 登录
app.post('/auth/login', async (c) => {
  try {
    const { email, code, isAdmin } = await c.req.json();

    if (isAdmin) {
      if (email === c.env.ADMIN_USER && code === c.env.ADMIN_PASSWD) {
        const token = await signToken({ id: 0, role: 'admin' }, c.env.JWT_SECRET);
        return c.json({ token, role: 'admin' });
      }
      return c.json({ error: '管理员认证失败' }, 400);
    }

    const record = await c.env.DB.prepare('SELECT * FROM codes WHERE email = ?').bind(email).first();
    if (!record || record.code !== code || Date.now() > record.expires_at) return c.json({ error: '验证码无效或已过期' }, 400);

    let user = await c.env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email).first();
    let isNewUser = false;
    if (!user) {
      user = await c.env.DB.prepare('INSERT INTO users (email) VALUES (?) RETURNING *').bind(email).first();
      isNewUser = true;
    }

    const token = await signToken({ id: user.id, role: 'user', email: user.email }, c.env.JWT_SECRET);
    return c.json({ token, role: 'user', email: user.email, isNew: isNewUser });
  } catch (e) {
    return c.json({ error: '登录失败: ' + e.message }, 500);
  }
});

// 3. 资源列表
app.get('/resources', async (c) => {
  const list = await c.env.DB.prepare('SELECT id, title, requires_login, view_limit, type, created_at FROM resources ORDER BY id DESC').all();
  return c.json(list.results || []);
});

// 4. 资源详情
app.get('/resource/:id', async (c) => {
  const id = c.req.param('id');
  const token = c.req.header('Authorization')?.split(' ')[1];
  let user = null;
  if (token) user = await verifyToken(token, c.env.JWT_SECRET);

  const resource = await c.env.DB.prepare('SELECT * FROM resources WHERE id = ?').bind(id).first();
  if (!resource) return c.json({ error: '资源不存在' }, 404);

  if (resource.requires_login === 1 && !user) return c.json({ error: '请登录后查看' }, 401);
  
  if (resource.view_limit > 0 && (!user || user.role !== 'admin')) {
    const view = await c.env.DB.prepare('SELECT count FROM views WHERE user_id = ? AND resource_id = ?').bind(user.id, id).first();
    if (view && view.count >= resource.view_limit) return c.json({ error: `次数已用尽` }, 403);
    
    if (!view) await c.env.DB.prepare('INSERT INTO views (user_id, resource_id, count) VALUES (?, ?, 1)').bind(user.id, id).run();
    else await c.env.DB.prepare('UPDATE views SET count = count + 1 WHERE user_id = ? AND resource_id = ?').bind(user.id, id).run();
  }

  return c.json({ content: resource.content, type: resource.type });
});

// 5. 发布
app.post('/admin/create', async (c) => {
  try {
    const token = c.req.header('Authorization')?.split(' ')[1];
    const user = await verifyToken(token, c.env.JWT_SECRET);
    if (!user || user.role !== 'admin') return c.json({ error: '无权操作' }, 403);

    const body = await c.req.parseBody();
    const title = body['title'];
    const requires_login = body['requires_login'] === 'true' ? 1 : 0;
    const view_limit = parseInt(body['view_limit'] || 0);
    const file = body['file'];
    const textContent = body['content'] || '';

    let finalContent = textContent;
    let type = 'text';

    if (file && typeof file === 'object' && file.name) {
        if (!c.env.BUCKET) throw new Error('R2未绑定');
        const fileName = `${Date.now()}-${file.name}`;
        await c.env.BUCKET.put(fileName, await file.arrayBuffer(), { httpMetadata: { contentType: file.type } });
        finalContent = `${c.env.R2_DOMAIN}/${fileName}`;
        type = 'image';
    }

    if (!finalContent) finalContent = '(空)';

    await c.env.DB.prepare(
      'INSERT INTO resources (title, content, requires_login, view_limit, type) VALUES (?, ?, ?, ?, ?)'
    ).bind(title, finalContent, requires_login, view_limit, type).run();

    return c.json({ success: true });
  } catch (e) {
    return c.json({ error: '发布失败: ' + e.message }, 500);
  }
});

export const onRequest = handle(app);
