import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import crypto from 'crypto';
import { Resend } from 'resend';

const app = express();
const PORT = process.env.PORT || 3000;
const LOGO_URL = process.env.LOGO_URL || 'https://lamsathub.com/lamsat.jpg';
const RESEND_API_KEY = process.env.RESEND_API_KEY || '';
const EMAIL_FROM = process.env.EMAIL_FROM || 'Lamsat Hub <onboarding@resend.dev>';
const TURNSTILE_SECRET_KEY = process.env.TURNSTILE_SECRET_KEY || '';
const TOKEN_SECRET = process.env.TOKEN_SECRET || RESEND_API_KEY || 'change-this-token-secret';

const JSONBIN_ID = process.env.JSONBIN_ID || '';
const JSONBIN_KEY = process.env.JSONBIN_KEY || '';
const JSONBIN_URL = JSONBIN_ID ? `https://api.jsonbin.io/v3/b/${JSONBIN_ID}` : '';

const OTP_EXPIRY_MINUTES = Number(process.env.OTP_EXPIRY_MINUTES || 10);
const OTP_MAX_ATTEMPTS = Number(process.env.OTP_MAX_ATTEMPTS || 5);
const OTP_RESEND_SECONDS = Number(process.env.OTP_RESEND_SECONDS || 60);
const VERIFY_TOKEN_MINUTES = Number(process.env.VERIFY_TOKEN_MINUTES || 60);

const allowedOrigins = (process.env.ALLOWED_ORIGIN || '')
  .split(',')
  .map(origin => origin.trim())
  .filter(Boolean);

const resend = RESEND_API_KEY ? new Resend(RESEND_API_KEY) : null;

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '250kb' }));
app.use(cors({
  origin(origin, callback) {
    if (!origin) return callback(null, true);
    if (!allowedOrigins.length || allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error(`Not allowed by CORS: ${origin}`));
  }
}));

const otpStore = new Map();
const sendRateStore = new Map();

function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function makeCode() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

function hashCode(email, code) {
  return crypto
    .createHash('sha256')
    .update(`${email}:${code}:${TOKEN_SECRET}`)
    .digest('hex');
}

function clientIp(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown';
}

function b64url(input) {
  return Buffer.from(input).toString('base64url');
}

function signToken(payload) {
  const body = b64url(JSON.stringify(payload));
  const sig = crypto.createHmac('sha256', TOKEN_SECRET).update(body).digest('base64url');
  return `${body}.${sig}`;
}

function verifyToken(token) {
  try {
    const [body, sig] = String(token || '').split('.');
    if (!body || !sig) return null;
    const expected = crypto.createHmac('sha256', TOKEN_SECRET).update(body).digest('base64url');
    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (!payload.email || Date.now() > Number(payload.exp || 0)) return null;
    return payload;
  } catch {
    return null;
  }
}

async function verifyTurnstile(token, ip) {
  if (!TURNSTILE_SECRET_KEY) {
    return { success: false, error: 'TURNSTILE_SECRET_KEY is missing' };
  }
  if (!token) {
    return { success: false, error: 'Missing Turnstile token' };
  }

  const formData = new URLSearchParams();
  formData.append('secret', TURNSTILE_SECRET_KEY);
  formData.append('response', token);
  formData.append('remoteip', ip);

  const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
    method: 'POST',
    body: formData
  });

  return response.json();
}

function canSendOtp(email, ip) {
  const now = Date.now();
  const key = `${email}:${ip}`;
  const last = sendRateStore.get(key) || 0;
  const waitMs = OTP_RESEND_SECONDS * 1000 - (now - last);

  if (waitMs > 0) {
    return { ok: false, waitSeconds: Math.ceil(waitMs / 1000) };
  }

  sendRateStore.set(key, now);
  return { ok: true };
}


function escapeHtml(value) {
  return String(value || '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

function buildOtpEmailText({ code, minutes }) {
  return [
    `كود التحقق الخاص بك من Lamsat Hub Gifts هو: ${code}`,
    `الكود صالح لمدة ${minutes} دقائق.`,
    'إذا لم تطلبي هذا الكود، يمكنك تجاهل هذه الرسالة.',
    'لا تشاركي الكود مع أي شخص حفاظاً على أمان طلبك.'
  ].join('\n');
}

function buildOtpEmailHtml({ code, minutes, logoUrl }) {
  const safeCode = escapeHtml(code);
  const safeLogoUrl = escapeHtml(logoUrl);
  const previewText = `كود التحقق الخاص بك هو ${safeCode} — صالح لمدة ${minutes} دقائق`;

  return `
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>كود التحقق من Lamsat Hub Gifts</title>
</head>

<body style="margin:0;padding:0;background:#fff7f0;font-family:Arial,Tahoma,sans-serif;direction:rtl;text-align:right;">
  <div style="display:none;max-height:0;overflow:hidden;opacity:0;color:transparent;font-size:1px;line-height:1px;">
    ${previewText}
  </div>

  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#fff7f0;padding:30px 12px;">
    <tr>
      <td align="center">

        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:560px;background:#ffffff;border-radius:24px;overflow:hidden;border:1px solid #f0e0de;box-shadow:0 18px 50px rgba(127,36,31,0.13);">

          <tr>
            <td style="background:linear-gradient(135deg,#7f241f,#b83a32);padding:30px 24px;text-align:center;">
              <img
                src="${safeLogoUrl}"
                alt="Lamsat Hub Gifts"
                width="102"
                height="102"
                style="width:102px;height:102px;border-radius:50%;object-fit:cover;border:4px solid rgba(255,255,255,0.58);display:block;margin:0 auto 14px;background:#fff7f0;"
              />

              <div style="font-size:24px;font-weight:900;color:#ffffff;letter-spacing:1px;line-height:1.35;">
                LAMSAT HUB GIFTS
              </div>

              <div style="font-size:14px;color:#ffd6cc;margin-top:6px;font-weight:700;">
                by Maria
              </div>
            </td>
          </tr>

          <tr>
            <td style="padding:34px 30px 10px;text-align:center;">
              <div style="font-size:42px;margin-bottom:10px;">💌</div>

              <h1 style="margin:0;color:#2b1d1a;font-size:25px;font-weight:900;line-height:1.45;">
                كود التحقق الخاص بك
              </h1>

              <p style="margin:12px 0 0;color:#8b7770;font-size:14px;line-height:1.9;font-weight:600;">
                استخدمي الكود التالي لإتمام الطلب أو لتتبع طلبك في متجر
                <strong style="color:#8f2924;">Lamsat Hub Gifts</strong>
              </p>
            </td>
          </tr>

          <tr>
            <td style="padding:22px 30px;text-align:center;">
              <div style="
                display:inline-block;
                background:#fff0ee;
                color:#8f2924;
                border:2px dashed #d85a50;
                border-radius:20px;
                padding:18px 30px;
                font-size:38px;
                font-weight:900;
                letter-spacing:9px;
                direction:ltr;
                text-align:center;
                box-shadow:0 8px 22px rgba(184,58,50,0.12);
              ">
                ${safeCode}
              </div>
            </td>
          </tr>

          <tr>
            <td style="padding:0 30px 26px;text-align:center;">
              <p style="margin:0;color:#6b4a43;font-size:14px;font-weight:800;line-height:1.8;">
                الكود صالح لمدة
                <strong style="color:#b83a32;">${minutes} دقائق</strong>
              </p>
            </td>
          </tr>

          <tr>
            <td style="padding:0 30px 30px;">
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#fdf8f6;border:1px solid #f0e0de;border-radius:18px;">
                <tr>
                  <td style="padding:17px 18px;">
                    <p style="margin:0;color:#8b7770;font-size:13px;line-height:1.9;font-weight:700;">
                      🔒 إذا لم تطلبي هذا الكود، يمكنك تجاهل هذه الرسالة.
                      لا تشاركي الكود مع أي شخص حفاظاً على أمان طلبك.
                    </p>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <tr>
            <td style="background:#2b1d1a;padding:20px;text-align:center;">
              <p style="margin:0;color:rgba(255,255,255,0.74);font-size:12px;line-height:1.8;">
                © 2026 Lamsat Hub Gifts — جميع الحقوق محفوظة 💝
              </p>

              <p style="margin:7px 0 0;color:rgba(255,255,255,0.42);font-size:11px;">
                lamsathub.com
              </p>
            </td>
          </tr>

        </table>

      </td>
    </tr>
  </table>
</body>
</html>
  `;
}


function jsonBinHeaders(write = false, master = false) {
  const headers = { 'X-Bin-Meta': 'false', 'Cache-Control': 'no-cache' };
  if (write) headers['Content-Type'] = 'application/json';
  headers[master ? 'X-Master-Key' : 'X-Access-Key'] = JSONBIN_KEY;
  return headers;
}

function normalizeStore(raw) {
  const record = raw?.record || raw || {};
  return {
    products: Array.isArray(record.products) ? record.products : [],
    orders: Array.isArray(record.orders) ? record.orders : [],
    testimonials: Array.isArray(record.testimonials) ? record.testimonials : [],
    settings: record.settings || {}
  };
}

async function readStore() {
  if (!JSONBIN_URL || !JSONBIN_KEY) {
    throw new Error('JSONBIN_ID or JSONBIN_KEY is missing');
  }
  const res = await fetch(`${JSONBIN_URL}/latest?ts=${Date.now()}`, {
    method: 'GET',
    cache: 'no-store',
    headers: jsonBinHeaders(false, false)
  });
  if (!res.ok) throw new Error(`JSONBin read failed: ${res.status} ${await res.text().catch(() => '')}`);
  return normalizeStore(await res.json());
}

async function writeStore(data) {
  const payload = {
    products: Array.isArray(data.products) ? data.products : [],
    orders: Array.isArray(data.orders) ? data.orders : [],
    testimonials: Array.isArray(data.testimonials) ? data.testimonials : [],
    settings: data.settings || {}
  };

  async function put(master) {
    return fetch(JSONBIN_URL, {
      method: 'PUT',
      cache: 'no-store',
      headers: jsonBinHeaders(true, master),
      body: JSON.stringify(payload)
    });
  }

  let res = await put(false);
  if (!res.ok && (res.status === 401 || res.status === 403)) res = await put(true);
  if (!res.ok) throw new Error(`JSONBin write failed: ${res.status} ${await res.text().catch(() => '')}`);
  return payload;
}

function statusText(status) {
  const map = {
    new: 'طلب جديد',
    processing: 'قيد المعالجة',
    shipped: 'تم الإرسال',
    done: 'مكتمل',
    cancel: 'ملغى'
  };
  return map[status || 'new'] || 'طلب جديد';
}

function publicOrder(order) {
  return {
    id: order.id,
    code: order.code || String(order.id || '').slice(-6),
    createdAt: order.createdAt,
    updatedAt: order.updatedAt,
    status: order.status || 'new',
    statusText: statusText(order.status || 'new'),
    adminNote: order.adminNote || '',
    paymentMethod: order.paymentMethod || 'cash',
    paymentText: 'الدفع نقداً عند الاستلام',
    total: Number(order.total || 0),
    subtotal: Number(order.subtotal || 0),
    giftWrapTotal: Number(order.giftWrapTotal || order.gift?.giftWrapTotal || 0),
    shippingTotal: Number(order.shippingTotal || 0),
    customer: {
      name: order.customer?.name || order.name || '',
      email: order.customer?.email || order.email || '',
      phone: order.customer?.phone || order.phone || '',
      city: order.customer?.city || order.city || '',
      address: order.customer?.address || order.address || ''
    },
    items: (order.items || []).map(item => ({
      id: item.id,
      name: item.name,
      qty: item.qty || 1,
      price: Number(item.price || 0),
      giftWrap: Boolean(item.giftWrap),
      giftNote: item.giftNote || ''
    })),
    statusHistory: Array.isArray(order.statusHistory) ? order.statusHistory : []
  };
}

app.get('/health', (req, res) => {
  res.json({
    ok: true,
    service: 'lamsat-email-otp-turnstile-backend',
    resendConfigured: Boolean(RESEND_API_KEY),
    jsonbinConfigured: Boolean(JSONBIN_ID && JSONBIN_KEY)
  });
});

app.post('/send-email-otp', async (req, res) => {
  try {
    if (!resend) {
      return res.status(500).json({ ok: false, message: 'RESEND_API_KEY غير موجود في Render' });
    }

    const email = normalizeEmail(req.body.email);
    const turnstileToken = req.body.turnstileToken;
    const ip = clientIp(req);

    if (!isValidEmail(email)) {
      return res.status(400).json({ ok: false, message: 'البريد الإلكتروني غير صحيح' });
    }

    const turnstile = await verifyTurnstile(turnstileToken, ip);
    if (!turnstile.success) {
      return res.status(403).json({ ok: false, message: 'فشل التحقق من أنك لست روبوت' });
    }

    const rate = canSendOtp(email, ip);
    if (!rate.ok) {
      return res.status(429).json({
        ok: false,
        message: `انتظر ${rate.waitSeconds} ثانية قبل إرسال كود جديد`,
        waitSeconds: rate.waitSeconds
      });
    }

    const code = makeCode();
    otpStore.set(email, {
      codeHash: hashCode(email, code),
      expiresAt: Date.now() + OTP_EXPIRY_MINUTES * 60 * 1000,
      attempts: 0
    });

await resend.emails.send({
      from: EMAIL_FROM,
      to: email,
      subject: 'كود التحقق الخاص بك من Lamsat Hub Gifts 💝',
      text: buildOtpEmailText({
        code,
        minutes: OTP_EXPIRY_MINUTES
      }),
      html: buildOtpEmailHtml({
        code,
        minutes: OTP_EXPIRY_MINUTES,
        logoUrl: LOGO_URL
      })
    });

    return res.json({ ok: true, message: 'تم إرسال كود التحقق إلى البريد الإلكتروني' });
  } catch (error) {
    console.error('send-email-otp error:', error);
    return res.status(500).json({ ok: false, message: error?.message || 'حدث خطأ أثناء إرسال الكود' });
  }
});

app.post('/verify-email-otp', async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const code = String(req.body.code || '').trim();

    if (!isValidEmail(email)) {
      return res.status(400).json({ ok: false, message: 'البريد الإلكتروني غير صحيح' });
    }
    if (!/^\d{6}$/.test(code)) {
      return res.status(400).json({ ok: false, message: 'كود التحقق يجب أن يكون 6 أرقام' });
    }

    const saved = otpStore.get(email);
    if (!saved) return res.status(400).json({ ok: false, message: 'لا يوجد كود فعال لهذا البريد' });
    if (Date.now() > saved.expiresAt) {
      otpStore.delete(email);
      return res.status(400).json({ ok: false, message: 'انتهت صلاحية الكود، أرسلي كود جديد' });
    }
    if (saved.attempts >= OTP_MAX_ATTEMPTS) {
      otpStore.delete(email);
      return res.status(429).json({ ok: false, message: 'تم تجاوز عدد المحاولات، أرسلي كود جديد' });
    }

    saved.attempts += 1;
    if (saved.codeHash !== hashCode(email, code)) {
      return res.status(400).json({ ok: false, message: 'كود التحقق غير صحيح' });
    }

    otpStore.delete(email);
    const verificationToken = signToken({
      email,
      exp: Date.now() + VERIFY_TOKEN_MINUTES * 60 * 1000
    });

    return res.json({ ok: true, message: 'تم تأكيد البريد الإلكتروني بنجاح', email, verificationToken });
  } catch (error) {
    console.error('verify-email-otp error:', error);
    return res.status(500).json({ ok: false, message: 'حدث خطأ أثناء تأكيد الكود' });
  }
});

app.post('/create-order', async (req, res) => {
  try {
    const tokenData = verifyToken(req.body.verificationToken);
    if (!tokenData) return res.status(401).json({ ok: false, message: 'يجب تأكيد البريد الإلكتروني من جديد' });

    const body = req.body.order || {};
    const email = normalizeEmail(body.customer?.email || body.email);
    if (email !== tokenData.email) return res.status(403).json({ ok: false, message: 'البريد الإلكتروني لا يطابق التحقق' });

    if (!body.termsAccepted) return res.status(400).json({ ok: false, message: 'يجب الموافقة على شروط الطلب' });
    if (!Array.isArray(body.items) || !body.items.length) return res.status(400).json({ ok: false, message: 'السلة فارغة' });

    const now = new Date().toISOString();
    const id = Date.now();
    const order = {
      ...body,
      id,
      code: String(id).slice(-6),
      createdAt: now,
      updatedAt: now,
      status: 'new',
      adminNote: '',
      paymentMethod: 'cash',
      paymentText: 'الدفع نقداً عند الاستلام',
      customer: {
        name: String(body.customer?.name || '').trim(),
        phone: String(body.customer?.phone || '').trim(),
        email,
        city: String(body.customer?.city || '').trim(),
        address: String(body.customer?.address || '').trim(),
        notes: String(body.customer?.notes || '').trim()
      },
      statusHistory: [
        { status: 'new', at: now, note: 'تم استلام الطلب وينتظر المراجعة' }
      ]
    };

    const store = await readStore();
    store.orders = [order, ...(store.orders || [])];
    await writeStore(store);

    return res.json({ ok: true, message: 'تم إنشاء الطلب بنجاح', order: publicOrder(order) });
  } catch (error) {
    console.error('create-order error:', error);
    return res.status(500).json({ ok: false, message: error?.message || 'حدث خطأ أثناء حفظ الطلب' });
  }
});

app.post('/orders-by-email', async (req, res) => {
  try {
    const tokenData = verifyToken(req.body.verificationToken);
    if (!tokenData) return res.status(401).json({ ok: false, message: 'يجب تأكيد البريد الإلكتروني من جديد' });

    const requestedEmail = normalizeEmail(req.body.email || tokenData.email);
    if (requestedEmail !== tokenData.email) return res.status(403).json({ ok: false, message: 'البريد الإلكتروني لا يطابق التحقق' });

    const orderCode = String(req.body.orderCode || '').trim();
    const store = await readStore();
    let orders = (store.orders || []).filter(order => {
      const orderEmail = normalizeEmail(order.customer?.email || order.email);
      return orderEmail === tokenData.email;
    });

    if (orderCode) {
      orders = orders.filter(order => {
        const code = String(order.code || order.id || '').slice(-6);
        return code === orderCode || String(order.id) === orderCode;
      });
    }

    orders.sort((a, b) => Number(b.id || 0) - Number(a.id || 0));
    return res.json({ ok: true, orders: orders.map(publicOrder) });
  } catch (error) {
    console.error('orders-by-email error:', error);
    return res.status(500).json({ ok: false, message: error?.message || 'حدث خطأ أثناء جلب الطلبات' });
  }
});

app.listen(PORT, () => {
  console.log(`Lamsat Email OTP backend running on port ${PORT}`);
});
