import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import crypto from 'crypto';
import { Resend } from 'resend';
const app = express();
const PORT = process.env.PORT || 3000;

const RESEND_API_KEY = process.env.RESEND_API_KEY;
const EMAIL_FROM = process.env.EMAIL_FROM || 'Lamsat Hub <onboarding@resend.dev>';
const TURNSTILE_SECRET_KEY = process.env.TURNSTILE_SECRET_KEY;

const OTP_EXPIRY_MINUTES = Number(process.env.OTP_EXPIRY_MINUTES || 10);
const OTP_MAX_ATTEMPTS = Number(process.env.OTP_MAX_ATTEMPTS || 5);
const OTP_RESEND_SECONDS = Number(process.env.OTP_RESEND_SECONDS || 60);

const allowedOrigins = (process.env.ALLOWED_ORIGIN || '')
  .split(',')
  .map(origin => origin.trim())
  .filter(Boolean);

const resend = new Resend(RESEND_API_KEY);

app.use(helmet());
app.use(express.json({ limit: '30kb' }));
app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error('Not allowed by CORS'));
  }
}));

// In-memory storage is enough for starting/tests.
// For a serious store with many users, move this to Redis/DB.
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
    .update(`${email}:${code}:${process.env.RESEND_API_KEY || 'salt'}`)
    .digest('hex');
}

function clientIp(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown';
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

  const data = await response.json();
  return data;
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

app.get('/health', (req, res) => {
  res.json({ ok: true, service: 'lamsat-email-otp-turnstile-backend' });
});

app.post('/send-email-otp', async (req, res) => {
  try {
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
    const expiresAt = Date.now() + OTP_EXPIRY_MINUTES * 60 * 1000;

    otpStore.set(email, {
      codeHash: hashCode(email, code),
      expiresAt,
      attempts: 0
    });

    await resend.emails.send({
      from: EMAIL_FROM,
      to: email,
      subject: 'كود التحقق من Lamsat Hub',
      html: `
        <div style="font-family:Arial,sans-serif;direction:rtl;text-align:right;line-height:1.7">
          <h2>كود التحقق من Lamsat Hub</h2>
          <p>استخدمي الكود التالي لإتمام الطلب:</p>
          <div style="font-size:32px;font-weight:bold;letter-spacing:6px;background:#fff0ee;color:#8f2924;padding:16px;border-radius:12px;display:inline-block">${code}</div>
          <p>الكود صالح لمدة ${OTP_EXPIRY_MINUTES} دقائق.</p>
          <p style="color:#777;font-size:13px">إذا لم تطلبي هذا الكود، تجاهلي الرسالة.</p>
        </div>
      `
    });

    return res.json({ ok: true, message: 'تم إرسال كود التحقق إلى البريد الإلكتروني' });
  } catch (error) {
    console.error('send-email-otp error:', error);
    return res.status(500).json({ ok: false, message: 'حدث خطأ أثناء إرسال الكود' });
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

    if (!saved) {
      return res.status(400).json({ ok: false, message: 'لا يوجد كود فعال لهذا البريد' });
    }

    if (Date.now() > saved.expiresAt) {
      otpStore.delete(email);
      return res.status(400).json({ ok: false, message: 'انتهت صلاحية الكود، أرسلي كود جديد' });
    }

    if (saved.attempts >= OTP_MAX_ATTEMPTS) {
      otpStore.delete(email);
      return res.status(429).json({ ok: false, message: 'تم تجاوز عدد المحاولات، أرسلي كود جديد' });
    }

    saved.attempts += 1;

    const isCorrect = saved.codeHash === hashCode(email, code);

    if (!isCorrect) {
      return res.status(400).json({ ok: false, message: 'كود التحقق غير صحيح' });
    }

    otpStore.delete(email);

    return res.json({ ok: true, message: 'تم تأكيد البريد الإلكتروني بنجاح' });
  } catch (error) {
    console.error('verify-email-otp error:', error);
    return res.status(500).json({ ok: false, message: 'حدث خطأ أثناء تأكيد الكود' });
  }
});

app.listen(PORT, () => {
  console.log(`Lamsat Email OTP backend running on port ${PORT}`);
});
