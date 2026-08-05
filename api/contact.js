// Kontaktformas pieteikumu sūtīšana caur uzņēmuma SMTP serveri.
//
// Vides mainīgie (Vercel -> Environment Variables):
//   SMTP_HOST   — piem. web2.sertex.eu
//   SMTP_PORT   — 587 (STARTTLS) vai 465 (SSL)
//   SMTP_USER   — pastkastes lietotājvārds, piem. sales@elspot.lv
//   SMTP_PASS   — pastkastes parole  (atzīmēt kā Sensitive)
//   MAIL_TO     — kur saņemt pieteikumus
//   MAIL_FROM   — no kā sūtīt; JĀBŪT tai pašai pastkastei, kas SMTP_USER,
//                 citādi SPF/DMARC vēstuli atzīmēs kā mēstuli
//   FORM_SECRET — neobligāts; paraksta formas talonu
//
// Spama aizsardzība (5 slāņi, bez ārējiem pakalpojumiem):
//   1) Slēptais lauks (honeypot) — roboti to aizpilda, cilvēki nē
//   2) Parakstīts talons — jāizsauc GET pirms POST
//   3) Minimālais aizpildīšanas laiks — roboti sūta uzreiz
//   4) Ātruma ierobežojums pēc IP adreses
//   5) Satura heiristika — pārāk daudz saišu, tipiskas mēstuļu frāzes

const nodemailer = require('nodemailer');
const crypto = require('crypto');

const SECRET = process.env.FORM_SECRET
  || process.env.ADMIN_PASSWORD
  || crypto.randomBytes(32).toString('hex');

const TOKEN_MIN_AGE_MS = 4 * 1000;            // ātrāk par 4 s = robots
const TOKEN_MAX_AGE_MS = 3 * 60 * 60 * 1000;  // talons derīgs 3 stundas
const RATE_MAX = 4;                           // pieteikumi no vienas IP
const RATE_WINDOW_MS = 60 * 60 * 1000;        // stundā

// Atmiņā glabāts skaitītājs — dzīvo, kamēr dzīvo servera instance,
// tāpēc tas ir papildu slānis, nevis vienīgā aizsardzība.
const hits = new Map();

function sign(ts) {
  return crypto.createHmac('sha256', SECRET).update(String(ts)).digest('hex').slice(0, 32);
}

function clientIp(req) {
  const fwd = req.headers['x-forwarded-for'];
  if (typeof fwd === 'string' && fwd.length) return fwd.split(',')[0].trim();
  return req.headers['x-real-ip'] || 'unknown';
}

function rateLimited(ip) {
  const now = Date.now();
  const rec = hits.get(ip) || [];
  const recent = rec.filter(t => now - t < RATE_WINDOW_MS);
  if (recent.length >= RATE_MAX) {
    hits.set(ip, recent);
    return true;
  }
  recent.push(now);
  hits.set(ip, recent);
  if (hits.size > 5000) hits.clear();
  return false;
}

const SPAM_PATTERNS = [
  /\b(seo|backlink|guest post|link building|casino|viagra|loan offer)\b/i,
  /\b(rank (your|higher)|increase traffic|buy now cheap)\b/i,
  /\[url=/i,
  /<a\s+href=/i,
];

function looksLikeSpam(name, message) {
  const links = (message.match(/https?:\/\//gi) || []).length;
  if (links > 2) return 'parak daudz saisu';
  const blob = name + '\n' + message;
  if (SPAM_PATTERNS.some(re => re.test(blob))) return 'mestulu paraugs';
  if (message.length > 40 && !/\s/.test(message)) return 'nederigs saturs';
  return null;
}

const esc = s => String(s || '')
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;');

module.exports = async (req, res) => {
  // --- Talona izsniegšana ---
  if (req.method === 'GET') {
    const ts = Date.now();
    res.setHeader('Cache-Control', 'no-store');
    return res.status(200).json({ ts, token: sign(ts) });
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Atļauts tikai POST' });
  }

  const { SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, MAIL_TO, MAIL_FROM } = process.env;
  if (!SMTP_HOST || !SMTP_USER || !SMTP_PASS || !MAIL_TO) {
    return res.status(500).json({ error: 'E-pasta konfigurācija nav pabeigta' });
  }

  let body = req.body;
  if (typeof body === 'string') {
    try { body = JSON.parse(body); } catch { return res.status(400).json({ error: 'Nederīgs pieprasījums' }); }
  }
  body = body || {};

  // --- 1. slānis: slēptais lauks ---
  // Klusi apstiprinām, lai robots neuzzinātu, ka tika noķerts.
  if (body.website) return res.status(200).json({ ok: true });

  // --- 2. un 3. slānis: parakstīts talons + aizpildīšanas laiks ---
  const ts = Number(body.ts);
  const token = String(body.token || '');
  if (!ts || !token || token !== sign(ts)) {
    return res.status(400).json({ error: 'Formas sesija nav derīga. Pārlādējiet lapu un mēģiniet vēlreiz.' });
  }
  const age = Date.now() - ts;
  if (age < TOKEN_MIN_AGE_MS) {
    return res.status(429).json({ error: 'Pārāk ātri. Lūdzu, mēģiniet vēlreiz pēc dažām sekundēm.' });
  }
  if (age > TOKEN_MAX_AGE_MS) {
    return res.status(400).json({ error: 'Formas sesija novecojusi. Pārlādējiet lapu.' });
  }

  // --- 4. slānis: ātruma ierobežojums ---
  if (rateLimited(clientIp(req))) {
    return res.status(429).json({ error: 'Pārāk daudz pieteikumu. Lūdzu, mēģiniet vēlāk vai rakstiet tieši uz e-pastu.' });
  }

  const name = String(body.name || '').trim().slice(0, 200);
  const email = String(body.email || '').trim().slice(0, 200);
  const phone = String(body.phone || '').trim().slice(0, 60);
  const message = String(body.message || '').trim().slice(0, 5000);

  if (!name || !email || !message) {
    return res.status(400).json({ error: 'Trūkst obligāto lauku' });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) {
    return res.status(400).json({ error: 'Nederīga e-pasta adrese' });
  }
  // Neļaujam ievietot papildu e-pasta galvenes
  if (/[\r\n]/.test(name + email + phone)) {
    return res.status(400).json({ error: 'Nederīgas rakstzīmes' });
  }

  // --- 5. slānis: satura heiristika ---
  const spam = looksLikeSpam(name, message);
  if (spam) {
    console.warn('Blokets ka mestule:', spam);
    return res.status(200).json({ ok: true });
  }

  const port = Number(SMTP_PORT) || 587;

  try {
    const transporter = nodemailer.createTransport({
      host: SMTP_HOST,
      port,
      secure: port === 465,          // 465 = tiešs SSL; 587 = STARTTLS
      requireTLS: port !== 465,
      auth: { user: SMTP_USER, pass: SMTP_PASS },
    });

    await transporter.sendMail({
      from: MAIL_FROM || SMTP_USER,   // vienmēr sava pastkaste, nevis apmeklētāja
      to: MAIL_TO,
      replyTo: name + ' <' + email + '>',
      subject: 'Pieteikums no mājaslapas — ' + name,
      text:
        'Jauns pieteikums no mājaslapas\n\n' +
        'Vārds / uzņēmums: ' + name + '\n' +
        'E-pasts: ' + email + '\n' +
        'Tālrunis: ' + (phone || '—') + '\n\n' +
        'Ziņa:\n' + message + '\n',
      html:
        '<h2 style="font-family:Arial,sans-serif;color:#161D42;">Jauns pieteikums no mājaslapas</h2>' +
        '<table style="font-family:Arial,sans-serif;font-size:14px;border-collapse:collapse;">' +
        '<tr><td style="padding:6px 14px 6px 0;color:#5B6178;">Vārds / uzņēmums</td><td><b>' + esc(name) + '</b></td></tr>' +
        '<tr><td style="padding:6px 14px 6px 0;color:#5B6178;">E-pasts</td><td><a href="mailto:' + esc(email) + '">' + esc(email) + '</a></td></tr>' +
        '<tr><td style="padding:6px 14px 6px 0;color:#5B6178;">Tālrunis</td><td>' + (esc(phone) || '—') + '</td></tr>' +
        '</table>' +
        '<p style="font-family:Arial,sans-serif;font-size:14px;color:#161D42;white-space:pre-wrap;margin-top:16px;">' + esc(message) + '</p>',
    });

    return res.status(200).json({ ok: true });
  } catch (err) {
    console.error('SMTP kluda:', err && err.message);
    return res.status(500).json({ error: 'Neizdevās nosūtīt vēstuli' });
  }
};
