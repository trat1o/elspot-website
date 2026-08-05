// ELSPOT — satura saglabāšana GitHub repozitorijā.
// Vides mainīgie (iestatāmi Vercel panelī, NEKAD kodā):
//   ADMIN_PASSWORD  — redaktora parole
//   GITHUB_TOKEN    — GitHub piekļuves talons ar tiesībām uz repozitoriju
//   GITHUB_REPO     — piem. trat1o/elspot-website
//   GITHUB_BRANCH   — neobligāti, pēc noklusējuma "main"

const GH = 'https://api.github.com';

function ghHeaders(token) {
  return {
    'Authorization': `Bearer ${token}`,
    'Accept': 'application/vnd.github+json',
    'Content-Type': 'application/json',
    'User-Agent': 'elspot-editor',
  };
}

async function getSha(repo, path, branch, token) {
  const r = await fetch(`${GH}/repos/${repo}/contents/${encodeURIComponent(path)}?ref=${branch}`, {
    headers: ghHeaders(token),
  });
  if (r.status === 404) return null;
  if (!r.ok) throw new Error(`GitHub kļūda (${r.status}) nolasot ${path}`);
  const j = await r.json();
  return j.sha;
}

async function putFile(repo, path, base64, message, branch, token) {
  const sha = await getSha(repo, path, branch, token);
  const body = { message, content: base64, branch };
  if (sha) body.sha = sha;
  const r = await fetch(`${GH}/repos/${repo}/contents/${encodeURIComponent(path)}`, {
    method: 'PUT',
    headers: ghHeaders(token),
    body: JSON.stringify(body),
  });
  if (!r.ok) {
    const t = await r.text();
    throw new Error(`GitHub kļūda (${r.status}) saglabājot ${path}: ${t.slice(0, 200)}`);
  }
}

module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Atļauts tikai POST' });
  }

  const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
  const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
  const GITHUB_REPO = process.env.GITHUB_REPO;
  const BRANCH = process.env.GITHUB_BRANCH || 'main';

  if (!ADMIN_PASSWORD || !GITHUB_TOKEN || !GITHUB_REPO) {
    return res.status(500).json({ error: 'Servera konfigurācija nav pabeigta (trūkst vides mainīgo)' });
  }

  let body = req.body;
  if (typeof body === 'string') {
    try { body = JSON.parse(body); } catch { return res.status(400).json({ error: 'Nederīgs pieprasījums' }); }
  }
  body = body || {};

  // Paroles pārbaude (pastāvīga laika salīdzinājums)
  const given = String(body.password || '');
  const ok = given.length === ADMIN_PASSWORD.length &&
    require('crypto').timingSafeEqual(Buffer.from(given), Buffer.from(ADMIN_PASSWORD));
  if (!ok) {
    return res.status(401).json({ error: 'Nepareiza parole' });
  }

  if (body.action === 'login') {
    return res.status(200).json({ ok: true });
  }

  const content = body.content;
  if (!content || typeof content !== 'object' || !content.lv || !content.en) {
    return res.status(400).json({ error: 'Trūkst satura datu' });
  }

  try {
    // 1) Bildes
    const images = Array.isArray(body.images) ? body.images : [];
    if (images.length > 20) return res.status(400).json({ error: 'Pārāk daudz bilžu vienā reizē' });

    for (const img of images) {
      const path = String(img.path || '');
      if (!/^images\/[A-Za-z0-9._-]+$/.test(path)) {
        return res.status(400).json({ error: `Nederīgs bildes ceļš: ${path}` });
      }
      const m = String(img.dataUrl || '').match(/^data:image\/[a-zA-Z+]+;base64,(.+)$/);
      if (!m) return res.status(400).json({ error: 'Nederīgs bildes formāts' });
      const b64 = m[1];
      if (b64.length > 6 * 1024 * 1024) return res.status(400).json({ error: 'Bilde par lielu' });
      await putFile(GITHUB_REPO, path, b64, `Redaktors: pievienota bilde ${path}`, BRANCH, GITHUB_TOKEN);
    }

    // 2) Saturs
    const json = JSON.stringify(content, null, 2);
    const b64 = Buffer.from(json, 'utf8').toString('base64');
    await putFile(GITHUB_REPO, 'content.json', b64, 'Redaktors: atjaunināts saturs', BRANCH, GITHUB_TOKEN);

    return res.status(200).json({ ok: true, images: images.length });
  } catch (err) {
    return res.status(500).json({ error: err.message || 'Neizdevās saglabāt' });
  }
};
