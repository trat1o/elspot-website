// Reāla nozares statistika no Latvijas Oficiālās statistikas portāla (data.stat.gov.lv).
// Tabula BUP020c — būvniecības produkcijas apjoms, NACE F432
// ("Elektroinstalācijas ierīkošanas, cauruļvadu uzstādīšanas un citas līdzīgas darbības").
// Rezultāts tiek kešots CDN līmenī, lai nenoslogotu avotu.

const SOURCE = 'https://data.stat.gov.lv/api/v1/lv/OSP_PUB/START/NOZ/BU/BUP/BUP020c/';

module.exports = async (req, res) => {
  try {
    const r = await fetch(SOURCE, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        query: [
          { code: 'NACE', selection: { filter: 'item', values: ['F432'] } },
          { code: 'ContentsCode', selection: { filter: 'item', values: ['BUP020c'] } },
          { code: 'TIME', selection: { filter: 'top', values: ['8'] } },
        ],
        response: { format: 'json-stat2' },
      }),
    });

    if (!r.ok) throw new Error(`Avota kļūda ${r.status}`);
    const j = await r.json();

    const periods = Object.keys(j.dimension.TIME.category.label);
    const values = j.value;
    if (!periods.length || !values.length) throw new Error('Tukši dati');

    const last = values.length - 1;
    const latest = values[last];
    const period = periods[last];

    // Salīdzinām ar to pašu ceturksni gadu iepriekš (4 ceturkšņi atpakaļ)
    const prevIdx = last - 4;
    const prev = prevIdx >= 0 ? values[prevIdx] : null;
    const changePct = prev ? ((latest - prev) / prev) * 100 : 0;

    // Kešojam stundu; statistika atjaunojas reizi ceturksnī
    res.setHeader('Cache-Control', 's-maxage=3600, stale-while-revalidate=86400');
    return res.status(200).json({
      period,                              // piem. "2026Q1"
      valueMEur: latest / 1000,            // tūkst. EUR -> milj. EUR
      changePct,
      nace: 'F432',
      table: 'BUP020c',
    });
  } catch (err) {
    return res.status(502).json({ error: err.message || 'Neizdevās ielādēt statistiku' });
  }
};
