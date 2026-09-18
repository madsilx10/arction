const https = require('https');
const crypto = require('crypto');
const fs = require('fs');
const readline = require('readline');

// ─── Config ─────────────────────────────────────────────────
const REF_URL       = 'https://arction.app/ref/E6DB3659';
const ACCOUNTS_FILE = 'akun.txt';

// ─── Prompt helper ──────────────────────────────────────────
function prompt(question) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise(resolve => rl.question(question, ans => { rl.close(); resolve(ans.trim()); }));
}

// ─── Cookie store (per domain) ──────────────────────────────
function parseCookies(setCookieHeaders) {
  const jar = {};
  for (const header of (setCookieHeaders || [])) {
    const [pair] = header.split(';');
    const idx = pair.indexOf('=');
    if (idx < 0) continue;
    const key = pair.slice(0, idx).trim();
    const val = pair.slice(idx + 1).trim();
    jar[key] = val;
  }
  return jar;
}

function mergeCookies(existing, incoming) {
  return { ...existing, ...incoming };
}

function serializeCookies(jar) {
  return Object.entries(jar).map(([k, v]) => `${k}=${v}`).join('; ');
}

// ─── HTTP helper ─────────────────────────────────────────────
function request({ method = 'GET', url, headers = {}, body = null, followRedirects = false, maxRedirects = 10 }) {
  return new Promise((resolve, reject) => {
    let redirectCount = 0;
    let allSetCookies = [];

    function doRequest(currentUrl, currentMethod, currentBody) {
      const u = new URL(currentUrl);
      const options = {
        hostname: u.hostname,
        path: u.pathname + u.search,
        method: currentMethod,
        headers,
      };
      const req = https.request(options, res => {
        // Kumpulkan semua set-cookie dari semua hop
        allSetCookies = allSetCookies.concat([].concat(res.headers['set-cookie'] || []));

        const isRedirect = [301, 302, 303, 307, 308].includes(res.statusCode);
        if (followRedirects && isRedirect && res.headers['location'] && redirectCount < maxRedirects) {
          redirectCount++;
          let nextUrl = res.headers['location'];
          // Resolve relative redirect
          if (nextUrl.startsWith('/')) {
            nextUrl = `${u.protocol}//${u.hostname}${nextUrl}`;
          }
          // 303 dan 301/302 pada non-GET → switch ke GET tanpa body
          const nextMethod = (res.statusCode === 303 || ([301, 302].includes(res.statusCode) && currentMethod !== 'GET'))
            ? 'GET' : currentMethod;
          const nextBody = nextMethod === 'GET' ? null : currentBody;
          // Update Cookie header dengan cookies baru dari hop ini
          const newCookies = parseCookies([].concat(res.headers['set-cookie'] || []));
          if (Object.keys(newCookies).length > 0) {
            const existing = {};
            for (const part of (headers['Cookie'] || '').split(';')) {
              const [k, ...v] = part.trim().split('=');
              if (k) existing[k.trim()] = v.join('=').trim();
            }
            const merged = { ...existing, ...newCookies };
            headers['Cookie'] = Object.entries(merged).map(([k, v]) => `${k}=${v}`).join('; ');
          }
          // Baca dan buang body response sebelum redirect
          res.resume();
          doRequest(nextUrl, nextMethod, nextBody);
        } else {
          let data = '';
          res.on('data', chunk => data += chunk);
          res.on('end', () => resolve({
            status: res.statusCode,
            headers: res.headers,
            setCookies: allSetCookies,
            data,
          }));
        }
      });
      req.on('error', reject);
      if (currentBody) req.write(currentBody);
      req.end();
    }

    doRequest(url, method, body);
  });
}

// ─── Per-account connect ─────────────────────────────────────
async function connectAccount(authToken, ct0, index) {
  // Cookie store per domain
  let arctionCookies = {};

  const baseHeaders = {
    'User-Agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36',
    'Accept-Language': 'id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7',
    'Sec-Ch-Ua': '"Mises";v="141", "Not?A_Brand";v="8", "Chromium";v="141"',
    'Sec-Ch-Ua-Mobile': '?1',
    'Sec-Ch-Ua-Platform': '"Android"',
  };

  // ── Step 0: Visit ref URL ────────────────────────────────────
  console.log(`[${index}] Step 0: Visit ref link...`);
  const refRes = await request({
    url: REF_URL,
    headers: { ...baseHeaders, 'Sec-Fetch-Dest': 'document', 'Sec-Fetch-Mode': 'navigate', 'Sec-Fetch-Site': 'none' },
  });
  arctionCookies = mergeCookies(arctionCookies, parseCookies(refRes.setCookies));

  // ── Step 1: GET arction login ────────────────────────────────
  console.log(`[${index}] Step 1: GET arction login...`);
  const loginRes = await request({
    url: 'https://arction.app/login?go=1&next=%2Fdashboard',
    headers: {
      ...baseHeaders,
      'Cookie': serializeCookies(arctionCookies),
      'Sec-Fetch-Dest': 'document', 'Sec-Fetch-Mode': 'navigate', 'Sec-Fetch-Site': 'none',
    },
  });
  arctionCookies = mergeCookies(arctionCookies, parseCookies(loginRes.setCookies));

  let xAuthUrl = loginRes.headers['location'];

  // Follow sekali lagi kalau masih relative
  if (xAuthUrl && !xAuthUrl.includes('twitter.com') && xAuthUrl.startsWith('/')) {
    const step1b = await request({
      url: `https://arction.app${xAuthUrl}`,
      headers: { ...baseHeaders, 'Cookie': serializeCookies(arctionCookies), 'Sec-Fetch-Site': 'same-origin' },
    });
    arctionCookies = mergeCookies(arctionCookies, parseCookies(step1b.setCookies));
    xAuthUrl = step1b.headers['location'];
  }

  if (!xAuthUrl || !xAuthUrl.includes('twitter.com')) {
    console.error(`[${index}] Gagal dapat X OAuth URL. Location:`, loginRes.headers['location']);
    return null;
  }

  const urlObj = new URL(xAuthUrl);
  console.log(`[${index}] State: ${urlObj.searchParams.get('state')}`);
  console.log(`[${index}] X Auth URL: ${xAuthUrl.slice(0, 80)}...`);

  // ── Step 2: GET Twitter authorize (JSON) ────────────────────
  console.log(`[${index}] Step 2: GET Twitter authorize (JSON)...`);
  const urlObj2 = new URL(xAuthUrl);
  const twitterAuthRes = await request({
    url: `https://x.com/i/api/2/oauth2/authorize?${urlObj2.searchParams.toString()}`,
    headers: {
      ...baseHeaders,
      'Authorization': 'Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I7BeIg1n0AH8%3DUkinIHmidszmwwXYFERnJpM3giqwFZszY0jokXT7uY',
      'Cookie': `auth_token=${authToken}; ct0=${ct0}`,
      'X-Csrf-Token': ct0,
      'Accept': 'application/json',
      'X-Twitter-Active-User': 'yes',
      'X-Twitter-Client-Language': 'en',
      'Sec-Fetch-Dest': 'empty', 'Sec-Fetch-Mode': 'cors', 'Sec-Fetch-Site': 'same-origin',
    },
  });

  if (twitterAuthRes.status !== 200) {
    console.error(`[${index}] Twitter authorize gagal: ${twitterAuthRes.status}`, twitterAuthRes.data);
    return null;
  }

  let twitterAuthJson;
  try { twitterAuthJson = JSON.parse(twitterAuthRes.data); } catch { twitterAuthJson = {}; }

  const authCode = twitterAuthJson.auth_code;
  if (!authCode) {
    console.error(`[${index}] Gagal dapat auth_code. Response:`, twitterAuthRes.data.slice(0, 500));
    return null;
  }
  console.log(`[${index}] Auth code: ${authCode.slice(0, 20)}...`);

  // ── Step 3: POST Twitter approve ────────────────────────────
  console.log(`[${index}] Step 3: POST Twitter approve...`);
  const postBody = new URLSearchParams({ approval: 'true', code: authCode, consent_flow: 'web_consent' }).toString();
  const approveRes = await request({
    method: 'POST',
    url: 'https://api.x.com/2/oauth2/authorize',
    headers: {
      ...baseHeaders,
      'Authorization': 'Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I7BeIg1n0AH8%3DUkinIHmidszmwwXYFERnJpM3giqwFZszY0jokXT7uY',
      'Cookie': `auth_token=${authToken}; ct0=${ct0}`,
      'Content-Type': 'application/x-www-form-urlencoded',
      'Content-Length': Buffer.byteLength(postBody),
      'X-Csrf-Token': ct0,
      'X-Twitter-Active-User': 'yes',
      'X-Twitter-Client-Language': 'en',
      'Origin': 'https://x.com',
      'Referer': 'https://x.com/',
      'Sec-Fetch-Dest': 'empty', 'Sec-Fetch-Mode': 'cors', 'Sec-Fetch-Site': 'same-site',
    },
    body: postBody,
  });

  if (approveRes.status !== 200) {
    console.error(`[${index}] Approve gagal: ${approveRes.status}`, approveRes.data);
    return null;
  }

  let approveData;
  try { approveData = JSON.parse(approveRes.data); } catch { approveData = {}; }
  console.log(`[${index}] Approve response:`, JSON.stringify(approveData).slice(0, 200));

  const callbackUrl = approveData.redirect_uri || approveData.redirectUri;
  if (!callbackUrl) {
    console.error(`[${index}] Tidak ada redirect_uri di approve response`);
    return null;
  }

  // ── Step 4: GET Arction callback ─────────────────────────────
  console.log(`[${index}] Step 4: GET Arction callback...`);
  const callbackRes = await request({
    url: callbackUrl,
    headers: {
      ...baseHeaders,
      'Cookie': serializeCookies(arctionCookies),
      'Sec-Fetch-Dest': 'document', 'Sec-Fetch-Mode': 'navigate', 'Sec-Fetch-Site': 'cross-site',
      'Referer': 'https://x.com/',
    },
  });
  arctionCookies = mergeCookies(arctionCookies, parseCookies(callbackRes.setCookies));

  const finalLocation = callbackRes.headers['location'];
  console.log(`[${index}] Callback status: ${callbackRes.status}, Location: ${finalLocation}`);

  if (callbackRes.status === 302 && finalLocation === '/dashboard') {
    const cnSession = arctionCookies['cn_session'];
    if (cnSession) {
      console.log(`[${index}] ✅ Berhasil! cn_session: ${cnSession.slice(0, 30)}...`);
      return { authToken, cn_session: cnSession };
    }
  }

  console.error(`[${index}] Callback gagal atau tidak redirect ke dashboard`);
  return null;
}


// ─── Main ────────────────────────────────────────────────────
async function main() {
  if (!fs.existsSync(ACCOUNTS_FILE)) {
    console.error(`File ${ACCOUNTS_FILE} tidak ditemukan!`);
    process.exit(1);
  }

  const lines = fs.readFileSync(ACCOUNTS_FILE, 'utf-8')
    .split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'));

  const accounts = [];
  for (let i = 0; i < lines.length; i += 2) {
    if (lines[i] && lines[i + 1]) accounts.push({ authToken: lines[i], ct0: lines[i + 1] });
  }

  console.log(`Total akun terbaca: ${accounts.length}`);
  console.log('\nPilih mode:');
  console.log('  1 → Jalankan 1 akun (pilih nomor)');
  console.log('  2 → Semua akun');
  console.log('  3 → Dari akun ke-X sampai akhir\n');

  const mode = await prompt('Mode [1/2/3]: ');
  let selected = [];

  if (mode === '1') {
    const n = parseInt(await prompt(`Nomor akun (1–${accounts.length}): `));
    if (isNaN(n) || n < 1 || n > accounts.length) { console.error('Nomor tidak valid.'); process.exit(1); }
    selected = [{ ...accounts[n - 1], displayIndex: n }];
  } else if (mode === '2') {
    selected = accounts.map((a, i) => ({ ...a, displayIndex: i + 1 }));
  } else if (mode === '3') {
    const from = parseInt(await prompt(`Mulai dari akun ke- (1–${accounts.length}): `));
    if (isNaN(from) || from < 1 || from > accounts.length) { console.error('Nomor tidak valid.'); process.exit(1); }
    selected = accounts.slice(from - 1).map((a, i) => ({ ...a, displayIndex: from + i }));
  } else {
    console.error('Pilihan tidak valid.'); process.exit(1);
  }

  console.log(`\nMenjalankan ${selected.length} akun...\n`);

  const results = [];
  for (let i = 0; i < selected.length; i++) {
    const { authToken, ct0, displayIndex } = selected[i];
    try {
      const res = await connectAccount(authToken.trim(), ct0.trim(), displayIndex);
      if (res) results.push(res);
    } catch (err) {
      console.error(`[${displayIndex}] Error:`, err.message);
    }
    if (i < selected.length - 1) await sleep(2000 + Math.random() * 1000);
  }

  console.log(`\n=== SELESAI: ${results.length}/${selected.length} akun berhasil connect ===`);
  fs.writeFileSync('arction_sessions.json', JSON.stringify(results, null, 2));
  console.log('Session disimpan ke arction_sessions.json');
}

const sleep = ms => new Promise(r => setTimeout(r, ms));
main().catch(console.error);
