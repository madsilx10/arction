const axios = require('axios');
const crypto = require('crypto');
const { CookieJar } = require('tough-cookie');
const { wrapper } = require('axios-cookiejar-support');
const fs = require('fs');

// ─── PKCE helpers ───────────────────────────────────────────
function generateCodeVerifier() {
  return crypto.randomBytes(32).toString('base64url');
}

function generateCodeChallenge(verifier) {
  return crypto.createHash('sha256').update(verifier).digest('base64url');
}

function generateState() {
  return crypto.randomBytes(20).toString('hex');
}

// ─── Config ─────────────────────────────────────────────────
const CLIENT_ID     = 'UmdmeFYtbVlsSkJIUjhVQWRWZXo6MTpjaQ';
const REDIRECT_URI  = 'https://arction.app/oauth/x_callback';
const SCOPE         = 'tweet.read users.read offline.access';
const REF_URL       = 'https://arction.app/ref/E6DB3659';

// Load accounts dari akun.txt
// Format: authtoken (baris ganjil), ct0 (baris genap), pisah antar akun boleh baris kosong
const ACCOUNTS_FILE = 'akun.txt';

// ─── Per-account connect ─────────────────────────────────────
async function connectAccount(authToken, ct0, index) {
  const jar = new CookieJar();
  const client = wrapper(axios.create({
    jar,
    withCredentials: true,
    maxRedirects: 0,       // handle redirect manual
    validateStatus: () => true,
  }));

  const baseHeaders = {
    'User-Agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36',
    'Accept-Language': 'id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7',
    'Sec-Ch-Ua': '"Mises";v="141", "Not?A_Brand";v="8", "Chromium";v="141"',
    'Sec-Ch-Ua-Mobile': '?1',
    'Sec-Ch-Ua-Platform': '"Android"',
  };

  // ── Step 0: Visit ref URL dulu biar cn_ref cookie ke-set ──────────────────
  console.log(`[${index}] Step 0: Visit ref link...`);
  await client.get(REF_URL, {
    headers: {
      ...baseHeaders,
      'Sec-Fetch-Dest': 'document',
      'Sec-Fetch-Mode': 'navigate',
      'Sec-Fetch-Site': 'none',
      'Upgrade-Insecure-Requests': '1',
    },
  });

  // ── Step 1: GET arction.app/login → dapat cn_ref cookie & redirect ke X ──
  console.log(`[${index}] Step 1: GET arction login...`);
  const loginRes = await client.get('https://arction.app/login?go=1&next=%2Fdashboard', {
    headers: {
      ...baseHeaders,
      'Sec-Fetch-Dest': 'document',
      'Sec-Fetch-Mode': 'navigate',
      'Sec-Fetch-Site': 'none',
      'Upgrade-Insecure-Requests': '1',
    },
  });

  // Arction redirect ke /login?go=1&next=/dashboard dulu (302)
  // lalu redirect ke twitter oauth — ambil Location dari header
  let xAuthUrl = loginRes.headers['location'];
  if (!xAuthUrl || !xAuthUrl.includes('twitter.com')) {
    // Mungkin butuh follow sekali lagi
    if (loginRes.headers['location']) {
      const step1b = await client.get(`https://arction.app${loginRes.headers['location']}`, {
        headers: { ...baseHeaders, 'Sec-Fetch-Site': 'same-origin' },
      });
      xAuthUrl = step1b.headers['location'];
    }
  }

  if (!xAuthUrl || !xAuthUrl.includes('twitter.com')) {
    console.error(`[${index}] Gagal dapat X OAuth URL. Location:`, loginRes.headers['location']);
    return null;
  }

  // Parse state & code_challenge dari URL arction (sudah di-generate server-side)
  const urlObj = new URL(xAuthUrl);
  const state          = urlObj.searchParams.get('state');
  const codeChallenge  = urlObj.searchParams.get('code_challenge');
  console.log(`[${index}] State: ${state}`);
  console.log(`[${index}] X Auth URL: ${xAuthUrl.slice(0, 80)}...`);

  // ── Step 2: GET twitter.com/i/oauth2/authorize ──────────────
  console.log(`[${index}] Step 2: GET Twitter authorize page...`);
  const twitterHeaders = {
    ...baseHeaders,
    'Cookie': `auth_token=${authToken}; ct0=${ct0}`,
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'cross-site',
    'Upgrade-Insecure-Requests': '1',
  };

  const twitterAuthRes = await client.get(xAuthUrl, { headers: twitterHeaders });
  if (twitterAuthRes.status !== 200) {
    console.error(`[${index}] Twitter authorize gagal: ${twitterAuthRes.status}`);
    return null;
  }

  // ── Step 3: POST /2/oauth2/authorize — approve ──────────────
  // Butuh ambil authenticity_token dari page HTML, tapi arction pakai PKCE flow
  // di mana approval langsung via POST API (bukan form submit biasa)
  // Dari screenshot: POST https://api.x.com/2/oauth2/authorize
  // dengan bearer token X + payload: approval=true, code=<auth_code>, consent_flow=web_consent
  // "code" di sini bukan OAuth code — ini authorization_code dari response body twitter authorize
  
  // Extract auth_code dari response (biasanya di JSON embedded di HTML atau header)
  let authCode = extractAuthCode(twitterAuthRes.data);
  if (!authCode) {
    console.error(`[${index}] Gagal extract auth_code dari Twitter authorize page`);
    return null;
  }
  console.log(`[${index}] Auth code (twitter internal): ${authCode.slice(0, 20)}...`);

  console.log(`[${index}] Step 3: POST Twitter approve...`);
  const approveRes = await client.post('https://api.x.com/2/oauth2/authorize', 
    new URLSearchParams({
      approval: 'true',
      code: authCode,
      consent_flow: 'web_consent',
    }).toString(),
    {
      headers: {
        ...baseHeaders,
        'Authorization': `Bearer AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`, // Twitter public bearer
        'Cookie': `auth_token=${authToken}; ct0=${ct0}`,
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-Csrf-Token': ct0,
        'Origin': 'https://x.com',
        'Referer': 'https://x.com/',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-site',
      },
    }
  );

  if (approveRes.status !== 200) {
    console.error(`[${index}] Approve gagal: ${approveRes.status}`, approveRes.data);
    return null;
  }

  // Response berisi redirect_uri dengan code
  const approveData = approveRes.data;
  console.log(`[${index}] Approve response:`, JSON.stringify(approveData).slice(0, 200));

  const callbackUrl = approveData.redirect_uri || approveData.redirectUri;
  if (!callbackUrl) {
    console.error(`[${index}] Tidak ada redirect_uri di approve response`);
    return null;
  }

  // ── Step 4: GET arction.app/oauth/x_callback?state=...&code=... ──
  console.log(`[${index}] Step 4: GET Arction callback...`);
  const callbackRes = await client.get(callbackUrl, {
    headers: {
      ...baseHeaders,
      'Sec-Fetch-Dest': 'document',
      'Sec-Fetch-Mode': 'navigate',
      'Sec-Fetch-Site': 'cross-site',
      'Referer': 'https://x.com/',
    },
  });

  // Seharusnya 302 → /dashboard
  const finalLocation = callbackRes.headers['location'];
  console.log(`[${index}] Callback status: ${callbackRes.status}, Location: ${finalLocation}`);

  if (callbackRes.status === 302 && finalLocation === '/dashboard') {
    // Ambil cn_session cookie
    const cookies = await jar.getCookies('https://arction.app');
    const cnSession = cookies.find(c => c.key === 'cn_session');
    if (cnSession) {
      console.log(`[${index}] ✅ Berhasil! cn_session: ${cnSession.value.slice(0, 30)}...`);
      return { authToken, cn_session: cnSession.value };
    }
  }

  console.error(`[${index}] Callback gagal atau tidak redirect ke dashboard`);
  return null;
}

// ─── Extract twitter internal auth_code dari HTML ─────────────
function extractAuthCode(html) {
  // Twitter embed auth_code di HTML dalam berbagai format
  // Coba beberapa pattern
  const patterns = [
    /"code"\s*:\s*"([^"]+)"/,
    /name="code"\s+value="([^"]+)"/,
    /authCode['"]\s*:\s*['"]([^'"]+)['"]/,
    /"auth_code"\s*:\s*"([^"]+)"/,
  ];
  for (const re of patterns) {
    const m = html.match(re);
    if (m) return m[1];
  }
  return null;
}

// ─── Main ───────────────────────────────────────────────────
async function main() {
  if (!fs.existsSync(ACCOUNTS_FILE)) {
    console.error(`File ${ACCOUNTS_FILE} tidak ditemukan!`);
    console.log('Format: satu akun per baris → auth_token|ct0');
    process.exit(1);
  }

  const lines = fs.readFileSync(ACCOUNTS_FILE, 'utf-8')
    .split('\n')
    .map(l => l.trim())
    .filter(l => l && !l.startsWith('#'));

  // Pasangkan baris: authtoken, ct0, authtoken, ct0, ...
  const accounts = [];
  for (let i = 0; i < lines.length; i += 2) {
    if (lines[i] && lines[i + 1]) {
      accounts.push({ authToken: lines[i], ct0: lines[i + 1] });
    }
  }

  const results = [];
  for (let i = 0; i < accounts.length; i++) {
    const { authToken, ct0 } = accounts[i];
    if (!authToken || !ct0) {
      console.warn(`[${i + 1}] Format salah, skip`);
      continue;
    }
    try {
      const res = await connectAccount(authToken.trim(), ct0.trim(), i + 1);
      if (res) results.push(res);
    } catch (err) {
      console.error(`[${i + 1}] Error:`, err.message);
    }
    // Delay antar akun
    if (i < accounts.length - 1) await sleep(2000 + Math.random() * 1000);
  }

  console.log(`\n=== SELESAI: ${results.length}/${accounts.length} akun berhasil connect ===`);
  fs.writeFileSync('arction_sessions.json', JSON.stringify(results, null, 2));
  console.log('Session disimpan ke arction_sessions.json');
}

const sleep = ms => new Promise(r => setTimeout(r, ms));

main().catch(console.error);
