const axios = require('axios');
const crypto = require('crypto');
const { CookieJar } = require('tough-cookie');
const { wrapper } = require('axios-cookiejar-support');
const fs = require('fs');
const readline = require('readline');

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

const ACCOUNTS_FILE = 'akun.txt';

// ─── Prompt helper ──────────────────────────────────────────
function prompt(question) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise(resolve => rl.question(question, ans => { rl.close(); resolve(ans.trim()); }));
}

// ─── Per-account connect ─────────────────────────────────────
async function connectAccount(authToken, ct0, index) {
  const jar = new CookieJar();
  const client = wrapper(axios.create({
    jar,
    withCredentials: true,
    maxRedirects: 0,
    validateStatus: () => true,
  }));

  const baseHeaders = {
    'User-Agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36',
    'Accept-Language': 'id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7',
    'Sec-Ch-Ua': '"Mises";v="141", "Not?A_Brand";v="8", "Chromium";v="141"',
    'Sec-Ch-Ua-Mobile': '?1',
    'Sec-Ch-Ua-Platform': '"Android"',
  };

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

  let xAuthUrl = loginRes.headers['location'];
  if (!xAuthUrl || !xAuthUrl.includes('twitter.com')) {
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

  const urlObj = new URL(xAuthUrl);
  const state          = urlObj.searchParams.get('state');
  const codeChallenge  = urlObj.searchParams.get('code_challenge');
  console.log(`[${index}] State: ${state}`);
  console.log(`[${index}] X Auth URL: ${xAuthUrl.slice(0, 80)}...`);

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
        'Authorization': `Bearer AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`,
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

  const approveData = approveRes.data;
  console.log(`[${index}] Approve response:`, JSON.stringify(approveData).slice(0, 200));

  const callbackUrl = approveData.redirect_uri || approveData.redirectUri;
  if (!callbackUrl) {
    console.error(`[${index}] Tidak ada redirect_uri di approve response`);
    return null;
  }

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

  const finalLocation = callbackRes.headers['location'];
  console.log(`[${index}] Callback status: ${callbackRes.status}, Location: ${finalLocation}`);

  if (callbackRes.status === 302 && finalLocation === '/dashboard') {
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
    process.exit(1);
  }

  const lines = fs.readFileSync(ACCOUNTS_FILE, 'utf-8')
    .split('\n')
    .map(l => l.trim())
    .filter(l => l && !l.startsWith('#'));

  const accounts = [];
  for (let i = 0; i < lines.length; i += 2) {
    if (lines[i] && lines[i + 1]) {
      accounts.push({ authToken: lines[i], ct0: lines[i + 1] });
    }
  }

  console.log(`Total akun terbaca: ${accounts.length}`);
  console.log('');
  console.log('Pilih mode:');
  console.log('  1 → Jalankan 1 akun (pilih nomor)');
  console.log('  2 → Semua akun');
  console.log('  3 → Dari akun ke-X sampai akhir');
  console.log('');

  const mode = await prompt('Mode [1/2/3]: ');

  let selected = [];

  if (mode === '1') {
    const input = await prompt(`Nomor akun (1–${accounts.length}): `);
    const n = parseInt(input);
    if (isNaN(n) || n < 1 || n > accounts.length) {
      console.error('Nomor tidak valid, keluar.');
      process.exit(1);
    }
    selected = [{ ...accounts[n - 1], displayIndex: n }];

  } else if (mode === '2') {
    selected = accounts.map((a, i) => ({ ...a, displayIndex: i + 1 }));

  } else if (mode === '3') {
    const input = await prompt(`Mulai dari akun ke- (1–${accounts.length}): `);
    const from = parseInt(input);
    if (isNaN(from) || from < 1 || from > accounts.length) {
      console.error('Nomor tidak valid, keluar.');
      process.exit(1);
    }
    selected = accounts.slice(from - 1).map((a, i) => ({ ...a, displayIndex: from + i }));

  } else {
    console.error('Pilihan tidak valid, keluar.');
    process.exit(1);
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
