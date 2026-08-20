const APPS_SCRIPT_URL =
  'https://script.google.com/macros/s/AKfycbyUNtzfkfGlXjnJgqzr1Y8BybDZPxIrkYn6oo3daz8uq-7p0bKQcI-dzs44M-d8NEIt/exec';

const GOOGLE_AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth';
const GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token';
const GOOGLE_CALENDAR_API = 'https://www.googleapis.com/calendar/v3';
const GOOGLE_SCOPE = 'https://www.googleapis.com/auth/calendar.app.created';

export default {
  async fetch(request, env, ctx) { 
    const url = new URL(request.url);

    try {
      if (request.method === 'GET' && url.pathname === '/oauth/google/start') {
        return handleGoogleOAuthStart_(url, env);
      }

      if (request.method === 'GET' && url.pathname === '/oauth/google/callback') {
        return handleGoogleOAuthCallback_(url, env);
      }

      if (request.method === 'GET' && url.pathname === '/api/google/status') {
        return handleGoogleStatus_(url, env);
      }

      if (request.method === 'GET' && url.pathname.startsWith('/calendar/')) {
        const token = decodeURIComponent(url.pathname.substring('/calendar/'.length)).trim();
        if (!token) return new Response('Calendar token missing.', { status: 400 });

        try {
          const upstream = await fetch(
            APPS_SCRIPT_URL + '?calendarToken=' + encodeURIComponent(token),
            { method: 'GET', redirect: 'follow' }
          );
          const body = await upstream.text();
          return new Response(body, {
            status: upstream.status,
            headers: {
              'Content-Type': 'text/calendar; charset=utf-8',
              'Cache-Control': 'no-cache, no-store, must-revalidate',
              'Access-Control-Allow-Origin': '*'
            }
          });
        } catch (error) {
          console.error('Calendar proxy error:', error);
          return new Response('Calendar feed unavailable.', { status: 502 });
        }
      }

      if (request.method === 'GET') {
        return new Response('IPFL Bot webhook is running.', {
          status: 200,
          headers: { 'Content-Type': 'text/plain; charset=utf-8' }
        });
      }

      if (request.method !== 'POST') {
        return new Response('Method Not Allowed', { status: 405 });
      }

      try {
        const body = await request.text();
        await fetch(APPS_SCRIPT_URL, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body,
          redirect: 'follow'
        });
        return new Response('OK', { status: 200 });
      } catch (error) {
        console.error('Webhook proxy error:', error);
        return new Response('OK', { status: 200 });
      }
    } catch (error) {
      console.error('Worker error:', error);
      return new Response('Internal Server Error', { status: 500 });
    }
  }
};

async function handleGoogleOAuthStart_(url, env) {
  assertOAuthEnv_(env);
  const chatId = String(url.searchParams.get('chatId') || '').trim();
  if (!/^\d+$/.test(chatId)) {
    return new Response('Missing or invalid Telegram chatId.', { status: 400 });
  }

  const state = await createSignedState_({ chatId, ts: Date.now() }, env.OAUTH_STATE_SECRET);
  const authUrl = new URL(GOOGLE_AUTH_URL);
  authUrl.searchParams.set('client_id', env.GOOGLE_CLIENT_ID);
  authUrl.searchParams.set('redirect_uri', env.GOOGLE_REDIRECT_URI);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('scope', GOOGLE_SCOPE);
  authUrl.searchParams.set('access_type', 'offline');
  authUrl.searchParams.set('prompt', 'consent');
  authUrl.searchParams.set('include_granted_scopes', 'true');
  authUrl.searchParams.set('state', state);
  return Response.redirect(authUrl.toString(), 302);
}

async function handleGoogleOAuthCallback_(url, env) {
  assertOAuthEnv_(env);

  if (url.searchParams.get('error')) {
    return htmlResponse_(
      'החיבור בוטל',
      'Google לא אישרה את החיבור. אפשר לסגור את החלון ולנסות שוב מהבוט.',
      false
    );
  }

  const code = String(url.searchParams.get('code') || '').trim();
  const state = String(url.searchParams.get('state') || '').trim();
  if (!code || !state) {
    return new Response('OAuth callback is missing code/state.', { status: 400 });
  }

  const stateData = await verifySignedState_(state, env.OAUTH_STATE_SECRET);
  if (!stateData) return new Response('Invalid OAuth state.', { status: 400 });

  const ageMs = Date.now() - Number(stateData.ts || 0);
  if (ageMs < 0 || ageMs > 10 * 60 * 1000) {
    return new Response('OAuth state expired.', { status: 400 });
  }

  const chatId = String(stateData.chatId || '').trim();
  if (!/^\d+$/.test(chatId)) {
    return new Response('Invalid Telegram chatId in OAuth state.', { status: 400 });
  }

  const tokens = await exchangeCodeForTokens_(code, env);
  const accessToken = tokens.access_token;
  if (!accessToken) throw new Error('Google token response has no access_token.');

  const existing = await env.DB.prepare(
    `SELECT refresh_token_encrypted, refresh_token_iv, calendar_id
     FROM google_connections
     WHERE telegram_chat_id = ?`
  ).bind(chatId).first();

  let encryptedToken = null;
  if (tokens.refresh_token) {
    encryptedToken = await encryptText_(tokens.refresh_token, env.TOKEN_ENCRYPTION_KEY);
  } else if (existing && existing.refresh_token_encrypted && existing.refresh_token_iv) {
    encryptedToken = {
      cipherText: existing.refresh_token_encrypted,
      iv: existing.refresh_token_iv
    };
  } else {
    throw new Error(
      'Google did not return a refresh token. Revoke IPFL Bot access in your Google Account and connect again.'
    );
  }

  let calendarId = existing && existing.calendar_id ? String(existing.calendar_id) : '';
  if (!calendarId) {
    const calendar = await createGoogleCalendar_(accessToken);
    calendarId = String(calendar.id || '');
    if (!calendarId) throw new Error('Google Calendar API did not return calendar id.');
  }

  const now = new Date().toISOString();
  await env.DB.prepare(
    `INSERT INTO google_connections (
       telegram_chat_id,
       google_email,
       refresh_token_encrypted,
       refresh_token_iv,
       calendar_id,
       calendar_name,
       scopes,
       created_at,
       updated_at
     )
     VALUES (?, NULL, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(telegram_chat_id)
     DO UPDATE SET
       refresh_token_encrypted = excluded.refresh_token_encrypted,
       refresh_token_iv = excluded.refresh_token_iv,
       calendar_id = excluded.calendar_id,
       calendar_name = excluded.calendar_name,
       scopes = excluded.scopes,
       updated_at = excluded.updated_at`
  ).bind(
    chatId,
    encryptedToken.cipherText,
    encryptedToken.iv,
    calendarId,
    'IPFL Bot - המשחקים שלי',
    GOOGLE_SCOPE,
    now,
    now
  ).run();

  return htmlResponse_(
    'Google Calendar חובר בהצלחה ✅',
    'נוצר וחובר היומן "IPFL Bot - המשחקים שלי". אפשר לסגור את החלון ולחזור לטלגרם.',
    true
  );
}

async function exchangeCodeForTokens_(code, env) {
  const body = new URLSearchParams({
    code,
    client_id: env.GOOGLE_CLIENT_ID,
    client_secret: env.GOOGLE_CLIENT_SECRET,
    redirect_uri: env.GOOGLE_REDIRECT_URI,
    grant_type: 'authorization_code'
  });

  const response = await fetch(GOOGLE_TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body
  });

  const data = await response.json();
  if (!response.ok) {
    throw new Error('Google token exchange failed: ' + JSON.stringify(data));
  }
  return data;
}

async function createGoogleCalendar_(accessToken) {
  const response = await fetch(GOOGLE_CALENDAR_API + '/calendars', {
    method: 'POST',
    headers: {
      Authorization: 'Bearer ' + accessToken,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      summary: 'IPFL Bot - המשחקים שלי',
      description: 'יומן משחקים אישי המתעדכן אוטומטית על ידי IPFL Bot.',
      timeZone: 'Asia/Jerusalem'
    })
  });

  const data = await response.json();
  if (!response.ok) {
    throw new Error('Calendar creation failed: ' + JSON.stringify(data));
  }
  return data;
}

async function handleGoogleStatus_(url, env) {
  const chatId = String(url.searchParams.get('chatId') || '').trim();
  if (!/^\d+$/.test(chatId)) {
    return jsonResponse_({ connected: false, error: 'invalid_chat_id' }, 400);
  }

  const row = await env.DB.prepare(
    `SELECT telegram_chat_id, calendar_id, calendar_name, scopes, created_at, updated_at
     FROM google_connections
     WHERE telegram_chat_id = ?`
  ).bind(chatId).first();

  if (!row) return jsonResponse_({ connected: false });

  return jsonResponse_({
    connected: true,
    calendarId: row.calendar_id,
    calendarName: row.calendar_name,
    scopes: row.scopes,
    createdAt: row.created_at,
    updatedAt: row.updated_at
  });
}

async function createSignedState_(payload, secret) {
  const json = JSON.stringify(payload);
  const payloadPart = base64UrlEncode_(new TextEncoder().encode(json));
  const signature = await hmacSha256_(payloadPart, secret);
  return payloadPart + '.' + base64UrlEncode_(signature);
}

async function verifySignedState_(state, secret) {
  const parts = String(state || '').split('.');
  if (parts.length !== 2) return null;

  const expected = await hmacSha256_(parts[0], secret);
  const actual = base64UrlDecode_(parts[1]);
  if (!constantTimeEqual_(expected, actual)) return null;

  try {
    const json = new TextDecoder().decode(base64UrlDecode_(parts[0]));
    return JSON.parse(json);
  } catch (_) {
    return null;
  }
}

async function hmacSha256_(value, secret) {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const signature = await crypto.subtle.sign(
    'HMAC',
    key,
    new TextEncoder().encode(value)
  );

  return new Uint8Array(signature);
}

async function encryptText_(plainText, hexKey) {
  const keyBytes = hexToBytes_(hexKey);
  if (keyBytes.length !== 32) {
    throw new Error('TOKEN_ENCRYPTION_KEY must be 32 bytes / 64 hex characters.');
  }

  const key = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'AES-GCM' },
    false,
    ['encrypt']
  );

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    new TextEncoder().encode(plainText)
  );

  return {
    cipherText: bytesToBase64_(new Uint8Array(encrypted)),
    iv: bytesToBase64_(iv)
  };
}

function assertOAuthEnv_(env) {
  const required = [
    'GOOGLE_CLIENT_ID',
    'GOOGLE_CLIENT_SECRET',
    'GOOGLE_REDIRECT_URI',
    'OAUTH_STATE_SECRET',
    'TOKEN_ENCRYPTION_KEY'
  ];

  required.forEach(name => {
    if (!String(env[name] || '').trim()) {
      throw new Error('Missing Worker secret: ' + name);
    }
  });

  if (!env.DB) throw new Error('Missing D1 binding: DB');
}

function hexToBytes_(hex) {
  const clean = String(hex || '').trim();
  if (!/^[0-9a-fA-F]+$/.test(clean) || clean.length % 2 !== 0) {
    throw new Error('Invalid hex key.');
  }

  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < clean.length; i += 2) {
    out[i / 2] = parseInt(clean.substring(i, i + 2), 16);
  }
  return out;
}

function bytesToBase64_(bytes) {
  let binary = '';
  bytes.forEach(b => { binary += String.fromCharCode(b); });
  return btoa(binary);
}

function base64UrlEncode_(bytes) {
  return bytesToBase64_(bytes)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function base64UrlDecode_(value) {
  let base64 = String(value || '')
    .replace(/-/g, '+')
    .replace(/_/g, '/');

  while (base64.length % 4) base64 += '=';

  const binary = atob(base64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

function constantTimeEqual_(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

function htmlResponse_(title, message, success) {
  const icon = success ? '✅' : '⚠️';
  const html = `<!doctype html>
<html lang="he" dir="rtl">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>${escapeHtml_(title)}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 0; background: #f4f7f5; color: #17231d; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
    .card { width: min(520px, calc(100% - 40px)); background: white; border-radius: 20px; padding: 28px; box-shadow: 0 12px 40px rgba(0,0,0,.08); text-align: center; }
    .icon { font-size: 48px; margin-bottom: 12px; }
    h1 { font-size: 22px; margin: 0 0 12px; }
    p { line-height: 1.6; margin: 0; }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">${icon}</div>
    <h1>${escapeHtml_(title)}</h1>
    <p>${escapeHtml_(message)}</p>
  </div>
</body>
</html>`;

  return new Response(html, {
    status: success ? 200 : 400,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store'
    }
  });
}

function jsonResponse_(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store'
    }
  });
}

function escapeHtml_(value) {
  return String(value || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
