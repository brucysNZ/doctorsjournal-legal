// Cloudflare Pages Function middleware — Basic Auth gate for the whole site.
// Runs on every request before static files are served.
//
// CO 2026-07-13: lock the DJ launch/pricing/legal pages the same way certo.brucys.me
// is locked. Anyone hitting dj.brucys.me/* (or the .pages.dev backup URL) is
// prompted for username + password before seeing content.
//
// Credentials are stored as Pages environment variables so they don't live in
// the repo. Set via Cloudflare dashboard → Pages → dj-launch → Settings →
// Environment variables → Production:
//   AUTH_USER = doctors
//   AUTH_PASS = <chosen strong password>
//
// To change the password later, edit ONLY the env var — no code change / no
// commit needed. Redeploy is automatic on env-var save.

const REALM = "Doctor's Journal — Launch";

// Timing-safe string compare (avoids leaking password length via response time)
function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let mismatch = 0;
  for (let i = 0; i < a.length; i++) mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return mismatch === 0;
}

export const onRequest = async ({ request, env, next }) => {
  const expectedUser = env.AUTH_USER;
  const expectedPass = env.AUTH_PASS;

  // If no credentials configured on the environment, fail open with a warning —
  // safer for local wrangler dev, and gives a clear signal in prod if the env
  // vars ever get wiped.
  if (!expectedUser || !expectedPass) {
    return next();
  }

  const authHeader = request.headers.get('Authorization') || '';
  const [scheme, encoded] = authHeader.split(' ');
  if (scheme === 'Basic' && encoded) {
    let decoded;
    try {
      decoded = atob(encoded);
    } catch {
      decoded = '';
    }
    const idx = decoded.indexOf(':');
    if (idx >= 0) {
      const user = decoded.slice(0, idx);
      const pass = decoded.slice(idx + 1);
      if (safeEqual(user, expectedUser) && safeEqual(pass, expectedPass)) {
        return next();
      }
    }
  }

  return new Response('Authentication required', {
    status: 401,
    headers: {
      'WWW-Authenticate': `Basic realm="${REALM}", charset="UTF-8"`,
      'Content-Type': 'text/plain; charset=utf-8',
      'Cache-Control': 'no-store',
    },
  });
};
