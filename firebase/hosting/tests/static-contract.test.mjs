import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import test from 'node:test';
import vm from 'node:vm';

const repo = new URL('../../../', import.meta.url).pathname;

async function text(path) {
  return readFile(join(repo, path), 'utf8');
}

test('hosting source binds exact owner and Google provider', async () => {
  const app = await text('firebase/hosting/src/app.js');
  const config = await text('firebase/hosting/src/firebase-config.js');
  assert.doesNotMatch(config, /owner@example\.invalid/);
  assert.match(config, /google\.com/);
  assert.match(config, /pinnedUid:"replace-with-owner-firebase-uid"/);
  assert.match(app, /emailVerified !== true/);
  assert.match(app, /token\.claims\.email_verified === true/);
  assert.match(app, /token\.signInProvider === ownerPolicy\.provider/);
  assert.match(app, /idToken: authProof\.idToken/);
  assert.match(app, /BRIDGE_AUTH_PROOF_MISMATCH/);
  assert.doesNotMatch(app, /owner@example\.invalid/);
  assert.doesNotMatch(app, /bootstrap_token|One-use bootstrap token/);
});

test('hosted controls use receipt-bound Firestore requests only', async () => {
  const app = await text('firebase/hosting/src/app.js');
  assert.match(app, /cct_control_requests/);
  assert.match(app, /cct_control_receipts/);
  assert.match(app, /parentRequestId/);
  assert.match(app, /previewSha256/);
  assert.match(app, /APPLY_VERIFIED/);
  assert.doesNotMatch(app, /fetch\(['"]\/api\//);
});

test('Firebase config is deny-by-default and contains no Cloud Functions', async () => {
  const config = JSON.parse(await text('firebase.json'));
  assert.equal(config.auth.providers.anonymous, false);
  assert.equal(config.auth.providers.emailPassword, false);
  assert.equal(config.auth.providers.googleSignIn.supportEmail, 'owner@example.invalid');
  assert.equal(config.firestore.rules, 'firestore.rules');
  assert.equal(config.hosting.public, 'firebase/hosting/dist');
  assert.equal('functions' in config, false);
  const rules = await text('firestore.rules');
  assert.match(rules, /request\.auth\.token\.email == 'owner@example\.invalid'/);
  assert.match(rules, /request\.auth\.uid == 'replace-with-owner-firebase-uid'/);
  assert.match(rules, /request\.auth\.token\.firebase\.sign_in_provider == 'google\.com'/);
  assert.match(rules, /match \/\{document=\*\*\}/);
  assert.match(rules, /allow read, write: if false/);
});

test('hosting template does not expose dashboard before auth observer', async () => {
  const html = await text('firebase/hosting/index.template.html');
  assert.match(html, /id="auth-gate"/);
  assert.match(html, /id="app-shell" class="shell(?: [^"]+)?" hidden/);
  assert.match(html, /noindex,nofollow,noarchive/);
  assert.doesNotMatch(html, /owner@example\.invalid/);
  assert.doesNotMatch(html, /apiKey/);
  assert.match(html, /Open this page in Chrome or Safari before signing in/);
});

test('CSP permits Firebase Google sign-in bootstrap without broad script permissions', async () => {
  const config = JSON.parse(await text('firebase.json'));
  const policy = config.hosting.headers.find((entry) => entry.source === '**')
    .headers.find((header) => header.key === 'Content-Security-Policy').value;
  const directives = new Map(policy.split(';').map((part) => {
    const [name, ...sources] = part.trim().split(/\s+/);
    return [name, sources];
  }));
  const scriptSources = directives.get('script-src-elem') || directives.get('script-src');
  assert.deepEqual(scriptSources, ["'self'", 'https://apis.google.com']);
  assert.deepEqual(directives.get('object-src'), ["'none'"]);
  assert.deepEqual(directives.get('frame-ancestors'), ["'none'"]);
  assert.ok(directives.get('frame-src').includes('https://demo-cctae.firebaseapp.com'));
  assert.doesNotMatch(policy, /'unsafe-inline'|'unsafe-eval'|script-src[^;]*\*/);
});

test('sign-in bootstrap failures are not misreported as owner identity failures', async () => {
  const app = await text('firebase/hosting/src/app.js');
  const source = app.match(/function boundedAuthError\(error\) \{[\s\S]*?\n\}/)?.[0];
  assert.ok(source, 'bounded error mapper exists');
  const boundedAuthError = vm.runInNewContext(`(${source})`);
  assert.equal(boundedAuthError({ code: 'auth/internal-error' }), 'auth/internal-error');
  assert.equal(boundedAuthError({ code: 'auth/operation-not-allowed' }), 'auth/operation-not-allowed');
  assert.equal(boundedAuthError({ code: 'auth/popup-blocked' }), 'auth/popup-blocked');
  assert.equal(boundedAuthError({ code: 'secret/untrusted-payload' }), 'auth/owner-verification-failed');
});
