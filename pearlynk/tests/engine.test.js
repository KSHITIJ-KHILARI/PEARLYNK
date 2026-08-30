const assert = require('assert');
const {
  analyzeUrl,
  parseUrl,
  isIp,
  subdomainCount,
  levenshtein,
  isTrustedDomain,
  isLegitimateBrandDomain,
  detectLookalike,
  detectBrandImpersonation,
  detectSuspiciousWords,
  detectObfuscation,
  extractKeywordsFromText,
  getWordCategories,
  SIGNALS,
  KEYWORD_GROUPS,
  SUSPICIOUS_WORDS,
  TRUSTED_BRANDS,
  BRAND_PROFILES,
  SUSPICIOUS_TLDS
} = require('../src/engine.js');

let passed = 0;
let failed = 0;
function test(name, fn) {
  try {
    fn();
    passed++;
    console.log(`PASS: ${name}`);
  } catch (e) {
    failed++;
    console.error(`FAIL: ${name} — ${e.message}`);
  }
}

// ──────────────────────────────────────────
// 1. URL Parsing
// ──────────────────────────────────────────
test('parseUrl adds https when missing', () => {
  const r = parseUrl('example.com');
  assert(r !== null, 'should parse');
  assert.strictEqual(r.protocol, 'https:');
  assert.strictEqual(r.hostname, 'example.com');
});

test('parseUrl returns null for empty string', () => {
  assert.strictEqual(parseUrl(''), null);
});

test('parseUrl returns null for garbage', () => {
  assert.strictEqual(parseUrl('not a url'), null);
});

// ──────────────────────────────────────────
// 2. IP Detection
// ──────────────────────────────────────────
test('isIp detects IPv4', () => {
  assert(isIp('192.168.1.1') === true);
  assert(isIp('255.255.255.255') === true);
});

test('isIp rejects invalid IPv4', () => {
  assert(isIp('256.1.2.3') === false);
  assert(isIp('1.2.3') === false);
});

test('isIp detects IPv6', () => {
  assert(isIp('::1') === true);
  assert(isIp('2001:db8::1') === true);
});

test('isIp rejects normal hostnames', () => {
  assert(isIp('google.com') === false);
});

// ──────────────────────────────────────────
// 3. Subdomain Count
// ──────────────────────────────────────────
test('subdomainCount counts levels correctly', () => {
  assert.strictEqual(subdomainCount('a.b.c.d.example.com'), 4);
  assert.strictEqual(subdomainCount('example.com'), 0);
});

// ──────────────────────────────────────────
// 4. Levenshtein Distance
// ──────────────────────────────────────────
test('levenshtein computes distance', () => {
  assert.strictEqual(levenshtein('kitten', 'sitting'), 3);
  assert.strictEqual(levenshtein('google', 'google'), 0);
});

// ──────────────────────────────────────────
// 5. Lookalike Detection
// ──────────────────────────────────────────
test('detectLookalike flags go0gle as Google', () => {
  assert.strictEqual(detectLookalike('go0gle.com'), 'Google');
});

test('detectLookalike flags micros0ft as Microsoft', () => {
  assert.strictEqual(detectLookalike('micros0ft.com'), 'Microsoft');
});

test('detectLookalike does not flag exact match', () => {
  assert.strictEqual(detectLookalike('google.com'), null);
});

test('detectLookalike returns null for IPs', () => {
  assert.strictEqual(detectLookalike('192.168.1.1'), null);
});

// ──────────────────────────────────────────
// 6. Suspicious Words & Categorization
// ──────────────────────────────────────────
test('detectSuspiciousWords finds multiple words', () => {
  const words = detectSuspiciousWords('secure-login.example.com', '/update-account');
  assert(words.includes('secure'));
  assert(words.includes('login'));
  assert(words.includes('update'));
  assert(words.includes('account'));
});

test('detectSuspiciousWords returns empty for clean URL', () => {
  const words = detectSuspiciousWords('example.com', '/about');
  assert(words.length === 0);
});

test('getWordCategories groups keywords into appropriate types', () => {
  const cats = getWordCategories(['login', 'verify', 'wallet']);
  assert(cats.includes('credential/account'));
  assert(cats.includes('urgency/verification'));
  assert(cats.includes('financial/reward'));
});

// ──────────────────────────────────────────
// 7. Obfuscation Detection
// ──────────────────────────────────────────
test('detectObfuscation finds @ symbol', () => {
  const result = detectObfuscation(new URL('http://example@evil.com/'), 'http://example@evil.com/');
  assert(result.includes('@ symbol in hostname'), `got ${JSON.stringify(result)}`);
});

test('detectObfuscation finds percent-encoding in host', () => {
  const result = detectObfuscation(new URL('http://ex%61mple.com/'), 'http://ex%61mple.com/');
  assert(result.includes('Percent-encoded characters in hostname'), `got ${JSON.stringify(result)}`);
});

// ──────────────────────────────────────────
// 8. Trusted Domains Context (No False Positives)
// ──────────────────────────────────────────
test('Trusted domain: https://www.google.com scores 0 (Safe)', () => {
  const r = analyzeUrl('https://www.google.com');
  assert(r.score >= 0 && r.score <= 10, `score=${r.score}`);
  assert.strictEqual(r.verdict, 'Safe');
});

test('Trusted domain: https://accounts.google.com scores 0 (Safe)', () => {
  const r = analyzeUrl('https://accounts.google.com');
  assert(r.score >= 0 && r.score <= 10, `score=${r.score}`);
  assert.strictEqual(r.verdict, 'Safe');
});

test('Trusted domain: https://github.com/login scores 0 (Safe)', () => {
  const r = analyzeUrl('https://github.com/login');
  assert(r.score >= 0 && r.score <= 10, `score=${r.score}`);
  assert.strictEqual(r.verdict, 'Safe');
});

test('Trusted domain: https://login.microsoftonline.com scores 0 (Safe)', () => {
  const r = analyzeUrl('https://login.microsoftonline.com');
  assert(r.score >= 0 && r.score <= 10, `score=${r.score}`);
  assert.strictEqual(r.verdict, 'Safe');
});

test('Trusted domain: https://www.paypal.com/signin scores 0 (Safe)', () => {
  const r = analyzeUrl('https://www.paypal.com/signin');
  assert(r.score >= 0 && r.score <= 10, `score=${r.score}`);
  assert.strictEqual(r.verdict, 'Safe');
});

// ──────────────────────────────────────────
// 9. Single Keyword on Normal Domains (Low Risk)
// ──────────────────────────────────────────
test('Single keyword: https://example.com/login scores low (Safe)', () => {
  const r = analyzeUrl('https://example.com/login');
  assert(r.score >= 0 && r.score <= 15, `score=${r.score}`);
  assert.strictEqual(r.verdict, 'Safe');
});

test('Single keyword: https://mysite.org/account scores low (Safe)', () => {
  const r = analyzeUrl('https://mysite.org/account');
  assert(r.score >= 0 && r.score <= 15, `score=${r.score}`);
  assert.strictEqual(r.verdict, 'Safe');
});

// ──────────────────────────────────────────
// 10. Brand Impersonation in Hostname
// ──────────────────────────────────────────
test('Brand impersonation: https://google-login.example.com scores Suspicious/High Risk', () => {
  const r = analyzeUrl('https://google-login.example.com');
  assert(r.score >= 45, `score=${r.score}`);
  assert(r.verdict === 'Suspicious' || r.verdict === 'High Risk');
  assert(r.reasons.some(x => x.type === 'impersonation'), 'should detect brand impersonation');
});

test('Brand impersonation: https://paypal-secure.example.net scores Suspicious/High Risk', () => {
  const r = analyzeUrl('https://paypal-secure.example.net');
  assert(r.score >= 45, `score=${r.score}`);
  assert(r.verdict === 'Suspicious' || r.verdict === 'High Risk');
  assert(r.reasons.some(x => x.type === 'impersonation'), 'should detect brand impersonation');
});

test('Brand impersonation + suspicious TLD: https://paypal-secure.top/login is High Risk', () => {
  const r = analyzeUrl('https://paypal-secure.top/login');
  assert(r.score >= 70, `score=${r.score}`);
  assert.strictEqual(r.verdict, 'High Risk');
  assert(r.reasons.some(x => x.type === 'impersonation'), 'should detect brand impersonation');
  assert(r.reasons.some(x => x.type === 'tld'), 'should detect suspicious TLD');
});

// ──────────────────────────────────────────
// 11. Contextual & Multiple Keyword Scoring
// ──────────────────────────────────────────
test('Multiple keywords in hostname: account-security-verification.example.com scores high', () => {
  const r = analyzeUrl('https://account-security-verification.example.com/login/secure/confirm?session=8492-VERIFY-NOW');
  assert(r.score >= 60, `score=${r.score}`);
  assert(r.verdict === 'Suspicious' || r.verdict === 'High Risk');
  assert(r.reasons.some(x => x.type === 'host_keywords'), 'should detect host keywords');
  assert(r.reasons.some(x => x.type === 'keyword_category_combo'), 'should detect category combo');
});

test('Hostname keyword weighted heavier than path keyword', () => {
  const hostKwUrl = analyzeUrl('https://account-security.example.com');
  const pathKwUrl = analyzeUrl('https://example.com/account-security');
  assert(hostKwUrl.score > pathKwUrl.score, `host=${hostKwUrl.score} should be > path=${pathKwUrl.score}`);
});

// ──────────────────────────────────────────
// 12. Lookalike + TLD & Impersonation Combinations
// ──────────────────────────────────────────
test('Lookalike on suspicious TLD: https://go0gle.xyz/login is High Risk', () => {
  const r = analyzeUrl('https://go0gle.xyz/login');
  assert(r.score >= 70, `score=${r.score}`);
  assert.strictEqual(r.verdict, 'High Risk');
  assert(r.reasons.some(x => x.type === 'lookalike'), 'should detect lookalike');
});

// ──────────────────────────────────────────
// 13. Raw IP Combinations
// ──────────────────────────────────────────
test('Raw IP with credential keywords: http://192.0.2.1/login/verify-account is High Risk', () => {
  const r = analyzeUrl('http://192.0.2.1/login/verify-account');
  assert.strictEqual(r.score, 100, `score=${r.score}`);
  assert.strictEqual(r.verdict, 'High Risk');
  assert(r.reasons.some(x => x.type === 'ip'), 'should detect IP');
  assert(r.reasons.some(x => x.type === 'ip_keyword_combo'), 'should detect IP + keyword combo');
});

// ──────────────────────────────────────────
// 14. Severe Signal Verdict Floors
// ──────────────────────────────────────────
test('Verdict Floor: Raw IP + credentials always reaches High Risk floor', () => {
  const r = analyzeUrl('https://192.168.1.1/login');
  assert(r.score >= 70, `score=${r.score}`);
  assert.strictEqual(r.verdict, 'High Risk');
});

test('Verdict Floor: Brand impersonation + TLD always reaches High Risk floor', () => {
  const r = analyzeUrl('https://microsoft-account.xyz');
  assert(r.score >= 70, `score=${r.score}`);
  assert.strictEqual(r.verdict, 'High Risk');
});

// ──────────────────────────────────────────
// 15. Obfuscation & Encoded Redirects
// ──────────────────────────────────────────
test('Obfuscation + keywords elevates risk', () => {
  const r = analyzeUrl('http://user:pass@example.com/login');
  assert(r.score >= 40, `score=${r.score}`);
  assert(r.reasons.some(x => x.type === 'obfuscation'));
});

// ──────────────────────────────────────────
// 16. Score Boundaries & Limits
// ──────────────────────────────────────────
test('Score is capped at 100', () => {
  const r = analyzeUrl('http://a.b.c.d.e.f.xn--pple-43d.xyz/login%40secure/update?account=free&wallet=gift/reward/crypto/path1/path2/path3@evil');
  assert(r.score <= 100, `score=${r.score}`);
});

test('Invalid URL returns error', () => {
  const r = analyzeUrl('not a url at all');
  assert(r.error !== null);
  assert.strictEqual(r.verdict, 'Safe');
});

test('Empty string returns error', () => {
  const r = analyzeUrl('');
  assert(r.error !== null);
});

test('Result includes domain, host, path, scheme', () => {
  const r = analyzeUrl('https://sub.example.com/path?q=1');
  assert.strictEqual(r.domain, 'sub.example.com');
  assert.strictEqual(r.host, 'sub.example.com');
  assert.strictEqual(r.path, '/path?q=1');
  assert.strictEqual(r.scheme, 'https');
});

console.log(`\n========================================`);
console.log(`Test Results: ${passed} passed, ${failed} failed`);
console.log(`========================================\n`);

process.exit(failed > 0 ? 1 : 0);
