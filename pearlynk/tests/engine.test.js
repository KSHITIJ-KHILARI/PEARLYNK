const assert = require('assert');
const { analyzeUrl, parseUrl, isIp, subdomainCount, levenshtein, detectLookalike, detectSuspiciousWords, detectObfuscation, SIGNALS, SUSPICIOUS_WORDS, TRUSTED_BRANDS, SUSPICIOUS_TLDS } = require('../src/engine.js');

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

// URL Parsing
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

// IP detection
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

// Subdomain count
test('subdomainCount counts levels correctly', () => {
  assert.strictEqual(subdomainCount('a.b.c.d.example.com'), 4);
  assert.strictEqual(subdomainCount('example.com'), 0);
});

// Levenshtein
test('levenshtein computes distance', () => {
  assert.strictEqual(levenshtein('kitten', 'sitting'), 3);
  assert.strictEqual(levenshtein('google', 'google'), 0);
});

// Lookalike detection
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

// Suspicious words
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

// Obfuscation
test('detectObfuscation finds @ symbol', () => {
  const result = detectObfuscation(new URL('http://example@evil.com/'), 'http://example@evil.com/');
  assert(result.includes('@ symbol in hostname'), `got ${JSON.stringify(result)}`);
});

test('detectObfuscation finds percent-encoding in host', () => {
  const result = detectObfuscation(new URL('http://ex%61mple.com/'), 'http://ex%61mple.com/');
  assert(result.includes('Percent-encoded characters in hostname'), `got ${JSON.stringify(result)}`);
});

// Score: safe URL
test('Safe URL: google.com scores 0-30', () => {
  const r = analyzeUrl('https://www.google.com');
  assert(r.score >= 0 && r.score <= 30, `score=${r.score}`);
  assert.strictEqual(r.verdict, 'Safe');
});

test('Safe URL: github.com scores low', () => {
  const r = analyzeUrl('https://github.com');
  assert(r.score >= 0 && r.score <= 30, `score=${r.score}`);
  assert.strictEqual(r.verdict, 'Safe');
});

// HTTP
test('HTTP adds points', () => {
  const r = analyzeUrl('http://example.com');
  assert(r.score >= 8, `score=${r.score}`);
  assert(r.reasons.some(x => x.type === 'http'));
});

// Raw IP
test('Raw IP adds 25 points', () => {
  const r = analyzeUrl('https://192.168.1.1');
  assert(r.score >= 25, `score=${r.score}`);
  assert(r.reasons.some(x => x.type === 'ip'));
});

// Excessive subdomains
test('Excessive subdomains adds points', () => {
  const r = analyzeUrl('https://a.b.c.d.e.f.example.com');
  assert(r.reasons.some(x => x.type === 'subdomains'), `reasons=${JSON.stringify(r.reasons)}`);
});

// Long URL
test('Long URL adds points', () => {
  const longUrl = 'https://example.com/' + 'a'.repeat(210);
  const r = analyzeUrl(longUrl);
  assert(r.reasons.some(x => x.type === 'length'), `reasons=${JSON.stringify(r.reasons)}`);
});

// Suspicious words
test('Suspicious words add points', () => {
  const r = analyzeUrl('https://example.com/login-secure-update');
  assert(r.reasons.some(x => x.type === 'words'), `reasons=${JSON.stringify(r.reasons)}`);
});

// Punycode
test('Punycode adds points', () => {
  const r = analyzeUrl('https://xn--e1afmkfd.xn--p1ai');
  assert(r.reasons.some(x => x.type === 'punycode'), `reasons=${JSON.stringify(r.reasons)}`);
});

// Obfuscation
test('Obfuscation adds points', () => {
  const r = analyzeUrl('http://user@pass@example.com/path');
  assert(r.reasons.some(x => x.type === 'obfuscation'), `reasons=${JSON.stringify(r.reasons)}`);
});

// Lookalike
test('Lookalike adds points', () => {
  const r = analyzeUrl('https://go0gle.com');
  assert(r.reasons.some(x => x.type === 'lookalike'), `reasons=${JSON.stringify(r.reasons)}`);
});

// Suspicious TLD
test('Suspicious TLD adds points', () => {
  const r = analyzeUrl('https://example.xyz');
  assert(r.reasons.some(x => x.type === 'tld'), `reasons=${JSON.stringify(r.reasons)}`);
});

// Combined high risk
test('Combined signals produce High Risk', () => {
  const longPart = 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';
  const r = analyzeUrl('http://go%30gle.com/login-secure-update?token=abc' + longPart);
  assert(r.score >= 70, `score=${r.score}`);
  assert.strictEqual(r.verdict, 'High Risk');
});

// Score cap
test('Score is capped at 100', () => {
  const r = analyzeUrl('http://a.b.c.d.e.f.xn--pple-43d.xyz/login%40secure/update?account=free&wallet=gift/reward/crypto/path1/path2/path3/path4/path5/path6/path7/path8/path9/path10/path11/path12/path13/path14/path15/path16/path17/path18/path19/path20@evil');
  assert(r.score <= 100, `score=${r.score}`);
});

// Specific high-risk URL from bug report
test('High Risk URL: raw IP with suspicious path/query/redirect scores 100', () => {
  const r = analyzeUrl('http://192.0.2.1/login/verify-account/free-gift/password-reset?redirect=%2Fsecure%2Fwallet&campaign=crypto-reward');
  assert.strictEqual(r.score, 100, `score=${r.score}`);
  assert.strictEqual(r.verdict, 'High Risk');
  assert(r.reasons.some(x => x.type === 'ip'), 'should detect raw IP');
  assert(r.reasons.some(x => x.type === 'http'), 'should detect HTTP');
  assert(r.reasons.some(x => x.type === 'words'), 'should detect suspicious words');
  assert(r.reasons.some(x => x.type === 'redirect'), 'should detect encoded redirect');
  assert(r.reasons.some(x => x.type === 'combined'), 'should detect combined signals');
});

// Invalid URL
test('Invalid URL returns error', () => {
  const r = analyzeUrl('not a url at all');
  assert(r.error !== null);
  assert.strictEqual(r.verdict, 'Safe');
});

// Empty string
test('Empty string returns error', () => {
  const r = analyzeUrl('');
  assert(r.error !== null);
});

// Results include details
test('Result includes domain, host, path, scheme', () => {
  const r = analyzeUrl('https://sub.example.com/path?q=1');
  assert.strictEqual(r.domain, 'sub.example.com');
  assert.strictEqual(r.host, 'sub.example.com');
  assert.strictEqual(r.path, '/path?q=1');
  assert.strictEqual(r.scheme, 'https');
});

// Verdict boundaries
test('Score 0-30 => Safe', () => {
  const r = analyzeUrl('https://www.google.com');
  if (r.score <= 30) assert.strictEqual(r.verdict, 'Safe');
});

test('Score 31-69 => Suspicious', () => {
  const r = analyzeUrl('http://example.xyz/login');
  if (r.score >= 31 && r.score <= 69) assert.strictEqual(r.verdict, 'Suspicious');
});

test('Score 70-100 => High Risk', () => {
  const r = analyzeUrl('http://go%30gle.com/login-secure-update?token=abc' + 'x'.repeat(200));
  if (r.score >= 70) assert.strictEqual(r.verdict, 'High Risk');
});

console.log(`\nResults: ${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
