// Pearlynk deterministic URL risk engine
// All analysis is local and synchronous. No network requests.

const SIGNALS = {
  HTTP: { max: 8, label: 'Connection is not encrypted (HTTP)' },
  RAW_IP: { max: 45, label: 'Domain is a raw IP address' },
  EXCESSIVE_SUBDOMAINS: { max: 10, label: 'Excessive subdomains detected' },
  LONG_URL: { max: 10, label: 'URL is unusually long' },
  SUSPICIOUS_WORDS: { max: 25, label: 'Suspicious keyword detected in URL' },
  PUNYCODE: { max: 20, label: 'Internationalized domain (punycode / xn--) detected' },
  OBFUSCATION: { max: 15, label: 'Obfuscated or suspicious URL pattern detected' },
  LOOKALIKE: { max: 25, label: 'Possible lookalike/typosquatting domain' },
  SUSPICIOUS_TLD: { max: 15, label: 'Suspicious top-level domain' }
};

const SUSPICIOUS_WORDS = [
  'login', 'verify', 'update', 'secure', 'account', 'password', 'wallet',
  'gift', 'reward', 'free', 'crypto', 'bank', 'confirm', 'signin', 'sign-in',
  'billing', 'paypal', 'appleid', 'microsoft', 'google', 'amazon', 'netflix',
  'facebook', 'instagram', 'linkedin', 'reset', 'unlock', 'activate', 'verification'
];

const TRUSTED_BRANDS = [
  { key: 'google', label: 'Google' },
  { key: 'microsoft', label: 'Microsoft' },
  { key: 'apple', label: 'Apple' },
  { key: 'paypal', label: 'PayPal' },
  { key: 'amazon', label: 'Amazon' },
  { key: 'instagram', label: 'Instagram' },
  { key: 'facebook', label: 'Facebook' },
  { key: 'linkedin', label: 'LinkedIn' },
  { key: 'netflix', label: 'Netflix' }
];

const SUSPICIOUS_TLDS = [
  '.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', '.buzz', '.monster',
  '.cam', '.cfd', '.hair', '.skin', '.boats', '.bond', '.autos',
  '.zip', '.mov', '.click', '.link', '.uno', '.work',
  '.men', '.bid', '.date', '.loan', '.racing', '.online', '.win', '.kim'
];

function parseUrl(input) {
  let str = input.trim();
  if (!str) return null;
  if (!/^[a-zA-Z][a-zA-Z0-9+\-.]*:\/\//.test(str)) {
    str = 'https://' + str;
  }
  try {
    const url = new URL(str);
    return url;
  } catch {
    return null;
  }
}

function isIp(host) {
  if (!host) return false;
  const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (ipv4.test(host)) {
    const parts = host.split('.');
    return parts.every(p => parseInt(p, 10) <= 255);
  }
  const ipv6 = /^[0-9a-fA-F:]+$/;
  return ipv6.test(host) && host.includes(':');
}

function subdomainCount(host) {
  if (!host || isIp(host)) return 0;
  const parts = host.split('.');
  if (parts.length <= 2) return 0;
  return parts.length - 2;
}

function levenshtein(a, b) {
  const m = a.length;
  const n = b.length;
  const dp = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,
        dp[i][j - 1] + 1,
        dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)
      );
    }
  }
  return dp[m][n];
}

function detectLookalike(host) {
  if (!host || isIp(host)) return null;
  const normalized = host.toLowerCase();
  const domain = normalized.split('.').slice(0, -1).join('.');
  for (const brand of TRUSTED_BRANDS) {
    const dist = levenshtein(domain, brand.key);
    if (dist >= 1 && dist <= 2 && domain !== brand.key) {
      return brand.label;
    }
    // Check if brand appears as subdomain in a suspicious way
    if (normalized.includes(brand.key + '-') || normalized.includes(brand.key + '.')) {
      const parts = normalized.split('.');
      for (const part of parts) {
        if (part.startsWith(brand.key) && part !== brand.key && levenshtein(part, brand.key) <= 2) {
          return brand.label;
        }
      }
    }
  }
  return null;
}

function detectSuspiciousWords(host, pathname, search) {
  const decodedSearch = search ? decodeURIComponent(search) : '';
  const haystack = ((host || '') + ' ' + (pathname || '') + ' ' + decodedSearch).toLowerCase();
  const found = [];
  for (const word of SUSPICIOUS_WORDS) {
    if (haystack.includes(word)) {
      found.push(word);
    }
  }
  return [...new Set(found)];
}

function detectEncodedRedirect(url) {
  if (!url.search) return false;
  const query = url.search.slice(1);
  const pairs = query.split('&');
  for (const pair of pairs) {
    const eqIdx = pair.indexOf('=');
    if (eqIdx >= 0) {
      const value = pair.slice(eqIdx + 1);
      if (/%[0-9a-fA-F]{2}/.test(value)) {
        try {
          const decoded = decodeURIComponent(value);
          if (decoded.includes('/')) {
            return true;
          }
        } catch {
          // skip invalid percent-encoding
        }
      }
    }
  }
  return false;
}

function detectObfuscation(url, rawInput) {
  const reasons = [];
  const raw = (rawInput || '').trim();
  if (url.hostname && url.hostname.includes('@')) {
    reasons.push('@ symbol in hostname');
  }
  // Detect @ in raw URL before path/query
  if (!url.hostname.includes('@') && raw) {
    const hostMatch = raw.match(/^[a-zA-Z][a-zA-Z0-9+\-.]*:\/\/([^/?#]*)/);
    if (hostMatch && hostMatch[1].includes('@')) {
      reasons.push('@ symbol in hostname');
    }
  }
  if (url.hostname && /%[0-9a-fA-F]{2}/.test(url.hostname)) {
    reasons.push('Percent-encoded characters in hostname');
  }
  // Detect percent-encoding in raw host portion
  if (!/%[0-9a-fA-F]{2}/.test(url.hostname || '') && raw) {
    const hostMatch = raw.match(/^[a-zA-Z][a-zA-Z0-9+\-.]*:\/\/([^/?#]*)/);
    if (hostMatch && /%[0-9a-fA-F]{2}/.test(hostMatch[1])) {
      reasons.push('Percent-encoded characters in hostname');
    }
  }
  if (url.pathname && /%[0-9a-fA-F]{2}/.test(url.pathname)) {
    reasons.push('Percent-encoded characters in pathname');
  }
  if (url.href && /data:|javascript:/i.test(url.href) && !url.href.startsWith(url.protocol)) {
    reasons.push('Potentially dangerous scheme pattern');
  }
  if (url.hostname && /[^\x00-\x7F]/.test(url.hostname)) {
    reasons.push('Non-ASCII characters in hostname');
  }
  return reasons;
}

function analyzeUrl(urlString) {
  const url = parseUrl(urlString);
  if (!url) {
    return {
      score: 0,
      verdict: 'Safe',
      reasons: [],
      domain: null,
      host: null,
      path: null,
      scheme: null,
      error: 'Invalid URL format'
    };
  }

  const reasons = [];
  let score = 0;

  // HTTP
  if (url.protocol === 'http:') {
    score += 8;
    reasons.push({ type: 'http', text: SIGNALS.HTTP.label, impact: 8 });
  }

  // Raw IP
  if (isIp(url.hostname)) {
    score += 45;
    reasons.push({ type: 'ip', text: SIGNALS.RAW_IP.label, impact: 45 });
  }

  // Excessive subdomains
  const subs = subdomainCount(url.hostname);
  if (subs > 4) {
    score += 10;
    reasons.push({ type: 'subdomains', text: `${SIGNALS.EXCESSIVE_SUBDOMAINS.label} (${subs} levels)`, impact: 10 });
  }

  // Long URL
  if (url.href.length > 200) {
    score += 10;
    reasons.push({ type: 'length', text: `${SIGNALS.LONG_URL.label} (${url.href.length} characters)`, impact: 10 });
  }

  // Suspicious words
  const words = detectSuspiciousWords(url.hostname, url.pathname, url.search);
  if (words.length > 0) {
    const wordImpact = Math.min(25, words.length * 5);
    score += wordImpact;
    reasons.push({ type: 'words', text: `${SIGNALS.SUSPICIOUS_WORDS.label}: ${words.slice(0, 3).join(', ')}`, impact: wordImpact });
  }

  // Punycode
  if (url.hostname && url.hostname.split('.').some(part => part.startsWith('xn--'))) {
    score += 20;
    reasons.push({ type: 'punycode', text: SIGNALS.PUNYCODE.label, impact: 20 });
  }

  // Obfuscation
  const obf = detectObfuscation(url, urlString);
  if (obf.length > 0) {
    score += 15;
    reasons.push({ type: 'obfuscation', text: obf.join('; '), impact: 15 });
  }

  // Lookalike
  const look = detectLookalike(url.hostname);
  if (look) {
    score += 25;
    reasons.push({ type: 'lookalike', text: `${SIGNALS.LOOKALIKE.label} (similar to ${look})`, impact: 25 });
  }

  // Suspicious TLD
  const hostLower = (url.hostname || '').toLowerCase();
  const matchedTld = SUSPICIOUS_TLDS.find(tld => hostLower.endsWith(tld));
  if (matchedTld) {
    score += 15;
    reasons.push({ type: 'tld', text: `${SIGNALS.SUSPICIOUS_TLD.label} (${matchedTld})`, impact: 15 });
  }

  // Encoded redirect
  if (detectEncodedRedirect(url)) {
    score += 20;
    reasons.push({ type: 'redirect', text: 'Encoded redirect value detected', impact: 20 });
  }

  // Combined risk signals bonus
  const nonBonusReasons = reasons.filter(r => r.type !== 'combined');
  if (nonBonusReasons.length >= 3) {
    score += 10;
    reasons.push({ type: 'combined', text: 'Multiple risk signals combined', impact: 10 });
  }

  // Cap score
  score = Math.max(0, Math.min(100, score));

  // Verdict
  let verdict = 'Safe';
  if (score >= 70) verdict = 'High Risk';
  else if (score >= 31) verdict = 'Suspicious';

  return {
    score,
    verdict,
    reasons,
    domain: url.hostname,
    host: url.hostname,
    path: url.pathname + url.search,
    scheme: url.protocol.replace(':', ''),
    error: null
  };
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { analyzeUrl, parseUrl, isIp, subdomainCount, levenshtein, detectLookalike, detectSuspiciousWords, detectObfuscation, SIGNALS, SUSPICIOUS_WORDS, TRUSTED_BRANDS, SUSPICIOUS_TLDS };
} else if (typeof window !== 'undefined') {
  window.PearlynkEngine = { analyzeUrl, parseUrl, isIp, subdomainCount, levenshtein, detectLookalike, detectSuspiciousWords, detectObfuscation, SIGNALS, SUSPICIOUS_WORDS, TRUSTED_BRANDS, SUSPICIOUS_TLDS };
}
