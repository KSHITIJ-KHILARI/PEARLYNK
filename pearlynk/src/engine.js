// Pearlynk deterministic URL risk engine
// All analysis is local, synchronous, and deterministic. No network requests.

const SIGNALS = {
  HTTP: { max: 8, label: 'Connection is not encrypted (HTTP)' },
  RAW_IP: { max: 45, label: 'Domain is a raw IP address' },
  EXCESSIVE_SUBDOMAINS: { max: 10, label: 'Excessive subdomains detected' },
  LONG_URL: { max: 10, label: 'URL is unusually long' },
  SUSPICIOUS_WORDS: { max: 35, label: 'Suspicious keyword detected in URL' },
  PUNYCODE: { max: 20, label: 'Internationalized domain (punycode / xn--) detected' },
  OBFUSCATION: { max: 15, label: 'Obfuscated or suspicious URL pattern detected' },
  LOOKALIKE: { max: 25, label: 'Possible lookalike/typosquatting domain' },
  BRAND_IMPERSONATION: { max: 35, label: 'Brand name used in unauthorized domain' },
  SUSPICIOUS_TLD: { max: 15, label: 'Suspicious top-level domain' }
};

const KEYWORD_GROUPS = {
  credential: {
    name: 'credential/account',
    words: [
      'login', 'signin', 'sign-in', 'password', 'passwd', 'passcode',
      'account', 'reset', 'unlock', 'appleid', 'auth', 'oauth',
      'authorize', 'session', 'credential', 'credentials', 'myaccount'
    ]
  },
  urgency: {
    name: 'urgency/verification',
    words: [
      'verify', 'verification', 'confirm', 'confirmation', 'update',
      'activate', 'activation', 'secure', 'security', 'validate',
      'validation', 'required', 'suspended', 'locked', 'restricted',
      'alert', 'notice', 'authenticate', 'authentication'
    ]
  },
  financial: {
    name: 'financial/reward',
    words: [
      'bank', 'banking', 'wallet', 'crypto', 'reward', 'gift',
      'free', 'billing', 'invoice', 'payment', 'payout', 'claim',
      'bonus', 'airdrop', 'funds', 'transfer', 'prize', 'winner'
    ]
  }
};

const SUSPICIOUS_WORDS = [
  ...new Set([
    ...KEYWORD_GROUPS.credential.words,
    ...KEYWORD_GROUPS.urgency.words,
    ...KEYWORD_GROUPS.financial.words
  ])
];

const BRAND_PROFILES = [
  {
    key: 'google',
    label: 'Google',
    domains: [
      'google.com', 'google.co.uk', 'google.ca', 'google.de', 'google.fr',
      'google.com.au', 'google.co.in', 'google.co.jp', 'google.org',
      'youtube.com', 'gmail.com', 'googleapis.com', 'googleusercontent.com', 'gstatic.com'
    ]
  },
  {
    key: 'microsoft',
    label: 'Microsoft',
    domains: [
      'microsoft.com', 'microsoftonline.com', 'live.com', 'office.com',
      'azure.com', 'outlook.com', 'bing.com', 'msn.com', 'windows.com', 'microsoftonline-p.com'
    ]
  },
  {
    key: 'apple',
    label: 'Apple',
    domains: ['apple.com', 'icloud.com', 'me.com']
  },
  {
    key: 'paypal',
    label: 'PayPal',
    domains: ['paypal.com', 'paypal.me']
  },
  {
    key: 'amazon',
    label: 'Amazon',
    domains: [
      'amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.in', 'amazon.co.jp',
      'aws.amazon.com', 'media-amazon.com'
    ]
  },
  {
    key: 'netflix',
    label: 'Netflix',
    domains: ['netflix.com']
  },
  {
    key: 'facebook',
    label: 'Facebook',
    domains: ['facebook.com', 'fb.com', 'messenger.com', 'meta.com']
  },
  {
    key: 'instagram',
    label: 'Instagram',
    domains: ['instagram.com']
  },
  {
    key: 'linkedin',
    label: 'LinkedIn',
    domains: ['linkedin.com']
  },
  {
    key: 'github',
    label: 'GitHub',
    domains: ['github.com', 'github.io', 'githubassets.com', 'githubusercontent.com']
  },
  {
    key: 'chase',
    label: 'Chase Bank',
    domains: ['chase.com']
  },
  {
    key: 'wellsfargo',
    label: 'Wells Fargo',
    domains: ['wellsfargo.com']
  },
  {
    key: 'bankofamerica',
    label: 'Bank of America',
    domains: ['bankofamerica.com']
  },
  {
    key: 'binance',
    label: 'Binance',
    domains: ['binance.com']
  },
  {
    key: 'coinbase',
    label: 'Coinbase',
    domains: ['coinbase.com']
  }
];

const TRUSTED_BRANDS = BRAND_PROFILES.map(b => ({ key: b.key, label: b.label }));

const SUSPICIOUS_TLDS = [
  '.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', '.buzz', '.monster',
  '.cam', '.cfd', '.hair', '.skin', '.boats', '.bond', '.autos',
  '.zip', '.mov', '.click', '.link', '.uno', '.work',
  '.men', '.bid', '.date', '.loan', '.racing', '.online', '.win', '.kim'
];

function parseUrl(input) {
  let str = (input || '').trim();
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

function isLegitimateBrandDomain(host, brand) {
  if (!host) return false;
  const h = host.toLowerCase();
  for (const d of brand.domains) {
    if (h === d || h.endsWith('.' + d)) {
      return true;
    }
  }
  return false;
}

function isTrustedDomain(host) {
  if (!host || isIp(host)) return { trusted: false, brand: null };
  const h = host.toLowerCase();
  for (const brand of BRAND_PROFILES) {
    if (isLegitimateBrandDomain(h, brand)) {
      return { trusted: true, brand: brand.label };
    }
  }
  return { trusted: false, brand: null };
}

function detectLookalike(host) {
  if (!host || isIp(host)) return null;
  const normalized = host.toLowerCase();
  const parts = normalized.split('.');
  const domainPart = parts.slice(0, -1).join('.');
  
  for (const brand of BRAND_PROFILES) {
    if (isLegitimateBrandDomain(normalized, brand)) {
      continue;
    }
    const dist = levenshtein(domainPart, brand.key);
    if (dist >= 1 && dist <= 2 && domainPart !== brand.key) {
      return brand.label;
    }
    // Check individual subdomain parts for lookalike typosquatting
    for (const part of parts) {
      const pDist = levenshtein(part, brand.key);
      if (pDist >= 1 && pDist <= 2 && part !== brand.key && part.length >= brand.key.length - 1) {
        return brand.label;
      }
    }
  }
  return null;
}

function detectBrandImpersonation(host) {
  if (!host || isIp(host)) return null;
  const normalized = host.toLowerCase();

  for (const brand of BRAND_PROFILES) {
    // If the host legitimately belongs to the brand, it's not impersonation
    if (isLegitimateBrandDomain(normalized, brand)) {
      continue;
    }

    // Check if the brand keyword appears in the hostname
    // e.g. "google-login.example.com", "paypal-security.top", "login.google.com.attacker.com"
    const hostTokens = normalized.split(/[\.\-_]+/);
    const hasBrandToken = hostTokens.some(token => token === brand.key || (token.startsWith(brand.key) && token.length > brand.key.length));
    
    if (hasBrandToken || normalized.includes(brand.key + '-') || normalized.includes('-' + brand.key) || normalized.includes('.' + brand.key)) {
      return {
        brand: brand.label,
        key: brand.key
      };
    }
  }
  return null;
}

function extractKeywordsFromText(text) {
  if (!text) return [];
  const normalized = text.toLowerCase().replace(/[^a-z0-9\-_\.]/g, ' ');
  const tokens = normalized.split(/[\s\-_\.]+/);
  const found = new Set();

  for (const groupKey in KEYWORD_GROUPS) {
    const group = KEYWORD_GROUPS[groupKey];
    for (const word of group.words) {
      for (const token of tokens) {
        if (token === word || (token.length > word.length && token.includes(word))) {
          found.add(word);
        }
      }
    }
  }
  return Array.from(found);
}

function getWordCategories(words) {
  const categories = new Set();
  for (const word of words) {
    for (const groupKey in KEYWORD_GROUPS) {
      if (KEYWORD_GROUPS[groupKey].words.includes(word)) {
        categories.add(KEYWORD_GROUPS[groupKey].name);
      }
    }
  }
  return Array.from(categories);
}

function detectSuspiciousWords(host, pathname, search) {
  const decodedSearch = search ? decodeURIComponent(search) : '';
  const haystack = ((host || '') + ' ' + (pathname || '') + ' ' + decodedSearch).toLowerCase();
  return extractKeywordsFromText(haystack);
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
          if (decoded.includes('/') || decoded.startsWith('http://') || decoded.startsWith('https://')) {
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
  if (!url.hostname.includes('@') && raw) {
    const hostMatch = raw.match(/^[a-zA-Z][a-zA-Z0-9+\-.]*:\/\/([^/?#]*)/);
    if (hostMatch && hostMatch[1].includes('@')) {
      reasons.push('@ symbol in hostname');
    }
  }
  if (url.hostname && /%[0-9a-fA-F]{2}/.test(url.hostname)) {
    reasons.push('Percent-encoded characters in hostname');
  }
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
  const host = (url.hostname || '').toLowerCase();
  const trustedCheck = isTrustedDomain(host);

  // 1. Protocol
  if (url.protocol === 'http:') {
    score += 8;
    reasons.push({ type: 'http', text: SIGNALS.HTTP.label, impact: 8 });
  }

  // 2. Raw IP address
  const hasIp = isIp(host);
  if (hasIp) {
    score += 45;
    reasons.push({ type: 'ip', text: SIGNALS.RAW_IP.label, impact: 45 });
  }

  // 3. Subdomain Depth
  const subs = subdomainCount(host);
  if (subs > 4) {
    score += 10;
    reasons.push({
      type: 'subdomains',
      text: `${SIGNALS.EXCESSIVE_SUBDOMAINS.label} (${subs} levels)`,
      impact: 10
    });
  }

  // 4. URL Length
  if (url.href.length > 200) {
    score += 10;
    reasons.push({
      type: 'length',
      text: `${SIGNALS.LONG_URL.label} (${url.href.length} characters)`,
      impact: 10
    });
  }

  // 5. Punycode detection
  const hasPunycode = Boolean(host && host.split('.').some(part => part.startsWith('xn--')));
  if (hasPunycode) {
    score += 20;
    reasons.push({ type: 'punycode', text: SIGNALS.PUNYCODE.label, impact: 20 });
  }

  // 6. Obfuscation detection
  const obf = detectObfuscation(url, urlString);
  if (obf.length > 0) {
    score += 15;
    reasons.push({ type: 'obfuscation', text: obf.join('; '), impact: 15 });
  }

  // 7. Lookalike / Typosquatting
  const lookalike = detectLookalike(host);
  if (lookalike) {
    score += 25;
    reasons.push({
      type: 'lookalike',
      text: `${SIGNALS.LOOKALIKE.label} (similar to ${lookalike})`,
      impact: 25
    });
  }

  // 8. Brand Impersonation in Hostname (e.g. google-login.example.com)
  const impersonation = detectBrandImpersonation(host);
  if (impersonation) {
    score += 30;
    reasons.push({
      type: 'impersonation',
      text: `Brand name (${impersonation.brand}) used in unauthorized domain (${host})`,
      impact: 30
    });
  }

  // 9. Suspicious Top-Level Domain (TLD)
  const matchedTld = SUSPICIOUS_TLDS.find(tld => host.endsWith(tld));
  if (matchedTld) {
    score += 15;
    reasons.push({
      type: 'tld',
      text: `${SIGNALS.SUSPICIOUS_TLD.label} (${matchedTld})`,
      impact: 15
    });
  }

  // 10. Encoded Redirect Detection
  if (detectEncodedRedirect(url)) {
    score += 20;
    reasons.push({
      type: 'redirect',
      text: 'Encoded redirect value detected in query parameters',
      impact: 20
    });
  }

  // 11. Context-Aware Keyword Scoring
  // Separate hostname keywords from path/query keywords
  const hostKeywords = extractKeywordsFromText(host);
  const decodedSearch = url.search ? decodeURIComponent(url.search) : '';
  const pathAndSearch = (url.pathname || '') + ' ' + decodedSearch;
  const pathKeywords = extractKeywordsFromText(pathAndSearch);
  const allKeywords = [...new Set([...hostKeywords, ...pathKeywords])];
  const categoriesMatched = getWordCategories(allKeywords);

  // If the host is legitimately trusted (e.g., accounts.google.com, github.com, paypal.com),
  // legitimate login/account/verify words are expected and not penalized.
  if (!trustedCheck.trusted && allKeywords.length > 0) {
    // (a) Hostname keyword scoring (Heavier weight)
    if (hostKeywords.length > 0) {
      let hostImpact = 12;
      if (hostKeywords.length === 2) hostImpact = 25;
      else if (hostKeywords.length >= 3) hostImpact = 35;

      score += hostImpact;
      reasons.push({
        type: 'host_keywords',
        text: `Phishing/credential keyword(s) in hostname: ${hostKeywords.join(', ')}`,
        impact: hostImpact
      });
    }

    // (b) Path/Query keyword scoring (Contextual weight)
    const uniquePathWords = pathKeywords.filter(w => !hostKeywords.includes(w));
    if (uniquePathWords.length > 0 || (hostKeywords.length === 0 && pathKeywords.length > 0)) {
      const activePathWords = uniquePathWords.length > 0 ? uniquePathWords : pathKeywords;
      let pathImpact = 5; // 1 word in path is low risk (e.g. /login on clean domain)
      if (activePathWords.length === 2) pathImpact = 12;
      else if (activePathWords.length >= 3) pathImpact = 20;

      score += pathImpact;
      reasons.push({
        type: 'words',
        text: `Suspicious keyword(s) detected in URL: ${activePathWords.slice(0, 4).join(', ')}`,
        impact: pathImpact
      });
    }

    // (c) Cross-category combination bonus (e.g. Credential + Urgency)
    if (categoriesMatched.length >= 2) {
      score += 15;
      reasons.push({
        type: 'keyword_category_combo',
        text: `Multiple phishing concepts combined (${categoriesMatched.join(' + ')})`,
        impact: 15
      });
    }

    // (d) Hostname + Path distribution bonus
    if (hostKeywords.length > 0 && uniquePathWords.length > 0) {
      score += 10;
      reasons.push({
        type: 'host_path_combo',
        text: 'Suspicious keywords distributed across both hostname and path',
        impact: 10
      });
    }

    // (e) Keywords + Suspicious TLD bonus
    if (matchedTld) {
      score += 15;
      reasons.push({
        type: 'tld_keyword_combo',
        text: `Phishing keywords combined with suspicious top-level domain (${matchedTld})`,
        impact: 15
      });
    }

    // (f) Keywords + Raw IP bonus
    if (hasIp) {
      score += 20;
      reasons.push({
        type: 'ip_keyword_combo',
        text: 'Phishing keywords hosted on an unverified raw IP address',
        impact: 20
      });
    }

    // (g) Keywords + Unencrypted HTTP bonus
    if (url.protocol === 'http:') {
      score += 10;
      reasons.push({
        type: 'http_keyword_combo',
        text: 'Unencrypted HTTP connection soliciting sensitive actions',
        impact: 10
      });
    }

    // (h) Brand Impersonation + Credential/Urgency Keywords bonus
    if (impersonation) {
      score += 15;
      reasons.push({
        type: 'impersonation_keyword_combo',
        text: `Brand impersonation (${impersonation.brand}) soliciting credential or account actions`,
        impact: 15
      });
    }

    // (i) Obfuscation + Keywords bonus
    if (obf.length > 0) {
      score += 15;
      reasons.push({
        type: 'obfuscation_keyword_combo',
        text: 'URL obfuscation combined with credential harvesting signals',
        impact: 15
      });
    }
  }

  // 12. Cross-Signal Non-Keyword Dangerous Combinations
  if (impersonation && matchedTld) {
    score += 15;
    reasons.push({
      type: 'impersonation_tld_combo',
      text: `Brand impersonation (${impersonation.brand}) targeted on suspicious top-level domain (${matchedTld})`,
      impact: 15
    });
  }

  if (lookalike && matchedTld) {
    score += 15;
    reasons.push({
      type: 'lookalike_tld_combo',
      text: `Lookalike domain (${lookalike}) registered on suspicious top-level domain (${matchedTld})`,
      impact: 15
    });
  }

  if (hasPunycode && (impersonation || lookalike)) {
    score += 15;
    reasons.push({
      type: 'punycode_deception_combo',
      text: 'Punycode internationalized domain attempting brand deception',
      impact: 15
    });
  }

  // 13. Combined Signals General Bonus
  const primarySignals = reasons.filter(r => !r.type.includes('combo') && r.type !== 'combined');
  if (primarySignals.length >= 3) {
    score += 10;
    reasons.push({
      type: 'combined',
      text: 'Multiple independent risk signals combined',
      impact: 10
    });
  }

  // 14. Severe Signal Verdict Floors
  let verdictFloor = null;

  if (hasIp && allKeywords.length >= 1) {
    verdictFloor = 'High Risk';
  } else if (impersonation && matchedTld) {
    verdictFloor = 'High Risk';
  } else if (impersonation && (hostKeywords.length >= 1 || pathKeywords.length >= 1)) {
    verdictFloor = 'High Risk';
  } else if (hasPunycode && (impersonation || lookalike)) {
    verdictFloor = 'High Risk';
  } else if (obf.length > 0 && allKeywords.length >= 1) {
    verdictFloor = 'High Risk';
  } else if (hostKeywords.length >= 3) {
    verdictFloor = 'High Risk';
  } else if (lookalike && matchedTld) {
    verdictFloor = 'High Risk';
  } else if (hostKeywords.length >= 2) {
    verdictFloor = 'Suspicious';
  } else if (impersonation) {
    verdictFloor = 'Suspicious';
  } else if (hasIp) {
    verdictFloor = 'Suspicious';
  } else if (categoriesMatched.length >= 2 && allKeywords.length >= 2) {
    verdictFloor = 'Suspicious';
  }

  // Apply verdict floor to score ensuring alignment
  if (verdictFloor === 'High Risk') {
    score = Math.max(70, score);
  } else if (verdictFloor === 'Suspicious') {
    score = Math.max(35, score);
  }

  // Cap score between 0 and 100
  score = Math.max(0, Math.min(100, score));

  // Determine final verdict based on score and severe floors
  let verdict = 'Safe';
  if (score >= 70 || verdictFloor === 'High Risk') {
    verdict = 'High Risk';
  } else if (score >= 31 || verdictFloor === 'Suspicious') {
    verdict = 'Suspicious';
  }

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
  module.exports = {
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
  };
} else if (typeof window !== 'undefined') {
  window.PearlynkEngine = {
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
  };
} else if (typeof self !== 'undefined') {
  self.PearlynkEngine = {
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
  };
}
