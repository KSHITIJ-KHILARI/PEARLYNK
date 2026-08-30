// Pearlynk background service worker (Manifest V3)
// Handles tab updates, auto-check, badge updates, and message routing.

const DEFAULT_SETTINGS = {
  autoCheckEnabled: false
};

chrome.runtime.onInstalled.addListener(async () => {
  const data = await chrome.storage.sync.get('settings');
  if (!data.settings) {
    await chrome.storage.sync.set({ settings: DEFAULT_SETTINGS });
  }
  chrome.action.setBadgeText({ text: '' });
});

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== 'complete') return;
  if (!tab.url) return;
  if (tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://') || tab.url.startsWith('about:')) return;

  const { settings } = await chrome.storage.sync.get('settings');
  if (settings && settings.autoCheckEnabled) {
    const result = analyzeUrlSync(tab.url);
    const color = result.verdict === 'High Risk' ? '#dc2626' : result.verdict === 'Suspicious' ? '#f59e0b' : '#10b981';
    chrome.action.setBadgeBackgroundColor({ color });
    chrome.action.setBadgeText({ text: String(result.score) });
    chrome.action.setTitle({
      title: `Pearlynk: ${result.verdict} (${result.score})`
    });
  }
});

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'analyzeUrl') {
    const result = analyzeUrlSync(request.url);
    sendResponse(result);
    return true;
  }
  if (request.action === 'getSettings') {
    chrome.storage.sync.get('settings').then(data => sendResponse({ settings: data.settings || DEFAULT_SETTINGS }));
    return true;
  }
  if (request.action === 'saveSettings') {
    chrome.storage.sync.set({ settings: request.settings }).then(() => sendResponse({ ok: true }));
    return true;
  }
});

function analyzeUrlSync(urlString) {
  const url = parseUrlSw(urlString);
  if (!url) {
    return { score: 0, verdict: 'Safe', reasons: [], domain: null, error: 'Invalid URL' };
  }
  const result = {
    score: 0,
    verdict: 'Safe',
    reasons: [],
    domain: url.hostname,
    host: url.hostname,
    path: url.pathname + url.search,
    scheme: url.protocol.replace(':', ''),
    error: null
  };
  const { score: s, reasons: r, verdict: v } = computeScoreSw(url, urlString);
  result.score = s;
  result.verdict = v;
  result.reasons = r;
  return result;
}

function parseUrlSw(input) {
  let str = (input || '').trim();
  if (!str) return null;
  if (!/^[a-zA-Z][a-zA-Z0-9+\-.]*:\/\//.test(str)) str = 'https://' + str;
  try { return new URL(str); } catch { return null; }
}

function computeScoreSw(url, rawInput) {
  let score = 0;
  const reasons = [];
  const host = (url.hostname || '').toLowerCase();

  if (url.protocol === 'http:') { score += 8; reasons.push({ type: 'http', text: 'Connection is not encrypted (HTTP)', impact: 8 }); }
  if (isIpSw(url.hostname)) { score += 45; reasons.push({ type: 'ip', text: 'Domain is a raw IP address', impact: 45 }); }
  const subs = host.split('.').length - 2;
  if (subs > 4) { score += 10; reasons.push({ type: 'subdomains', text: `Excessive subdomains detected (${subs} levels)`, impact: 10 }); }
  if (url.href.length > 200) { score += 10; reasons.push({ type: 'length', text: `URL is unusually long (${url.href.length} characters)`, impact: 10 }); }

  const words = [];
  const suspicious = ['login','verify','update','secure','account','password','wallet','gift','reward','free','crypto','reset'];
  const decodedSearch = url.search ? decodeURIComponent(url.search) : '';
  const haystack = (host + ' ' + (url.pathname || '') + ' ' + decodedSearch).toLowerCase();
  for (const w of suspicious) { if (haystack.includes(w)) words.push(w); }
  if (words.length) { const imp = Math.min(25, words.length * 5); score += imp; reasons.push({ type: 'words', text: `Suspicious keyword detected in URL: ${words.slice(0,3).join(', ')}`, impact: imp }); }

  if (url.hostname && url.hostname.split('.').some(part => part.startsWith('xn--'))) { score += 20; reasons.push({ type: 'punycode', text: 'Internationalized domain (punycode / xn--) detected', impact: 20 }); }

  const obf = detectObfuscationSw(url, rawInput);
  if (obf.length) { score += 15; reasons.push({ type: 'obfuscation', text: obf.join('; '), impact: 15 }); }

  const brands = [{ key: 'google', label: 'Google' }, { key: 'microsoft', label: 'Microsoft' }, { key: 'apple', label: 'Apple' }, { key: 'paypal', label: 'PayPal' }, { key: 'amazon', label: 'Amazon' }, { key: 'instagram', label: 'Instagram' }, { key: 'facebook', label: 'Facebook' }, { key: 'linkedin', label: 'LinkedIn' }, { key: 'netflix', label: 'Netflix' }];
  const domainPart = host.split('.').slice(0, -1).join('.');
  for (const b of brands) {
    if (domainPart !== b.key && levenshteinSw(domainPart, b.key) >= 1 && levenshteinSw(domainPart, b.key) <= 2) {
      score += 25; reasons.push({ type: 'lookalike', text: `Possible lookalike/typosquatting domain (similar to ${b.label})`, impact: 25 }); break;
    }
  }

  const tlds = ['.xyz','.top','.tk','.ml','.ga','.cf','.gq','.buzz','.monster','.click','.link','.uno','.work','.men','.bid','.date','.loan','.racing','.online','.win','.kim','.cfd','.hair','.skin','.boats','.bond','.autos','.zip','.mov'];
  const mt = tlds.find(t => host.endsWith(t));
  if (mt) { score += 15; reasons.push({ type: 'tld', text: `Suspicious top-level domain (${mt})`, impact: 15 }); }

  if (detectEncodedRedirectSw(url)) {
    score += 20;
    reasons.push({ type: 'redirect', text: 'Encoded redirect value detected', impact: 20 });
  }

  const nonBonusReasons = reasons.filter(r => r.type !== 'combined');
  if (nonBonusReasons.length >= 3) {
    score += 10;
    reasons.push({ type: 'combined', text: 'Multiple risk signals combined', impact: 10 });
  }

  score = Math.max(0, Math.min(100, score));
  let verdict = 'Safe';
  if (score >= 70) verdict = 'High Risk'; else if (score >= 31) verdict = 'Suspicious';
  return { score, reasons, verdict };
}

function isIpSw(host) {
  if (!host) return false;
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(host)) { return host.split('.').every(p => parseInt(p,10) <= 255); }
  return /^[0-9a-fA-F:]+$/.test(host) && host.includes(':');
}

function levenshteinSw(a, b) {
  const m = a.length; const n = b.length;
  const dp = Array.from({length: m+1}, () => Array(n+1).fill(0));
  for (let i=0;i<=m;i++) dp[i][0]=i;
  for (let j=0;j<=n;j++) dp[0][j]=j;
  for (let i=1;i<=m;i++) for (let j=1;j<=n;j++) dp[i][j]=Math.min(dp[i-1][j]+1, dp[i][j-1]+1, dp[i-1][j-1]+(a[i-1]===b[j-1]?0:1));
  return dp[m][n];
}

function detectEncodedRedirectSw(url) {
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

function detectObfuscationSw(url, rawInput) {
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
  if (url.hostname && /[^\x00-\x7F]/.test(url.hostname)) {
    reasons.push('Non-ASCII characters in hostname');
  }
  return reasons;
}
