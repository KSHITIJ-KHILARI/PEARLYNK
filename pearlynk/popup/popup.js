// Pearlynk popup script

document.addEventListener('DOMContentLoaded', async () => {
  const urlInput = document.getElementById('urlInput');
  const analyzeBtn = document.getElementById('analyzeBtn');
  const currentTabBtn = document.getElementById('currentTabBtn');
  const resultCard = document.getElementById('resultCard');
  const scorePath = document.getElementById('scorePath');
  const scoreValue = document.getElementById('scoreValue');
  const verdictBadge = document.getElementById('verdictBadge');
  const domainText = document.getElementById('domainText');
  const schemeText = document.getElementById('schemeText');
  const pathText = document.getElementById('pathText');
  const hostText = document.getElementById('hostText');
  const reasonsList = document.getElementById('reasonsList');
  const historyList = document.getElementById('historyList');
  const clearHistoryBtn = document.getElementById('clearHistoryBtn');
  const optionsLink = document.getElementById('optionsLink');

  let currentResult = null;

  async function loadHistory() {
    const data = await chrome.storage.local.get('history');
    const history = data.history || [];
    historyList.innerHTML = '';
    for (const item of history.slice(0, 20)) {
      const li = document.createElement('li');
      const urlSpan = document.createElement('span');
      urlSpan.className = 'history-url';
      urlSpan.textContent = item.url || item.domain || '(empty)';
      const scoreSpan = document.createElement('span');
      scoreSpan.className = 'history-score';
      const color = item.verdict === 'High Risk' ? 'var(--high)' : item.verdict === 'Suspicious' ? 'var(--suspicious)' : 'var(--safe)';
      scoreSpan.style.color = color;
      scoreSpan.textContent = `${item.score} ${item.verdict}`;
      li.appendChild(urlSpan);
      li.appendChild(scoreSpan);
      li.addEventListener('click', () => renderResult(item));
      historyList.appendChild(li);
    }
  }

  function renderResult(result) {
    currentResult = result;
    resultCard.classList.remove('hidden');
    scoreValue.textContent = result.score;
    const dash = `${result.score}, 100`;
    scorePath.setAttribute('stroke-dasharray', dash);
    const color = result.verdict === 'High Risk' ? 'var(--high)' : result.verdict === 'Suspicious' ? 'var(--suspicious)' : 'var(--safe)';
    scorePath.style.stroke = color;
    verdictBadge.textContent = result.verdict;
    const verdictKey = result.verdict === 'High Risk' ? 'high' : result.verdict.toLowerCase();
    verdictBadge.className = 'verdict ' + verdictKey;
    domainText.textContent = result.domain || '-';
    schemeText.textContent = result.scheme || '-';
    pathText.textContent = result.path || '-';
    hostText.textContent = result.host || '-';
    reasonsList.innerHTML = '';
    if (result.reasons && result.reasons.length) {
      for (const r of result.reasons) {
        const li = document.createElement('li');
        const textNode = document.createTextNode(r.text || r);
        const badge = document.createElement('span');
        badge.className = 'impact-badge';
        badge.textContent = (r.impact ? `+${r.impact}` : '');
        li.appendChild(textNode);
        li.appendChild(badge);
        reasonsList.appendChild(li);
      }
    } else {
      const li = document.createElement('li');
      li.textContent = 'No suspicious signals detected.';
      reasonsList.appendChild(li);
    }
  }

  async function analyzeUrl(input) {
    if (!input || !input.trim()) {
      renderResult({ score: 0, verdict: 'Safe', reasons: [], domain: '-', error: 'Please enter a URL to analyze.', scheme: '-', path: '-', host: '-' });
      return;
    }
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    let url = input.trim();
    if (input === '__CURRENT_TAB__' && tab && tab.url && !tab.url.startsWith('chrome://') && !tab.url.startsWith('chrome-extension://') && !tab.url.startsWith('about:')) {
      url = tab.url;
    }
    if (!url) return;

    try {
      const result = await chrome.runtime.sendMessage({ action: 'analyzeUrl', url });
      if (result && result.error) {
        renderResult({ score: 0, verdict: 'Safe', reasons: [], domain: url, error: result.error, scheme: '-', path: '-', host: url });
        return;
      }
      renderResult(result);
      const data = await chrome.storage.local.get('history');
      const history = data.history || [];
      history.unshift({ url: result.domain || url, score: result.score, verdict: result.verdict, time: Date.now(), domain: result.domain, host: result.host, path: result.path, scheme: result.scheme, reasons: result.reasons });
      await chrome.storage.local.set({ history: history.slice(0, 100) });
      await loadHistory();
    } catch (e) {
      renderResult({ score: 0, verdict: 'Safe', reasons: [], domain: url, error: 'Analysis failed. Please try again.', scheme: '-', path: '-', host: url });
    }
  }

  analyzeBtn.addEventListener('click', () => analyzeUrl(urlInput.value));
  urlInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') analyzeUrl(urlInput.value); });

  currentTabBtn.addEventListener('click', async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !tab.url) {
      alert('Could not read the current tab URL.');
      return;
    }
    if (tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://') || tab.url.startsWith('about:')) {
      alert('Pearlynk cannot analyze this restricted page.');
      return;
    }
    analyzeUrl('__CURRENT_TAB__');
  });

  clearHistoryBtn.addEventListener('click', async () => {
    await chrome.storage.local.set({ history: [] });
    await loadHistory();
  });

  optionsLink.addEventListener('click', (e) => {
    e.preventDefault();
    if (chrome.runtime.openOptionsPage) {
      chrome.runtime.openOptionsPage();
    } else {
      chrome.tabs.create({ url: chrome.runtime.getURL('options/options.html') });
    }
  });

  await loadHistory();
});
