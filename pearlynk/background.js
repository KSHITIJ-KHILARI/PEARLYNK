// Pearlynk background service worker (Manifest V3)
// Handles tab updates, auto-check, badge updates, and message routing.

try {
  importScripts('src/engine.js');
} catch (e) {
  console.error('Failed to import engine.js in background service worker:', e);
}

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
  if (typeof self !== 'undefined' && self.PearlynkEngine && typeof self.PearlynkEngine.analyzeUrl === 'function') {
    return self.PearlynkEngine.analyzeUrl(urlString);
  }
  return { score: 0, verdict: 'Safe', reasons: [], domain: null, error: 'Engine unavailable' };
}
