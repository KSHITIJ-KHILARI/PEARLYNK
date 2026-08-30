document.addEventListener('DOMContentLoaded', async () => {
  const toggle = document.getElementById('autoCheckToggle');
  const { settings } = await chrome.storage.sync.get('settings');
  if (settings && settings.autoCheckEnabled !== undefined) {
    toggle.checked = settings.autoCheckEnabled;
  }
  toggle.addEventListener('change', async () => {
    const { settings } = await chrome.storage.sync.get('settings');
    const next = { ...settings, autoCheckEnabled: toggle.checked };
    await chrome.storage.sync.set({ settings: next });
  });
});
