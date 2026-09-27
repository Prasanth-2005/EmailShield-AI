const dot = document.getElementById('dot');
const msg = document.getElementById('msg');

chrome.runtime.sendMessage({ type: 'EMAILSHIELD_HEALTH' }, (resp) => {
  if (chrome.runtime.lastError || !resp || !resp.ok) {
    dot.classList.add('down');
    msg.textContent = 'Backend not running (localhost:3000)';
    return;
  }
  dot.classList.add('up');
  msg.textContent = 'Backend reachable on localhost:3000';
});
