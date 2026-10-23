const urlInput = document.getElementById('urlInput');
const messageInput = document.getElementById('messageInput');
const analyzeButton = document.getElementById('analyzeButton');
const scanNowButton = document.getElementById('scanNowButton');
const getStartedButton = document.getElementById('getStartedButton');
const viewDemoButton = document.getElementById('viewDemoButton');
const exportButton = document.getElementById('exportButton');
const featureCards = document.querySelectorAll('.feature-card');
const severityBadge = document.getElementById('severityBadge');
const scoreValue = document.getElementById('scoreValue');
const scoreLabel = document.getElementById('scoreLabel');
const riskList = document.getElementById('riskList');
const recommendationText = document.getElementById('recommendationText');

function showAnalysisError(message) {
  severityBadge.textContent = 'Scan unavailable';
  severityBadge.className = 'result-severity moderate';
  scoreValue.textContent = '—';
  scoreLabel.textContent = 'Could not verify this message';
  riskList.replaceChildren();
  const item = document.createElement('li');
  item.textContent = message;
  riskList.appendChild(item);
  recommendationText.textContent = 'Do not treat this message as safe. Check the server and try the scan again.';
  document.querySelector('.score-ring').style.background = 'conic-gradient(var(--warning) 0 50%, rgba(255,255,255,0.08) 50% 100%)';
}

function renderAnalysis(result) {
  severityBadge.textContent = result.severity;
  severityBadge.className = 'result-severity';
  if (result.severity === 'High Risk') {
    severityBadge.classList.add('high');
  } else if (result.severity === 'Moderate Risk') {
    severityBadge.classList.add('moderate');
  } else {
    severityBadge.classList.add('safe');
  }

  scoreValue.textContent = result.score;
  scoreLabel.textContent = result.severity === 'Low Risk'
    ? 'No strong phishing indicators detected'
    : 'Suspicious activity detected';
  riskList.replaceChildren();
  result.findings.forEach((finding) => {
    const item = document.createElement('li');
    item.textContent = finding;
    riskList.appendChild(item);
  });
  recommendationText.textContent = result.recommendation;

  const color = result.severity === 'High Risk'
    ? 'var(--danger)'
    : result.severity === 'Moderate Risk' ? 'var(--warning)' : 'var(--success)';
  const percentage = Math.max(8, Math.min(result.score, 100));
  document.querySelector('.score-ring').style.background =
    `conic-gradient(${color} 0 ${percentage}%, rgba(255,255,255,0.08) ${percentage}% 100%)`;
}

async function evaluateThreat(url, message) {
  analyzeButton.disabled = true;
  analyzeButton.textContent = 'Analyzing...';
  try {
    const response = await fetch('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, message })
    });
    const result = await response.json();
    if (!response.ok) {
      throw new Error(result.error || `Scan failed (${response.status})`);
    }
    renderAnalysis(result);
  } catch (error) {
    showAnalysisError(error.message || 'Unable to reach the PhishGuard analysis service.');
  } finally {
    analyzeButton.disabled = false;
    analyzeButton.textContent = 'Analyze Threat';
  }
}

function handleAnalyze() {
  const url = urlInput.value.trim();
  const message = messageInput.value.trim();

  if (!url && !message) {
    alert('Please enter a URL or a message to scan.');
    return;
  }

  evaluateThreat(url, message);
}

function exportReport() {
  const url = (urlInput.value || '').trim() || 'Not provided';
  const message = (messageInput.value || '').trim() || 'Not provided';
  const severity = severityBadge.textContent || 'Unknown';
  const score = scoreValue.textContent || '0';
  const label = scoreLabel.textContent || 'No label';
  const reasons = [...riskList.querySelectorAll('li')].map((item) => item.textContent.trim());
  const recommendation = recommendationText.textContent || 'No recommendation';

  const report = [
    'PhishGuard Security Report',
    '========================',
    `Timestamp: ${new Date().toLocaleString()}`,
    `URL: ${url}`,
    `Message: ${message}`,
    `Severity: ${severity}`,
    `Score: ${score}%`,
    `Status: ${label}`,
    '',
    'Risk Findings:',
    ...reasons.map((reason, index) => `${index + 1}. ${reason}`),
    '',
    'Recommended Action:',
    recommendation
  ].join('\n');

  const blob = new Blob([report], { type: 'text/plain;charset=utf-8' });
  const blobUrl = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = blobUrl;
  a.download = 'phishguard-report.txt';
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(blobUrl);
}

function runFeatureDemo(type) {
  const demoConfig = {
    url: {
      url: 'https://secure-login-paypal-verify.com/account',
      message: 'Please verify your account now to avoid suspension.'
    },
    email: {
      url: 'https://bank-secure-update.com/login',
      message: 'Urgent action required. Your account will be suspended unless you confirm your identity immediately.'
    },
    risk: {
      url: 'https://support-portal-account.net/confirm',
      message: 'Click here to approve payment and avoid a temporary hold.'
    }
  };

  const selected = demoConfig[type] || demoConfig.url;
  urlInput.value = selected.url;
  messageInput.value = selected.message;

  document.getElementById('scanner').scrollIntoView({ behavior: 'smooth', block: 'start' });
  evaluateThreat(selected.url, selected.message);
}

analyzeButton.addEventListener('click', handleAnalyze);
scanNowButton.addEventListener('click', () => {
  document.getElementById('scanner').scrollIntoView({ behavior: 'smooth', block: 'start' });
  handleAnalyze();
});

getStartedButton.addEventListener('click', () => {
  document.getElementById('scanner').scrollIntoView({ behavior: 'smooth', block: 'start' });
  handleAnalyze();
});

viewDemoButton.addEventListener('click', () => {
  document.getElementById('scanner').scrollIntoView({ behavior: 'smooth', block: 'start' });
  handleAnalyze();
});

featureCards.forEach((card) => {
  card.addEventListener('click', () => {
    runFeatureDemo(card.dataset.demo);
  });
});

exportButton.addEventListener('click', exportReport);

window.addEventListener('DOMContentLoaded', () => {
  evaluateThreat(urlInput.value, messageInput.value);
});
