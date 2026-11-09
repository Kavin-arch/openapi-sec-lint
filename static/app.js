const form = document.querySelector('#scan-form');
const fileInput = document.querySelector('#spec-file');
const fileLabel = document.querySelector('#file-label');
const formError = document.querySelector('#form-error');
const submitButton = document.querySelector('#submit-button');
const resultSection = document.querySelector('#result-section');
const historyList = document.querySelector('#history-list');
const findingsList = document.querySelector('#findings-list');
let selectedFile = null;
let activeScan = null;
let findingPage = 0;
const FINDINGS_PER_PAGE = 50;

fileInput.addEventListener('change', () => {
  selectedFile = fileInput.files?.[0] || null;
  fileLabel.textContent = selectedFile ? selectedFile.name : 'Choose a JSON or YAML file';
  formError.hidden = true;
});

document.querySelector('#sample-button').addEventListener('click', async () => {
  const button = document.querySelector('#sample-button');
  button.disabled = true;
  try {
    const response = await fetch('/api/v1/sample-spec');
    if (!response.ok) throw new Error('Could not load the sample specification.');
    selectedFile = new File([await response.blob()], 'sample-openapi.yaml', { type: 'text/yaml' });
    fileLabel.textContent = selectedFile.name;
    formError.hidden = true;
  } catch (error) {
    showError(error.message || 'Could not load the sample specification.');
  } finally {
    button.disabled = false;
  }
});

const dropZone = document.querySelector('#file-drop');
for (const eventName of ['dragenter', 'dragover']) {
  dropZone.addEventListener(eventName, (event) => { event.preventDefault(); dropZone.classList.add('dragover'); });
}
for (const eventName of ['dragleave', 'drop']) {
  dropZone.addEventListener(eventName, (event) => { event.preventDefault(); dropZone.classList.remove('dragover'); });
}
dropZone.addEventListener('drop', (event) => {
  const file = event.dataTransfer?.files?.[0];
  if (file) {
    selectedFile = file;
    fileLabel.textContent = file.name;
    formError.hidden = true;
  }
});

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  formError.hidden = true;
  if (!selectedFile) return showError('Choose an OpenAPI or Swagger file first.');
  if (selectedFile.size > 16 * 1024 * 1024) return showError('The file is larger than the 16 MB limit.');
  if (!/\.(json|ya?ml)$/i.test(selectedFile.name)) return showError('Choose a .json, .yaml, or .yml file.');

  submitButton.disabled = true;
  submitButton.firstElementChild.textContent = 'Reading specification…';
  try {
    const specText = await selectedFile.text();
    const response = await fetch('/api/v1/scans', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: document.querySelector('#scan-name').value,
        target_url: document.querySelector('#target-url').value,
        filename: selectedFile.name,
        spec_text: specText,
      }),
    });
    const payload = await response.json();
    if (!response.ok) throw new Error(formatApiError(payload.detail));
    resultSection.hidden = false;
    document.querySelector('#result-title').textContent = payload.name;
    document.querySelector('#scan-message').textContent = 'Queued. Analyzing the uploaded definition locally…';
    resultSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    await pollScan(payload.id);
    await refreshHistory();
  } catch (error) {
    showError(error.message || 'Could not create the scan.');
  } finally {
    submitButton.disabled = false;
    submitButton.firstElementChild.textContent = 'Analyze specification';
  }
});

function formatApiError(detail) {
  if (Array.isArray(detail)) return detail.map((item) => item.msg).join(' ');
  return typeof detail === 'string' ? detail : 'The request could not be processed.';
}

function showError(message) {
  formError.textContent = message;
  formError.hidden = false;
}

async function pollScan(id) {
  let delay = 150;
  for (let attempt = 0; attempt < 120; attempt += 1) {
    const response = await fetch(`/api/v1/scans/${encodeURIComponent(id)}`);
    if (!response.ok) throw new Error('Could not load scan status.');
    const scan = await response.json();
    renderScan(scan);
    if (scan.status === 'completed' || scan.status === 'failed') return;
    await new Promise((resolve) => setTimeout(resolve, delay));
    delay = Math.min(900, delay * 2);
  }
  document.querySelector('#scan-message').textContent = 'Still working. You can return to this report from Recent scans.';
}

function renderScan(scan) {
  if (activeScan?.id !== scan.id) findingPage = 0;
  activeScan = scan;
  resultSection.hidden = false;
  document.querySelector('#result-title').textContent = scan.name;
  const status = document.querySelector('#status-badge');
  status.textContent = scan.status;
  status.className = `status-badge ${scan.status}`;
  const summary = scan.summary || {};
  const severityTiles = ['critical', 'high', 'medium', 'low', 'info'];
  document.querySelector('#scan-summary').innerHTML = [
    ['findings', summary.findings ?? '—'], ['operations', summary.operations ?? '—'],
    ...severityTiles.map((level) => [level, summary[level] ?? 0]),
  ].map(([label, value]) => `<div class="summary-tile"><strong>${escapeHtml(String(value))}</strong><span>${escapeHtml(label)}</span></div>`).join('');

  const message = document.querySelector('#scan-message');
  if (scan.status === 'failed') message.textContent = scan.error || 'The scan could not be completed.';
  else if (scan.status === 'completed') message.textContent = `Analyzed ${summary.operations ?? 0} operations in ${scan.spec_filename}. No requests were sent to ${scan.target_url}. SHA-256: ${scan.spec_sha256 || 'unavailable'}`;
  else message.textContent = 'Queued. Analyzing the uploaded definition locally…';

  document.querySelector('#export-links').hidden = scan.status !== 'completed';
  document.querySelector('#export-links').innerHTML = scan.status === 'completed'
    ? ['json', 'sarif', 'md'].map((format) => `<a href="/api/v1/scans/${encodeURIComponent(scan.id)}/export?format=${format}" download>Download ${format.toUpperCase()}</a>`).join('')
    : '';
  const findings = scan.findings || [];
  document.querySelector('#finding-controls').hidden = findings.length === 0;
  renderFindings(findings);
}

function renderFindings(findings) {
  const pagination = document.querySelector('#finding-pagination');
  if (!findings.length) {
    pagination.hidden = true;
    pagination.replaceChildren();
    findingsList.innerHTML = activeScan?.status === 'completed'
      ? '<div class="empty-findings">No findings from the included checks. This does not establish that the live API is secure.</div>'
      : '';
    return;
  }
  const severity = document.querySelector('#filter-severity').value;
  const confidence = document.querySelector('#filter-confidence').value;
  const rule = document.querySelector('#filter-rule').value.trim().toLowerCase();
  const endpoint = document.querySelector('#filter-endpoint').value.trim().toLowerCase();
  const filtered = findings.filter((finding) => {
    if (severity && finding.severity !== severity) return false;
    if (confidence && finding.confidence !== confidence) return false;
    if (rule && !finding.rule_id.toLowerCase().includes(rule)) return false;
    if (endpoint && !(finding.affected_operations || []).some((operation) => operation.toLowerCase().includes(endpoint))) return false;
    return true;
  });
  if (!filtered.length) {
    pagination.hidden = true;
    pagination.replaceChildren();
    findingsList.innerHTML = '<div class="empty-findings">No findings match these filters.</div>';
    return;
  }
  const pageCount = Math.ceil(filtered.length / FINDINGS_PER_PAGE);
  findingPage = Math.max(0, Math.min(findingPage, pageCount - 1));
  const start = findingPage * FINDINGS_PER_PAGE;
  const pageFindings = filtered.slice(start, start + FINDINGS_PER_PAGE);
  findingsList.innerHTML = pageFindings.map((finding) => {
    const ops = finding.affected_operations?.length ? `<div class="operations">${finding.affected_operations.map(escapeHtml).join('<br>')}</div>` : '';
    const evidence = finding.evidence || {};
    const details = evidence.servers || evidence.schema_fields || evidence.fields || evidence.issues || evidence.parameters;
    const evidenceHtml = details?.length ? `<div class="operations">${details.map(escapeHtml).join('<br>')}</div>` : '';
    const pointers = evidence.json_pointers;
    const pointerHtml = pointers?.length ? `<div class="operations pointer-list"><strong>Specification locations</strong><br>${pointers.map(escapeHtml).join('<br>')}</div>` : '';
    let truncation = '';
    if (evidence.truncated) {
      const shown = Math.min(Number(evidence.total_matches) || 100, pointers?.length || details?.length || 100);
      const total = Number(evidence.total_matches);
      truncation = `<span class="truncation-badge">${total > 0 ? `Showing ${shown} of ${total} affected entries` : `Showing the first ${shown} affected entries`}</span>`;
    }
    return `<article class="finding"><div class="finding-top"><span class="severity ${escapeHtml(finding.severity)}">${escapeHtml(finding.severity)}</span><span class="rule-id">${escapeHtml(finding.rule_id)}</span><span class="confidence">${escapeHtml(finding.confidence)} confidence</span></div><h3>${escapeHtml(finding.title)}</h3><p>${escapeHtml(finding.summary)}</p><p><strong>Potential impact:</strong> ${escapeHtml(finding.impact)}</p><p class="remediation"><strong>Suggested review:</strong> ${escapeHtml(finding.remediation)}</p>${truncation}${ops}${evidenceHtml}${pointerHtml}</article>`;
  }).join('');
  pagination.hidden = filtered.length <= FINDINGS_PER_PAGE;
  pagination.replaceChildren();
  if (filtered.length > FINDINGS_PER_PAGE) {
    const summary = document.createElement('span');
    summary.textContent = `Showing ${start + 1}–${Math.min(start + FINDINGS_PER_PAGE, filtered.length)} of ${filtered.length} findings`;
    const previous = document.createElement('button');
    previous.type = 'button';
    previous.textContent = 'Previous';
    previous.disabled = findingPage === 0;
    previous.addEventListener('click', () => { findingPage -= 1; renderFindings(activeScan?.findings || []); });
    const next = document.createElement('button');
    next.type = 'button';
    next.textContent = 'Next';
    next.disabled = findingPage >= pageCount - 1;
    next.addEventListener('click', () => { findingPage += 1; renderFindings(activeScan?.findings || []); });
    pagination.append(summary, previous, next);
  }
}

for (const id of ['filter-severity', 'filter-confidence', 'filter-rule', 'filter-endpoint']) {
  const applyFilter = () => { findingPage = 0; renderFindings(activeScan?.findings || []); };
  document.querySelector(`#${id}`).addEventListener('input', applyFilter);
  document.querySelector(`#${id}`).addEventListener('change', applyFilter);
}

async function refreshHistory() {
  try {
    const response = await fetch('/api/v1/scans?limit=50');
    if (!response.ok) return;
    const payload = await response.json();
    if (!payload.items.length) {
      historyList.innerHTML = '<div class="empty-state">Your scan reports will appear here.</div>';
      return;
    }
    historyList.innerHTML = payload.items.map((scan) => `<div class="history-row"><button class="history-open" type="button" data-id="${escapeHtml(scan.id)}"><span class="history-name"><strong>${escapeHtml(scan.name)}</strong><small>${escapeHtml(scan.target_url)} · ${escapeHtml(new Date(scan.created_at).toLocaleString())}</small></span><span class="history-count">${escapeHtml(String(scan.summary?.findings ?? '—'))} findings</span><span class="history-status">${escapeHtml(scan.status)}</span></button><button class="history-delete" type="button" data-id="${escapeHtml(scan.id)}" aria-label="Delete ${escapeHtml(scan.name)}" title="${['queued', 'running'].includes(scan.status) ? 'Cancel and delete this scan' : 'Delete this scan'}">${['queued', 'running'].includes(scan.status) ? 'Cancel' : 'Delete'}</button></div>`).join('');
    historyList.querySelectorAll('.history-open').forEach((button) => button.addEventListener('click', () => loadScan(button.dataset.id)));
    historyList.querySelectorAll('.history-delete').forEach((button) => button.addEventListener('click', () => deleteHistoryItem(button.dataset.id)));
  } catch { /* Keep the current history visible if the network is temporarily unavailable. */ }
}

async function loadScan(id) {
  const response = await fetch(`/api/v1/scans/${encodeURIComponent(id)}`);
  if (!response.ok) return;
  renderScan(await response.json());
  resultSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

async function deleteHistoryItem(id) {
  const response = await fetch(`/api/v1/scans/${encodeURIComponent(id)}`, { method: 'DELETE' });
  if (!response.ok && response.status !== 404) return showError('Could not delete this scan.');
  if (activeScan?.id === id) {
    activeScan = null;
    resultSection.hidden = true;
  }
  await refreshHistory();
}

document.querySelector('#clear-history-button').addEventListener('click', async () => {
  if (!window.confirm('Delete all scan history? This cannot be undone.')) return;
  const response = await fetch('/api/v1/scans', { method: 'DELETE' });
  if (response.status === 409) return showError('Cancel queued or running scans before clearing all history.');
  if (!response.ok) return showError('Could not clear scan history.');
  activeScan = null;
  resultSection.hidden = true;
  await refreshHistory();
});

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]);
}

document.querySelector('#refresh-button').addEventListener('click', refreshHistory);
refreshHistory();
loadCheckCount();

async function loadCheckCount() {
  try {
    const response = await fetch('/health');
    if (!response.ok) return;
    const health = await response.json();
    if (Number.isInteger(health.checks)) {
      document.querySelector('#check-count').textContent = String(health.checks);
    }
  } catch { /* Keep the static count visible if the health request is unavailable. */ }
}
