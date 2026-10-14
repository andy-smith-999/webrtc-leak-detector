/**
 * Minimal DOM helpers for rendering detector results.
 * Brand-neutral: no product marketing copy.
 */

/**
 * @param {import('./detector.js').DetectorResult} result
 * @returns {{ title: string, tone: 'ok' | 'warn' | 'danger' | 'muted', description: string }}
 */
export function verdictPresentation(result) {
  switch (result.verdict) {
    case 'potential_leak':
      return {
        title: 'Potential WebRTC Leak',
        tone: 'danger',
        description: result.summary
      }
    case 'local_only':
      return {
        title: 'Local / mDNS Only',
        tone: 'warn',
        description: result.summary
      }
    case 'relay_only':
      return {
        title: 'Relay Candidates Only',
        tone: 'ok',
        description: result.summary
      }
    case 'no_public_mismatch':
      return {
        title: 'No Public IP Mismatch',
        tone: 'ok',
        description: result.summary
      }
    case 'no_candidates':
      return {
        title: 'No Candidates Found',
        tone: 'ok',
        description: result.summary
      }
    case 'unsupported':
      return {
        title: 'WebRTC Unsupported',
        tone: 'muted',
        description: result.summary
      }
    default:
      return {
        title: 'Idle',
        tone: 'muted',
        description: result.summary || ''
      }
  }
}

/**
 * @param {HTMLElement} root
 * @param {import('./detector.js').DetectorResult} result
 */
export function renderResult(root, result) {
  const view = verdictPresentation(result)
  const toneClass = {
    ok: 'tone-ok',
    warn: 'tone-warn',
    danger: 'tone-danger',
    muted: 'tone-muted'
  }[view.tone]

  const list = (items) =>
    items.length
      ? `<ul class="mono-list">${items.map((i) => `<li><code>${escapeHtml(i)}</code></li>`).join('')}</ul>`
      : '<p class="muted">None</p>'

  const candidateRows = result.candidates.length
    ? `<table class="cand-table">
        <thead>
          <tr>
            <th>Type</th>
            <th>Address</th>
            <th>Kind</th>
            <th>Proto</th>
            <th>Port</th>
          </tr>
        </thead>
        <tbody>
          ${result.candidates
            .map(
              (c) => `<tr>
              <td><code>${escapeHtml(c.type)}</code></td>
              <td><code>${escapeHtml(c.address)}</code></td>
              <td>${escapeHtml(c.addressKind)}</td>
              <td>${escapeHtml(c.protocol || '—')}</td>
              <td>${c.port || '—'}</td>
            </tr>`
            )
            .join('')}
        </tbody>
      </table>`
    : '<p class="muted">No candidates to display.</p>'

  root.innerHTML = `
    <div class="banner ${toneClass}">
      <h2>${escapeHtml(view.title)}</h2>
      <p>${escapeHtml(view.description)}</p>
    </div>

    <div class="grid">
      <section>
        <h3>HTTP egress IP</h3>
        <p class="hint">Optional lookup used only for comparison.</p>
        <p class="mono">${escapeHtml(result.httpEgressIp || 'Not provided')}</p>
      </section>
      <section>
        <h3>Candidate type counts</h3>
        <p class="mono">${escapeHtml(
          Object.entries(result.typeCounts)
            .map(([k, v]) => `${k}: ${v}`)
            .join(' · ')
        )}</p>
      </section>
      <section>
        <h3>Public IPs (WebRTC)</h3>
        ${list(result.publicIps)}
      </section>
      <section>
        <h3>Mismatched public IPs</h3>
        ${list(result.mismatchedPublicIps)}
      </section>
      <section>
        <h3>Private / local IPs</h3>
        ${list(result.privateIps)}
      </section>
      <section>
        <h3>mDNS hostnames</h3>
        ${list(result.mdnsHostnames)}
      </section>
    </div>

    <section class="block">
      <h3>ICE candidates</h3>
      ${candidateRows}
    </section>

    <section class="block notes">
      <h3>Limitations & privacy</h3>
      <ul>
        ${result.notes.map((n) => `<li>${escapeHtml(n)}</li>`).join('')}
      </ul>
    </section>
  `
}

/**
 * @param {string} value
 * @returns {string}
 */
function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}
