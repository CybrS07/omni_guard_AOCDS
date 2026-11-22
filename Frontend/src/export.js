/** Helpers to copy / save extracted data (used by the Downloads page). */

export async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text)
    return true
  } catch {
    // clipboard API can be blocked (non-secure origin): fall back to a hidden textarea
    const ta = document.createElement('textarea')
    ta.value = text
    ta.style.position = 'fixed'
    ta.style.opacity = '0'
    document.body.appendChild(ta)
    ta.select()
    let ok = false
    try {
      ok = document.execCommand('copy')
    } catch {
      /* ignore */
    }
    ta.remove()
    return ok
  }
}

const cell = (v) => {
  const s = v == null ? '' : typeof v === 'object' ? JSON.stringify(v) : String(v)
  // quote, and neutralise spreadsheet formulas (=, +, -, @) coming from file names / CVE text
  const safe = /^[=+\-@]/.test(s) ? `'${s}` : s
  return /[",\n\r]/.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe
}

/** rows: array of flat objects -> CSV text (columns = keys of the first row, then any extra keys). */
export function toCsv(rows) {
  const cols = []
  rows.forEach((r) => Object.keys(r).forEach((k) => cols.includes(k) || cols.push(k)))
  return [cols.join(','), ...rows.map((r) => cols.map((c) => cell(r[c])).join(','))].join('\r\n')
}

export function saveFile(name, text, type) {
  const url = URL.createObjectURL(new Blob([text], { type }))
  const a = document.createElement('a')
  a.href = url
  a.download = name
  document.body.appendChild(a)
  a.click()
  a.remove()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

export const stamp = () => new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')
