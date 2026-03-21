'use client';
import { useState } from 'react';

const FIELDS = {
  protocol: {
    label: 'Security protocol',
    options: [
      { value: 'wpa3', label: 'WPA3' },
      { value: 'wpa2', label: 'WPA2-AES' },
      { value: 'wpa2tkip', label: 'WPA2-TKIP' },
      { value: 'wpa', label: 'WPA (original)' },
      { value: 'wep', label: 'WEP' },
      { value: 'open', label: 'Open (no password)' },
    ],
  },
  band: {
    label: 'Router band',
    options: [
      { value: '5ghz', label: '5 GHz' },
      { value: '24ghz', label: '2.4 GHz' },
      { value: 'dual', label: 'Dual band' },
    ],
  },
  password_length: {
    label: 'Password length',
    options: [
      { value: '20+', label: '20+ characters' },
      { value: '12-19', label: '12–19 characters' },
      { value: '8-11', label: '8–11 characters' },
      { value: '<8', label: 'Under 8 characters' },
    ],
  },
  ssid_visibility: {
    label: 'Network name (SSID)',
    options: [
      { value: 'hidden', label: 'Hidden' },
      { value: 'visible', label: 'Visible (custom name)' },
      { value: 'default', label: 'Default router name' },
    ],
  },
  firewall: {
    label: 'Firewall',
    options: [
      { value: 'yes', label: 'Enabled' },
      { value: 'no', label: 'Disabled' },
      { value: 'unknown', label: "Don't know" },
    ],
  },
  remote_management: {
    label: 'Remote management',
    options: [
      { value: 'no', label: 'Disabled' },
      { value: 'yes', label: 'Enabled' },
      { value: 'unknown', label: "Don't know" },
    ],
  },
  guest_network: {
    label: 'Guest network',
    options: [
      { value: 'isolated', label: 'Enabled & isolated' },
      { value: 'yes', label: 'Enabled, not isolated' },
      { value: 'no', label: 'Disabled' },
    ],
  },
  firmware: {
    label: 'Router firmware',
    options: [
      { value: 'recent', label: 'Updated recently' },
      { value: 'old', label: 'Not updated in 1+ year' },
      { value: 'unknown', label: 'Never updated / unknown' },
    ],
  },
};

const SEV_STYLES: Record<string, { bg: string; text: string; label: string; bar: string }> = {
  critical: { bg: 'bg-red-50',    text: 'text-red-700',    label: 'Critical', bar: 'bg-red-500' },
  warning:  { bg: 'bg-amber-50',  text: 'text-amber-700',  label: 'Warning',  bar: 'bg-amber-400' },
  notice:   { bg: 'bg-blue-50',   text: 'text-blue-700',   label: 'Notice',   bar: 'bg-blue-400' },
  pass:     { bg: 'bg-green-50',  text: 'text-green-700',  label: 'Pass',     bar: 'bg-green-500' },
};

type Finding = { severity: string; title: string; description: string; recommendation: string };
type AuditResult = { score: number; grade: string; findings: Finding[]; scan_performed: boolean };

const defaultForm = Object.fromEntries(
  Object.entries(FIELDS).map(([k, v]) => [k, v.options[1]?.value ?? v.options[0].value])
);

export default function Home() {
  const [form, setForm] = useState<Record<string, string>>(defaultForm);
  const [result, setResult] = useState<AuditResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  async function runAudit() {
    setLoading(true);
    setError('');
    setResult(null);
    try {
      const res = await fetch('http://127.0.0.1:8000/audit/manual', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(form),
      });
      if (!res.ok) throw new Error(`Server error: ${res.status}`);
      setResult(await res.json());
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Could not reach backend. Is it running?');
    } finally {
      setLoading(false);
    }
  }

  const scoreColor = result
    ? result.score >= 80 ? '#16a34a' : result.score >= 55 ? '#d97706' : '#dc2626'
    : '#94a3b8';

  const criticals = result?.findings.filter(f => f.severity === 'critical').length ?? 0;
  const warnings  = result?.findings.filter(f => f.severity === 'warning').length ?? 0;
  const passes    = result?.findings.filter(f => f.severity === 'pass').length ?? 0;

  return (
    <main className="min-h-screen bg-gray-950 text-gray-100" style={{ fontFamily: "'DM Sans', sans-serif" }}>
      <link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600&family=DM+Mono:wght@400;500&display=swap" rel="stylesheet" />

      {/* Header */}
      <div className="border-b border-gray-800 px-6 py-4 flex items-center gap-3">
        <div className="w-7 h-7 rounded-md bg-emerald-500 flex items-center justify-center">
          <svg width="14" height="14" fill="none" stroke="white" strokeWidth="2" viewBox="0 0 24 24">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          </svg>
        </div>
        <span className="font-semibold text-white tracking-tight">NetGuard</span>
        <span className="ml-auto text-xs text-gray-500 font-mono">Wi-Fi Security Auditor</span>
      </div>

      <div className="max-w-5xl mx-auto px-6 py-10 grid grid-cols-1 lg:grid-cols-2 gap-8">

        {/* Left — form */}
        <div>
          <h1 className="text-2xl font-semibold text-white mb-1">Audit your network</h1>
          <p className="text-sm text-gray-400 mb-7">Answer 8 questions about your router setup and get an instant security score.</p>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-6">
            {Object.entries(FIELDS).map(([key, field]) => (
              <div key={key}>
                <label className="block text-xs font-medium text-gray-400 mb-1.5 uppercase tracking-wide">
                  {field.label}
                </label>
                <select
                  value={form[key]}
                  onChange={e => setForm(f => ({ ...f, [key]: e.target.value }))}
                  className="w-full bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-100 focus:outline-none focus:border-emerald-500 transition-colors"
                >
                  {field.options.map(o => (
                    <option key={o.value} value={o.value}>{o.label}</option>
                  ))}
                </select>
              </div>
            ))}
          </div>

          <button
            onClick={runAudit}
            disabled={loading}
            className="w-full bg-emerald-500 hover:bg-emerald-400 disabled:opacity-50 text-gray-950 font-semibold text-sm py-3 rounded-lg transition-colors"
          >
            {loading ? 'Scanning...' : 'Run audit'}
          </button>

          {error && (
            <div className="mt-4 bg-red-950 border border-red-800 rounded-lg px-4 py-3 text-sm text-red-300">
              {error}
            </div>
          )}
        </div>

        {/* Right — results */}
        <div>
          {!result && !loading && (
            <div className="h-full flex items-center justify-center text-center text-gray-600 border border-dashed border-gray-800 rounded-xl p-10">
              <div>
                <div className="text-4xl mb-3">🛡</div>
                <p className="text-sm">Fill in your network config<br />and run the audit to see results.</p>
              </div>
            </div>
          )}

          {loading && (
            <div className="h-full flex items-center justify-center text-emerald-400 text-sm">
              Analysing your network...
            </div>
          )}

          {result && (
            <div className="space-y-4">
              {/* Score card */}
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 flex items-center gap-5">
                <div
                  className="w-20 h-20 rounded-full flex flex-col items-center justify-center flex-shrink-0 border-4"
                  style={{ borderColor: scoreColor }}
                >
                  <span className="text-2xl font-semibold" style={{ color: scoreColor }}>{result.score}</span>
                  <span className="text-xs text-gray-500">/100</span>
                </div>
                <div>
                  <div className="text-lg font-semibold" style={{ color: scoreColor }}>{result.grade}</div>
                  <div className="text-xs text-gray-400 mt-1">Security score</div>
                  <div className="flex gap-3 mt-3 text-xs">
                    <span className="text-red-400">{criticals} critical</span>
                    <span className="text-amber-400">{warnings} warnings</span>
                    <span className="text-green-400">{passes} passing</span>
                  </div>
                </div>
              </div>

              {/* Findings */}
              <div className="space-y-2">
                {result.findings.map((f, i) => {
                  const s = SEV_STYLES[f.severity] ?? SEV_STYLES.notice;
                  return (
                    <div key={i} className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
                      <div className={`h-0.5 ${s.bar}`} />
                      <div className="px-4 py-3">
                        <div className="flex items-center justify-between gap-2 mb-1">
                          <span className="text-sm font-medium text-gray-100">{f.title}</span>
                          <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${s.bg} ${s.text}`}>
                            {s.label}
                          </span>
                        </div>
                        <p className="text-xs text-gray-400 mb-1">{f.description}</p>
                        <p className="text-xs text-emerald-400">→ {f.recommendation}</p>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      </div>
    </main>
  );
}
