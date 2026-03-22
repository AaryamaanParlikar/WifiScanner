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
  critical: { bg: 'bg-red-950',   text: 'text-red-400',   label: 'Critical', bar: 'bg-red-500' },
  warning:  { bg: 'bg-amber-950', text: 'text-amber-400', label: 'Warning',  bar: 'bg-amber-400' },
  notice:   { bg: 'bg-blue-950',  text: 'text-blue-400',  label: 'Notice',   bar: 'bg-blue-400' },
  pass:     { bg: 'bg-green-950', text: 'text-green-400', label: 'Pass',     bar: 'bg-green-500' },
};

type Finding = { severity: string; title: string; description: string; recommendation: string };
type AuditResult = {
  score: number; grade: string; findings: Finding[];
  device_count?: number; open_ports?: {port: number; service: string; risk: string}[];
  scan_performed: boolean;
};

const defaultForm = Object.fromEntries(
  Object.entries(FIELDS).map(([k, v]) => [k, v.options[1]?.value ?? v.options[0].value])
);

function Results({ result }: { result: AuditResult }) {
  const scoreColor = result.score >= 80 ? '#22c55e' : result.score >= 55 ? '#f59e0b' : '#ef4444';
  const criticals = result.findings.filter(f => f.severity === 'critical').length;
  const warnings  = result.findings.filter(f => f.severity === 'warning').length;
  const passes    = result.findings.filter(f => f.severity === 'pass').length;

  return (
    <div className="space-y-4">
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 flex items-center gap-5">
        <div className="w-20 h-20 rounded-full flex flex-col items-center justify-center flex-shrink-0 border-4"
          style={{ borderColor: scoreColor }}>
          <span className="text-2xl font-semibold" style={{ color: scoreColor }}>{result.score}</span>
          <span className="text-xs text-gray-500">/100</span>
        </div>
        <div>
          <div className="text-lg font-semibold" style={{ color: scoreColor }}>{result.grade}</div>
          <div className="text-xs text-gray-400 mt-1">
            {result.scan_performed ? 'Live network scan' : 'Manual audit'}
          </div>
          <div className="flex gap-3 mt-3 text-xs">
            <span className="text-red-400">{criticals} critical</span>
            <span className="text-amber-400">{warnings} warnings</span>
            <span className="text-green-400">{passes} passing</span>
          </div>
          {result.device_count !== undefined && (
            <div className="text-xs text-gray-500 mt-1">{result.device_count} device(s) detected</div>
          )}
        </div>
      </div>

      {result.open_ports && result.open_ports.length > 0 && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
          <div className="text-xs font-medium text-gray-400 uppercase tracking-wide mb-3">Open ports on gateway</div>
          <div className="flex flex-wrap gap-2">
            {result.open_ports.map((p, i) => (
              <span key={i} className={`text-xs px-2 py-1 rounded-md font-mono ${
                p.risk === 'critical' ? 'bg-red-950 text-red-400' :
                p.risk === 'warning'  ? 'bg-amber-950 text-amber-400' :
                'bg-gray-800 text-gray-400'
              }`}>
                {p.port}/{p.service}
              </span>
            ))}
          </div>
        </div>
      )}

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
  );
}

export default function Home() {
  const [tab, setTab] = useState<'manual' | 'scan'>('manual');
  const [form, setForm] = useState<Record<string, string>>(defaultForm);
  const [subnet, setSubnet] = useState('');
  const [result, setResult] = useState<AuditResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  async function runManual() {
    setLoading(true); setError(''); setResult(null);
    try {
      const res = await fetch('https://web-production-cc839.up.railway.app/audit/manual', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(form),
      });
      if (!res.ok) throw new Error(`Server error: ${res.status}`);
      setResult(await res.json());
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Could not reach backend. Is it running?');
    } finally { setLoading(false); }
  }

  async function runScan() {
    setLoading(true); setError(''); setResult(null);
    try {
      const body = subnet.trim() ? { target: subnet.trim() } : {};
      const res = await fetch('https://web-production-cc839.up.railway.app/audit/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.detail ?? `Server error: ${res.status}`);
      }
      setResult(await res.json());
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Could not reach backend. Is it running?');
    } finally { setLoading(false); }
  }

  return (
    <main className="min-h-screen bg-gray-950 text-gray-100" style={{ fontFamily: "'DM Sans', sans-serif" }}>
      <link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600&family=DM+Mono:wght@400;500&display=swap" rel="stylesheet" />

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
        <div>
          <h1 className="text-2xl font-semibold text-white mb-1">Audit your network</h1>
          <p className="text-sm text-gray-400 mb-6">Check your Wi-Fi setup for vulnerabilities and get a security score.</p>

          <div className="flex gap-1 bg-gray-900 border border-gray-800 rounded-lg p-1 mb-6">
            <button onClick={() => { setTab('manual'); setResult(null); setError(''); }}
              className={`flex-1 text-sm py-2 rounded-md transition-colors font-medium ${
                tab === 'manual' ? 'bg-emerald-500 text-gray-950' : 'text-gray-400 hover:text-gray-200'
              }`}>
              Manual audit
            </button>
            <button onClick={() => { setTab('scan'); setResult(null); setError(''); }}
              className={`flex-1 text-sm py-2 rounded-md transition-colors font-medium ${
                tab === 'scan' ? 'bg-emerald-500 text-gray-950' : 'text-gray-400 hover:text-gray-200'
              }`}>
              Live scan
            </button>
          </div>

          {tab === 'manual' && (
            <>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-6">
                {Object.entries(FIELDS).map(([key, field]) => (
                  <div key={key}>
                    <label className="block text-xs font-medium text-gray-400 mb-1.5 uppercase tracking-wide">
                      {field.label}
                    </label>
                    <select value={form[key]}
                      onChange={e => setForm(f => ({ ...f, [key]: e.target.value }))}
                      className="w-full bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-100 focus:outline-none focus:border-emerald-500 transition-colors">
                      {field.options.map(o => (
                        <option key={o.value} value={o.value}>{o.label}</option>
                      ))}
                    </select>
                  </div>
                ))}
              </div>
              <button onClick={runManual} disabled={loading}
                className="w-full bg-emerald-500 hover:bg-emerald-400 disabled:opacity-50 text-gray-950 font-semibold text-sm py-3 rounded-lg transition-colors">
                {loading ? 'Scoring...' : 'Run audit'}
              </button>
            </>
          )}

          {tab === 'scan' && (
            <>
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-4 mb-4">
                <div className="flex items-start gap-3">
                  <div className="w-2 h-2 rounded-full bg-emerald-400 mt-1.5 flex-shrink-0"></div>
                  <div>
                    <p className="text-sm text-gray-200 font-medium">Real-time network scan</p>
                    <p className="text-xs text-gray-400 mt-1">Uses nmap to scan your local network and detect connected devices and open ports on your router gateway.</p>
                  </div>
                </div>
              </div>
              <div className="mb-4">
                <label className="block text-xs font-medium text-gray-400 mb-1.5 uppercase tracking-wide">
                  Subnet (optional)
                </label>
                <input
                  type="text"
                  placeholder="e.g. 10.27.175.29/28  (auto-detected if empty)"
                  value={subnet}
                  onChange={e => setSubnet(e.target.value)}
                  className="w-full bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-100 font-mono focus:outline-none focus:border-emerald-500 transition-colors placeholder-gray-600"
                />
              </div>
              <button onClick={runScan} disabled={loading}
                className="w-full bg-emerald-500 hover:bg-emerald-400 disabled:opacity-50 text-gray-950 font-semibold text-sm py-3 rounded-lg transition-colors">
                {loading ? 'Scanning network...' : 'Start live scan'}
              </button>
              {loading && (
                <p className="text-xs text-gray-500 mt-2 text-center">This may take 10–30 seconds...</p>
              )}
            </>
          )}

          {error && (
            <div className="mt-4 bg-red-950 border border-red-800 rounded-lg px-4 py-3 text-sm text-red-300">
              {error}
            </div>
          )}
        </div>

        <div>
          {!result && !loading && (
            <div className="h-full flex items-center justify-center text-center text-gray-600 border border-dashed border-gray-800 rounded-xl p-10">
              <div>
                <svg width="32" height="32" fill="none" stroke="currentColor" strokeWidth="1.5" viewBox="0 0 24 24" className="mx-auto mb-3">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                </svg>
                <p className="text-sm">
                  {tab === 'manual'
                    ? 'Fill in your network config and run the audit.'
                    : 'Start a live scan to detect devices and open ports.'}
                </p>
              </div>
            </div>
          )}

          {loading && (
            <div className="h-full flex flex-col items-center justify-center text-emerald-400 gap-3">
              <div className="w-8 h-8 border-2 border-emerald-500 border-t-transparent rounded-full animate-spin"></div>
              <p className="text-sm">{tab === 'scan' ? 'Scanning your network...' : 'Analysing your config...'}</p>
            </div>
          )}

          {result && <Results result={result} />}
        </div>
      </div>
    </main>
  );
}

