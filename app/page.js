'use client';

import { useEffect, useMemo, useState, useCallback } from 'react';
import { useTheme } from 'next-themes';
import {
  ShieldCheck, ShieldAlert, Radar, LayoutDashboard, Boxes, Bug, Server,
  CalendarClock, Settings as SettingsIcon, Moon, Sun, Plus, Play, Search,
  Globe, Lock, Network, AlertTriangle, CheckCircle2, Clock,
  Trash2, RefreshCw, TerminalSquare, Copy, ChevronRight, Activity, Cloud, HardDrive,
} from 'lucide-react';
import {
  ResponsiveContainer, AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip as RTooltip,
  PieChart, Pie, Cell,
} from 'recharts';
import { toast } from 'sonner';

import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Separator } from '@/components/ui/separator';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from '@/components/ui/dialog';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Toaster } from '@/components/ui/sonner';

const api = async (path, opts = {}) => {
  const res = await fetch(`/api${path}`, { headers: { 'Content-Type': 'application/json' }, ...opts });
  if (!res.ok) { let e; try { e = await res.json(); } catch (x) { e = { error: res.statusText }; } throw new Error(e.error || 'Request failed'); }
  return res.json();
};

const SEV = {
  Critical: { badge: 'bg-red-500/15 text-red-500 border-red-500/30', dot: 'bg-red-500', hex: '#ef4444' },
  High: { badge: 'bg-orange-500/15 text-orange-500 border-orange-500/30', dot: 'bg-orange-500', hex: '#f97316' },
  Medium: { badge: 'bg-amber-400/15 text-amber-500 border-amber-400/30', dot: 'bg-amber-400', hex: '#f59e0b' },
  Low: { badge: 'bg-sky-500/15 text-sky-500 border-sky-500/30', dot: 'bg-sky-500', hex: '#0ea5e9' },
  Info: { badge: 'bg-slate-500/15 text-slate-400 border-slate-500/30', dot: 'bg-slate-400', hex: '#64748b' },
};
const scoreColor = (s) => (s >= 80 ? '#22c55e' : s >= 60 ? '#eab308' : s >= 40 ? '#f97316' : '#ef4444');
const STATUS_COLORS = { Open: 'bg-red-500/15 text-red-400 border-red-500/30', 'In Progress': 'bg-amber-400/15 text-amber-500 border-amber-400/30', Resolved: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30', 'False Positive': 'bg-slate-500/15 text-slate-400 border-slate-500/30' };

function ScoreRing({ score = 0, size = 150, stroke = 12, label = 'Security Score' }) {
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  const off = c - (score / 100) * c;
  const color = scoreColor(score);
  return (
    <div className="relative inline-flex items-center justify-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="hsl(var(--muted))" strokeWidth={stroke} />
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={color} strokeWidth={stroke} strokeDasharray={c} strokeDashoffset={off} strokeLinecap="round" style={{ transition: 'stroke-dashoffset 1s ease' }} />
      </svg>
      <div className="absolute flex flex-col items-center">
        <span className="text-4xl font-bold tracking-tight" style={{ color }}>{score}</span>
        <span className="text-[11px] uppercase tracking-widest text-muted-foreground mt-1">{label}</span>
      </div>
    </div>
  );
}

const NAV = [
  { id: 'dashboard', label: 'Executive Dashboard', icon: LayoutDashboard },
  { id: 'scanner', label: 'Instant Scanner', icon: Radar },
  { id: 'assets', label: 'Asset Inventory', icon: Boxes },
  { id: 'vulns', label: 'Vulnerability Center', icon: Bug },
  { id: 'infra', label: 'Infrastructure Health', icon: Server },
  { id: 'scheduler', label: 'Scheduler & Logs', icon: CalendarClock },
  { id: 'settings', label: 'Settings & API Keys', icon: SettingsIcon },
];

export default function App() {
  const { theme, setTheme } = useTheme();
  const [mounted, setMounted] = useState(false);
  const [view, setView] = useState('dashboard');
  const [dashboard, setDashboard] = useState(null);
  const [assets, setAssets] = useState([]);
  const [findings, setFindings] = useState([]);
  const [infra, setInfra] = useState([]);
  const [scanTarget, setScanTarget] = useState('');

  useEffect(() => setMounted(true), []);

  const loadAll = useCallback(async () => {
    try {
      const [d, a, f, i] = await Promise.all([api('/dashboard'), api('/assets'), api('/findings'), api('/infra')]);
      setDashboard(d); setAssets(a); setFindings(f); setInfra(i);
    } catch (e) { toast.error(e.message); }
  }, []);

  useEffect(() => { loadAll(); }, [loadAll]);

  return (
    <div className="min-h-screen bg-background text-foreground flex">
      <Toaster position="top-right" richColors />
      <aside className="hidden md:flex w-64 shrink-0 flex-col border-r border-border bg-sidebar/40 backdrop-blur sticky top-0 h-screen">
        <div className="flex items-center gap-2 px-5 h-16 border-b border-border">
          <div className="grid place-items-center w-9 h-9 rounded-lg bg-primary text-primary-foreground"><ShieldCheck className="w-5 h-5" /></div>
          <div>
            <div className="font-semibold leading-tight">Sentinel</div>
            <div className="text-[10px] text-muted-foreground tracking-wide">POSTURE & VULN MGMT</div>
          </div>
        </div>
        <nav className="flex-1 p-3 space-y-1 overflow-y-auto">
          {NAV.map((n) => {
            const Icon = n.icon; const active = view === n.id;
            return (
              <button key={n.id} onClick={() => setView(n.id)} className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-md text-sm transition-colors ${active ? 'bg-primary text-primary-foreground font-medium' : 'text-muted-foreground hover:bg-muted hover:text-foreground'}`}>
                <Icon className="w-4 h-4" /> {n.label}
              </button>
            );
          })}
        </nav>
        <div className="p-3 border-t border-border text-[11px] text-muted-foreground">
          <div className="flex items-center gap-2"><span className="relative flex h-2 w-2"><span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" /><span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500" /></span> Engine online</div>
        </div>
      </aside>

      <div className="flex-1 flex flex-col min-w-0">
        <header className="h-16 border-b border-border flex items-center justify-between px-4 md:px-6 sticky top-0 bg-background/80 backdrop-blur z-20">
          <div className="flex items-center gap-3">
            <div className="md:hidden grid place-items-center w-8 h-8 rounded-lg bg-primary text-primary-foreground"><ShieldCheck className="w-4 h-4" /></div>
            <h1 className="text-lg font-semibold">{NAV.find((n) => n.id === view)?.label}</h1>
          </div>
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={() => setView('scanner')}><Radar className="w-4 h-4 mr-1.5" />New Scan</Button>
            <Button variant="ghost" size="icon" onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}>
              {mounted && theme === 'dark' ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
            </Button>
          </div>
        </header>

        <div className="md:hidden flex gap-1 overflow-x-auto p-2 border-b border-border">
          {NAV.map((n) => (<button key={n.id} onClick={() => setView(n.id)} className={`whitespace-nowrap text-xs px-3 py-1.5 rounded-full ${view === n.id ? 'bg-primary text-primary-foreground' : 'bg-muted text-muted-foreground'}`}>{n.label}</button>))}
        </div>

        <main className="flex-1 p-4 md:p-6 max-w-[1400px] w-full mx-auto">
          {view === 'dashboard' && <DashboardView data={dashboard} findings={findings} onScan={() => setView('scanner')} />}
          {view === 'scanner' && <ScannerView presetUrl={scanTarget} onDone={loadAll} />}
          {view === 'assets' && <AssetsView assets={assets} reload={loadAll} onScan={(url) => { setScanTarget(url); setView('scanner'); }} />}
          {view === 'vulns' && <VulnView findings={findings} reload={loadAll} />}
          {view === 'infra' && <InfraView infra={infra} />}
          {view === 'scheduler' && <SchedulerView assets={assets} />}
          {view === 'settings' && <SettingsView />}
        </main>
      </div>
    </div>
  );
}

function StatCard({ icon: Icon, label, value, sub, tone = 'default' }) {
  const tones = { default: 'text-foreground', danger: 'text-red-500', warn: 'text-amber-500', good: 'text-emerald-500' };
  return (
    <Card>
      <CardContent className="p-5">
        <div className="flex items-center justify-between">
          <span className="text-xs uppercase tracking-wide text-muted-foreground">{label}</span>
          <Icon className="w-4 h-4 text-muted-foreground" />
        </div>
        <div className={`text-3xl font-bold mt-2 ${tones[tone]}`}>{value}</div>
        {sub && <div className="text-xs text-muted-foreground mt-1">{sub}</div>}
      </CardContent>
    </Card>
  );
}

function DashboardView({ data, findings, onScan }) {
  if (!data) return <SkeletonGrid />;
  const sev = data.bySeverity || {};
  const pie = [
    { name: 'Critical', value: sev.Critical || 0, color: SEV.Critical.hex },
    { name: 'High', value: sev.High || 0, color: SEV.High.hex },
    { name: 'Medium', value: sev.Medium || 0, color: SEV.Medium.hex },
    { name: 'Low', value: sev.Low || 0, color: SEV.Low.hex },
  ];
  const recent = [...findings].filter((f) => f.status === 'Open').sort((a, b) => (b.createdAt || '').localeCompare(a.createdAt || '')).slice(0, 6);
  return (
    <div className="space-y-6">
      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-1">
          <CardHeader className="pb-2"><CardTitle className="text-base">Overall Posture</CardTitle><CardDescription>Fleet-wide average security score</CardDescription></CardHeader>
          <CardContent className="flex flex-col items-center pt-2 pb-6"><ScoreRing score={data.avgScore || 0} /><div className="mt-4 flex gap-4 text-center">
            <div><div className="text-lg font-semibold">{data.totalAssets}</div><div className="text-[11px] text-muted-foreground">Assets</div></div>
            <Separator orientation="vertical" className="h-8" />
            <div><div className="text-lg font-semibold text-red-500">{data.criticalOpen}</div><div className="text-[11px] text-muted-foreground">Critical</div></div>
            <Separator orientation="vertical" className="h-8" />
            <div><div className="text-lg font-semibold text-amber-500">{data.infraIssues}</div><div className="text-[11px] text-muted-foreground">Infra Risks</div></div>
          </div></CardContent>
        </Card>
        <Card className="lg:col-span-2">
          <CardHeader className="pb-2"><CardTitle className="text-base">30-Day Posture Trend</CardTitle><CardDescription>Average security score over time</CardDescription></CardHeader>
          <CardContent className="pt-4">
            <ResponsiveContainer width="100%" height={220}>
              <AreaChart data={data.trend || []} margin={{ left: -20, right: 8, top: 8 }}>
                <defs><linearGradient id="g" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="#6366f1" stopOpacity={0.5} /><stop offset="95%" stopColor="#6366f1" stopOpacity={0} /></linearGradient></defs>
                <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" vertical={false} />
                <XAxis dataKey="date" tick={{ fontSize: 11, fill: 'hsl(var(--muted-foreground))' }} interval={4} />
                <YAxis domain={[0, 100]} tick={{ fontSize: 11, fill: 'hsl(var(--muted-foreground))' }} />
                <RTooltip contentStyle={{ background: 'hsl(var(--popover))', border: '1px solid hsl(var(--border))', borderRadius: 8, fontSize: 12 }} />
                <Area type="monotone" dataKey="score" stroke="#6366f1" strokeWidth={2} fill="url(#g)" />
              </AreaChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 md:grid-cols-4">
        <StatCard icon={AlertTriangle} label="Critical" value={sev.Critical || 0} sub="Open critical findings" tone="danger" />
        <StatCard icon={ShieldAlert} label="High" value={sev.High || 0} sub="Open high findings" tone="warn" />
        <StatCard icon={Bug} label="Medium / Low" value={(sev.Medium || 0) + (sev.Low || 0)} sub="Lower priority" />
        <StatCard icon={Server} label="Infra Nodes" value={data.infraNodes} sub={`${data.infraIssues} risks detected`} />
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-base">Active Vulnerabilities by Severity</CardTitle></CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie data={pie} dataKey="value" nameKey="name" innerRadius={55} outerRadius={85} paddingAngle={3}>
                  {pie.map((e, i) => <Cell key={i} fill={e.color} />)}
                </Pie>
                <RTooltip contentStyle={{ background: 'hsl(var(--popover))', border: '1px solid hsl(var(--border))', borderRadius: 8, fontSize: 12 }} />
              </PieChart>
            </ResponsiveContainer>
            <div className="flex flex-wrap gap-3 justify-center">{pie.map((p) => <div key={p.name} className="flex items-center gap-1.5 text-xs"><span className="w-2.5 h-2.5 rounded-full" style={{ background: p.color }} />{p.name} · {p.value}</div>)}</div>
          </CardContent>
        </Card>
        <Card className="lg:col-span-2">
          <CardHeader className="pb-2 flex-row items-center justify-between space-y-0"><CardTitle className="text-base">Latest Open Findings</CardTitle><Button size="sm" variant="outline" onClick={onScan}><Play className="w-3.5 h-3.5 mr-1.5" />Run a scan</Button></CardHeader>
          <CardContent className="space-y-2">
            {recent.length === 0 && <p className="text-sm text-muted-foreground py-6 text-center">No open findings. Run a scan to populate.</p>}
            {recent.map((f) => (
              <div key={f.id} className="flex items-center gap-3 p-2.5 rounded-md border border-border hover:bg-muted/50">
                <span className={`w-2 h-2 rounded-full ${SEV[f.severity]?.dot}`} />
                <div className="min-w-0 flex-1"><div className="text-sm font-medium truncate">{f.title}</div><div className="text-xs text-muted-foreground truncate">{f.assetName} · {f.cwe || f.category}</div></div>
                <Badge variant="outline" className={SEV[f.severity]?.badge}>{f.severity}</Badge>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

const SCAN_STEPS = [
  'Resolving target host…', 'Establishing connection…', 'Fetching HTTP response headers…',
  'Analyzing security headers (HSTS, CSP, X-Frame-Options)…', 'Inspecting Set-Cookie flags…',
  'Negotiating TLS & reading certificate…', 'Probing for exposed sensitive files (.env, .git, phpinfo)…',
  'Scanning for accidentally exposed data ports…', 'Correlating findings & scoring…',
];
function ScannerView({ presetUrl, onDone }) {
  const [url, setUrl] = useState(presetUrl || '');
  const [framework, setFramework] = useState('CodeIgniter');
  const [environment, setEnvironment] = useState('Production');
  const [host, setHost] = useState('GCP');
  const [running, setRunning] = useState(false);
  const [logs, setLogs] = useState([]);
  const [result, setResult] = useState(null);

  useEffect(() => { if (presetUrl) setUrl(presetUrl); }, [presetUrl]);

  const run = async () => {
    if (!url.trim()) { toast.error('Enter a URL or hostname to scan'); return; }
    setRunning(true); setResult(null); setLogs([]);
    let i = 0;
    const iv = setInterval(() => { if (i < SCAN_STEPS.length) { const t = new Date().toLocaleTimeString(); setLogs((l) => [...l, { t, m: SCAN_STEPS[i] }]); i++; } }, 550);
    try {
      const r = await api('/scan', { method: 'POST', body: JSON.stringify({ url, framework, environment, host }) });
      clearInterval(iv);
      setLogs((l) => [...l, { t: new Date().toLocaleTimeString(), m: `Scan complete — ${r.findings.length} findings, score ${r.score}/100.`, ok: true }]);
      setResult(r);
      toast.success(`Scan complete · Score ${r.score}/100`);
      onDone && onDone();
    } catch (e) {
      clearInterval(iv);
      setLogs((l) => [...l, { t: new Date().toLocaleTimeString(), m: `Error: ${e.message}`, err: true }]);
      toast.error(e.message);
    } finally { setRunning(false); }
  };

  return (
    <div className="space-y-5">
      <Card className="border-primary/20 bg-gradient-to-br from-primary/5 to-transparent">
        <CardHeader><CardTitle className="flex items-center gap-2"><Radar className="w-5 h-5 text-primary" />Non-Intrusive Vulnerability Scanner</CardTitle><CardDescription>Live baseline audit — real HTTP headers, TLS certificate, cookie flags, exposed files & risky ports. No exploitation.</CardDescription></CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-3 md:grid-cols-[1fr_auto]">
            <div className="relative"><Globe className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" /><Input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="example.com or https://app.example.com" className="pl-9" onKeyDown={(e) => e.key === 'Enter' && run()} /></div>
            <Button onClick={run} disabled={running} className="min-w-[130px]">{running ? <><RefreshCw className="w-4 h-4 mr-2 animate-spin" />Scanning…</> : <><Play className="w-4 h-4 mr-2" />Run Scan</>}</Button>
          </div>
          <div className="grid gap-3 sm:grid-cols-3">
            <div><Label className="text-xs">Framework</Label><Select value={framework} onValueChange={setFramework}><SelectTrigger className="mt-1"><SelectValue /></SelectTrigger><SelectContent>{['CodeIgniter', 'NestJS', 'Go'].map((x) => <SelectItem key={x} value={x}>{x}</SelectItem>)}</SelectContent></Select></div>
            <div><Label className="text-xs">Environment</Label><Select value={environment} onValueChange={setEnvironment}><SelectTrigger className="mt-1"><SelectValue /></SelectTrigger><SelectContent>{['Production', 'Staging'].map((x) => <SelectItem key={x} value={x}>{x}</SelectItem>)}</SelectContent></Select></div>
            <div><Label className="text-xs">Host</Label><Select value={host} onValueChange={setHost}><SelectTrigger className="mt-1"><SelectValue /></SelectTrigger><SelectContent>{['GCP', 'Proxmox'].map((x) => <SelectItem key={x} value={x}>{x}</SelectItem>)}</SelectContent></Select></div>
          </div>
        </CardContent>
      </Card>

      {(running || logs.length > 0) && (
        <Card className="bg-black/90 border-border">
          <CardHeader className="pb-2"><CardTitle className="text-sm flex items-center gap-2 text-emerald-400"><TerminalSquare className="w-4 h-4" />Live Scan Log</CardTitle></CardHeader>
          <CardContent><div className="font-mono text-xs space-y-1 max-h-56 overflow-y-auto">
            {logs.map((l, i) => (<div key={i} className={l.err ? 'text-red-400' : l.ok ? 'text-emerald-400' : 'text-slate-300'}><span className="text-slate-500">[{l.t}]</span> {l.m}</div>))}
            {running && <div className="text-emerald-400 animate-pulse">▊</div>}
          </div></CardContent>
        </Card>
      )}

      {result && <ScanResult result={result} />}
    </div>
  );
}

function ScanResult({ result }) {
  const grouped = useMemo(() => {
    const g = { Critical: [], High: [], Medium: [], Low: [], Info: [] };
    for (const f of result.findings) (g[f.severity] = g[f.severity] || []).push(f);
    return g;
  }, [result]);
  const tls = result.tls;
  return (
    <div className="space-y-5">
      <div className="grid gap-4 md:grid-cols-3">
        <Card><CardContent className="p-5 flex items-center gap-5"><ScoreRing score={result.score} size={120} stroke={10} label={`Grade ${result.grade}`} /><div className="space-y-1 text-sm"><div className="font-medium break-all">{result.url}</div><div className="text-muted-foreground">{result.framework} · {result.findings.length} findings</div><div className="text-muted-foreground">Scanned in {(result.durationMs / 1000).toFixed(1)}s</div></div></CardContent></Card>
        <Card><CardHeader className="pb-2"><CardTitle className="text-sm flex items-center gap-2"><Lock className="w-4 h-4" />TLS / Certificate</CardTitle></CardHeader><CardContent className="text-sm space-y-1.5">
          {tls?.ok ? (<>
            <Row k="Protocol" v={tls.protocol} bad={tls.protocol === 'TLSv1' || tls.protocol === 'TLSv1.1'} />
            <Row k="Issuer" v={tls.issuer} />
            <Row k="Expires in" v={tls.daysLeft != null ? `${tls.daysLeft} days` : '—'} bad={tls.daysLeft != null && tls.daysLeft < 30} />
            <Row k="Valid to" v={tls.validTo || '—'} />
            <Row k="Trusted" v={tls.authorized ? 'Yes' : 'No'} bad={!tls.authorized} />
          </>) : <div className="text-muted-foreground">{result.isHttps ? `Could not read certificate (${tls?.error || 'n/a'})` : 'Served over plaintext HTTP — no TLS.'}</div>}
        </CardContent></Card>
        <Card><CardHeader className="pb-2"><CardTitle className="text-sm flex items-center gap-2"><Network className="w-4 h-4" />Port Exposure</CardTitle></CardHeader><CardContent className="text-sm space-y-1.5">
          {(result.ports || []).map((p) => (<div key={p.port} className="flex items-center justify-between"><span className="text-muted-foreground">{p.name} ({p.port})</span>{p.open ? <Badge variant="outline" className={SEV.Critical.badge}>OPEN</Badge> : <span className="text-emerald-500 text-xs flex items-center gap-1"><CheckCircle2 className="w-3.5 h-3.5" />closed</span>}</div>))}
        </CardContent></Card>
      </div>

      <div className="flex flex-wrap gap-2">
        {['Critical', 'High', 'Medium', 'Low', 'Info'].map((s) => grouped[s].length > 0 && <Badge key={s} variant="outline" className={SEV[s].badge}>{s}: {grouped[s].length}</Badge>)}
      </div>

      <div className="space-y-3">
        {['Critical', 'High', 'Medium', 'Low', 'Info'].map((s) => grouped[s].map((f) => <FindingCard key={f.id} f={f} />))}
        {result.findings.length === 0 && <Card><CardContent className="p-8 text-center text-emerald-500"><CheckCircle2 className="w-8 h-8 mx-auto mb-2" />No baseline issues detected. Nicely hardened!</CardContent></Card>}
      </div>
    </div>
  );
}

function Row({ k, v, bad }) { return (<div className="flex items-center justify-between"><span className="text-muted-foreground">{k}</span><span className={bad ? 'text-red-500 font-medium' : ''}>{v}</span></div>); }

function FindingCard({ f }) {
  const [open, setOpen] = useState(false);
  const rem = f.remediation || {};
  const copy = (t) => { navigator.clipboard.writeText(t); toast.success('Copied'); };
  return (
    <Card className="overflow-hidden">
      <button onClick={() => setOpen(!open)} className="w-full flex items-center gap-3 p-4 text-left hover:bg-muted/40">
        <span className={`w-2.5 h-2.5 rounded-full ${SEV[f.severity]?.dot}`} />
        <div className="flex-1 min-w-0"><div className="font-medium text-sm">{f.title}</div><div className="text-xs text-muted-foreground truncate">{f.category}{f.cwe ? ` · ${f.cwe}` : ''}{f.endpoint ? ` · ${f.endpoint}` : ''}</div></div>
        <Badge variant="outline" className={SEV[f.severity]?.badge}>{f.severity}</Badge>
        <ChevronRight className={`w-4 h-4 text-muted-foreground transition-transform ${open ? 'rotate-90' : ''}`} />
      </button>
      {open && (
        <CardContent className="border-t border-border pt-4 space-y-3">
          <p className="text-sm text-muted-foreground">{f.description}</p>
          {f.evidence && <div className="text-xs"><span className="text-muted-foreground">Evidence: </span><code className="bg-muted px-1.5 py-0.5 rounded break-all">{f.evidence}</code></div>}
          <div>
            <div className="text-xs font-medium mb-1.5 flex items-center gap-1.5"><ShieldCheck className="w-3.5 h-3.5 text-primary" />Remediation ({rem.framework})</div>
            {rem.generic && <p className="text-xs text-muted-foreground mb-2">{rem.generic}</p>}
            {rem.snippet && (<div className="relative"><pre className="bg-black/90 text-slate-200 text-xs rounded-md p-3 overflow-x-auto font-mono whitespace-pre-wrap">{rem.snippet}</pre><Button size="icon" variant="ghost" className="absolute top-1.5 right-1.5 h-6 w-6" onClick={() => copy(rem.snippet)}><Copy className="w-3.5 h-3.5" /></Button></div>)}
          </div>
        </CardContent>
      )}
    </Card>
  );
}

function AssetsView({ assets, reload, onScan }) {
  const [q, setQ] = useState('');
  const [fw, setFw] = useState('all');
  const [env, setEnv] = useState('all');
  const [addOpen, setAddOpen] = useState(false);
  const [form, setForm] = useState({ name: '', url: '', framework: 'CodeIgniter', environment: 'Production', host: 'GCP' });

  const filtered = assets.filter((a) => (fw === 'all' || a.framework === fw) && (env === 'all' || a.environment === env) && (!q || a.name?.toLowerCase().includes(q.toLowerCase()) || a.url?.toLowerCase().includes(q.toLowerCase())));

  const add = async () => {
    if (!form.name || !form.url) { toast.error('Name and URL are required'); return; }
    try { await api('/assets', { method: 'POST', body: JSON.stringify(form) }); toast.success('Asset added'); setAddOpen(false); setForm({ name: '', url: '', framework: 'CodeIgniter', environment: 'Production', host: 'GCP' }); reload(); } catch (e) { toast.error(e.message); }
  };
  const del = async (id) => { try { await api(`/assets/${id}`, { method: 'DELETE' }); toast.success('Deleted'); reload(); } catch (e) { toast.error(e.message); } };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative flex-1 min-w-[200px]"><Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" /><Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search assets…" className="pl-9" /></div>
        <Select value={fw} onValueChange={setFw}><SelectTrigger className="w-[150px]"><SelectValue /></SelectTrigger><SelectContent><SelectItem value="all">All frameworks</SelectItem>{['CodeIgniter', 'NestJS', 'Go'].map((x) => <SelectItem key={x} value={x}>{x}</SelectItem>)}</SelectContent></Select>
        <Select value={env} onValueChange={setEnv}><SelectTrigger className="w-[150px]"><SelectValue /></SelectTrigger><SelectContent><SelectItem value="all">All environments</SelectItem>{['Production', 'Staging'].map((x) => <SelectItem key={x} value={x}>{x}</SelectItem>)}</SelectContent></Select>
        <Dialog open={addOpen} onOpenChange={setAddOpen}><Button onClick={() => setAddOpen(true)}><Plus className="w-4 h-4 mr-1.5" />Add Asset</Button>
          <DialogContent><DialogHeader><DialogTitle>Register Asset</DialogTitle><DialogDescription>Add an application to your inventory.</DialogDescription></DialogHeader>
            <div className="space-y-3">
              <div><Label>Name</Label><Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="Payments API" /></div>
              <div><Label>URL</Label><Input value={form.url} onChange={(e) => setForm({ ...form, url: e.target.value })} placeholder="https://api.example.com" /></div>
              <div className="grid grid-cols-3 gap-2">
                <div><Label className="text-xs">Framework</Label><Select value={form.framework} onValueChange={(v) => setForm({ ...form, framework: v })}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent>{['CodeIgniter', 'NestJS', 'Go'].map((x) => <SelectItem key={x} value={x}>{x}</SelectItem>)}</SelectContent></Select></div>
                <div><Label className="text-xs">Env</Label><Select value={form.environment} onValueChange={(v) => setForm({ ...form, environment: v })}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent>{['Production', 'Staging'].map((x) => <SelectItem key={x} value={x}>{x}</SelectItem>)}</SelectContent></Select></div>
                <div><Label className="text-xs">Host</Label><Select value={form.host} onValueChange={(v) => setForm({ ...form, host: v })}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent>{['GCP', 'Proxmox'].map((x) => <SelectItem key={x} value={x}>{x}</SelectItem>)}</SelectContent></Select></div>
              </div>
            </div>
            <DialogFooter><Button onClick={add}>Add Asset</Button></DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      <Card><CardContent className="p-0 overflow-x-auto"><Table>
        <TableHeader><TableRow>
          <TableHead>Name</TableHead><TableHead>Framework</TableHead><TableHead>Env</TableHead><TableHead>Host</TableHead><TableHead>Status</TableHead><TableHead>Last Scan</TableHead><TableHead>Score</TableHead><TableHead className="text-right">Actions</TableHead>
        </TableRow></TableHeader>
        <TableBody>
          {filtered.map((a) => (
            <TableRow key={a.id}>
              <TableCell><div className="font-medium">{a.name}</div><div className="text-xs text-muted-foreground truncate max-w-[200px]">{a.url}</div></TableCell>
              <TableCell><Badge variant="secondary">{a.framework}</Badge></TableCell>
              <TableCell><span className={`text-xs ${a.environment === 'Production' ? 'text-emerald-500' : 'text-amber-500'}`}>{a.environment}</span></TableCell>
              <TableCell><span className="flex items-center gap-1 text-xs">{a.host === 'GCP' ? <Cloud className="w-3.5 h-3.5" /> : <HardDrive className="w-3.5 h-3.5" />}{a.host}</span></TableCell>
              <TableCell><span className="flex items-center gap-1.5 text-xs"><span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />{a.status}</span></TableCell>
              <TableCell className="text-xs text-muted-foreground">{a.lastScanned ? new Date(a.lastScanned).toLocaleDateString() : 'Never'}</TableCell>
              <TableCell>{typeof a.score === 'number' ? <span className="font-semibold" style={{ color: scoreColor(a.score) }}>{a.score}</span> : <span className="text-muted-foreground text-xs">—</span>}</TableCell>
              <TableCell className="text-right"><div className="flex justify-end gap-1"><Button size="sm" variant="outline" onClick={() => onScan(a.url)}><Play className="w-3.5 h-3.5 mr-1" />Scan</Button><Button size="icon" variant="ghost" onClick={() => del(a.id)}><Trash2 className="w-3.5 h-3.5 text-red-500" /></Button></div></TableCell>
            </TableRow>
          ))}
          {filtered.length === 0 && <TableRow><TableCell colSpan={8} className="text-center text-muted-foreground py-10">No assets match your filters.</TableCell></TableRow>}
        </TableBody>
      </Table></CardContent></Card>
    </div>
  );
}

const WF = ['Open', 'In Progress', 'Resolved', 'False Positive'];
function VulnView({ findings, reload }) {
  const [sev, setSev] = useState('all');
  const [q, setQ] = useState('');
  const [detail, setDetail] = useState(null);

  const list = findings.filter((f) => (sev === 'all' || f.severity === sev) && (!q || f.title.toLowerCase().includes(q.toLowerCase()) || (f.assetName || '').toLowerCase().includes(q.toLowerCase())));
  const cols = useMemo(() => { const g = {}; for (const s of WF) g[s] = findings.filter((f) => f.status === s); return g; }, [findings]);

  const setStatus = async (id, status) => { try { await api(`/findings/${id}`, { method: 'PATCH', body: JSON.stringify({ status }) }); toast.success(`Marked ${status}`); reload(); } catch (e) { toast.error(e.message); } };

  return (
    <div className="space-y-5">
      <div className="grid gap-3 md:grid-cols-4">
        {WF.map((s) => (<Card key={s}><CardContent className="p-4"><div className="flex items-center justify-between"><span className="text-xs text-muted-foreground">{s}</span><Badge variant="outline" className={STATUS_COLORS[s]}>{cols[s].length}</Badge></div><div className="mt-2 flex -space-x-1">{cols[s].slice(0, 8).map((f) => <span key={f.id} className={`w-2.5 h-2.5 rounded-full ring-2 ring-background ${SEV[f.severity]?.dot}`} />)}</div></CardContent></Card>))}
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <div className="relative flex-1 min-w-[200px]"><Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" /><Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search findings…" className="pl-9" /></div>
        <Select value={sev} onValueChange={setSev}><SelectTrigger className="w-[160px]"><SelectValue /></SelectTrigger><SelectContent><SelectItem value="all">All severities</SelectItem>{['Critical', 'High', 'Medium', 'Low', 'Info'].map((x) => <SelectItem key={x} value={x}>{x}</SelectItem>)}</SelectContent></Select>
      </div>

      <Card><CardContent className="p-0 overflow-x-auto"><Table>
        <TableHeader><TableRow><TableHead>Finding</TableHead><TableHead>Asset</TableHead><TableHead>Ref</TableHead><TableHead>Severity</TableHead><TableHead>Status</TableHead><TableHead className="text-right">Action</TableHead></TableRow></TableHeader>
        <TableBody>
          {list.map((f) => (
            <TableRow key={f.id} className="cursor-pointer" onClick={() => setDetail(f)}>
              <TableCell><div className="font-medium text-sm">{f.title}</div><div className="text-xs text-muted-foreground">{f.category}</div></TableCell>
              <TableCell className="text-xs">{f.assetName}<div className="text-muted-foreground">{f.framework}</div></TableCell>
              <TableCell className="text-xs text-muted-foreground">{f.cwe || '—'}</TableCell>
              <TableCell><Badge variant="outline" className={SEV[f.severity]?.badge}>{f.severity}</Badge></TableCell>
              <TableCell><Badge variant="outline" className={STATUS_COLORS[f.status]}>{f.status}</Badge></TableCell>
              <TableCell className="text-right" onClick={(e) => e.stopPropagation()}>
                <Select value={f.status} onValueChange={(v) => setStatus(f.id, v)}><SelectTrigger className="w-[150px] ml-auto h-8 text-xs"><SelectValue /></SelectTrigger><SelectContent>{WF.map((s) => <SelectItem key={s} value={s}>{s}</SelectItem>)}</SelectContent></Select>
              </TableCell>
            </TableRow>
          ))}
          {list.length === 0 && <TableRow><TableCell colSpan={6} className="text-center text-muted-foreground py-10">No findings.</TableCell></TableRow>}
        </TableBody>
      </Table></CardContent></Card>

      <Dialog open={!!detail} onOpenChange={(o) => !o && setDetail(null)}>
        <DialogContent className="max-w-2xl max-h-[85vh] overflow-y-auto">
          {detail && (<>
            <DialogHeader><DialogTitle className="flex items-center gap-2"><span className={`w-2.5 h-2.5 rounded-full ${SEV[detail.severity]?.dot}`} />{detail.title}</DialogTitle><DialogDescription>{detail.assetName} · {detail.category} · {detail.cwe}</DialogDescription></DialogHeader>
            <div className="space-y-4">
              <p className="text-sm text-muted-foreground">{detail.description}</p>
              {detail.evidence && <div className="text-xs"><span className="text-muted-foreground">Evidence: </span><code className="bg-muted px-1.5 py-0.5 rounded break-all">{detail.evidence}</code></div>}
              <RemediationBlock finding={detail} />
            </div>
          </>)}
        </DialogContent>
      </Dialog>
    </div>
  );
}

function RemediationBlock({ finding }) {
  const rem = finding.remediation || {};
  const copy = (t) => { navigator.clipboard.writeText(t); toast.success('Copied'); };
  return (
    <div>
      <div className="text-sm font-medium mb-2 flex items-center gap-1.5"><ShieldCheck className="w-4 h-4 text-primary" />Remediation Guide</div>
      {rem.generic && <p className="text-xs text-muted-foreground mb-2">{rem.generic}</p>}
      {rem.snippet ? (<div className="relative"><div className="text-[11px] text-muted-foreground mb-1">{rem.framework}</div><pre className="bg-black/90 text-slate-200 text-xs rounded-md p-3 overflow-x-auto font-mono whitespace-pre-wrap">{rem.snippet}</pre><Button size="icon" variant="ghost" className="absolute top-6 right-1.5 h-6 w-6" onClick={() => copy(rem.snippet)}><Copy className="w-3.5 h-3.5" /></Button></div>) : <p className="text-xs text-muted-foreground">Apply the relevant framework security control.</p>}
    </div>
  );
}

function InfraView({ infra }) {
  const gcp = infra.filter((n) => n.kind === 'GCP');
  const pve = infra.filter((n) => n.kind === 'Proxmox');
  const st = { Healthy: 'text-emerald-500', 'At Risk': 'text-amber-500', Critical: 'text-red-500' };
  const NodeCard = ({ n }) => (
    <Card className={n.status === 'Critical' ? 'border-red-500/40' : n.status === 'At Risk' ? 'border-amber-500/30' : ''}>
      <CardContent className="p-4 space-y-2">
        <div className="flex items-center justify-between"><div className="font-medium text-sm flex items-center gap-2">{n.kind === 'GCP' ? <Cloud className="w-4 h-4" /> : <HardDrive className="w-4 h-4" />}{n.name}</div><span className={`text-xs font-medium ${st[n.status]}`}>{n.status}</span></div>
        <div className="text-xs text-muted-foreground">{n.type} · {n.region} · {n.publicIp}</div>
        <div className="flex flex-wrap gap-1.5">{(n.openPorts || []).map((p) => <Badge key={p} variant="outline" className={[3306, 6379, 27017, 8006].includes(p) && n.status !== 'Healthy' ? SEV.High.badge : 'bg-muted'}>:{p}</Badge>)}{n.openPorts?.length === 0 && <span className="text-xs text-muted-foreground">no public ports</span>}</div>
        <div className="grid grid-cols-2 gap-2 text-xs pt-1"><div><span className="text-muted-foreground">TLS: </span>{n.tls}</div><div className="flex items-center gap-1">{n.issues > 0 ? <span className="text-red-500 flex items-center gap-1"><AlertTriangle className="w-3.5 h-3.5" />{n.issues} issues</span> : <span className="text-emerald-500 flex items-center gap-1"><CheckCircle2 className="w-3.5 h-3.5" />compliant</span>}</div></div>
        <div className={`text-xs ${n.issues > 0 ? 'text-amber-500' : 'text-muted-foreground'}`}>{n.firewall}</div>
      </CardContent>
    </Card>
  );
  return (
    <div className="space-y-6">
      <div><div className="flex items-center gap-2 mb-3"><Cloud className="w-5 h-5 text-primary" /><h2 className="font-semibold">Google Cloud Platform</h2><Badge variant="secondary">{gcp.length} assets</Badge></div><div className="grid gap-4 md:grid-cols-3">{gcp.map((n) => <NodeCard key={n.id} n={n} />)}</div></div>
      <Separator />
      <div><div className="flex items-center gap-2 mb-3"><HardDrive className="w-5 h-5 text-primary" /><h2 className="font-semibold">Proxmox VE (On-Prem)</h2><Badge variant="secondary">{pve.length} nodes</Badge></div><div className="grid gap-4 md:grid-cols-3">{pve.map((n) => <NodeCard key={n.id} n={n} />)}</div></div>
    </div>
  );
}

function SchedulerView({ assets }) {
  const [schedules, setSchedules] = useState([]);
  const [form, setForm] = useState({ assetName: 'All assets', frequency: 'daily', time: '02:00' });
  const load = useCallback(async () => { try { setSchedules(await api('/schedules')); } catch (e) {} }, []);
  useEffect(() => { load(); }, [load]);
  const add = async () => { try { await api('/schedules', { method: 'POST', body: JSON.stringify(form) }); toast.success('Schedule created'); load(); } catch (e) { toast.error(e.message); } };
  const del = async (id) => { try { await api(`/schedules/${id}`, { method: 'DELETE' }); load(); } catch (e) {} };

  const demoLog = ['[02:00:01] cron: nightly scan triggered for 5 assets', '[02:00:02] Corporate CMS → fetching headers…', '[02:00:07] Payments API → TLS cert expires in 12d (HIGH) → alert dispatched', '[02:00:11] Ledger Service → score 88 (A)', '[02:00:15] pve-vm-db → MySQL 3306 exposed (CRITICAL) → Slack + Email sent', '[02:00:19] Run complete · 3 new findings · avg score 64'];

  return (
    <div className="grid gap-5 lg:grid-cols-2">
      <Card>
        <CardHeader><CardTitle className="text-base flex items-center gap-2"><CalendarClock className="w-4 h-4" />Automated Scan Schedules</CardTitle><CardDescription>Cron-based recurring scans with alerting.</CardDescription></CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-3 gap-2">
            <div className="col-span-3"><Label className="text-xs">Target</Label><Select value={form.assetName} onValueChange={(v) => setForm({ ...form, assetName: v })}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent><SelectItem value="All assets">All assets</SelectItem>{assets.map((a) => <SelectItem key={a.id} value={a.name}>{a.name}</SelectItem>)}</SelectContent></Select></div>
            <div className="col-span-2"><Label className="text-xs">Frequency</Label><Select value={form.frequency} onValueChange={(v) => setForm({ ...form, frequency: v })}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent>{['hourly', 'daily', 'weekly'].map((x) => <SelectItem key={x} value={x}>{x}</SelectItem>)}</SelectContent></Select></div>
            <div><Label className="text-xs">Time</Label><Input value={form.time} onChange={(e) => setForm({ ...form, time: e.target.value })} /></div>
          </div>
          <Button onClick={add} className="w-full"><Plus className="w-4 h-4 mr-1.5" />Create Schedule</Button>
          <div className="space-y-2">
            {schedules.map((s) => (<div key={s.id} className="flex items-center justify-between p-2.5 rounded-md border border-border"><div className="flex items-center gap-2 text-sm"><Clock className="w-3.5 h-3.5 text-muted-foreground" /><span className="font-medium">{s.assetName}</span><Badge variant="secondary">{s.frequency} @ {s.time}</Badge></div><Button size="icon" variant="ghost" onClick={() => del(s.id)}><Trash2 className="w-3.5 h-3.5 text-red-500" /></Button></div>))}
            {schedules.length === 0 && <p className="text-sm text-muted-foreground text-center py-4">No schedules yet.</p>}
          </div>
        </CardContent>
      </Card>
      <Card className="bg-black/90">
        <CardHeader><CardTitle className="text-sm text-emerald-400 flex items-center gap-2"><TerminalSquare className="w-4 h-4" />Recent Scan Run Log</CardTitle></CardHeader>
        <CardContent><div className="font-mono text-xs space-y-1 text-slate-300">{demoLog.map((l, i) => <div key={i} className={l.includes('CRITICAL') ? 'text-red-400' : l.includes('HIGH') ? 'text-amber-400' : l.includes('complete') ? 'text-emerald-400' : ''}>{l}</div>)}</div></CardContent>
      </Card>
    </div>
  );
}

function SettingsView() {
  const [data, setData] = useState(null);
  const [keys, setKeys] = useState({ zap: '', proxmox: '', gcp: '', nuclei: '' });
  const [alerts, setAlerts] = useState({ slack: '', discord: '', telegram: '', email: '', notifyOn: 'high' });
  useEffect(() => { (async () => { try { const s = await api('/settings'); setData(s); setAlerts((a) => ({ ...a, ...(s.alerts || {}) })); } catch (e) {} })(); }, []);
  const save = async () => { try { await api('/settings', { method: 'POST', body: JSON.stringify({ keys, alerts }) }); toast.success('Settings saved securely'); const s = await api('/settings'); setData(s); setKeys({ zap: '', proxmox: '', gcp: '', nuclei: '' }); } catch (e) { toast.error(e.message); } };

  const KeyField = ({ id, label, placeholder }) => (
    <div><Label className="text-xs">{label}</Label><Input type="password" value={keys[id]} onChange={(e) => setKeys({ ...keys, [id]: e.target.value })} placeholder={data?.keys?.[id] ? `Saved: ${data.keys[id]}` : placeholder} className="mt-1 font-mono" /></div>
  );
  return (
    <div className="grid gap-5 lg:grid-cols-2">
      <Card>
        <CardHeader><CardTitle className="text-base flex items-center gap-2"><Lock className="w-4 h-4" />Credentials Vault</CardTitle><CardDescription>Scanner & infrastructure API tokens. Stored server-side, shown masked.</CardDescription></CardHeader>
        <CardContent className="space-y-3">
          <KeyField id="zap" label="OWASP ZAP API Key" placeholder="zap-api-xxxx" />
          <KeyField id="nuclei" label="Nuclei / DAST Token" placeholder="nuclei-xxxx" />
          <KeyField id="proxmox" label="Proxmox API Token" placeholder="PVEAPIToken=user@pam!id=uuid" />
          <KeyField id="gcp" label="GCP Service Account JSON" placeholder='{"type":"service_account",...}' />
        </CardContent>
      </Card>
      <Card>
        <CardHeader><CardTitle className="text-base flex items-center gap-2"><Activity className="w-4 h-4" />Alerting & Webhooks</CardTitle><CardDescription>Notify on High/Critical findings & expiring SSL.</CardDescription></CardHeader>
        <CardContent className="space-y-3">
          <div><Label className="text-xs">Slack Webhook</Label><Input value={alerts.slack} onChange={(e) => setAlerts({ ...alerts, slack: e.target.value })} placeholder="https://hooks.slack.com/…" className="mt-1" /></div>
          <div><Label className="text-xs">Discord Webhook</Label><Input value={alerts.discord} onChange={(e) => setAlerts({ ...alerts, discord: e.target.value })} placeholder="https://discord.com/api/webhooks/…" className="mt-1" /></div>
          <div><Label className="text-xs">Telegram Bot Token</Label><Input value={alerts.telegram} onChange={(e) => setAlerts({ ...alerts, telegram: e.target.value })} placeholder="bot token" className="mt-1" /></div>
          <div><Label className="text-xs">Alert Email</Label><Input value={alerts.email} onChange={(e) => setAlerts({ ...alerts, email: e.target.value })} placeholder="security@company.com" className="mt-1" /></div>
          <div><Label className="text-xs">Notify on</Label><Select value={alerts.notifyOn} onValueChange={(v) => setAlerts({ ...alerts, notifyOn: v })}><SelectTrigger className="mt-1"><SelectValue /></SelectTrigger><SelectContent><SelectItem value="critical">Critical only</SelectItem><SelectItem value="high">High & Critical</SelectItem><SelectItem value="all">All findings</SelectItem></SelectContent></Select></div>
        </CardContent>
      </Card>
      <div className="lg:col-span-2"><Button onClick={save} className="w-full md:w-auto"><ShieldCheck className="w-4 h-4 mr-1.5" />Save Settings</Button></div>
    </div>
  );
}

function SkeletonGrid() { return (<div className="grid gap-4 md:grid-cols-3">{[1, 2, 3].map((i) => <div key={i} className="h-48 rounded-lg bg-muted animate-pulse" />)}</div>); }
