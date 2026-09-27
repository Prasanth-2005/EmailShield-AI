import React, { useState } from 'react';
import { Server, KeyRound, Mail, Loader2, AlertCircle, ArrowLeft, Lock } from 'lucide-react';
import { imapConnect, type ImapConnectFailure } from '../services/mailboxService';

interface ImapConnectFormProps {
  onConnected: (email: string) => void;
  onCancel: () => void;
}

type PresetKey = 'outlook' | 'yahoo' | 'custom';

const PRESETS: Record<PresetKey, { label: string; host: string; appPwNote: React.ReactNode }> = {
  outlook: {
    label: 'Outlook / Microsoft 365',
    host: 'outlook.office365.com',
    appPwNote: (
      <>
        <span className="text-amber-300">Heads up:</span> Microsoft disabled password / app-password sign-in for
        Outlook &amp; Microsoft 365 IMAP — these mailboxes now require OAuth, which this form does not do. Try{' '}
        <span className="text-gray-300">Yahoo</span> or a <span className="text-gray-300">Custom</span> server
        (iCloud, GMX, Zoho, college mail) instead.
      </>
    ),
  },
  yahoo: {
    label: 'Yahoo Mail',
    host: 'imap.mail.yahoo.com',
    appPwNote: (
      <>
        Yahoo account → <span className="text-gray-300">Account Security → Generate app password</span> (or “Manage app
        passwords”). Yahoo requires an app password for IMAP — your normal password will not work.
      </>
    ),
  },
  custom: {
    label: 'Custom IMAP server',
    host: '',
    appPwNote: (
      <>
        Use an <span className="text-gray-300">app-specific password</span> if your provider issues one; otherwise your
        normal IMAP password. Port 993 uses implicit SSL/TLS; 143 uses STARTTLS.
      </>
    ),
  },
};

export const ImapConnectForm: React.FC<ImapConnectFormProps> = ({ onConnected, onCancel }) => {
  const [preset, setPreset] = useState<PresetKey>('yahoo');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [host, setHost] = useState(PRESETS.yahoo.host);
  const [port, setPort] = useState(993);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<{ kind: 'auth' | 'conn' | 'other'; message: string } | null>(null);

  const choosePreset = (key: PresetKey) => {
    setPreset(key);
    setErr(null);
    if (key !== 'custom') setHost(PRESETS[key].host);
    else setHost('');
  };

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr(null);
    if (!email.trim() || !password || !host.trim()) {
      setErr({ kind: 'other', message: 'Email, app password and IMAP server host are all required.' });
      return;
    }
    setBusy(true);
    try {
      const { email: connectedEmail } = await imapConnect({
        email: email.trim(),
        password,
        host: host.trim(),
        port: Number(port) || 993,
      });
      setPassword(''); // drop it from component state immediately
      onConnected(connectedEmail);
    } catch (e2) {
      const f = e2 as ImapConnectFailure;
      if (f.code === 'imap-auth') setErr({ kind: 'auth', message: f.message });
      else if (f.code === 'imap-conn') setErr({ kind: 'conn', message: f.message });
      else setErr({ kind: 'other', message: f.message || 'Could not connect.' });
    } finally {
      setBusy(false);
    }
  };

  const inputCls =
    'w-full text-sm px-3 py-2 rounded-lg bg-black border border-white/10 text-gray-100 placeholder-gray-600 focus:outline-none focus:border-blue-500 transition';

  return (
    <div className="max-w-lg mx-auto rounded-xl border border-white/10 bg-[#161616] p-6 shadow-2xl">
      <button
        onClick={onCancel}
        className="flex items-center gap-1.5 text-xs font-medium text-gray-400 hover:text-white transition mb-4 cursor-pointer"
      >
        <ArrowLeft className="w-3.5 h-3.5" />
        Back
      </button>

      <div className="flex items-center gap-2.5 mb-1">
        <Server className="w-5 h-5 text-blue-400" />
        <h2 className="text-lg font-semibold text-white">Connect via IMAP</h2>
      </div>
      <p className="text-xs text-gray-400 mb-5">
        For Yahoo, iCloud, GMX, Zoho and any IMAP server that accepts an app password. Read-only — the app never
        sends or changes mail. (Outlook / Microsoft 365 now require OAuth for IMAP.)
      </p>

      <form onSubmit={submit} className="space-y-4">
        {/* Provider preset */}
        <div>
          <label className="block text-[11px] uppercase tracking-widest text-gray-500 font-bold mb-1.5">Provider</label>
          <div className="grid grid-cols-3 gap-2">
            {(Object.keys(PRESETS) as PresetKey[]).map((key) => (
              <button
                key={key}
                type="button"
                onClick={() => choosePreset(key)}
                className={`text-xs font-medium px-2 py-2 rounded-lg border transition cursor-pointer ${
                  preset === key
                    ? 'bg-blue-600/20 border-blue-500/50 text-white'
                    : 'bg-white/[0.03] border-white/10 text-gray-400 hover:text-gray-200'
                }`}
              >
                {key === 'outlook' ? 'Outlook' : key === 'yahoo' ? 'Yahoo' : 'Custom'}
              </button>
            ))}
          </div>
        </div>

        {/* Email */}
        <div>
          <label className="block text-[11px] uppercase tracking-widest text-gray-500 font-bold mb-1.5">Email address</label>
          <div className="relative">
            <Mail className="w-4 h-4 text-gray-600 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="email"
              autoComplete="username"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="you@yahoo.com"
              className={`${inputCls} pl-9`}
            />
          </div>
        </div>

        {/* App password */}
        <div>
          <label className="block text-[11px] uppercase tracking-widest text-gray-500 font-bold mb-1.5">App password</label>
          <div className="relative">
            <KeyRound className="w-4 h-4 text-gray-600 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="password"
              autoComplete="off"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="app-specific password"
              className={`${inputCls} pl-9`}
            />
          </div>
          <p className="text-[11px] text-gray-500 mt-1.5 leading-relaxed">{PRESETS[preset].appPwNote}</p>
        </div>

        {/* Host + port */}
        <div className="grid grid-cols-[1fr_auto] gap-3">
          <div>
            <label className="block text-[11px] uppercase tracking-widest text-gray-500 font-bold mb-1.5">IMAP server</label>
            <input
              type="text"
              value={host}
              onChange={(e) => setHost(e.target.value)}
              readOnly={preset !== 'custom'}
              placeholder="imap.example.com"
              className={`${inputCls} ${preset !== 'custom' ? 'opacity-70 cursor-not-allowed' : ''} font-mono`}
            />
          </div>
          <div className="w-24">
            <label className="block text-[11px] uppercase tracking-widest text-gray-500 font-bold mb-1.5">Port</label>
            <input
              type="number"
              value={port}
              onChange={(e) => setPort(Number(e.target.value))}
              className={`${inputCls} font-mono`}
            />
          </div>
        </div>
        <p className="text-[11px] text-gray-500 flex items-center gap-1.5 -mt-1">
          <Lock className="w-3 h-3" /> Port 993 = SSL/TLS (default). The password is kept in server memory for this
          session only and is never stored.
        </p>

        {err && (
          <div
            className={`p-3 rounded-lg border text-xs flex items-start gap-2.5 ${
              err.kind === 'auth'
                ? 'bg-amber-500/10 border-amber-500/20 text-amber-200'
                : 'bg-red-500/10 border-red-500/20 text-red-200'
            }`}
          >
            <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
            <div>
              <p className="font-medium">{err.message}</p>
            </div>
          </div>
        )}

        <button
          type="submit"
          disabled={busy}
          className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-60 disabled:cursor-wait text-white text-sm font-semibold border border-blue-400/30 transition cursor-pointer shadow"
        >
          {busy ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin" />
              <span>Connecting…</span>
            </>
          ) : (
            <>
              <Server className="w-4 h-4" />
              <span>Connect</span>
            </>
          )}
        </button>
      </form>
    </div>
  );
};
