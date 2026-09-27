import React, { useCallback, useEffect, useState } from 'react';
import { RefreshCw, AlertCircle, LogOut, Inbox as InboxIcon, ChevronRight, Mail } from 'lucide-react';
import {
  fetchInbox,
  signOutMailbox,
  MailboxAuthError,
  type InboxMessage,
  type MailProvider,
} from '../services/mailboxService';
import { RiskBadge } from './RiskBadge';
import { MessageDetailView } from './MessageDetailView';

interface MailboxInboxProps {
  email: string;
  /** Which login path connected this mailbox — drives the API base path only. */
  provider: MailProvider;
  /** Called after a successful sign-out (or when the session is lost). */
  onSignedOut: (notice?: string) => void;
}

const PROVIDER_LABEL: Record<MailProvider, string> = { gmail: 'Gmail', imap: 'IMAP' };

function relativeDate(raw: string): string {
  const d = new Date(raw);
  if (isNaN(d.getTime())) return raw || '';
  const now = Date.now();
  const diff = now - d.getTime();
  const day = 86_400_000;
  if (diff < day && d.getDate() === new Date().getDate()) {
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }
  if (diff < 7 * day) return d.toLocaleDateString([], { weekday: 'short' });
  return d.toLocaleDateString([], { month: 'short', day: 'numeric' });
}

export const MailboxInbox: React.FC<MailboxInboxProps> = ({ email, provider, onSignedOut }) => {
  const [messages, setMessages] = useState<InboxMessage[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [partialFailures, setPartialFailures] = useState(0);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const load = useCallback(() => {
    setLoading(true);
    setError(null);
    fetchInbox(provider)
      .then((res) => {
        setMessages(res.messages);
        setPartialFailures(res.partialFailures || 0);
      })
      .catch((err) => {
        if (err instanceof MailboxAuthError) {
          onSignedOut('Your mailbox session ended. Please connect again.');
        } else {
          setError(err?.message || 'Could not load your inbox.');
        }
      })
      .finally(() => setLoading(false));
  }, [onSignedOut, provider]);

  useEffect(() => {
    load();
  }, [load]);

  const handleSignOut = async () => {
    try {
      await signOutMailbox(provider);
    } catch {
      /* clear locally regardless */
    }
    onSignedOut();
  };

  if (selectedId) {
    return (
      <MessageDetailView
        messageId={selectedId}
        provider={provider}
        onBack={() => setSelectedId(null)}
        onAuthLost={(msg) => onSignedOut(msg)}
      />
    );
  }

  const counts = messages
    ? messages.reduce(
        (acc, m) => ((acc[m.riskBand] = (acc[m.riskBand] || 0) + 1), acc),
        {} as Record<string, number>,
      )
    : {};

  return (
    <div className="space-y-4">
      {/* Account bar */}
      <div className="rounded-xl border border-white/10 bg-[#161616] px-5 py-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3 shadow-xl">
        <div className="flex items-center gap-2.5 text-sm">
          <InboxIcon className="w-4 h-4 text-blue-500 shrink-0" />
          <span className="text-gray-400">Connected via</span>
          <span className="text-[10px] font-mono uppercase tracking-wider px-1.5 py-0.5 rounded bg-white/[0.06] border border-white/10 text-gray-300">
            {PROVIDER_LABEL[provider]}
          </span>
          <span className="text-white font-medium truncate">{email}</span>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={load}
            disabled={loading}
            className="flex items-center gap-1.5 text-xs font-medium px-3 py-1.5 rounded-lg bg-white/[0.05] hover:bg-white/[0.1] border border-white/10 text-gray-200 transition disabled:opacity-50 cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
          <button
            onClick={handleSignOut}
            className="flex items-center gap-1.5 text-xs font-medium px-3 py-1.5 rounded-lg bg-white/[0.05] hover:bg-white/[0.1] border border-white/10 text-gray-200 hover:text-white transition cursor-pointer"
          >
            <LogOut className="w-3.5 h-3.5" />
            <span>Sign out</span>
          </button>
        </div>
      </div>

      {/* Header + legend */}
      <div className="flex items-center justify-between px-1">
        <h2 className="text-sm font-semibold text-white">Inbox — last 20 messages</h2>
        {messages && (
          <div className="flex items-center gap-3 text-[11px] text-gray-400">
            {counts.red ? <span className="flex items-center gap-1"><RiskBadge band="red" variant="dot" /> {counts.red}</span> : null}
            {counts.amber ? <span className="flex items-center gap-1"><RiskBadge band="amber" variant="dot" /> {counts.amber}</span> : null}
            {counts.green ? <span className="flex items-center gap-1"><RiskBadge band="green" variant="dot" /> {counts.green}</span> : null}
          </div>
        )}
      </div>

      <p className="px-1 -mt-2 text-[11px] text-gray-500">
        Badges are computed from the free, instant rule engine on message metadata — no AI call. Open a
        message and run <span className="text-gray-300">Advanced Scan</span> for the full rule + ML + Gemini forensic report.
      </p>

      {error && (
        <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/20 text-red-200 text-sm flex items-start gap-3">
          <AlertCircle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
          <div className="flex-1">
            <h4 className="font-semibold text-white">Inbox unavailable</h4>
            <p className="text-xs text-red-300 mt-1">{error}</p>
            <button onClick={load} className="mt-2 text-xs font-mono text-blue-400 hover:underline cursor-pointer">
              Retry
            </button>
          </div>
        </div>
      )}

      {partialFailures > 0 && !error && (
        <div className="px-4 py-2 rounded-lg bg-amber-500/10 border border-amber-500/20 text-amber-300 text-[11px] font-mono">
          {partialFailures} message{partialFailures === 1 ? '' : 's'} could not be read and are not shown.
        </div>
      )}

      {loading && !messages && (
        <div className="rounded-xl border border-white/10 bg-[#161616] p-10 text-center">
          <RefreshCw className="w-6 h-6 animate-spin text-blue-400 mx-auto" />
          <p className="text-sm text-gray-400 mt-3">Loading your inbox…</p>
        </div>
      )}

      {messages && messages.length === 0 && !loading && (
        <div className="rounded-xl border border-white/10 bg-[#161616] p-10 text-center text-sm text-gray-400">
          <Mail className="w-6 h-6 text-gray-600 mx-auto mb-2" />
          No messages found in your inbox.
        </div>
      )}

      {messages && messages.length > 0 && (
        <div className="rounded-xl border border-white/10 bg-[#161616] shadow-xl overflow-hidden divide-y divide-white/[0.06]">
          {messages.map((m) => (
            <button
              key={m.id}
              onClick={() => setSelectedId(m.id)}
              className="w-full text-left px-4 sm:px-5 py-3.5 flex items-center gap-3 hover:bg-white/[0.03] transition cursor-pointer group"
            >
              <RiskBadge band={m.riskBand} variant="dot" className="shrink-0" />
              <div className="min-w-0 flex-1">
                <div className="flex items-center justify-between gap-3">
                  <span className="text-sm font-medium text-gray-100 truncate">
                    {m.from.name}
                    {m.from.domain && (
                      <span className="text-gray-500 font-mono text-xs font-normal"> · {m.from.domain}</span>
                    )}
                  </span>
                  <span className="text-[11px] text-gray-500 font-mono shrink-0">{relativeDate(m.date)}</span>
                </div>
                <div className="text-sm text-gray-300 truncate mt-0.5">{m.subject}</div>
                <div className="flex items-center gap-2 mt-1">
                  <RiskBadge band={m.riskBand} score={m.ruleScore} />
                  {m.ruleCount > 0 && (
                    <span className="text-[10px] text-gray-500 font-mono truncate">
                      {m.ruleTitles.slice(0, 2).join(' · ')}
                      {m.ruleCount > 2 ? ` +${m.ruleCount - 2}` : ''}
                    </span>
                  )}
                </div>
              </div>
              <ChevronRight className="w-4 h-4 text-gray-600 group-hover:text-gray-400 shrink-0" />
            </button>
          ))}
        </div>
      )}
    </div>
  );
};
