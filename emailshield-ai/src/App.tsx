/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useEffect, useState } from 'react';
import { Navbar } from './components/Navbar';
import { UploadArea } from './components/UploadArea';
import { Dashboard } from './components/Dashboard';
import { MailboxInbox } from './components/MailboxInbox';
import { ImapConnectForm } from './components/ImapConnectForm';
import { parseRawEml } from './utils/emlParser';
import { hashAndClassifyAttachments } from './utils/attachments';
import { analyzeEmailWithGemini } from './services/geminiService';
import { SIGN_IN_URL } from './services/gmailService';
import { fetchMe, type MailProvider } from './services/mailboxService';
import { ParsedEmail, ThreatAnalysisResult } from './types';
import { Shield, Cpu, RefreshCw, AlertCircle, Server } from 'lucide-react';

export default function App() {
  const [parsedEmail, setParsedEmail] = useState<ParsedEmail | null>(null);
  const [analysisResult, setAnalysisResult] = useState<ThreatAnalysisResult | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [currentFileName, setCurrentFileName] = useState<string | undefined>(undefined);
  const [analysisError, setAnalysisError] = useState<string | null>(null);
  const [analysisStep, setAnalysisStep] = useState<string>('Initializing forensic inspection...');
  const [caseLoading, setCaseLoading] = useState(false);
  const [caseNotice, setCaseNotice] = useState<string | null>(null);

  const [authEmail, setAuthEmail] = useState<string | null>(null);
  const [authProvider, setAuthProvider] = useState<MailProvider>('gmail');
  const [authChecked, setAuthChecked] = useState(false);
  const [authNotice, setAuthNotice] = useState<string | null>(null);
  const [showImapForm, setShowImapForm] = useState(false);

  // Check for an existing Google session + surface any OAuth redirect result.
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const authError = params.get('auth_error');
    const signedIn = params.get('signed_in');
    if (authError || signedIn) {
      if (authError) {
        setAuthNotice(
          authError === 'state_mismatch'
            ? 'Sign-in could not be verified (state mismatch). Please try again.'
            : `Google sign-in failed: ${authError}`,
        );
      }
      params.delete('auth_error');
      params.delete('signed_in');
      const qs = params.toString();
      window.history.replaceState({}, '', window.location.pathname + (qs ? `?${qs}` : ''));
    }

    fetchMe()
      .then((me) => {
        if (me) {
          setAuthEmail(me.email);
          setAuthProvider(me.provider);
          if (signedIn) setAuthNotice(null);
        }
      })
      .catch(() => {
        /* not signed in / server down — landing page handles it */
      })
      .finally(() => setAuthChecked(true));
  }, []);

  const handleSignedOut = (notice?: string) => {
    setAuthEmail(null);
    setAuthProvider('gmail');
    setShowImapForm(false);
    setAuthNotice(notice ?? null);
  };

  const handleImapConnected = (imapEmail: string) => {
    setAuthEmail(imapEmail);
    setAuthProvider('imap');
    setShowImapForm(false);
    setAuthNotice(null);
  };

  // Handoff from the Chrome extension: /?case=EMS-XXXXXX loads a stored analysis.
  useEffect(() => {
    const caseId = new URLSearchParams(window.location.search).get('case');
    if (!caseId) return;

    setCaseLoading(true);
    fetch(`/api/analysis/${encodeURIComponent(caseId)}`)
      .then(async (res) => {
        if (!res.ok) {
          throw new Error(
            res.status === 404
              ? `Analysis "${caseId}" was not found — the link may have expired (the server keeps only the 50 most recent).`
              : `Could not load analysis "${caseId}" (HTTP ${res.status}).`,
          );
        }
        return res.json();
      })
      .then((data: { caseId: string; parsedEmail: ParsedEmail; analysis: ThreatAnalysisResult }) => {
        setParsedEmail(data.parsedEmail);
        setAnalysisResult(data.analysis);
        setCurrentFileName(`Gmail Quick Scan · ${data.caseId}`);
        setCaseNotice(null);
      })
      .catch((err: any) => {
        setCaseNotice(err?.message || 'That analysis link could not be loaded.');
      })
      .finally(() => {
        setCaseLoading(false);
        // Drop the query param so a refresh / reset starts clean.
        window.history.replaceState({}, '', window.location.pathname);
      });
  }, []);

  const handleAnalyze = async (rawEmail: string, fileName?: string) => {
    setIsAnalyzing(true);
    setAnalysisError(null);
    setCurrentFileName(fileName);

    try {
      setAnalysisStep('Parsing RFC 5322 headers, MIME boundaries and attachments...');
      const parsed = parseRawEml(rawEmail);
      await hashAndClassifyAttachments(parsed); // SHA-256 + extension risk; drops the bytes
      setParsedEmail(parsed);

      setAnalysisStep('Evaluating SPF, DKIM, DMARC authentication & Received routing hops...');
      await new Promise((r) => setTimeout(r, 250));

      setAnalysisStep('Running deterministic rule checks and querying Gemini for phishing, urgency, and impersonation...');
      const analysis = await analyzeEmailWithGemini(parsed);
      setAnalysisResult(analysis);
    } catch (err: any) {
      console.error('Analysis error:', err);
      setAnalysisError(err.message || 'An error occurred during forensic email analysis.');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleReset = () => {
    setParsedEmail(null);
    setAnalysisResult(null);
    setCurrentFileName(undefined);
    setAnalysisError(null);
    setCaseNotice(null);
  };

  // Connected users (Gmail OR IMAP) see their inbox instead of the landing page.
  const showInbox = authChecked && !!authEmail && !caseLoading && !isAnalyzing && !analysisResult;
  // The IMAP connect form replaces the landing hero + upload area while open.
  const showImapConnect = showImapForm && !showInbox && !isAnalyzing && !analysisResult && !caseLoading;

  return (
    <div className="min-h-screen bg-[#0a0a0a] text-gray-200 flex flex-col font-sans">
      {/* Top Navbar */}
      <Navbar
        hasAnalysis={!!analysisResult}
        onReset={handleReset}
        isAnalyzing={isAnalyzing}
        engine={analysisResult?.engine}
      />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">
        {/* Loading a handoff case from the Chrome extension */}
        {caseLoading && (
          <div className="rounded-xl border border-white/10 bg-[#161616] p-8 text-center shadow-2xl max-w-xl mx-auto my-8 space-y-3">
            <RefreshCw className="w-7 h-7 animate-spin text-blue-400 mx-auto" />
            <p className="text-sm text-gray-300">Loading the analysis from Gmail Quick Scan…</p>
          </div>
        )}

        {/* Handoff case could not be loaded — fall back to the upload screen */}
        {caseNotice && !caseLoading && (
          <div className="p-4 rounded-xl bg-amber-500/10 border border-amber-500/20 text-amber-200 text-sm flex items-start space-x-3 max-w-2xl mx-auto">
            <AlertCircle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
            <div>
              <h4 className="font-semibold text-white">Analysis link unavailable</h4>
              <p className="text-xs text-amber-300/90 mt-1">{caseNotice}</p>
              <p className="text-xs text-gray-400 mt-1">Re-run the scan from Gmail, or upload the email below.</p>
              <button
                onClick={() => setCaseNotice(null)}
                className="mt-2 text-xs font-mono text-blue-400 hover:underline cursor-pointer"
              >
                Dismiss
              </button>
            </div>
          </div>
        )}

        {/* Google auth notice (sign-in failed / session ended) */}
        {authNotice && !caseLoading && (
          <div className="p-4 rounded-xl bg-amber-500/10 border border-amber-500/20 text-amber-200 text-sm flex items-start gap-3 max-w-2xl mx-auto">
            <AlertCircle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
            <div className="flex-1">
              <h4 className="font-semibold text-white">Google sign-in</h4>
              <p className="text-xs text-amber-300/90 mt-1">{authNotice}</p>
              <div className="mt-2 flex gap-3">
                <a href={SIGN_IN_URL} className="text-xs font-mono text-blue-400 hover:underline">
                  Sign in again
                </a>
                <button
                  onClick={() => setAuthNotice(null)}
                  className="text-xs font-mono text-gray-400 hover:underline cursor-pointer"
                >
                  Dismiss
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Connected (Gmail OR IMAP): inbox with rule-based risk badges */}
        {showInbox && authEmail && (
          <MailboxInbox email={authEmail} provider={authProvider} onSignedOut={handleSignedOut} />
        )}

        {/* IMAP connect form — replaces the landing page while open */}
        {showImapConnect && (
          <ImapConnectForm onConnected={handleImapConnected} onCancel={() => setShowImapForm(false)} />
        )}

        {/* Hero Banner + sign-in — landing page (not connected) */}
        {!showInbox && !showImapConnect && !analysisResult && !isAnalyzing && !caseLoading && (
          <div className="text-center max-w-3xl mx-auto pt-4 pb-2 space-y-4">
            <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-400 text-xs font-mono">
              <Shield className="w-3.5 h-3.5" />
              <span>Next-Gen Cybersecurity Forensics</span>
            </div>
            <h2 className="text-3xl sm:text-4xl font-semibold tracking-tight text-white">
              Instant Email Threat Detection & Forensic Intelligence
            </h2>
            <p className="text-gray-400 text-sm sm:text-base leading-relaxed">
              Upload raw <span className="text-gray-200 font-mono">.eml</span> emails to inspect full <span className="text-blue-400 font-mono">Received</span> routing hops, authenticate <span className="text-emerald-400 font-mono">SPF / DKIM / DMARC</span> signatures, and deploy <span className="text-blue-400 font-mono">Gemini AI</span> to isolate social engineering, brand spoofing, and credential harvesting.
            </p>
            {authChecked && (
              <div className="pt-1 flex flex-col sm:flex-row items-center justify-center gap-3">
                <a
                  href={SIGN_IN_URL}
                  className="inline-flex items-center gap-2.5 px-5 py-2.5 rounded-lg bg-white text-gray-800 text-sm font-semibold border border-gray-300 hover:bg-gray-100 transition shadow"
                >
                  <svg className="w-4 h-4" viewBox="0 0 48 48" aria-hidden="true">
                    <path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z" />
                    <path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z" />
                    <path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z" />
                    <path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z" />
                  </svg>
                  <span>Sign in with Google</span>
                </a>
                <button
                  onClick={() => {
                    setAuthNotice(null);
                    setShowImapForm(true);
                  }}
                  className="inline-flex items-center gap-2.5 px-5 py-2.5 rounded-lg bg-white/[0.05] text-gray-100 text-sm font-semibold border border-white/15 hover:bg-white/[0.1] transition shadow cursor-pointer"
                >
                  <Server className="w-4 h-4 text-blue-400" />
                  <span>Connect via IMAP</span>
                </button>
              </div>
            )}
            <p className="text-[11px] text-gray-500">
              Gmail is read-only OAuth. IMAP uses an app password — works with Yahoo, iCloud, GMX, Zoho and most
              custom / college servers. (Outlook &amp; Microsoft 365 now require OAuth for IMAP and aren&apos;t supported here.)
            </p>
          </div>
        )}

        {/* Upload / Paste area — landing flow only (hidden while the IMAP form is open) */}
        {!showInbox && !showImapConnect && (!analysisResult || isAnalyzing) && !caseLoading && (
          <UploadArea onAnalyze={handleAnalyze} isAnalyzing={isAnalyzing} />
        )}

        {/* Loading / Analysis Progress Animation */}
        {isAnalyzing && (
          <div className="rounded-xl border border-white/10 bg-[#161616] p-8 text-center shadow-2xl backdrop-blur max-w-xl mx-auto my-8 space-y-4">
            <div className="relative flex items-center justify-center w-14 h-14 rounded-lg bg-blue-600/20 border border-blue-500/30 text-blue-400 mx-auto shadow-[0_0_20px_rgba(37,99,235,0.3)]">
              <RefreshCw className="w-7 h-7 animate-spin text-blue-400" />
            </div>

            <div>
              <h3 className="text-base font-semibold text-white flex items-center justify-center gap-2">
                <Cpu className="w-4 h-4 text-blue-400" />
                <span>Running Deep Forensic Analysis</span>
              </h3>
              <p className="text-xs font-mono text-gray-300 mt-2 bg-black border border-white/10 py-2 px-3 rounded-lg inline-block">
                {analysisStep}
              </p>
            </div>

            <p className="text-[10px] uppercase tracking-widest text-gray-500 font-bold">
              Auditing RFC headers &bull; Verifying cryptographic signatures &bull; Scanning for social engineering
            </p>
          </div>
        )}

        {/* Error Notification */}
        {analysisError && (
          <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/20 text-red-200 text-sm flex items-start space-x-3 max-w-2xl mx-auto">
            <AlertCircle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
            <div>
              <h4 className="font-semibold text-white">Forensic Analysis Failed</h4>
              <p className="text-xs text-red-300 mt-1">{analysisError}</p>
              <button
                onClick={() => setAnalysisError(null)}
                className="mt-2 text-xs font-mono text-blue-400 hover:underline cursor-pointer"
              >
                Dismiss
              </button>
            </div>
          </div>
        )}

        {/* Results Dashboard when analyzed */}
        {analysisResult && parsedEmail && !isAnalyzing && (
          <Dashboard
            email={parsedEmail}
            analysis={analysisResult}
            fileName={currentFileName}
            onAnalyzeEml={handleAnalyze}
            onAnalysisUpdate={setAnalysisResult}
          />
        )}
      </main>

      {/* Footer */}
      <footer className="mt-8 border-t border-white/10 bg-[#0a0a0a] py-4 px-4 text-center text-[10px] text-gray-500 uppercase tracking-widest">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-2">
          <div>EmailShield Forensic Engine v2.4.1-Stable</div>
          <div className="flex gap-4">
            <span>RFC 5322 Standard</span>
            <span>Powered by Google Gemini</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
