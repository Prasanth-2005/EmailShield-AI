import React, { useState, useMemo } from 'react';
import { Eye, Code, FileText, AlertTriangle, ExternalLink, HelpCircle, ShieldAlert, Sparkles } from 'lucide-react';
import { ParsedEmail, SuspiciousPhrase, ExtractedLink } from '../types';

interface EmailPreviewProps {
  email: ParsedEmail;
  suspiciousPhrases: SuspiciousPhrase[];
}

export const EmailPreview: React.FC<EmailPreviewProps> = ({ email, suspiciousPhrases }) => {
  const [viewMode, setViewMode] = useState<'highlighted' | 'rendered' | 'raw'>('highlighted');
  const [activePhrase, setActivePhrase] = useState<SuspiciousPhrase | null>(null);

  const { bodyText, bodyHtml, rawSource, extractedLinks } = email;

  // Inline highlighter logic
  const highlightedElements = useMemo(() => {
    if (!bodyText || suspiciousPhrases.length === 0) {
      return [<span key="pure-body">{bodyText || '(No plain text body content found)'}</span>];
    }

    // Identify match intervals
    interface MatchInterval {
      start: number;
      end: number;
      phraseObj: SuspiciousPhrase;
      text: string;
    }

    const intervals: MatchInterval[] = [];

    suspiciousPhrases.forEach((item) => {
      if (!item.phrase || item.phrase.trim().length === 0) return;

      const escaped = item.phrase.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const regex = new RegExp(escaped, 'gi');
      let match;

      while ((match = regex.exec(bodyText)) !== null) {
        intervals.push({
          start: match.index,
          end: match.index + match[0].length,
          phraseObj: item,
          text: match[0],
        });
      }
    });

    // Sort intervals by start position
    intervals.sort((a, b) => a.start - b.start || b.end - a.end);

    // Filter out overlapping intervals
    const nonOverlapping: MatchInterval[] = [];
    let lastEnd = 0;

    for (const interval of intervals) {
      if (interval.start >= lastEnd) {
        nonOverlapping.push(interval);
        lastEnd = interval.end;
      }
    }

    // Build JSX nodes
    const elements: React.ReactNode[] = [];
    let currentIndex = 0;

    nonOverlapping.forEach((interval, idx) => {
      // Unhighlighted text before this match
      if (interval.start > currentIndex) {
        elements.push(
          <span key={`text-${currentIndex}`}>
            {bodyText.substring(currentIndex, interval.start)}
          </span>
        );
      }

      // Highlighted phrase
      const isSelected = activePhrase?.phrase.toLowerCase() === interval.phraseObj.phrase.toLowerCase();

      elements.push(
        <span
          key={`highlight-${idx}-${interval.start}`}
          onClick={() => setActivePhrase(interval.phraseObj)}
          className={`inline-block my-0.5 px-1.5 py-0.5 rounded cursor-pointer transition border-b-2 font-medium ${
            interval.phraseObj.severity === 'critical'
              ? 'bg-rose-500/25 text-rose-200 border-rose-500 hover:bg-rose-500/40'
              : interval.phraseObj.severity === 'high'
              ? 'bg-red-500/25 text-red-200 border-red-500 hover:bg-red-500/40'
              : 'bg-amber-500/25 text-amber-200 border-amber-500 hover:bg-amber-500/40'
          } ${isSelected ? 'ring-2 ring-cyan-400 bg-rose-500/40' : ''}`}
          title={`${interval.phraseObj.category}: ${interval.phraseObj.explanation}`}
        >
          {interval.text}
          <span className="ml-1 text-[10px] font-mono opacity-80 uppercase px-1 rounded bg-black/40">
            {interval.phraseObj.severity}
          </span>
        </span>
      );

      currentIndex = interval.end;
    });

    // Remaining text after last match
    if (currentIndex < bodyText.length) {
      elements.push(
        <span key={`text-end-${currentIndex}`}>
          {bodyText.substring(currentIndex)}
        </span>
      );
    }

    return elements;
  }, [bodyText, suspiciousPhrases, activePhrase]);

  return (
    <div className="rounded-xl border border-white/10 bg-[#161616] shadow-xl overflow-hidden">
      {/* Header bar with view toggles */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-white/10 bg-black/40 px-4 py-3 gap-2">
        <div className="flex items-center space-x-2 text-sm font-semibold text-white">
          <Eye className="w-4 h-4 text-blue-500" />
          <span>Original Email Inspection</span>
          {suspiciousPhrases.length > 0 && (
            <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/20 uppercase tracking-wider">
              {suspiciousPhrases.length} Suspicious Phrases Flagged
            </span>
          )}
        </div>

        {/* View mode buttons */}
        <div className="flex items-center space-x-1 bg-black/60 p-1 rounded-lg border border-white/10 text-xs font-mono">
          <button
            id="btn-view-highlighted"
            onClick={() => setViewMode('highlighted')}
            className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-md transition cursor-pointer ${
              viewMode === 'highlighted'
                ? 'bg-blue-600 text-white font-semibold shadow-sm'
                : 'text-gray-400 hover:text-white'
            }`}
          >
            <Sparkles className="w-3.5 h-3.5" />
            <span>Threat Highlights</span>
          </button>

          {bodyHtml && (
            <button
              id="btn-view-rendered"
              onClick={() => setViewMode('rendered')}
              className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-md transition cursor-pointer ${
                viewMode === 'rendered'
                  ? 'bg-blue-600 text-white font-semibold shadow-sm'
                  : 'text-gray-400 hover:text-white'
              }`}
            >
              <FileText className="w-3.5 h-3.5" />
              <span>Rendered HTML</span>
            </button>
          )}

          <button
            id="btn-view-raw"
            onClick={() => setViewMode('raw')}
            className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-md transition cursor-pointer ${
              viewMode === 'raw'
                ? 'bg-blue-600 text-white font-semibold shadow-sm'
                : 'text-gray-400 hover:text-white'
            }`}
          >
            <Code className="w-3.5 h-3.5" />
            <span>Raw .EML Source</span>
          </button>
        </div>
      </div>

      {/* Interactive Active Phrase Details Banner */}
      {activePhrase && viewMode === 'highlighted' && (
        <div className="bg-red-500/10 border-b border-red-500/20 p-3.5 px-5 flex items-start justify-between gap-3 text-xs">
          <div className="flex items-start space-x-2.5">
            <ShieldAlert className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
            <div>
              <div className="flex items-center gap-2">
                <span className="font-semibold text-red-200 font-sans">
                  Suspicious Cue: "{activePhrase.phrase}"
                </span>
                <span className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded bg-red-500/20 text-red-300 border border-red-500/30 uppercase">
                  {activePhrase.category}
                </span>
              </div>
              <p className="text-gray-300 mt-1 leading-relaxed">
                {activePhrase.explanation}
              </p>
            </div>
          </div>
          <button
            onClick={() => setActivePhrase(null)}
            className="text-gray-400 hover:text-white text-[11px] underline cursor-pointer shrink-0"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Main Body View */}
      <div className="p-5">
        {/* View 1: Threat Highlighted Body */}
        {viewMode === 'highlighted' && (
          <div className="space-y-4">
            <div className="p-4 rounded-xl bg-black/40 border border-white/10 text-gray-200 text-sm leading-relaxed whitespace-pre-wrap font-mono selection:bg-red-500/30">
              {highlightedElements}
            </div>

            {/* Guide footnote */}
            <div className="flex items-center space-x-2 text-xs text-gray-500">
              <HelpCircle className="w-3.5 h-3.5 text-blue-400 shrink-0" />
              <span>
                Suspicious phrases are highlighted inline above. Click any highlighted phrase to view its forensic breakdown.
              </span>
            </div>
          </div>
        )}

        {/* View 2: Rendered HTML Body */}
        {viewMode === 'rendered' && bodyHtml && (
          <div className="rounded-xl border border-white/10 bg-white overflow-hidden p-4 min-h-[350px]">
            {/* Sandboxed rendering container */}
            <div
              className="rendered-email-container text-slate-900 text-sm"
              dangerouslySetInnerHTML={{ __html: bodyHtml }}
            />
          </div>
        )}

        {/* View 3: Raw EML Source */}
        {viewMode === 'raw' && (
          <div className="relative">
            <pre className="p-4 rounded-xl bg-black border border-white/10 text-gray-300 font-mono text-xs overflow-x-auto max-h-[500px] whitespace-pre leading-relaxed">
              {rawSource}
            </pre>
          </div>
        )}

        {/* Extracted Hyperlinks Inspection Table */}
        {extractedLinks.length > 0 && (
          <div className="mt-6 pt-5 border-t border-white/10">
            <div className="flex items-center space-x-2 text-xs font-semibold uppercase tracking-wider text-gray-300 mb-3">
              <ExternalLink className="w-4 h-4 text-blue-400" />
              <span>Extracted Hyperlink Destinations ({extractedLinks.length})</span>
            </div>

            <div className="space-y-2">
              {extractedLinks.map((link, idx) => (
                <div
                  key={idx}
                  className={`p-3 rounded-lg border text-xs font-mono ${
                    link.isMismatched
                      ? 'bg-red-500/[0.04] border-red-500/30 text-red-200'
                      : 'bg-black/40 border-white/10 text-gray-300'
                  }`}
                >
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 mb-1">
                    <div className="flex items-center space-x-2">
                      <span className="text-gray-500 text-[10px] uppercase tracking-wider">Display Text:</span>
                      <span className="font-semibold text-white">{link.text}</span>
                    </div>
                    {link.isMismatched && (
                      <span className="inline-flex items-center gap-1 text-[10px] font-bold px-2 py-0.5 rounded bg-red-500/10 border border-red-500/20 text-red-400 uppercase self-start sm:self-auto">
                        <AlertTriangle className="w-3 h-3" /> Deceptive Mismatch
                      </span>
                    )}
                  </div>

                  <div className="flex items-start space-x-2 text-[11px] break-all">
                    <span className="text-gray-500 text-[10px] uppercase tracking-wider shrink-0">Destination:</span>
                    <span className={link.isMismatched ? 'text-red-400 font-bold' : 'text-blue-400'}>
                      {link.href}
                    </span>
                  </div>

                  {link.mismatchReason && (
                    <div className="mt-1 text-[11px] text-red-300/90 font-sans">
                      &bull; {link.mismatchReason}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
