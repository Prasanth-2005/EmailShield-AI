import React, { useRef, useState } from 'react';
import { FileUp, ShieldQuestion, ChevronRight } from 'lucide-react';

interface EscalateBannerProps {
  /** Same handler App uses for uploads: (rawEml, fileName) => void */
  onAnalyzeEml: (rawEml: string, fileName?: string) => void;
}

/**
 * Shown on dashboards produced by the Gmail Quick Scan extension
 * (`analysisScope === 'body-and-sender'`). Gmail exposes only the rendered
 * message, so header forensics — SPF/DKIM/DMARC, Return-Path alignment, the
 * Received relay chain and origin geolocation — could not run. This banner lets
 * the analyst escalate to a full forensic pass by uploading the original .eml.
 */
export const EscalateBanner: React.FC<EscalateBannerProps> = ({ onAnalyzeEml }) => {
  const inputRef = useRef<HTMLInputElement>(null);
  const [error, setError] = useState<string | null>(null);

  const handleFile = (file: File) => {
    setError(null);
    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target?.result as string;
      if (!content || !content.trim()) {
        setError('That file appears to be empty.');
        return;
      }
      onAnalyzeEml(content, file.name);
    };
    reader.onerror = () => setError('Could not read that file.');
    reader.readAsText(file);
  };

  return (
    <div className="rounded-xl border border-sky-500/30 bg-sky-500/[0.06] p-4 sm:p-5 shadow-xl">
      <div className="flex flex-col sm:flex-row sm:items-center gap-4">
        <div className="flex items-start gap-3 flex-1">
          <ShieldQuestion className="w-5 h-5 text-sky-400 shrink-0 mt-0.5" />
          <div>
            <h3 className="text-sm font-semibold text-white">
              Triage result from Gmail — body &amp; sender only
            </h3>
            <p className="text-xs text-gray-300 mt-1 leading-relaxed">
              This analysis came from the Gmail Quick Scan extension, which cannot read raw headers.
              SPF/DKIM/DMARC, Return-Path alignment, the Received relay chain and origin geolocation
              were <span className="text-sky-300 font-medium">not evaluated</span>.
              Upload the original <span className="font-mono text-sky-300">.eml</span> file for full
              header forensics and origin tracing.
            </p>
            {error && <p className="text-xs text-red-300 mt-1.5">{error}</p>}

            <details className="group mt-2.5">
              <summary className="flex items-center gap-1 text-[11px] font-medium text-sky-300 cursor-pointer select-none list-none">
                <ChevronRight className="w-3 h-3 transition-transform group-open:rotate-90" />
                How do I get the .eml file?
              </summary>
              <div className="mt-2 pl-4 text-[11px] text-gray-300 leading-relaxed space-y-1.5">
                <div>
                  <span className="text-gray-200 font-medium">Gmail:</span>
                  <ol className="list-decimal ml-4 mt-1 space-y-0.5 text-gray-400">
                    <li>Open the email in Gmail.</li>
                    <li>Click the three-dot menu (⋮) at the top right of the message.</li>
                    <li>Select <span className="text-gray-200">“Download message”</span>.</li>
                    <li>The <span className="font-mono">.eml</span> file saves to your Downloads folder.</li>
                    <li>Upload it here.</li>
                  </ol>
                </div>
                <div className="text-gray-400">
                  <span className="text-gray-200 font-medium">Outlook:</span> open the email, then
                  <span className="text-gray-200"> File &rarr; Save As</span> and choose the
                  <span className="font-mono"> .eml</span> format.
                </div>
              </div>
            </details>
          </div>
        </div>

        <div className="shrink-0">
          <input
            ref={inputRef}
            type="file"
            accept=".eml,.txt,.msg,message/rfc822"
            className="hidden"
            onChange={(e) => {
              if (e.target.files && e.target.files.length > 0) handleFile(e.target.files[0]);
            }}
          />
          <button
            onClick={() => inputRef.current?.click()}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-sky-600 hover:bg-sky-500 text-white text-xs font-semibold border border-sky-400/30 transition cursor-pointer shadow"
          >
            <FileUp className="w-4 h-4" />
            <span>Upload .eml for full forensics</span>
          </button>
        </div>
      </div>
    </div>
  );
};
