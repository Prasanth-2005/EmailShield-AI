import React, { useState, useRef } from 'react';
import { UploadCloud, FileText, Sparkles, AlertCircle, FileCode } from 'lucide-react';

interface UploadAreaProps {
  onAnalyze: (rawEmail: string, fileName?: string) => void;
  isAnalyzing: boolean;
}

export const UploadArea: React.FC<UploadAreaProps> = ({ onAnalyze, isAnalyzing }) => {
  const [activeTab, setActiveTab] = useState<'upload' | 'paste'>('upload');
  const [pastedContent, setPastedContent] = useState('');
  const [selectedFile, setSelectedFile] = useState<{ name: string; size: number; content: string } | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFile = (file: File) => {
    setErrorMessage(null);
    if (!file.name.toLowerCase().endsWith('.eml') && !file.name.toLowerCase().endsWith('.txt') && !file.name.toLowerCase().endsWith('.msg')) {
      // allow anyway with warning, but notify
      console.warn('Non-.eml extension, reading as text');
    }

    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target?.result as string;
      if (!content || content.trim().length === 0) {
        setErrorMessage('The selected file appears to be empty.');
        return;
      }
      setSelectedFile({
        name: file.name,
        size: file.size,
        content,
      });
      // Auto analyze or let user click
      onAnalyze(content, file.name);
    };
    reader.onerror = () => {
      setErrorMessage('Failed to read file. Please try pasting raw source.');
    };
    reader.readAsText(file);
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleFile(e.dataTransfer.files[0]);
    }
  };

  const handlePasteSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!pastedContent.trim()) {
      setErrorMessage('Please paste email headers and body text.');
      return;
    }
    setErrorMessage(null);
    onAnalyze(pastedContent.trim(), 'pasted-raw-email.eml');
  };

  return (
    <div className="w-full space-y-6">
      {/* Main Upload / Source Panel */}
      <div className="rounded-xl border border-white/10 bg-[#161616] shadow-xl overflow-hidden">
        {/* Navigation tabs */}
        <div className="flex items-center border-b border-white/10 bg-black/40 px-4 pt-2">
          <button
            id="tab-upload-file"
            type="button"
            onClick={() => setActiveTab('upload')}
            className={`flex items-center space-x-2 px-4 py-2.5 text-xs font-semibold rounded-t-lg transition border-b-2 cursor-pointer ${
              activeTab === 'upload'
                ? 'border-blue-500 text-white bg-white/[0.04]'
                : 'border-transparent text-gray-400 hover:text-gray-200'
            }`}
          >
            <UploadCloud className="w-4 h-4 text-blue-400" />
            <span>Upload .EML Forensic Export</span>
          </button>
          <button
            id="tab-paste-raw"
            type="button"
            onClick={() => setActiveTab('paste')}
            className={`flex items-center space-x-2 px-4 py-2.5 text-xs font-semibold rounded-t-lg transition border-b-2 cursor-pointer ${
              activeTab === 'paste'
                ? 'border-blue-500 text-white bg-white/[0.04]'
                : 'border-transparent text-gray-400 hover:text-gray-200'
            }`}
          >
            <FileCode className="w-4 h-4 text-blue-400" />
            <span>Paste Raw Email Source</span>
          </button>
        </div>

        {/* Tab 1: File Dropzone */}
        {activeTab === 'upload' && (
          <div className="p-6">
            <div
              id="dropzone-eml"
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
              className={`border-2 border-dashed rounded-xl p-8 sm:p-12 text-center transition cursor-pointer flex flex-col items-center justify-center ${
                isDragging
                  ? 'border-blue-500 bg-blue-500/10 ring-4 ring-blue-500/20'
                  : 'border-white/10 bg-white/[0.02] hover:border-white/20 hover:bg-white/[0.04]'
              }`}
            >
              <input
                ref={fileInputRef}
                type="file"
                accept=".eml,.txt,.msg,message/rfc822"
                onChange={(e) => {
                  if (e.target.files && e.target.files.length > 0) {
                    handleFile(e.target.files[0]);
                  }
                }}
                className="hidden"
              />

              <div className="w-12 h-12 rounded-lg bg-blue-600/10 border border-blue-500/20 flex items-center justify-center text-blue-400 mb-3 shadow-[0_0_15px_rgba(37,99,235,0.2)]">
                <UploadCloud className="w-6 h-6" />
              </div>

              <h3 className="text-sm font-semibold text-gray-200">
                Upload <span className="text-blue-400 font-mono">.eml</span> Forensic Export
              </h3>
              <p className="text-xs text-gray-500 mt-1 max-w-sm">
                Drop file or click to browse. Standard RFC 5322 exports from Outlook, Gmail, Thunderbird, and Apple Mail supported.
              </p>

              <div className="mt-4 flex items-center gap-2 text-[10px] font-mono text-gray-500 uppercase tracking-wider">
                <span className="px-2 py-0.5 rounded bg-black border border-white/10">RFC 5322</span>
                <span className="px-2 py-0.5 rounded bg-black border border-white/10">MIME Multi-part</span>
                <span className="px-2 py-0.5 rounded bg-black border border-white/10">Auth Headers</span>
              </div>
            </div>

            {selectedFile && (
              <div className="mt-4 p-3.5 rounded-lg bg-black/60 border border-white/10 flex items-center justify-between text-xs">
                <div className="flex items-center space-x-2.5">
                  <FileText className="w-4 h-4 text-blue-400" />
                  <span className="font-mono text-gray-300 font-medium">{selectedFile.name}</span>
                  <span className="text-gray-500">({(selectedFile.size / 1024).toFixed(1)} KB)</span>
                </div>
                <button
                  id="btn-reanalyze-file"
                  onClick={() => onAnalyze(selectedFile.content, selectedFile.name)}
                  disabled={isAnalyzing}
                  className="px-3 py-1.5 rounded-md bg-blue-600 hover:bg-blue-500 text-white font-medium transition cursor-pointer disabled:opacity-50 shadow-sm"
                >
                  {isAnalyzing ? 'Analyzing...' : 'Re-analyze'}
                </button>
              </div>
            )}
          </div>
        )}

        {/* Tab 2: Raw Textarea */}
        {activeTab === 'paste' && (
          <form onSubmit={handlePasteSubmit} className="p-6 space-y-4">
            <div>
              <label htmlFor="raw-email-textarea" className="block text-[10px] uppercase tracking-widest text-gray-500 font-bold mb-2">
                Or Paste Raw RFC Headers & Message Source
              </label>
              <textarea
                id="raw-email-textarea"
                rows={10}
                value={pastedContent}
                onChange={(e) => setPastedContent(e.target.value)}
                placeholder={`Received: from mail.example.com ([192.0.2.1]) by mx.target.com...\nFrom: sender@example.com\nTo: recipient@example.com\nSubject: Account Verification\n\nEmail body content here...`}
                className="w-full font-mono text-xs p-3.5 rounded-lg bg-black border border-white/10 text-gray-200 placeholder-gray-600 focus:outline-none focus:border-blue-500"
              />
            </div>

            <div className="flex items-center justify-between">
              <button
                type="button"
                onClick={() => setPastedContent('')}
                className="text-xs text-gray-500 hover:text-gray-300 transition-colors"
              >
                Clear text
              </button>
              <button
                id="btn-analyze-pasted"
                type="submit"
                disabled={isAnalyzing || !pastedContent.trim()}
                className="flex items-center space-x-2 px-5 py-2.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold uppercase tracking-wider transition cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed shadow-[0_0_15px_rgba(37,99,235,0.3)]"
              >
                <Sparkles className="w-3.5 h-3.5" />
                <span>{isAnalyzing ? 'Running Forensic Scan...' : 'Analyze Raw Source'}</span>
              </button>
            </div>
          </form>
        )}

        {errorMessage && (
          <div className="mx-6 mb-6 p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-red-300 text-xs flex items-center space-x-2">
            <AlertCircle className="w-4 h-4 shrink-0" />
            <span>{errorMessage}</span>
          </div>
        )}
      </div>
    </div>
  );
};
