export type EmailClassification = 'Legitimate' | 'Suspicious' | 'Phishing' | 'Fraud';

export type RedFlagSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type RedFlagCategory = 
  | 'Urgency & Fear Tactics'
  | 'Brand Impersonation'
  | 'Credential Harvesting'
  | 'Financial & Wire Fraud'
  | 'Suspicious Link'
  | 'Header & Auth Anomaly'
  | 'Security Verification';

export interface RedFlag {
  id: string;
  severity: RedFlagSeverity;
  category: RedFlagCategory;
  title: string;
  description: string;
}

export interface SuspiciousPhrase {
  phrase: string;
  explanation: string;
  severity: RedFlagSeverity;
  category: string;
}

/**
 * A deterministic rule-based check that fired during forensic inspection.
 * These run independently of the AI model and combine 50/50 with its score.
 */
export interface TriggeredRule {
  id: string;
  rule: string;
  description: string;
  points: number;
  category: string;
}

/**
 * Geolocation for a single IP, as resolved from the free ip-api.com endpoint.
 * `status` records whether the lookup succeeded so the UI can degrade gracefully.
 */
export interface GeoLocation {
  ip: string;
  status: 'success' | 'fail' | 'private' | 'error';
  message?: string; // failure reason when status !== 'success'
  country?: string;
  countryCode?: string;
  region?: string;
  city?: string;
  isp?: string;
  org?: string;
  asName?: string;
  lat?: number;
  lon?: number;
  proxy?: boolean; // anonymising proxy / VPN / TOR exit
  hosting?: boolean; // datacentre / hosting provider
  mobile?: boolean; // mobile carrier network
}

/**
 * AbuseIPDB reputation for a single IP. `status` degrades gracefully so the
 * Origin Trace panel never breaks when the lookup fails / is rate limited.
 */
export interface IpReputation {
  ip: string;
  status: 'clean' | 'flagged' | 'unavailable';
  abuseConfidenceScore: number; // 0 - 100
  totalReports: number;
  categories: string[]; // human-readable abuse category names
  countryCode?: string;
  isTor?: boolean;
  isWhitelisted?: boolean;
  lastReportedAt?: string;
  message?: string; // reason when status === 'unavailable'
}

/**
 * Domain registration intelligence for one domain, from RDAP (rdap.org bootstrap,
 * free, no API key). `status` degrades gracefully so the panel and the pipeline
 * never break when a registry does not answer (common for some ccTLDs).
 */
export interface DomainIntelEntry {
  domain: string; // the registrable domain that was looked up
  role: 'from' | 'return-path' | 'deceptive-link';
  status: 'ok' | 'not-found' | 'unavailable';
  registeredAt?: string; // ISO date
  updatedAt?: string; // ISO date (last changed)
  expiresAt?: string; // ISO date
  registrar?: string; // registrar organisation name
  ageDays?: number; // whole days since registration
  message?: string; // reason when status !== 'ok'
}

/** All domain-intel lookups for one analysed email. */
export interface DomainIntelReport {
  entries: DomainIntelEntry[];
  /** Youngest known age across the From / Return-Path domains (drives a rule). */
  sendingMinAgeDays?: number;
  /** Which sending domain carries that age (for the rule description). */
  sendingYoungestDomain?: string;
}

/** A single relay hop enriched with geolocation for the Origin Trace panel. */
export interface OriginTraceHop {
  hopNumber: number;
  fromServer: string;
  byServer: string;
  ip?: string;
  isPublic: boolean; // routable (non-private, non-loopback) IPv4
  timestamp?: string;
  geo: GeoLocation | null; // null when there is no public IP to resolve
  reputation?: IpReputation | null; // AbuseIPDB (public IPs only)
  isProbableOrigin: boolean; // earliest reliable public-IP hop
  flags: Array<'proxy' | 'hosting' | 'mobile'>;
}

/** Ordered relay path with the probable originating node and its geolocation. */
export interface OriginTrace {
  hops: OriginTraceHop[];
  originIp: string | null;
  originGeo: GeoLocation | null;
  originCountryCode: string | null;
  lookupCount: number; // distinct IPs geolocated
  reputationLookups?: number; // distinct IPs checked against AbuseIPDB
  maxAbuseScore?: number; // highest AbuseIPDB confidence across all hops
  abuseFlaggedIp?: string | null; // the hop IP carrying that score
  note?: string; // set when the trace could not be built normally
}

export interface ReceivedHop {
  hopNumber: number;
  fromServer: string;
  byServer: string;
  withProtocol?: string;
  forRecipient?: string;
  timestamp?: string;
  ipAddress?: string;
  tls?: string;
  delayFromPrevious?: string;
  rawHop: string;
}

export interface AuthResults {
  spf?: {
    status: 'pass' | 'fail' | 'softfail' | 'neutral' | 'none' | 'temperror' | 'permerror';
    domain?: string;
    ip?: string;
    details?: string;
  };
  dkim?: {
    status: 'pass' | 'fail' | 'neutral' | 'none';
    domain?: string;
    selector?: string;
    details?: string;
  };
  dmarc?: {
    status: 'pass' | 'fail' | 'none';
    policy?: string;
    domain?: string;
    details?: string;
  };
  rawAuthHeader?: string;
}

export interface ExtractedLink {
  text: string;
  href: string;
  isMismatched?: boolean;
  mismatchReason?: string;
}

/**
 * A parsed email attachment. `content` is transient (used only to compute the
 * SHA-256 and inspect archives) and is stripped before any network response —
 * user file bytes never leave the server / browser.
 */
export interface EmailAttachment {
  filename: string;
  mimeType: string;
  size: number; // decoded byte length
  sha256: string; // lowercase hex; '' until hashAndClassifyAttachments runs
  extensionRisk: 'high' | 'macro' | 'archive-exe' | null;
  riskReason?: string;
  archiveContents?: string[]; // listed entry names for .zip archives
  content?: Uint8Array; // SERVER/BROWSER-ONLY, never serialized
}

/** VirusTotal detection stats for one scanned item. */
export interface VtStats {
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
  total: number; // engines that returned a verdict
}

export interface DeepScanUrlResult extends VtStats {
  kind: 'url';
  url: string; // normalized (scheme + host + path)
  displayText?: string;
  mismatched?: boolean;
  status: 'done' | 'pending' | 'unavailable';
  message?: string;
  analysisId?: string; // VT analysis id — set while pending, re-polled by "Check again"
  appearsCount?: number; // how many raw links in the email share this destination
}

export interface DeepScanFileResult extends VtStats {
  kind: 'file';
  filename: string;
  sha256: string;
  status: 'done' | 'unknown' | 'unavailable';
  message?: string;
}

export type DeepScanItemResult = DeepScanUrlResult | DeepScanFileResult;

/** Cumulative on-demand VirusTotal deep-scan state for an analysis. */
export interface DeepScanState {
  ranAt: string;
  items: DeepScanItemResult[];
  addedPoints: number; // points folded into fraudScore from flagged items
}

export interface ParsedEmail {
  from: {
    raw: string;
    displayName: string;
    address: string;
    domain: string;
  };
  to: {
    raw: string;
    address: string;
  };
  subject: string;
  date: string;
  returnPath: string;
  replyTo: string;
  messageId: string;
  receivedHops: ReceivedHop[];
  authResults: AuthResults;
  bodyText: string;
  bodyHtml?: string;
  extractedLinks: ExtractedLink[];
  attachments: EmailAttachment[];
  rawHeaders: Record<string, string | string[]>;
  rawSource: string;
}

/**
 * Verdict from the third detection engine — a local pretrained BERT phishing
 * classifier (`ealvaradob/bert-finetuned-phishing`) served by the optional
 * Python microservice. `null` on the analysis result when the service was
 * unreachable and the ML layer was skipped.
 */
export interface MlModelResult {
  label: 'phishing' | 'legitimate';
  confidence: number; // 0 - 100, model's confidence in `label`
  score: number; // 0 - 100 on the fraud scale (P(phishing)) — the value used in the blend
}

export interface ThreatAnalysisResult {
  classification: EmailClassification;
  fraudScore: number; // FINAL hybrid score (see `scoreWeights`), capped at 100
  geminiScore: number; // AI engine (0 - 100): live Gemini judgment, or heuristic fallback score
  ruleScore: number; // deterministic rule-check engine (0 - 100)
  mlScore?: number | null; // ML engine fraud score (0 - 100); null when the ML layer was skipped
  mlModel?: MlModelResult | null; // ML engine verdict + confidence; null when skipped
  mlSkipped?: boolean; // true when the Python ML service was unreachable
  scoreWeights?: { rule: number; ml: number | null; gemini: number }; // blend actually used
  triggeredRules: TriggeredRule[]; // rules that fired in the deterministic engine
  confidence: number; // 0 - 100
  explanation: string; // 2-3 sentences, analyst-facing
  // 2-4 sentences written for a NON-technical reader (no jargon) — verdict in
  // plain words + the single biggest reason. Shown on the Overview tab.
  plainSummary?: string;
  redFlags: RedFlag[]; // AI-detected flags (from Gemini, or the heuristic fallback)
  suspiciousPhrases: SuspiciousPhrase[];
  indicators: {
    urgencyScore: number; // 0 - 100
    impersonationScore: number; // 0 - 100
    credentialHarvestingRisk: boolean;
    financialFraudRisk: boolean;
    domainSpoofingRisk: boolean;
    headerAnomalyRisk: boolean;
  };
  analyzedAt: string;
  // Model id when a live call succeeded (e.g. "gemini-flash-latest"),
  // or "forensic-heuristic-fallback" when the local engine was used.
  engine: string;
  // When `engine` is the heuristic fallback, why the live model was not used.
  fallbackReason?: 'no-api-key' | 'gemini-quota-exceeded' | 'gemini-model-unavailable' | 'gemini-error';
  // Relay-path geolocation trace (null when it could not be built).
  originTrace: OriginTrace | null;
  // 'full' for uploaded .eml files; 'body-and-sender' for the Gmail Quick Scan
  // extension, which has no access to raw headers.
  analysisScope?: 'full' | 'body-and-sender';
  // Short ID under which the server cached this result (for the extension ->
  // web-app "View Full Forensic Analysis" handoff, and for deep-scan updates).
  caseId?: string;
  // Attachments (metadata + SHA-256 + extension risk; never the bytes).
  attachments?: EmailAttachment[];
  // Score before any VirusTotal deep scan — fraudScore = min(100, base + deepScan.addedPoints).
  baseFraudScore?: number;
  // On-demand VirusTotal deep-scan results (null until the user runs one).
  deepScan?: DeepScanState | null;
  // RDAP domain registration intelligence for the sender / return-path / link
  // domains (null when it could not be built).
  domainIntel?: DomainIntelReport | null;
}
