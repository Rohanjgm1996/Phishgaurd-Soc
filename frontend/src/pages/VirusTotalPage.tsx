import React, { useMemo, useState } from "react";
import { threatIntelApi } from "@/lib/api";
import {
    Search,
    Shield,
    Globe,
    Lock,
    Network,
    FileText,
    ChevronRight,
    ExternalLink,
    Calendar,
    Server,
    Fingerprint,
    AlertTriangle,
    CheckCircle2,
    XCircle,
    Info,
    Copy,
    Activity,
    Radar,
    Link as LinkIcon,
    Target,
    Skull,
} from "lucide-react";
import { motion } from "framer-motion";

type Verdict = "clean" | "suspicious" | "malicious" | "unknown";

type DetectionStats = {
    malicious: number;
    suspicious: number;
    harmless: number;
    undetected: number;
    timeout?: number;
};

type WhoisData = {
    registrar?: string;
    created?: string;
    updated?: string;
    expires?: string;
    registrarCountry?: string;
    nameServers?: string[];
    whoisText?: string;
};

type DnsData = {
    a?: string[];
    aaaa?: string[];
    mx?: string[];
    ns?: string[];
    txt?: string[];
    cname?: string[];
};

type SslData = {
    issuer?: string;
    subject?: string;
    validFrom?: string;
    validTo?: string;
    serialNumber?: string;
    san?: string[];
};

type ThreatIntel = {
    abuseIpdbScore?: number;
    otxPulses?: number;
    urlscanDetections?: number;
    talosReputation?: string;
    openPhish?: boolean;
    phishTank?: boolean;
};

type RelatedUrl = {
    url: string;
    status?: string;
    lastSeen?: string;
};

type Subdomain = {
    hostname: string;
    ip?: string;
};

type VendorResult = {
    vendor: string;
    status: string;
    result?: string | null;
    category?: string;
};

type CiaImpact = {
    confidentiality?: string;
    integrity?: string;
    availability?: string;
};

type MitreTechnique = {
    id: string;
    name: string;
};

type AnalysisResult = {
    query: string;
    type: "domain" | "url" | "ip" | "hash";
    verdict: Verdict;
    communityScore: number;
    riskScore: number;
    lastAnalysisDate?: string;
    resolvedIp?: string;
    asn?: string;
    hostingProvider?: string;
    country?: string;
    categories?: string[];
    stats: DetectionStats;
    whois?: WhoisData;
    dns?: DnsData;
    ssl?: SslData;
    intel?: ThreatIntel;
    subdomains?: Subdomain[];
    relatedUrls?: RelatedUrl[];
    vendors?: VendorResult[];
    cia?: CiaImpact;
    mitreAttack?: MitreTechnique[];
    cyberKillChain?: string[];
    raw?: unknown;
};

const cx = (...parts: Array<string | false | null | undefined>) =>
    parts.filter(Boolean).join(" ");

function getVerdictMeta(verdict: Verdict) {
    switch (verdict) {
        case "clean":
            return {
                label: "Clean",
                icon: CheckCircle2,
                className:
                    "bg-emerald-500/10 text-emerald-300 border border-emerald-400/20",
                dot: "bg-emerald-400",
            };
        case "suspicious":
            return {
                label: "Suspicious",
                icon: AlertTriangle,
                className:
                    "bg-amber-500/10 text-amber-300 border border-amber-400/20",
                dot: "bg-amber-400",
            };
        case "malicious":
            return {
                label: "Malicious",
                icon: XCircle,
                className: "bg-red-500/10 text-red-300 border border-red-400/20",
                dot: "bg-red-400",
            };
        default:
            return {
                label: "Unknown",
                icon: Info,
                className: "bg-slate-500/10 text-slate-300 border border-slate-400/20",
                dot: "bg-slate-400",
            };
    }
}

function detectQueryType(input: string): "url" | "domain" | "ip" | "hash" {
    const value = input.trim();

    const ipRegex =
        /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

    const md5Regex = /^[a-fA-F0-9]{32}$/;
    const sha1Regex = /^[a-fA-F0-9]{40}$/;
    const sha256Regex = /^[a-fA-F0-9]{64}$/;

    if (/^https?:\/\//i.test(value)) return "url";
    if (ipRegex.test(value)) return "ip";
    if (md5Regex.test(value) || sha1Regex.test(value) || sha256Regex.test(value)) return "hash";
    return "domain";
}

function formatUnixDate(ts?: number | string | null): string | undefined {
    if (ts === undefined || ts === null || ts === "") return undefined;

    if (typeof ts === "string") {
        const parsed = Number(ts);
        if (!Number.isNaN(parsed) && parsed > 0) {
            return new Date(parsed * 1000).toUTCString();
        }
        return ts;
    }

    return new Date(ts * 1000).toUTCString();
}

function toArray(value: unknown): string[] {
    if (!value) return [];

    if (Array.isArray(value)) {
        return value.map((item) => String(item).trim()).filter(Boolean);
    }

    if (typeof value === "string") {
        return value
            .split(/[\n,]/)
            .map((item) => item.trim())
            .filter(Boolean);
    }

    return [];
}

function dedupe(items: string[]): string[] {
    return [...new Set(items.filter(Boolean))];
}

function collectDnsRecords(attributes: any): DnsData {
    const lastDnsRecords = Array.isArray(attributes?.last_dns_records)
        ? attributes.last_dns_records
        : [];
    const records = Array.isArray(attributes?.dns_records) ? attributes.dns_records : [];

    const allRecords = [...lastDnsRecords, ...records];

    const pickByType = (types: string[]) =>
        dedupe(
            allRecords
                .filter((item: any) =>
                    types.includes(String(item?.type || "").toUpperCase())
                )
                .map((item: any) => item?.value || item?.address || item?.hostname || item?.target)
                .filter(Boolean)
                .map((item: any) => String(item))
        );

    return {
        a: pickByType(["A"]),
        aaaa: pickByType(["AAAA"]),
        mx: pickByType(["MX"]),
        ns: pickByType(["NS"]),
        txt: pickByType(["TXT"]),
        cname: pickByType(["CNAME"]),
    };
}

function extractCategories(attributes: any): string[] {
    const tags = toArray(attributes?.tags);
    const cats = attributes?.categories;

    if (Array.isArray(cats)) {
        return dedupe([...tags, ...cats.map((x: any) => String(x))]);
    }

    if (cats && typeof cats === "object") {
        return dedupe([
            ...tags,
            ...Object.values(cats)
                .flatMap((value) =>
                    Array.isArray(value) ? value.map((x) => String(x)) : [String(value)]
                )
                .filter(Boolean),
        ]);
    }

    if (typeof cats === "string") {
        return dedupe([...tags, cats]);
    }

    return dedupe(tags);
}

function buildWhoisData(attributes: any): WhoisData {
    return {
        registrar: attributes?.registrar || attributes?.whois_registrar,
        created: formatUnixDate(attributes?.creation_date),
        updated: formatUnixDate(attributes?.last_modification_date),
        expires: formatUnixDate(attributes?.whois_date),
        registrarCountry: attributes?.country,
        nameServers: dedupe(toArray(attributes?.name_servers)),
        whoisText: typeof attributes?.whois === "string" ? attributes.whois : undefined,
    };
}

function buildSslData(attributes: any): SslData {
    const cert = attributes?.last_https_certificate || attributes?.last_analysis_certificate || {};
    const issuerObj = cert?.issuer || {};
    const subjectObj = cert?.subject || {};

    const san =
        Array.isArray(cert?.extensions?.subject_alternative_name)
            ? cert.extensions.subject_alternative_name
                .map((item: any) => {
                    if (typeof item === "string") return item;
                    if (item?.value) return String(item.value);
                    return "";
                })
                .filter(Boolean)
            : [];

    return {
        issuer:
            issuerObj?.O ||
            issuerObj?.CN ||
            attributes?.cert_issuer ||
            undefined,
        subject:
            subjectObj?.CN ||
            attributes?.cert_subject ||
            undefined,
        validFrom:
            cert?.validity?.not_before ||
            formatUnixDate(attributes?.cert_valid_from),
        validTo:
            cert?.validity?.not_after ||
            formatUnixDate(attributes?.cert_valid_to),
        serialNumber: cert?.serial_number || attributes?.cert_serial,
        san: dedupe(san),
    };
}

function buildResolvedIp(attributes: any, queryType: string): string | undefined {
    if (queryType === "ip") {
        return undefined;
    }

    const lastDnsRecords = Array.isArray(attributes?.last_dns_records)
        ? attributes.last_dns_records
        : [];

    const aRecord = lastDnsRecords.find((item: any) => String(item?.type).toUpperCase() === "A");

    return (
        attributes?.last_serving_ip_address ||
        attributes?.resolved_ip ||
        attributes?.ip_address ||
        attributes?.ip ||
        aRecord?.value ||
        undefined
    );
}

function extractHostingProvider(attributes: any, summary: any, queryType: string): string | undefined {
    const candidates = [
        attributes?.as_owner,
        attributes?.owner,
        attributes?.org,
        attributes?.organization,
        attributes?.registrar,
        attributes?.whois_registrar,
        attributes?.network,
        attributes?.isp,
        summary?.as_owner,
        summary?.org,
        summary?.organization,
        summary?.network,
        summary?.isp,
        summary?.registrar,
    ]
        .map((item) => (typeof item === "string" ? item.trim() : ""))
        .filter(Boolean)
        .filter((item) => item.toLowerCase() !== "unknown");

    if (candidates.length > 0) {
        return candidates[0];
    }

    if (queryType === "ip") {
        return undefined;
    }

    if (attributes?.last_serving_ip_address) {
        return `Resolved via ${attributes.last_serving_ip_address}`;
    }

    return undefined;
}

function mapBackendResultToUI(data: any, originalQuery: string): AnalysisResult {
    const rawData = data?.raw?.data || data?.data || {};
    const attributes = rawData?.attributes || {};
    const stats = data?.stats || attributes?.last_analysis_stats || {};
    const vendors = Array.isArray(data?.vendors) ? data.vendors : [];

    const malicious = Number(stats?.malicious || 0);
    const suspicious = Number(stats?.suspicious || 0);
    const harmless = Number(stats?.harmless || 0);
    const undetected = Number(stats?.undetected || 0);
    const timeout = Number(stats?.timeout || 0);
    const total =
        Number(stats?.total) ||
        malicious + suspicious + harmless + undetected + timeout;

    let verdict: Verdict = "unknown";
    const backendVerdict = String(data?.verdict || "").toLowerCase();

    if (backendVerdict.includes("malicious")) verdict = "malicious";
    else if (backendVerdict.includes("suspicious")) verdict = "suspicious";
    else if (backendVerdict.includes("clean")) verdict = "clean";
    else if (malicious > 0) verdict = "malicious";
    else if (suspicious > 0) verdict = "suspicious";
    else if (total > 0) verdict = "clean";

    const riskScore =
        total > 0
            ? Math.min(100, Math.round(((malicious + suspicious) / total) * 100))
            : 0;

    const queryType = (data?.query_type ||
        detectQueryType(originalQuery)) as "domain" | "url" | "ip" | "hash";

    const communityScore = Number(
        data?.summary?.community_score ??
        attributes?.reputation ??
        0
    );

    const resolvedIp = buildResolvedIp(attributes, queryType);

    return {
        query: String(data?.query || originalQuery),
        type: queryType,
        verdict,
        communityScore,
        riskScore,
        lastAnalysisDate: formatUnixDate(attributes?.last_analysis_date || data?.summary?.last_analysis_date),
        resolvedIp,
        asn: attributes?.asn ? `AS${attributes.asn}` : data?.summary?.asn ? `AS${data.summary.asn}` : undefined,
        hostingProvider: extractHostingProvider(attributes, data?.summary, queryType),
        country: attributes?.country || data?.summary?.country || undefined,
        categories: extractCategories(attributes),
        stats: {
            malicious,
            suspicious,
            harmless,
            undetected,
            timeout,
        },
        whois: buildWhoisData(attributes),
        dns: collectDnsRecords(attributes),
        ssl: buildSslData(attributes),
        intel: {
            abuseIpdbScore: Number(attributes?.abuseipdb_score || 0),
            otxPulses: Number(attributes?.otx_pulses || 0),
            urlscanDetections: Number(attributes?.urlscan_detections || 0),
            talosReputation:
                attributes?.talos_reputation ||
                (verdict === "malicious"
                    ? "Poor"
                    : verdict === "suspicious"
                        ? "Questionable"
                        : "Neutral"),
            openPhish: Boolean(attributes?.openphish),
            phishTank: Boolean(attributes?.phishtank),
        },
        subdomains: Array.isArray(attributes?.subdomains)
            ? attributes.subdomains
                .map((item: any) => ({
                    hostname: String(item?.hostname || item?.domain || item || ""),
                    ip: item?.ip ? String(item.ip) : undefined,
                }))
                .filter((item: Subdomain) => item.hostname)
            : [],
        relatedUrls: Array.isArray(attributes?.related_urls)
            ? attributes.related_urls
                .map((item: any) => ({
                    url: String(item?.url || item || ""),
                    status: item?.status ? String(item.status) : undefined,
                    lastSeen: item?.last_seen
                        ? formatUnixDate(item.last_seen) || String(item.last_seen)
                        : undefined,
                }))
                .filter((item: RelatedUrl) => item.url)
            : [],
        vendors,
        cia: data?.cia || {},
        mitreAttack: Array.isArray(data?.mitre_attack) ? data.mitre_attack : [],
        cyberKillChain: Array.isArray(data?.cyber_kill_chain) ? data.cyber_kill_chain : [],
        raw: data,
    };
}

function StatCard({
    label,
    value,
    tone,
}: {
    label: string;
    value: number | string;
    tone?: "red" | "yellow" | "green" | "blue";
}) {
    const toneClass =
        tone === "red"
            ? "text-red-300 border-red-400/20 bg-red-500/5"
            : tone === "yellow"
                ? "text-amber-300 border-amber-400/20 bg-amber-500/5"
                : tone === "green"
                    ? "text-emerald-300 border-emerald-400/20 bg-emerald-500/5"
                    : "text-cyan-300 border-cyan-400/20 bg-cyan-500/5";

    return (
        <div
            className={cx(
                "rounded-2xl border px-4 py-4 backdrop-blur-sm shadow-[0_0_0_1px_rgba(255,255,255,0.02)]",
                toneClass
            )}
        >
            <div className="text-[11px] uppercase tracking-[0.22em] opacity-80">
                {label}
            </div>
            <div className="mt-2 text-2xl font-semibold">{value}</div>
        </div>
    );
}

function SectionCard({
    title,
    icon: Icon,
    right,
    children,
}: {
    title: string;
    icon: React.ComponentType<{ className?: string }>;
    right?: React.ReactNode;
    children: React.ReactNode;
}) {
    return (
        <div className="rounded-3xl border border-cyan-400/10 bg-slate-900/70 p-5 shadow-[0_0_0_1px_rgba(34,211,238,0.04),0_20px_60px_rgba(2,8,23,0.45)]">
            <div className="mb-4 flex items-center justify-between gap-3">
                <div className="flex items-center gap-3">
                    <div className="rounded-2xl border border-cyan-400/10 bg-cyan-400/5 p-2">
                        <Icon className="h-4 w-4 text-cyan-300" />
                    </div>
                    <h3 className="text-sm font-semibold tracking-wide text-slate-100">
                        {title}
                    </h3>
                </div>
                {right}
            </div>
            {children}
        </div>
    );
}

function KV({
    label,
    value,
}: {
    label: string;
    value?: React.ReactNode;
}) {
    return (
        <div className="grid grid-cols-1 gap-1 border-b border-white/5 py-3 md:grid-cols-[180px_1fr]">
            <div className="text-xs uppercase tracking-[0.18em] text-slate-400">
                {label}
            </div>
            <div className="break-all text-sm text-slate-100">
                {value ?? <span className="text-slate-500">—</span>}
            </div>
        </div>
    );
}

function ProgressBar({ result }: { result: AnalysisResult }) {
    const total =
        result.stats.malicious +
        result.stats.suspicious +
        result.stats.harmless +
        result.stats.undetected +
        (result.stats.timeout ?? 0);

    const segments = [
        { key: "malicious", value: result.stats.malicious, cls: "bg-red-400" },
        { key: "suspicious", value: result.stats.suspicious, cls: "bg-amber-400" },
        { key: "harmless", value: result.stats.harmless, cls: "bg-emerald-400" },
        { key: "undetected", value: result.stats.undetected, cls: "bg-cyan-400" },
    ];

    return (
        <div className="mt-4">
            <div className="h-3 overflow-hidden rounded-full bg-slate-800">
                <div className="flex h-full w-full">
                    {segments.map((seg) => {
                        const width = total > 0 ? `${(seg.value / total) * 100}%` : "0%";
                        return (
                            <div
                                key={seg.key}
                                className={seg.cls}
                                style={{ width }}
                                title={`${seg.key}: ${seg.value}`}
                            />
                        );
                    })}
                </div>
            </div>
            <div className="mt-3 flex flex-wrap gap-3 text-xs text-slate-400">
                <span className="inline-flex items-center gap-2">
                    <span className="h-2 w-2 rounded-full bg-red-400" />
                    Detected
                </span>
                <span className="inline-flex items-center gap-2">
                    <span className="h-2 w-2 rounded-full bg-amber-400" />
                    Suspicious
                </span>
                <span className="inline-flex items-center gap-2">
                    <span className="h-2 w-2 rounded-full bg-emerald-400" />
                    Clean
                </span>
                <span className="inline-flex items-center gap-2">
                    <span className="h-2 w-2 rounded-full bg-cyan-400" />
                    Unknown
                </span>
            </div>
        </div>
    );
}

function EmptyState() {
    return (
        <div className="rounded-3xl border border-cyan-400/10 bg-slate-900/70 p-10 text-center shadow-[0_0_0_1px_rgba(34,211,238,0.05),0_20px_60px_rgba(2,8,23,0.45)]">
            <div className="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-2xl border border-cyan-400/20 bg-cyan-500/10">
                <Search className="h-7 w-7 text-cyan-300" />
            </div>
            <h3 className="text-xl font-semibold text-slate-100">
                Search an IOC to begin
            </h3>
            <p className="mt-2 text-sm text-slate-400">
                Paste an IP, domain, URL, or file hash and click Analyze.
            </p>
        </div>
    );
}

function ImpactPill({ label, value }: { label: string; value?: string }) {
    const tone =
        value === "High"
            ? "bg-red-500/10 text-red-300 border-red-400/20"
            : value === "Medium"
                ? "bg-amber-500/10 text-amber-300 border-amber-400/20"
                : "bg-emerald-500/10 text-emerald-300 border-emerald-400/20";

    return (
        <div className={cx("rounded-2xl border px-3 py-2 text-sm", tone)}>
            <span className="font-medium">{label}:</span> {value || "—"}
        </div>
    );
}

const TABS = [
    "Overview",
    "Detection",
    "Whois",
    "DNS",
    "SSL",
    "Relations",
    "Raw JSON",
] as const;

type TabName = (typeof TABS)[number];

export default function VirusTotalPage() {
    const [query, setQuery] = useState("");
    const [activeTab, setActiveTab] = useState<TabName>("Overview");
    const [result, setResult] = useState<AnalysisResult | null>(null);
    const [loading, setLoading] = useState(false);
    const [errorMessage, setErrorMessage] = useState("");

    const verdictMeta = useMemo(
        () => getVerdictMeta(result?.verdict || "unknown"),
        [result]
    );
    const VerdictIcon = verdictMeta.icon;

    const totalEngines = result
        ? result.stats.malicious +
        result.stats.suspicious +
        result.stats.harmless +
        result.stats.undetected +
        (result.stats.timeout ?? 0)
        : 0;

    async function handleAnalyze() {
        const trimmed = query.trim();
        if (!trimmed) return;

        setLoading(true);
        setErrorMessage("");

        try {
            const queryType = detectQueryType(trimmed);
            const data = await threatIntelApi.searchVirusTotal(queryType, trimmed);

            if (data?.error) {
                throw new Error(data.error);
            }

            const mapped = mapBackendResultToUI(data, trimmed);
            setResult(mapped);
            setActiveTab("Overview");
        } catch (error: any) {
            const message =
                error?.response?.data?.detail ||
                error?.response?.data?.error ||
                error?.message ||
                "Threat intel lookup failed";

            setErrorMessage(String(message));
            setResult(null);
        } finally {
            setLoading(false);
        }
    }

    async function copyText(text: string) {
        try {
            await navigator.clipboard.writeText(text);
        } catch {
            // ignore
        }
    }

    return (
        <div className="min-h-screen bg-[radial-gradient(circle_at_top,_rgba(34,211,238,0.10),_transparent_30%),linear-gradient(to_bottom,_#020617,_#0f172a_45%,_#020617)] text-slate-100">
            <div className="pointer-events-none absolute inset-0 bg-[linear-gradient(rgba(34,211,238,0.04)_1px,transparent_1px),linear-gradient(90deg,rgba(34,211,238,0.04)_1px,transparent_1px)] bg-[size:36px_36px] [mask-image:radial-gradient(circle_at_center,black,transparent_80%)]" />

            <div className="relative mx-auto max-w-7xl px-4 py-8 md:px-6 lg:px-8">
                <motion.div
                    initial={{ opacity: 0, y: 14 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.35 }}
                    className="mb-8 flex flex-col gap-5"
                >
                    <div className="flex items-center gap-3">
                        <div className="rounded-2xl border border-cyan-400/20 bg-cyan-500/10 p-3 shadow-[0_0_30px_rgba(34,211,238,0.15)]">
                            <Shield className="h-6 w-6 text-cyan-300" />
                        </div>
                        <div>
                            <div className="text-xs tracking-[0.28em] text-cyan-300/80">
                                PHISHGUARD SOC — THREAT INTELLIGENCE BY ROHAN M
                            </div>
                            <h1 className="text-2xl font-semibold tracking-tight md:text-3xl">
                                Threat Reputation Explorer
                            </h1>
                        </div>
                    </div>

                    <div className="rounded-3xl border border-cyan-400/10 bg-slate-900/70 p-4 shadow-[0_0_0_1px_rgba(34,211,238,0.05),0_20px_60px_rgba(2,8,23,0.45)]">
                        <div className="flex flex-col gap-3 md:flex-row">
                            <div className="relative flex-1">
                                <Search className="pointer-events-none absolute left-4 top-1/2 h-5 w-5 -translate-y-1/2 text-slate-500" />
                                <input
                                    value={query}
                                    onChange={(e) => setQuery(e.target.value)}
                                    onKeyDown={(e) => e.key === "Enter" && handleAnalyze()}
                                    placeholder="Search domain, URL, IP, or hash..."
                                    className="h-14 w-full rounded-2xl border border-cyan-400/10 bg-slate-950/80 pl-12 pr-4 text-sm text-slate-100 outline-none ring-0 placeholder:text-slate-500 focus:border-cyan-400/30"
                                />
                            </div>

                            <button
                                onClick={handleAnalyze}
                                disabled={loading}
                                className="inline-flex h-14 items-center justify-center rounded-2xl border border-cyan-400/20 bg-cyan-500/10 px-6 text-sm font-medium text-cyan-200 transition hover:bg-cyan-500/20 disabled:opacity-60"
                            >
                                {loading ? "Analyzing..." : "Analyze"}
                            </button>
                        </div>

                        {errorMessage && (
                            <div className="mt-3 rounded-2xl border border-red-400/20 bg-red-500/10 px-4 py-3 text-sm text-red-200">
                                {errorMessage}
                            </div>
                        )}
                    </div>
                </motion.div>

                {!result ? (
                    <EmptyState />
                ) : (
                    <>
                        <motion.div
                            initial={{ opacity: 0, y: 14 }}
                            animate={{ opacity: 1, y: 0 }}
                            transition={{ delay: 0.08, duration: 0.35 }}
                            className="mb-6 grid gap-6 lg:grid-cols-[1.4fr_0.8fr]"
                        >
                            <div className="rounded-3xl border border-cyan-400/10 bg-slate-900/70 p-6 shadow-[0_0_0_1px_rgba(34,211,238,0.05),0_20px_60px_rgba(2,8,23,0.45)]">
                                <div className="flex flex-col gap-5 md:flex-row md:items-start md:justify-between">
                                    <div className="flex items-start gap-4">
                                        <div className="rounded-2xl border border-cyan-400/20 bg-cyan-500/10 p-3">
                                            <Globe className="h-7 w-7 text-cyan-300" />
                                        </div>
                                        <div>
                                            <div className="mb-2 flex flex-wrap items-center gap-2">
                                                <h2 className="text-2xl font-semibold">{result.query}</h2>
                                                <span className="rounded-full border border-white/10 bg-white/5 px-3 py-1 text-[11px] uppercase tracking-[0.2em] text-slate-300">
                                                    {result.type}
                                                </span>
                                            </div>

                                            <div className="flex flex-wrap gap-2">
                                                {(result.categories ?? []).map((tag) => (
                                                    <span
                                                        key={tag}
                                                        className="rounded-full border border-cyan-400/10 bg-cyan-400/5 px-3 py-1 text-xs text-cyan-200"
                                                    >
                                                        {tag}
                                                    </span>
                                                ))}
                                            </div>

                                            <div className="mt-4 flex flex-wrap gap-4 text-sm text-slate-400">
                                                <span className="inline-flex items-center gap-2">
                                                    <Calendar className="h-4 w-4" />
                                                    Last analysis: {result.lastAnalysisDate ?? "—"}
                                                </span>
                                                <span className="inline-flex items-center gap-2">
                                                    <Server className="h-4 w-4" />
                                                    {result.hostingProvider ?? "—"}
                                                </span>
                                            </div>
                                        </div>
                                    </div>

                                    <div className="flex flex-col items-start gap-3 md:items-end">
                                        <div
                                            className={cx(
                                                "inline-flex items-center gap-2 rounded-full px-4 py-2 text-sm font-medium",
                                                verdictMeta.className
                                            )}
                                        >
                                            <span className={cx("h-2.5 w-2.5 rounded-full", verdictMeta.dot)} />
                                            <VerdictIcon className="h-4 w-4" />
                                            {verdictMeta.label}
                                        </div>

                                        <div className="flex gap-2">
                                            <button
                                                onClick={() => copyText(result.query)}
                                                className="inline-flex items-center gap-2 rounded-2xl border border-white/10 bg-white/5 px-3 py-2 text-sm text-slate-200 hover:bg-white/10"
                                            >
                                                <Copy className="h-4 w-4" />
                                                Copy IOC
                                            </button>
                                            <button
                                                onClick={() => copyText(JSON.stringify(result.raw ?? result, null, 2))}
                                                className="inline-flex items-center gap-2 rounded-2xl border border-white/10 bg-white/5 px-3 py-2 text-sm text-slate-200 hover:bg-white/10"
                                            >
                                                <ExternalLink className="h-4 w-4" />
                                                Export
                                            </button>
                                        </div>
                                    </div>
                                </div>

                                <div className="mt-6 grid gap-4 md:grid-cols-5">
                                    <StatCard label="Detected" value={result.stats.malicious} tone="red" />
                                    <StatCard label="Suspicious" value={result.stats.suspicious} tone="yellow" />
                                    <StatCard label="Clean" value={result.stats.harmless} tone="green" />
                                    <StatCard label="Unknown" value={result.stats.undetected} tone="blue" />
                                    <StatCard label="Total Engines" value={totalEngines} tone="blue" />
                                </div>

                                <ProgressBar result={result} />
                            </div>

                            <div className="grid gap-4">
                                <SectionCard title="Risk Snapshot" icon={Radar}>
                                    <div className="grid grid-cols-2 gap-4">
                                        <div className="rounded-2xl border border-white/5 bg-slate-950/50 p-4">
                                            <div className="text-[11px] uppercase tracking-[0.2em] text-slate-400">
                                                Community Score
                                            </div>
                                            <div className="mt-2 text-3xl font-semibold text-cyan-300">
                                                {result.communityScore}
                                            </div>
                                        </div>
                                        <div className="rounded-2xl border border-white/5 bg-slate-950/50 p-4">
                                            <div className="text-[11px] uppercase tracking-[0.2em] text-slate-400">
                                                Risk Score
                                            </div>
                                            <div className="mt-2 text-3xl font-semibold text-slate-100">
                                                {result.riskScore}
                                            </div>
                                        </div>
                                    </div>

                                    <div className="mt-4 space-y-3 text-sm text-slate-300">
                                        <div className="flex items-center justify-between rounded-2xl border border-white/5 bg-slate-950/50 px-4 py-3">
                                            <span>Resolved IP</span>
                                            <span className="font-medium text-slate-100">
                                                {result.resolvedIp ?? "—"}
                                            </span>
                                        </div>
                                        <div className="flex items-center justify-between rounded-2xl border border-white/5 bg-slate-950/50 px-4 py-3">
                                            <span>ASN</span>
                                            <span className="font-medium text-slate-100">{result.asn ?? "—"}</span>
                                        </div>
                                        <div className="flex items-center justify-between rounded-2xl border border-white/5 bg-slate-950/50 px-4 py-3">
                                            <span>Country</span>
                                            <span className="font-medium text-slate-100">{result.country ?? "—"}</span>
                                        </div>
                                    </div>
                                </SectionCard>

                                <SectionCard title="Threat Context" icon={Target}>
                                    <div className="space-y-4">
                                        <div>
                                            <div className="mb-2 text-xs uppercase tracking-[0.2em] text-slate-400">
                                                CIA Impact
                                            </div>
                                            <div className="grid gap-2">
                                                <ImpactPill label="Confidentiality" value={result.cia?.confidentiality} />
                                                <ImpactPill label="Integrity" value={result.cia?.integrity} />
                                                <ImpactPill label="Availability" value={result.cia?.availability} />
                                            </div>
                                        </div>

                                        <div>
                                            <div className="mb-2 text-xs uppercase tracking-[0.2em] text-slate-400">
                                                MITRE ATT&CK
                                            </div>
                                            <div className="space-y-2">
                                                {(result.mitreAttack ?? []).length > 0 ? (
                                                    result.mitreAttack?.map((item) => (
                                                        <div
                                                            key={`${item.id}-${item.name}`}
                                                            className="rounded-2xl border border-white/5 bg-slate-950/50 px-3 py-2 text-sm text-slate-200"
                                                        >
                                                            <span className="font-semibold text-cyan-300">{item.id}</span>{" "}
                                                            — {item.name}
                                                        </div>
                                                    ))
                                                ) : (
                                                    <div className="rounded-2xl border border-white/5 bg-slate-950/50 px-3 py-2 text-sm text-slate-400">
                                                        No ATT&CK mapping available
                                                    </div>
                                                )}
                                            </div>
                                        </div>

                                        <div>
                                            <div className="mb-2 text-xs uppercase tracking-[0.2em] text-slate-400">
                                                Cyber Kill Chain
                                            </div>
                                            <div className="flex flex-wrap gap-2">
                                                {(result.cyberKillChain ?? []).length > 0 ? (
                                                    result.cyberKillChain?.map((stage) => (
                                                        <span
                                                            key={stage}
                                                            className="rounded-full border border-red-400/20 bg-red-500/10 px-3 py-1 text-xs text-red-200"
                                                        >
                                                            {stage}
                                                        </span>
                                                    ))
                                                ) : (
                                                    <span className="text-sm text-slate-400">No kill chain mapping available</span>
                                                )}
                                            </div>
                                        </div>
                                    </div>
                                </SectionCard>

                                <SectionCard title="Threat Feeds" icon={Activity}>
                                    <div className="space-y-3">
                                        <div className="flex items-center justify-between rounded-2xl border border-white/5 bg-slate-950/50 px-4 py-3 text-sm">
                                            <span className="text-slate-400">AbuseIPDB</span>
                                            <span className="font-medium text-slate-100">
                                                {result.intel?.abuseIpdbScore ?? 0}/100
                                            </span>
                                        </div>
                                        <div className="flex items-center justify-between rounded-2xl border border-white/5 bg-slate-950/50 px-4 py-3 text-sm">
                                            <span className="text-slate-400">AlienVault OTX Pulses</span>
                                            <span className="font-medium text-slate-100">
                                                {result.intel?.otxPulses ?? 0}
                                            </span>
                                        </div>
                                        <div className="flex items-center justify-between rounded-2xl border border-white/5 bg-slate-950/50 px-4 py-3 text-sm">
                                            <span className="text-slate-400">urlscan Detections</span>
                                            <span className="font-medium text-slate-100">
                                                {result.intel?.urlscanDetections ?? 0}
                                            </span>
                                        </div>
                                        <div className="flex items-center justify-between rounded-2xl border border-white/5 bg-slate-950/50 px-4 py-3 text-sm">
                                            <span className="text-slate-400">Cisco Talos</span>
                                            <span className="font-medium text-slate-100">
                                                {result.intel?.talosReputation ?? "Unknown"}
                                            </span>
                                        </div>
                                    </div>
                                </SectionCard>
                            </div>
                        </motion.div>

                        <motion.div
                            initial={{ opacity: 0, y: 14 }}
                            animate={{ opacity: 1, y: 0 }}
                            transition={{ delay: 0.14, duration: 0.35 }}
                            className="mb-6 flex flex-wrap gap-2"
                        >
                            {TABS.map((tab) => (
                                <button
                                    key={tab}
                                    onClick={() => setActiveTab(tab)}
                                    className={cx(
                                        "rounded-2xl border px-4 py-2 text-sm transition",
                                        activeTab === tab
                                            ? "border-cyan-400/30 bg-cyan-500/10 text-cyan-200"
                                            : "border-white/10 bg-white/5 text-slate-300 hover:bg-white/10"
                                    )}
                                >
                                    {tab}
                                </button>
                            ))}
                        </motion.div>

                        <motion.div
                            initial={{ opacity: 0, y: 14 }}
                            animate={{ opacity: 1, y: 0 }}
                            transition={{ delay: 0.2, duration: 0.35 }}
                        >
                            {activeTab === "Overview" && (
                                <div className="grid gap-6 lg:grid-cols-2">
                                    <SectionCard title="Overview" icon={Info}>
                                        <KV label="Entity" value={result.query} />
                                        <KV label="Type" value={result.type} />
                                        <KV label="Verdict" value={verdictMeta.label} />
                                        <KV label="Hosting Provider" value={result.hostingProvider} />
                                        <KV label="Resolved IP" value={result.resolvedIp} />
                                        <KV label="ASN" value={result.asn} />
                                        <KV label="Country" value={result.country} />
                                    </SectionCard>

                                    <SectionCard title="OSINT Summary" icon={Fingerprint}>
                                        <KV label="Community Score" value={result.communityScore} />
                                        <KV label="Risk Score" value={result.riskScore} />
                                        <KV label="OpenPhish" value={result.intel?.openPhish ? "Match" : "No hit"} />
                                        <KV label="PhishTank" value={result.intel?.phishTank ? "Match" : "No hit"} />
                                        <KV label="OTX Pulses" value={result.intel?.otxPulses ?? 0} />
                                        <KV label="Talos Reputation" value={result.intel?.talosReputation} />
                                    </SectionCard>
                                </div>
                            )}

                            {activeTab === "Detection" && (
                                <div className="grid gap-6 lg:grid-cols-2">
                                    <SectionCard title="Detection Ratios" icon={Shield}>
                                        <div className="grid gap-4 md:grid-cols-2">
                                            <StatCard label="Malicious" value={result.stats.malicious} tone="red" />
                                            <StatCard label="Suspicious" value={result.stats.suspicious} tone="yellow" />
                                            <StatCard label="Harmless" value={result.stats.harmless} tone="green" />
                                            <StatCard label="Undetected" value={result.stats.undetected} tone="blue" />
                                        </div>
                                        <ProgressBar result={result} />
                                    </SectionCard>

                                    <SectionCard title="Engine Results" icon={Skull}>
                                        {result.vendors && result.vendors.length > 0 ? (
                                            <div className="overflow-hidden rounded-2xl border border-white/5">
                                                {result.vendors.slice(0, 15).map((vendor, idx) => (
                                                    <div
                                                        key={`${vendor.vendor}-${idx}`}
                                                        className="grid grid-cols-[1fr_auto] items-center gap-4 border-b border-white/5 bg-slate-950/50 px-4 py-3 last:border-b-0"
                                                    >
                                                        <div>
                                                            <div className="text-sm text-slate-100">{vendor.vendor}</div>
                                                            <div className="text-xs text-slate-500">
                                                                {vendor.result || vendor.category || "No label"}
                                                            </div>
                                                        </div>
                                                        <span
                                                            className={cx(
                                                                "rounded-full px-3 py-1 text-xs",
                                                                vendor.status === "Malicious"
                                                                    ? "bg-red-500/10 text-red-300"
                                                                    : vendor.status === "Suspicious"
                                                                        ? "bg-amber-500/10 text-amber-300"
                                                                        : vendor.status === "Clean"
                                                                            ? "bg-emerald-500/10 text-emerald-300"
                                                                            : "bg-slate-500/10 text-slate-300"
                                                            )}
                                                        >
                                                            {vendor.status}
                                                        </span>
                                                    </div>
                                                ))}
                                            </div>
                                        ) : (
                                            <div className="rounded-2xl border border-white/5 bg-slate-950/50 p-4 text-sm text-slate-400">
                                                No per-engine result list returned for this indicator.
                                            </div>
                                        )}
                                    </SectionCard>
                                </div>
                            )}

                            {activeTab === "Whois" && (
                                <SectionCard title="WHOIS / RDAP" icon={FileText}>
                                    <KV label="Registrar" value={result.whois?.registrar} />
                                    <KV label="Created" value={result.whois?.created} />
                                    <KV label="Updated" value={result.whois?.updated} />
                                    <KV label="Expires" value={result.whois?.expires} />
                                    <KV label="Registrar Country" value={result.whois?.registrarCountry} />
                                    <KV
                                        label="Name Servers"
                                        value={
                                            <div className="space-y-1">
                                                {(result.whois?.nameServers ?? []).length > 0
                                                    ? result.whois?.nameServers?.map((item) => (
                                                        <div key={item}>{item}</div>
                                                    ))
                                                    : "—"}
                                            </div>
                                        }
                                    />
                                    <KV
                                        label="WHOIS Raw"
                                        value={
                                            result.whois?.whoisText ? (
                                                <pre className="overflow-x-auto rounded-xl border border-white/5 bg-slate-950/70 p-3 text-xs leading-6 text-slate-300">
                                                    {result.whois.whoisText}
                                                </pre>
                                            ) : (
                                                "—"
                                            )
                                        }
                                    />
                                </SectionCard>
                            )}

                            {activeTab === "DNS" && (
                                <div className="grid gap-6 lg:grid-cols-2">
                                    <SectionCard title="DNS Records" icon={Network}>
                                        <KV label="A" value={(result.dns?.a ?? []).join(", ")} />
                                        <KV label="AAAA" value={(result.dns?.aaaa ?? []).join(", ")} />
                                        <KV label="MX" value={(result.dns?.mx ?? []).join(", ")} />
                                        <KV label="NS" value={(result.dns?.ns ?? []).join(", ")} />
                                        <KV label="TXT" value={(result.dns?.txt ?? []).join(", ")} />
                                        <KV label="CNAME" value={(result.dns?.cname ?? []).join(", ")} />
                                    </SectionCard>

                                    <SectionCard title="Email / TXT Context" icon={Shield}>
                                        <KV
                                            label="TXT Values"
                                            value={
                                                <div className="space-y-2">
                                                    {(result.dns?.txt ?? []).length > 0
                                                        ? result.dns?.txt?.map((item) => (
                                                            <div
                                                                key={item}
                                                                className="rounded-xl border border-white/5 bg-slate-950/50 p-3 text-xs text-slate-300"
                                                            >
                                                                {item}
                                                            </div>
                                                        ))
                                                        : "—"}
                                                </div>
                                            }
                                        />
                                    </SectionCard>
                                </div>
                            )}

                            {activeTab === "SSL" && (
                                <SectionCard title="SSL / Certificate" icon={Lock}>
                                    <KV label="Issuer" value={result.ssl?.issuer} />
                                    <KV label="Subject" value={result.ssl?.subject} />
                                    <KV label="Valid From" value={result.ssl?.validFrom} />
                                    <KV label="Valid To" value={result.ssl?.validTo} />
                                    <KV label="Serial Number" value={result.ssl?.serialNumber} />
                                    <KV
                                        label="SAN"
                                        value={
                                            <div className="space-y-1">
                                                {(result.ssl?.san ?? []).length > 0
                                                    ? result.ssl?.san?.map((item) => (
                                                        <div key={item}>{item}</div>
                                                    ))
                                                    : "—"}
                                            </div>
                                        }
                                    />
                                </SectionCard>
                            )}

                            {activeTab === "Relations" && (
                                <div className="grid gap-6 lg:grid-cols-2">
                                    <SectionCard title="Subdomains" icon={Globe}>
                                        {(result.subdomains ?? []).length > 0 ? (
                                            <div className="overflow-hidden rounded-2xl border border-white/5">
                                                {(result.subdomains ?? []).map((item, idx) => (
                                                    <div
                                                        key={`${item.hostname}-${idx}`}
                                                        className="grid grid-cols-[1fr_auto] items-center gap-4 border-b border-white/5 bg-slate-950/50 px-4 py-3 last:border-b-0"
                                                    >
                                                        <div>
                                                            <div className="text-sm text-slate-100">{item.hostname}</div>
                                                            <div className="text-xs text-slate-500">{item.ip ?? "No IP"}</div>
                                                        </div>
                                                        <ChevronRight className="h-4 w-4 text-slate-500" />
                                                    </div>
                                                ))}
                                            </div>
                                        ) : (
                                            <div className="rounded-2xl border border-white/5 bg-slate-950/50 p-4 text-sm text-slate-400">
                                                No subdomains returned.
                                            </div>
                                        )}
                                    </SectionCard>

                                    <SectionCard title="Related URLs" icon={LinkIcon}>
                                        {(result.relatedUrls ?? []).length > 0 ? (
                                            <div className="overflow-hidden rounded-2xl border border-white/5">
                                                {(result.relatedUrls ?? []).map((item, idx) => (
                                                    <div
                                                        key={`${item.url}-${idx}`}
                                                        className="grid grid-cols-[1fr_auto] items-center gap-4 border-b border-white/5 bg-slate-950/50 px-4 py-3 last:border-b-0"
                                                    >
                                                        <div>
                                                            <div className="break-all text-sm text-slate-100">{item.url}</div>
                                                            <div className="text-xs text-slate-500">
                                                                {item.status ?? "unknown"} • {item.lastSeen ?? "n/a"}
                                                            </div>
                                                        </div>
                                                        <ChevronRight className="h-4 w-4 text-slate-500" />
                                                    </div>
                                                ))}
                                            </div>
                                        ) : (
                                            <div className="rounded-2xl border border-white/5 bg-slate-950/50 p-4 text-sm text-slate-400">
                                                No related URLs returned.
                                            </div>
                                        )}
                                    </SectionCard>
                                </div>
                            )}

                            {activeTab === "Raw JSON" && (
                                <SectionCard title="Raw Response" icon={FileText}>
                                    <pre className="overflow-x-auto rounded-2xl border border-white/5 bg-slate-950/80 p-4 text-xs leading-6 text-slate-300">
                                        {JSON.stringify(result.raw ?? result, null, 2)}
                                    </pre>
                                </SectionCard>
                            )}
                        </motion.div>
                    </>
                )}
            </div>
        </div>
    );
}