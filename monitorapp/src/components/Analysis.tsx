import { useMemo, useState } from "react";
import {
  FileText,
  Activity,
  Shield,
  Network,
  BarChart3,
  Clock,
  Globe,
  Server,
  AlertTriangle,
  Eye,
} from "lucide-react";
import { StatCard } from "./UI/StatCard";
import { SectionHeader } from "./UI/SectionHeaderProps";

type ProtocolCounts = Record<string, number>;
type PortCounts = Record<string, number>;
type IpCounts = Record<string, number>;

type SectionKey = "basicStats" | "conversations" | "suspicious";

interface AnalysisData {
  basic_stats: {
    total_packets: number;
    time_range: {
      start_readable?: string;
      end_readable?: string;
      duration_seconds?: number;
    };
    packet_size_stats: {
      min: number;
      max: number;
      avg: number;
    };
    src_ips: IpCounts;
    protocols: ProtocolCounts;
    src_ports: PortCounts;
    dst_ports: PortCounts;
  };
  conversations: Array<{
    conversation: string;
    packets: number;
    bytes: number;
    duration: number;
    protocols: string[];
    start_time_readable?: string;
  }>;
  suspicious_activity: {
    port_scans: Array<{
      src_ip: string;
      ports_accessed: number;
      ports: number[];
    }>;
    high_volume_ips: Array<{
      ip: string;
      packet_count: number;
      percentage: number;
    }>;
    large_packets: Array<{
      size: number;
      src: string;
      dst: string;
      timestamp?: number;
    }>;
    unusual_protocols: Array<{
      protocol: string;
      count: number;
      percentage: number;
    }>;
  };
}

// Removed UploadInfo since uploads are handled in Dashboard

type AnalysisProps = {
  data: unknown | null
}

export default function Analysis({ data }: AnalysisProps) {
  const analysisData = (data as AnalysisData) ?? null;
  const loading = false;
//   const [error, setError] = useState<string | null>(null);
//   const [uploadInfo, setUploadInfo] = useState<UploadInfo | null>(null);
  const [expandedSections, setExpandedSections] = useState<
    Record<SectionKey, boolean>
  >({
    basicStats: true,
    conversations: true,
    suspicious: true,
  });
//   const fileInputRef = useRef<HTMLInputElement | null>(null);

  const toggleSection = (section: SectionKey) => {
    setExpandedSections((prev) => ({
      ...prev,
      [section]: !prev[section],
    }));
  };

  // Conversations table UI state
  type SortKey = "conversation" | "packets" | "bytes" | "duration" | "start_time_readable";
  type SortDir = "asc" | "desc";
  const [searchText, setSearchText] = useState("");
  const [sortKey, setSortKey] = useState<SortKey>("packets");
  const [sortDir, setSortDir] = useState<SortDir>("desc");
  const [pageIndex, setPageIndex] = useState(0);
  const [pageSize, setPageSize] = useState(10);
  const [selectedConv, setSelectedConv] = useState<AnalysisData["conversations"][number] | null>(null);

  const filteredSortedConvs = useMemo(() => {
    if (!analysisData) return [] as AnalysisData["conversations"];
    const base = analysisData.conversations;
    const filtered = searchText.trim()
      ? base.filter((c) => {
          const q = searchText.toLowerCase();
          const proto = c.protocols.join(",").toLowerCase();
          return (
            c.conversation.toLowerCase().includes(q) ||
            String(c.packets).includes(q) ||
            String(c.bytes).includes(q) ||
            String(c.duration).includes(q) ||
            (c.start_time_readable ? c.start_time_readable.toLowerCase().includes(q) : false) ||
            proto.includes(q)
          );
        })
      : base.slice();
    filtered.sort((a, b) => {
      const dir = sortDir === "asc" ? 1 : -1;
      switch (sortKey) {
        case "packets":
          return dir * (a.packets - b.packets);
        case "bytes":
          return dir * (a.bytes - b.bytes);
        case "duration":
          return dir * (a.duration - b.duration);
        case "start_time_readable": {
          const at = a.start_time_readable ? new Date(a.start_time_readable).getTime() : 0;
          const bt = b.start_time_readable ? new Date(b.start_time_readable).getTime() : 0;
          return dir * (at - bt);
        }
        case "conversation":
        default:
          return dir * a.conversation.localeCompare(b.conversation);
      }
    });
    return filtered;
  }, [analysisData, searchText, sortKey, sortDir]);

  const totalRows = filteredSortedConvs.length;
  const totalPages = Math.max(1, Math.ceil(totalRows / pageSize));
  const currentPage = Math.min(pageIndex, totalPages - 1);
  const pageRows = useMemo(() => {
    const start = currentPage * pageSize;
    return filteredSortedConvs.slice(start, start + pageSize);
  }, [filteredSortedConvs, currentPage, pageSize]);

  const onHeaderClick = (key: SortKey) => {
    if (key === sortKey) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDir("desc");
    }
  };

//   const handleFileUpload = async (
//     event: React.ChangeEvent<HTMLInputElement>
//   ) => {
//     const file = event.target.files?.[0];
//     if (!file) return;

//     if (!file.name.toLowerCase().endsWith(".pcap")) {
//       setError("Please select a valid .pcap file");
//       return;
//     }

//     setLoading(true);
//     setError(null);
//     setAnalysisData(null);

//     const formData = new FormData();
//     formData.append("file", file);

//     try {
//       const response = await fetch("http://127.0.0.1:8000/upload", {
//         method: "POST",
//         body: formData,
//       });

//       if (!response.ok) {
//         const errorData = await response.json();
//         throw new Error(errorData.detail || "Upload failed");
//       }

//       const result = await response.json();
//       setUploadInfo({
//         filename: result.filename as string,
//         fileSize: result.file_size as number,
//       });
//       setAnalysisData(result.analysis as AnalysisData);
//     } catch (err) {
//       const message = err instanceof Error ? err.message : String(err);
//       setError(message);
//     } finally {
//       setLoading(false);
//     }
//   };

  const formatBytes = (bytes: number): string => {
    if (bytes === 0) return "0 Bytes";
    const k = 1024;
    const sizes = ["Bytes", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 via-white to-purple-50 p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header
        <div className="text-center mb-8">
          <h1 className="text-4xl font-bold bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent mb-2">
            PCAP Analysis Dashboard
          </h1>
          <p className="text-gray-600">
            Upload and analyze network packet capture files
          </p>
        </div> */}

        {/* Upload Section */}
        {/* <div className="bg-white rounded-2xl shadow-xl p-8 mb-8 border border-gray-200">
          <div className="flex items-center justify-center">
            <div className="w-full max-w-md">
              <input
                type="file"
                ref={fileInputRef}
                onChange={handleFileUpload}
                accept=".pcap"
                className="hidden"
              />
              <button
                onClick={() => fileInputRef.current?.click()}
                disabled={loading}
                className="w-full bg-gradient-to-r from-blue-500 to-purple-600 hover:from-blue-600 hover:to-purple-700 disabled:from-gray-400 disabled:to-gray-500 text-white font-semibold py-4 px-8 rounded-xl transition-all duration-300 flex items-center justify-center space-x-3 shadow-lg hover:shadow-xl transform hover:scale-105 disabled:transform-none"
              >
                <Upload className="w-5 h-5" />
                <span>{loading ? "Analyzing..." : "Upload PCAP File"}</span>
              </button>
            </div>
          </div>

          {uploadInfo && (
            <div className="mt-4 p-4 bg-green-50 rounded-lg border border-green-200">
              <p className="text-green-800 font-medium">
                ✓ {uploadInfo.filename}
              </p>
              <p className="text-green-600 text-sm">
                File size: {formatBytes(uploadInfo.fileSize)}
              </p>
            </div>
          )}

          {error && (
            <div className="mt-4 p-4 bg-red-50 rounded-lg border border-red-200">
              <p className="text-red-800 font-medium">⚠ {error}</p>
            </div>
          )}
        </div> */}

        {/* Loading Spinner */}
        {loading && (
          <div className="flex justify-center items-center py-12">
            <div className="animate-spin rounded-full h-16 w-16 border-b-2 border-blue-500"></div>
          </div>
        )}

        {/* Analysis Results */}
        {analysisData && (
          <div className="space-y-8">
            {/* Basic Statistics */}
            <div>
              <SectionHeader
                icon={BarChart3}
                title="Basic Statistics"
                isExpanded={expandedSections.basicStats}
                onToggle={() => toggleSection("basicStats")}
              />

              {expandedSections.basicStats && (
                <div className="space-y-6">
                  {/* Overview Cards */}
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                    <StatCard
                      icon={FileText}
                      title="Total Packets"
                      value={analysisData.basic_stats.total_packets.toLocaleString()}
                      color="blue"
                    />
                    <StatCard
                      icon={Clock}
                      title="Duration"
                      value={`${
                        analysisData.basic_stats.time_range.duration_seconds ||
                        0
                      }s`}
                      subtitle={(() => {
                        const tr = analysisData.basic_stats.time_range;
                        if (!tr.start_readable) return "No timing data";
                        const start = tr.start_readable;
                        const end = tr.end_readable ?? tr.start_readable;
                        return `${new Date(
                          start
                        ).toLocaleString()} - ${new Date(
                          end
                        ).toLocaleString()}`;
                      })()}
                      color="green"
                    />
                    <StatCard
                      icon={Activity}
                      title="Avg Packet Size"
                      value={`${analysisData.basic_stats.packet_size_stats.avg} bytes`}
                      subtitle={`Range: ${analysisData.basic_stats.packet_size_stats.min} - ${analysisData.basic_stats.packet_size_stats.max}`}
                      color="purple"
                    />
                    <StatCard
                      icon={Globe}
                      title="Unique IPs"
                      value={
                        Object.keys(analysisData.basic_stats.src_ips).length
                      }
                      subtitle="Source addresses"
                      color="orange"
                    />
                  </div>

                  {/* Protocol Distribution */}
                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    <div className="bg-white rounded-xl shadow-lg p-6">
                      <h3 className="text-lg font-semibold text-gray-800 mb-4 flex items-center space-x-2">
                        <Network className="w-5 h-5 text-blue-500" />
                        <span>Protocol Distribution</span>
                      </h3>
                      <div className="space-y-3">
                        {Object.entries(analysisData.basic_stats.protocols).map(
                          ([protocol, count]) => (
                            <div
                              key={protocol}
                              className="flex justify-between items-center"
                            >
                              <span className="text-gray-700 font-medium">
                                {protocol}
                              </span>
                              <div className="flex items-center space-x-2">
                                <div className="bg-blue-100 text-blue-800 px-3 py-1 rounded-full text-sm font-medium">
                                  {count.toLocaleString()}
                                </div>
                                <div className="w-24 bg-gray-200 rounded-full h-2">
                                  <div
                                    className="bg-blue-500 h-2 rounded-full transition-all duration-500"
                                    style={{
                                      width: `${
                                        (count /
                                          analysisData.basic_stats
                                            .total_packets) *
                                        100
                                      }%`,
                                    }}
                                  ></div>
                                </div>
                              </div>
                            </div>
                          )
                        )}
                      </div>
                    </div>

                    {/* Top Source IPs */}
                    <div className="bg-white rounded-xl shadow-lg p-6">
                      <h3 className="text-lg font-semibold text-gray-800 mb-4 flex items-center space-x-2">
                        <Server className="w-5 h-5 text-green-500" />
                        <span>Top Source IPs</span>
                      </h3>
                      <div className="space-y-3">
                        {Object.entries(analysisData.basic_stats.src_ips)
                          .slice(0, 8)
                          .map(([ip, count]) => (
                            <div
                              key={ip}
                              className="flex justify-between items-center"
                            >
                              <span className="text-gray-700 font-mono text-sm">
                                {ip}
                              </span>
                              <div className="bg-green-100 text-green-800 px-3 py-1 rounded-full text-sm font-medium">
                                {count.toLocaleString()}
                              </div>
                            </div>
                          ))}
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* Network Conversations */}
            <div>
              <SectionHeader
                icon={Network}
                title="Network Conversations"
                isExpanded={expandedSections.conversations}
                onToggle={() => toggleSection("conversations")}
              />

              {expandedSections.conversations && (
                <div className="bg-white rounded-xl shadow-lg overflow-hidden">
                  {/* Toolbar */}
                  <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3 p-4 border-b border-gray-200">
                    <input
                      type="text"
                      value={searchText}
                      onChange={(e) => {
                        setSearchText(e.target.value);
                        setPageIndex(0);
                      }}
                      placeholder="Search by IP, protocol, counts…"
                      className="w-full md:max-w-sm px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                    <div className="flex items-center gap-2">
                      <label className="text-sm text-gray-600">Rows</label>
                      <select
                        className="px-2 py-1 border border-gray-300 rounded-md"
                        value={pageSize}
                        onChange={(e) => {
                          setPageSize(Number(e.target.value));
                          setPageIndex(0);
                        }}
                      >
                        <option value={10}>10</option>
                        <option value={25}>25</option>
                        <option value={50}>50</option>
                        <option value={100}>100</option>
                      </select>
                    </div>
                  </div>

                  <div className="overflow-x-auto">
                    <table className="w-full">
                      <thead className="bg-gray-50">
                        <tr>
                          <th
                            className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer select-none"
                            onClick={() => onHeaderClick("conversation")}
                          >
                            Conversation {sortKey === "conversation" && (sortDir === "asc" ? "▲" : "▼")}
                          </th>
                          <th
                            className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer select-none"
                            onClick={() => onHeaderClick("packets")}
                          >
                            Packets {sortKey === "packets" && (sortDir === "asc" ? "▲" : "▼")}
                          </th>
                          <th
                            className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer select-none"
                            onClick={() => onHeaderClick("bytes")}
                          >
                            Bytes {sortKey === "bytes" && (sortDir === "asc" ? "▲" : "▼")}
                          </th>
                          <th
                            className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer select-none"
                            onClick={() => onHeaderClick("duration")}
                          >
                            Duration {sortKey === "duration" && (sortDir === "asc" ? "▲" : "▼")}
                          </th>
                          <th
                            className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer select-none"
                            onClick={() => onHeaderClick("start_time_readable")}
                          >
                            Start Time {sortKey === "start_time_readable" && (sortDir === "asc" ? "▲" : "▼")}
                          </th>
                          <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                            Protocols
                          </th>
                        </tr>
                      </thead>
                      <tbody className="bg-white divide-y divide-gray-200">
                        {pageRows.map((conv, index) => (
                          <tr
                            key={`${conv.conversation}-${index}`}
                            className="hover:bg-gray-50 transition-colors duration-200 cursor-pointer"
                            onClick={() => setSelectedConv(conv)}
                          >
                            <td className="px-6 py-4 whitespace-nowrap">
                              <div className="text-sm font-mono text-gray-900">
                                {conv.conversation}
                              </div>
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap">
                              <span className="bg-blue-100 text-blue-800 px-3 py-1 rounded-full text-sm font-medium">
                                {conv.packets.toLocaleString()}
                              </span>
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                              {formatBytes(conv.bytes)}
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                              {conv.duration}s
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                              {conv.start_time_readable ? new Date(conv.start_time_readable).toLocaleString() : "—"}
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap">
                              <div className="flex flex-wrap gap-1">
                                {conv.protocols.map((protocol, i) => (
                                  <span
                                    key={i}
                                    className="bg-purple-100 text-purple-800 px-2 py-1 rounded text-xs font-medium"
                                  >
                                    {protocol}
                                  </span>
                                ))}
                              </div>
                            </td>
                          </tr>
                        ))}
                        {pageRows.length === 0 && (
                          <tr>
                            <td colSpan={6} className="px-6 py-8 text-center text-gray-500">
                              No conversations match your search.
                            </td>
                          </tr>
                        )}
                      </tbody>
                    </table>
                  </div>

                  {/* Pagination */}
                  <div className="flex items-center justify-between px-4 py-3 border-t border-gray-200 text-sm">
                    <div className="text-gray-600">
                      Showing {totalRows === 0 ? 0 : currentPage * pageSize + 1}–
                      {Math.min(totalRows, (currentPage + 1) * pageSize)} of {totalRows}
                    </div>
                    <div className="flex items-center gap-2">
                      <button
                        className="px-3 py-1 border rounded-md disabled:opacity-50"
                        onClick={() => setPageIndex(0)}
                        disabled={currentPage === 0}
                      >
                        « First
                      </button>
                      <button
                        className="px-3 py-1 border rounded-md disabled:opacity-50"
                        onClick={() => setPageIndex((p) => Math.max(0, p - 1))}
                        disabled={currentPage === 0}
                      >
                        ‹ Prev
                      </button>
                      <span className="px-2 text-gray-600">
                        Page {currentPage + 1} / {totalPages}
                      </span>
                      <button
                        className="px-3 py-1 border rounded-md disabled:opacity-50"
                        onClick={() => setPageIndex((p) => Math.min(totalPages - 1, p + 1))}
                        disabled={currentPage >= totalPages - 1}
                      >
                        Next ›
                      </button>
                      <button
                        className="px-3 py-1 border rounded-md disabled:opacity-50"
                        onClick={() => setPageIndex(totalPages - 1)}
                        disabled={currentPage >= totalPages - 1}
                      >
                        Last »
                      </button>
                    </div>
                  </div>
                </div>
              )}
              {/* Details Modal */}
              {selectedConv && (
                <div className="fixed inset-0 z-50 flex items-center justify-center">
                  <div className="absolute inset-0 bg-black/40" onClick={() => setSelectedConv(null)}></div>
                  <div className="relative bg-white rounded-xl shadow-2xl w-full max-w-2xl mx-4 p-6">
                    <div className="flex items-start justify-between mb-4">
                      <h4 className="text-lg font-semibold text-gray-900">Conversation Details</h4>
                      <button
                        className="text-gray-500 hover:text-gray-700"
                        onClick={() => setSelectedConv(null)}
                        aria-label="Close"
                      >
                        ✕
                      </button>
                    </div>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                      <div>
                        <p className="text-xs text-gray-500">Conversation</p>
                        <p className="font-mono text-sm text-gray-900 break-all">{selectedConv.conversation}</p>
                      </div>
                      <div>
                        <p className="text-xs text-gray-500">Packets</p>
                        <p className="text-sm font-semibold text-gray-900">{selectedConv.packets.toLocaleString()}</p>
                      </div>
                      <div>
                        <p className="text-xs text-gray-500">Bytes</p>
                        <p className="text-sm font-semibold text-gray-900">{formatBytes(selectedConv.bytes)}</p>
                      </div>
                      <div>
                        <p className="text-xs text-gray-500">Duration</p>
                        <p className="text-sm font-semibold text-gray-900">{selectedConv.duration}s</p>
                      </div>
                      <div>
                        <p className="text-xs text-gray-500">Start Time</p>
                        <p className="text-sm font-semibold text-gray-900">{selectedConv.start_time_readable ? new Date(selectedConv.start_time_readable).toLocaleString() : "—"}</p>
                      </div>
                      <div>
                        <p className="text-xs text-gray-500">Protocols</p>
                        <div className="flex flex-wrap gap-1 mt-1">
                          {selectedConv.protocols.map((p, i) => (
                            <span key={i} className="bg-purple-100 text-purple-800 px-2 py-1 rounded text-xs font-medium">{p}</span>
                          ))}
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* Suspicious Activity */}
            <div>
              <SectionHeader
                icon={Shield}
                title="Security Analysis"
                isExpanded={expandedSections.suspicious}
                onToggle={() => toggleSection("suspicious")}
              />

              {expandedSections.suspicious && (
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  {/* Port Scans */}
                  <div className="bg-white rounded-xl shadow-lg p-6">
                    <h3 className="text-lg font-semibold text-gray-800 mb-4 flex items-center space-x-2">
                      <Eye className="w-5 h-5 text-red-500" />
                      <span>Potential Port Scans</span>
                      {analysisData.suspicious_activity.port_scans.length >
                        0 && (
                        <span className="bg-red-100 text-red-800 px-2 py-1 rounded-full text-xs font-medium ml-2">
                          {analysisData.suspicious_activity.port_scans.length}
                        </span>
                      )}
                    </h3>
                    {analysisData.suspicious_activity.port_scans.length ===
                    0 ? (
                      <p className="text-gray-500 text-center py-4">
                        No port scans detected
                      </p>
                    ) : (
                      <div className="space-y-3">
                        {analysisData.suspicious_activity.port_scans.map(
                          (scan, index) => (
                            <div
                              key={index}
                              className="bg-red-50 border border-red-200 rounded-lg p-4"
                            >
                              <div className="flex justify-between items-start">
                                <div>
                                  <p className="font-mono text-sm text-red-800 font-medium">
                                    {scan.src_ip}
                                  </p>
                                  <p className="text-xs text-red-600">
                                    {scan.ports_accessed} ports accessed
                                  </p>
                                </div>
                                <AlertTriangle className="w-5 h-5 text-red-500" />
                              </div>
                              <div className="mt-2">
                                <p className="text-xs text-gray-600 mb-1">
                                  Ports:
                                </p>
                                <div className="flex flex-wrap gap-1">
                                  {scan.ports.slice(0, 10).map((port, i) => (
                                    <span
                                      key={i}
                                      className="bg-red-100 text-red-700 px-2 py-1 rounded text-xs"
                                    >
                                      {port}
                                    </span>
                                  ))}
                                  {scan.ports.length > 10 && (
                                    <span className="text-red-500 text-xs">
                                      ...and {scan.ports.length - 10} more
                                    </span>
                                  )}
                                </div>
                              </div>
                            </div>
                          )
                        )}
                      </div>
                    )}
                  </div>

                  {/* High Volume IPs */}
                  <div className="bg-white rounded-xl shadow-lg p-6">
                    <h3 className="text-lg font-semibold text-gray-800 mb-4 flex items-center space-x-2">
                      <Activity className="w-5 h-5 text-orange-500" />
                      <span>High Volume IPs</span>
                      {analysisData.suspicious_activity.high_volume_ips.length >
                        0 && (
                        <span className="bg-orange-100 text-orange-800 px-2 py-1 rounded-full text-xs font-medium ml-2">
                          {
                            analysisData.suspicious_activity.high_volume_ips
                              .length
                          }
                        </span>
                      )}
                    </h3>
                    {analysisData.suspicious_activity.high_volume_ips.length ===
                    0 ? (
                      <p className="text-gray-500 text-center py-4">
                        No high volume IPs detected
                      </p>
                    ) : (
                      <div className="space-y-3">
                        {analysisData.suspicious_activity.high_volume_ips.map(
                          (ip, index) => (
                            <div
                              key={index}
                              className="bg-orange-50 border border-orange-200 rounded-lg p-4"
                            >
                              <div className="flex justify-between items-center">
                                <div>
                                  <p className="font-mono text-sm text-orange-800 font-medium">
                                    {ip.ip}
                                  </p>
                                  <p className="text-xs text-orange-600">
                                    {ip.packet_count.toLocaleString()} packets
                                  </p>
                                </div>
                                <div className="text-right">
                                  <p className="text-lg font-bold text-orange-700">
                                    {ip.percentage.toFixed(1)}%
                                  </p>
                                  <p className="text-xs text-orange-600">
                                    of traffic
                                  </p>
                                </div>
                              </div>
                            </div>
                          )
                        )}
                      </div>
                    )}
                  </div>

                  {/* Large Packets */}
                  <div className="bg-white rounded-xl shadow-lg p-6">
                    <h3 className="text-lg font-semibold text-gray-800 mb-4 flex items-center space-x-2">
                      <AlertTriangle className="w-5 h-5 text-yellow-500" />
                      <span>Large Packets ({">"}1500 bytes)</span>
                      {analysisData.suspicious_activity.large_packets.length >
                        0 && (
                        <span className="bg-yellow-100 text-yellow-800 px-2 py-1 rounded-full text-xs font-medium ml-2">
                          {
                            analysisData.suspicious_activity.large_packets
                              .length
                          }
                        </span>
                      )}
                    </h3>
                    {analysisData.suspicious_activity.large_packets.length ===
                    0 ? (
                      <p className="text-gray-500 text-center py-4">
                        No large packets detected
                      </p>
                    ) : (
                      <div className="space-y-2 max-h-64 overflow-y-auto">
                        {analysisData.suspicious_activity.large_packets
                          .slice(0, 10)
                          .map((packet, index) => (
                            <div
                              key={index}
                              className="bg-yellow-50 border border-yellow-200 rounded-lg p-3"
                            >
                              <div className="flex justify-between items-center">
                                <div>
                                  <p className="text-sm font-medium text-yellow-800">
                                    {formatBytes(packet.size)}
                                  </p>
                                  <p className="text-xs text-yellow-600 font-mono">
                                    {packet.src} → {packet.dst}
                                  </p>
                                </div>
                                <p className="text-xs text-yellow-600">
                                  {packet.timestamp
                                    ? new Date(
                                        packet.timestamp * 1000
                                      ).toLocaleTimeString()
                                    : "Unknown time"}
                                </p>
                              </div>
                            </div>
                          ))}
                        {analysisData.suspicious_activity.large_packets.length >
                          10 && (
                          <p className="text-center text-gray-500 text-sm py-2">
                            ...and{" "}
                            {analysisData.suspicious_activity.large_packets
                              .length - 10}{" "}
                            more large packets
                          </p>
                        )}
                      </div>
                    )}
                  </div>

                  {/* Unusual Protocols */}
                  <div className="bg-white rounded-xl shadow-lg p-6">
                    <h3 className="text-lg font-semibold text-gray-800 mb-4 flex items-center space-x-2">
                      <Shield className="w-5 h-5 text-indigo-500" />
                      <span>Unusual Protocols</span>
                      {analysisData.suspicious_activity.unusual_protocols
                        .length > 0 && (
                        <span className="bg-indigo-100 text-indigo-800 px-2 py-1 rounded-full text-xs font-medium ml-2">
                          {
                            analysisData.suspicious_activity.unusual_protocols
                              .length
                          }
                        </span>
                      )}
                    </h3>
                    {analysisData.suspicious_activity.unusual_protocols
                      .length === 0 ? (
                      <p className="text-gray-500 text-center py-4">
                        No unusual protocols detected
                      </p>
                    ) : (
                      <div className="space-y-3">
                        {analysisData.suspicious_activity.unusual_protocols.map(
                          (protocol, index) => (
                            <div
                              key={index}
                              className="bg-indigo-50 border border-indigo-200 rounded-lg p-3"
                            >
                              <div className="flex justify-between items-center">
                                <span className="text-indigo-800 font-medium">
                                  {protocol.protocol}
                                </span>
                                <div className="text-right">
                                  <p className="text-sm font-bold text-indigo-700">
                                    {protocol.count}
                                  </p>
                                  <p className="text-xs text-indigo-600">
                                    {protocol.percentage.toFixed(2)}%
                                  </p>
                                </div>
                              </div>
                            </div>
                          )
                        )}
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>

            {/* Port Statistics */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div className="bg-white rounded-xl shadow-lg p-6">
                <h3 className="text-lg font-semibold text-gray-800 mb-4 flex items-center space-x-2">
                  <Server className="w-5 h-5 text-blue-500" />
                  <span>Top Source Ports</span>
                </h3>
                <div className="space-y-2">
                  {Object.entries(analysisData.basic_stats.src_ports)
                    .slice(0, 8)
                    .map(([port, count]) => (
                      <div
                        key={port}
                        className="flex justify-between items-center"
                      >
                        <span className="text-gray-700 font-mono">{port}</span>
                        <span className="bg-blue-100 text-blue-800 px-2 py-1 rounded text-sm">
                          {count}
                        </span>
                      </div>
                    ))}
                </div>
              </div>

              <div className="bg-white rounded-xl shadow-lg p-6">
                <h3 className="text-lg font-semibold text-gray-800 mb-4 flex items-center space-x-2">
                  <Server className="w-5 h-5 text-green-500" />
                  <span>Top Destination Ports</span>
                </h3>
                <div className="space-y-2">
                  {Object.entries(analysisData.basic_stats.dst_ports)
                    .slice(0, 8)
                    .map(([port, count]) => (
                      <div
                        key={port}
                        className="flex justify-between items-center"
                      >
                        <span className="text-gray-700 font-mono">{port}</span>
                        <span className="bg-green-100 text-green-800 px-2 py-1 rounded text-sm">
                          {count}
                        </span>
                      </div>
                    ))}
                </div>
              </div>
            </div>
          </div>
        )}

        {!analysisData && !loading && (
          <div className="text-center py-12">
            <FileText className="w-16 h-16 text-gray-400 mx-auto mb-4" />
            <p className="text-gray-500 text-lg">
              Upload a PCAP file to begin analysis
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
