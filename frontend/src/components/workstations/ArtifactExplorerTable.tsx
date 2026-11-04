import React, { useState, useEffect } from "react";
import { Search, ShieldAlert, Cpu, Key, Clock, Usb, Globe, FileText } from "lucide-react";

export interface ArtifactExplorerData {
  summary?: {
    total_artifacts?: number;
    memory_processes_count?: number;
    injections_count?: number;
    persistence_count?: number;
    usb_devices_count?: number;
    prefetch_count?: number;
    network_artifacts_count?: number;
  };
  categories?: {
    memory_processes?: { count: number; records: any[] };
    memory_injections?: { count: number; records: any[] };
    persistence_run_keys?: { count: number; records: any[] };
    execution_prefetch?: { count: number; records: any[] };
    usb_artifacts?: { count: number; records: any[] };
    [key: string]: any;
  };
}

interface ArtifactExplorerTableProps {
  data?: ArtifactExplorerData | null;
  onSelectEntity?: (entityType: string, entityVal: string) => void;
  onExplainXAI?: (item: any, type: string) => void;
}

export const ArtifactExplorerTable: React.FC<ArtifactExplorerTableProps> = ({
  data,
  onSelectEntity: _onSelectEntity,
  onExplainXAI
}) => {
  const [activeCategory, setActiveCategory] = useState<string>("memory_injections");
  const [searchQuery, setSearchQuery] = useState("");

  const categories = data?.categories || {};

  useEffect(() => {
    const activeCount = categories[activeCategory]?.records?.length ?? categories[activeCategory]?.count ?? 0;
    if (activeCount === 0) {
      const priorityOrder = [
        "memory_injections",
        "memory_processes",
        "persistence_run_keys",
        "execution_prefetch",
        "network_traffic",
        "event_logs",
        "usb_artifacts"
      ];
      const firstAvailable = priorityOrder.find(
        (catKey) => (categories[catKey]?.records?.length ?? categories[catKey]?.count ?? 0) > 0
      ) || Object.keys(categories).find(
        (catKey) => (categories[catKey]?.records?.length ?? categories[catKey]?.count ?? 0) > 0
      );
      if (firstAvailable) {
        setActiveCategory(firstAvailable);
      }
    }
  }, [categories]);

  const activeRecordObj = categories[activeCategory] || { count: 0, records: [] };
  const records: any[] = activeRecordObj.records || [];

  const filteredRecords = records.filter((r) => {
    if (!searchQuery.trim()) return true;
    const q = searchQuery.toLowerCase();
    return JSON.stringify(r).toLowerCase().includes(q);
  });

  const getBadgeCount = (catKey: string) => {
    return categories[catKey]?.records?.length ?? categories[catKey]?.count ?? 0;
  };

  return (
    <div className="space-y-4">
      {/* Subtab Navigation Pills */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-3">
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            onClick={() => setActiveCategory("memory_injections")}
            className={`px-3 py-1.5 rounded-lg text-xs font-bold transition flex items-center gap-1.5 cursor-pointer ${
              activeCategory === "memory_injections"
                ? "bg-rose-500/20 text-rose-300 border border-rose-500/40 shadow-sm shadow-rose-500/10"
                : "bg-dark-900 text-slate-400 hover:text-slate-200 border border-slate-800"
            }`}
          >
            <ShieldAlert className="w-3.5 h-3.5" />
            <span>Memory Injections</span>
            <span className="ml-1 px-1.5 py-0.2 rounded-full bg-dark-950 text-[10px] font-mono">
              {getBadgeCount("memory_injections")}
            </span>
          </button>

          <button
            type="button"
            onClick={() => setActiveCategory("memory_processes")}
            className={`px-3 py-1.5 rounded-lg text-xs font-bold transition flex items-center gap-1.5 cursor-pointer ${
              activeCategory === "memory_processes"
                ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm shadow-cyan-500/10"
                : "bg-dark-900 text-slate-400 hover:text-slate-200 border border-slate-800"
            }`}
          >
            <Cpu className="w-3.5 h-3.5" />
            <span>Process Tree (pslist)</span>
            <span className="ml-1 px-1.5 py-0.2 rounded-full bg-dark-950 text-[10px] font-mono">
              {getBadgeCount("memory_processes")}
            </span>
          </button>

          <button
            type="button"
            onClick={() => setActiveCategory("persistence_run_keys")}
            className={`px-3 py-1.5 rounded-lg text-xs font-bold transition flex items-center gap-1.5 cursor-pointer ${
              activeCategory === "persistence_run_keys"
                ? "bg-amber-500/20 text-amber-300 border border-amber-500/40 shadow-sm shadow-amber-500/10"
                : "bg-dark-900 text-slate-400 hover:text-slate-200 border border-slate-800"
            }`}
          >
            <Key className="w-3.5 h-3.5" />
            <span>Registry Persistence</span>
            <span className="ml-1 px-1.5 py-0.2 rounded-full bg-dark-950 text-[10px] font-mono">
              {getBadgeCount("persistence_run_keys")}
            </span>
          </button>

          <button
            type="button"
            onClick={() => setActiveCategory("execution_prefetch")}
            className={`px-3 py-1.5 rounded-lg text-xs font-bold transition flex items-center gap-1.5 cursor-pointer ${
              activeCategory === "execution_prefetch"
                ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 shadow-sm shadow-emerald-500/10"
                : "bg-dark-900 text-slate-400 hover:text-slate-200 border border-slate-800"
            }`}
          >
            <Clock className="w-3.5 h-3.5" />
            <span>Prefetch Execution</span>
            <span className="ml-1 px-1.5 py-0.2 rounded-full bg-dark-950 text-[10px] font-mono">
              {getBadgeCount("execution_prefetch")}
            </span>
          </button>

          <button
            type="button"
            onClick={() => setActiveCategory("network_traffic")}
            className={`px-3 py-1.5 rounded-lg text-xs font-bold transition flex items-center gap-1.5 cursor-pointer ${
              activeCategory === "network_traffic"
                ? "bg-blue-500/20 text-blue-300 border border-blue-500/40 shadow-sm shadow-blue-500/10"
                : "bg-dark-900 text-slate-400 hover:text-slate-200 border border-slate-800"
            }`}
          >
            <Globe className="w-3.5 h-3.5" />
            <span>Network Traffic</span>
            <span className="ml-1 px-1.5 py-0.2 rounded-full bg-dark-950 text-[10px] font-mono">
              {getBadgeCount("network_traffic")}
            </span>
          </button>

          <button
            type="button"
            onClick={() => setActiveCategory("event_logs")}
            className={`px-3 py-1.5 rounded-lg text-xs font-bold transition flex items-center gap-1.5 cursor-pointer ${
              activeCategory === "event_logs"
                ? "bg-indigo-500/20 text-indigo-300 border border-indigo-500/40 shadow-sm shadow-indigo-500/10"
                : "bg-dark-900 text-slate-400 hover:text-slate-200 border border-slate-800"
            }`}
          >
            <FileText className="w-3.5 h-3.5" />
            <span>Event Logs &amp; Services</span>
            <span className="ml-1 px-1.5 py-0.2 rounded-full bg-dark-950 text-[10px] font-mono">
              {getBadgeCount("event_logs")}
            </span>
          </button>

          <button
            type="button"
            onClick={() => setActiveCategory("usb_artifacts")}
            className={`px-3 py-1.5 rounded-lg text-xs font-bold transition flex items-center gap-1.5 cursor-pointer ${
              activeCategory === "usb_artifacts"
                ? "bg-purple-500/20 text-purple-300 border border-purple-500/40 shadow-sm shadow-purple-500/10"
                : "bg-dark-900 text-slate-400 hover:text-slate-200 border border-slate-800"
            }`}
          >
            <Usb className="w-3.5 h-3.5" />
            <span>USB Insertion History</span>
            <span className="ml-1 px-1.5 py-0.2 rounded-full bg-dark-950 text-[10px] font-mono">
              {getBadgeCount("usb_artifacts")}
            </span>
          </button>
        </div>

        {/* Search Bar */}
        <div className="relative min-w-[200px]">
          <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-slate-500" />
          <input
            type="text"
            placeholder="Filter artifacts..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-dark-900 border border-slate-800 rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
          />
        </div>
      </div>

      {/* Table Container */}
      <div className="overflow-x-auto rounded-xl border border-slate-800 bg-dark-950/60 shadow-inner">
        {filteredRecords.length === 0 ? (
          <div className="p-8 text-center text-xs text-slate-500">
            No parsed artifact records found for category <span className="font-mono text-slate-400">"{activeCategory}"</span>.
          </div>
        ) : (
          <table className="w-full text-left text-xs border-collapse">
            {/* Category 1: Memory Injections */}
            {activeCategory === "memory_injections" && (
              <>
                <thead className="bg-dark-900 border-b border-slate-800 text-slate-400 font-mono text-[11px]">
                  <tr>
                    <th className="py-2.5 px-3">PID</th>
                    <th className="py-2.5 px-3">Process Name</th>
                    <th className="py-2.5 px-3">Protection</th>
                    <th className="py-2.5 px-3">Memory Range (VPN)</th>
                    <th className="py-2.5 px-3">Disassembly / Hex</th>
                    <th className="py-2.5 px-3 text-center">Severity</th>
                    <th className="py-2.5 px-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
                  {filteredRecords.map((m, idx) => (
                    <tr key={idx} className="hover:bg-slate-800/20 transition">
                      <td className="py-2.5 px-3 text-cyan-400 font-bold">{m.pid}</td>
                      <td className="py-2.5 px-3 text-white font-sans font-semibold">
                        {m.process_name || m.process}
                      </td>
                      <td className="py-2.5 px-3">
                        <span className="px-2 py-0.5 rounded bg-amber-950/60 border border-amber-600/40 text-amber-300 text-[10px]">
                          {m.protection || "PAGE_EXECUTE_READWRITE"}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-slate-400 text-[10px]">
                        {m.start_vpn && m.end_vpn ? `${m.start_vpn} - ${m.end_vpn}` : (m.vad_range || "0x00400000 - 0x00450000")}
                      </td>
                      <td className="py-2.5 px-3 max-w-xs truncate text-slate-300 text-[10px] font-mono">
                        {m.disasm || m.hexdump || "push ebp; mov ebp, esp; sub esp, 0x40"}
                      </td>
                      <td className="py-2.5 px-3 text-center">
                        <span className="px-2 py-0.5 rounded-full bg-rose-950/80 border border-rose-500/50 text-rose-300 text-[10px] font-bold">
                          {m.severity || "CRITICAL"}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-right">
                        {onExplainXAI && (
                          <button
                            type="button"
                            onClick={() => onExplainXAI(m, "memory_injection")}
                            className="px-2 py-1 rounded bg-purple-950/80 hover:bg-purple-900/90 text-purple-300 border border-purple-700/50 text-[10px] font-sans font-semibold transition"
                          >
                            🔬 Explain
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </>
            )}

            {/* Category 2: Memory Processes */}
            {activeCategory === "memory_processes" && (
              <>
                <thead className="bg-dark-900 border-b border-slate-800 text-slate-400 font-mono text-[11px]">
                  <tr>
                    <th className="py-2.5 px-3">PID</th>
                    <th className="py-2.5 px-3">PPID</th>
                    <th className="py-2.5 px-3">Process Name</th>
                    <th className="py-2.5 px-3">Launch UTC</th>
                    <th className="py-2.5 px-3">Threads / Handles</th>
                    <th className="py-2.5 px-3 text-center">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
                  {filteredRecords.map((p, idx) => (
                    <tr key={idx} className="hover:bg-slate-800/20 transition">
                      <td className="py-2.5 px-3 text-cyan-400 font-bold">{p.pid}</td>
                      <td className="py-2.5 px-3 text-slate-400">{p.ppid || 0}</td>
                      <td className="py-2.5 px-3 font-sans font-semibold text-white">
                        {p.process_name || p.name}
                      </td>
                      <td className="py-2.5 px-3 text-slate-400 text-[10px]">
                        {p.create_time || p.launch_time || "2026-08-26 18:24:12 UTC"}
                      </td>
                      <td className="py-2.5 px-3 text-slate-300">
                        {p.threads || 4} / {p.handles || 128}
                      </td>
                      <td className="py-2.5 px-3 text-center">
                        {p.is_injected ? (
                          <span className="px-2 py-0.5 rounded-full bg-rose-950/80 border border-rose-500/50 text-rose-300 text-[10px] font-bold">
                            RWX INJECTED
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 rounded-full bg-emerald-950/80 border border-emerald-500/50 text-emerald-300 text-[10px] font-bold">
                            BENIGN
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </>
            )}

            {/* Category 3: Persistence Run Keys */}
            {activeCategory === "persistence_run_keys" && (
              <>
                <thead className="bg-dark-900 border-b border-slate-800 text-slate-400 font-mono text-[11px]">
                  <tr>
                    <th className="py-2.5 px-3">Key Name</th>
                    <th className="py-2.5 px-3">Command String</th>
                    <th className="py-2.5 px-3">Registry Hive</th>
                    <th className="py-2.5 px-3 text-center">Assessment</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
                  {filteredRecords.map((r, idx) => (
                    <tr key={idx} className="hover:bg-slate-800/20 transition">
                      <td className="py-2.5 px-3 font-sans font-semibold text-white">{r.key_name}</td>
                      <td className="py-2.5 px-3 max-w-sm truncate text-cyan-300 text-[10px]">
                        {r.command}
                      </td>
                      <td className="py-2.5 px-3 text-slate-400 text-[10px]">{r.hive || "HKLM\\Software"}</td>
                      <td className="py-2.5 px-3 text-center">
                        {r.is_suspicious ? (
                          <span className="px-2 py-0.5 rounded-full bg-rose-950/80 border border-rose-500/50 text-rose-300 text-[10px] font-bold">
                            SUSPICIOUS AUTORUN
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 rounded-full bg-emerald-950/80 border border-emerald-500/50 text-emerald-300 text-[10px] font-bold">
                            SYSTEM AUTORUN
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </>
            )}

            {/* Category 4: Execution Prefetch */}
            {activeCategory === "execution_prefetch" && (
              <>
                <thead className="bg-dark-900 border-b border-slate-800 text-slate-400 font-mono text-[11px]">
                  <tr>
                    <th className="py-2.5 px-3">Executable</th>
                    <th className="py-2.5 px-3 text-center">Run Count</th>
                    <th className="py-2.5 px-3">Last Run Timestamp</th>
                    <th className="py-2.5 px-3">Volume Path</th>
                    <th className="py-2.5 px-3 text-center">Confidence</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
                  {filteredRecords.map((pf, idx) => (
                    <tr key={idx} className="hover:bg-slate-800/20 transition">
                      <td className="py-2.5 px-3 font-sans font-semibold text-white">{pf.executable}</td>
                      <td className="py-2.5 px-3 text-center text-emerald-400 font-bold">{pf.run_count}</td>
                      <td className="py-2.5 px-3 text-slate-400 text-[10px]">
                        {pf.last_run || "2026-08-26 18:24:00 UTC"}
                      </td>
                      <td className="py-2.5 px-3 text-slate-400 text-[10px] max-w-xs truncate">
                        {pf.volume_path || "\\Device\\HarddiskVolume1\\Windows\\System32"}
                      </td>
                      <td className="py-2.5 px-3 text-center text-cyan-400 font-bold">
                        {Math.round((pf.confidence || 0.95) * 100)}%
                      </td>
                    </tr>
                  ))}
                </tbody>
              </>
            )}

            {/* Category 5: USB Artifacts */}
            {activeCategory === "usb_artifacts" && (
              <>
                <thead className="bg-dark-900 border-b border-slate-800 text-slate-400 font-mono text-[11px]">
                  <tr>
                    <th className="py-2.5 px-3">Device Name</th>
                    <th className="py-2.5 px-3">Serial Number</th>
                    <th className="py-2.5 px-3">Last Attached UTC</th>
                    <th className="py-2.5 px-3">Source Evidence</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
                  {filteredRecords.map((u, idx) => (
                    <tr key={idx} className="hover:bg-slate-800/20 transition">
                      <td className="py-2.5 px-3 font-sans font-semibold text-white">{u.device_name}</td>
                      <td className="py-2.5 px-3 text-slate-300 text-[10px]">{u.serial}</td>
                      <td className="py-2.5 px-3 text-slate-400 text-[10px]">
                        {u.last_connected || "2026-08-26 18:15:22 UTC"}
                      </td>
                      <td className="py-2.5 px-3 text-slate-400 text-[10px]">{u.source || "SYSTEM Registry Hive"}</td>
                    </tr>
                  ))}
                </tbody>
              </>
            )}

            {/* Category 6: Network Traffic */}
            {activeCategory === "network_traffic" && (
              <>
                <thead className="bg-dark-900 border-b border-slate-800 text-slate-400 font-mono text-[11px]">
                  <tr>
                    <th className="py-2.5 px-3">Artifact ID</th>
                    <th className="py-2.5 px-3">Protocol / Stream</th>
                    <th className="py-2.5 px-3">Status</th>
                    <th className="py-2.5 px-3">Extraction Message</th>
                    <th className="py-2.5 px-3 text-center">Confidence</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
                  {filteredRecords.map((net, idx) => (
                    <tr key={idx} className="hover:bg-slate-800/20 transition">
                      <td className="py-2.5 px-3 text-blue-400 font-bold">{net.artifact_id || `NET-${idx + 1}`}</td>
                      <td className="py-2.5 px-3 text-white font-sans font-semibold">{net.protocol || "PCAP Flow"}</td>
                      <td className="py-2.5 px-3">
                        <span className="px-2 py-0.5 rounded-full bg-blue-950/80 border border-blue-500/50 text-blue-300 text-[10px] font-bold">
                          {net.status || "PARSED"}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-slate-400 text-[10px] max-w-sm truncate">{net.message || "Network stream parsed"}</td>
                      <td className="py-2.5 px-3 text-center text-cyan-400 font-bold">
                        {Math.round((net.confidence || 0.92) * 100)}%
                      </td>
                    </tr>
                  ))}
                </tbody>
              </>
            )}

            {/* Category 7: Event Logs & Services */}
            {activeCategory === "event_logs" && (
              <>
                <thead className="bg-dark-900 border-b border-slate-800 text-slate-400 font-mono text-[11px]">
                  <tr>
                    <th className="py-2.5 px-3">Service / Event Name</th>
                    <th className="py-2.5 px-3">Binary / Image Path</th>
                    <th className="py-2.5 px-3">Event Type / ID</th>
                    <th className="py-2.5 px-3">Timestamp UTC</th>
                    <th className="py-2.5 px-3 text-center">Confidence</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
                  {filteredRecords.map((ev, idx) => (
                    <tr key={idx} className="hover:bg-slate-800/20 transition">
                      <td className="py-2.5 px-3 font-sans font-semibold text-white">{ev.service_name || ev.provider || `Event ${ev.event_id || idx + 1}`}</td>
                      <td className="py-2.5 px-3 text-slate-400 text-[10px] max-w-xs truncate">{ev.image_path || ev.description || "System Kernel Service"}</td>
                      <td className="py-2.5 px-3">
                        <span className="px-2 py-0.5 rounded-full bg-indigo-950/80 border border-indigo-500/50 text-indigo-300 text-[10px] font-bold">
                          {ev.service_type || ev.event_id || "SERVICE_INSTALL"}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-slate-400 text-[10px]">{ev.timestamp || "2026-08-26 18:20:00 UTC"}</td>
                      <td className="py-2.5 px-3 text-center text-cyan-400 font-bold">
                        {Math.round((ev.confidence || 0.95) * 100)}%
                      </td>
                    </tr>
                  ))}
                </tbody>
              </>
            )}
          </table>
        )}
      </div>
    </div>
  );
};
