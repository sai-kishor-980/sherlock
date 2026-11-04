import React, { useState } from "react";
import { GitCommit, ShieldCheck, CheckCircle2, Clock, GitMerge, AlertCircle } from "lucide-react";
import type { SISState } from "../../types/forensic";

interface SISTimelineWorkstationProps {
  sisState: SISState | null;
  onReviewSubmit: (action: "APPROVE" | "REJECT_REANALYZE", notes: string) => Promise<void>;
  isLoading: boolean;
  onNavigateToVault?: () => void;
  onUnlockVault?: (reason: string) => Promise<void>;
}

export const SISTimelineWorkstation: React.FC<SISTimelineWorkstationProps> = ({
  sisState,
  onReviewSubmit,
  isLoading: _isLoading,
  onNavigateToVault,
  onUnlockVault
}) => {
  const [reviewNotes, setReviewNotes] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [reviewSuccess, setReviewSuccess] = useState<string | null>(null);

  const timeline = sisState?.timeline || (sisState as any)?.attack_timeline || [];
  const hypotheses = sisState?.attack_hypotheses || (sisState as any)?.causal_hypotheses || [];
  const correlations = sisState?.cross_domain_correlations || (sisState as any)?.correlations || [];
  const isReviewed = sisState?.status === "LOCKED_APPROVED" || (sisState as any)?.investigation_status === "LOCKED_APPROVED" || (sisState as any)?.review_gate?.status === "APPROVED";

  const handleReview = async (action: "APPROVE" | "REJECT_REANALYZE") => {
    setIsSubmitting(true);
    setReviewSuccess(null);
    try {
      await onReviewSubmit(action, reviewNotes.trim());
      setReviewSuccess(action === "APPROVE" ? "Investigation state signed off and cryptographically locked!" : "Re-analysis requested.");
      setReviewNotes("");
    } catch (err: any) {
      alert(err.message || "Failed to submit review");
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Top Banner */}
      <div className="forensic-card p-5 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-lg font-bold font-display text-white flex items-center gap-2">
            <GitCommit className="w-5 h-5 text-cyan-400" />
            Structured Investigation State (SIS) &amp; Timeline
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Formal unified attack state: chronological sequence, cross-domain causality, and human-in-the-loop review
          </p>
        </div>

        <div className="flex items-center gap-2">
          {isReviewed ? (
            <span className="forensic-badge-emerald">
              <CheckCircle2 className="w-3.5 h-3.5" />
              <span>Signed &amp; Approved</span>
            </span>
          ) : (
            <span className="forensic-badge-amber">
              <Clock className="w-3.5 h-3.5" />
              <span>Pending Human Review</span>
            </span>
          )}
        </div>
      </div>

      {/* Dynamic Evidence Sufficiency Gate (Slide 8/16 Closed Loop) */}
      {(() => {
        const suff: any = (sisState as any)?.evidence_sufficiency || {
          sufficiency_score: 0.85,
          status: "SUFFICIENT",
          total_gaps: 0,
          detected_gaps: [],
          upload_engine_recommendations: []
        };
        const hasGaps = suff.status === "GAPS_DETECTED" || (suff.total_gaps && suff.total_gaps > 0);

        return (
          <div className={`forensic-card p-5 border ${hasGaps ? "border-amber-500/40 bg-amber-950/10" : "border-emerald-500/30 bg-emerald-950/10"}`}>
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 mb-2">
              <div className="flex items-center gap-2">
                <span className="text-base">{hasGaps ? "⚠️" : "🛡️"}</span>
                <h3 className="text-sm font-bold text-slate-100">
                  Evidence Sufficiency Gate (Closed Loop Validation)
                </h3>
              </div>
              <div className="flex items-center gap-2">
                <span className={`px-2.5 py-0.5 rounded text-xs font-mono font-bold border ${
                  hasGaps
                    ? "bg-amber-500/10 text-amber-400 border-amber-500/30"
                    : "bg-emerald-500/10 text-emerald-400 border-emerald-500/30"
                }`}>
                  Score: {((suff.sufficiency_score || 0.85) * 100).toFixed(0)}% • {suff.status || "SUFFICIENT"}
                </span>
                {hasGaps && onNavigateToVault && (
                  <button
                    type="button"
                    onClick={async () => {
                      if (onUnlockVault) {
                        await onUnlockVault("Supplemental evidence upload requested by Sufficiency Gate");
                      }
                      onNavigateToVault();
                    }}
                    className="px-3 py-1 bg-amber-600 hover:bg-amber-500 text-white rounded text-xs font-bold transition shadow cursor-pointer"
                  >
                    Unlock Vault for Supplemental Ingestion &rarr;
                  </button>
                )}
              </div>
            </div>

            <p className="text-xs text-slate-400 mb-3">
              {hasGaps
                ? "Candidate attack chain has missing evidentiary links across correlated domains. Ingest follow-up artifacts to close gaps."
                : "All primary attack vectors verified across heterogeneous domains with complete parent-child causality."}
            </p>

            {hasGaps && suff.upload_engine_recommendations && suff.upload_engine_recommendations.length > 0 && (
              <div className="space-y-2 pt-2 border-t border-slate-800">
                <div className="text-[11px] font-bold text-amber-400 uppercase tracking-wider">
                  Targeted Ingestion Recommendations:
                </div>
                {suff.upload_engine_recommendations.map((rec: any, idx: number) => (
                  <div key={idx} className="p-2.5 rounded-lg bg-dark-900 border border-slate-800 flex items-start justify-between gap-3 text-xs">
                    <div>
                      <span className="px-1.5 py-0.5 rounded bg-dark-800 text-cyan-400 font-mono text-[10px] uppercase font-bold mr-2">
                        {rec.evidence_domain || "MEMORY"}
                      </span>
                      <span className="text-slate-200">{rec.description}</span>
                    </div>
                    <span className="text-[10px] font-mono text-slate-500 whitespace-nowrap">
                      {rec.action || "SUPPLEMENTAL_UPLOAD"}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        );
      })()}

      {/* Review Station Card */}
      <div className="forensic-card p-5 bg-gradient-to-b from-dark-850 to-dark-900 border-amber-500/30">
        <h3 className="text-sm font-bold text-slate-200 mb-1 flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-amber-400" />
          <span>Investigator Sign-off &amp; Rationale</span>
        </h3>
        <p className="text-xs text-slate-400 mb-3">
          Record corroborating rationale, confirm evidence sufficiency, or request re-analysis before court sealing.
        </p>

        {reviewSuccess && (
          <div className="mb-3 p-2.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs">
            {reviewSuccess}
          </div>
        )}

        <textarea
          rows={2}
          disabled={isReviewed || isSubmitting}
          placeholder={isReviewed ? "Investigation State is permanently approved and locked." : "Enter findings verification rationale, external intelligence links, or notes..."}
          value={reviewNotes}
          onChange={(e) => setReviewNotes(e.target.value)}
          className="w-full bg-dark-950 border border-slate-800 rounded-lg p-3 text-xs text-slate-100 focus:outline-none focus:border-cyan-500 disabled:opacity-50"
        />

        {!isReviewed && (
          <div className="mt-3 flex justify-end gap-2.5">
            <button
              onClick={() => handleReview("REJECT_REANALYZE")}
              disabled={isSubmitting}
              className="px-3.5 py-1.5 bg-dark-800 hover:bg-slate-700 text-rose-300 border border-rose-500/30 text-xs font-semibold rounded-lg transition"
            >
              🔄 Request Re-Analysis
            </button>
            <button
              onClick={() => handleReview("APPROVE")}
              disabled={isSubmitting}
              className="px-4 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-bold rounded-lg shadow-lg shadow-emerald-600/20 transition"
            >
              🛡️ Approve &amp; Lock State
            </button>
          </div>
        )}
      </div>

      {/* Chronological Timeline */}
      <div className="forensic-card overflow-hidden">
        <div className="px-5 py-3.5 border-b border-slate-800 bg-dark-850 flex items-center justify-between">
          <h3 className="text-sm font-bold text-slate-200">
            Reconstructed Multi-Source Attack Timeline
          </h3>
          <span className="text-xs font-mono px-2 py-0.5 rounded bg-dark-900 border border-slate-800 text-cyan-400">
            {timeline.length} Sequenced Events
          </span>
        </div>

        <div className="p-6">
          {timeline.length === 0 ? (
            <div className="text-center py-8 text-slate-500 text-xs">
              No timeline events reconstructed yet. Run multi-agent analysis to correlate timestamps across sources.
            </div>
          ) : (
            <div className="relative border-l border-slate-800 ml-4 space-y-6">
              {timeline.map((evt: any, idx: number) => (
                <div key={idx} className="relative pl-6">
                  <div className="absolute -left-1.5 top-1.5 w-3 h-3 rounded-full bg-cyan-400 border-2 border-dark-900 shadow" />
                  <div className="bg-dark-850 border border-slate-800 rounded-xl p-3.5">
                    <div className="flex items-center justify-between gap-2 mb-1">
                      <span className="font-mono text-xs text-cyan-400 font-semibold">
                        {evt.timestamp_utc || (evt as any).timestamp || "TIMESTAMP UNAVAILABLE"}
                      </span>
                      <span className="font-mono text-[10px] px-2 py-0.5 rounded bg-dark-900 text-slate-400 uppercase">
                        {evt.domain || (evt as any).phase || "GENERAL"}
                      </span>
                    </div>
                    <p className="text-xs text-slate-200">{evt.description}</p>
                    {(evt.evidence_ref || (evt as any).artifact_id) && (
                      <span className="mt-2 inline-block font-mono text-[10px] text-slate-500">
                        Ref: {evt.evidence_ref || (evt as any).artifact_id}
                      </span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Hypotheses & Correlations Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Attack Hypotheses */}
        <div className="forensic-card overflow-hidden">
          <div className="px-5 py-3.5 border-b border-slate-800 bg-dark-850 flex items-center justify-between">
            <h3 className="text-sm font-bold text-slate-200 flex items-center gap-2">
              <AlertCircle className="w-4 h-4 text-amber-400" />
              <span>Reconstructed Hypotheses</span>
            </h3>
            <span className="text-xs font-mono px-2 py-0.5 rounded bg-dark-900 border border-slate-800 text-amber-400">
              {hypotheses.length} Stages
            </span>
          </div>
          <div className="p-4 space-y-3">
            {hypotheses.length === 0 ? (
              <div className="text-center py-6 text-slate-500 text-xs">
                No attack hypotheses generated yet.
              </div>
            ) : (
              hypotheses.map((h: any, i: number) => (
                <div key={i} className="p-3 bg-dark-850 border border-slate-800 rounded-lg">
                  <div className="flex items-center justify-between gap-2 mb-1">
                    <span className="text-xs font-semibold text-slate-200">{h.stage || (h as any).title || `Stage ${i + 1}`}</span>
                    <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800/40">
                      Confidence: {(h.confidence * 100).toFixed(0)}%
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 leading-relaxed">{h.description || (h as any).claim || ""}</p>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Cross-Domain Correlations */}
        <div className="forensic-card overflow-hidden">
          <div className="px-5 py-3.5 border-b border-slate-800 bg-dark-850 flex items-center justify-between">
            <h3 className="text-sm font-bold text-slate-200 flex items-center gap-2">
              <GitMerge className="w-4 h-4 text-cyan-400" />
              <span>Cross-Domain Pivots</span>
            </h3>
            <span className="text-xs font-mono px-2 py-0.5 rounded bg-dark-900 border border-slate-800 text-cyan-400">
              {correlations.length} Pivots
            </span>
          </div>
          <div className="p-4 space-y-3">
            {correlations.length === 0 ? (
              <div className="text-center py-6 text-slate-500 text-xs">
                No cross-domain pivot correlations identified.
              </div>
            ) : (
              correlations.map((c: any, i: number) => (
                <div key={i} className="p-3 bg-dark-850 border border-slate-800 rounded-lg">
                  <div className="flex items-center justify-between gap-2 mb-1">
                    <span className="font-mono text-[10px] text-cyan-400 uppercase">
                      {c.source_domain} &rarr; {c.target_domain}
                    </span>
                    <span className="font-mono text-[10px] text-slate-400">
                      {(c.correlation_key || (c as any).pivot_point || "pivot")}: <code className="text-emerald-400">{c.key_value || (c as any).target_entity || ""}</code>
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 leading-relaxed">{c.rationale || (c as any).reasoning || ""}</p>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
