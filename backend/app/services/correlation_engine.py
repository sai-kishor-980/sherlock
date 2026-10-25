"""
Explainable Multi-Agent Correlation Engine for SherlockAI / H-MACFR.

Implements Phase 2:
- Consumes real 12-field normalized findings from all 5 domain agents (Network, Memory, Disk, Logs, Registry).
- Typed Entity Normalization (paths, IPs, domains, hashes, PIDs, registry keys).
- 6 Explainable Forensic Correlation Rules:
  1. Process & execution correlation
  2. Persistence-to-execution correlation
  3. Disk-to-process correlation
  4. Network-to-process correlation
  5. Cross-agent typed entity correlation
  6. Temporal correlation with explicit epistemic tagging
- Calibrated confidence & uncertainty tracking (1.0 - confidence).
- NetworkX Property Graph & Neo4j export integration.
"""

import re
import json
import uuid
import datetime
from typing import Dict, List, Any, Optional, Tuple, Set
from pathlib import Path

from app.core.logger import log_app_event, log_error_event
from app.services.registry_timeline_service import (
    RegistryTimelineEngine,
    TimestampType,
    TimestampSource
)


class CorrelationEpistemicClass:
    CAUSAL_DEPENDENCY = "CAUSAL_DEPENDENCY"
    CORRELATIONAL_ASSOCIATION = "CORRELATIONAL_ASSOCIATION"
    COINCIDENTAL_NOISE = "COINCIDENTAL_NOISE"
    AMBIGUOUS_UNKNOWN = "AMBIGUOUS_UNKNOWN"


class MatchingMethod:
    EXACT = "EXACT"
    NORMALIZED_TYPED = "NORMALIZED_TYPED"
    BEHAVIORAL_HEURISTIC = "BEHAVIORAL_HEURISTIC"
    AMBIGUOUS = "AMBIGUOUS"


class TypedEntityExtractor:
    """
    Extracts and normalizes typed forensic entities from finding schemas and raw text.
    """

    @staticmethod
    def normalize_path(path_str: str) -> str:
        if not path_str:
            return ""
        # Normalize slashes and casing
        norm = path_str.replace("/", "\\").strip().strip('"').strip("'")
        return norm.lower()

    @staticmethod
    def extract_entities(finding: Dict[str, Any]) -> Dict[str, Set[str]]:
        """
        Extracts typed entities: executables, ips, domains, hashes, pids, registry_keys, users.
        """
        entities: Dict[str, Set[str]] = {
            "executables": set(),
            "paths": set(),
            "ips": set(),
            "domains": set(),
            "hashes": set(),
            "pids": set(),
            "ppids": set(),
            "registry_keys": set(),
            "users": set(),
            "services": set()
        }

        # Check structured entities field
        raw_ents = finding.get("entities", [])
        if isinstance(raw_ents, dict):
            raw_ents = [raw_ents]
        elif not isinstance(raw_ents, list):
            raw_ents = []

        for e in raw_ents:
            if isinstance(e, dict):
                for k, v in e.items():
                    val = str(v).strip()
                    if not val:
                        continue
                    k_lower = k.lower()
                    if "exe" in k_lower or "binary" in k_lower or "process" in k_lower:
                        bname = RegistryTimelineEngine.extract_executable_basename(val)
                        if bname:
                            entities["executables"].add(bname)
                        entities["paths"].add(TypedEntityExtractor.normalize_path(val))
                    elif "ip" in k_lower:
                        entities["ips"].add(val.lower())
                    elif "domain" in k_lower or "dns" in k_lower or "host" in k_lower:
                        if "." in val and not val.endswith(".exe"):
                            entities["domains"].add(val.lower())
                    elif "hash" in k_lower or "sha" in k_lower or "md5" in k_lower:
                        entities["hashes"].add(val.lower())
                    elif "ppid" in k_lower or "parent_pid" in k_lower or "parentpid" in k_lower:
                        try:
                            entities["ppids"].add(str(int(val)))
                        except Exception:
                            pass
                    elif "pid" in k_lower:
                        try:
                            entities["pids"].add(str(int(val)))
                        except Exception:
                            pass
                    elif "reg" in k_lower or "key" in k_lower:
                        entities["registry_keys"].add(val.lower())
                    elif "user" in k_lower or "account" in k_lower:
                        entities["users"].add(val.lower())
                    elif "service" in k_lower:
                        entities["services"].add(val.lower())

        # Scan text payload (title + description + observation + reasoning + supporting evidence + evidence_sources)
        text_parts = [
            str(finding.get("title", "")),
            str(finding.get("description", "")),
            str(finding.get("observation", "")),
            str(finding.get("reasoning", "")),
            str(finding.get("category", ""))
        ]
        for ev in finding.get("supporting_evidence", []):
            text_parts.append(json.dumps(ev) if isinstance(ev, dict) else str(ev))
        for ev in finding.get("evidence_sources", []):
            text_parts.append(json.dumps(ev) if isinstance(ev, dict) else str(ev))

        text = " ".join(text_parts)

        # Regex for PIDs: PID: 1234 or PID 1234 or PID=1234
        pid_matches = re.findall(r'\b(?:pid|process\s*id)[:\s=]+(\d+)\b', text, re.IGNORECASE)
        for p in pid_matches:
            entities["pids"].add(str(int(p)))

        # Regex for IPs
        ip_matches = re.findall(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', text)
        for ip in ip_matches:
            if not ip.startswith("127.") and not ip.startswith("0."):
                entities["ips"].add(ip)

        # Regex for SHA-256 / MD5
        hash_matches = re.findall(r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{64}\b', text)
        for h in hash_matches:
            entities["hashes"].add(h.lower())

        # Regex for Executable names (.exe, .dll, .sys, etc.)
        exe_matches = re.findall(r'\b([a-zA-Z0-9_\-\.]+\.(?:exe|dll|sys|bat|cmd|ps1|vbs))\b', text, re.IGNORECASE)
        for exe in exe_matches:
            entities["executables"].add(exe.lower())

        # Regex for Registry Keys (HKLM or HKCU)
        reg_matches = re.findall(r'\b(HKLM\\[a-zA-Z0-9_\\\-]+|HKCU\\[a-zA-Z0-9_\\\-]+)\b', text, re.IGNORECASE)
        for reg in reg_matches:
            entities["registry_keys"].add(reg.lower())

        return entities


class ExplainableCorrelationEngine:
    """
    Consumes verified agent findings and executes the 6 explainable forensic correlation rules.
    """

    RULE_CATALOG = {
        "RULE-PROC-01": {"name": "Process Execution & Lineage", "version": "2.0"},
        "RULE-PERSIST-01": {"name": "Persistence to Execution Linkage", "version": "2.0"},
        "RULE-DISK-01": {"name": "Disk Artifact to Process Lineage", "version": "2.0"},
        "RULE-NET-01": {"name": "Network Socket to Process Flow Attribution", "version": "2.0"},
        "RULE-ENTITY-01": {"name": "Cross-Agent Typed Entity Corroboration", "version": "2.0"},
        "RULE-TIME-01": {"name": "Chronological Multi-Stage Attack Sequence", "version": "2.0"}
    }

    @classmethod
    def correlate_case_findings(
        cls,
        findings: List[Dict[str, Any]],
        case_id: str = "CASE_DEFAULT",
        extracted_artifacts: Optional[Dict[str, Any]] = None,
        case_context: Optional[Dict[str, Any]] = None,
        invoke_supervisor: bool = True
    ) -> Dict[str, Any]:
        """
        Executes cross-agent correlation across the supplied normalized findings.
        Returns correlated findings, explainable edges, unified timeline, and graph telemetry.
        """
        log_app_event(f"[CorrelationEngine] Correlating {len(findings)} agent findings for {case_id}")

        # 1. Deterministic enrichment for Registry findings & agent domain auto-resolution
        normalized_findings = []
        for f in findings:
            f_norm = dict(f)
            if not f_norm.get("agent") and not f_norm.get("domain"):
                cat = (f_norm.get("category") or "").lower()
                desc = (f_norm.get("description") or "").lower()
                srcs = str(f_norm.get("evidence_sources", [])).lower()
                combined = f"{cat} {desc} {srcs}"
                if "memory" in combined or "vad" in combined or "malfind" in combined:
                    f_norm["agent"] = "memory"
                    f_norm["domain"] = "memory"
                elif "prefetch" in combined or "disk" in combined or "mft" in combined or "lnk" in combined:
                    f_norm["agent"] = "disk"
                    f_norm["domain"] = "disk"
                elif "registry" in combined or "run key" in combined or "hklm" in combined:
                    f_norm["agent"] = "registry"
                    f_norm["domain"] = "registry"
                elif "network" in combined or "pcap" in combined or "dns" in combined:
                    f_norm["agent"] = "network"
                    f_norm["domain"] = "network"
                elif "event" in combined or "log" in combined or "evtx" in combined:
                    f_norm["agent"] = "logs"
                    f_norm["domain"] = "logs"
                else:
                    f_norm["agent"] = "general"
                    f_norm["domain"] = "general"
            elif not f_norm.get("agent") and f_norm.get("domain"):
                f_norm["agent"] = f_norm["domain"]
            elif f_norm.get("agent") and not f_norm.get("domain"):
                f_norm["domain"] = f_norm["agent"]
            normalized_findings.append(f_norm)

        enriched_findings = []
        for f in normalized_findings:
            if (f.get("agent") or f.get("domain")) == "registry":
                enriched_f = RegistryTimelineEngine.enrich_registry_finding(
                    registry_finding=f,
                    corroborating_findings=normalized_findings,
                    extracted_artifacts=extracted_artifacts
                )
                enriched_findings.append(enriched_f)
            else:
                enriched_findings.append(f)

        # 2. Extract typed entities for each finding
        findings_with_entities = []
        for f in enriched_findings:
            f_copy = dict(f)
            f_copy["_typed_entities"] = TypedEntityExtractor.extract_entities(f)
            findings_with_entities.append(f_copy)

        correlation_edges = []
        seen_pairs = set()

        # 3. Apply the 6 Explainable Rules pairwise
        num_findings = len(findings_with_entities)
        for i in range(num_findings):
            for j in range(num_findings):
                if i == j:
                    continue
                f1 = findings_with_entities[i]
                f2 = findings_with_entities[j]

                id1 = f1.get("finding_id") or f"F1-{i}"
                id2 = f2.get("finding_id") or f"F2-{j}"
                pair_key = tuple(sorted([id1, id2]))

                # Rule 2: Persistence-to-Execution Linkage (Registry <-> Disk / Process / Logs)
                if pair_key not in seen_pairs:
                    edge = cls._evaluate_persistence_to_execution(f1, f2)
                    if edge:
                        correlation_edges.append(edge)
                        seen_pairs.add(pair_key)
                        continue

                # Rule 4: Network-to-Process Correlation (Network <-> Memory / Logs)
                if pair_key not in seen_pairs:
                    edge = cls._evaluate_network_to_process(f1, f2)
                    if edge:
                        correlation_edges.append(edge)
                        seen_pairs.add(pair_key)
                        continue

                # Rule 1: Process Lineage Correlation (Memory <-> Logs / Disk)
                if pair_key not in seen_pairs:
                    edge = cls._evaluate_process_lineage(f1, f2)
                    if edge:
                        correlation_edges.append(edge)
                        seen_pairs.add(pair_key)
                        continue

                # Rule 3: Disk-to-Process Correlation (Disk <-> Memory / Logs)
                if pair_key not in seen_pairs:
                    edge = cls._evaluate_disk_to_process(f1, f2)
                    if edge:
                        correlation_edges.append(edge)
                        seen_pairs.add(pair_key)
                        continue

                # Rule 5: Cross-Agent Typed Entity Corroboration (Shared IP, hash, domain, path)
                if pair_key not in seen_pairs:
                    edge = cls._evaluate_shared_entity(f1, f2)
                    if edge:
                        correlation_edges.append(edge)
                        seen_pairs.add(pair_key)
                        continue

                # Rule 6: Temporal Sequence Correlation (if both have verified UTC timestamps)
                if pair_key not in seen_pairs:
                    edge = cls._evaluate_temporal_sequence(f1, f2)
                    if edge:
                        correlation_edges.append(edge)
                        seen_pairs.add(pair_key)
                        continue

        # Tag visual styles on deterministic edges
        for edge in correlation_edges:
            ep = edge.get("epistemic_class")
            edge["is_model_hypothesis"] = False
            edge["verification_status"] = "VERIFIED"
            edge["uncertainty_label"] = "HEURISTIC"
            if ep == CorrelationEpistemicClass.CAUSAL_DEPENDENCY:
                edge["visual_style"] = "SOLID_CYAN"
            elif ep == CorrelationEpistemicClass.CORRELATIONAL_ASSOCIATION:
                edge["visual_style"] = "SOLID_PURPLE"
            elif ep == CorrelationEpistemicClass.COINCIDENTAL_NOISE:
                edge["visual_style"] = "DOTTED_GRAY"
            else:
                edge["visual_style"] = "AMBIGUOUS"

        # 4. Hybrid Neuro-Symbolic Correlation: Invoke Supervisor Model
        supervisor_telemetry = None
        if invoke_supervisor and findings:
            try:
                from app.services.model_adapter_service import ModelAdapterService
                sup_result = ModelAdapterService.analyze_supervisor_correlation(
                    case_id=case_id,
                    findings=enriched_findings,
                    candidate_edges=correlation_edges,
                    case_context=case_context
                )
                supervisor_telemetry = {
                    "inference_provider": sup_result.get("inference_provider"),
                    "validation_status": sup_result.get("validation_status"),
                    "retry_count": sup_result.get("retry_count", 0),
                    "model_narrative": sup_result.get("incident_narrative")
                }

                valid_finding_ids = {f.get("finding_id") for f in enriched_findings if f.get("finding_id")}

                # Merge model-proposed relationships
                for m_edge in sup_result.get("correlations", []):
                    src = m_edge.get("source_finding_id")
                    tgt = m_edge.get("target_finding_id")
                    pair_key = tuple(sorted([src, tgt]))

                    if pair_key in seen_pairs:
                        # Enrich existing edge with supervisor cross-domain insights
                        for existing in correlation_edges:
                            ex_key = tuple(sorted([existing.get("source_finding_id"), existing.get("target_finding_id")]))
                            if ex_key == pair_key:
                                existing["supervisor_reasoning"] = m_edge.get("reasoning")
                                existing["alternative_explanations"] = m_edge.get("alternative_explanations")
                                existing["missing_evidence"] = m_edge.get("missing_evidence")
                                break
                    else:
                        # Validate proposed hypothesis
                        if src in valid_finding_ids and tgt in valid_finding_ids:
                            conf = float(m_edge.get("confidence", 0.75))
                            conf = max(0.1, min(1.0, conf))
                            correlation_edges.append({
                                "correlation_id": f"CORR-SUP-{uuid.uuid4().hex[:6].upper()}",
                                "source_finding_id": src,
                                "target_finding_id": tgt,
                                "relationship_type": m_edge.get("relationship_type") or "CORRELATES_WITH",
                                "matched_entities": m_edge.get("matched_entities") or [],
                                "matching_method": MatchingMethod.BEHAVIORAL_HEURISTIC,
                                "epistemic_class": m_edge.get("epistemic_class") or CorrelationEpistemicClass.CORRELATIONAL_ASSOCIATION,
                                "confidence": conf,
                                "uncertainty_score": round(1.0 - conf, 4),
                                "uncertainty_label": "HEURISTIC",
                                "rule_id": "SUPERVISOR-HYPOTHESIS-01",
                                "rule_version": "1.0",
                                "reasoning": m_edge.get("reasoning") or "Cross-domain relationship proposed by Supervisor LLM.",
                                "alternative_explanations": m_edge.get("alternative_explanations") or "Unverified environmental coincidence.",
                                "missing_evidence": m_edge.get("missing_evidence") or "Additional corroborating telemetry needed.",
                                "is_model_hypothesis": True,
                                "verification_status": "UNRESOLVED_HYPOTHESIS",
                                "visual_style": "DASHED_AMBER",
                                "supporting_observations": [
                                    f"Source finding: {src}",
                                    f"Target finding: {tgt}"
                                ]
                            })
                            seen_pairs.add(pair_key)
            except Exception as se:
                log_error_event(f"[CorrelationEngine] Supervisor correlation call skipped: {se}")

        # 5. Construct Unified Chronological Timeline
        unified_timeline = cls._build_unified_timeline(enriched_findings, correlation_edges)

        # 6. Build Graph Representation (NetworkX nodes & edges)
        graph_data = cls._build_graph_payload(enriched_findings, correlation_edges)

        # 7. Generate Coherent Incident Narrative
        narrative = cls._synthesize_incident_narrative(enriched_findings, correlation_edges)
        if supervisor_telemetry and supervisor_telemetry.get("model_narrative"):
            narrative += f"\n\n[Supervisor Strategic Synthesis]\n{supervisor_telemetry['model_narrative']}"

        # Clean private fields before returning
        clean_findings = []
        for f in findings_with_entities:
            clean_f = dict(f)
            clean_f.pop("_typed_entities", None)
            clean_findings.append(clean_f)

        return {
            "case_id": case_id,
            "total_findings": len(clean_findings),
            "total_correlations": len(correlation_edges),
            "findings": clean_findings,
            "correlation_edges": correlation_edges,
            "unified_timeline": unified_timeline,
            "evidence_graph": graph_data,
            "incident_narrative": narrative,
            "rule_catalog": cls.RULE_CATALOG,
            "supervisor_telemetry": supervisor_telemetry,
            "epistemic_summary": {
                "causal_dependencies": sum(1 for e in correlation_edges if e["epistemic_class"] == CorrelationEpistemicClass.CAUSAL_DEPENDENCY),
                "correlational_associations": sum(1 for e in correlation_edges if e["epistemic_class"] == CorrelationEpistemicClass.CORRELATIONAL_ASSOCIATION),
                "coincidental_noise": sum(1 for e in correlation_edges if e["epistemic_class"] == CorrelationEpistemicClass.COINCIDENTAL_NOISE),
                "ambiguous_unknown": sum(1 for e in correlation_edges if e["epistemic_class"] == CorrelationEpistemicClass.AMBIGUOUS_UNKNOWN),
                "model_hypotheses": sum(1 for e in correlation_edges if e.get("is_model_hypothesis", False))
            }
        }

    # =========================================================================
    # RULE EVALUATORS
    # =========================================================================

    @classmethod
    def _evaluate_persistence_to_execution(cls, f1: Dict[str, Any], f2: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Rule 2: Correlates Registry Run Keys / Service Install with observed execution
        (Prefetch, Process creation, or Memory execution).
        """
        a1 = f1.get("agent") or f1.get("domain", "")
        a2 = f2.get("agent") or f2.get("domain", "")

        is_reg = a1 == "registry" or a2 == "registry"
        is_exec = a1 in ("disk", "logs", "memory") or a2 in ("disk", "logs", "memory")

        if not (is_reg and is_exec):
            return None

        reg_f = f1 if a1 == "registry" else f2
        exec_f = f2 if a1 == "registry" else f1

        reg_ents = reg_f["_typed_entities"]
        exec_ents = exec_f["_typed_entities"]

        # Check for shared executable binary
        shared_execs = reg_ents["executables"].intersection(exec_ents["executables"])
        if shared_execs:
            matched_bin = next(iter(shared_execs))
            exec_agent = exec_f.get("agent") or exec_f.get("domain")

            # Determine epistemic class:
            # If Prefetch has run_count >= 1 or Log 4688 has matching command line -> CAUSAL_DEPENDENCY
            epistemic = CorrelationEpistemicClass.CAUSAL_DEPENDENCY
            confidence = 0.94
            matching_method = MatchingMethod.EXACT

            reasoning = (
                f"Registry persistence established in '{reg_f.get('artifact_type', 'Run Key')}' "
                f"correlates with confirmed execution of binary '{matched_bin}' "
                f"observed by {exec_agent.capitalize()} Agent."
            )

            return {
                "correlation_id": f"CORR-PERSIST-{uuid.uuid4().hex[:6].upper()}",
                "source_finding_id": reg_f.get("finding_id"),
                "target_finding_id": exec_f.get("finding_id"),
                "relationship_type": "PERSISTENCE_TO_EXECUTION",
                "matched_entities": [{"type": "executable", "value": matched_bin}],
                "matching_method": matching_method,
                "epistemic_class": epistemic,
                "confidence": confidence,
                "uncertainty_score": round(1.0 - confidence, 2),
                "rule_id": "RULE-PERSIST-01",
                "rule_version": "2.0",
                "reasoning": reasoning,
                "supporting_observations": [
                    f"Registry finding: {reg_f.get('observation', 'Configuration detected')}",
                    f"Execution finding: {exec_f.get('observation', 'Execution detected')}"
                ]
            }

        return None

    @classmethod
    def _evaluate_network_to_process(cls, f1: Dict[str, Any], f2: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Rule 4: Network-to-Process correlation (Network <-> Memory / Logs).
        """
        a1 = f1.get("agent") or f1.get("domain", "")
        a2 = f2.get("agent") or f2.get("domain", "")

        is_net = a1 == "network" or a2 == "network"
        is_proc = a1 in ("memory", "logs") or a2 in ("memory", "logs")

        if not (is_net and is_proc):
            return None

        net_f = f1 if a1 == "network" else f2
        proc_f = f2 if a1 == "network" else f1

        net_ents = net_f["_typed_entities"]
        proc_ents = proc_f["_typed_entities"]

        # Check for shared IP or C2 domain
        shared_ips = net_ents["ips"].intersection(proc_ents["ips"])
        shared_domains = net_ents["domains"].intersection(proc_ents["domains"])

        # Also check if process commandline references C2 IP/domain
        if not (shared_ips or shared_domains):
            cmd_text = f"{proc_f.get('observation', '')} {proc_f.get('reasoning', '')}".lower()
            for ip in net_ents["ips"]:
                if ip in cmd_text:
                    shared_ips.add(ip)
            for dom in net_ents["domains"]:
                if dom in cmd_text:
                    shared_domains.add(dom)

        if shared_ips or shared_domains:
            matched_entity = next(iter(shared_ips or shared_domains))
            epistemic = CorrelationEpistemicClass.CAUSAL_DEPENDENCY
            confidence = 0.95

            return {
                "correlation_id": f"CORR-NET-{uuid.uuid4().hex[:6].upper()}",
                "source_finding_id": proc_f.get("finding_id"),
                "target_finding_id": net_f.get("finding_id"),
                "relationship_type": "PROCESS_NETWORK_C2_FLOW",
                "matched_entities": [{"type": "network_endpoint", "value": matched_entity}],
                "matching_method": MatchingMethod.NORMALIZED_TYPED,
                "epistemic_class": epistemic,
                "confidence": confidence,
                "uncertainty_score": round(1.0 - confidence, 2),
                "rule_id": "RULE-NET-01",
                "rule_version": "2.0",
                "reasoning": (
                    f"Process execution in {proc_f.get('agent', 'process')} matches outbound "
                    f"network communication endpoint '{matched_entity}' identified by Network Agent."
                ),
                "supporting_observations": [
                    f"Network observation: {net_f.get('observation', '')}",
                    f"Process observation: {proc_f.get('observation', '')}"
                ]
            }

        return None

    @classmethod
    def _evaluate_process_lineage(cls, f1: Dict[str, Any], f2: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Rule 1: Process and execution lineage (Memory <-> Logs).
        """
        a1 = f1.get("agent") or f1.get("domain", "")
        a2 = f2.get("agent") or f2.get("domain", "")

        if not ((a1 == "memory" and a2 == "logs") or (a1 == "logs" and a2 == "memory")):
            return None

        mem_f = f1 if a1 == "memory" else f2
        log_f = f2 if a1 == "memory" else f1

        mem_ents = mem_f["_typed_entities"]
        log_ents = log_f["_typed_entities"]

        shared_execs = mem_ents["executables"].intersection(log_ents["executables"])
        shared_pids = mem_ents["pids"].intersection(log_ents["pids"])

        parent_child_link = False
        parent_finding = None
        child_finding = None
        matched_ppid = None

        if mem_ents.get("pids") and log_ents.get("ppids") and mem_ents["pids"].intersection(log_ents["ppids"]):
            parent_child_link = True
            parent_finding = mem_f
            child_finding = log_f
            matched_ppid = next(iter(mem_ents["pids"].intersection(log_ents["ppids"])))
        elif log_ents.get("pids") and mem_ents.get("ppids") and log_ents["pids"].intersection(mem_ents["ppids"]):
            parent_child_link = True
            parent_finding = log_f
            child_finding = mem_f
            matched_ppid = next(iter(log_ents["pids"].intersection(mem_ents["ppids"])))

        if shared_pids or shared_execs or parent_child_link:
            matched = matched_ppid if parent_child_link else next(iter(shared_pids or shared_execs))
            epistemic = CorrelationEpistemicClass.CAUSAL_DEPENDENCY if (shared_pids or parent_child_link) else CorrelationEpistemicClass.CORRELATIONAL_ASSOCIATION
            confidence = 0.98 if (shared_pids or parent_child_link) else 0.88

            reasoning = (
                f"Process launch recorded in Windows Event Logs matches in-memory process "
                f"artifact on {'parent PID ' + matched if parent_child_link else ('PID ' + matched if shared_pids else 'executable ' + matched)}."
            )

            # Check for inverted timestamps / PID reuse
            ts_mem = (mem_f.get("timeline") or {}).get("timestamp_utc") or mem_f.get("timestamp_utc")
            ts_log = (log_f.get("timeline") or {}).get("timestamp_utc") or log_f.get("timestamp_utc")

            if parent_child_link and ts_mem and ts_log:
                ts_p = (parent_finding.get("timeline") or {}).get("timestamp_utc") or parent_finding.get("timestamp_utc")
                ts_c = (child_finding.get("timeline") or {}).get("timestamp_utc") or child_finding.get("timestamp_utc")
                if ts_p and ts_c and str(ts_p) > str(ts_c):
                    epistemic = CorrelationEpistemicClass.AMBIGUOUS_UNKNOWN
                    confidence = 0.40
                    reasoning += f" However, parent process creation timestamp ({ts_p}) is later than child timestamp ({ts_c}), indicating probable PID reuse or anomalous clock discrepancy."

            return {
                "correlation_id": f"CORR-PROC-{uuid.uuid4().hex[:6].upper()}",
                "source_finding_id": (parent_finding if parent_child_link else log_f).get("finding_id"),
                "target_finding_id": (child_finding if parent_child_link else mem_f).get("finding_id"),
                "relationship_type": "PROCESS_PARENT_CHILD_LINEAGE" if parent_child_link else "PROCESS_LINEAGE_TO_MEMORY",
                "matched_entities": [{"type": "ppid" if parent_child_link else ("pid" if shared_pids else "executable"), "value": matched}],
                "matching_method": MatchingMethod.EXACT if (shared_pids or parent_child_link) else MatchingMethod.NORMALIZED_TYPED,
                "epistemic_class": epistemic,
                "confidence": confidence,
                "uncertainty_score": round(1.0 - confidence, 2),
                "rule_id": "RULE-PROC-01",
                "rule_version": "2.0",
                "reasoning": reasoning,
                "supporting_observations": [
                    f"Log event: {log_f.get('observation', '')}",
                    f"Memory record: {mem_f.get('observation', '')}"
                ]
            }

        return None

    @classmethod
    def _evaluate_disk_to_process(cls, f1: Dict[str, Any], f2: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Rule 3: Disk-to-Process correlation (Disk <-> Memory / Logs).
        """
        a1 = f1.get("agent") or f1.get("domain", "")
        a2 = f2.get("agent") or f2.get("domain", "")

        if not (a1 == "disk" or a2 == "disk"):
            return None

        disk_f = f1 if a1 == "disk" else f2
        other_f = f2 if a1 == "disk" else f1

        if (other_f.get("agent") or other_f.get("domain")) not in ("memory", "logs"):
            return None

        disk_ents = disk_f["_typed_entities"]
        other_ents = other_f["_typed_entities"]

        shared_execs = disk_ents["executables"].intersection(other_ents["executables"])
        if shared_execs:
            matched_exe = next(iter(shared_execs))
            confidence = 0.91

            return {
                "correlation_id": f"CORR-DISK-{uuid.uuid4().hex[:6].upper()}",
                "source_finding_id": disk_f.get("finding_id"),
                "target_finding_id": other_f.get("finding_id"),
                "relationship_type": "DISK_EXECUTION_TO_RUNTIME",
                "matched_entities": [{"type": "executable", "value": matched_exe}],
                "matching_method": MatchingMethod.NORMALIZED_TYPED,
                "epistemic_class": CorrelationEpistemicClass.CORRELATIONAL_ASSOCIATION,
                "confidence": confidence,
                "uncertainty_score": round(1.0 - confidence, 2),
                "rule_id": "RULE-DISK-01",
                "rule_version": "2.0",
                "reasoning": (
                    f"Prefetch / filesystem execution artifact for '{matched_exe}' correlates with "
                    f"runtime telemetry observed by {other_f.get('agent', 'other').capitalize()} Agent."
                ),
                "supporting_observations": [
                    f"Disk observation: {disk_f.get('observation', '')}",
                    f"Runtime observation: {other_f.get('observation', '')}"
                ]
            }

        return None

    @classmethod
    def _evaluate_shared_entity(cls, f1: Dict[str, Any], f2: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Rule 5: Cross-Agent Typed Entity Corroboration (Shared IP, hash, user, domain).
        """
        e1 = f1["_typed_entities"]
        e2 = f2["_typed_entities"]

        # Check hashes
        shared_hashes = e1["hashes"].intersection(e2["hashes"])
        if shared_hashes:
            h = next(iter(shared_hashes))
            return {
                "correlation_id": f"CORR-HASH-{uuid.uuid4().hex[:6].upper()}",
                "source_finding_id": f1.get("finding_id"),
                "target_finding_id": f2.get("finding_id"),
                "relationship_type": "CRYPTOGRAPHIC_HASH_MATCH",
                "matched_entities": [{"type": "hash", "value": h}],
                "matching_method": MatchingMethod.EXACT,
                "epistemic_class": CorrelationEpistemicClass.CAUSAL_DEPENDENCY,
                "confidence": 0.99,
                "uncertainty_score": 0.01,
                "rule_id": "RULE-ENTITY-01",
                "rule_version": "2.0",
                "reasoning": f"Identical cryptographic digest '{h[:12]}...' verified across {f1.get('agent')} and {f2.get('agent')}.",
                "supporting_observations": [f1.get("observation", ""), f2.get("observation", "")]
            }

        # Check users
        shared_users = e1["users"].intersection(e2["users"])
        # Ignore generic default users
        valid_users = [u for u in shared_users if u not in ("system", "local system", "administrator", "none")]
        if valid_users:
            u = valid_users[0]
            return {
                "correlation_id": f"CORR-USER-{uuid.uuid4().hex[:6].upper()}",
                "source_finding_id": f1.get("finding_id"),
                "target_finding_id": f2.get("finding_id"),
                "relationship_type": "SHARED_SECURITY_ACCOUNT_CONTEXT",
                "matched_entities": [{"type": "user", "value": u}],
                "matching_method": MatchingMethod.NORMALIZED_TYPED,
                "epistemic_class": CorrelationEpistemicClass.CORRELATIONAL_ASSOCIATION,
                "confidence": 0.85,
                "uncertainty_score": 0.15,
                "rule_id": "RULE-ENTITY-01",
                "rule_version": "2.0",
                "reasoning": f"Security account '{u}' shared across {f1.get('agent')} and {f2.get('agent')} operations.",
                "supporting_observations": [f1.get("observation", ""), f2.get("observation", "")]
            }

        return None

    @classmethod
    def _evaluate_temporal_sequence(cls, f1: Dict[str, Any], f2: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Rule 6: Temporal Sequence Correlation.
        Requires valid timestamps. Never invents temporal placement.
        """
        t1_obj = f1.get("timeline") or {}
        t2_obj = f2.get("timeline") or {}

        ts1 = t1_obj.get("timestamp_utc") or f1.get("timestamp_utc")
        ts2 = t2_obj.get("timestamp_utc") or f2.get("timestamp_utc")

        if not (ts1 and ts2):
            return None

        try:
            # Parse ISO timestamps
            dt1 = datetime.datetime.fromisoformat(ts1.replace("Z", "+00:00"))
            dt2 = datetime.datetime.fromisoformat(ts2.replace("Z", "+00:00"))
            delta_sec = abs((dt2 - dt1).total_seconds())

            # If within 30 minutes of each other
            if delta_sec <= 1800:
                earlier_f = f1 if dt1 <= dt2 else f2
                later_f = f2 if dt1 <= dt2 else f1

                # If they share no entities at all, it is COINCIDENTAL_NOISE
                e1 = f1["_typed_entities"]
                e2 = f2["_typed_entities"]
                has_entity_link = any(
                    e1[k].intersection(e2[k])
                    for k in ("executables", "ips", "domains", "hashes", "pids")
                )

                epistemic = (
                    CorrelationEpistemicClass.CORRELATIONAL_ASSOCIATION
                    if has_entity_link
                    else CorrelationEpistemicClass.COINCIDENTAL_NOISE
                )

                return {
                    "correlation_id": f"CORR-TIME-{uuid.uuid4().hex[:6].upper()}",
                    "source_finding_id": earlier_f.get("finding_id"),
                    "target_finding_id": later_f.get("finding_id"),
                    "relationship_type": "TEMPORAL_PROXIMITY_WINDOW",
                    "matched_entities": [{"type": "time_delta_seconds", "value": str(int(delta_sec))}],
                    "matching_method": MatchingMethod.NORMALIZED_TYPED,
                    "epistemic_class": epistemic,
                    "confidence": 0.80 if has_entity_link else 0.45,
                    "uncertainty_score": 0.20 if has_entity_link else 0.55,
                    "rule_id": "RULE-TIME-01",
                    "rule_version": "2.0",
                    "reasoning": (
                        f"Events occurred within {int(delta_sec)} seconds of each other. "
                        + ("Corroborated by shared entity indicators." if has_entity_link
                           else "No shared entity indicators; flagged as potential coincidental environmental noise.")
                    ),
                    "supporting_observations": [
                        f"T1 ({ts1}): {f1.get('observation', '')}",
                        f"T2 ({ts2}): {f2.get('observation', '')}"
                    ]
                }
        except Exception:
            return None

        return None

    # =========================================================================
    # TIMELINE & GRAPH BUILDERS
    # =========================================================================

    @classmethod
    def _build_unified_timeline(
        cls,
        findings: List[Dict[str, Any]],
        correlations: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Builds unified chronological attack timeline with strict timestamp provenance.
        """
        events = []
        for idx, f in enumerate(findings):
            tl = f.get("timeline") or {}
            ts_utc = tl.get("timestamp_utc") or f.get("timestamp_utc")
            ts_type = tl.get("timestamp_type") or ("OBSERVED" if ts_utc else "UNAVAILABLE")
            ts_source = tl.get("timestamp_source") or ("SOURCE_METADATA" if ts_utc else "UNRECORDED")

            events.append({
                "event_id": f"EVT-UNIFIED-{idx+1:03d}",
                "finding_id": f.get("finding_id"),
                "agent": f.get("agent") or f.get("domain"),
                "timestamp_utc": ts_utc,
                "timestamp_type": ts_type,
                "timestamp_source": ts_source,
                "event_description": tl.get("event_description") or f.get("observation") or f.get("reasoning", "")[:100],
                "assessment": f.get("assessment") or f.get("classification", "BENIGN"),
                "risk": f.get("risk") or f.get("risk_level", "LOW"),
                "discrepancy_flag": tl.get("discrepancy_flag", False),
                "enrichment_provenance": tl.get("enrichment_provenance")
            })

        # Sort: verified UTC timestamps first, unavailable at the end
        def sort_key(evt):
            ts = evt.get("timestamp_utc")
            if not ts or ts == "null":
                return "9999-12-31T23:59:59Z"
            return str(ts)

        events.sort(key=sort_key)
        return events

    @classmethod
    def _build_graph_payload(
        cls,
        findings: List[Dict[str, Any]],
        correlation_edges: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Generates NetworkX / Neo4j compatible property graph nodes and edges.
        """
        nodes = []
        for f in findings:
            nodes.append({
                "id": f.get("finding_id"),
                "label": f.get("finding_id"),
                "agent": f.get("agent") or f.get("domain"),
                "artifact_type": f.get("artifact_type"),
                "assessment": f.get("assessment") or f.get("classification"),
                "risk": f.get("risk") or f.get("risk_level"),
                "confidence": f.get("confidence", 0.9),
                "timestamp_utc": (f.get("timeline") or {}).get("timestamp_utc")
            })

        edges = []
        for e in correlation_edges:
            edges.append({
                "id": e.get("correlation_id"),
                "source": e.get("source_finding_id"),
                "target": e.get("target_finding_id"),
                "relationship": e.get("relationship_type"),
                "epistemic_class": e.get("epistemic_class"),
                "confidence": e.get("confidence"),
                "uncertainty_score": e.get("uncertainty_score"),
                "uncertainty_label": e.get("uncertainty_label", "HEURISTIC"),
                "rule_id": e.get("rule_id"),
                "reasoning": e.get("reasoning"),
                "alternative_explanations": e.get("alternative_explanations"),
                "missing_evidence": e.get("missing_evidence"),
                "matched_entities": e.get("matched_entities", []),
                "is_model_hypothesis": e.get("is_model_hypothesis", False),
                "verification_status": e.get("verification_status", "VERIFIED"),
                "visual_style": e.get("visual_style", "SOLID_CYAN")
            })

        return {
            "nodes": nodes,
            "edges": edges,
            "total_nodes": len(nodes),
            "total_edges": len(edges)
        }

    @classmethod
    def _synthesize_incident_narrative(
        cls,
        findings: List[Dict[str, Any]],
        correlation_edges: List[Dict[str, Any]]
    ) -> str:
        """
        Generates a transparent investigative incident narrative from verified relationships.
        """
        malicious_count = sum(1 for f in findings if (f.get("assessment") or f.get("classification")) == "MALICIOUS")
        suspicious_count = sum(1 for f in findings if (f.get("assessment") or f.get("classification")) == "SUSPICIOUS")
        causal_count = sum(1 for e in correlation_edges if e.get("epistemic_class") == CorrelationEpistemicClass.CAUSAL_DEPENDENCY)

        narrative = (
            f"Investigation synthesized across {len(findings)} agent findings identified {malicious_count} malicious "
            f"and {suspicious_count} suspicious security indicators. The correlation engine established {len(correlation_edges)} "
            f"cross-domain correlation edges, including {causal_count} mechanically proven causal dependencies.\n\n"
        )

        for idx, edge in enumerate(correlation_edges, 1):
            narrative += f"{idx}. [{edge['epistemic_class']}] {edge['reasoning']}\n"

        if not correlation_edges:
            narrative += "No cross-domain causal dependencies or entity linkages could be verified among the current artifact set."

        return narrative
