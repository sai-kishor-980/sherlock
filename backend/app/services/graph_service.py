"""
H-MACFR Evidence Graph Service.
Constructs, persists, queries, and audits the cross-domain Forensic Evidence Graph.
Uses NetworkX DiGraph as the primary deterministic, air-gapped knowledge graph engine.
Strictly distinguishes OBSERVED_FACT from CORROBORATED_HYPOTHESIS, COINCIDENTAL_NOISE, and ATTACK_MAPPING.
"""

import os
import json
import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple, Set

import networkx as nx

from app.db.connection import SessionLocal
from app.db.models.case import Case
from app.db.models.evidence import Evidence
from app.services.knowledge_service import KnowledgeService

logger = logging.getLogger("hmacfr.graph_service")

BACKEND_DIR = Path(__file__).resolve().parents[2]
OUTPUT_CASES_DIR = BACKEND_DIR / "output" / "cases"


class EvidenceGraphService:
    """
    Evidence Graph Construction and Traceability Engine.
    Builds a directed acyclic/cyclic property graph connecting:
    Case -> Raw Evidence -> Extracted Artifacts -> Observations (Processes/Endpoints) -> Findings -> ATT&CK Techniques.
    """

    @classmethod
    def get_case_output_dir(cls, case_id: str) -> Path:
        target = OUTPUT_CASES_DIR / case_id
        target.mkdir(parents=True, exist_ok=True)
        return target

    @classmethod
    def build_case_evidence_graph(cls, case_id: str) -> nx.DiGraph:
        """
        Constructs the comprehensive, traceable Evidence Graph for a case.
        """
        G = nx.DiGraph(
            case_id=case_id,
            generated_at=datetime.now(timezone.utc).isoformat(),
            framework="H-MACFR Forensic Evidence Graph"
        )

        db = SessionLocal()
        try:
            # 1. Fetch Case & Raw Evidence records from SQLite
            case_rec = db.query(Case).filter(Case.case_id == case_id).first()
            evidence_recs = db.query(Evidence).filter(Evidence.case_id == case_id).all()

            case_node_id = f"case:{case_id}"
            G.add_node(
                case_node_id,
                entity_type="case",
                case_id=case_id,
                case_name=case_rec.case_name if case_rec else case_id,
                investigator=case_rec.investigator_name if case_rec else "unknown",
                status=case_rec.status if case_rec else "Active",
                label=f"Case: {case_id}"
            )

            # Map filename -> evidence_node_id for downstream edge creation
            evidence_by_name = {}
            for ev in evidence_recs:
                ev_node_id = f"evidence:{ev.evidence_id}"
                evidence_by_name[ev.original_filename.lower()] = ev_node_id
                G.add_node(
                    ev_node_id,
                    entity_type="evidence",
                    evidence_id=ev.evidence_id,
                    filename=ev.original_filename,
                    category=ev.category,
                    sha256=ev.file_hash,
                    size_bytes=ev.file_size,
                    storage_path=ev.storage_path,
                    label=f"Evidence: {ev.original_filename}"
                )
                # Edge: Case CONTAINS_EVIDENCE -> Evidence
                G.add_edge(
                    case_node_id,
                    ev_node_id,
                    relationship_type="CONTAINS_EVIDENCE",
                    nature="OBSERVED_FACT",
                    confidence=1.0,
                    provenance="SQLite evidence registry"
                )

        finally:
            db.close()

        case_dir = cls.get_case_output_dir(case_id)
        report_file = case_dir / "synthesized_report.json"
        report_data = {}
        if report_file.exists():
            with open(report_file, "r", encoding="utf-8") as f:
                report_data = json.load(f)

        # 2. Add Artifact Contract Nodes (extracted tables)
        artifacts_dir = case_dir / "extracted_artifacts"
        if artifacts_dir.exists():
            for domain_path in artifacts_dir.iterdir():
                if domain_path.is_dir():
                    domain = domain_path.name
                    for art_file in domain_path.glob("*.json"):
                        art_node_id = f"artifact:{domain}:{art_file.name}"
                        size = os.path.getsize(art_file)
                        G.add_node(
                            art_node_id,
                            entity_type="artifact",
                            domain=domain,
                            filename=art_file.name,
                            rel_path=f"extracted_artifacts/{domain}/{art_file.name}",
                            size_bytes=size,
                            label=f"Artifact: {domain}/{art_file.name}"
                        )

                        # Link artifact to raw evidence source if matched
                        matched_ev_id = None
                        if domain == "registry":
                            matched_ev_id = next((eid for fn, eid in evidence_by_name.items() if "system" in fn or "reg" in fn or fn.endswith(".hive")), None)
                        elif domain == "disk":
                            matched_ev_id = next((eid for fn, eid in evidence_by_name.items() if fn.endswith(".pf") or fn.endswith(".lnk") or fn.endswith(".raw") or fn.endswith(".img") or fn.endswith(".e01")), None)
                        elif domain == "logs":
                            matched_ev_id = next((eid for fn, eid in evidence_by_name.items() if fn.endswith(".evtx")), None)
                        elif domain == "network":
                            matched_ev_id = next((eid for fn, eid in evidence_by_name.items() if fn.endswith(".pcap") or fn.endswith(".pcapng") or "pcap" in fn), None)
                        
                        if not matched_ev_id and len(evidence_by_name) == 1:
                            matched_ev_id = list(evidence_by_name.values())[0]

                        elif domain == "memory":
                            # Pre-extracted Volatility tables node
                            mem_snap_id = f"evidence:{case_id}:volatility_tables"
                            if mem_snap_id not in G:
                                G.add_node(
                                    mem_snap_id,
                                    entity_type="evidence",
                                    evidence_id="pre_extracted_volatility_snapshot",
                                    filename="volatility_tables_snapshot",
                                    category="Memory (Pre-extracted)",
                                    provenance_qualification="Pre-extracted Volatility 3 tables (not raw RAM execution in this run)",
                                    label="Evidence: Volatility 3 Tables"
                                )
                                G.add_edge(
                                    case_node_id,
                                    mem_snap_id,
                                    relationship_type="CONTAINS_EVIDENCE",
                                    nature="OBSERVED_FACT",
                                    confidence=1.0,
                                    provenance="Pre-extracted memory analysis ingestion"
                                )
                            matched_ev_id = mem_snap_id

                        if matched_ev_id:
                            G.add_edge(
                                art_node_id,
                                matched_ev_id,
                                relationship_type="EXTRACTED_FROM",
                                nature="OBSERVED_FACT",
                                confidence=1.0,
                                provenance=f"Extractor plugin pipeline ({domain})"
                            )

        # 3. Add Extracted Memory Processes & Hierarchy
        mem_processes = report_data.get("artifacts", {}).get("memory_processes", {}).get("records", [])
        proc_node_ids = {}
        for p in mem_processes:
            pid = p.get("pid")
            ppid = p.get("ppid")
            pname = p.get("process_name", f"PID-{pid}")
            proc_node_id = f"process:{case_id}:{pid}"
            proc_node_ids[pid] = proc_node_id

            G.add_node(
                proc_node_id,
                entity_type="process",
                pid=pid,
                ppid=ppid,
                process_name=pname,
                create_time=p.get("create_time"),
                offset=p.get("offset"),
                is_injected=p.get("is_injected", False),
                label=f"Process: {pname} ({pid})"
            )

            # Link process to memory artifact source
            mem_art_id = "artifact:memory:processes.json"
            if mem_art_id in G:
                G.add_edge(
                    proc_node_id,
                    mem_art_id,
                    relationship_type="OBSERVED_IN",
                    nature="OBSERVED_FACT",
                    confidence=1.0,
                    provenance="Volatility 3 windows.pslist"
                )

        # Process parent-child spawn hierarchy edges
        for p in mem_processes:
            pid = p.get("pid")
            ppid = p.get("ppid")
            if ppid and ppid in proc_node_ids:
                G.add_edge(
                    proc_node_ids[pid],
                    proc_node_ids[ppid],
                    relationship_type="SPAWNED_BY",
                    nature="OBSERVED_FACT",
                    confidence=1.0,
                    provenance=f"Process PPID linkage: {p.get('process_name')} ({pid}) -> Parent PPID ({ppid})"
                )

        # 4. Add Network Endpoints & DNS Flows
        dns_file = case_dir / "extracted_artifacts" / "network" / "dns_analysis.json"
        if dns_file.exists():
            try:
                with open(dns_file, "r", encoding="utf-8") as f:
                    dns_data = json.load(f)
                for d in dns_data.get("records", []):
                    query = d.get("query")
                    if query:
                        domain_node_id = f"endpoint:domain:{query}"
                        G.add_node(
                            domain_node_id,
                            entity_type="network_endpoint",
                            endpoint_type="domain_name",
                            domain_name=query,
                            suspicious_dga=d.get("suspicious_dga", False),
                            label=f"Domain: {query}"
                        )
                        # Link to network artifact
                        pcap_art_id = "artifact:network:dns_analysis.json"
                        if pcap_art_id in G:
                            G.add_edge(
                                domain_node_id,
                                pcap_art_id,
                                relationship_type="OBSERVED_IN",
                                nature="OBSERVED_FACT",
                                confidence=1.0,
                                provenance="PCAP DNS parser"
                            )

                        for ans in d.get("answers", []):
                            ip_node_id = f"endpoint:ip:{ans}"
                            G.add_node(
                                ip_node_id,
                                entity_type="network_endpoint",
                                endpoint_type="ip_address",
                                ip=ans,
                                label=f"IP: {ans}"
                            )
                            # Edge: Domain RESOLVED_TO IP
                            G.add_edge(
                                domain_node_id,
                                ip_node_id,
                                relationship_type="RESOLVED_TO",
                                nature="OBSERVED_FACT",
                                confidence=0.95,
                                provenance=f"DNS A Record answer: {query} -> {ans}"
                            )
            except Exception as ex:
                logger.warning(f"Error parsing dns_analysis in graph builder: {ex}")

        # 4b. Add Extracted Disk Prefetch & USB Device Entities if present
        prefetch_file = case_dir / "extracted_artifacts" / "disk" / "prefetch_analysis.json"
        if prefetch_file.exists():
            try:
                with open(prefetch_file, "r", encoding="utf-8") as f:
                    pf_data = json.load(f)
                pf_items = pf_data if isinstance(pf_data, list) else pf_data.get("records", []) or pf_data.get("prefetch_files", [])
                for pf in pf_items:
                    exe = str(pf.get("executable_name") or pf.get("executable") or pf.get("name") or "").lower()
                    if exe:
                        pf_node_id = f"prefetch:{case_id}:{exe}"
                        if pf_node_id not in G:
                            G.add_node(
                                pf_node_id,
                                entity_type="prefetch_execution",
                                executable_name=exe,
                                run_count=pf.get("run_count", 1),
                                last_run_time=str(pf.get("last_run_time") or pf.get("last_executed") or ""),
                                label=f"Prefetch: {exe}"
                            )
                            pf_art_id = "artifact:disk:prefetch_analysis.json"
                            if pf_art_id in G:
                                G.add_edge(
                                    pf_node_id,
                                    pf_art_id,
                                    relationship_type="OBSERVED_IN",
                                    nature="OBSERVED_FACT",
                                    confidence=1.0,
                                    provenance="Prefetch parser"
                                )
            except Exception as ex:
                logger.warning(f"Error parsing prefetch_analysis in graph builder: {ex}")

        usb_file = case_dir / "extracted_artifacts" / "registry" / "usb_devices.json"
        if not usb_file.exists():
            usb_file = case_dir / "extracted_artifacts" / "disk" / "usb_devices.json"
        if usb_file.exists():
            try:
                with open(usb_file, "r", encoding="utf-8") as f:
                    usb_data = json.load(f)
                usb_items = usb_data if isinstance(usb_data, list) else usb_data.get("records", [])
                for u in usb_items:
                    serial = str(u.get("serial_number") or u.get("serial") or "")
                    if serial:
                        usb_node_id = f"usb:{case_id}:{serial}"
                        dev_name = u.get("values", {}).get("FriendlyName") or u.get("device_name") or "USB Device"
                        if usb_node_id not in G:
                            G.add_node(
                                usb_node_id,
                                entity_type="usb_device",
                                serial_number=serial,
                                device_name=dev_name,
                                last_connected=str(u.get("last_connected") or ""),
                                label=f"USB: {dev_name} ({serial})"
                            )
                            u_art_id = f"artifact:{usb_file.parent.name}:{usb_file.name}"
                            if u_art_id in G:
                                G.add_edge(
                                    usb_node_id,
                                    u_art_id,
                                    relationship_type="OBSERVED_IN",
                                    nature="OBSERVED_FACT",
                                    confidence=1.0,
                                    provenance="USBSTOR registry parser"
                                )
            except Exception as ex:
                logger.warning(f"Error parsing usb_devices in graph builder: {ex}")

        runkey_file = case_dir / "extracted_artifacts" / "registry" / "run_keys.json"
        if not runkey_file.exists():
            runkey_file = case_dir / "extracted_artifacts" / "disk" / "run_keys.json"
        if runkey_file.exists():
            try:
                with open(runkey_file, "r", encoding="utf-8") as f:
                    rk_data = json.load(f)
                rk_items = rk_data if isinstance(rk_data, list) else rk_data.get("records", [])
                for rk in rk_items:
                    rk_name = str(rk.get("name") or "")
                    if rk_name:
                        rk_node_id = f"runkey:{case_id}:{rk_name}"
                        if rk_node_id not in G:
                            G.add_node(
                                rk_node_id,
                                entity_type="registry_run_key",
                                name=rk_name,
                                command=rk.get("command", ""),
                                label=f"RunKey: {rk_name}"
                            )
                            rk_art_id = f"artifact:{runkey_file.parent.name}:{runkey_file.name}"
                            if rk_art_id in G:
                                G.add_edge(
                                    rk_node_id,
                                    rk_art_id,
                                    relationship_type="OBSERVED_IN",
                                    nature="OBSERVED_FACT",
                                    confidence=1.0,
                                    provenance="Registry Run Key parser"
                                )
            except Exception as ex:
                logger.warning(f"Error parsing run_keys in graph builder: {ex}")

        # 5. Add Finding Nodes & Cross-Domain Edge Links
        findings = report_data.get("findings", [])
        finding_node_ids = {}
        for idx, f in enumerate(findings):
            fid = f.get("finding_id") or f"FIND-{idx+1:03d}"
            finding_node_id = f"finding:{case_id}:{fid}"
            finding_node_ids[fid] = finding_node_id

            G.add_node(
                finding_node_id,
                entity_type="finding",
                finding_id=fid,
                title=f.get("title"),
                domain=f.get("domain", "general"),
                risk_level=f.get("risk_level", "MEDIUM"),
                assessment=f.get("assessment", "suspicious"),
                confidence=f.get("confidence", 0.80),
                mitre_technique=f.get("mitre_technique"),
                label=f"Finding: {f.get('title')}"
            )

            # Edge to target entity (e.g. process) from evidence_sources
            for src in f.get("evidence_sources", []):
                art_id_target = src.get("artifact_id", "") if isinstance(src, dict) else str(src)
                if "PID-" in art_id_target:
                    try:
                        target_pid = int(art_id_target.replace("PID-", ""))
                        if target_pid in proc_node_ids:
                            G.add_edge(
                                finding_node_id,
                                proc_node_ids[target_pid],
                                relationship_type="INDICATES_ANOMALY",
                                nature="CORROBORATED_HYPOTHESIS",
                                confidence=min(f.get("confidence", 0.80), 0.85),
                                provenance=f"Forensic finding deduction: {f.get('title')}"
                            )
                    except ValueError:
                        pass
                elif isinstance(src, dict) and "file" in src:
                    f_name = Path(src["file"]).name
                    for art_node in list(G.nodes()):
                        if G.nodes[art_node].get("entity_type") == "artifact" and G.nodes[art_node].get("filename") == f_name:
                            G.add_edge(
                                finding_node_id,
                                art_node,
                                relationship_type="DERIVED_FROM_ARTIFACT",
                                nature="OBSERVED_FACT",
                                confidence=f.get("confidence", 0.80),
                                provenance=f"Forensic finding source: {src.get('file')}"
                            )

            # 6. Add MITRE Technique Nodes & Mapping Edge
            raw_tech = f.get("mitre_technique")
            if raw_tech and raw_tech != "N/A":
                technique_id = raw_tech.split(":")[0].strip().upper() if ":" in raw_tech else raw_tech.strip().upper()
                tech_node_id = f"technique:{technique_id}"
                if tech_node_id not in G:
                    # Lookup technique from ChromaDB Knowledge Base
                    tech_meta = KnowledgeService.get_technique_by_id(technique_id)
                    tech_name = tech_meta.get("name") if tech_meta else raw_tech
                    tactics = tech_meta.get("tactics") if tech_meta else ""
                    stix_id = tech_meta.get("stix_id") if tech_meta else ""
                    tech_url = tech_meta.get("url") if tech_meta else f"https://attack.mitre.org/techniques/{technique_id}"

                    G.add_node(
                        tech_node_id,
                        entity_type="mitre_technique",
                        technique_id=technique_id,
                        name=tech_name,
                        tactics=tactics,
                        stix_id=stix_id,
                        url=tech_url,
                        label=f"ATT&CK: {technique_id} - {tech_name}"
                    )

                # Edge: Finding MAPPED_TO_TECHNIQUE -> Technique
                G.add_edge(
                    finding_node_id,
                    tech_node_id,
                    relationship_type="MAPPED_TO_TECHNIQUE",
                    nature="ATTACK_MAPPING",
                    confidence=0.80,
                    disclaimer="Technique mapping represents analytic taxonomy categorization; does not constitute definitive proof of adversary attack.",
                    provenance=f"Supervisor ATT&CK mapping heuristic for {f.get('title')}"
                )

        # 7. Add Correlation Edges
        correlations = report_data.get("correlations", [])
        if "unresolved_correlation_edges" not in G.graph:
            G.graph["unresolved_correlation_edges"] = []

        for c in correlations:
            c_nature = c.get("correlation_nature", "CORROBORATED_HYPOTHESIS")
            conf = c.get("confidence_score") or c.get("confidence", 0.80)
            rel_type = c.get("relationship_type", "CORRELATED_WITH")
            src_a = c.get("source_a", {})
            src_b = c.get("source_b", {})

            node_a = None
            node_b = None

            # Resolve node A
            art_a = src_a.get("artifact_id", "")
            if "PID-" in art_a:
                try:
                    p_a = int(art_a.replace("PID-", ""))
                    node_a = proc_node_ids.get(p_a)
                except ValueError:
                    pass
            elif "DNS-" in art_a:
                d_q = art_a.replace("DNS-", "")
                node_a = f"endpoint:domain:{d_q}"
            elif "RUNKEY-" in art_a:
                rk_k = art_a.replace("RUNKEY-", "")
                rk_ent = f"runkey:{case_id}:{rk_k}"
                if rk_ent in G:
                    node_a = rk_ent
                elif "artifact:registry:run_keys.json" in G:
                    node_a = "artifact:registry:run_keys.json"
                elif "artifact:disk:run_keys.json" in G:
                    node_a = "artifact:disk:run_keys.json"
            elif "USB-" in art_a:
                u_ser = art_a.replace("USB-", "")
                u_ent = f"usb:{case_id}:{u_ser}"
                if u_ent in G:
                    node_a = u_ent
                elif "artifact:registry:usb_devices.json" in G:
                    node_a = "artifact:registry:usb_devices.json"
                elif "artifact:disk:usb_devices.json" in G:
                    node_a = "artifact:disk:usb_devices.json"

            # Resolve node B
            art_b = src_b.get("artifact_id", "")
            if "PID-" in art_b:
                try:
                    p_b = int(art_b.replace("PID-", ""))
                    node_b = proc_node_ids.get(p_b)
                except ValueError:
                    pass
            elif "NET-FLOW-" in art_b or "NET-" in art_b:
                net_ip = art_b.replace("NET-FLOW-", "").replace("NET-", "")
                node_b = f"endpoint:ip:{net_ip}"
            elif "PREFETCH-" in art_b:
                pf_k = art_b.replace("PREFETCH-", "").lower()
                pf_ent = f"prefetch:{case_id}:{pf_k}"
                if pf_ent in G:
                    node_b = pf_ent
                elif "artifact:disk:prefetch_analysis.json" in G:
                    node_b = "artifact:disk:prefetch_analysis.json"

            if node_a and node_b and node_a in G and node_b in G:
                is_causal = c_nature in ("DETERMINISTIC_GROUNDED", "CORROBORATED_HYPOTHESIS")
                G.add_edge(
                    node_a,
                    node_b,
                    relationship_type=rel_type.upper(),
                    nature=c_nature,
                    is_causal=is_causal,
                    confidence=conf,
                    correlation_id=c.get("correlation_id"),
                    source_artifact_id=art_a,
                    target_artifact_id=art_b,
                    provenance=c.get("reasoning", "")[:200],
                    temporal_status=c.get("temporal_status", "UNKNOWN"),
                    temporal_delta_seconds=c.get("temporal_delta_seconds")
                )
            else:
                missing = []
                if not node_a or node_a not in G:
                    missing.append(f"source_a: {art_a} (resolved: {node_a})")
                if not node_b or node_b not in G:
                    missing.append(f"source_b: {art_b} (resolved: {node_b})")

                G.graph["unresolved_correlation_edges"].append({
                    "correlation_id": c.get("correlation_id"),
                    "relationship_type": rel_type,
                    "source_a": art_a,
                    "source_b": art_b,
                    "unresolved_reasons": missing,
                    "diagnostic": "Correlation edge dropped from active graph because referenced source or target entity node does not exist in evidence."
                })

        return G

    @classmethod
    def save_graph(cls, G: nx.DiGraph, case_id: str) -> Path:
        """
        Serializes the Evidence Graph to JSON format in the case output directory.
        """
        case_dir = cls.get_case_output_dir(case_id)
        graph_file = case_dir / "evidence_graph.json"

        # Standard networkx node_link format (edges="edges" for NetworkX 3.6 compatibility)
        data = nx.node_link_data(G, edges="edges")
        with open(graph_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)

        logger.info(f"Saved Evidence Graph for Case {case_id} to {graph_file} ({G.number_of_nodes()} nodes, {G.number_of_edges()} edges)")

        # Synchronize with Neo4j & write neo4j_export.cypher
        cls.sync_to_neo4j(G, case_id)

        return graph_file

    @classmethod
    def sync_to_neo4j(cls, G: nx.DiGraph, case_id: str) -> Dict[str, Any]:
        """
        Exports the NetworkX Evidence Graph to Neo4j.
        Generates 'neo4j_export.cypher' and live-syncs if Neo4j is running.
        """
        try:
            from app.services.neo4j_service import Neo4jService
            case_dir = cls.get_case_output_dir(case_id)

            evidence_list = []
            artifacts = []
            correlations = []
            techniques = []

            for n, d in G.nodes(data=True):
                etype = d.get("entity_type", "")
                if etype == "evidence":
                    evidence_list.append({
                        "evidence_id": d.get("evidence_id") or n,
                        "name": d.get("filename") or d.get("label"),
                        "type": d.get("evidence_type", "DISK"),
                        "sha256": d.get("sha256", "")
                    })
                elif etype == "artifact":
                    artifacts.append({
                        "artifact_id": d.get("artifact_id") or n,
                        "domain": d.get("domain", "forensics"),
                        "category": d.get("category", "artifact"),
                        "timestamp": d.get("timestamp", ""),
                        "confidence": d.get("confidence", 1.0),
                        "description": d.get("description", d.get("label", ""))
                    })
                elif etype == "technique":
                    techniques.append({
                        "technique_id": d.get("technique_id") or n,
                        "name": d.get("name", ""),
                        "tactic": d.get("tactic", "")
                    })

            for u, v, d in G.edges(data=True):
                rel_type = d.get("relationship_type", "CORRELATION")
                nature = d.get("nature", "CORRELATIONAL_ASSOCIATION")
                if nature == "DETERMINISTIC_GROUNDED" or d.get("is_causal"):
                    epistemic = "CAUSAL_DEPENDENCY"
                elif nature == "COINCIDENTAL_NOISE":
                    epistemic = "COINCIDENTAL_NOISE"
                elif nature == "AMBIGUOUS_UNKNOWN":
                    epistemic = "AMBIGUOUS_UNKNOWN"
                else:
                    epistemic = "CORRELATIONAL_ASSOCIATION"

                correlations.append({
                    "source_id": u,
                    "target_id": v,
                    "relationship_type": rel_type,
                    "epistemic_classification": epistemic,
                    "confidence": d.get("confidence", 0.5),
                    "uncertainty_score": round(1.0 - float(d.get("confidence", 0.5)), 3),
                    "reasoning": d.get("provenance", "")
                })

            return Neo4jService.sync_case_graph(
                case_id=case_id,
                case_name=f"Forensic Case {case_id}",
                evidence_list=evidence_list,
                artifacts=artifacts,
                correlations=correlations,
                techniques=techniques,
                output_dir=case_dir
            )
        except Exception as e:
            logger.warning(f"Neo4j sync failed: {e}")
            return {"status": "ERROR", "error": str(e)}

    @classmethod
    def load_graph(cls, case_id: str) -> Optional[nx.DiGraph]:
        """
        Loads the Evidence Graph from disk.
        """
        case_dir = cls.get_case_output_dir(case_id)
        graph_file = case_dir / "evidence_graph.json"
        if not graph_file.exists():
            return None

        with open(graph_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        return nx.node_link_graph(data, directed=True, edges="edges")

    @classmethod
    def get_graph_metrics(cls, G: nx.DiGraph) -> Dict[str, Any]:
        """
        Calculates diagnostic and provenance metrics across the Evidence Graph.
        """
        node_types = {}
        for n, d in G.nodes(data=True):
            etype = d.get("entity_type", "unknown")
            node_types[etype] = node_types.get(etype, 0) + 1

        rel_types = {}
        nature_counts = {}
        for u, v, d in G.edges(data=True):
            rtype = d.get("relationship_type", "unknown")
            rel_types[rtype] = rel_types.get(rtype, 0) + 1
            nat = d.get("nature", "unknown")
            nature_counts[nat] = nature_counts.get(nat, 0) + 1

        return {
            "total_nodes": G.number_of_nodes(),
            "total_edges": G.number_of_edges(),
            "node_distribution": node_types,
            "relationship_distribution": rel_types,
            "nature_distribution": nature_counts,
            "unresolved_correlation_edges_count": len(G.graph.get("unresolved_correlation_edges", [])),
            "unresolved_correlation_edges": G.graph.get("unresolved_correlation_edges", []),
            "is_directed": G.is_directed()
        }

    @classmethod
    def get_case_evidence_graph_data(
        cls,
        case_id: str,
        include_noise: bool = True,
        min_confidence: float = 0.0
    ) -> Dict[str, Any]:
        """
        Retrieves, converts, and optionally filters the Evidence Graph for API presentation.
        Preserves raw evidence and original graph files without permanent modification.
        """
        G = cls.load_graph(case_id)
        if G is None:
            # Build and persist graph if not yet created on disk
            G = cls.build_case_evidence_graph(case_id)
            cls.save_graph(G, case_id)

        raw_data = nx.node_link_data(G, edges="edges")
        raw_nodes = raw_data.get("nodes", [])
        raw_edges = raw_data.get("edges", [])
        graph_meta = raw_data.get("graph", {})

        total_nodes = len(raw_nodes)
        total_edges = len(raw_edges)

        # Apply filtering purely in-memory
        filtered_edges = []
        for e in raw_edges:
            # Noise filter: exclude if include_noise is False and edge is coincidental noise or not causal
            if not include_noise:
                if e.get("nature") == "COINCIDENTAL_NOISE" or e.get("is_causal") is False:
                    continue

            # Confidence threshold filter
            conf = float(e.get("confidence", 0.0))
            if conf < min_confidence:
                continue

            filtered_edges.append(e)

        is_filtered = (len(filtered_edges) != total_edges)

        filter_meta = {
            "include_noise": include_noise,
            "min_confidence": min_confidence,
            "total_unfiltered_nodes": total_nodes,
            "total_unfiltered_edges": total_edges,
            "returned_nodes_count": total_nodes,
            "returned_edges_count": len(filtered_edges),
            "is_filtered": is_filtered
        }

        # Calculate metrics for the returned view
        metrics = cls.get_graph_metrics(G)

        return {
            "case_id": case_id,
            "generated_at": graph_meta.get("generated_at"),
            "framework": graph_meta.get("framework", "H-MACFR Forensic Evidence Graph"),
            "confidence_metric_disclaimer": (
                "Confidence values are expert-calibrated heuristic ordinal risk scores; "
                "they do not represent statistical Bayesian probabilities."
            ),
            "filtering": filter_meta,
            "metrics": metrics,
            "nodes": raw_nodes,
            "edges": filtered_edges,
            "links": filtered_edges,
            "unresolved_correlation_edges": graph_meta.get("unresolved_correlation_edges", [])
        }


    @classmethod
    def trace_technique_provenance(cls, G: nx.DiGraph, technique_id: str) -> List[Dict[str, Any]]:
        """
        Demonstrates a complete evidentiary trace backwards:
        ATT&CK Technique -> Finding -> Target Observation (Process/Endpoint) -> Extracted Artifact -> Raw Evidence.
        """
        tech_node_id = f"technique:{technique_id.upper().strip()}"
        if tech_node_id not in G:
            return []

        traces = []
        # Find incoming edges to technique (Findings mapped to technique)
        for finding_node_id in G.predecessors(tech_node_id):
            edge_map = G.get_edge_data(finding_node_id, tech_node_id)
            finding_data = G.nodes[finding_node_id]

            # Find target observations connected to this finding
            for obs_node_id in G.successors(finding_node_id):
                if obs_node_id == tech_node_id:
                    continue
                obs_data = G.nodes[obs_node_id]

                # Find artifacts where this observation was observed
                artifacts = []
                raw_evidences = []
                if obs_data.get("entity_type") == "artifact":
                    artifacts.append({
                        "artifact_node": obs_node_id,
                        "filename": obs_data.get("filename"),
                        "domain": obs_data.get("domain")
                    })
                    for ev_node_id in G.successors(obs_node_id):
                        if G.nodes[ev_node_id].get("entity_type") == "evidence":
                            ev_data = G.nodes[ev_node_id]
                            raw_evidences.append({
                                "evidence_id": ev_data.get("evidence_id"),
                                "filename": ev_data.get("filename"),
                                "sha256": ev_data.get("sha256")
                            })
                else:
                    for art_node_id in G.successors(obs_node_id):
                        if G.nodes[art_node_id].get("entity_type") == "artifact":
                            art_data = G.nodes[art_node_id]
                            artifacts.append({
                                "artifact_node": art_node_id,
                                "filename": art_data.get("filename"),
                                "domain": art_data.get("domain")
                            })
                            # Find raw evidence for this artifact
                            for ev_node_id in G.successors(art_node_id):
                                if G.nodes[ev_node_id].get("entity_type") == "evidence":
                                    ev_data = G.nodes[ev_node_id]
                                    raw_evidences.append({
                                        "evidence_id": ev_data.get("evidence_id"),
                                        "filename": ev_data.get("filename"),
                                        "sha256": ev_data.get("sha256")
                                    })

                traces.append({
                    "technique": {
                        "node_id": tech_node_id,
                        "technique_id": G.nodes[tech_node_id].get("technique_id"),
                        "name": G.nodes[tech_node_id].get("name")
                    },
                    "mapping_edge": {
                        "relationship": edge_map.get("relationship_type"),
                        "nature": edge_map.get("nature"),
                        "confidence": edge_map.get("confidence")
                    },
                    "finding": {
                        "node_id": finding_node_id,
                        "title": finding_data.get("title"),
                        "confidence": finding_data.get("confidence"),
                        "risk_level": finding_data.get("risk_level")
                    },
                    "observation": {
                        "node_id": obs_node_id,
                        "entity_type": obs_data.get("entity_type"),
                        "label": obs_data.get("label")
                    },
                    "supporting_artifacts": artifacts,
                    "source_raw_evidence": raw_evidences
                })

        return traces
