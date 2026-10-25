"""
Neo4j Graph Database Service for Sherlock AI / H-MACFR.
Provides bidirectional integration between the in-memory NetworkX Forensic Graph
and an enterprise Neo4j Property Graph.

Supports:
- Live streaming of Case -> Evidence -> Artifact -> Correlation -> ATT&CK nodes and edges.
- 4-Class Epistemic Relationship labels:
    - CAUSAL_DEPENDENCY
    - CORRELATIONAL_ASSOCIATION
    - COINCIDENTAL_NOISE
    - AMBIGUOUS_UNKNOWN
- Standalone Cypher script generation (neo4j_export.cypher) for air-gapped or deferred import.
- Graceful offline fallback (never blocks investigation workflow if Neo4j is offline).
"""

import os
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from app.core.config import settings

logger = logging.getLogger("hmacfr.neo4j_service")


class Neo4jService:
    _driver = None
    _driver_failed = False

    @classmethod
    def get_driver(cls):
        """
        Lazily initializes and caches the Neo4j driver connection.
        """
        if not settings.NEO4J_ENABLED:
            return None

        if cls._driver is not None:
            return cls._driver

        if cls._driver_failed:
            return None

        try:
            from neo4j import GraphDatabase
            cls._driver = GraphDatabase.driver(
                settings.NEO4J_URI,
                auth=(settings.NEO4J_USER, settings.NEO4J_PASSWORD),
                max_connection_lifetime=300,
                connection_timeout=5.0
            )
            # Verify connectivity
            cls._driver.verify_connectivity()
            logger.info(f"[Neo4jService] Connected successfully to Neo4j at {settings.NEO4J_URI}")
            return cls._driver
        except Exception as e:
            cls._driver_failed = True
            cls._driver = None
            logger.warning(f"[Neo4jService] Neo4j is currently unreachable ({e}). Operating in offline Cypher-export mode.")
            return None

    @classmethod
    def close(cls):
        if cls._driver:
            try:
                cls._driver.close()
            except Exception:
                pass
            cls._driver = None
            cls._driver_failed = False

    @classmethod
    def test_connection(cls) -> Dict[str, Any]:
        """
        Tests connection to the configured Neo4j instance.
        """
        cls._driver_failed = False  # Reset failure flag for explicit test
        driver = cls.get_driver()
        if driver:
            try:
                with driver.session(database=settings.NEO4J_DATABASE) as session:
                    res = session.run("RETURN 1 AS online")
                    record = res.single()
                    if record and record["online"] == 1:
                        return {
                            "status": "ONLINE",
                            "uri": settings.NEO4J_URI,
                            "user": settings.NEO4J_USER,
                            "database": settings.NEO4J_DATABASE,
                            "message": "Neo4j connection verified and active."
                        }
            except Exception as e:
                return {
                    "status": "ERROR",
                    "uri": settings.NEO4J_URI,
                    "error": str(e),
                    "message": "Connected to Neo4j endpoint but session query failed."
                }
        return {
            "status": "OFFLINE",
            "uri": settings.NEO4J_URI,
            "message": "Neo4j server is unreachable. Forensic pipeline will generate standalone neo4j_export.cypher files."
        }

    @classmethod
    def generate_cypher_export(
        cls,
        case_id: str,
        case_name: str,
        evidence_list: List[Dict[str, Any]],
        artifacts: List[Dict[str, Any]],
        correlations: List[Dict[str, Any]],
        techniques: Optional[List[Dict[str, Any]]] = None
    ) -> str:
        """
        Generates a standalone, executable Cypher script that can be pasted directly
        into the Neo4j Browser or executed via cypher-shell.
        """
        statements = []
        statements.append("// ==========================================================")
        statements.append(f"// Sherlock AI / H-MACFR Forensic Graph Export for Case: {case_id}")
        statements.append("// ==========================================================\n")

        # 1. Schema constraints
        statements.append("// --- 1. Schema Constraints & Indexes ---")
        statements.append("CREATE CONSTRAINT IF NOT EXISTS FOR (c:Case) REQUIRE c.case_id IS UNIQUE;")
        statements.append("CREATE CONSTRAINT IF NOT EXISTS FOR (e:Evidence) REQUIRE e.evidence_id IS UNIQUE;")
        statements.append("CREATE CONSTRAINT IF NOT EXISTS FOR (a:Artifact) REQUIRE a.artifact_id IS UNIQUE;")
        statements.append("CREATE INDEX IF NOT EXISTS FOR (t:MITRE_Technique) ON (t.technique_id);\n")

        # 2. Case node
        safe_name = (case_name or case_id).replace("'", "\\'")
        statements.append("// --- 2. Case Node ---")
        statements.append(
            f"MERGE (c:Case {{case_id: '{case_id}'}})\n"
            f"ON CREATE SET c.name = '{safe_name}', c.synced_at = datetime();\n"
        )

        # 3. Evidence nodes
        if evidence_list:
            statements.append("// --- 3. Evidence Nodes ---")
            for ev in evidence_list:
                ev_id = ev.get("evidence_id") or ev.get("id") or f"ev_{case_id}_{len(statements)}"
                ev_name = (ev.get("name") or ev.get("file_name") or "Evidence").replace("'", "\\'")
                ev_type = (ev.get("type") or ev.get("evidence_type") or "DISK").replace("'", "\\'")
                ev_sha = ev.get("sha256") or ev.get("sha256_hash") or ""
                statements.append(
                    f"MERGE (e:Evidence {{evidence_id: '{ev_id}'}})\n"
                    f"ON CREATE SET e.name = '{ev_name}', e.type = '{ev_type}', e.sha256 = '{ev_sha}'\n"
                    f"WITH e MATCH (c:Case {{case_id: '{case_id}'}})\n"
                    f"MERGE (c)-[:HAS_EVIDENCE]->(e);\n"
                )

        # 4. Artifact nodes
        if artifacts:
            statements.append("// --- 4. Extracted Artifact Nodes ---")
            for art in artifacts:
                art_id = art.get("artifact_id") or art.get("id") or f"art_{len(statements)}"
                cat = (art.get("category") or art.get("domain") or "UNKNOWN").replace("'", "\\'")
                domain = (art.get("domain") or "forensics").replace("'", "\\'")
                ts = art.get("timestamp") or ""
                conf = art.get("confidence", 1.0)
                desc = (art.get("description") or art.get("summary") or "").replace("'", "\\'")
                ev_id = art.get("evidence_id")

                stmt = (
                    f"MERGE (a:Artifact {{artifact_id: '{art_id}'}})\n"
                    f"ON CREATE SET a.category = '{cat}', a.domain = '{domain}', a.timestamp = '{ts}',\n"
                    f"              a.confidence = {conf}, a.description = '{desc[:200]}'\n"
                )
                if ev_id:
                    stmt += (
                        f"WITH a MATCH (e:Evidence {{evidence_id: '{ev_id}'}})\n"
                        f"MERGE (e)-[:EXTRACTED_TO]->(a);\n"
                    )
                else:
                    stmt += (
                        f"WITH a MATCH (c:Case {{case_id: '{case_id}'}})\n"
                        f"MERGE (c)-[:CONTAINS_ARTIFACT]->(a);\n"
                    )
                statements.append(stmt)

        # 5. Correlations with 4-Class Epistemic Labels
        if correlations:
            statements.append("// --- 5. Epistemic Cross-Domain Correlations ---")
            for corr in correlations:
                src_id = corr.get("source_id") or corr.get("source_artifact_id")
                tgt_id = corr.get("target_id") or corr.get("target_artifact_id")
                if not src_id or not tgt_id:
                    continue

                rel_type = corr.get("relationship_type", "CORRELATION")
                epistemic_class = corr.get("epistemic_classification", "CORRELATIONAL_ASSOCIATION")
                conf = corr.get("confidence", 0.5)
                uncertainty = corr.get("uncertainty_score", round(1.0 - conf, 3))
                reason = (corr.get("reasoning") or corr.get("explanation") or "").replace("'", "\\'")

                # Map epistemic class to valid Neo4j Relationship type
                neo4j_rel = epistemic_class.upper().replace("-", "_").replace(" ", "_")
                if neo4j_rel not in ["CAUSAL_DEPENDENCY", "CORRELATIONAL_ASSOCIATION", "COINCIDENTAL_NOISE", "AMBIGUOUS_UNKNOWN"]:
                    neo4j_rel = "CORRELATIONAL_ASSOCIATION"

                statements.append(
                    f"MATCH (src:Artifact {{artifact_id: '{src_id}'}}), (tgt:Artifact {{artifact_id: '{tgt_id}'}})\n"
                    f"MERGE (src)-[r:{neo4j_rel} {{relationship_type: '{rel_type}'}}]->(tgt)\n"
                    f"ON CREATE SET r.confidence = {conf}, r.uncertainty_score = {uncertainty},\n"
                    f"              r.epistemic_classification = '{epistemic_class}',\n"
                    f"              r.reasoning = '{reason[:250]}';\n"
                )

        # 6. MITRE ATT&CK Techniques
        if techniques:
            statements.append("// --- 6. MITRE ATT&CK Technique Mappings ---")
            for t in techniques:
                tid = t.get("technique_id") or t.get("id")
                tname = (t.get("name") or "").replace("'", "\\'")
                tactic = (t.get("tactic") or "").replace("'", "\\'")
                art_id = t.get("artifact_id")
                if not tid:
                    continue

                stmt = (
                    f"MERGE (m:MITRE_Technique {{technique_id: '{tid}'}})\n"
                    f"ON CREATE SET m.name = '{tname}', m.tactic = '{tactic}'\n"
                )
                if art_id:
                    stmt += (
                        f"WITH m MATCH (a:Artifact {{artifact_id: '{art_id}'}})\n"
                        f"MERGE (a)-[:MAPS_TO_TECHNIQUE]->(m);\n"
                    )
                statements.append(stmt)

        return "\n".join(statements)

    @classmethod
    def sync_case_graph(
        cls,
        case_id: str,
        case_name: str,
        evidence_list: List[Dict[str, Any]],
        artifacts: List[Dict[str, Any]],
        correlations: List[Dict[str, Any]],
        techniques: Optional[List[Dict[str, Any]]] = None,
        output_dir: Optional[Path] = None
    ) -> Dict[str, Any]:
        """
        Synchronizes the forensic case graph with Neo4j.
        Always outputs 'neo4j_export.cypher' in the case output directory.
        If Neo4j is actively running, executes Cypher transactions directly.
        """
        # 1. Generate full Cypher script
        cypher_script = cls.generate_cypher_export(
            case_id=case_id,
            case_name=case_name,
            evidence_list=evidence_list,
            artifacts=artifacts,
            correlations=correlations,
            techniques=techniques
        )

        # 2. Save script to disk for export/backup
        if output_dir:
            output_dir.mkdir(parents=True, exist_ok=True)
            cypher_file = output_dir / "neo4j_export.cypher"
            with open(cypher_file, "w", encoding="utf-8") as f:
                f.write(cypher_script)
            logger.info(f"[Neo4jService] Saved Cypher script to {cypher_file}")

        # 3. Attempt live sync if driver is connected
        driver = cls.get_driver()
        live_synced = False
        nodes_created = 0
        relationships_created = 0

        if driver:
            try:
                with driver.session(database=settings.NEO4J_DATABASE) as session:
                    # Execute distinct statement blocks
                    raw_blocks = [b.strip() for b in cypher_script.split(";") if b.strip()]
                    for block in raw_blocks:
                        if block.startswith("//"):
                            # Filter out comment-only blocks
                            lines = [ln for ln in block.splitlines() if not ln.strip().startswith("//")]
                            block = "\n".join(lines).strip()
                        if not block:
                            continue
                        session.run(block)
                    live_synced = True
                    logger.info(f"[Neo4jService] Successfully live-synced Case {case_id} to Neo4j database.")
            except Exception as e:
                logger.warning(f"[Neo4jService] Live sync encountered an issue: {e}. Cypher export file remains available.")

        return {
            "case_id": case_id,
            "live_synced": live_synced,
            "neo4j_status": "ONLINE" if live_synced else "OFFLINE_EXPORT_READY",
            "cypher_export_path": str(output_dir / "neo4j_export.cypher") if output_dir else None,
            "total_artifacts": len(artifacts),
            "total_correlations": len(correlations)
        }
