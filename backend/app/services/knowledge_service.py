"""
H-MACFR Knowledge Service — MITRE ATT&CK STIX 2.1 ChromaDB Ingestion & Retrieval Engine.
Maintains an authoritative, reproducible vector knowledge base of MITRE ATT&CK Enterprise techniques.
Ensures 100% idempotent ingestion, metadata tracking, and semantic search.
"""

import os
import json
import hashlib
import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

import chromadb
from chromadb.config import Settings

logger = logging.getLogger("hmacfr.knowledge_service")

BACKEND_DIR = Path(__file__).resolve().parents[2]
DEFAULT_KNOWLEDGE_DIR = BACKEND_DIR / "knowledge_base" / "mitre"
DEFAULT_CHROMA_DIR = BACKEND_DIR / "knowledge_base" / "chroma_db"
COLLECTION_NAME = "mitre_attack_enterprise"


class KnowledgeService:
    """
    Service for ingesting, managing, and retrieving MITRE ATT&CK STIX 2.1 objects
    stored in a local persistent ChromaDB vector store.
    """

    _client: Optional[chromadb.PersistentClient] = None
    _collection = None

    @classmethod
    def get_chroma_client(cls, chroma_dir: Optional[Path] = None) -> chromadb.PersistentClient:
        """
        Returns or initializes the persistent ChromaDB client.
        """
        target_dir = Path(chroma_dir or DEFAULT_CHROMA_DIR)
        target_dir.mkdir(parents=True, exist_ok=True)
        if cls._client is None or getattr(cls._client, "_target_dir", None) != str(target_dir):
            cls._client = chromadb.PersistentClient(
                path=str(target_dir),
                settings=Settings(anonymized_telemetry=False, allow_reset=True)
            )
            setattr(cls._client, "_target_dir", str(target_dir))
        return cls._client

    @classmethod
    def get_collection(cls, chroma_dir: Optional[Path] = None):
        """
        Returns the persistent ChromaDB collection for MITRE ATT&CK Enterprise techniques.
        """
        client = cls.get_chroma_client(chroma_dir)
        try:
            return client.get_or_create_collection(
                name=COLLECTION_NAME,
                metadata={"description": "Authoritative MITRE ATT&CK Enterprise STIX 2.1 Knowledge Base"}
            )
        except Exception as e:
            logger.error(f"Error getting ChromaDB collection: {e}")
            raise

    @classmethod
    def get_source_metadata(cls, knowledge_dir: Optional[Path] = None) -> Dict[str, Any]:
        """
        Reads source metadata (URL, retrieval date, version, hash) for the ATT&CK dataset.
        """
        meta_file = Path(knowledge_dir or DEFAULT_KNOWLEDGE_DIR) / "source_metadata.json"
        if meta_file.exists():
            with open(meta_file, "r", encoding="utf-8") as f:
                return json.load(f)
        return {
            "source_url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
            "stix_version": "2.1",
            "status": "UNINITIALIZED"
        }

    @classmethod
    def load_stix_bundle(cls, stix_path: Optional[Path] = None) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Loads the STIX 2.1 JSON bundle from disk and computes its cryptographic hash.
        """
        target_path = Path(stix_path or (DEFAULT_KNOWLEDGE_DIR / "enterprise-attack.json"))
        if not target_path.exists():
            raise FileNotFoundError(f"MITRE STIX 2.1 dataset not found at: {target_path}")

        with open(target_path, "rb") as f:
            raw_bytes = f.read()

        file_hash = hashlib.sha256(raw_bytes).hexdigest()
        bundle = json.loads(raw_bytes.decode("utf-8"))
        objects = bundle.get("objects", [])

        meta = {
            "file_path": str(target_path),
            "file_size_bytes": len(raw_bytes),
            "sha256_hash": file_hash,
            "total_objects": len(objects)
        }
        return objects, meta

    @classmethod
    def parse_attack_techniques(cls, objects: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Filters and normalizes active (non-revoked, non-deprecated) ATT&CK attack patterns.
        """
        techniques = []
        for obj in objects:
            if obj.get("type") != "attack-pattern":
                continue

            # Filter revoked and deprecated objects
            if obj.get("revoked", False) or obj.get("x_mitre_deprecated", False):
                continue

            stix_id = obj.get("id")
            name = obj.get("name", "Unknown Technique")
            description = obj.get("description", "")
            is_subtechnique = obj.get("x_mitre_is_subtechnique", False)
            version = obj.get("x_mitre_version", "1.0")
            platforms = obj.get("x_mitre_platforms", [])

            # Extract external technique ID (e.g., T1055, T1055.001)
            ext_refs = obj.get("external_references", [])
            technique_id = None
            url = None
            for ref in ext_refs:
                if ref.get("source_name") == "mitre-attack":
                    technique_id = ref.get("external_id")
                    url = ref.get("url")
                    break

            if not technique_id:
                # Skip objects without a valid MITRE ATT&CK technique identifier
                continue

            # Extract kill-chain phases (tactics)
            tactics = []
            for phase in obj.get("kill_chain_phases", []):
                if phase.get("kill_chain_name") == "mitre-attack":
                    tactics.append(phase.get("phase_name"))

            techniques.append({
                "technique_id": technique_id,
                "stix_id": stix_id,
                "name": name,
                "description": description,
                "tactics": tactics,
                "tactics_str": ", ".join(tactics) if tactics else "unknown",
                "is_subtechnique": is_subtechnique,
                "version": str(version),
                "platforms": ", ".join(platforms) if platforms else "Windows, Linux, macOS",
                "url": url or f"https://attack.mitre.org/techniques/{technique_id}"
            })

        return techniques

    @classmethod
    def ingest_mitre_attack(
        cls,
        stix_path: Optional[Path] = None,
        chroma_dir: Optional[Path] = None,
        batch_size: int = 100
    ) -> Dict[str, Any]:
        """
        Ingests all active MITRE ATT&CK techniques into ChromaDB idempotently using upsert.
        Rerunning this method updates existing records without creating duplicates.
        """
        objects, file_meta = cls.load_stix_bundle(stix_path)
        techniques = cls.parse_attack_techniques(objects)

        collection = cls.get_collection(chroma_dir)
        total_techniques = len(techniques)

        # Batch upsert into ChromaDB
        for i in range(0, total_techniques, batch_size):
            batch = techniques[i:i + batch_size]
            ids = [t["technique_id"] for t in batch]
            # Form rich text representation for semantic embeddings
            documents = [
                f"{t['technique_id']}: {t['name']} (Tactics: {t['tactics_str']}). Platforms: {t['platforms']}.\n{t['description']}"
                for t in batch
            ]
            metadatas = [
                {
                    "technique_id": t["technique_id"],
                    "stix_id": t["stix_id"],
                    "name": t["name"],
                    "tactics": t["tactics_str"],
                    "is_subtechnique": bool(t["is_subtechnique"]),
                    "version": t["version"],
                    "platforms": t["platforms"],
                    "url": t["url"],
                    "ingested_at": datetime.now(timezone.utc).isoformat()
                }
                for t in batch
            ]
            # upsert guarantees idempotence (updates if exists, inserts if new)
            collection.upsert(ids=ids, documents=documents, metadatas=metadatas)

        stats = {
            "status": "SUCCESS",
            "ingested_count": total_techniques,
            "collection_count": collection.count(),
            "file_sha256": file_meta["sha256_hash"],
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        logger.info(f"Ingested {total_techniques} active MITRE ATT&CK techniques. Total in store: {stats['collection_count']}")
        return stats

    @classmethod
    def search_techniques(
        cls,
        query: str,
        n_results: int = 5,
        tactic_filter: Optional[str] = None,
        chroma_dir: Optional[Path] = None
    ) -> List[Dict[str, Any]]:
        """
        Performs semantic vector search across MITRE ATT&CK techniques in ChromaDB.
        """
        collection = cls.get_collection(chroma_dir)
        count = collection.count()
        if count == 0:
            return []

        where_clause = None
        if tactic_filter:
            where_clause = {"tactics": {"$contains": tactic_filter.lower()}}

        k = min(n_results, count)
        results = collection.query(
            query_texts=[query],
            n_results=k,
            where=where_clause
        )

        matches = []
        if results and results.get("ids") and results["ids"][0]:
            ids = results["ids"][0]
            docs = results["documents"][0] if results.get("documents") else []
            metas = results["metadatas"][0] if results.get("metadatas") else []
            distances = results["distances"][0] if results.get("distances") else []

            for idx in range(len(ids)):
                meta = metas[idx] if idx < len(metas) else {}
                dist = distances[idx] if idx < len(distances) else 1.0
                similarity = round(max(0.0, 1.0 - (dist / 2.0)), 4)
                matches.append({
                    "technique_id": ids[idx],
                    "name": meta.get("name", "Unknown"),
                    "tactics": meta.get("tactics", ""),
                    "platforms": meta.get("platforms", ""),
                    "url": meta.get("url", ""),
                    "similarity_score": similarity,
                    "excerpt": docs[idx][:250] + "..." if idx < len(docs) else ""
                })

        return matches

    @classmethod
    def get_technique_by_id(cls, technique_id: str, chroma_dir: Optional[Path] = None) -> Optional[Dict[str, Any]]:
        """
        Exact primary key lookup for a technique ID (e.g. T1055 or T1055.001).
        """
        collection = cls.get_collection(chroma_dir)
        clean_id = technique_id.upper().strip()
        res = collection.get(ids=[clean_id])
        if res and res.get("ids") and len(res["ids"]) > 0:
            meta = res["metadatas"][0] if res.get("metadatas") else {}
            doc = res["documents"][0] if res.get("documents") else ""
            return {
                "technique_id": clean_id,
                "name": meta.get("name"),
                "stix_id": meta.get("stix_id"),
                "tactics": meta.get("tactics"),
                "url": meta.get("url"),
                "platforms": meta.get("platforms"),
                "version": meta.get("version"),
                "document": doc
            }
        return None
