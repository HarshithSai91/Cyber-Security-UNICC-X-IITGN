"""
mitre_graph.py
==============
In-process MITRE ATT&CK knowledge graph for explainability and threat-linkage.

The retrieval layers answer "what documents look like this observation?". The
graph answers "how do these entities *relate*?" — the connective tissue an
analyst uses to reason: *this actor uses that technique*, *that technique is
implemented by this malware*. Surfacing those edges turns a ranked list into an
explanation ("APT29 -[uses]-> T1021.002").

Rather than stand up Neo4j (a container + a server), we load the MITRE ATT&CK
STIX 2.1 bundle straight into memory and index it as a plain adjacency graph.
For a single enterprise-attack bundle this is a few hundred milliseconds at
startup and needs zero external services — consistent with the rest of this
repo's fully-local design.

Get the bundle (once, offline) from MITRE's public CTI repo:

    enterprise-attack.json  (mitre-attack/attack-stix-data or mitre/cti)

Then::

    g = load_attack_bundle("data/mitre/enterprise-attack.json")
    g.techniques_for_actor("APT29")          # -> ['T1021.002', ...]
    g.expand(threat_actors=["APT29"], techniques=["T1021.002"])
"""

from __future__ import annotations

import json
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

logger = logging.getLogger(__name__)

# STIX object types we care about, mapped to a friendly node kind.
_TYPE_TO_KIND = {
    "intrusion-set": "actor",
    "attack-pattern": "technique",
    "malware": "malware",
    "tool": "tool",
    "course-of-action": "mitigation",
    "campaign": "campaign",
}


@dataclass
class AttackNode:
    stix_id: str
    kind: str                     # actor | technique | malware | tool | ...
    name: str
    attack_id: str = ""           # external ATT&CK id: G0016, T1021.002, S0154 …
    aliases: list[str] = field(default_factory=list)


@dataclass
class AttackEdge:
    source: str                   # stix_id
    target: str                   # stix_id
    relationship: str             # uses | mitigates | attributed-to | ...


class MitreAttackGraph:
    """Adjacency-indexed view over an ATT&CK STIX bundle."""

    def __init__(self) -> None:
        self.nodes: dict[str, AttackNode] = {}                 # stix_id -> node
        self.edges: list[AttackEdge] = []
        self._out: dict[str, list[AttackEdge]] = defaultdict(list)
        self._in: dict[str, list[AttackEdge]] = defaultdict(list)
        # lookup helpers
        self._by_attack_id: dict[str, str] = {}                # T1021.002 -> stix_id
        self._by_name: dict[str, str] = {}                     # lowercased name/alias -> stix_id

    # -- construction ------------------------------------------------------

    def add_node(self, node: AttackNode) -> None:
        self.nodes[node.stix_id] = node
        if node.attack_id:
            self._by_attack_id[node.attack_id.upper()] = node.stix_id
        for label in [node.name, *node.aliases]:
            if label:
                self._by_name[label.lower()] = node.stix_id

    def add_edge(self, edge: AttackEdge) -> None:
        # Only keep edges whose endpoints are node kinds we indexed.
        if edge.source not in self.nodes or edge.target not in self.nodes:
            return
        self.edges.append(edge)
        self._out[edge.source].append(edge)
        self._in[edge.target].append(edge)

    # -- resolution --------------------------------------------------------

    def resolve(self, identifier: str) -> str | None:
        """Map an ATT&CK id (T1021.002 / G0016) or a name/alias to a stix_id."""
        if not identifier:
            return None
        key = identifier.strip()
        if key.upper() in self._by_attack_id:
            return self._by_attack_id[key.upper()]
        return self._by_name.get(key.lower())

    def node(self, identifier: str) -> AttackNode | None:
        sid = self.resolve(identifier)
        return self.nodes.get(sid) if sid else None

    def _label(self, stix_id: str) -> str:
        n = self.nodes.get(stix_id)
        if not n:
            return stix_id
        return n.attack_id or n.name

    # -- traversal ---------------------------------------------------------

    def neighbors(
        self,
        identifier: str,
        relationship: str | None = None,
        target_kind: str | None = None,
        direction: str = "out",
    ) -> list[AttackNode]:
        """
        Return nodes adjacent to ``identifier``.

        direction : "out" (identifier is the source), "in" (identifier is the
                    target), or "both".
        relationship : filter to one relationship_type (e.g. "uses").
        target_kind : filter neighbor kind (e.g. "technique").
        """
        sid = self.resolve(identifier)
        if not sid:
            return []

        edges: list[tuple[AttackEdge, str]] = []
        if direction in ("out", "both"):
            edges += [(e, e.target) for e in self._out.get(sid, ())]
        if direction in ("in", "both"):
            edges += [(e, e.source) for e in self._in.get(sid, ())]

        out: list[AttackNode] = []
        seen: set[str] = set()
        for edge, other in edges:
            if relationship and edge.relationship != relationship:
                continue
            node = self.nodes.get(other)
            if not node or other in seen:
                continue
            if target_kind and node.kind != target_kind:
                continue
            seen.add(other)
            out.append(node)
        return out

    # -- convenience queries ----------------------------------------------

    def techniques_for_actor(self, actor: str) -> list[str]:
        """ATT&CK technique ids used by a threat actor/group."""
        return [n.attack_id for n in self.neighbors(actor, "uses", "technique") if n.attack_id]

    def malware_for_actor(self, actor: str) -> list[str]:
        """Malware/tool names attributed to a threat actor."""
        mal = self.neighbors(actor, "uses", "malware")
        tools = self.neighbors(actor, "uses", "tool")
        return [n.name for n in (*mal, *tools)]

    def actors_for_technique(self, technique: str) -> list[str]:
        """Threat actors known to use a technique (reverse of `uses`)."""
        return [
            n.name
            for n in self.neighbors(technique, "uses", "actor", direction="in")
        ]

    def actors_for_malware(self, malware: str) -> list[str]:
        return [
            n.name
            for n in self.neighbors(malware, "uses", "actor", direction="in")
        ]

    def relationship_paths(self, identifier: str, limit: int = 25) -> list[str]:
        """
        Human-readable edges out of a node, e.g. "APT29 -[uses]-> T1021.002".
        These strings are what the retrieval response surfaces for explainability.
        """
        sid = self.resolve(identifier)
        if not sid:
            return []
        src_label = self._label(sid)
        paths = [
            f"{src_label} -[{e.relationship}]-> {self._label(e.target)}"
            for e in self._out.get(sid, ())
        ]
        return paths[:limit]

    def expand(
        self,
        threat_actors: Iterable[str] = (),
        techniques: Iterable[str] = (),
        malware: Iterable[str] = (),
    ) -> dict[str, Any]:
        """
        Given entities observed in a threat, return linked ATT&CK context:
        related techniques, actors, malware, and the explanatory relationship
        strings. This is the graph hook the matching layer calls to enrich a
        candidate with STIX linkage.
        """
        linked_techniques: set[str] = set(t.upper() for t in techniques)
        linked_actors: set[str] = set()
        linked_malware: set[str] = set()
        relationships: list[str] = []

        for actor in threat_actors:
            if self.resolve(actor):
                linked_actors.add(self.node(actor).name)  # type: ignore[union-attr]
                linked_techniques.update(self.techniques_for_actor(actor))
                linked_malware.update(self.malware_for_actor(actor))
                relationships.extend(self.relationship_paths(actor))

        for tech in techniques:
            relationships.extend(self.relationship_paths(tech))
            linked_actors.update(self.actors_for_technique(tech))

        for mal in malware:
            if self.resolve(mal):
                linked_actors.update(self.actors_for_malware(mal))
                relationships.extend(self.relationship_paths(mal))

        return {
            "actors": sorted(linked_actors),
            "techniques": sorted(linked_techniques),
            "malware": sorted(linked_malware),
            "relationships": relationships,
        }

    def __repr__(self) -> str:
        return f"MitreAttackGraph(nodes={len(self.nodes)}, edges={len(self.edges)})"


# ---------------------------------------------------------------------------
# Bundle loading
# ---------------------------------------------------------------------------


def _external_attack_id(obj: dict[str, Any]) -> str:
    """Pull the ATT&CK external id (Txxxx / Gxxxx / Sxxxx) from external_references."""
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref["external_id"]
    return ""


def build_graph_from_bundle(bundle: dict[str, Any]) -> MitreAttackGraph:
    """Build a :class:`MitreAttackGraph` from a parsed STIX bundle dict."""
    g = MitreAttackGraph()
    objects = bundle.get("objects", [])

    # Pass 1 — nodes
    for obj in objects:
        otype = obj.get("type")
        kind = _TYPE_TO_KIND.get(otype)
        if kind is None:
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        aliases = obj.get("aliases", []) or obj.get("x_mitre_aliases", []) or []
        g.add_node(
            AttackNode(
                stix_id=obj["id"],
                kind=kind,
                name=obj.get("name", ""),
                attack_id=_external_attack_id(obj),
                aliases=[a for a in aliases if a],
            )
        )

    # Pass 2 — relationships
    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        if obj.get("revoked"):
            continue
        g.add_edge(
            AttackEdge(
                source=obj.get("source_ref", ""),
                target=obj.get("target_ref", ""),
                relationship=obj.get("relationship_type", ""),
            )
        )

    logger.info("Loaded MITRE ATT&CK graph — %r", g)
    return g


def load_attack_bundle(path: str | Path) -> MitreAttackGraph:
    """Load and index an ATT&CK STIX bundle from a local JSON file."""
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(
            f"ATT&CK STIX bundle not found at {path}. Download enterprise-attack.json "
            "from MITRE's attack-stix-data repo and point config at it."
        )
    with path.open("r", encoding="utf-8") as fh:
        bundle = json.load(fh)
    return build_graph_from_bundle(bundle)
