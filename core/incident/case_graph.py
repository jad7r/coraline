"""Deterministic case graph projection for Coreline incidents.

The graph is not authoritative state. It is rebuilt from IncidentWorkspace
records and can be discarded without losing incident information.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Tuple


NODE_TYPES = ("EVIDENCE", "OBSERVATION", "CLAIM", "ACTION", "DECISION", "SUBJECT")
EDGE_TYPES = (
    "SUPPORTS",
    "JUSTIFIES",
    "INFORMS",
    "SUBJECT_OF",
    "TARGET_OF",
    "CONSIDERED_IN",
    "SUPERSEDES",
)

VALID_EDGES = {
    ("EVIDENCE", "SUPPORTS", "OBSERVATION"),
    ("EVIDENCE", "SUPPORTS", "ACTION"),
    ("EVIDENCE", "SUPPORTS", "DECISION"),
    ("OBSERVATION", "SUPPORTS", "CLAIM"),
    ("OBSERVATION", "SUPPORTS", "ACTION"),
    ("OBSERVATION", "SUPPORTS", "DECISION"),
    ("CLAIM", "JUSTIFIES", "ACTION"),
    ("CLAIM", "SUPPORTS", "DECISION"),
    ("ACTION", "INFORMS", "DECISION"),
    ("SUBJECT", "SUBJECT_OF", "OBSERVATION"),
    ("SUBJECT", "SUBJECT_OF", "CLAIM"),
    ("SUBJECT", "TARGET_OF", "ACTION"),
    ("SUBJECT", "CONSIDERED_IN", "DECISION"),
    ("DECISION", "SUPERSEDES", "DECISION"),
}


@dataclass(frozen=True)
class CaseGraphNode:
    node_id: str
    node_type: str
    record_id: str
    label: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "node_type": self.node_type,
            "record_id": self.record_id,
            "label": self.label,
        }


@dataclass(frozen=True)
class CaseGraphEdge:
    edge_id: str
    source: str
    target: str
    relationship: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "edge_id": self.edge_id,
            "source": self.source,
            "target": self.target,
            "relationship": self.relationship,
        }


@dataclass(frozen=True)
class CaseGraph:
    incident_id: str
    nodes: Tuple[CaseGraphNode, ...]
    edges: Tuple[CaseGraphEdge, ...]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "nodes": [node.to_dict() for node in self.nodes],
            "edges": [edge.to_dict() for edge in self.edges],
            "summary": self.summary(),
        }

    def summary(self) -> Dict[str, int]:
        counts = {node_type.lower(): 0 for node_type in NODE_TYPES}
        for node in self.nodes:
            counts[node.node_type.lower()] = counts.get(node.node_type.lower(), 0) + 1
        counts["relationships"] = len(self.edges)
        return counts

    def verify(self) -> Tuple[bool, List[str]]:
        errors: List[str] = []
        node_ids = set()
        node_types: Dict[str, str] = {}
        for node in self.nodes:
            if node.node_id in node_ids:
                errors.append(f"{node.node_id}: duplicate graph node")
            node_ids.add(node.node_id)
            if node.node_type not in NODE_TYPES:
                errors.append(f"{node.node_id}: invalid node type {node.node_type}")
            node_types[node.node_id] = node.node_type
        edge_ids = set()
        for edge in self.edges:
            if edge.edge_id in edge_ids:
                errors.append(f"{edge.edge_id}: duplicate graph edge")
            edge_ids.add(edge.edge_id)
            if edge.relationship not in EDGE_TYPES:
                errors.append(f"{edge.edge_id}: invalid edge type {edge.relationship}")
            if edge.source not in node_ids:
                errors.append(f"{edge.edge_id}: dangling source {edge.source}")
            if edge.target not in node_ids:
                errors.append(f"{edge.edge_id}: dangling target {edge.target}")
            if edge.source in node_types and edge.target in node_types:
                spec = (node_types[edge.source], edge.relationship, node_types[edge.target])
                if spec not in VALID_EDGES:
                    errors.append(f"{edge.edge_id}: invalid edge {spec}")
        return not errors, errors

    def trace(
        self,
        record_id: str,
        *,
        direction: str = "both",
        max_depth: int | None = None,
    ) -> "CaseGraphTrace":
        """Return the deterministic relationship subgraph around one record.

        ``upstream`` follows incoming edges toward supporting records,
        ``downstream`` follows outgoing edges toward dependent records, and
        ``both`` follows either direction. The root is always included.
        """
        normalized_direction = direction.lower()
        if normalized_direction not in {"upstream", "downstream", "both"}:
            raise ValueError(f"invalid trace direction: {direction}")
        if max_depth is not None and max_depth < 0:
            raise ValueError("max depth must be zero or greater")

        exact = [
            node for node in self.nodes
            if node.node_id == record_id or node.record_id == record_id
        ]
        if not exact:
            raise ValueError(f"record not found in case graph: {record_id}")
        if len(exact) > 1:
            raise ValueError(f"ambiguous record in case graph: {record_id}")
        root = exact[0]

        outgoing: Dict[str, List[CaseGraphEdge]] = {}
        incoming: Dict[str, List[CaseGraphEdge]] = {}
        for edge in self.edges:
            outgoing.setdefault(edge.source, []).append(edge)
            incoming.setdefault(edge.target, []).append(edge)

        seen = {root.node_id}
        frontier = [(root.node_id, 0)]
        traced_edge_ids = set()
        while frontier:
            node_id, depth = frontier.pop(0)
            if max_depth is not None and depth >= max_depth:
                continue
            candidates: List[Tuple[CaseGraphEdge, str]] = []
            if normalized_direction in {"downstream", "both"}:
                candidates.extend((edge, edge.target) for edge in outgoing.get(node_id, ()))
            if normalized_direction in {"upstream", "both"}:
                candidates.extend((edge, edge.source) for edge in incoming.get(node_id, ()))
            for edge, adjacent in sorted(candidates, key=lambda item: item[0].edge_id):
                traced_edge_ids.add(edge.edge_id)
                if adjacent not in seen:
                    seen.add(adjacent)
                    frontier.append((adjacent, depth + 1))

        return CaseGraphTrace(
            incident_id=self.incident_id,
            root=root,
            direction=normalized_direction,
            max_depth=max_depth,
            nodes=tuple(node for node in self.nodes if node.node_id in seen),
            edges=tuple(edge for edge in self.edges if edge.edge_id in traced_edge_ids),
        )


@dataclass(frozen=True)
class CaseGraphTrace:
    incident_id: str
    root: CaseGraphNode
    direction: str
    max_depth: int | None
    nodes: Tuple[CaseGraphNode, ...]
    edges: Tuple[CaseGraphEdge, ...]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "root": self.root.to_dict(),
            "direction": self.direction,
            "max_depth": self.max_depth,
            "nodes": [node.to_dict() for node in self.nodes],
            "edges": [edge.to_dict() for edge in self.edges],
        }


def _node_id(node_type: str, record_id: str) -> str:
    return f"{node_type}:{record_id}"


def _edge_id(source: str, relationship: str, target: str) -> str:
    return f"{source}--{relationship}-->{target}"


def _node(node_type: str, record_id: str, label: str) -> CaseGraphNode:
    return CaseGraphNode(
        node_id=_node_id(node_type, record_id),
        node_type=node_type,
        record_id=record_id,
        label=label,
    )


def _edge(source: str, relationship: str, target: str) -> CaseGraphEdge:
    return CaseGraphEdge(
        edge_id=_edge_id(source, relationship, target),
        source=source,
        target=target,
        relationship=relationship,
    )


def _dedupe_edges(edges: Iterable[CaseGraphEdge]) -> Tuple[CaseGraphEdge, ...]:
    by_id = {edge.edge_id: edge for edge in edges}
    return tuple(by_id[key] for key in sorted(by_id))


def build_case_graph(workspace) -> CaseGraph:
    nodes: List[CaseGraphNode] = []
    edges: List[CaseGraphEdge] = []

    for item in workspace.evidence_items():
        nodes.append(_node("EVIDENCE", item.sha256, item.path))
    for subject in workspace.subjects():
        nodes.append(_node("SUBJECT", subject.subject_id, subject.display_name or subject.value))
    for obs in workspace.observations():
        nodes.append(_node("OBSERVATION", obs.observation_id, obs.text))
        obs_node = _node_id("OBSERVATION", obs.observation_id)
        for sha in obs.evidence:
            edges.append(_edge(_node_id("EVIDENCE", sha), "SUPPORTS", obs_node))
        for subject_id in obs.subjects:
            edges.append(_edge(_node_id("SUBJECT", subject_id), "SUBJECT_OF", obs_node))
    for claim in workspace.claims():
        nodes.append(_node("CLAIM", claim.claim_id, claim.text))
        claim_node = _node_id("CLAIM", claim.claim_id)
        for observation_id in claim.observations:
            edges.append(_edge(_node_id("OBSERVATION", observation_id), "SUPPORTS", claim_node))
        for subject_id in claim.subjects:
            edges.append(_edge(_node_id("SUBJECT", subject_id), "SUBJECT_OF", claim_node))
    for action in workspace.actions():
        nodes.append(_node("ACTION", action.action_id, action.description))
        action_node = _node_id("ACTION", action.action_id)
        for claim_id in action.claims:
            edges.append(_edge(_node_id("CLAIM", claim_id), "JUSTIFIES", action_node))
        for observation_id in action.observations:
            edges.append(_edge(_node_id("OBSERVATION", observation_id), "SUPPORTS", action_node))
        for sha in action.evidence:
            edges.append(_edge(_node_id("EVIDENCE", sha), "SUPPORTS", action_node))
        for subject_id in action.subjects:
            edges.append(_edge(_node_id("SUBJECT", subject_id), "TARGET_OF", action_node))
    for decision in workspace.decisions():
        nodes.append(_node("DECISION", decision.decision_id, decision.statement))
        decision_node = _node_id("DECISION", decision.decision_id)
        for action_id in decision.actions:
            edges.append(_edge(_node_id("ACTION", action_id), "INFORMS", decision_node))
        for claim_id in decision.claims:
            edges.append(_edge(_node_id("CLAIM", claim_id), "SUPPORTS", decision_node))
        for observation_id in decision.observations:
            edges.append(_edge(_node_id("OBSERVATION", observation_id), "SUPPORTS", decision_node))
        for sha in decision.evidence:
            edges.append(_edge(_node_id("EVIDENCE", sha), "SUPPORTS", decision_node))
        for subject_id in decision.subjects:
            edges.append(_edge(_node_id("SUBJECT", subject_id), "CONSIDERED_IN", decision_node))
    for amendment in workspace.decision_amendments():
        if amendment.amendment_type == "SUPERSEDE" and amendment.supersedes:
            edges.append(
                _edge(
                    _node_id("DECISION", amendment.supersedes),
                    "SUPERSEDES",
                    _node_id("DECISION", amendment.decision_id),
                )
            )

    ordered_nodes = tuple(sorted(nodes, key=lambda node: (node.node_type, node.record_id)))
    return CaseGraph(
        incident_id=workspace.incident_id,
        nodes=ordered_nodes,
        edges=_dedupe_edges(edges),
    )
