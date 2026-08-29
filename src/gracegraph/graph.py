"""Typed claim evaluation, invalidation propagation, and next-action ranking."""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from .canonical import GraceGraphError, canonical_bytes, sha256_bytes
from .inventory import evaluate_artifact
from .memory import evaluate_memory
from .models import AUTO_CLOSABLE, CLAIM_DOMAINS, COMPILER_VERSION, authority_sufficient

BAD_STATES = {"HOLD", "CONFLICTING", "REFUTED", "STALE", "MISSING", "REVIEW_REQUIRED", "INVALID"}
ALPHA_CLAIM_BOUNDARY = {
    "empirical_n": 0,
    "biological_gate_closed": False,
    "target_selected": False,
    "experiment_authorized": False,
    "release_authorized": False,
}


def _claim_order(claims: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_id = {claim["id"]: claim for claim in claims}
    visiting: set[str] = set()
    visited: set[str] = set()
    order: list[dict[str, Any]] = []

    def visit(identity: str) -> None:
        if identity in visited or identity not in by_id:
            return
        if identity in visiting:
            raise GraceGraphError(f"claim dependency cycle includes {identity}")
        visiting.add(identity)
        claim = by_id[identity]
        for dependency in (
            claim.get("requires", []) + claim.get("evidence", []) + claim.get("contradictions", [])
        ):
            visit(dependency)
        visiting.remove(identity)
        visited.add(identity)
        order.append(by_id[identity])

    for identity in sorted(by_id):
        visit(identity)
    return order


def _claim_node(
    claim: dict[str, Any], nodes: dict[str, dict[str, Any]], ceiling: str
) -> dict[str, Any]:
    domain = claim["domain"]
    required = CLAIM_DOMAINS[domain]
    declared = claim.get("declared_state", "HOLD")
    dependencies = claim.get("requires", [])
    evidence = claim.get("evidence", [])
    contradictions = claim.get("contradictions", [])
    result: dict[str, Any] = {
        "id": claim["id"],
        "node_type": "claim",
        "domain": domain,
        "claim_kind": claim["claim_kind"],
        "authority": required,
        "declared_state": declared,
        "state": "HOLD",
        "requires": dependencies,
        "evidence": evidence,
        "contradictions": contradictions,
        "reasons": [],
    }
    active_contradictions = [
        identity for identity in contradictions if nodes[identity]["state"] == "VERIFIED"
    ]
    blocked = [
        identity for identity in dependencies + evidence if nodes[identity]["state"] != "VERIFIED"
    ]
    if declared in {"REFUTED", "CONFLICTING", "INVALID"}:
        result["state"] = declared
        result["reasons"].append(f"declared state is {declared}")
    elif active_contradictions:
        result["state"] = "CONFLICTING"
        result["reasons"].append(f"verified contradiction(s): {active_contradictions}")
    elif declared != "VERIFIED":
        result["state"] = "HOLD"
        result["reasons"].append(f"claim is declared {declared}; no promotion is inferred")
    elif blocked:
        result["state"] = "HOLD"
        result["reasons"].append(f"dependency/evidence not verified: {blocked}")
    elif not evidence:
        result["state"] = "HOLD"
        result["reasons"].append("claim has no evidence nodes")
    elif domain == "BIOLOGICAL":
        result["state"] = "HOLD"
        result["disposition"] = "ABSTAIN_UNCALIBRATED"
        result["reasons"].append("empirical N=0; biological claims must abstain")
    elif domain == "COMPUTATIONAL":
        result["state"] = "REVIEW_REQUIRED"
        result["reasons"].append(
            "v1 has no registered semantic receipt adapter for computational claims"
        )
    elif required not in AUTO_CLOSABLE:
        result["state"] = "REVIEW_REQUIRED"
        result["reasons"].append(f"{required} authority cannot be closed computationally")
    elif not authority_sufficient(ceiling, required):
        result["state"] = "REVIEW_REQUIRED"
        result["reasons"].append(f"project claim ceiling {ceiling} is below {required}")
    elif any(
        not authority_sufficient(nodes[identity]["authority"], required) for identity in evidence
    ):
        result["state"] = "REVIEW_REQUIRED"
        result["reasons"].append("evidence authority is below the claim's required authority")
    else:
        result["state"] = "VERIFIED"
        result["reasons"].append("all typed dependencies and evidence are verified")
    return result


def _rank_actions(
    actions: list[dict[str, Any]], nodes: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    reverse: dict[str, set[str]] = defaultdict(set)
    for node in nodes.values():
        for dependency in (
            node.get("requires", []) + node.get("evidence", []) + node.get("contradictions", [])
        ):
            reverse[dependency].add(node["id"])

    def downstream(start: str) -> set[str]:
        found: set[str] = set()
        frontier = [start]
        while frontier:
            current = frontier.pop()
            for child in reverse.get(current, set()):
                if child not in found:
                    found.add(child)
                    frontier.append(child)
        return found

    ranked: list[dict[str, Any]] = []
    for action in actions:
        prerequisites = action.get("requires", [])
        blocked_by = [
            identity for identity in prerequisites if nodes[identity]["state"] != "VERIFIED"
        ]
        targets = action.get("resolves", [])
        unresolved = [identity for identity in targets if nodes[identity]["state"] != "VERIFIED"]
        impact_nodes = set(unresolved)
        for identity in unresolved:
            impact_nodes.update(
                child for child in downstream(identity) if nodes[child]["state"] != "VERIFIED"
            )
        cost = (
            float(action.get("effort", 1))
            + float(action.get("time", 1))
            + float(action.get("risk", 1))
        )
        eligible = not blocked_by and bool(unresolved)
        score = round(100.0 * len(impact_nodes) / max(cost, 0.001), 6) if eligible else 0.0
        ranked.append(
            {
                "id": action["id"],
                "title": action.get("title", action["id"]),
                "state": "ELIGIBLE" if eligible else "BLOCKED",
                "score": score,
                "resolves": targets,
                "blocked_by": blocked_by,
                "impact_nodes": sorted(impact_nodes),
                "cost": {field: action.get(field, 1) for field in ("effort", "time", "risk")},
                "note": "deterministic heuristic; not a proof of optimality",
            }
        )
    ranked.sort(key=lambda item: (item["state"] != "ELIGIBLE", -item["score"], item["id"]))
    for position, item in enumerate(ranked, 1):
        item["rank"] = position
    return ranked


def evaluate_spec(spec: dict[str, Any], root: Any) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, str]] = []
    for item in spec.get("artifacts", []):
        node = evaluate_artifact(root, item)
        nodes[node["id"]] = node
    for item in spec.get("memory_sources", []):
        for node in evaluate_memory(root, item):
            nodes[node["id"]] = node
            for dependency in node.get("requires", []):
                edges.append({"from": dependency, "to": node["id"], "relation": "REQUIRES"})
    for claim in _claim_order(spec.get("claims", [])):
        node = _claim_node(claim, nodes, spec["claim_ceiling"])
        nodes[node["id"]] = node
        relation_names = {
            "requires": "REQUIRES",
            "evidence": "SUPPORTS",
            "contradictions": "CONTRADICTS",
        }
        for field, relation in relation_names.items():
            for dependency in node.get(field, []):
                edges.append({"from": dependency, "to": node["id"], "relation": relation})

    node_list = sorted(nodes.values(), key=lambda item: item["id"])
    counts = Counter(node["state"] for node in node_list)
    spec_digest = sha256_bytes(canonical_bytes(spec))
    claim_boundary = dict(ALPHA_CLAIM_BOUNDARY)
    evidence_digest = sha256_bytes(
        canonical_bytes(
            {
                "spec_sha256": spec_digest,
                "nodes": node_list,
                "edges": sorted(
                    edges, key=lambda item: (item["to"], item["relation"], item["from"])
                ),
                "claim_boundary": claim_boundary,
            }
        )
    )
    return {
        "schema_version": "gracegraph.evaluation.v1",
        "run_id": evidence_digest[:16],
        "project_id": spec["project_id"],
        "compiler": {"name": "gracegraph", "version": COMPILER_VERSION},
        "spec_sha256": spec_digest,
        "evidence_sha256": evidence_digest,
        "claim_ceiling": spec["claim_ceiling"],
        "verification_scope": "STRUCTURAL_EVIDENCE_BINDING_ONLY",
        "capsule_scope": "PRIVATE_LOCAL_REPLAY",
        "claim_boundary": claim_boundary,
        "summary": {"total_nodes": len(node_list), "states": dict(sorted(counts.items()))},
        "nodes": node_list,
        "edges": sorted(edges, key=lambda item: (item["to"], item["relation"], item["from"])),
        "frontier": _rank_actions(spec.get("actions", []), nodes),
        "nonclaims": spec.get("nonclaims", []),
    }
