from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping


_OUTER_FIELDS = {
    "submit": {"schemaVersion", "action", "runRequest"},
    "status": {"schemaVersion", "action", "runId"},
    "events": {"schemaVersion", "action", "runId"},
    "request_approval": {"schemaVersion", "action", "runId", "reason"},
    "cancel": {"schemaVersion", "action", "runId"},
}
_RUN_REQUEST_FIELDS = {
    "requestId",
    "approvedBy",
    "repo",
    "prd",
    "config",
    "stateDir",
    "provider",
    "maxIterations",
}
_COUNT_FIELDS = ("truePositive", "trueNegative", "falsePositive", "falseNegative")


@dataclass(frozen=True)
class OuterCommand:
    action: str
    payload: Mapping[str, Any]


def validate_outer_command(raw: Mapping[str, Any]) -> OuterCommand:
    if not isinstance(raw, Mapping) or raw.get("schemaVersion") != 1:
        raise ValueError("outer command schemaVersion must be 1")
    action = raw.get("action")
    if action not in _OUTER_FIELDS:
        raise ValueError("outer command action is not permitted")
    unknown_root = set(raw) - _OUTER_FIELDS[action]
    if unknown_root:
        raise ValueError(f"outer command contains unsupported fields: {sorted(unknown_root)}")
    missing_root = _OUTER_FIELDS[action] - set(raw)
    if missing_root:
        raise ValueError(f"outer command is missing required fields: {sorted(missing_root)}")
    payload: dict[str, Any] = {}
    if action == "submit":
        request = raw.get("runRequest")
        if not isinstance(request, Mapping):
            raise ValueError("submit requires a runRequest object")
        unknown = set(request) - _RUN_REQUEST_FIELDS
        if unknown:
            raise ValueError(f"runRequest contains unsupported fields: {sorted(unknown)}")
        for required in ("requestId", "approvedBy"):
            if not isinstance(request.get(required), str) or not request[required].strip():
                raise ValueError(f"runRequest {required} must be a non-empty string")
        if "maxIterations" in request and (
            not isinstance(request["maxIterations"], int)
            or isinstance(request["maxIterations"], bool)
            or request["maxIterations"] <= 0
        ):
            raise ValueError("runRequest maxIterations must be a positive integer")
        for key, value in request.items():
            if key != "maxIterations" and (not isinstance(value, str) or not value.strip()):
                raise ValueError(f"runRequest {key} must be a non-empty string")
        payload["runRequest"] = MappingProxyType(dict(request))
    else:
        run_id = raw.get("runId")
        if not isinstance(run_id, str) or not run_id.strip():
            raise ValueError(f"{action} requires a non-empty runId")
        payload["runId"] = run_id
        if action == "request_approval":
            reason = raw.get("reason")
            if not isinstance(reason, str) or not reason.strip():
                raise ValueError("request_approval requires a non-empty reason")
            payload["reason"] = reason
    return OuterCommand(action, MappingProxyType(payload))


def _ratio(numerator: int, denominator: int) -> float | None:
    return None if denominator == 0 else numerator / denominator


def build_accuracy_report(raw: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(raw, Mapping):
        raise ValueError("benchmark observations must be an object")
    allowed = {"labelSource", "sampleCount", *_COUNT_FIELDS}
    unknown = set(raw) - allowed
    if unknown:
        raise ValueError(f"benchmark observations contain unsupported fields: {sorted(unknown)}")
    label_source = raw.get("labelSource")
    if not isinstance(label_source, str) or not label_source.strip():
        raise ValueError("an independent labelSource is required")
    sample_count = raw.get("sampleCount")
    if not isinstance(sample_count, int) or isinstance(sample_count, bool) or sample_count <= 0:
        raise ValueError("sampleCount must be a positive integer")
    counts: dict[str, int] = {}
    for field in _COUNT_FIELDS:
        value = raw.get(field)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError(f"{field} must be a non-negative integer")
        counts[field] = value
    if sum(counts.values()) != sample_count:
        raise ValueError("sampleCount must equal the sum of the four labeled counts")
    tp = counts["truePositive"]
    tn = counts["trueNegative"]
    fp = counts["falsePositive"]
    fn = counts["falseNegative"]
    return {
        "schemaVersion": 1,
        "labelSource": label_source,
        "counts": {"sampleCount": sample_count, **counts},
        "metrics": {
            "accuracy": _ratio(tp + tn, sample_count),
            "precision": _ratio(tp, tp + fp),
            "recall": _ratio(tp, tp + fn),
            "falsePositiveRate": _ratio(fp, fp + tn),
            "falseNegativeRate": _ratio(fn, fn + tp),
        },
    }
