"""Explicit cache and index layer for long IDA AI sessions."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import time
from bisect import bisect_right
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

_EXPORT_SCHEMA = "ida-cli-cache-index-v1"
_EXPORT_VERSION = 1
_PERSIST_KIND = "ida-cli-cache-persistent-v1"


class CacheError(RuntimeError):
    """Raised when cached data cannot satisfy the exact requested operation."""


class IDACache:
    """Build explicit indexes over an injected IDA-shaped helper or provider."""

    __slots__ = (
        "_call_edges",
        "_decompile_cache",
        "_function_starts",
        "_functions",
        "_generation",
        "_import_refs",
        "_name_to_address",
        "_provider",
        "_refreshed_at_ns",
        "_stale",
        "_stale_reason",
        "_string_refs",
    )

    def __init__(self, provider: Any) -> None:
        # Keep IDA optional; future changes must preserve injected provider tests.
        self._provider = provider
        # Start stale; future changes must never auto-refresh on first read.
        self._stale = True
        self._stale_reason = "cache has not been refreshed"
        self._generation = 0
        self._refreshed_at_ns: int | None = None
        self._functions: list[dict[str, Any]] = []
        self._function_starts: list[int] = []
        self._name_to_address: dict[str, int] = {}
        self._string_refs: list[dict[str, Any]] = []
        self._import_refs: list[dict[str, Any]] = []
        self._call_edges: list[dict[str, Any]] = []
        self._decompile_cache: dict[int, dict[str, Any]] = {}

    @property
    def is_stale(self) -> bool:
        """Return whether cached indexes are unavailable until refresh."""

        return self._stale

    def status(self) -> dict[str, Any]:
        """Return JSON-compatible cache freshness and count metadata."""

        return {
            "generation": self._generation,
            "refreshed_at_ns": self._refreshed_at_ns,
            "stale": self._stale,
            "stale_reason": self._stale_reason,
            "counts": self._counts(),
        }

    def mark_stale(self, reason: str) -> dict[str, Any]:
        """Mark all indexes stale until the caller explicitly refreshes."""

        if not isinstance(reason, str) or not reason.strip():
            raise CacheError("stale reason must be a non-empty string")
        # Clear lazy code; future changes must not serve decompile text across mutations.
        self._decompile_cache.clear()
        self._stale = True
        self._stale_reason = reason
        return self.status()

    def refresh(self) -> dict[str, Any]:
        """Rebuild non-lazy indexes from the provider in one explicit step."""

        started = time.perf_counter_ns()
        try:
            functions = self._load_functions()
            imports = self._load_imports()
            strings = self._load_strings()
            name_to_address = self._load_names(functions, imports)
            function_starts = [int(item["ea"]) for item in functions]
            string_refs = self._load_string_refs(strings, functions, function_starts)
            import_refs = self._load_import_refs(imports, functions, function_starts)
            call_edges = self._load_call_edges(functions, function_starts)
        except Exception as exc:
            self._stale = True
            self._stale_reason = f"refresh failed: {exc}"
            raise

        # Commit only complete snapshots; future changes must not expose partial refreshes.
        self._functions = functions
        self._function_starts = function_starts
        self._name_to_address = name_to_address
        self._string_refs = string_refs
        self._import_refs = import_refs
        self._call_edges = call_edges
        self._decompile_cache.clear()
        self._generation += 1
        self._refreshed_at_ns = time.time_ns()
        self._stale = False
        self._stale_reason = None
        status = self.status()
        status["elapsed_ms"] = (time.perf_counter_ns() - started) // 1_000_000
        return status

    def functions(self) -> list[dict[str, Any]]:
        """Return the cached function index."""

        self._ensure_fresh()
        return _clone(self._functions)

    def name_to_address(self) -> dict[str, int]:
        """Return the cached name-to-address index."""

        self._ensure_fresh()
        return dict(self._name_to_address)

    def get_ea(self, ea_or_name: int | str) -> int:
        """Resolve an integer, hex string, or cached name without provider calls."""

        self._ensure_fresh()
        return self._resolve_ea(ea_or_name)

    def address_to_function(self, ea_or_name: int | str) -> dict[str, Any]:
        """Return the cached containing function for an address or name."""

        self._ensure_fresh()
        ea = self._resolve_ea(ea_or_name)
        function = self._function_for_ea(ea)
        if function is None:
            raise CacheError(f"no cached function contains 0x{ea:x}")
        return _clone(function)

    def string_refs(self) -> list[dict[str, Any]]:
        """Return cached string records with incoming xrefs and ref functions."""

        self._ensure_fresh()
        return _clone(self._string_refs)

    def import_refs(self) -> list[dict[str, Any]]:
        """Return cached import records with incoming xrefs and ref functions."""

        self._ensure_fresh()
        return _clone(self._import_refs)

    def call_edges(self, ea_or_name: int | str | None = None) -> list[dict[str, Any]]:
        """Return cached call edges, optionally filtered by caller function."""

        self._ensure_fresh()
        if ea_or_name is None:
            return _clone(self._call_edges)
        caller = self.address_to_function(ea_or_name)
        caller_ea = int(caller["ea"])
        return _clone([edge for edge in self._call_edges if int(edge["caller"]) == caller_ea])

    def decompile(self, ea_or_name: int | str) -> dict[str, Any]:
        """Return cached pseudocode, lazily decompiling only the requested function."""

        self._ensure_fresh()
        function = self.address_to_function(ea_or_name)
        function_ea = int(function["ea"])
        cached = self._decompile_cache.get(function_ea)
        if cached is not None:
            return _clone(cached)
        decompile = _method(self._provider, "decompile")
        record = _normalize_decompile(decompile(function_ea), function_ea)
        self._decompile_cache[function_ea] = record
        return _clone(record)

    def export(self) -> dict[str, Any]:
        """Return the JSON-compatible artifact payload for the cache snapshot."""

        self._ensure_fresh()
        return {
            "schema": _EXPORT_SCHEMA,
            "version": _EXPORT_VERSION,
            "generation": self._generation,
            "refreshed_at_ns": self._refreshed_at_ns,
            "stale": False,
            "counts": self._counts(),
            "functions": _clone(self._functions),
            "name_to_address": dict(self._name_to_address),
            "address_to_function": _function_ranges(self._functions),
            "string_refs": _clone(self._string_refs),
            "import_refs": _clone(self._import_refs),
            "call_edges": _clone(self._call_edges),
            "decompile_cache": _sorted_decompile(self._decompile_cache),
        }

    def export_artifact(self, writer: Any, name: str = "cache/index.json") -> dict[str, Any]:
        """Write the cache export through an injected artifact writer."""

        payload = self.export()
        if hasattr(writer, "write_json"):
            artifact = writer.write_json(name, payload)
        elif hasattr(writer, "write_artifact"):
            artifact = writer.write_artifact(name, payload)
        else:
            raise CacheError("artifact writer requires write_json or write_artifact")
        return {
            "schema": _EXPORT_SCHEMA,
            "version": _EXPORT_VERSION,
            "generation": self._generation,
            "counts": payload["counts"],
            "artifact": artifact,
        }

    def save_persistent(self, path: str | os.PathLike[str]) -> dict[str, Any]:
        """Persist the full cache snapshot to a deterministic JSON file."""

        payload = {
            "kind": _PERSIST_KIND,
            "payload": self.export(),
        }
        data = json.dumps(payload, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
        target = _persistent_path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        temp = target.with_name(f".{target.name}.tmp")
        try:
            temp.write_bytes(data)
            os.replace(temp, target)
        except Exception:
            _remove_temp(temp)
            raise
        return {"path": str(target), "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}

    def load_persistent(self, path: str | os.PathLike[str]) -> dict[str, Any]:
        """Load a previously persisted cache snapshot without querying IDA."""

        target = _persistent_path(path)
        data = target.read_bytes()
        try:
            wrapper = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CacheError(f"persistent cache is not valid JSON: {target}") from exc
        self._load_export(_persistent_payload(wrapper))
        return {
            "path": str(target),
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "status": self.status(),
        }

    def _ensure_fresh(self) -> None:
        """Reject reads from stale indexes instead of refreshing silently."""

        if self._stale:
            raise CacheError(f"cache is stale; call refresh() explicitly: {self._stale_reason}")

    def _load_export(self, payload: Mapping[str, Any]) -> None:
        """Replace current indexes from a validated export payload."""

        if payload.get("schema") != _EXPORT_SCHEMA or payload.get("version") != _EXPORT_VERSION:
            raise CacheError("persistent cache schema/version mismatch")
        functions = [_normalize_function(row) for row in _records(payload.get("functions"), "functions")]
        functions.sort(key=lambda item: int(item["ea"]))
        self._functions = functions
        self._function_starts = [int(item["ea"]) for item in functions]
        self._name_to_address = _normalize_name_map(payload.get("name_to_address"))
        self._string_refs = _json_records(payload.get("string_refs"), "string_refs")
        self._import_refs = _json_records(payload.get("import_refs"), "import_refs")
        self._call_edges = _json_records(payload.get("call_edges"), "call_edges")
        self._decompile_cache = _decompile_map(payload.get("decompile_cache"))
        self._generation = _non_negative_int(payload.get("generation"), "generation")
        self._refreshed_at_ns = _optional_non_negative_int(payload.get("refreshed_at_ns"), "refreshed_at_ns")
        self._stale = False
        self._stale_reason = None

    def _load_functions(self) -> list[dict[str, Any]]:
        """Load and validate provider function records."""

        rows = [_normalize_function(row) for row in _records(_method(self._provider, "functions")(), "functions")]
        rows.sort(key=lambda item: int(item["ea"]))
        seen: set[int] = set()
        for row in rows:
            ea = int(row["ea"])
            if ea in seen:
                raise CacheError(f"duplicate function start 0x{ea:x}")
            seen.add(ea)
        return rows

    def _load_imports(self) -> list[dict[str, Any]]:
        """Load provider imports once for names and import reference indexes."""

        return [_normalize_import(row) for row in _records(_method(self._provider, "imports")(), "imports")]

    def _load_strings(self) -> list[dict[str, Any]]:
        """Load provider strings once for string reference indexes."""

        return [_normalize_string(row) for row in _records(_method(self._provider, "strings")(), "strings")]

    def _load_names(self, functions: list[dict[str, Any]], imports: list[dict[str, Any]]) -> dict[str, int]:
        """Load deterministic name resolution from functions, names, and imports."""

        index: dict[str, int] = {}
        for function in functions:
            _add_name(index, function.get("name"), int(function["ea"]))
        if hasattr(self._provider, "names"):
            for row in _records(_method(self._provider, "names")(), "names"):
                name, ea = _normalize_name(row)
                _add_name(index, name, ea)
        for record in imports:
            _add_name(index, record.get("name"), int(record["ea"]))
            _add_name(index, _qualified_import_name(record), int(record["ea"]))
        return dict(sorted(index.items()))

    def _load_string_refs(
        self, strings: list[dict[str, Any]], functions: list[dict[str, Any]], starts: list[int]
    ) -> list[dict[str, Any]]:
        """Load strings and incoming references using the refreshed function ranges."""

        refs: list[dict[str, Any]] = []
        xrefs_to = _method(self._provider, "xrefs_to")
        for row in strings:
            string = dict(row)
            incoming = _sorted_xrefs(xrefs_to(int(string["ea"])))
            string["refs"] = incoming
            string["ref_functions"] = _ref_functions(incoming, functions, starts, "frm")
            refs.append(string)
        refs.sort(key=lambda item: int(item["ea"]))
        return refs

    def _load_import_refs(
        self, imports: list[dict[str, Any]], functions: list[dict[str, Any]], starts: list[int]
    ) -> list[dict[str, Any]]:
        """Load imports and incoming references using the refreshed function ranges."""

        refs: list[dict[str, Any]] = []
        xrefs_to = _method(self._provider, "xrefs_to")
        for row in imports:
            record = dict(row)
            incoming = _sorted_xrefs(xrefs_to(int(record["ea"])))
            record["refs"] = incoming
            record["ref_functions"] = _ref_functions(incoming, functions, starts, "frm")
            refs.append(record)
        refs.sort(key=lambda item: (str(item.get("module") or ""), str(item.get("name") or ""), int(item["ea"])))
        return refs

    def _load_call_edges(self, functions: list[dict[str, Any]], starts: list[int]) -> list[dict[str, Any]]:
        """Load function call edges without relying on stale address lookups."""

        edges: list[dict[str, Any]] = []
        seen: set[tuple[int, int, int, int | None]] = set()
        for function in functions:
            caller = int(function["ea"])
            for xref in _sorted_xrefs(self._function_xrefs(function)):
                if xref.get("iscode") is False:
                    continue
                target = int(xref["to"])
                callee = _find_function(functions, starts, target)
                edge = _call_edge(function, xref, callee)
                key = (caller, int(edge["site"]), target, edge.get("type"))
                if key in seen:
                    continue
                seen.add(key)
                edges.append(edge)
        edges.sort(key=lambda item: (int(item["caller"]), int(item["site"]), int(item["target"])))
        return edges

    def _function_xrefs(self, function: dict[str, Any]) -> Iterable[Any]:
        """Return provider xrefs for every instruction in a function."""

        if hasattr(self._provider, "function_xrefs_from"):
            return _method(self._provider, "function_xrefs_from")(_clone(function))
        if hasattr(self._provider, "function_items") and hasattr(self._provider, "xrefs_from"):
            return _flatten_function_item_xrefs(self._provider, function)
        raise CacheError("call edge cache requires function_xrefs_from or function_items plus xrefs_from")

    def _resolve_ea(self, ea_or_name: int | str) -> int:
        """Resolve an address or cached name using only refreshed indexes."""

        if isinstance(ea_or_name, bool):
            raise CacheError("boolean values are not valid addresses")
        if isinstance(ea_or_name, int):
            if ea_or_name < 0:
                raise CacheError(f"invalid effective address: {ea_or_name!r}")
            return ea_or_name
        if not isinstance(ea_or_name, str):
            raise CacheError(f"unsupported address type: {type(ea_or_name).__name__}")
        text = ea_or_name.strip()
        if not text:
            raise CacheError("empty address/name cannot be resolved")
        try:
            value = int(text, 0)
        except ValueError:
            if text not in self._name_to_address:
                raise CacheError(f"name is not present in refreshed cache: {text!r}")
            return self._name_to_address[text]
        if value < 0:
            raise CacheError(f"invalid effective address: {value!r}")
        return value

    def _function_for_ea(self, ea: int) -> dict[str, Any] | None:
        """Find the cached function range containing an effective address."""

        return _find_function(self._functions, self._function_starts, ea)

    def _counts(self) -> dict[str, int]:
        """Return compact count metadata for status and export responses."""

        return {
            "functions": len(self._functions),
            "names": len(self._name_to_address),
            "strings": len(self._string_refs),
            "imports": len(self._import_refs),
            "call_edges": len(self._call_edges),
            "decompiled": len(self._decompile_cache),
        }


def create_cache(provider: Any) -> IDACache:
    """Create a cache over an injected provider."""

    return IDACache(provider)


def load_persistent_cache(provider: Any, path: str | os.PathLike[str]) -> IDACache:
    """Create a cache and hydrate it from a persistent snapshot."""

    cache = IDACache(provider)
    cache.load_persistent(path)
    return cache


def _records(value: Any, label: str) -> list[Any]:
    """Return a finite record list and reject scalar provider mistakes."""

    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Iterable):
        raise CacheError(f"{label} provider must return an iterable of records")
    return list(value)


def _method(provider: Any, name: str) -> Any:
    """Resolve a required provider method with a precise failure."""

    method = getattr(provider, name, None)
    if method is None or not callable(method):
        raise CacheError(f"cache provider requires callable {name}()")
    return method


def _field(record: Any, name: str, *, default: Any = None) -> Any:
    """Read mapping or object fields without accepting missing required values."""

    if isinstance(record, Mapping):
        return record.get(name, default)
    return getattr(record, name, default)


def _int_field(record: Any, name: str, label: str, *, default: Any = None) -> int | None:
    """Normalize optional integer-like fields."""

    value = _field(record, name, default=default)
    if value is None:
        return None
    if isinstance(value, bool):
        raise CacheError(f"{label}.{name} must be an integer address")
    try:
        converted = int(value)
    except (TypeError, ValueError) as exc:
        raise CacheError(f"{label}.{name} must be an integer address") from exc
    if converted < 0:
        raise CacheError(f"{label}.{name} must be non-negative")
    return converted


def _normalize_function(record: Any) -> dict[str, Any]:
    """Return a compact JSON-compatible function record."""

    ea = _int_field(record, "ea", "function")
    if ea is None:
        raise CacheError("function.ea is required")
    end_ea = _int_field(record, "end_ea", "function")
    size = _int_field(record, "size", "function")
    if end_ea is None and size is not None:
        end_ea = ea + size
    if end_ea is not None and end_ea < ea:
        raise CacheError(f"function 0x{ea:x} has end before start")
    name = _optional_str(_field(record, "name"))
    return {"ea": ea, "name": name, "end_ea": end_ea, "size": None if end_ea is None else end_ea - ea}


def _normalize_string(record: Any) -> dict[str, Any]:
    """Return a compact JSON-compatible string record."""

    ea = _int_field(record, "ea", "string")
    if ea is None:
        raise CacheError("string.ea is required")
    return {
        "ea": ea,
        "length": _int_field(record, "length", "string"),
        "type": _int_field(record, "type", "string"),
        "value": _optional_str(_field(record, "value")),
    }


def _normalize_import(record: Any) -> dict[str, Any]:
    """Return a compact JSON-compatible import record."""

    ea = _int_field(record, "ea", "import")
    if ea is None:
        raise CacheError("import.ea is required")
    return {
        "ea": ea,
        "module": _optional_str(_field(record, "module")),
        "name": _optional_str(_field(record, "name")),
        "ordinal": _int_field(record, "ordinal", "import"),
    }


def _normalize_name(record: Any) -> tuple[str, int]:
    """Return a validated name-to-address pair."""

    if isinstance(record, tuple) and len(record) == 2:
        ea, name = record
    else:
        ea = _field(record, "ea")
        name = _field(record, "name")
    normalized_name = _optional_str(name)
    if normalized_name is None:
        raise CacheError("name record requires a non-empty name")
    normalized_ea = _int_field({"ea": ea}, "ea", "name")
    if normalized_ea is None:
        raise CacheError(f"name {normalized_name!r} requires an address")
    return normalized_name, normalized_ea


def _normalize_xref(record: Any) -> dict[str, Any]:
    """Return a JSON-compatible xref record."""

    frm = _int_field(record, "frm", "xref")
    target = _int_field(record, "to", "xref")
    if frm is None or target is None:
        raise CacheError("xref.frm and xref.to are required")
    result: dict[str, Any] = {"frm": frm, "to": target}
    xref_type = _int_field(record, "type", "xref")
    if xref_type is not None:
        result["type"] = xref_type
    iscode = _field(record, "iscode")
    if iscode is not None:
        result["iscode"] = bool(iscode)
    return result


def _normalize_decompile(record: Any, function_ea: int) -> dict[str, Any]:
    """Return a JSON-compatible decompile record."""

    if isinstance(record, Mapping):
        pseudocode = record.get("pseudocode")
        name = _optional_str(record.get("name"))
        ea = _int_field(record, "ea", "decompile", default=function_ea)
    else:
        pseudocode = str(record)
        name = None
        ea = function_ea
    if ea is None:
        raise CacheError("decompile.ea is required")
    if pseudocode is None:
        raise CacheError(f"decompile result at 0x{function_ea:x} has no pseudocode")
    return {"ea": ea, "name": name, "pseudocode": str(pseudocode)}


def _sorted_xrefs(value: Any) -> list[dict[str, Any]]:
    """Normalize and sort xrefs for deterministic cache artifacts."""

    refs = [_normalize_xref(row) for row in _records(value, "xrefs")]
    refs.sort(key=lambda item: (int(item["frm"]), int(item["to"]), int(item.get("type", -1))))
    return refs


def _flatten_function_item_xrefs(provider: Any, function: dict[str, Any]) -> list[Any]:
    """Collect xrefs from every provider-reported item in one function."""

    xrefs_from = _method(provider, "xrefs_from")
    refs: list[Any] = []
    for item_ea in _records(_method(provider, "function_items")(_clone(function)), "function_items"):
        ea = _int_field({"ea": item_ea}, "ea", "function_item")
        if ea is None:
            raise CacheError("function item address is required")
        refs.extend(_records(xrefs_from(ea), "xrefs_from"))
    return refs


def _call_edge(function: dict[str, Any], xref: dict[str, Any], callee: dict[str, Any] | None) -> dict[str, Any]:
    """Build one call-edge artifact row."""

    edge: dict[str, Any] = {
        "caller": int(function["ea"]),
        "caller_name": function.get("name"),
        "site": int(xref["frm"]),
        "target": int(xref["to"]),
        "callee": None if callee is None else int(callee["ea"]),
        "callee_name": None if callee is None else callee.get("name"),
        "external": callee is None,
    }
    if "type" in xref:
        edge["type"] = xref["type"]
    return edge


def _ref_functions(
    refs: list[dict[str, Any]], functions: list[dict[str, Any]], starts: list[int], address_key: str
) -> list[int]:
    """Return unique function starts that contain referenced addresses."""

    result: list[int] = []
    seen: set[int] = set()
    for ref in refs:
        function = _find_function(functions, starts, int(ref[address_key]))
        if function is None:
            continue
        ea = int(function["ea"])
        if ea not in seen:
            seen.add(ea)
            result.append(ea)
    result.sort()
    return result


def _find_function(functions: list[dict[str, Any]], starts: list[int], ea: int) -> dict[str, Any] | None:
    """Find the function interval containing an address."""

    index = bisect_right(starts, ea) - 1
    if index < 0:
        return None
    function = functions[index]
    start = int(function["ea"])
    end = function.get("end_ea")
    if end is None:
        return function if ea == start else None
    return function if start <= ea < int(end) else None


def _function_ranges(functions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return address-to-function range records for export."""

    return [
        {"start_ea": int(function["ea"]), "end_ea": function.get("end_ea"), "function_ea": int(function["ea"])}
        for function in functions
    ]


def _add_name(index: dict[str, int], name: Any, ea: int) -> None:
    """Insert one name and fail on ambiguous addresses."""

    text = _optional_str(name)
    if text is None:
        return
    existing = index.get(text)
    if existing is not None and existing != ea:
        raise CacheError(f"duplicate name {text!r} maps to both 0x{existing:x} and 0x{ea:x}")
    index[text] = ea


def _qualified_import_name(record: dict[str, Any]) -> str | None:
    """Return a module-qualified import name when both parts are known."""

    module = _optional_str(record.get("module"))
    name = _optional_str(record.get("name"))
    if module is None or name is None:
        return None
    return f"{module}!{name}"


def _optional_str(value: Any) -> str | None:
    """Normalize optional non-empty strings."""

    if value is None:
        return None
    text = str(value)
    return text if text else None


def _sorted_decompile(cache: dict[int, dict[str, Any]]) -> list[dict[str, Any]]:
    """Return deterministic lazy decompile cache rows."""

    return [_clone(cache[key]) for key in sorted(cache)]


def _clone(value: Any) -> Any:
    """Return a defensive copy so callers cannot mutate cache internals."""

    return copy.deepcopy(value)


def _persistent_path(path: str | os.PathLike[str]) -> Path:
    """Validate a persistent cache target path."""

    target = Path(path)
    if str(target) == "":
        raise CacheError("persistent cache path must not be empty")
    return target


def _persistent_payload(wrapper: Any) -> Mapping[str, Any]:
    """Return a validated persistent cache payload."""

    if not isinstance(wrapper, Mapping) or wrapper.get("kind") != _PERSIST_KIND:
        raise CacheError("persistent cache kind mismatch")
    payload = wrapper.get("payload")
    if not isinstance(payload, Mapping):
        raise CacheError("persistent cache payload must be an object")
    return payload


def _normalize_name_map(value: Any) -> dict[str, int]:
    """Validate a persistent name-to-address index."""

    if not isinstance(value, Mapping):
        raise CacheError("name_to_address must be an object")
    result: dict[str, int] = {}
    for name, ea in value.items():
        if not isinstance(name, str) or name == "":
            raise CacheError("name_to_address keys must be non-empty strings")
        normalized = _non_negative_int(ea, f"name_to_address[{name!r}]")
        result[name] = normalized
    return dict(sorted(result.items()))


def _json_records(value: Any, label: str) -> list[dict[str, Any]]:
    """Validate generic JSON object records from persistent storage."""

    records = _records(value, label)
    if not all(isinstance(record, Mapping) for record in records):
        raise CacheError(f"{label} records must be objects")
    return [dict(record) for record in records]


def _decompile_map(value: Any) -> dict[int, dict[str, Any]]:
    """Validate persisted lazy decompiler records."""

    result: dict[int, dict[str, Any]] = {}
    for record in _json_records(value, "decompile_cache"):
        normalized = _normalize_decompile(record, _non_negative_int(record.get("ea"), "decompile.ea"))
        result[int(normalized["ea"])] = normalized
    return result


def _non_negative_int(value: Any, label: str) -> int:
    """Validate non-negative integer fields from persistent cache JSON."""

    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise CacheError(f"{label} must be a non-negative integer")
    return value


def _optional_non_negative_int(value: Any, label: str) -> int | None:
    """Validate optional non-negative integer fields from persistent cache JSON."""

    return None if value is None else _non_negative_int(value, label)


def _remove_temp(path: Path) -> None:
    """Remove a temporary persistence file after a failed atomic write."""

    try:
        path.unlink()
    except FileNotFoundError:
        return


__all__ = ("CacheError", "IDACache", "create_cache", "load_persistent_cache")
