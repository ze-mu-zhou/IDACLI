"""Explicit cache and index layer for long IDA AI sessions."""

from __future__ import annotations

import copy
import hashlib
import importlib
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
_BADADDR = (1 << 64) - 1
# Every field is optional and compared only when both sides have it, so keys may
# be appended: snapshots written before a key existed store nothing for it and
# keep loading. When changing this, obey _check_fingerprint's None-skip rule.
_FINGERPRINT_KEYS = ("root_filename", "input_md5", "input_size")


class CacheError(RuntimeError):
    """Raised when cached data cannot satisfy the exact requested operation."""


class IDACache:
    """Build explicit indexes over an injected IDA-shaped helper or provider."""

    __slots__ = (
        "_ambiguous_names",
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
        self._stale_reason: str | None = "cache has not been refreshed"
        self._generation = 0
        self._refreshed_at_ns: int | None = None
        self._functions: list[dict[str, Any]] = []
        self._function_starts: list[int] = []
        self._name_to_address: dict[str, int] = {}
        self._ambiguous_names: dict[str, list[int]] = {}
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
            name_to_address, ambiguous_names = self._load_names(functions, imports)
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
        self._ambiguous_names = ambiguous_names
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
        return _clone_flat_rows(self._functions)

    def name_to_address(self) -> dict[str, int]:
        """Return the cached name-to-address index of unambiguous names."""

        self._ensure_fresh()
        return dict(self._name_to_address)

    @property
    def ambiguous_names(self) -> dict[str, list[int]]:
        """Return names excluded from resolution for mapping to multiple addresses.

        Duplicate names are a normal property of binaries (same-named
        functions, or a function sharing its name with an import thunk), so
        they never fail ``refresh``; instead the name is dropped from
        ``name_to_address`` and recorded here with sorted candidate
        addresses. Imports register only their ``module!name`` qualified
        form, but their bare name still marks a same-named function
        ambiguous rather than silently resolving to the function.
        """

        self._ensure_fresh()
        return _clone(self._ambiguous_names)

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
        return function.copy()  # _normalize_function guarantees a flat row

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
            return cached.copy()  # _normalize_decompile guarantees a flat row
        decompile = _method(self._provider, "decompile")
        record = _normalize_decompile(decompile(function_ea), function_ea)
        self._decompile_cache[function_ea] = record
        return record.copy()  # _normalize_decompile guarantees a flat row

    def export(self) -> dict[str, Any]:
        """Return the JSON-compatible artifact payload for the cache snapshot."""

        return self._export_payload(detach=True)

    def _export_payload(self, *, detach: bool) -> dict[str, Any]:
        """Build the export payload, copying the indexes only when handed out.

        ``detach=False`` is for callers that serialize the payload and drop
        it (export_artifact, save_persistent): a full defensive copy of every
        index is pure waste there, and it is the single most expensive step
        of save_cache on a large database. Public ``export()`` keeps the copy
        because its result belongs to the caller.
        """

        self._ensure_fresh()
        return {
            "schema": _EXPORT_SCHEMA,
            "version": _EXPORT_VERSION,
            "generation": self._generation,
            "refreshed_at_ns": self._refreshed_at_ns,
            "stale": False,
            "counts": self._counts(),
            "functions": _clone_flat_rows(self._functions) if detach else self._functions,
            "name_to_address": dict(self._name_to_address),
            "address_to_function": _function_ranges(self._functions),
            "string_refs": _clone(self._string_refs) if detach else self._string_refs,
            "import_refs": _clone(self._import_refs) if detach else self._import_refs,
            "call_edges": _clone(self._call_edges) if detach else self._call_edges,
            "decompile_cache": _sorted_decompile(self._decompile_cache),
        }

    def export_artifact(self, writer: Any, name: str = "cache/index.json") -> dict[str, Any]:
        """Write the cache export through an injected artifact writer."""

        payload = self._export_payload(detach=False)
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
            "fingerprint": _database_fingerprint(self._provider),
            "payload": self._export_payload(detach=False),  # serialized immediately, never handed out
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

    def load_persistent(self, path: str | os.PathLike[str], *, force: bool = False) -> dict[str, Any]:
        """Load a previously persisted cache snapshot without querying IDA.

        Snapshots carry a best-effort database fingerprint; a mismatch is
        refused unless ``force=True``. When either side lacks fingerprint
        data the load is allowed, and legacy envelopes without a fingerprint
        key keep loading.
        """

        target = _persistent_path(path)
        data = target.read_bytes()
        try:
            wrapper = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CacheError(f"persistent cache is not valid JSON: {target}") from exc
        payload = _persistent_payload(wrapper)
        self._check_fingerprint(wrapper.get("fingerprint"), force=force)
        self._load_export(payload)
        return {
            "path": str(target),
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "status": self.status(),
        }

    def _check_fingerprint(self, stored: Any, *, force: bool) -> None:
        """Refuse snapshots captured from a different database unless forced."""

        if force or stored is None:
            return
        saved = _normalize_fingerprint(stored)
        current = _database_fingerprint(self._provider)
        mismatched = [
            key
            for key in _FINGERPRINT_KEYS
            if saved.get(key) is not None and current.get(key) is not None and saved[key] != current[key]
        ]
        if mismatched:
            raise CacheError(f"persistent cache database fingerprint mismatch: {', '.join(mismatched)}")

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
        # Persisted snapshots predate ambiguity tracking; ambiguous names are simply absent from the stored map.
        self._ambiguous_names = {}
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

    def _load_names(
        self, functions: list[dict[str, Any]], imports: list[dict[str, Any]]
    ) -> tuple[dict[str, int], dict[str, list[int]]]:
        """Load deterministic name resolution from functions, names, and imports.

        Duplicate names are a normal property of binaries, not corrupted
        data: any name mapping to multiple distinct addresses is excluded
        from the resolution table and returned in the ambiguous map with
        sorted candidate addresses. Imports register only their
        ``module!name`` qualified form; their bare name never resolves but
        still marks a same-named function ambiguous, so resolving an import
        by name can never silently return the function's address.
        """

        candidates: dict[str, set[int]] = {}
        for function in functions:
            _add_name_candidate(candidates, function.get("name"), int(function["ea"]))
        if hasattr(self._provider, "names"):
            for row in _records(_method(self._provider, "names")(), "names"):
                name, ea = _normalize_name(row)
                _add_name_candidate(candidates, name, ea)
        for record in imports:
            _add_name_candidate(candidates, _qualified_import_name(record), int(record["ea"]))
        index, ambiguous = _resolve_name_candidates(candidates)
        import_bare: dict[str, set[int]] = {}
        for record in imports:
            _add_name_candidate(import_bare, record.get("name"), int(record["ea"]))
        for name, eas in import_bare.items():
            addresses = set(eas)
            existing = index.get(name)
            if existing is not None:
                addresses.add(existing)
            addresses.update(ambiguous.get(name, ()))
            if len(addresses) > 1:
                index.pop(name, None)
                ambiguous[name] = sorted(addresses)
        return dict(sorted(index.items())), dict(sorted(ambiguous.items()))

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
            return _method(self._provider, "function_xrefs_from")(function.copy())
        if hasattr(self._provider, "function_items") and hasattr(self._provider, "xrefs_from"):
            return _flatten_function_item_xrefs(self._provider, function)
        raise CacheError("call edge cache requires function_xrefs_from or function_items plus xrefs_from")

    def _resolve_ea(self, ea_or_name: int | str) -> int:
        """Resolve an address or cached name using only refreshed indexes."""

        if isinstance(ea_or_name, bool):
            raise CacheError("boolean values are not valid addresses")
        if isinstance(ea_or_name, int):
            return self._checked_ea(ea_or_name)
        if not isinstance(ea_or_name, str):
            raise CacheError(f"unsupported address type: {type(ea_or_name).__name__}")
        text = ea_or_name.strip()
        if not text:
            raise CacheError("empty address/name cannot be resolved")
        value: int | None = None
        try:
            value = int(text, 0)
        except ValueError:
            try:
                # Accept leading-zero decimals; future changes must keep name lookup as the final fallback.
                value = int(text, 10)
            except ValueError:
                if text in self._name_to_address:
                    return self._checked_ea(self._name_to_address[text])
                candidates = self._ambiguous_names.get(text)
                if candidates is not None:
                    choices = ", ".join(f"0x{ea:x}" for ea in candidates)
                    raise CacheError(
                        f"name {text!r} is ambiguous in refreshed cache; candidates: {choices}"
                    ) from None
                raise CacheError(f"name is not present in refreshed cache: {text!r}") from None
        return self._checked_ea(value)

    def _checked_ea(self, ea: int) -> int:
        """Reject negative and BADADDR-sentinel addresses like sibling resolvers."""

        if ea < 0 or ea == _BADADDR:
            raise CacheError(f"invalid effective address: {ea!r}")
        return ea

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


def load_persistent_cache(provider: Any, path: str | os.PathLike[str], *, force: bool = False) -> IDACache:
    """Create a cache and hydrate it from a persistent snapshot."""

    cache = IDACache(provider)
    cache.load_persistent(path, force=force)
    return cache


def _database_fingerprint(provider: Any) -> dict[str, Any]:
    """Return a best-effort fingerprint of the database behind a provider.

    Both legs run through _normalize_fingerprint so the stored and current
    sides are always the same shape (str or None); _check_fingerprint
    compares them with ``!=``, so an int on one side and its str form on
    the other would read as a mismatch.

    The content hash is deliberately not the only discriminator: the input
    file size costs one netnode read and already separates two same-named
    binaries when a loader never recorded a hash. The input *path* is not
    recorded on purpose -- copying or re-analyzing a binary from another
    directory would then demand ``force=`` for a database that genuinely
    matches.
    """

    # Prefer provider-reported identity; future changes must stay None-safe without IDA modules.
    hook = getattr(provider, "fingerprint", None)
    if callable(hook):
        return _normalize_fingerprint(hook())
    return _normalize_fingerprint(
        {
            "root_filename": _optional_ida_value("ida_nalt", "get_root_filename"),
            # idc.get_input_md5 does not exist in IDA 9; the hashes live in
            # ida_nalt and return raw bytes. Getting this name wrong is silent
            # (the field just stays None), which is exactly how the md5 leg of
            # this fingerprint stayed dead and let a snapshot from another
            # binary of the same base name load.
            "input_md5": _optional_ida_hex("ida_nalt", "retrieve_input_file_md5"),
            "input_size": _optional_ida_positive_int("ida_nalt", "retrieve_input_file_size"),
        }
    )


def _ida_call(module_name: str, attr: str) -> Any:
    """Call one zero-argument IDA getter, returning None when unavailable.

    Import failure, a renamed or missing attribute, and a raising getter are
    all "this session cannot compute the field". Callers must keep that
    None-safe: a field the current session cannot produce is skipped by
    _check_fingerprint, never treated as a mismatch.
    """

    try:
        module = importlib.import_module(module_name)
    except ImportError:
        return None
    getter = getattr(module, attr, None)
    if not callable(getter):
        return None
    try:
        return getter()
    except Exception:  # noqa: BLE001 - optional IDA getters expose no stable exception contract.
        return None


def _optional_ida_value(module_name: str, attr: str) -> str | None:
    """Return one IDA module scalar attribute as text, or None when unavailable."""

    value = _ida_call(module_name, attr)
    return None if value is None else str(value)


def _optional_ida_hex(module_name: str, attr: str) -> str | None:
    """Return one IDA module hash attribute as lowercase hex, or None.

    A bytes-aware sibling of _optional_ida_value rather than a change to it:
    the hash getters return raw bytes, and str() on those yields a Python
    repr (``b'\\xab...'``) that would be persisted verbatim. Empty bytes mean
    the database never recorded the hash, which is "unavailable" rather than
    "the empty hash".
    """

    value = _ida_call(module_name, attr)
    if isinstance(value, (bytes, bytearray)):
        return value.hex() if value else None
    if isinstance(value, str):
        # Tolerate a build that already hands back hex text; anything else has
        # no defined fingerprint form and is dropped instead of guessed at.
        return value.strip().lower() or None
    return None


def _optional_ida_positive_int(module_name: str, attr: str) -> str | None:
    """Return one positive IDA integer attribute as text, or None.

    Zero and negatives are IDA's "not recorded" answers -- with no database
    loaded, IDA 9's retrieve_input_file_size() returns 0 -- and a sentinel
    must read as unavailable, not as a real value: a snapshot that stored a
    0 size would otherwise be refused by every session able to measure the
    real one, which is exactly the refusal this fingerprint must not make.
    """

    value = _ida_call(module_name, attr)
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        return None
    return str(value)


def _normalize_fingerprint(value: Any) -> dict[str, Any]:
    """Return a JSON-safe fingerprint dict with optional string fields.

    Empty text collapses to None on both the stored and the current side, so
    a field IDA answered with "" is skipped as unavailable rather than
    compared against a session that knows the real value.
    """

    if not isinstance(value, Mapping):
        raise CacheError("persistent cache fingerprint must be an object")
    return {key: _optional_str(value.get(key)) for key in _FINGERPRINT_KEYS}


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
    for item_ea in _records(_method(provider, "function_items")(function.copy()), "function_items"):
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


def _add_name_candidate(candidates: dict[str, set[int]], name: Any, ea: int) -> None:
    """Record one candidate address for a name, ignoring empty names."""

    text = _optional_str(name)
    if text is None:
        return
    candidates.setdefault(text, set()).add(ea)


def _resolve_name_candidates(candidates: dict[str, set[int]]) -> tuple[dict[str, int], dict[str, list[int]]]:
    """Split name candidates into unambiguous resolutions and sorted ambiguous lists."""

    index: dict[str, int] = {}
    ambiguous: dict[str, list[int]] = {}
    for name, eas in candidates.items():
        if len(eas) == 1:
            index[name] = next(iter(eas))
        else:
            ambiguous[name] = sorted(eas)
    return index, ambiguous


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

    return [cache[key].copy() for key in sorted(cache)]


def _clone(value: Any) -> Any:
    """Return a defensive copy so callers cannot mutate cache internals.

    Everything reaching this walker is already JSON-shaped -- dicts with
    string keys, lists, and immutable scalars -- because every entry point
    runs through the _normalize_* helpers or JSON decoding. That lets it
    beat copy.deepcopy by ~3x: no memo table, no __reduce_ex__ dispatch,
    C-level dict.copy for the container itself, and no recursion at all
    into the scalar leaves that dominate these records.
    """

    kind = type(value)
    if kind is dict:
        copied = value.copy()
        for key, item in copied.items():
            item_kind = type(item)
            if item_kind is dict or item_kind is list:
                copied[key] = _clone(item)
        return copied
    if kind is list:
        return [_clone(item) for item in value]
    if kind in _IMMUTABLE_LEAF_TYPES:
        return value
    # Anything else (tuple, set, a dict subclass, an IDA object that slipped
    # through) is not part of the JSON contract; fall back rather than hand
    # out a shared reference.
    return copy.deepcopy(value)


_IMMUTABLE_LEAF_TYPES = frozenset({str, int, float, bool, type(None)})


def _clone_flat_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Copy rows that _normalize_* guarantees are flat dicts of scalars.

    Only for indexes whose every write path is normalized (functions and
    decompile records, on both refresh and persistent load). A shallow
    per-row copy is then a complete defensive copy, and skipping the value
    scan is another ~3x on top of _clone. Indexes hydrated by _json_records
    keep the generic walker because a hand-written snapshot may nest.
    """

    return [row.copy() for row in rows]


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
