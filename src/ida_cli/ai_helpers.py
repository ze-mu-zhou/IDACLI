"""AI convenience helpers for unrestricted IDAPython sessions."""

from __future__ import annotations

import hashlib
import importlib
import json
import time
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any


class AIHelperError(RuntimeError):
    """Raised when an AI helper cannot satisfy the exact requested operation."""


_MAX_BYTE_READ = 1 << 20
_MAX_OPERAND_INDEX = 7
_DANGEROUS_IMPORTS = frozenset(
    ("gets", "printf", "scanf", "sprintf", "strcpy", "strcat", "system", "read", "write", "mprotect")
)
_SUSPICIOUS_NAME_PARTS = ("backdoor", "shell", "win", "flag", "gift", "vuln")
_SUSPICIOUS_STRING_PARTS = ("/bin/sh", "flag", "cat ", "sh\x00")


class AIHelpers:
    """Small JSON-compatible helper layer over raw IDAPython modules."""

    def __init__(
        self,
        artifact_dir: str | Path | None = None,
        *,
        modules: Mapping[str, Any] | None = None,
        auto_import: bool = True,
    ) -> None:
        # Keep artifact IO available outside IDA; when changing this, obey path containment checks.
        self._artifact_dir = Path(artifact_dir) if artifact_dir is not None else Path.cwd() / "artifacts"
        # Keep tests deterministic by allowing injected modules; when changing this, obey lazy import semantics.
        self._modules = dict(modules) if modules is not None else {}
        self._auto_import = auto_import
        from .cache import IDACache
        from .mutations import DatabaseMutations

        # Keep helper groups on the same AI object; when changing this, obey unrestricted raw-IDAPython access.
        self.mutations = DatabaseMutations(modules=self._modules, auto_import=auto_import)
        self.cache = IDACache(self)

    def functions(self) -> list[dict[str, Any]]:
        """Return known functions as JSON-compatible records."""

        idautils = self._require_module("idautils")
        return [self._function_record(int(ea)) for ea in idautils.Functions()]

    def get_ea(self, ea_or_name: int | str) -> int:
        """Resolve an integer address or IDA name into an effective address."""

        if isinstance(ea_or_name, bool):
            raise AIHelperError("boolean values are not valid addresses")
        if isinstance(ea_or_name, int):
            return self._checked_ea(ea_or_name)
        if not isinstance(ea_or_name, str):
            raise AIHelperError(f"unsupported address type: {type(ea_or_name).__name__}")

        text = ea_or_name.strip()
        if not text:
            raise AIHelperError("empty address/name cannot be resolved")
        try:
            return self._checked_ea(int(text, 0))
        except ValueError:
            pass

        ea = self._name_ea(text)
        if ea == self._badaddr():
            raise AIHelperError(f"cannot resolve IDA name: {text!r}")
        return self._checked_ea(ea)

    def function(self, ea_or_name: int | str) -> dict[str, Any]:
        """Return the containing IDA function for an address or name."""

        ea = self.get_ea(ea_or_name)
        ida_funcs = self._require_module("ida_funcs")
        func = ida_funcs.get_func(ea)
        if func is None:
            raise AIHelperError(f"no function contains 0x{ea:x}")
        return self._function_record(int(getattr(func, "start_ea")), func)

    def decompile(self, ea_or_name: int | str) -> dict[str, Any]:
        """Return Hex-Rays pseudocode and never fall back to disassembly."""

        ea = self.get_ea(ea_or_name)
        decompiler = self._decompiler()
        try:
            cfunc = decompiler(ea)
        except Exception as exc:  # pragma: no cover - exact IDA exception types vary.
            raise AIHelperError(f"decompile failed at 0x{ea:x}: {exc}") from exc
        if cfunc is None:
            raise AIHelperError(f"decompile returned no result at 0x{ea:x}")
        return {"ea": ea, "name": self._name_or_none(ea), "pseudocode": str(cfunc)}

    def disasm(self, ea_or_name: int | str, limit: int = 64) -> list[dict[str, Any]]:
        """Return bounded disassembly lines starting at an address or name."""

        count = self._checked_limit(limit, "limit")
        ea = self.get_ea(ea_or_name)
        idc = self._require_module("idc")
        records: list[dict[str, Any]] = []
        cursor = ea
        for _ in range(count):
            line = self._disasm_line(idc, cursor)
            records.append({"ea": cursor, "line": line})
            next_ea = self._next_item_ea(cursor)
            if next_ea == self._badaddr() or next_ea <= cursor:
                break
            cursor = next_ea
        return records

    def xrefs(self, ea_or_name: int | str) -> dict[str, list[dict[str, Any]]]:
        """Return incoming and outgoing xrefs for an address or name."""

        ea = self.get_ea(ea_or_name)
        return {"to": self.xrefs_to(ea), "from": self.xrefs_from(ea)}

    def xrefs_to(self, ea_or_name: int | str) -> list[dict[str, Any]]:
        """Return xrefs targeting an address or name."""

        ea = self.get_ea(ea_or_name)
        idautils = self._require_module("idautils")
        return [self._xref_record(xref) for xref in idautils.XrefsTo(ea)]

    def xrefs_from(self, ea_or_name: int | str) -> list[dict[str, Any]]:
        """Return xrefs originating at an address or name."""

        ea = self.get_ea(ea_or_name)
        idautils = self._require_module("idautils")
        return [self._xref_record(xref) for xref in idautils.XrefsFrom(ea)]

    def strings(self, string_limit: int | None = None) -> list[dict[str, Any]]:
        """Return IDA string records up to an optional bounded limit."""

        max_items = None if string_limit is None else self._checked_limit(string_limit, "string_limit", allow_zero=True)
        idautils = self._require_module("idautils")
        records: list[dict[str, Any]] = []
        for item in idautils.Strings():
            if max_items is not None and len(records) >= max_items:
                break
            records.append(
                {
                    "ea": int(getattr(item, "ea")),
                    "length": self._optional_int(item, "length"),
                    "type": self._optional_int(item, "type"),
                    "value": str(item),
                }
            )
        return records

    def imports(self) -> list[dict[str, Any]]:
        """Return imported symbols grouped by the source import module name."""

        ida_nalt = self._require_module("ida_nalt")
        records: list[dict[str, Any]] = []
        for module_index in range(int(ida_nalt.get_import_module_qty())):
            module_name = ida_nalt.get_import_module_name(module_index)
            if module_name is None:
                raise AIHelperError(f"import module {module_index} has no name")

            def collect(ea: int, name: str | None, ordinal: int | None) -> bool:
                records.append(
                    {
                        "module": module_name,
                        "ea": int(ea),
                        "name": name,
                        "ordinal": None if ordinal is None else int(ordinal),
                    }
                )
                return True

            if ida_nalt.enum_import_names(module_index, collect) is False:
                raise AIHelperError(f"failed to enumerate imports for {module_name!r}")
        return records

    def segments(self) -> list[dict[str, Any]]:
        """Return loaded IDA segments with bounds and compact metadata."""

        idautils = self._require_module("idautils")
        if not hasattr(idautils, "Segments"):
            raise AIHelperError("segment enumeration requires idautils.Segments")
        return [self._segment_record(int(ea)) for ea in idautils.Segments()]

    def entries(self) -> list[dict[str, Any]]:
        """Return IDA entry points and exports as JSON-compatible records."""

        idautils = self._optional_module("idautils")
        if idautils is not None and hasattr(idautils, "Entries"):
            return [self._entry_record(item) for item in idautils.Entries()]
        ida_entry = self._require_module("ida_entry")
        records: list[dict[str, Any]] = []
        for index in range(int(ida_entry.get_entry_qty())):
            ordinal = int(ida_entry.get_entry_ordinal(index))
            records.append(
                self._entry_record(
                    {
                        "index": index,
                        "ordinal": ordinal,
                        "ea": int(ida_entry.get_entry(ordinal)),
                        "name": ida_entry.get_entry_name(ordinal),
                    }
                )
            )
        return records

    def exports(self) -> list[dict[str, Any]]:
        """Alias IDA's entry/export enumeration for concise AI code."""

        return self.entries()

    def names(self) -> list[dict[str, Any]]:
        """Return named addresses when IDA exposes `idautils.Names`."""

        idautils = self._optional_module("idautils")
        if idautils is None or not hasattr(idautils, "Names"):
            return []
        return [{"ea": int(ea), "name": str(name)} for ea, name in idautils.Names()]

    def bytes_at(self, ea_or_name: int | str, size: int) -> dict[str, Any]:
        """Return a bounded byte window as JSON-safe integers and hex."""

        ea = self.get_ea(ea_or_name)
        count = self._checked_byte_size(size)
        payload = self._read_bytes(ea, count)
        return {"ea": ea, "size": count, "bytes": list(payload), "hex": payload.hex()}

    def bytes_hex(self, ea_or_name: int | str, size: int) -> dict[str, Any]:
        """Return a bounded byte window as compact hex."""

        ea = self.get_ea(ea_or_name)
        count = self._checked_byte_size(size)
        return {"ea": ea, "size": count, "hex": self._read_bytes(ea, count).hex()}

    def item_size(self, ea_or_name: int | str) -> dict[str, Any]:
        """Return IDA's item size at one address."""

        ea = self.get_ea(ea_or_name)
        ida_bytes = self._require_module("ida_bytes")
        if not hasattr(ida_bytes, "get_item_size"):
            raise AIHelperError("item size lookup requires ida_bytes.get_item_size")
        return {"ea": ea, "size": int(ida_bytes.get_item_size(ea))}

    def comments(self, ea_or_name: int | str) -> dict[str, Any]:
        """Return repeatable and non-repeatable comments at an address."""

        ea = self.get_ea(ea_or_name)
        return {
            "ea": ea,
            "nonrepeatable": self._comment_at(ea, False),
            "repeatable": self._comment_at(ea, True),
        }

    def type_at(self, ea_or_name: int | str) -> dict[str, Any]:
        """Return the printed type at an address, or None when IDA has none."""

        ea = self.get_ea(ea_or_name)
        return {"ea": ea, "type": self._type_at(ea)}

    def operand_value(self, ea_or_name: int | str, index: int) -> dict[str, Any]:
        """Return IDA's numeric operand value for one operand slot."""

        ea = self.get_ea(ea_or_name)
        operand_index = self._checked_operand_index(index)
        idc = self._require_module("idc")
        if not hasattr(idc, "get_operand_value"):
            raise AIHelperError("operand value lookup requires idc.get_operand_value")
        return {"ea": ea, "index": operand_index, "value": int(idc.get_operand_value(ea, operand_index))}

    def function_bounds(self, ea_or_name: int | str) -> dict[str, Any]:
        """Alias containing-function lookup for explicit bound queries."""

        return self.function(ea_or_name)

    def callers(self, ea_or_name: int | str) -> list[dict[str, Any]]:
        """Return incoming xrefs annotated with their containing functions."""

        return self._xref_endpoint_records(self.xrefs_to(ea_or_name), "frm")

    def callees(self, ea_or_name: int | str) -> list[dict[str, Any]]:
        """Return outgoing function xrefs annotated with their target functions."""

        return self._xref_endpoint_records(self.function_xrefs_from(self.function(ea_or_name)), "to")

    def basic_blocks(self, ea_or_name: int | str) -> list[dict[str, Any]]:
        """Return basic blocks for the containing function."""

        return self.cfg(ea_or_name)["blocks"]

    def cfg(self, ea_or_name: int | str) -> dict[str, Any]:
        """Return a compact FlowChart CFG for the containing function."""

        ea = self.get_ea(ea_or_name)
        ida_funcs = self._require_module("ida_funcs")
        func = ida_funcs.get_func(ea)
        if func is None:
            raise AIHelperError(f"no function contains 0x{ea:x}")
        ida_gdl = self._require_module("ida_gdl")
        if not hasattr(ida_gdl, "FlowChart"):
            raise AIHelperError("CFG enumeration requires ida_gdl.FlowChart")
        return self._cfg_record(func, ida_gdl.FlowChart(func))

    def demangle(self, name_or_ea: int | str, flags: int = 0) -> dict[str, Any]:
        """Return IDA's demangled form for a symbol name or named address."""

        symbol = self._symbol_text(name_or_ea)
        demangled = self._demangle_symbol(symbol, flags)
        return {"input": symbol, "demangled": demangled}

    def function_items(self, ea_or_function: int | str | Mapping[str, Any]) -> list[int]:
        """Return item addresses for the containing function."""

        if isinstance(ea_or_function, Mapping):
            ea = int(ea_or_function["ea"])
        else:
            ea = int(self.function(ea_or_function)["ea"])
        idautils = self._require_module("idautils")
        if not hasattr(idautils, "FuncItems"):
            raise AIHelperError("function item enumeration requires idautils.FuncItems")
        return [int(item_ea) for item_ea in idautils.FuncItems(ea)]

    def function_xrefs_from(self, ea_or_function: int | str | Mapping[str, Any]) -> list[dict[str, Any]]:
        """Return outgoing xrefs from every item in one function."""

        refs: list[dict[str, Any]] = []
        for item_ea in self.function_items(ea_or_function):
            refs.extend(self.xrefs_from(item_ea))
        return refs

    def context_pack(
        self,
        ea_or_name: int | str,
        *,
        disasm_limit: int = 32,
        include_decompile: bool = False,
    ) -> dict[str, Any]:
        """Return a compact evidence bundle for follow-up AI reasoning."""

        ea = self.get_ea(ea_or_name)
        pack: dict[str, Any] = {
            "ea": ea,
            "function": self.function(ea),
            "disasm": self.disasm(ea, disasm_limit),
            "xrefs_to": self.xrefs_to(ea),
            "xrefs_from": self.xrefs_from(ea),
        }
        if include_decompile:
            pack["decompile"] = self.decompile(ea)
        return pack

    def write_artifact(self, name: str, value: Any) -> dict[str, Any]:
        """Write a JSON, JSONL, text, or binary artifact and return metadata."""

        started = time.perf_counter_ns()
        target = self._artifact_path(name, value)
        payload, artifact_format, count = self._artifact_payload(target, value)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
        elapsed_ms = (time.perf_counter_ns() - started) // 1_000_000
        return {
            "artifact": str(target),
            "format": artifact_format,
            "bytes": len(payload),
            "count": count,
            "sha256": hashlib.sha256(payload).hexdigest(),
            "elapsed_ms": elapsed_ms,
        }

    def propose_rename(self, ea_or_name: int | str, new_name: str, flags: int = 0) -> dict[str, Any]:
        """Return a proposed rename without mutating the database."""

        return self.mutations.propose_rename(ea_or_name, new_name, flags)

    def rename(self, ea_or_name: int | str, new_name: str, flags: int = 0) -> dict[str, Any]:
        """Rename an address and mark cached indexes stale."""

        result = self.mutations.rename(ea_or_name, new_name, flags)
        self.cache.mark_stale("rename applied")
        return result

    def propose_comment(self, ea_or_name: int | str, comment: str, *, repeatable: bool = False) -> dict[str, Any]:
        """Return a proposed comment without mutating the database."""

        return self.mutations.propose_comment(ea_or_name, comment, repeatable=repeatable)

    def set_comment(self, ea_or_name: int | str, comment: str, *, repeatable: bool = False) -> dict[str, Any]:
        """Set a comment and mark cached indexes stale."""

        result = self.mutations.set_comment(ea_or_name, comment, repeatable=repeatable)
        self.cache.mark_stale("comment applied")
        return result

    def set_repeatable_comment(self, ea_or_name: int | str, comment: str) -> dict[str, Any]:
        """Set a repeatable comment and mark cached indexes stale."""

        return self.set_comment(ea_or_name, comment, repeatable=True)

    def set_nonrepeatable_comment(self, ea_or_name: int | str, comment: str) -> dict[str, Any]:
        """Set a non-repeatable comment and mark cached indexes stale."""

        return self.set_comment(ea_or_name, comment, repeatable=False)

    def propose_type(self, ea_or_name: int | str, declaration: str, flags: int = 0) -> dict[str, Any]:
        """Return a proposed type application without mutating the database."""

        return self.mutations.propose_type(ea_or_name, declaration, flags)

    def apply_type(self, ea_or_name: int | str, declaration: str, flags: int = 0) -> dict[str, Any]:
        """Apply a type and mark cached indexes stale."""

        result = self.mutations.apply_type(ea_or_name, declaration, flags)
        self.cache.mark_stale("type applied")
        return result

    def propose_patch_bytes(self, ea_or_name: int | str, data: bytes | bytearray | memoryview | str) -> dict[str, Any]:
        """Return a proposed byte patch without mutating the database."""

        return self.mutations.propose_patch_bytes(ea_or_name, data)

    def patch_bytes(self, ea_or_name: int | str, data: bytes | bytearray | memoryview | str) -> dict[str, Any]:
        """Patch bytes and mark cached indexes stale."""

        result = self.mutations.patch_bytes(ea_or_name, data)
        self.cache.mark_stale("bytes patched")
        return result

    def patch_byte(self, ea_or_name: int | str, value: int) -> dict[str, Any]:
        """Patch one byte and mark cached indexes stale."""

        result = self.mutations.patch_byte(ea_or_name, value)
        self.cache.mark_stale("byte patched")
        return result

    def propose_save_database(self, path: str | None = None, flags: int = 0) -> dict[str, Any]:
        """Return a proposed explicit database save operation."""

        return self.mutations.propose_save_database(path, flags)

    def save_database(self, path: str | None = None, flags: int = 0) -> dict[str, Any]:
        """Save the database explicitly without hidden side effects."""

        return self.mutations.save_database(path, flags)

    def save(self, path: str | None = None, flags: int = 0) -> dict[str, Any]:
        """Alias explicit database save for concise AI code."""

        return self.save_database(path, flags)

    def refresh_cache(self) -> dict[str, Any]:
        """Explicitly rebuild the cache indexes."""

        return self.cache.refresh()

    def cache_status(self) -> dict[str, Any]:
        """Return cache freshness and count metadata."""

        return self.cache.status()

    def mark_cache_stale(self, reason: str) -> dict[str, Any]:
        """Mark cache indexes stale with an explicit reason."""

        return self.cache.mark_stale(reason)

    def cached_functions(self) -> list[dict[str, Any]]:
        """Return cached function records."""

        return self.cache.functions()

    def cached_name_to_address(self) -> dict[str, int]:
        """Return cached name-to-address records."""

        return self.cache.name_to_address()

    def cached_address_to_function(self, ea_or_name: int | str) -> dict[str, Any]:
        """Return cached containing-function metadata."""

        return self.cache.address_to_function(ea_or_name)

    def cached_string_refs(self) -> list[dict[str, Any]]:
        """Return cached string reference records."""

        return self.cache.string_refs()

    def cached_import_refs(self) -> list[dict[str, Any]]:
        """Return cached import reference records."""

        return self.cache.import_refs()

    def cached_call_edges(self, ea_or_name: int | str | None = None) -> list[dict[str, Any]]:
        """Return cached call graph edges."""

        return self.cache.call_edges(ea_or_name)

    def cached_decompile(self, ea_or_name: int | str) -> dict[str, Any]:
        """Return lazy cached decompiler output."""

        return self.cache.decompile(ea_or_name)

    def export_cache(self, name: str = "cache/index.json") -> dict[str, Any]:
        """Write cache indexes through this helper's artifact writer."""

        return self.cache.export_artifact(self, name)

    def save_cache(self, path: str | Path) -> dict[str, Any]:
        """Persist cache indexes for reuse across independent runs."""

        return self.cache.save_persistent(path)

    def load_cache(self, path: str | Path) -> dict[str, Any]:
        """Load persisted cache indexes without querying IDA."""

        return self.cache.load_persistent(path)

    def merge_changes(self, changes: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
        """Merge mutation records and report deterministic conflicts."""

        from .conflicts import merge_changes

        return merge_changes(changes)

    def merge_change_sets(self, change_sets: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
        """Merge branch change sets and report deterministic conflicts."""

        from .conflicts import merge_change_sets

        return merge_change_sets(change_sets)

    def focus(
        self,
        targets: int | str | Iterable[int | str],
        *,
        disasm_limit: int = 64,
        include_decompile: bool = True,
    ) -> dict[str, Any]:
        """Return compact evidence for named targets without dumping the whole database."""

        target_values = (targets,) if isinstance(targets, (int, str)) else tuple(targets)
        if not target_values:
            raise AIHelperError("focus targets must not be empty")
        records: dict[str, Any] = {}
        for target in target_values:
            ea = self.get_ea(target)
            key = str(target)
            record = {"ea": ea, "function": self.function(ea), "disasm": self.disasm(ea, disasm_limit)}
            if include_decompile:
                try:
                    record["decompile"] = self.decompile(ea)
                except Exception as exc:  # pragma: no cover - exact IDA errors vary.
                    record["decompile_error"] = f"{type(exc).__name__}: {exc}"
            records[key] = record
        return {"count": len(records), "targets": records}

    def inventory_summary(self, *, function_limit: int = 16, string_limit: int = 16) -> dict[str, Any]:
        """Return a small triage summary instead of full noisy inventories."""

        functions = self.functions()
        imports = self.imports()
        strings = self.strings(string_limit)
        names = self.names()
        return {
            "counts": {
                "functions": len(functions),
                "imports": len(imports),
                "names": len(names),
                "strings_sampled": len(strings),
            },
            "dangerous_imports": _dangerous_imports(imports),
            "interesting_functions": _interesting_symbols(functions + names, function_limit),
            "string_hits": _interesting_strings(strings),
            "functions": functions[: self._checked_limit(function_limit, "function_limit", allow_zero=True)],
        }

    def export_inventory(self, prefix: str = "inventory", *, string_limit: int | None = None) -> dict[str, Any]:
        """Write common inventories as artifacts and return only metadata."""

        base = _artifact_prefix(prefix)
        strings = self.strings(string_limit)
        summary = self.inventory_summary(string_limit=0)
        return {
            "summary": self.write_artifact(f"{base}/summary.json", summary),
            "functions": self.write_artifact(f"{base}/functions.jsonl", self.functions()),
            "imports": self.write_artifact(f"{base}/imports.jsonl", self.imports()),
            "names": self.write_artifact(f"{base}/names.jsonl", self.names()),
            "strings": self.write_artifact(f"{base}/strings.jsonl", strings),
        }

    def pwn_overview(self, *, string_limit: int = 64, function_limit: int = 32) -> dict[str, Any]:
        """Return pwn-oriented triage: dangerous calls, canary hints, and shell clues."""

        imports = self.imports()
        strings = self.strings(string_limit)
        symbols = self.functions() + self.names()
        import_names = {_base_symbol_name(row.get("name")) for row in imports}
        return {
            "mitigation_hints": {
                "stack_canary_import": "__stack_chk_fail" in import_names,
                "imports_system": "system" in import_names,
            },
            "dangerous_imports": _dangerous_imports(imports),
            "interesting_symbols": _interesting_symbols(symbols, function_limit),
            "string_hits": _interesting_strings(strings),
        }

    def _optional_module(self, *names: str) -> Any | None:
        # Keep IDA imports lazy; when changing this, obey fail-fast handling for broken imports.
        for name in names:
            if name in self._modules:
                return self._modules[name]
            if not self._auto_import:
                continue
            try:
                module = importlib.import_module(name)
            except ModuleNotFoundError as exc:
                if exc.name == name:
                    continue
                raise AIHelperError(f"failed to import {name}: {exc}") from exc
            self._modules[name] = module
            return module
        return None

    def _require_module(self, *names: str) -> Any:
        module = self._optional_module(*names)
        if module is None:
            joined = ", ".join(names)
            raise AIHelperError(f"required IDAPython module is unavailable: {joined}")
        return module

    def _badaddr(self) -> int:
        for module_name in ("idaapi", "idc"):
            module = self._optional_module(module_name)
            if module is not None and hasattr(module, "BADADDR"):
                return int(module.BADADDR)
        return (1 << 64) - 1

    def _checked_ea(self, ea: int) -> int:
        if ea < 0 or ea == self._badaddr():
            raise AIHelperError(f"invalid effective address: {ea!r}")
        return int(ea)

    def _name_ea(self, name: str) -> int:
        idc = self._optional_module("idc")
        if idc is not None and hasattr(idc, "get_name_ea_simple"):
            return int(idc.get_name_ea_simple(name))
        ida_name = self._optional_module("ida_name")
        if ida_name is not None and hasattr(ida_name, "get_name_ea"):
            return int(ida_name.get_name_ea(self._badaddr(), name))
        raise AIHelperError("name resolution requires idc or ida_name")

    def _name_or_none(self, ea: int) -> str | None:
        for module_name, attr in (("idc", "get_func_name"), ("idc", "get_name"), ("ida_funcs", "get_func_name")):
            module = self._optional_module(module_name)
            if module is not None and hasattr(module, attr):
                value = getattr(module, attr)(ea)
                if value:
                    return str(value)
        return None

    def _function_record(self, ea: int, func: Any | None = None) -> dict[str, Any]:
        ida_funcs = self._optional_module("ida_funcs")
        resolved = func if func is not None else ida_funcs.get_func(ea) if ida_funcs is not None else None
        start = int(getattr(resolved, "start_ea", ea)) if resolved is not None else ea
        end = int(getattr(resolved, "end_ea", start)) if resolved is not None else None
        return {
            "ea": start,
            "name": self._name_or_none(start),
            "end_ea": end,
            "size": None if end is None else max(0, end - start),
        }

    def _segment_record(self, ea: int) -> dict[str, Any]:
        ida_segment = self._optional_module("ida_segment")
        idc = self._optional_module("idc")
        seg = ida_segment.getseg(ea) if ida_segment is not None and hasattr(ida_segment, "getseg") else None
        start = self._segment_bound(seg, idc, "start_ea", "get_segm_start", ea)
        end = self._segment_bound(seg, idc, "end_ea", "get_segm_end", ea)
        if start is None or end is None:
            raise AIHelperError(f"cannot resolve segment bounds at 0x{ea:x}")
        return {
            "start_ea": start,
            "end_ea": end,
            "size": max(0, end - start),
            "name": self._segment_text(ida_segment, idc, "get_segm_name", seg, start),
            "class": self._segment_text(ida_segment, None, "get_segm_class", seg, start),
            "perm": self._optional_int(seg, "perm") if seg is not None else None,
            "bitness": self._optional_int(seg, "bitness") if seg is not None else None,
        }

    def _segment_bound(self, seg: Any | None, idc: Any | None, attr: str, fallback: str, ea: int) -> int | None:
        if seg is not None and hasattr(seg, attr):
            return int(getattr(seg, attr))
        if idc is not None and hasattr(idc, fallback):
            value = int(getattr(idc, fallback)(ea))
            return None if value == self._badaddr() else value
        return None

    def _segment_text(self, primary: Any | None, fallback: Any | None, attr: str, seg: Any | None, start: int) -> str | None:
        for module in (primary, fallback):
            if module is None or not hasattr(module, attr):
                continue
            getter = getattr(module, attr)
            try:
                value = getter(seg) if seg is not None else getter(start)
            except TypeError:
                value = getter(start)
            if value:
                return str(value)
        return None

    def _entry_record(self, item: Any) -> dict[str, Any]:
        if isinstance(item, Mapping):
            index = item.get("index")
            ordinal = item.get("ordinal")
            ea = item.get("ea")
            name = item.get("name")
        else:
            index, ordinal, ea, name = self._entry_tuple(item)
        if ordinal is None or ea is None:
            raise AIHelperError("entry record requires ordinal and ea")
        return {
            "index": None if index is None else int(index),
            "ordinal": int(ordinal),
            "ea": self._checked_ea(int(ea)),
            "name": None if name is None else str(name),
        }

    def _entry_tuple(self, item: Any) -> tuple[Any | None, Any, Any, Any | None]:
        if isinstance(item, (str, bytes, bytearray, memoryview)) or not isinstance(item, Sequence):
            raise AIHelperError("entry records must be mappings or finite tuples")
        values = tuple(item)
        if len(values) == 4:
            index, ordinal, ea, name = values
            return index, ordinal, ea, name
        if len(values) == 3:
            ordinal, ea, name = values
            return None, ordinal, ea, name
        raise AIHelperError(f"unsupported entry tuple width: {len(values)}")

    def _read_bytes(self, ea: int, size: int) -> bytes:
        if size == 0:
            return b""
        for module_name in ("ida_bytes", "idc"):
            module = self._optional_module(module_name)
            if module is None or not hasattr(module, "get_bytes"):
                continue
            value = module.get_bytes(ea, size)
            if value is None:
                continue
            payload = bytes(value)
            if len(payload) != size:
                raise AIHelperError(f"byte read at 0x{ea:x} returned {len(payload)} bytes, expected {size}")
            return payload
        return self._read_bytes_bytewise(ea, size)

    def _read_bytes_bytewise(self, ea: int, size: int) -> bytes:
        ida_bytes = self._require_module("ida_bytes")
        if not hasattr(ida_bytes, "get_db_byte"):
            raise AIHelperError("byte reads require ida_bytes.get_bytes, idc.get_bytes, or ida_bytes.get_db_byte")
        payload = bytearray()
        for offset in range(size):
            value = int(ida_bytes.get_db_byte(ea + offset))
            if value < 0 or value > 0xFF:
                raise AIHelperError(f"cannot read byte at 0x{ea + offset:x}")
            payload.append(value)
        return bytes(payload)

    def _comment_at(self, ea: int, repeatable: bool) -> str | None:
        for module_name in ("ida_bytes", "idc"):
            module = self._optional_module(module_name)
            if module is None or not hasattr(module, "get_cmt"):
                continue
            value = module.get_cmt(ea, repeatable)
            return None if value is None else str(value)
        raise AIHelperError("comment lookup requires ida_bytes.get_cmt or idc.get_cmt")

    def _type_at(self, ea: int) -> str | None:
        idc = self._optional_module("idc")
        if idc is not None and hasattr(idc, "get_type"):
            value = idc.get_type(ea)
            if value:
                return str(value)
        ida_typeinf = self._optional_module("ida_typeinf")
        if ida_typeinf is not None and hasattr(ida_typeinf, "print_type"):
            value = ida_typeinf.print_type(ea, 0)
            return None if value is None else str(value)
        if idc is not None and hasattr(idc, "get_type"):
            return None
        raise AIHelperError("type lookup requires idc.get_type or ida_typeinf.print_type")

    def _xref_endpoint_records(self, refs: Iterable[Mapping[str, Any]], endpoint: str) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        seen: set[tuple[int, int, int | None, str]] = set()
        for ref in refs:
            frm = int(ref["frm"])
            target = int(ref["to"])
            xref_type = None if "type" not in ref else int(ref["type"])
            key = (frm, target, xref_type, endpoint)
            if key in seen:
                continue
            seen.add(key)
            endpoint_ea = frm if endpoint == "frm" else target
            records.append(
                {
                    "ea": endpoint_ea,
                    "name": self._name_or_none(endpoint_ea),
                    "function": self._containing_function_record(endpoint_ea),
                    "xref": dict(ref),
                }
            )
        return records

    def _containing_function_record(self, ea: int) -> dict[str, Any] | None:
        ida_funcs = self._optional_module("ida_funcs")
        if ida_funcs is None:
            return None
        func = ida_funcs.get_func(ea)
        if func is None:
            return None
        return self._function_record(int(getattr(func, "start_ea", ea)), func)

    def _cfg_record(self, func: Any, flowchart: Iterable[Any]) -> dict[str, Any]:
        raw_blocks: list[tuple[Any, dict[str, Any]]] = []
        for index, block in enumerate(flowchart):
            start = int(getattr(block, "start_ea"))
            end = int(getattr(block, "end_ea"))
            raw_blocks.append((block, {"id": index, "start_ea": start, "end_ea": end, "size": max(0, end - start)}))
        start_to_id = {record["start_ea"]: record["id"] for _block, record in raw_blocks}
        edges = self._cfg_edges(raw_blocks, start_to_id)
        return {"function": self._function_record(int(getattr(func, "start_ea")), func), "blocks": [r for _b, r in raw_blocks], "edges": edges}

    def _cfg_edges(self, raw_blocks: list[tuple[Any, dict[str, Any]]], start_to_id: Mapping[int, int]) -> list[dict[str, Any]]:
        edges: list[dict[str, Any]] = []
        for block, record in raw_blocks:
            if not hasattr(block, "succs"):
                continue
            for successor in block.succs():
                dst_start = int(getattr(successor, "start_ea"))
                edges.append(
                    {
                        "src": int(record["id"]),
                        "dst": start_to_id.get(dst_start),
                        "src_ea": int(record["start_ea"]),
                        "dst_ea": dst_start,
                    }
                )
        return edges

    def _symbol_text(self, name_or_ea: int | str) -> str:
        if isinstance(name_or_ea, bool):
            raise AIHelperError("boolean values are not valid symbols")
        if isinstance(name_or_ea, int):
            name = self._name_or_none(self._checked_ea(name_or_ea))
            if name is None:
                raise AIHelperError(f"address 0x{name_or_ea:x} has no symbol name")
            return name
        if not isinstance(name_or_ea, str) or not name_or_ea.strip():
            raise AIHelperError("symbol name must be a non-empty string")
        return name_or_ea.strip()

    def _demangle_symbol(self, symbol: str, flags: int) -> str | None:
        if isinstance(flags, bool) or not isinstance(flags, int):
            raise AIHelperError("demangle flags must be an integer")
        for module_name in ("ida_name", "idc"):
            module = self._optional_module(module_name)
            if module is None or not hasattr(module, "demangle_name"):
                continue
            value = module.demangle_name(symbol, flags)
            return None if value is None else str(value)
        raise AIHelperError("demangle requires ida_name.demangle_name or idc.demangle_name")

    def _decompiler(self) -> Any:
        ida_hexrays = self._optional_module("ida_hexrays")
        if ida_hexrays is not None and hasattr(ida_hexrays, "init_hexrays_plugin"):
            if ida_hexrays.init_hexrays_plugin() is False:
                raise AIHelperError("Hex-Rays plugin is unavailable")
        if ida_hexrays is not None and hasattr(ida_hexrays, "decompile"):
            return ida_hexrays.decompile
        idaapi = self._optional_module("idaapi")
        if idaapi is not None and hasattr(idaapi, "decompile"):
            return idaapi.decompile
        raise AIHelperError("Hex-Rays decompiler is unavailable; disassembly fallback is forbidden")

    def _disasm_line(self, idc: Any, ea: int) -> str:
        if hasattr(idc, "generate_disasm_line"):
            value = idc.generate_disasm_line(ea, 0)
        elif hasattr(idc, "GetDisasm"):
            value = idc.GetDisasm(ea)
        else:
            raise AIHelperError("disassembly requires idc.generate_disasm_line or idc.GetDisasm")
        return "" if value is None else str(value)

    def _next_item_ea(self, ea: int) -> int:
        ida_bytes = self._optional_module("ida_bytes")
        if ida_bytes is not None and hasattr(ida_bytes, "get_item_size"):
            size = int(ida_bytes.get_item_size(ea))
            if size > 0:
                return ea + size
        idc = self._optional_module("idc")
        if idc is not None and hasattr(idc, "next_head"):
            return int(idc.next_head(ea, self._badaddr()))
        raise AIHelperError(f"cannot advance disassembly cursor at 0x{ea:x}")

    def _xref_record(self, xref: Any) -> dict[str, Any]:
        record = {"frm": int(getattr(xref, "frm")), "to": int(getattr(xref, "to"))}
        if hasattr(xref, "type"):
            record["type"] = int(getattr(xref, "type"))
        if hasattr(xref, "iscode"):
            record["iscode"] = bool(getattr(xref, "iscode"))
        return record

    def _artifact_path(self, name: str, value: Any) -> Path:
        if not isinstance(name, str) or not name.strip():
            raise AIHelperError("artifact name must be a non-empty string")
        raw = Path(name)
        if raw.is_absolute() or any(part in {"", ".", ".."} for part in raw.parts):
            raise AIHelperError(f"artifact path escapes artifact directory: {name!r}")
        suffix = raw.suffix or self._inferred_suffix(value)
        relative = raw if raw.suffix else raw.with_suffix(suffix)
        base = self._artifact_dir.resolve()
        target = (base / relative).resolve()
        try:
            target.relative_to(base)
        except ValueError as exc:
            raise AIHelperError(f"artifact path escapes artifact directory: {name!r}") from exc
        return target

    def _artifact_payload(self, target: Path, value: Any) -> tuple[bytes, str, int | None]:
        suffix = target.suffix.lower()
        if suffix == ".bin":
            if not isinstance(value, (bytes, bytearray, memoryview)):
                raise AIHelperError("binary artifacts require a bytes-like value")
            payload = bytes(value)
            return payload, "binary", len(payload)
        if suffix == ".txt":
            if not isinstance(value, str):
                raise AIHelperError("text artifacts require a string value")
            payload = value.encode("utf-8")
            return payload, "text", len(value.splitlines())
        if suffix == ".jsonl":
            payload, count = self._jsonl_payload(value)
            return payload, "jsonl", count
        payload = self._json_bytes(value)
        return payload, "json", self._json_count(value)

    def _jsonl_payload(self, value: Any) -> tuple[bytes, int]:
        if isinstance(value, (str, bytes, bytearray, memoryview)) or not isinstance(value, Iterable):
            raise AIHelperError("JSONL artifacts require a non-string iterable")
        chunks: list[bytes] = []
        count = 0
        for item in value:
            chunks.append(self._json_bytes(item) + b"\n")
            count += 1
        return b"".join(chunks), count

    def _json_bytes(self, value: Any) -> bytes:
        try:
            text = json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":"))
        except (TypeError, ValueError) as exc:
            raise AIHelperError(f"value is not JSON serializable: {exc}") from exc
        return text.encode("utf-8")

    def _inferred_suffix(self, value: Any) -> str:
        if isinstance(value, (bytes, bytearray, memoryview)):
            return ".bin"
        if isinstance(value, str):
            return ".txt"
        return ".json"

    def _json_count(self, value: Any) -> int | None:
        if isinstance(value, Mapping):
            return len(value)
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray, memoryview)):
            return len(value)
        return None

    def _checked_limit(self, value: int, name: str, *, allow_zero: bool = False) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise AIHelperError(f"{name} must be an integer")
        minimum = 0 if allow_zero else 1
        if value < minimum:
            raise AIHelperError(f"{name} must be >= {minimum}")
        return value

    def _checked_byte_size(self, value: int) -> int:
        count = self._checked_limit(value, "size", allow_zero=True)
        if count > _MAX_BYTE_READ:
            raise AIHelperError(f"size must be <= {_MAX_BYTE_READ}")
        return count

    def _checked_operand_index(self, value: int) -> int:
        index = self._checked_limit(value, "index", allow_zero=True)
        if index > _MAX_OPERAND_INDEX:
            raise AIHelperError(f"index must be <= {_MAX_OPERAND_INDEX}")
        return index

    def _optional_int(self, obj: Any, attr: str) -> int | None:
        if obj is None:
            return None
        if not hasattr(obj, attr):
            return None
        value = getattr(obj, attr)
        return None if value is None else int(value)


def _artifact_prefix(prefix: str) -> str:
    """Normalize an artifact prefix while leaving final path validation to the writer."""

    if not isinstance(prefix, str) or not prefix.strip():
        raise AIHelperError("artifact prefix must be a non-empty string")
    normalized = prefix.strip().strip("/\\")
    if not normalized:
        raise AIHelperError("artifact prefix must contain a path component")
    return normalized


def _base_symbol_name(name: Any) -> str:
    """Return a lower-case symbol name without common ELF version suffixes."""

    if name is None:
        return ""
    text = str(name).split("@", 1)[0]
    if "!" in text:
        text = text.rsplit("!", 1)[1]
    return text.lower()


def _dangerous_imports(imports: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Return imported symbols that often matter for pwn triage."""

    result: list[dict[str, Any]] = []
    seen: set[tuple[str, int | None]] = set()
    for record in imports:
        name = _base_symbol_name(record.get("name"))
        if name not in _DANGEROUS_IMPORTS:
            continue
        ea = None if record.get("ea") is None else int(record["ea"])
        key = (name, ea)
        if key in seen:
            continue
        seen.add(key)
        result.append({"name": name, "ea": ea, "module": record.get("module")})
    return result


def _interesting_symbols(records: Iterable[Mapping[str, Any]], limit: int) -> list[dict[str, Any]]:
    """Return symbol names whose spelling suggests exploit-relevant helpers."""

    max_items = _bounded_count("limit", limit)
    if max_items == 0:
        return []
    result: list[dict[str, Any]] = []
    seen: set[tuple[str, int | None]] = set()
    for record in records:
        text = str(record.get("name") or "")
        lowered = text.lower()
        reason = next((part for part in _SUSPICIOUS_NAME_PARTS if part in lowered), None)
        if reason is None:
            continue
        ea = None if record.get("ea") is None else int(record["ea"])
        key = (text, ea)
        if key in seen:
            continue
        seen.add(key)
        result.append({"name": text, "ea": ea, "reason": reason})
        if len(result) >= max_items:
            break
    return result


def _interesting_strings(strings: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Return string records that look like shell, command, or flag clues."""

    result: list[dict[str, Any]] = []
    for record in strings:
        value = str(record.get("value") or "")
        lowered = value.lower()
        reason = next((part for part in _SUSPICIOUS_STRING_PARTS if part in lowered), None)
        if reason is not None:
            result.append({"ea": record.get("ea"), "value": value, "reason": reason})
    return result


def _bounded_count(name: str, value: int) -> int:
    """Validate a public summary limit."""

    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise AIHelperError(f"{name} must be a non-negative integer")
    return value


def create_ai(artifact_dir: str | Path | None = None) -> AIHelpers:
    """Create an AI helper object for runtime globals."""

    return AIHelpers(artifact_dir)


ai = AIHelpers()


def functions() -> list[dict[str, Any]]:
    """Delegate to the default helper object's function enumeration."""

    return ai.functions()


def get_ea(ea_or_name: int | str) -> int:
    """Delegate to the default helper object's address resolver."""

    return ai.get_ea(ea_or_name)


def function(ea_or_name: int | str) -> dict[str, Any]:
    """Delegate to the default helper object's function lookup."""

    return ai.function(ea_or_name)


def decompile(ea_or_name: int | str) -> dict[str, Any]:
    """Delegate to the default helper object's fail-fast decompiler."""

    return ai.decompile(ea_or_name)


def disasm(ea_or_name: int | str, limit: int = 64) -> list[dict[str, Any]]:
    """Delegate to the default helper object's disassembler."""

    return ai.disasm(ea_or_name, limit)


def xrefs(ea_or_name: int | str) -> dict[str, list[dict[str, Any]]]:
    """Delegate to the default helper object's xref bundle."""

    return ai.xrefs(ea_or_name)


def xrefs_to(ea_or_name: int | str) -> list[dict[str, Any]]:
    """Delegate to the default helper object's incoming xrefs."""

    return ai.xrefs_to(ea_or_name)


def xrefs_from(ea_or_name: int | str) -> list[dict[str, Any]]:
    """Delegate to the default helper object's outgoing xrefs."""

    return ai.xrefs_from(ea_or_name)


def strings(string_limit: int | None = None) -> list[dict[str, Any]]:
    """Delegate to the default helper object's string enumeration."""

    return ai.strings(string_limit)


def imports() -> list[dict[str, Any]]:
    """Delegate to the default helper object's import enumeration."""

    return ai.imports()


def segments() -> list[dict[str, Any]]:
    """Delegate to the default helper object's segment enumeration."""

    return ai.segments()


def entries() -> list[dict[str, Any]]:
    """Delegate to the default helper object's entry enumeration."""

    return ai.entries()


def exports() -> list[dict[str, Any]]:
    """Delegate to the default helper object's export enumeration."""

    return ai.exports()


def names() -> list[dict[str, Any]]:
    """Delegate to the default helper object's name enumeration."""

    return ai.names()


def bytes_at(ea_or_name: int | str, size: int) -> dict[str, Any]:
    """Delegate to the default helper object's byte reader."""

    return ai.bytes_at(ea_or_name, size)


def bytes_hex(ea_or_name: int | str, size: int) -> dict[str, Any]:
    """Delegate to the default helper object's hex byte reader."""

    return ai.bytes_hex(ea_or_name, size)


def item_size(ea_or_name: int | str) -> dict[str, Any]:
    """Delegate to the default helper object's item-size lookup."""

    return ai.item_size(ea_or_name)


def comments(ea_or_name: int | str) -> dict[str, Any]:
    """Delegate to the default helper object's comment lookup."""

    return ai.comments(ea_or_name)


def type_at(ea_or_name: int | str) -> dict[str, Any]:
    """Delegate to the default helper object's type lookup."""

    return ai.type_at(ea_or_name)


def operand_value(ea_or_name: int | str, index: int) -> dict[str, Any]:
    """Delegate to the default helper object's operand-value lookup."""

    return ai.operand_value(ea_or_name, index)


def function_bounds(ea_or_name: int | str) -> dict[str, Any]:
    """Delegate to the default helper object's function-bound lookup."""

    return ai.function_bounds(ea_or_name)


def callers(ea_or_name: int | str) -> list[dict[str, Any]]:
    """Delegate to the default helper object's caller lookup."""

    return ai.callers(ea_or_name)


def callees(ea_or_name: int | str) -> list[dict[str, Any]]:
    """Delegate to the default helper object's callee lookup."""

    return ai.callees(ea_or_name)


def basic_blocks(ea_or_name: int | str) -> list[dict[str, Any]]:
    """Delegate to the default helper object's basic-block lookup."""

    return ai.basic_blocks(ea_or_name)


def cfg(ea_or_name: int | str) -> dict[str, Any]:
    """Delegate to the default helper object's CFG lookup."""

    return ai.cfg(ea_or_name)


def demangle(name_or_ea: int | str, flags: int = 0) -> dict[str, Any]:
    """Delegate to the default helper object's demangler."""

    return ai.demangle(name_or_ea, flags)


def context_pack(
    ea_or_name: int | str,
    *,
    disasm_limit: int = 32,
    include_decompile: bool = False,
) -> dict[str, Any]:
    """Delegate to the default helper object's context pack builder."""

    return ai.context_pack(ea_or_name, disasm_limit=disasm_limit, include_decompile=include_decompile)


def focus(
    targets: int | str | Iterable[int | str],
    *,
    disasm_limit: int = 64,
    include_decompile: bool = True,
) -> dict[str, Any]:
    """Delegate to the default helper object's focused evidence builder."""

    return ai.focus(targets, disasm_limit=disasm_limit, include_decompile=include_decompile)


def inventory_summary(*, function_limit: int = 16, string_limit: int = 16) -> dict[str, Any]:
    """Delegate to the default helper object's small inventory summary."""

    return ai.inventory_summary(function_limit=function_limit, string_limit=string_limit)


def export_inventory(prefix: str = "inventory", *, string_limit: int | None = None) -> dict[str, Any]:
    """Delegate to the default helper object's artifact-backed inventory export."""

    return ai.export_inventory(prefix, string_limit=string_limit)


def pwn_overview(*, string_limit: int = 64, function_limit: int = 32) -> dict[str, Any]:
    """Delegate to the default helper object's pwn-oriented overview."""

    return ai.pwn_overview(string_limit=string_limit, function_limit=function_limit)


def write_artifact(name: str, value: Any) -> dict[str, Any]:
    """Delegate to the default helper object's artifact writer."""

    return ai.write_artifact(name, value)


def rename(ea_or_name: int | str, new_name: str, flags: int = 0) -> dict[str, Any]:
    """Delegate to the default helper object's rename helper."""

    return ai.rename(ea_or_name, new_name, flags)


def set_comment(ea_or_name: int | str, comment: str, *, repeatable: bool = False) -> dict[str, Any]:
    """Delegate to the default helper object's comment helper."""

    return ai.set_comment(ea_or_name, comment, repeatable=repeatable)


def apply_type(ea_or_name: int | str, declaration: str, flags: int = 0) -> dict[str, Any]:
    """Delegate to the default helper object's type helper."""

    return ai.apply_type(ea_or_name, declaration, flags)


def patch_bytes(ea_or_name: int | str, data: bytes | bytearray | memoryview | str) -> dict[str, Any]:
    """Delegate to the default helper object's byte patch helper."""

    return ai.patch_bytes(ea_or_name, data)


def save_database(path: str | None = None, flags: int = 0) -> dict[str, Any]:
    """Delegate to the default helper object's explicit save helper."""

    return ai.save_database(path, flags)


def refresh_cache() -> dict[str, Any]:
    """Delegate to the default helper object's cache refresh."""

    return ai.refresh_cache()


def export_cache(name: str = "cache/index.json") -> dict[str, Any]:
    """Delegate to the default helper object's cache export."""

    return ai.export_cache(name)


def save_cache(path: str | Path) -> dict[str, Any]:
    """Delegate to the default helper object's persistent cache save."""

    return ai.save_cache(path)


def load_cache(path: str | Path) -> dict[str, Any]:
    """Delegate to the default helper object's persistent cache load."""

    return ai.load_cache(path)


def merge_changes(changes: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Delegate to the default helper object's change merge helper."""

    return ai.merge_changes(changes)


def merge_change_sets(change_sets: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Delegate to the default helper object's branch merge helper."""

    return ai.merge_change_sets(change_sets)


__all__ = (
    "AIHelperError",
    "AIHelpers",
    "ai",
    "apply_type",
    "basic_blocks",
    "bytes_at",
    "bytes_hex",
    "callers",
    "callees",
    "cfg",
    "comments",
    "context_pack",
    "create_ai",
    "decompile",
    "demangle",
    "disasm",
    "entries",
    "export_inventory",
    "export_cache",
    "exports",
    "focus",
    "function",
    "function_bounds",
    "functions",
    "get_ea",
    "imports",
    "item_size",
    "patch_bytes",
    "operand_value",
    "pwn_overview",
    "refresh_cache",
    "rename",
    "load_cache",
    "merge_change_sets",
    "merge_changes",
    "names",
    "save_database",
    "save_cache",
    "segments",
    "set_comment",
    "strings",
    "inventory_summary",
    "type_at",
    "write_artifact",
    "xrefs",
    "xrefs_from",
    "xrefs_to",
)
