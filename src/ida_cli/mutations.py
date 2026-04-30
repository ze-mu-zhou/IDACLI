"""Local IDA database mutation convenience helpers."""

from __future__ import annotations

import importlib
from collections.abc import Mapping
from typing import Any

MAX_PATCH_BYTES = 1 << 20


class MutationError(RuntimeError):
    """Raised when a database mutation cannot complete exactly."""


class DatabaseMutations:
    """Small fail-fast helper layer over mutating IDAPython APIs."""

    def __init__(self, *, modules: Mapping[str, Any] | None = None, auto_import: bool = True) -> None:
        # Keep tests deterministic through injection; when changing this, obey fail-fast import semantics.
        self._modules = dict(modules) if modules is not None else {}
        self._auto_import = auto_import

    def propose_rename(self, ea_or_name: int | str, new_name: str, flags: int = 0) -> dict[str, Any]:
        """Return a proposed rename record without touching the database."""

        ea = self._resolve_ea(ea_or_name)
        checked_name = self._checked_text(new_name, "new_name", allow_empty=False)
        checked_flags = self._checked_int(flags, "flags")
        old_name = self._name_at(ea)
        return self._rename_record(ea, old_name, checked_name, checked_flags, applied=False)

    def rename(self, ea_or_name: int | str, new_name: str, flags: int = 0) -> dict[str, Any]:
        """Rename an address and return the exact applied change record."""

        ea = self._resolve_ea(ea_or_name)
        checked_name = self._checked_text(new_name, "new_name", allow_empty=False)
        checked_flags = self._checked_int(flags, "flags")
        old_name = self._name_at(ea)
        if old_name != checked_name:
            set_name = self._require_attr("ida_name", "set_name")
            self._must_succeed(set_name(ea, checked_name, checked_flags), "ida_name.set_name")
            actual_name = self._name_at(ea)
            if actual_name != checked_name:
                raise MutationError(
                    f"ida_name.set_name changed 0x{ea:x} to {actual_name!r}, not {checked_name!r}"
                )
        return self._rename_record(ea, old_name, checked_name, checked_flags, applied=True)

    def propose_comment(
        self,
        ea_or_name: int | str,
        comment: str,
        *,
        repeatable: bool = False,
    ) -> dict[str, Any]:
        """Return a proposed comment change without touching the database."""

        ea = self._resolve_ea(ea_or_name)
        checked_comment = self._checked_text(comment, "comment", allow_empty=True)
        checked_repeatable = self._checked_bool(repeatable, "repeatable")
        old_comment = self._comment_at(ea, checked_repeatable)
        return self._comment_record(ea, checked_repeatable, old_comment, checked_comment, applied=False)

    def set_comment(
        self,
        ea_or_name: int | str,
        comment: str,
        *,
        repeatable: bool = False,
    ) -> dict[str, Any]:
        """Set a repeatable or non-repeatable comment and report exact metadata."""

        ea = self._resolve_ea(ea_or_name)
        checked_comment = self._checked_text(comment, "comment", allow_empty=True)
        checked_repeatable = self._checked_bool(repeatable, "repeatable")
        old_comment = self._comment_at(ea, checked_repeatable)
        if old_comment != checked_comment:
            set_cmt = self._require_attr("ida_bytes", "set_cmt")
            self._must_succeed(set_cmt(ea, checked_comment, checked_repeatable), "ida_bytes.set_cmt")
            actual_comment = self._comment_at(ea, checked_repeatable)
            if actual_comment != checked_comment:
                raise MutationError(f"ida_bytes.set_cmt did not set the exact comment at 0x{ea:x}")
        return self._comment_record(ea, checked_repeatable, old_comment, checked_comment, applied=True)

    def set_repeatable_comment(self, ea_or_name: int | str, comment: str) -> dict[str, Any]:
        """Set a repeatable comment with explicit metadata."""

        return self.set_comment(ea_or_name, comment, repeatable=True)

    def set_nonrepeatable_comment(self, ea_or_name: int | str, comment: str) -> dict[str, Any]:
        """Set a non-repeatable comment with explicit metadata."""

        return self.set_comment(ea_or_name, comment, repeatable=False)

    def propose_type(self, ea_or_name: int | str, declaration: str, flags: int = 0) -> dict[str, Any]:
        """Return a proposed C type application record without mutating IDA."""

        ea = self._resolve_ea(ea_or_name)
        checked_decl = self._checked_text(declaration, "declaration", allow_empty=False)
        checked_flags = self._checked_int(flags, "flags")
        old_type = self._type_at(ea)
        return self._type_record(ea, old_type, checked_decl, checked_decl, checked_flags, applied=False)

    def apply_type(self, ea_or_name: int | str, declaration: str, flags: int = 0) -> dict[str, Any]:
        """Apply a C declaration through IDA's type engine and report the result."""

        ea = self._resolve_ea(ea_or_name)
        checked_decl = self._checked_text(declaration, "declaration", allow_empty=False)
        checked_flags = self._checked_int(flags, "flags")
        old_type = self._type_at(ea)
        apply_cdecl = self._require_attr("ida_typeinf", "apply_cdecl")
        get_idati = self._require_attr("ida_typeinf", "get_idati")
        self._must_succeed(
            apply_cdecl(get_idati(), ea, checked_decl, checked_flags),
            "ida_typeinf.apply_cdecl",
        )
        actual_type = self._type_at(ea)
        return self._type_record(ea, old_type, checked_decl, actual_type, checked_flags, applied=True)

    def propose_patch_bytes(self, ea_or_name: int | str, data: bytes | bytearray | memoryview | str) -> dict[str, Any]:
        """Return a proposed byte patch record without touching the database."""

        ea = self._resolve_ea(ea_or_name)
        payload = self._byte_payload(data)
        old_bytes = self._read_bytes(ea, len(payload))
        return self._patch_record(ea, old_bytes, payload, applied=False)

    def patch_bytes(self, ea_or_name: int | str, data: bytes | bytearray | memoryview | str) -> dict[str, Any]:
        """Patch bytes through IDA and report every changed address."""

        ea = self._resolve_ea(ea_or_name)
        payload = self._byte_payload(data)
        old_bytes = self._read_bytes(ea, len(payload))
        patch_byte = self._require_attr("ida_bytes", "patch_byte")
        for index, (old_value, new_value) in enumerate(zip(old_bytes, payload, strict=True)):
            if old_value != new_value:
                address = self._checked_ea(ea + index)
                self._must_succeed(patch_byte(address, new_value), "ida_bytes.patch_byte")
        actual_bytes = self._read_bytes(ea, len(payload))
        if actual_bytes != payload:
            raise MutationError(f"ida_bytes.patch_byte did not apply the exact byte sequence at 0x{ea:x}")
        return self._patch_record(ea, old_bytes, payload, applied=True)

    def patch_byte(self, ea_or_name: int | str, value: int) -> dict[str, Any]:
        """Patch one byte while preserving the byte-range record format."""

        checked_value = self._checked_byte(value, "value")
        return self.patch_bytes(ea_or_name, bytes((checked_value,)))

    def propose_save_database(self, path: str | None = None, flags: int = 0) -> dict[str, Any]:
        """Return a proposed explicit database save record."""

        checked_path = self._checked_optional_text(path, "path")
        checked_flags = self._checked_int(flags, "flags")
        return self._save_record(checked_path, checked_flags, applied=False)

    def save_database(self, path: str | None = None, flags: int = 0) -> dict[str, Any]:
        """Save the current database explicitly and report the save operation."""

        checked_path = self._checked_optional_text(path, "path")
        checked_flags = self._checked_int(flags, "flags")
        save_database = self._require_attr("ida_loader", "save_database")
        self._must_succeed(save_database(checked_path, checked_flags), "ida_loader.save_database")
        return self._save_record(checked_path, checked_flags, applied=True)

    def save(self, path: str | None = None, flags: int = 0) -> dict[str, Any]:
        """Alias the explicit database save helper for concise AI calls."""

        return self.save_database(path, flags)

    def _rename_record(self, ea: int, old_name: str | None, new_name: str, flags: int, *, applied: bool) -> dict[str, Any]:
        changed = old_name != new_name
        return self._record(
            "rename",
            applied,
            target={"ea": ea, "old_name": old_name, "new_name": new_name},
            before={"name": old_name},
            after={"name": new_name},
            changed_addresses=[ea] if changed else [],
            changed_names=[{"ea": ea, "before": old_name, "after": new_name}] if changed else [],
            metadata={"api": "ida_name.set_name", "flags": flags},
        )

    def _comment_record(
        self,
        ea: int,
        repeatable: bool,
        old_comment: str | None,
        new_comment: str,
        *,
        applied: bool,
    ) -> dict[str, Any]:
        changed = old_comment != new_comment
        return self._record(
            "comment",
            applied,
            target={"ea": ea, "repeatable": repeatable},
            before={"comment": old_comment},
            after={"comment": new_comment},
            changed_addresses=[ea] if changed else [],
            metadata={"api": "ida_bytes.set_cmt"},
        )

    def _type_record(
        self,
        ea: int,
        old_type: str | None,
        requested_type: str,
        actual_type: str | None,
        flags: int,
        *,
        applied: bool,
    ) -> dict[str, Any]:
        changed = old_type != actual_type
        return self._record(
            "type",
            applied,
            target={"ea": ea},
            before={"type": old_type},
            after={"requested_type": requested_type, "type": actual_type},
            changed_addresses=[ea] if changed else [],
            metadata={"api": "ida_typeinf.apply_cdecl", "flags": flags},
        )

    def _patch_record(self, ea: int, old_bytes: bytes, new_bytes: bytes, *, applied: bool) -> dict[str, Any]:
        changed_addresses = [
            ea + index
            for index, (old_value, new_value) in enumerate(zip(old_bytes, new_bytes, strict=True))
            if old_value != new_value
        ]
        return self._record(
            "patch_bytes",
            applied,
            target={"ea": ea, "length": len(new_bytes)},
            before={"bytes": old_bytes.hex()},
            after={"bytes": new_bytes.hex()},
            changed_addresses=changed_addresses,
            metadata={"api": "ida_bytes.patch_byte", "read_api": "ida_bytes.get_db_byte"},
        )

    def _save_record(self, path: str | None, flags: int, *, applied: bool) -> dict[str, Any]:
        return self._record(
            "save_database",
            applied,
            target={"path": path},
            before={},
            after={"path": path},
            changed_addresses=[],
            metadata={"api": "ida_loader.save_database", "flags": flags},
        )

    def _record(
        self,
        kind: str,
        applied: bool,
        *,
        target: dict[str, Any],
        before: dict[str, Any],
        after: dict[str, Any],
        changed_addresses: list[int],
        changed_names: list[dict[str, Any]] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        # Keep records JSON-native; when adding fields, obey deterministic protocol encoding.
        return {
            "kind": kind,
            "status": "applied" if applied else "proposed",
            "applied": applied,
            "target": target,
            "before": before,
            "after": after,
            "changed_addresses": changed_addresses,
            "changed_names": [] if changed_names is None else changed_names,
            "metadata": {} if metadata is None else metadata,
        }

    def _resolve_ea(self, ea_or_name: int | str) -> int:
        if isinstance(ea_or_name, bool):
            raise MutationError("boolean values are not valid addresses")
        if isinstance(ea_or_name, int):
            return self._checked_ea(ea_or_name)
        if not isinstance(ea_or_name, str):
            raise MutationError(f"unsupported address type: {type(ea_or_name).__name__}")

        text = ea_or_name.strip()
        if not text:
            raise MutationError("empty address/name cannot be resolved")
        try:
            return self._checked_ea(int(text, 0))
        except ValueError:
            pass

        get_name_ea = self._require_attr("ida_name", "get_name_ea")
        ea = int(get_name_ea(self._badaddr(), text))
        if ea == self._badaddr():
            raise MutationError(f"cannot resolve IDA name: {text!r}")
        return self._checked_ea(ea)

    def _name_at(self, ea: int) -> str | None:
        get_name = self._require_attr("ida_name", "get_name")
        value = get_name(ea)
        return None if value is None or value == "" else str(value)

    def _comment_at(self, ea: int, repeatable: bool) -> str | None:
        get_cmt = self._require_attr("ida_bytes", "get_cmt")
        value = get_cmt(ea, repeatable)
        return None if value is None else str(value)

    def _type_at(self, ea: int) -> str | None:
        print_type = self._require_attr("ida_typeinf", "print_type")
        value = print_type(ea, 0)
        return None if value is None or value == "" else str(value)

    def _read_bytes(self, ea: int, count: int) -> bytes:
        get_byte = self._require_attr("ida_bytes", "get_db_byte")
        values: list[int] = []
        for index in range(count):
            address = self._checked_ea(ea + index)
            value = int(get_byte(address))
            if value < 0 or value > 0xFF:
                raise MutationError(f"ida_bytes.get_db_byte returned invalid byte at 0x{address:x}: {value!r}")
            values.append(value)
        return bytes(values)

    def _byte_payload(self, data: bytes | bytearray | memoryview | str) -> bytes:
        if isinstance(data, str):
            compact = "".join(data.strip().split())
            if not compact or len(compact) % 2 != 0:
                raise MutationError("hex byte patches must contain a non-empty even number of hex digits")
            try:
                payload = bytes.fromhex(compact)
            except ValueError as exc:
                raise MutationError(f"invalid hex byte patch: {exc}") from exc
        elif isinstance(data, bytes | bytearray | memoryview):
            payload = bytes(data)
        else:
            raise MutationError(f"unsupported byte patch type: {type(data).__name__}")
        if not payload:
            raise MutationError("byte patch payload must not be empty")
        if len(payload) > MAX_PATCH_BYTES:
            raise MutationError(f"byte patch payload exceeds {MAX_PATCH_BYTES} bytes")
        return payload

    def _checked_ea(self, ea: int) -> int:
        if ea < 0 or ea == self._badaddr():
            raise MutationError(f"invalid effective address: {ea!r}")
        return int(ea)

    def _checked_text(self, value: str, name: str, *, allow_empty: bool) -> str:
        if not isinstance(value, str):
            raise MutationError(f"{name} must be a string")
        if not allow_empty and not value.strip():
            raise MutationError(f"{name} must be a non-empty string")
        return value

    def _checked_optional_text(self, value: str | None, name: str) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise MutationError(f"{name} must be a string or None")
        if not value.strip():
            raise MutationError(f"{name} must not be empty")
        return value

    def _checked_int(self, value: int, name: str) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise MutationError(f"{name} must be an integer")
        if value < 0:
            raise MutationError(f"{name} must be >= 0")
        return value

    def _checked_byte(self, value: int, name: str) -> int:
        checked = self._checked_int(value, name)
        if checked > 0xFF:
            raise MutationError(f"{name} must be <= 255")
        return checked

    def _checked_bool(self, value: bool, name: str) -> bool:
        if not isinstance(value, bool):
            raise MutationError(f"{name} must be a boolean")
        return value

    def _badaddr(self) -> int:
        module = self._require_module("ida_idaapi")
        if not hasattr(module, "BADADDR"):
            raise MutationError("required IDAPython attribute is unavailable: ida_idaapi.BADADDR")
        return int(module.BADADDR)

    def _require_attr(self, module_name: str, attr: str) -> Any:
        module = self._require_module(module_name)
        if not hasattr(module, attr):
            raise MutationError(f"required IDAPython attribute is unavailable: {module_name}.{attr}")
        return getattr(module, attr)

    def _require_module(self, name: str) -> Any:
        module = self._optional_module(name)
        if module is None:
            raise MutationError(f"required IDAPython module is unavailable: {name}")
        return module

    def _optional_module(self, name: str) -> Any | None:
        if name in self._modules:
            return self._modules[name]
        if not self._auto_import:
            return None
        try:
            module = importlib.import_module(name)
        except ModuleNotFoundError as exc:
            if exc.name == name:
                return None
            raise MutationError(f"failed to import {name}: {exc}") from exc
        self._modules[name] = module
        return module

    def _must_succeed(self, result: Any, api: str) -> None:
        if result is True or result == 1:
            return
        raise MutationError(f"{api} failed with result {result!r}")


def create_mutations(*, modules: Mapping[str, Any] | None = None, auto_import: bool = True) -> DatabaseMutations:
    """Create a mutation helper object for local IDAPython database edits."""

    return DatabaseMutations(modules=modules, auto_import=auto_import)


mutations = DatabaseMutations()


def propose_rename(ea_or_name: int | str, new_name: str, flags: int = 0) -> dict[str, Any]:
    """Delegate to the default helper object's proposed rename."""

    return mutations.propose_rename(ea_or_name, new_name, flags)


def rename(ea_or_name: int | str, new_name: str, flags: int = 0) -> dict[str, Any]:
    """Delegate to the default helper object's applied rename."""

    return mutations.rename(ea_or_name, new_name, flags)


def propose_comment(ea_or_name: int | str, comment: str, *, repeatable: bool = False) -> dict[str, Any]:
    """Delegate to the default helper object's proposed comment."""

    return mutations.propose_comment(ea_or_name, comment, repeatable=repeatable)


def set_comment(ea_or_name: int | str, comment: str, *, repeatable: bool = False) -> dict[str, Any]:
    """Delegate to the default helper object's applied comment."""

    return mutations.set_comment(ea_or_name, comment, repeatable=repeatable)


def set_repeatable_comment(ea_or_name: int | str, comment: str) -> dict[str, Any]:
    """Delegate to the default helper object's repeatable comment setter."""

    return mutations.set_repeatable_comment(ea_or_name, comment)


def set_nonrepeatable_comment(ea_or_name: int | str, comment: str) -> dict[str, Any]:
    """Delegate to the default helper object's non-repeatable comment setter."""

    return mutations.set_nonrepeatable_comment(ea_or_name, comment)


def propose_type(ea_or_name: int | str, declaration: str, flags: int = 0) -> dict[str, Any]:
    """Delegate to the default helper object's proposed type application."""

    return mutations.propose_type(ea_or_name, declaration, flags)


def apply_type(ea_or_name: int | str, declaration: str, flags: int = 0) -> dict[str, Any]:
    """Delegate to the default helper object's type application."""

    return mutations.apply_type(ea_or_name, declaration, flags)


def propose_patch_bytes(ea_or_name: int | str, data: bytes | bytearray | memoryview | str) -> dict[str, Any]:
    """Delegate to the default helper object's proposed byte patch."""

    return mutations.propose_patch_bytes(ea_or_name, data)


def patch_bytes(ea_or_name: int | str, data: bytes | bytearray | memoryview | str) -> dict[str, Any]:
    """Delegate to the default helper object's byte patch."""

    return mutations.patch_bytes(ea_or_name, data)


def patch_byte(ea_or_name: int | str, value: int) -> dict[str, Any]:
    """Delegate to the default helper object's single byte patch."""

    return mutations.patch_byte(ea_or_name, value)


def propose_save_database(path: str | None = None, flags: int = 0) -> dict[str, Any]:
    """Delegate to the default helper object's proposed database save."""

    return mutations.propose_save_database(path, flags)


def save_database(path: str | None = None, flags: int = 0) -> dict[str, Any]:
    """Delegate to the default helper object's explicit database save."""

    return mutations.save_database(path, flags)


def save(path: str | None = None, flags: int = 0) -> dict[str, Any]:
    """Delegate to the default helper object's explicit database save alias."""

    return mutations.save(path, flags)


__all__ = (
    "DatabaseMutations",
    "MAX_PATCH_BYTES",
    "MutationError",
    "apply_type",
    "create_mutations",
    "mutations",
    "patch_byte",
    "patch_bytes",
    "propose_comment",
    "propose_patch_bytes",
    "propose_rename",
    "propose_save_database",
    "propose_type",
    "rename",
    "save",
    "save_database",
    "set_comment",
    "set_nonrepeatable_comment",
    "set_repeatable_comment",
)
