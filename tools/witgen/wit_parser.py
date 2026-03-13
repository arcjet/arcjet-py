"""Recursive-descent parser for WIT text (as output by wasm-tools component wit).

Parses the two package blocks emitted by wasm-tools:
  1. package root:component; world root { ... }
  2. package arcjet:js-req { interface ... }
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from .ir import (
    WitEnum,
    WitField,
    WitFunc,
    WitInterface,
    WitList,
    WitOption,
    WitPrimitive,
    WitRecord,
    WitRef,
    WitResult,
    WitType,
    WitTypeAlias,
    WitUse,
    WitVariant,
    WitVariantCase,
    WitWorld,
)


def extract_wit(wasm_path: str | Path) -> str:
    """Run wasm-tools to extract WIT from a WASM component binary."""
    try:
        result = subprocess.run(
            ["wasm-tools", "component", "wit", str(wasm_path)],
            capture_output=True,
            text=True,
            check=True,
        )
    except FileNotFoundError:
        raise FileNotFoundError(
            "wasm-tools not found on PATH. Install it with: "
            "cargo install wasm-tools "
            "(or use the devcontainer which includes it)"
        ) from None
    return result.stdout


# ---------------------------------------------------------------------------
# Tokenizer
# ---------------------------------------------------------------------------

_TOKEN_RE = re.compile(
    r"""
    //[^\n]*                  |  # line comment (skip)
    ->                        |  # arrow (must be before identifier)
    [a-zA-Z][a-zA-Z0-9\-]*   |  # identifier (may contain hyphens)
    [{}()<>,;:=]              |  # punctuation
    \*                        |  # star (for use X.{*})
    _                         |  # underscore (result<_, E>)
    \.                        |  # dot
    /                         |  # slash (for qualified names)
    \s+                          # whitespace (skip)
    """,
    re.VERBOSE,
)


def _tokenize(text: str) -> list[str]:
    tokens: list[str] = []
    last_end = 0
    for m in _TOKEN_RE.finditer(text):
        if m.start() != last_end:
            skipped = text[last_end : m.start()]
            raise SyntaxError(
                f"Unexpected character(s) {skipped!r} at position {last_end}"
            )
        last_end = m.end()
        tok = m.group()
        if tok.startswith("//") or tok.isspace():
            continue
        tokens.append(tok)
    if last_end != len(text):
        skipped = text[last_end:]
        raise SyntaxError(f"Unexpected character(s) {skipped!r} at position {last_end}")
    return tokens


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


class _Parser:
    def __init__(self, tokens: list[str]) -> None:
        self.tokens = tokens
        self.pos = 0

    def peek(self) -> str | None:
        if self.pos < len(self.tokens):
            return self.tokens[self.pos]
        return None

    def advance(self) -> str:
        if self.pos >= len(self.tokens):
            raise SyntaxError(f"Unexpected end of input at position {self.pos}")
        tok = self.tokens[self.pos]
        self.pos += 1
        return tok

    def expect(self, expected: str) -> str:
        tok = self.advance()
        if tok != expected:
            raise SyntaxError(
                f"Expected {expected!r}, got {tok!r} at position {self.pos - 1}"
            )
        return tok

    def at(self, expected: str) -> bool:
        return self.peek() == expected

    def eat(self, expected: str) -> bool:
        if self.at(expected):
            self.advance()
            return True
        return False

    # -- Type parsing --

    def parse_type(self) -> WitType:
        tok = self.peek()
        if tok == "list":
            return self._parse_list_type()
        if tok == "option":
            return self._parse_option_type()
        if tok == "result":
            return self._parse_result_type()
        if tok in ("string", "bool", "u32", "u64", "s32", "s64", "f32", "f64"):
            return WitPrimitive(self.advance())
        # Named reference
        name = self.advance()
        return WitRef(name)

    def _parse_list_type(self) -> WitList:
        self.expect("list")
        self.expect("<")
        elem = self.parse_type()
        self.expect(">")
        return WitList(elem)

    def _parse_option_type(self) -> WitOption:
        self.expect("option")
        self.expect("<")
        inner = self.parse_type()
        self.expect(">")
        return WitOption(inner)

    def _parse_result_type(self) -> WitResult:
        self.expect("result")
        self.expect("<")
        # Ok type: _ means no Ok payload
        if self.at("_"):
            self.advance()
            ok_type = None
        else:
            ok_type = self.parse_type()
        self.expect(",")
        err_type = self.parse_type()
        self.expect(">")
        return WitResult(ok_type, err_type)

    # -- Field parsing --

    def parse_field(self) -> WitField:
        name = self.advance()
        self.expect(":")
        ty = self.parse_type()
        return WitField(name, ty)

    # -- Top-level definitions --

    def parse_record(self) -> WitRecord:
        self.expect("record")
        name = self.advance()
        self.expect("{")
        fields: list[WitField] = []
        while not self.at("}"):
            fields.append(self.parse_field())
            self.eat(",")
        self.expect("}")
        return WitRecord(name, fields)

    def parse_variant(self) -> WitVariant:
        self.expect("variant")
        name = self.advance()
        self.expect("{")
        cases: list[WitVariantCase] = []
        while not self.at("}"):
            case_name = self.advance()
            payload: WitType | None = None
            if self.eat("("):
                payload = self.parse_type()
                self.expect(")")
            cases.append(WitVariantCase(case_name, payload))
            self.eat(",")
        self.expect("}")
        return WitVariant(name, cases)

    def parse_enum(self) -> WitEnum:
        self.expect("enum")
        name = self.advance()
        self.expect("{")
        cases: list[str] = []
        while not self.at("}"):
            cases.append(self.advance())
            self.eat(",")
        self.expect("}")
        return WitEnum(name, cases)

    def parse_type_alias(self) -> WitTypeAlias:
        self.expect("type")
        name = self.advance()
        self.expect("=")
        target = self.parse_type()
        self.expect(";")
        return WitTypeAlias(name, target)

    def parse_func(self) -> WitFunc:
        name = self.advance()
        self.expect(":")
        self.expect("func")
        self.expect("(")
        params: list[WitField] = []
        while not self.at(")"):
            params.append(self.parse_field())
            self.eat(",")
        self.expect(")")
        result_type: WitType | None = None
        if self.eat("->"):
            result_type = self.parse_type()
        self.expect(";")
        return WitFunc(name, params, result_type)

    def parse_export_func(self) -> WitFunc:
        self.expect("export")
        return self.parse_func()

    def _parse_qualified_name(self) -> str:
        """Parse a potentially qualified name like arcjet:js-req/filter-overrides."""
        name = self.advance()
        # Handle colon: arcjet:js-req
        if self.eat(":"):
            name = name + ":" + self.advance()
        # Handle slash: .../filter-overrides
        if self.eat("/"):
            name = name + "/" + self.advance()
        return name

    def parse_use(self) -> WitUse:
        self.expect("use")
        # arcjet:js-req/sensitive-information-identifier.{sensitive-info-entity}
        interface = self._parse_qualified_name()
        # After qualified name, there's a dot then {names}
        self.expect(".")
        self.expect("{")
        names: list[str] = []
        while not self.at("}"):
            names.append(self.advance())
            self.eat(",")
        self.expect("}")
        self.expect(";")
        return WitUse(interface, names)

    def parse_interface(self) -> WitInterface:
        self.expect("interface")
        name = self.advance()
        self.expect("{")
        iface = WitInterface(name)
        while not self.at("}"):
            tok = self.peek()
            if tok == "record":
                iface.types.append(self.parse_record())
            elif tok == "variant":
                iface.types.append(self.parse_variant())
            elif tok == "enum":
                iface.types.append(self.parse_enum())
            elif tok == "type":
                iface.types.append(self.parse_type_alias())
            else:
                iface.funcs.append(self.parse_func())
        self.expect("}")
        return iface

    def parse_world(self, package: str) -> WitWorld:
        self.expect("world")
        name = self.advance()
        self.expect("{")
        world = WitWorld(name, package)
        while not self.at("}"):
            tok = self.peek()
            if tok == "import":
                self.advance()
                # import arcjet:js-req/filter-overrides;
                import_name = self._parse_qualified_name()
                self.expect(";")
                # We'll resolve the interface later from the parsed interfaces
                world.imports.append(WitInterface(import_name))
            elif tok == "export":
                world.exports.append(self.parse_export_func())
            elif tok == "use":
                world.uses.append(self.parse_use())
            elif tok == "record":
                world.types.append(self.parse_record())
            elif tok == "variant":
                world.types.append(self.parse_variant())
            elif tok == "enum":
                world.types.append(self.parse_enum())
            elif tok == "type":
                world.types.append(self.parse_type_alias())
            else:
                raise SyntaxError(
                    f"Unexpected token {tok!r} in world at position {self.pos}"
                )
        self.expect("}")
        return world

    def parse_package_block(self) -> tuple[str, WitWorld | None, list[WitInterface]]:
        """Parse a package block: package P; world/interface ..."""
        self.expect("package")
        # Package name: root:component or arcjet:js-req
        pkg_parts: list[str] = []
        pkg_parts.append(self.advance())
        while self.eat(":"):
            pkg_parts.append(self.advance())
        pkg_name = ":".join(pkg_parts)

        world: WitWorld | None = None
        interfaces: list[WitInterface] = []

        if self.eat(";"):
            # package root:component; followed by world/interface at top level
            while self.pos < len(self.tokens) and self.peek() != "package":
                tok = self.peek()
                if tok == "world":
                    world = self.parse_world(pkg_name)
                elif tok == "interface":
                    interfaces.append(self.parse_interface())
                else:
                    break
        elif self.eat("{"):
            # package arcjet:js-req { interface ... }
            while not self.at("}"):
                tok = self.peek()
                if tok == "interface":
                    interfaces.append(self.parse_interface())
                elif tok == "world":
                    world = self.parse_world(pkg_name)
                else:
                    raise SyntaxError(
                        f"Unexpected {tok!r} in package block at position {self.pos}"
                    )
            self.expect("}")

        return pkg_name, world, interfaces


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def parse_wit(text: str) -> tuple[WitWorld, list[WitInterface]]:
    """Parse WIT text into a world and list of import interfaces.

    Returns (world, interfaces) where world contains the exports and
    world-level types, and interfaces contains the import interface definitions.
    """
    tokens = _tokenize(text)
    parser = _Parser(tokens)

    world: WitWorld | None = None
    all_interfaces: list[WitInterface] = []

    while parser.pos < len(parser.tokens):
        _pkg_name, pkg_world, pkg_interfaces = parser.parse_package_block()
        if pkg_world is not None:
            world = pkg_world
        all_interfaces.extend(pkg_interfaces)

    if world is None:
        raise ValueError("No world found in WIT text")

    # Resolve import stubs: replace WitInterface stubs with full definitions
    iface_by_name: dict[str, WitInterface] = {}
    for iface in all_interfaces:
        iface_by_name[iface.name] = iface

    resolved_imports: list[WitInterface] = []
    for imp in world.imports:
        # Import name might be "arcjet:js-req/filter-overrides"
        # The interface name is just "filter-overrides"
        short_name = imp.name.split("/")[-1] if "/" in imp.name else imp.name
        if short_name in iface_by_name:
            full = iface_by_name[short_name]
            # Preserve the full qualified name
            resolved = WitInterface(imp.name, full.types, full.funcs)
            resolved_imports.append(resolved)
        else:
            resolved_imports.append(imp)

    world.imports = resolved_imports
    return world, all_interfaces
