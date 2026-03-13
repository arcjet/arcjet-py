"""Tests for the WIT tokenizer and parser."""

from __future__ import annotations

import pytest

from tools.witgen.ir import (
    WitEnum,
    WitField,
    WitFunc,
    WitList,
    WitOption,
    WitPrimitive,
    WitRecord,
    WitRef,
    WitResult,
    WitTypeAlias,
    WitVariant,
    WitVariantCase,
)
from tools.witgen.wit_parser import _Parser, _tokenize, parse_wit


# ---------------------------------------------------------------------------
# Tokenizer tests
# ---------------------------------------------------------------------------


class TestTokenize:
    def test_keywords_and_identifiers(self) -> None:
        tokens = _tokenize("package world interface export import")
        assert tokens == ["package", "world", "interface", "export", "import"]

    def test_punctuation(self) -> None:
        tokens = _tokenize("{ } ( ) < > , ; : =")
        assert tokens == ["{", "}", "(", ")", "<", ">", ",", ";", ":", "="]

    def test_arrow(self) -> None:
        tokens = _tokenize("-> foo")
        assert tokens == ["->", "foo"]

    def test_star_underscore_dot_slash(self) -> None:
        tokens = _tokenize("* _ . /")
        assert tokens == ["*", "_", ".", "/"]

    def test_hyphenated_identifiers(self) -> None:
        tokens = _tokenize("my-type some-long-name")
        assert tokens == ["my-type", "some-long-name"]

    def test_line_comments_stripped(self) -> None:
        tokens = _tokenize("foo // this is a comment\nbar")
        assert tokens == ["foo", "bar"]

    def test_whitespace_stripped(self) -> None:
        tokens = _tokenize("  foo   bar  \n  baz  ")
        assert tokens == ["foo", "bar", "baz"]

    def test_empty_input(self) -> None:
        assert _tokenize("") == []
        assert _tokenize("   ") == []
        assert _tokenize("// only a comment\n") == []

    def test_unexpected_character_raises(self) -> None:
        with pytest.raises(SyntaxError, match="Unexpected character"):
            _tokenize('foo "string-literal"')

    def test_gap_detection(self) -> None:
        # @ is not matched by any token pattern
        with pytest.raises(SyntaxError, match="Unexpected character"):
            _tokenize("foo @bar")


# ---------------------------------------------------------------------------
# parse_type tests
# ---------------------------------------------------------------------------


class TestParseType:
    @staticmethod
    def _parse(wit_type_str: str) -> object:
        tokens = _tokenize(wit_type_str)
        parser = _Parser(tokens)
        return parser.parse_type()

    @pytest.mark.parametrize(
        "name",
        ["string", "bool", "u32", "u64", "s32", "s64", "f32", "f64"],
    )
    def test_primitive_types(self, name: str) -> None:
        result = self._parse(name)
        assert result == WitPrimitive(name)

    def test_list_type(self) -> None:
        result = self._parse("list<string>")
        assert result == WitList(WitPrimitive("string"))

    def test_nested_list(self) -> None:
        result = self._parse("list<list<u32>>")
        assert result == WitList(WitList(WitPrimitive("u32")))

    def test_option_type(self) -> None:
        result = self._parse("option<bool>")
        assert result == WitOption(WitPrimitive("bool"))

    def test_result_type(self) -> None:
        result = self._parse("result<string, string>")
        assert result == WitResult(WitPrimitive("string"), WitPrimitive("string"))

    def test_result_with_underscore_ok(self) -> None:
        result = self._parse("result<_, string>")
        assert result == WitResult(None, WitPrimitive("string"))

    def test_named_ref(self) -> None:
        result = self._parse("my-custom-type")
        assert result == WitRef("my-custom-type")

    def test_list_of_option(self) -> None:
        result = self._parse("list<option<string>>")
        assert result == WitList(WitOption(WitPrimitive("string")))

    def test_result_with_record_ref(self) -> None:
        result = self._parse("result<my-record, string>")
        assert result == WitResult(WitRef("my-record"), WitPrimitive("string"))


# ---------------------------------------------------------------------------
# parse_wit tests — small WIT snippets
# ---------------------------------------------------------------------------


class TestParseWit:
    def test_minimal_world_with_export(self) -> None:
        wit = """
        package root:component;
        world root {
            export do-thing: func(input: string) -> string;
        }
        """
        world, _ifaces = parse_wit(wit)
        assert world.name == "root"
        assert world.package == "root:component"
        assert len(world.exports) == 1
        f = world.exports[0]
        assert f.name == "do-thing"
        assert f.params == [WitField("input", WitPrimitive("string"))]
        assert f.result == WitPrimitive("string")

    def test_export_no_return(self) -> None:
        wit = """
        package root:component;
        world root {
            export fire: func(x: u32);
        }
        """
        world, _ = parse_wit(wit)
        assert world.exports[0].result is None

    def test_record_type(self) -> None:
        wit = """
        package root:component;
        world root {
            record my-rec {
                name: string,
                age: u32,
            }
            export noop: func();
        }
        """
        world, _ = parse_wit(wit)
        assert len(world.types) == 1
        rec = world.types[0]
        assert isinstance(rec, WitRecord)
        assert rec.name == "my-rec"
        assert rec.fields == [
            WitField("name", WitPrimitive("string")),
            WitField("age", WitPrimitive("u32")),
        ]

    def test_enum_type(self) -> None:
        wit = """
        package root:component;
        world root {
            enum color {
                red,
                green,
                blue,
            }
            export noop: func();
        }
        """
        world, _ = parse_wit(wit)
        assert len(world.types) == 1
        e = world.types[0]
        assert isinstance(e, WitEnum)
        assert e.name == "color"
        assert e.cases == ["red", "green", "blue"]

    def test_variant_type(self) -> None:
        wit = """
        package root:component;
        world root {
            variant shape {
                circle(f32),
                square(f32),
                none,
            }
            export noop: func();
        }
        """
        world, _ = parse_wit(wit)
        assert len(world.types) == 1
        v = world.types[0]
        assert isinstance(v, WitVariant)
        assert v.name == "shape"
        assert v.cases == [
            WitVariantCase("circle", WitPrimitive("f32")),
            WitVariantCase("square", WitPrimitive("f32")),
            WitVariantCase("none", None),
        ]

    def test_type_alias(self) -> None:
        wit = """
        package root:component;
        world root {
            type my-string = string;
            export noop: func();
        }
        """
        world, _ = parse_wit(wit)
        assert len(world.types) == 1
        alias = world.types[0]
        assert isinstance(alias, WitTypeAlias)
        assert alias.name == "my-string"
        assert alias.target == WitPrimitive("string")

    def test_import_interface_resolved(self) -> None:
        wit = """
        package root:component;
        world root {
            import arcjet:js-req/my-iface;
            export noop: func();
        }
        package arcjet:js-req {
            interface my-iface {
                record point {
                    x: f32,
                    y: f32,
                }
                do-stuff: func(p: point) -> bool;
            }
        }
        """
        world, ifaces = parse_wit(wit)
        assert len(world.imports) == 1
        imp = world.imports[0]
        assert imp.name == "arcjet:js-req/my-iface"
        # Resolved: should have the record and func from the interface definition
        assert len(imp.types) == 1
        assert isinstance(imp.types[0], WitRecord)
        assert imp.types[0].name == "point"
        assert len(imp.funcs) == 1
        assert imp.funcs[0].name == "do-stuff"

    def test_interface_with_enum_and_func(self) -> None:
        wit = """
        package test:pkg {
            interface my-iface {
                enum level {
                    low,
                    high,
                }
                check: func(l: level) -> bool;
            }
        }
        package root:component;
        world root {
            import test:pkg/my-iface;
            export noop: func();
        }
        """
        world, ifaces = parse_wit(wit)
        assert len(ifaces) == 1
        iface = ifaces[0]
        assert iface.name == "my-iface"
        assert len(iface.types) == 1
        assert isinstance(iface.types[0], WitEnum)
        assert len(iface.funcs) == 1

    def test_no_world_raises(self) -> None:
        wit = """
        package test:pkg {
            interface foo {
                bar: func();
            }
        }
        """
        with pytest.raises(ValueError, match="No world found"):
            parse_wit(wit)

    def test_use_statement(self) -> None:
        wit = """
        package root:component;
        world root {
            use arcjet:js-req/utils.{my-type};
            export noop: func();
        }
        """
        world, _ = parse_wit(wit)
        assert len(world.uses) == 1
        use = world.uses[0]
        assert use.interface == "arcjet:js-req/utils"
        assert use.names == ["my-type"]

    def test_multiple_export_params(self) -> None:
        wit = """
        package root:component;
        world root {
            export combine: func(a: string, b: u32, c: bool) -> string;
        }
        """
        world, _ = parse_wit(wit)
        f = world.exports[0]
        assert len(f.params) == 3
        assert f.params[0] == WitField("a", WitPrimitive("string"))
        assert f.params[1] == WitField("b", WitPrimitive("u32"))
        assert f.params[2] == WitField("c", WitPrimitive("bool"))

    def test_complex_return_type(self) -> None:
        wit = """
        package root:component;
        world root {
            export check: func() -> result<list<string>, string>;
        }
        """
        world, _ = parse_wit(wit)
        f = world.exports[0]
        assert f.result == WitResult(
            WitList(WitPrimitive("string")), WitPrimitive("string")
        )
