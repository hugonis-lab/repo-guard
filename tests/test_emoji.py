"""Unit tests for repo_guard/emoji.py (Unicode 16.0 UTS #51 UI emoji detector).

Zero literal emoji characters are allowed anywhere in this file (not even in
comments or docstrings). All literal emoji test strings are built at runtime
with chr(...). The file is also pure ASCII so it passes `audit-repo --strict`
with no findings, and it doubles as a self-check that the LITERAL_EMOJI_RE
pattern has zero matches inside the test file itself.
"""

from __future__ import annotations

import dataclasses
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from repo_guard.emoji import (  # noqa: E402
    ALWAYS_UI_EXTENSIONS,
    UI_SCRIPT_EXTENSIONS,
    CSS_EXTENSIONS,
    LITERAL_EMOJI_RE,
    EmojiMatch,
    _is_css_path,
    format_codepoints,
    find_ui_emojis,
    is_bmp_vs16_emoji_base,
    is_direct_emoji_codepoint,
    is_ui_source_path,
)

# Runtime builders: avoids any literal non-ASCII character in the source file.
def bmp(cp: int) -> str:
    return chr(cp)


def smp(cp: int) -> str:
    return chr(cp)


def vs16() -> str:
    return chr(0xFE0F)


def zwj() -> str:
    return chr(0x200D)


class TestIsDirectEmojiCodepoint(unittest.TestCase):
    def test_bmp_emoji_presentation_range_boundaries(self) -> None:
        # First BMP EP range (0x231A, 0x231B)
        self.assertTrue(is_direct_emoji_codepoint(0x231A))
        self.assertTrue(is_direct_emoji_codepoint(0x231B))
        self.assertFalse(is_direct_emoji_codepoint(0x231C))
        # Single-codepoint BMP EP ranges
        self.assertTrue(is_direct_emoji_codepoint(0x23F0))
        self.assertFalse(is_direct_emoji_codepoint(0x23F1))
        self.assertTrue(is_direct_emoji_codepoint(0x26A1))
        self.assertFalse(is_direct_emoji_codepoint(0x26A2))
        self.assertTrue(is_direct_emoji_codepoint(0x2705))
        self.assertFalse(is_direct_emoji_codepoint(0x2706))
        self.assertTrue(is_direct_emoji_codepoint(0x2B50))
        self.assertFalse(is_direct_emoji_codepoint(0x2B4F))
        self.assertTrue(is_direct_emoji_codepoint(0x2B55))
        self.assertFalse(is_direct_emoji_codepoint(0x2B56))

    def test_bmp_emoji_presentation_range_internal_points(self) -> None:
        self.assertTrue(is_direct_emoji_codepoint(0x23F3))
        self.assertTrue(is_direct_emoji_codepoint(0x2614))
        self.assertTrue(is_direct_emoji_codepoint(0x2648))
        self.assertTrue(is_direct_emoji_codepoint(0x2653))
        self.assertTrue(is_direct_emoji_codepoint(0x26F2))
        self.assertTrue(is_direct_emoji_codepoint(0x26FD))
        self.assertTrue(is_direct_emoji_codepoint(0x2728))
        self.assertTrue(is_direct_emoji_codepoint(0x274C))
        self.assertTrue(is_direct_emoji_codepoint(0x2753))
        self.assertTrue(is_direct_emoji_codepoint(0x2795))
        self.assertTrue(is_direct_emoji_codepoint(0x27B0))
        self.assertTrue(is_direct_emoji_codepoint(0x27BF))
        self.assertTrue(is_direct_emoji_codepoint(0x2B1B))
        self.assertTrue(is_direct_emoji_codepoint(0x2B1C))

    def test_bmp_emoji_presentation_gaps(self) -> None:
        self.assertFalse(is_direct_emoji_codepoint(0x2319))
        self.assertFalse(is_direct_emoji_codepoint(0x231C))
        self.assertFalse(is_direct_emoji_codepoint(0x23E8))
        self.assertFalse(is_direct_emoji_codepoint(0x23F2))
        self.assertFalse(is_direct_emoji_codepoint(0x23F4))
        self.assertFalse(is_direct_emoji_codepoint(0x25FC))
        self.assertFalse(is_direct_emoji_codepoint(0x26A0))  # BMP XP-only, not EP
        self.assertFalse(is_direct_emoji_codepoint(0x2713))   # monochrome checkmark
        self.assertFalse(is_direct_emoji_codepoint(0x2764))   # heart, not EP
        self.assertFalse(is_direct_emoji_codepoint(0x2B4F))

    def test_smp_emoji_range_boundaries(self) -> None:
        self.assertTrue(is_direct_emoji_codepoint(0x1F004))
        self.assertFalse(is_direct_emoji_codepoint(0x1F003))
        self.assertTrue(is_direct_emoji_codepoint(0x1F680))
        self.assertTrue(is_direct_emoji_codepoint(0x1F6C5))
        self.assertTrue(is_direct_emoji_codepoint(0x1FC00))
        self.assertTrue(is_direct_emoji_codepoint(0x1FFFD))
        self.assertFalse(is_direct_emoji_codepoint(0x1F6C6))
        self.assertFalse(is_direct_emoji_codepoint(0x1FFFE))

    def test_smp_emoji_ranges_and_gaps(self) -> None:
        self.assertTrue(is_direct_emoji_codepoint(0x1F02C))
        self.assertTrue(is_direct_emoji_codepoint(0x1F1AE))
        self.assertTrue(is_direct_emoji_codepoint(0x1F1FF))
        self.assertFalse(is_direct_emoji_codepoint(0x1F1AD))
        self.assertTrue(is_direct_emoji_codepoint(0x1F3F4))
        self.assertTrue(is_direct_emoji_codepoint(0x1F3FD))
        self.assertTrue(is_direct_emoji_codepoint(0x1F4FD))
        self.assertTrue(is_direct_emoji_codepoint(0x1F4AC))
        self.assertFalse(is_direct_emoji_codepoint(0x1F4FE))
        self.assertTrue(is_direct_emoji_codepoint(0x1FA58))
        self.assertTrue(is_direct_emoji_codepoint(0x1FAFF))
        self.assertFalse(is_direct_emoji_codepoint(0x1FA60))

    def test_below_and_above_all_ranges(self) -> None:
        self.assertFalse(is_direct_emoji_codepoint(0x0000))
        self.assertFalse(is_direct_emoji_codepoint(0x0041))
        self.assertFalse(is_direct_emoji_codepoint(0x2319))
        self.assertFalse(is_direct_emoji_codepoint(0x1FFFE))
        self.assertFalse(is_direct_emoji_codepoint(0x10FFFF))


class TestIsBmpVs16EmojiBase(unittest.TestCase):
    def test_true_for_bmp_extended_pictographic(self) -> None:
        for cp in (0x00A9, 0x00AE, 0x2122, 0x26A0, 0x2764, 0x2714, 0x25B6, 0x26A1, 0x3299):
            self.assertTrue(is_bmp_vs16_emoji_base(cp), f"expected XP base for {cp:#06x}")

    def test_true_for_additional_bmp_xp_glyphs(self) -> None:
        for cp in (0x203C, 0x2049, 0x2139, 0x2194, 0x2199, 0x21A9, 0x231A, 0x2328, 0x23CF):
            self.assertTrue(is_bmp_vs16_emoji_base(cp), f"expected XP base for {cp:#06x}")

    def test_false_for_non_xp_bmp_glyphs(self) -> None:
        for cp in (0x0041, 0x2713, 0x2717, 0x2605, 0x2192, 0x2022, 0x2014, 0x2026, 0x00B0):
            self.assertFalse(is_bmp_vs16_emoji_base(cp), f"expected non-XP for {cp:#06x}")

    def test_false_for_bmp_surrogate_codepoints(self) -> None:
        self.assertFalse(is_bmp_vs16_emoji_base(0xD800))
        self.assertFalse(is_bmp_vs16_emoji_base(0xDC00))
        self.assertFalse(is_bmp_vs16_emoji_base(0xDFFF))

    def test_false_for_smp_and_non_bmp_codepoints(self) -> None:
        self.assertFalse(is_bmp_vs16_emoji_base(0x10000))
        self.assertFalse(is_bmp_vs16_emoji_base(0x1F680))
        self.assertFalse(is_bmp_vs16_emoji_base(0x10FFFF))


class TestFormatCodepoints(unittest.TestCase):
    def test_empty_string_returns_empty(self) -> None:
        self.assertEqual(format_codepoints(""), "")

    def test_single_bmp_character_zero_pads_to_four_hex_digits(self) -> None:
        self.assertEqual(format_codepoints("1"), "U+0031")
        self.assertEqual(format_codepoints(bmp(0x00A9)), "U+00A9")
        self.assertEqual(format_codepoints("A"), "U+0041")

    def test_single_smp_character(self) -> None:
        self.assertEqual(format_codepoints(smp(0x1F680)), "U+1F680")
        self.assertEqual(format_codepoints(smp(0x1F4BB)), "U+1F4BB")

    def test_multi_codepoint_cluster_is_space_separated(self) -> None:
        self.assertEqual(format_codepoints(bmp(0x26A0) + vs16()), "U+26A0 U+FE0F")
        self.assertEqual(
            format_codepoints(smp(0x1F469) + zwj() + smp(0x1F4BB)),
            "U+1F469 U+200D U+1F4BB",
        )

    def test_zwj_sequence_after_base_with_vs16(self) -> None:
        cluster = bmp(0x26A0) + vs16() + zwj() + smp(0x1F680)
        self.assertEqual(format_codepoints(cluster), "U+26A0 U+FE0F U+200D U+1F680")


class TestIsUiSourcePath(unittest.TestCase):
    def test_every_always_ui_extension_matches_lowercase_and_uppercase(self) -> None:
        for ext in ALWAYS_UI_EXTENSIONS:
            self.assertTrue(is_ui_source_path("src/App" + ext), f"expected UI path for {ext}")
            self.assertTrue(is_ui_source_path("src/App" + ext.upper()), f"expected UI path for {ext.upper()}")

    def test_every_script_extension_matches_lowercase_and_uppercase(self) -> None:
        for ext in UI_SCRIPT_EXTENSIONS:
            self.assertTrue(is_ui_source_path("src/App" + ext), f"expected UI path for {ext}")
            self.assertTrue(is_ui_source_path("src/App" + ext.upper()), f"expected UI path for {ext.upper()}")

    def test_normalization_leading_dot_slash_and_windows_separators(self) -> None:
        self.assertTrue(is_ui_source_path("./src/App.tsx"))
        self.assertTrue(is_ui_source_path("././src/App.tsx"))
        self.assertTrue(is_ui_source_path("src\\components\\Button.tsx"))
        self.assertTrue(is_ui_source_path("./src\\components\\Button.tsx"))

    def test_non_ui_paths(self) -> None:
        for path in (
            "",
            "commit:abc123",
            "COMMIT_EDITMSG",
            "src/a.py",
            "src/a.md",
            "src/a.json",
            "src/a.toml",
            "src/a.rs",
            "Makefile",
            "src/README",
        ):
            self.assertFalse(is_ui_source_path(path), f"expected non-UI path: {path!r}")

    def test_excluded_directories_top_level_and_nested(self) -> None:
        for excluded in (
            "test", "tests", "__tests__", "__mocks__", "spec", "specs",
            "fixture", "fixtures", "testdata", "node_modules", ".git",
        ):
            self.assertFalse(is_ui_source_path(excluded + "/a.tsx"), f"expected exclusion: {excluded}")
            self.assertFalse(is_ui_source_path("src/" + excluded + "/a.tsx"), f"expected nested exclusion: {excluded}")
            self.assertFalse(is_ui_source_path("src/nested/" + excluded + "/a.tsx"), f"expected deep exclusion: {excluded}")

    def test_excluded_directories_case_insensitive(self) -> None:
        self.assertFalse(is_ui_source_path("TEST/a.tsx"))
        self.assertFalse(is_ui_source_path("src/Tests/a.tsx"))
        self.assertFalse(is_ui_source_path("src/test/nested/a.tsx"))

    def test_non_excluded_directories_with_excluded_substring(self) -> None:
        self.assertTrue(is_ui_source_path("src/contest/App.tsx"))
        self.assertTrue(is_ui_source_path("src/inspector/view.html"))
        self.assertTrue(is_ui_source_path("src/spectrum/page.css"))

    def test_excluded_test_filenames(self) -> None:
        for path in (
            "test_app.tsx",
            "test-ui.js",
            "test.html",
            "App.test.tsx",
            "app_test.js",
            "button.spec.ts",
            "conftest.js",
            "TEST_APP.TSX",
            "APP_TEST.JS",
            "BUTTON.SPEC.TS",
            "CONFTEST.JS",
            "src/test_app.tsx",
            "src/conftest.ts",
        ):
            self.assertFalse(is_ui_source_path(path), f"expected test filename exclusion: {path!r}")

    def test_non_test_filenames_with_similar_names(self) -> None:
        for path in (
            "src/contest.tsx",
            "src/spectrum.css",
            "src/latest.js",
            "src/contestant.tsx",
            "src/testified.css",
        ):
            self.assertTrue(is_ui_source_path(path), f"expected UI path: {path!r}")

    def test_css_path_helper_and_extension_set(self) -> None:
        self.assertEqual(CSS_EXTENSIONS, frozenset({".css", ".scss", ".sass", ".less"}))
        self.assertTrue(_is_css_path("styles/main.css"))
        self.assertTrue(_is_css_path("styles/main.CSS"))
        self.assertTrue(_is_css_path("styles/main.scss"))
        self.assertTrue(_is_css_path("styles/main.sass"))
        self.assertTrue(_is_css_path("styles/main.less"))
        self.assertTrue(_is_css_path("styles\\main.scss"))
        self.assertFalse(_is_css_path("src/a.js"))
        self.assertFalse(_is_css_path(""))


class TestFindUiEmojisBasics(unittest.TestCase):
    def test_empty_line_returns_empty(self) -> None:
        self.assertEqual(find_ui_emojis("", "a.tsx"), [])
        self.assertEqual(find_ui_emojis("", ""), [])

    def test_pure_ascii_fast_path_returns_empty(self) -> None:
        self.assertEqual(find_ui_emojis("plain ascii text", "a.tsx"), [])
        self.assertEqual(find_ui_emojis("plain ascii text", "a.css"), [])

    def test_match_attributes_and_frozen_dataclass(self) -> None:
        line = "x" + smp(0x1F680) + "y"
        matches = find_ui_emojis(line, "a.tsx")
        self.assertEqual(len(matches), 1)
        m = matches[0]
        self.assertIsInstance(m, EmojiMatch)
        self.assertEqual(m.start, 1)
        self.assertEqual(m.end, 2)
        self.assertEqual(m.raw, smp(0x1F680))
        self.assertEqual(m.codepoints, "U+1F680")
        self.assertEqual(m.kind, "literal")
        with self.assertRaises(dataclasses.FrozenInstanceError):
            m.start = 0  # type: ignore[misc]
        with self.assertRaises(dataclasses.FrozenInstanceError):
            m.kind = "html_entity"  # type: ignore[misc]

    def test_frozen_dataclass_equality_and_hash(self) -> None:
        m1 = EmojiMatch(start=0, end=1, raw="a", codepoints="U+0041", kind="literal")
        m2 = EmojiMatch(start=0, end=1, raw="a", codepoints="U+0041", kind="literal")
        self.assertEqual(m1, m2)
        self.assertEqual(hash(m1), hash(m2))


class TestFindUiEmojisLiteral(unittest.TestCase):
    def test_bmp_emoji_presentation_literal(self) -> None:
        matches = find_ui_emojis(bmp(0x26A1), "a.tsx")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].kind, "literal")
        self.assertEqual(matches[0].codepoints, "U+26A1")
        self.assertEqual(matches[0].raw, bmp(0x26A1))
        self.assertEqual(find_ui_emojis(bmp(0x2705), "a.tsx")[0].codepoints, "U+2705")

    def test_smp_pictograph_literal(self) -> None:
        self.assertEqual(find_ui_emojis(smp(0x1F680), "a.tsx")[0].codepoints, "U+1F680")
        self.assertEqual(find_ui_emojis(smp(0x1F6E0), "a.tsx")[0].codepoints, "U+1F6E0")

    def test_bmp_xp_with_vs16_literal(self) -> None:
        matches = find_ui_emojis(bmp(0x26A0) + vs16(), "a.tsx")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].kind, "literal")
        self.assertEqual(matches[0].codepoints, "U+26A0 U+FE0F")
        self.assertEqual(matches[0].raw, bmp(0x26A0) + vs16())
        self.assertEqual(find_ui_emojis(bmp(0x2764) + vs16(), "a.tsx")[0].codepoints, "U+2764 U+FE0F")
        self.assertEqual(find_ui_emojis(bmp(0x00A9) + vs16(), "a.tsx")[0].codepoints, "U+00A9 U+FE0F")

    def test_bmp_xp_without_vs16_is_not_detected(self) -> None:
        self.assertEqual(find_ui_emojis(bmp(0x26A0), "a.tsx"), [])
        self.assertEqual(find_ui_emojis(bmp(0x2764), "a.tsx"), [])
        self.assertEqual(find_ui_emojis(bmp(0x00A9), "a.tsx"), [])

    def test_clean_monochrome_symbols_are_ignored(self) -> None:
        for cp in (
            0x2713, 0x2717, 0x2715, 0x270F, 0x2726, 0x25B8, 0x25B6,
            0x25CB, 0x25CF, 0x2605, 0x2192, 0x2197, 0x00A9, 0x00AE, 0x2122,
            0x2014, 0x2026,
        ):
            self.assertEqual(find_ui_emojis(bmp(cp), "a.tsx"), [], f"expected clean symbol {cp:#06x}")

    def test_skin_tone_modifier_cluster_is_single_match(self) -> None:
        cluster = smp(0x1F44D) + smp(0x1F3FD)
        matches = find_ui_emojis(cluster, "a.tsx")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].kind, "literal")
        self.assertEqual(matches[0].codepoints, "U+1F44D U+1F3FD")
        self.assertEqual(matches[0].raw, cluster)

    def test_keycap_sequences(self) -> None:
        k1 = "1" + vs16() + chr(0x20E3)
        matches = find_ui_emojis(k1, "a.tsx")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].codepoints, "U+0031 U+FE0F U+20E3")
        k2 = "#" + chr(0x20E3)
        self.assertEqual(find_ui_emojis(k2, "a.tsx")[0].codepoints, "U+0023 U+20E3")
        k3 = "*" + vs16() + chr(0x20E3)
        self.assertEqual(find_ui_emojis(k3, "a.tsx")[0].codepoints, "U+002A U+FE0F U+20E3")

    def test_plain_keycap_base_digits_ignored(self) -> None:
        self.assertEqual(find_ui_emojis("1", "a.tsx"), [])
        self.assertEqual(find_ui_emojis("#", "a.tsx"), [])
        self.assertEqual(find_ui_emojis("*", "a.tsx"), [])

    def test_regional_indicator_flag_is_single_match(self) -> None:
        matches = find_ui_emojis(smp(0x1F1FA) + smp(0x1F1F8), "a.tsx")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].codepoints, "U+1F1FA U+1F1F8")
        self.assertEqual(matches[0].kind, "literal")

    def test_tag_sequence_is_single_match(self) -> None:
        cluster = (
            smp(0x1F3F4) + chr(0xE0067) + chr(0xE0062) + chr(0xE0065)
            + chr(0xE006E) + chr(0xE0067) + chr(0xE007F)
        )
        matches = find_ui_emojis(cluster, "a.tsx")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].codepoints, "U+1F3F4 U+E0067 U+E0062 U+E0065 U+E006E U+E0067 U+E007F")
        self.assertEqual(matches[0].kind, "literal")

    def test_zwj_sequences_are_single_cluster_match(self) -> None:
        matches = find_ui_emojis(smp(0x1F469) + zwj() + smp(0x1F4BB), "a.tsx")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].kind, "literal")
        self.assertEqual(matches[0].codepoints, "U+1F469 U+200D U+1F4BB")

    def test_multi_joiner_zwj_sequence(self) -> None:
        cluster = smp(0x1F469) + zwj() + smp(0x1F415) + zwj() + smp(0x1F468)
        matches = find_ui_emojis(cluster, "a.tsx")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].codepoints, "U+1F469 U+200D U+1F415 U+200D U+1F468")

    def test_vs16_zwj_sequence(self) -> None:
        cluster = bmp(0x26A0) + vs16() + zwj() + smp(0x1F680)
        matches = find_ui_emojis(cluster, "a.tsx")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].codepoints, "U+26A0 U+FE0F U+200D U+1F680")


class TestFindUiEmojisHtmlEntities(unittest.TestCase):
    def test_hex_smp_entity(self) -> None:
        matches = find_ui_emojis("&#x1F680;", "a.html")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].kind, "html_entity")
        self.assertEqual(matches[0].codepoints, "U+1F680")
        self.assertEqual(matches[0].raw, "&#x1F680;")

    def test_lowercase_hex_smp_entity(self) -> None:
        self.assertEqual(find_ui_emojis("&#x1f680;", "a.html")[0].codepoints, "U+1F680")

    def test_decimal_smp_entity(self) -> None:
        self.assertEqual(find_ui_emojis("&#128640;", "a.html")[0].codepoints, "U+1F680")

    def test_bmp_ep_entity_hex_and_decimal(self) -> None:
        self.assertEqual(find_ui_emojis("&#x26A1;", "a.html")[0].codepoints, "U+26A1")
        self.assertEqual(find_ui_emojis("&#9889;", "a.html")[0].codepoints, "U+26A1")

    def test_bmp_xp_with_vs16_entity(self) -> None:
        m1 = find_ui_emojis("&#x26A0;&#xFE0F;", "a.html")
        self.assertEqual(len(m1), 1)
        self.assertEqual(m1[0].codepoints, "U+26A0 U+FE0F")
        self.assertEqual(m1[0].kind, "html_entity")

        m2 = find_ui_emojis("&#x26A0; &#xfe0f;", "a.html")
        self.assertEqual(len(m2), 1)
        self.assertEqual(m2[0].codepoints, "U+26A0 U+FE0F")

        m3 = find_ui_emojis("&#9888;&#65039;", "a.html")
        self.assertEqual(len(m3), 1)
        self.assertEqual(m3[0].codepoints, "U+26A0 U+FE0F")

    def test_non_emoji_and_bare_bmp_xp_entities_ignored(self) -> None:
        self.assertEqual(find_ui_emojis("&#x26A0;", "a.html"), [])
        self.assertEqual(find_ui_emojis("&#x2713;", "a.html"), [])
        self.assertEqual(find_ui_emojis("&#x2713;&#xFE0F;", "a.html"), [])
        self.assertEqual(find_ui_emojis("&#169;", "a.html"), [])


class TestFindUiEmojisJsEscapes(unittest.TestCase):
    def test_brace_escape_smp_and_bmp_ep(self) -> None:
        self.assertEqual(find_ui_emojis("\\u{1F680}", "a.ts")[0].codepoints, "U+1F680")
        self.assertEqual(find_ui_emojis("\\u{1f680}", "a.ts")[0].codepoints, "U+1F680")
        self.assertEqual(find_ui_emojis("\\u{26A1}", "a.ts")[0].codepoints, "U+26A1")

    def test_brace_escape_bmp_xp_with_vs16(self) -> None:
        m1 = find_ui_emojis("\\u{26A0}\\u{FE0F}", "a.ts")
        self.assertEqual(len(m1), 1)
        self.assertEqual(m1[0].codepoints, "U+26A0 U+FE0F")
        self.assertEqual(m1[0].kind, "js_escape")

        m2 = find_ui_emojis("\\u{26A0}\\uFE0F", "a.ts")
        self.assertEqual(len(m2), 1)
        self.assertEqual(m2[0].codepoints, "U+26A0 U+FE0F")

    def test_bare_bmp_xp_brace_escape_ignored(self) -> None:
        self.assertEqual(find_ui_emojis("\\u{26A0}", "a.ts"), [])

    def test_utf16_surrogate_pair_escape(self) -> None:
        m1 = find_ui_emojis("\\uD83D\\uDE80", "a.ts")
        self.assertEqual(len(m1), 1)
        self.assertEqual(m1[0].codepoints, "U+1F680")
        self.assertEqual(m1[0].kind, "js_escape")
        self.assertEqual(find_ui_emojis("\\ud83d\\ude80", "a.ts")[0].codepoints, "U+1F680")

    def test_non_emoji_surrogate_pair_ignored(self) -> None:
        self.assertEqual(find_ui_emojis("\\uD800\\uDC00", "a.ts"), [])

    def test_bmp_4_hex_escapes(self) -> None:
        m1 = find_ui_emojis("\\u26A1", "a.ts")
        self.assertEqual(len(m1), 1)
        self.assertEqual(m1[0].codepoints, "U+26A1")
        self.assertEqual(m1[0].kind, "js_escape")

        m2 = find_ui_emojis("\\u26A0\\uFE0F", "a.ts")
        self.assertEqual(len(m2), 1)
        self.assertEqual(m2[0].codepoints, "U+26A0 U+FE0F")

        m3 = find_ui_emojis("\\u26a0\\ufe0f", "a.ts")
        self.assertEqual(len(m3), 1)
        self.assertEqual(m3[0].codepoints, "U+26A0 U+FE0F")

    def test_bare_bmp_4_hex_escape_ignored(self) -> None:
        self.assertEqual(find_ui_emojis("\\u26A0", "a.ts"), [])
        self.assertEqual(find_ui_emojis("\\u2713", "a.ts"), [])


class TestFindUiEmojisCssEscapes(unittest.TestCase):
    def test_css_escape_detected_on_stylesheet_paths(self) -> None:
        for path in ("styles/main.css", "styles/main.scss", "styles/main.sass", "styles/main.less"):
            matches = find_ui_emojis('content: "\\1F680";', path)
            self.assertEqual(len(matches), 1, f"expected match for {path}")
            self.assertEqual(matches[0].kind, "css_escape")

    def test_css_escape_uppercase_extension(self) -> None:
        matches = find_ui_emojis('content: "\\1F680";', "styles/main.CSS")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].kind, "css_escape")

    def test_css_escape_windows_path(self) -> None:
        matches = find_ui_emojis('content: "\\1F680";', "styles\\main.scss")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].kind, "css_escape")

    def test_css_escape_smp_with_leading_zero(self) -> None:
        matches = find_ui_emojis('content: "\\01F4AC ";', "styles/main.css")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].codepoints, "U+1F4AC")

    def test_css_escape_bmp_ep(self) -> None:
        matches = find_ui_emojis('content: "\\26A1";', "styles/main.css")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].codepoints, "U+26A1")

    def test_css_escape_at_trailing_end_of_line(self) -> None:
        matches = find_ui_emojis("content: \\1F680", "styles/main.css")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].codepoints, "U+1F680")

    def test_css_escape_ignored_on_non_css_paths(self) -> None:
        for path in ("src/a.js", "src/a.ts", "src/a.html", ""):
            self.assertEqual(find_ui_emojis('content: "\\1F680";', path), [], f"expected non-CSS path {path!r}")

    def test_non_emoji_css_escapes_ignored(self) -> None:
        self.assertEqual(find_ui_emojis('content: "\\2022";', "x.css"), [])
        self.assertEqual(find_ui_emojis('content: "\\2713";', "x.css"), [])
        self.assertEqual(find_ui_emojis('content: "\\26A0";', "x.css"), [])


class TestFindUiEmojisRegexRangeGuard(unittest.TestCase):
    def test_regex_character_class_ranges_ignored(self) -> None:
        for line in (
            "[\\u{1F000}-\\u{1FAFF}]",
            "[\\u2600-\\u26FF]",
            "[\\u26A1-\\u2705]",
            "[\\uD83D\\uDE00-\\uD83D\\uDE4F]",
        ):
            self.assertEqual(find_ui_emojis(line, "a.tsx"), [], f"expected range guard for {line!r}")

    def test_non_range_hyphen_usage_still_detected(self) -> None:
        m = find_ui_emojis('const x = "\\u{1F680}-launch";', "a.tsx")
        self.assertEqual(len(m), 1)
        self.assertEqual(m[0].codepoints, "U+1F680")
        self.assertEqual(m[0].kind, "js_escape")

        m2 = find_ui_emojis('const y = "status-\\u{1F680}";', "a.tsx")
        self.assertEqual(len(m2), 1)
        self.assertEqual(m2[0].codepoints, "U+1F680")


class TestFindUiEmojisMultipleMatches(unittest.TestCase):
    def test_multiple_match_kinds_sorted_by_start_offset(self) -> None:
        line = "\\1F680 \\u{1F680} &#x1F680; " + smp(0x1F680)
        matches = find_ui_emojis(line, "styles.css")
        self.assertEqual(len(matches), 4)
        self.assertEqual([m.kind for m in matches], ["css_escape", "js_escape", "html_entity", "literal"])
        self.assertEqual([m.start for m in matches], [0, 7, 17, 27])
        self.assertEqual([m.end for m in matches], [6, 16, 26, 28])
        self.assertEqual([m.codepoints for m in matches], ["U+1F680"] * 4)
        self.assertEqual([m.raw for m in matches], ["\\1F680", "\\u{1F680}", "&#x1F680;", smp(0x1F680)])

    def test_literal_regex_has_zero_matches_inside_test_file(self) -> None:
        text = Path(__file__).read_text(encoding="utf-8")
        self.assertIsNone(LITERAL_EMOJI_RE.search(text))


if __name__ == "__main__":
    unittest.main()
