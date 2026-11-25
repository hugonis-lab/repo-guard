"""Zero-dependency Unicode 16.0 UTS #51 emoji detector for user-facing UI source files.

Detects:
- Literal Unicode emojis (`Emoji_Presentation=Yes`, Supplementary Plane pictographs,
  BMP `Extended_Pictographic` + Variation Selector-16 `U+FE0F`, keycaps, flags, ZWJ sequences)
- Encoded emoji bypasses in UI source files:
  - HTML numeric/hex entities (`&#x1F680;`, `&#128640;`)
  - JS/TS Unicode escapes (`\\u{1F680}`, UTF-16 surrogate pairs `\\uD83D\\uDE80`, `\\u26A0\\uFE0F`)
  - CSS Unicode escapes (`content: "\\1F680"`, `"\\01F680"`)

Explicitly preserves clean monochrome typographic and geometric UI glyphs
(e.g., `✓`, `✗`, `✕`, `✎`, `✦`, `▸`, `▶`, `○`, `●`, `★`, `→`, `↗`, `©`, `®`, `™`, `—`, `…`)
unless explicitly forced into emoji presentation with `U+FE0F`.
"""

from __future__ import annotations

import bisect
from functools import lru_cache
import re
from dataclasses import dataclass
from pathlib import PurePosixPath

# File extensions representing user-facing UI templates, components, stylesheets, and frontend scripts.
ALWAYS_UI_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".html",
        ".htm",
        ".xhtml",
        ".jsx",
        ".tsx",
        ".vue",
        ".svelte",
        ".astro",
        ".css",
        ".scss",
        ".sass",
        ".less",
        ".qml",
        ".svg",
        ".jinja",
        ".jinja2",
        ".j2",
        ".hbs",
        ".handlebars",
        ".ejs",
        ".pug",
        ".njk",
        ".webmanifest",
    }
)

UI_SCRIPT_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".js",
        ".mjs",
        ".cjs",
        ".ts",
        ".mts",
        ".cts",
    }
)

CSS_EXTENSIONS: frozenset[str] = frozenset({".css", ".scss", ".sass", ".less"})

_EXCLUDED_DIR_PARTS: frozenset[str] = frozenset(
    {
        "test",
        "tests",
        "__tests__",
        "__mocks__",
        "spec",
        "specs",
        "fixture",
        "fixtures",
        "testdata",
        "node_modules",
        ".git",
    }
)

_RE_TEST_FILENAME = re.compile(
    r"(?:^test[_.-]|[_.-](?:test|spec)\.[^.]+$|^conftest\.)",
    re.IGNORECASE,
)

# Exact Unicode 16.0 UTS #51 BMP Emoji_Presentation=Yes ranges (start, end inclusive).
_BMP_EP_RANGES: tuple[tuple[int, int], ...] = (
    (0x231A, 0x231B),
    (0x23E9, 0x23EC),
    (0x23F0, 0x23F0),
    (0x23F3, 0x23F3),
    (0x25FD, 0x25FE),
    (0x2614, 0x2615),
    (0x2648, 0x2653),
    (0x267F, 0x267F),
    (0x2693, 0x2693),
    (0x26A1, 0x26A1),
    (0x26AA, 0x26AB),
    (0x26BD, 0x26BE),
    (0x26C4, 0x26C5),
    (0x26CE, 0x26CE),
    (0x26D4, 0x26D4),
    (0x26EA, 0x26EA),
    (0x26F2, 0x26F3),
    (0x26F5, 0x26F5),
    (0x26FA, 0x26FA),
    (0x26FD, 0x26FD),
    (0x2705, 0x2705),
    (0x270A, 0x270B),
    (0x2728, 0x2728),
    (0x274C, 0x274C),
    (0x274E, 0x274E),
    (0x2753, 0x2755),
    (0x2757, 0x2757),
    (0x2795, 0x2797),
    (0x27B0, 0x27B0),
    (0x27BF, 0x27BF),
    (0x2B1B, 0x2B1C),
    (0x2B50, 0x2B50),
    (0x2B55, 0x2B55),
)

# Exact Unicode 16.0 UTS #51 SMP Emoji_Presentation | Extended_Pictographic ranges (>= U+10000).
_SMP_EMOJI_RANGES: tuple[tuple[int, int], ...] = (
    (0x1F004, 0x1F004),
    (0x1F02C, 0x1F02F),
    (0x1F094, 0x1F09F),
    (0x1F0AF, 0x1F0B0),
    (0x1F0C0, 0x1F0C0),
    (0x1F0CF, 0x1F0D0),
    (0x1F0F6, 0x1F0FF),
    (0x1F170, 0x1F171),
    (0x1F17E, 0x1F17F),
    (0x1F18E, 0x1F18E),
    (0x1F191, 0x1F19A),
    (0x1F1AE, 0x1F1FF),
    (0x1F201, 0x1F20F),
    (0x1F21A, 0x1F21A),
    (0x1F22F, 0x1F22F),
    (0x1F232, 0x1F23A),
    (0x1F23C, 0x1F23F),
    (0x1F249, 0x1F25F),
    (0x1F266, 0x1F321),
    (0x1F324, 0x1F393),
    (0x1F396, 0x1F397),
    (0x1F399, 0x1F39B),
    (0x1F39E, 0x1F3F0),
    (0x1F3F3, 0x1F3F5),
    (0x1F3F7, 0x1F4FD),
    (0x1F4FF, 0x1F53D),
    (0x1F549, 0x1F54E),
    (0x1F550, 0x1F567),
    (0x1F56F, 0x1F570),
    (0x1F573, 0x1F57A),
    (0x1F587, 0x1F587),
    (0x1F58A, 0x1F58D),
    (0x1F590, 0x1F590),
    (0x1F595, 0x1F596),
    (0x1F5A4, 0x1F5A5),
    (0x1F5A8, 0x1F5A8),
    (0x1F5B1, 0x1F5B2),
    (0x1F5BC, 0x1F5BC),
    (0x1F5C2, 0x1F5C4),
    (0x1F5D1, 0x1F5D3),
    (0x1F5DC, 0x1F5DE),
    (0x1F5E1, 0x1F5E1),
    (0x1F5E3, 0x1F5E3),
    (0x1F5E8, 0x1F5E8),
    (0x1F5EF, 0x1F5EF),
    (0x1F5F3, 0x1F5F3),
    (0x1F5FA, 0x1F64F),
    (0x1F680, 0x1F6C5),
    (0x1F6CB, 0x1F6D2),
    (0x1F6D5, 0x1F6E5),
    (0x1F6E9, 0x1F6E9),
    (0x1F6EB, 0x1F6F0),
    (0x1F6F3, 0x1F6FF),
    (0x1F7DA, 0x1F7FF),
    (0x1F80C, 0x1F80F),
    (0x1F848, 0x1F84F),
    (0x1F85A, 0x1F85F),
    (0x1F888, 0x1F88F),
    (0x1F8AE, 0x1F8AF),
    (0x1F8BC, 0x1F8BF),
    (0x1F8C2, 0x1F8CF),
    (0x1F8D9, 0x1F8FF),
    (0x1F90C, 0x1F93A),
    (0x1F93C, 0x1F945),
    (0x1F947, 0x1F9FF),
    (0x1FA58, 0x1FA5F),
    (0x1FA6E, 0x1FAFF),
    (0x1FC00, 0x1FFFD),
)

_ALL_DIRECT_EMOJI_RANGES: tuple[tuple[int, int], ...] = _BMP_EP_RANGES + _SMP_EMOJI_RANGES
_DIRECT_STARTS: tuple[int, ...] = tuple(r[0] for r in _ALL_DIRECT_EMOJI_RANGES)

# BMP Extended_Pictographic character class (for VS-16 U+FE0F emoji presentation checks).
_BMP_EP_CLS = (
    r"\u231A-\u231B\u23E9-\u23EC\u23F0\u23F3\u25FD-\u25FE\u2614-\u2615\u2648-\u2653"
    r"\u267F\u2693\u26A1\u26AA-\u26AB\u26BD-\u26BE\u26C4-\u26C5\u26CE\u26D4\u26EA"
    r"\u26F2-\u26F3\u26F5\u26FA\u26FD\u2705\u270A-\u270B\u2728\u274C\u274E"
    r"\u2753-\u2755\u2757\u2795-\u2797\u27B0\u27BF\u2B1B-\u2B1C\u2B50\u2B55"
)

_BMP_XP_CLS = (
    r"\u00A9\u00AE\u203C\u2049\u2122\u2139\u2194-\u2199\u21A9-\u21AA\u231A-\u231B"
    r"\u2328\u23CF\u23E9-\u23F3\u23F8-\u23FA\u24C2\u25AA-\u25AB\u25B6\u25C0"
    r"\u25FB-\u25FE\u2600-\u2604\u260E\u2611\u2614-\u2615\u2618\u261D\u2620"
    r"\u2622-\u2623\u2626\u262A\u262E-\u262F\u2638-\u263A\u2640\u2642\u2648-\u2653"
    r"\u265F-\u2660\u2663\u2665-\u2666\u2668\u267B\u267E-\u267F\u2692-\u2697\u2699"
    r"\u269B-\u269C\u26A0-\u26A1\u26A7\u26AA-\u26AB\u26B0-\u26B1\u26BD-\u26BE"
    r"\u26C4-\u26C5\u26C8\u26CE-\u26CF\u26D1\u26D3-\u26D4\u26E9-\u26EA\u26F0-\u26F5"
    r"\u26F7-\u26FA\u26FD\u2702\u2705\u2708-\u270D\u270F\u2712\u2714\u2716\u271D"
    r"\u2721\u2728\u2733-\u2734\u2744\u2747\u274C\u274E\u2753-\u2755\u2757"
    r"\u2763-\u2764\u2795-\u2797\u27A1\u27B0\u27BF\u2934-\u2935\u2B05-\u2B07"
    r"\u2B1B-\u2B1C\u2B50\u2B55\u3030\u303D\u3297\u3299"
)

_SMP_EMOJI_CLS = (
    r"\U0001F004\U0001F02C-\U0001F02F\U0001F094-\U0001F09F\U0001F0AF-\U0001F0B0"
    r"\U0001F0C0\U0001F0CF-\U0001F0D0\U0001F0F6-\U0001F0FF\U0001F170-\U0001F171"
    r"\U0001F17E-\U0001F17F\U0001F18E\U0001F191-\U0001F19A\U0001F1AE-\U0001F1FF"
    r"\U0001F201-\U0001F20F\U0001F21A\U0001F22F\U0001F232-\U0001F23A"
    r"\U0001F23C-\U0001F23F\U0001F249-\U0001F25F\U0001F266-\U0001F321"
    r"\U0001F324-\U0001F393\U0001F396-\U0001F397\U0001F399-\U0001F39B"
    r"\U0001F39E-\U0001F3F0\U0001F3F3-\U0001F3F5\U0001F3F7-\U0001F4FD"
    r"\U0001F4FF-\U0001F53D\U0001F549-\U0001F54E\U0001F550-\U0001F567"
    r"\U0001F56F-\U0001F570\U0001F573-\U0001F57A\U0001F587\U0001F58A-\U0001F58D"
    r"\U0001F590\U0001F595-\U0001F596\U0001F5A4-\U0001F5A5\U0001F5A8"
    r"\U0001F5B1-\U0001F5B2\U0001F5BC\U0001F5C2-\U0001F5C4\U0001F5D1-\U0001F5D3"
    r"\U0001F5DC-\U0001F5DE\U0001F5E1\U0001F5E3\U0001F5E8\U0001F5EF\U0001F5F3"
    r"\U0001F5FA-\U0001F64F\U0001F680-\U0001F6C5\U0001F6CB-\U0001F6D2"
    r"\U0001F6D5-\U0001F6E5\U0001F6E9\U0001F6EB-\U0001F6F0\U0001F6F3-\U0001F6FF"
    r"\U0001F7DA-\U0001F7FF\U0001F80C-\U0001F80F\U0001F848-\U0001F84F"
    r"\U0001F85A-\U0001F85F\U0001F888-\U0001F88F\U0001F8AE-\U0001F8AF"
    r"\U0001F8BC-\U0001F8BF\U0001F8C2-\U0001F8CF\U0001F8D9-\U0001F8FF"
    r"\U0001F90C-\U0001F93A\U0001F93C-\U0001F945\U0001F947-\U0001F9FF"
    r"\U0001FA58-\U0001FA5F\U0001FA6E-\U0001FAFF\U0001FC00-\U0001FFFD"
)

_EMOJI_MOD = r"\U0001F3FB-\U0001F3FF"
_EMOJI_TAG_SEQ = r"\U0001F3F4[\U000E0020-\U000E007E]+\U000E007F"
_REGIONAL_FLAG = r"[\U0001F1E6-\U0001F1FF]{2}"
_KEYCAP_SEQ = r"[#*0-9]\uFE0F?\u20E3"
_BASE_EMOJI = rf"(?:[{_BMP_EP_CLS}{_SMP_EMOJI_CLS}]|[{_BMP_XP_CLS}]\uFE0F)"
_ZWJ_MEMBER = rf"(?:[{_BMP_XP_CLS}{_SMP_EMOJI_CLS}](?:\uFE0F|[{_EMOJI_MOD}])?)"

LITERAL_EMOJI_RE: re.Pattern[str] = re.compile(
    rf"(?:{_EMOJI_TAG_SEQ}|{_REGIONAL_FLAG}|{_KEYCAP_SEQ}|"
    rf"{_BASE_EMOJI}(?:\uFE0F|[{_EMOJI_MOD}])?(?:\u200D{_ZWJ_MEMBER})*)"
)

_RE_BMP_XP_SINGLE = re.compile(rf"^[{_BMP_XP_CLS}]$")

# Encoded emoji bypass detectors:
# 1. HTML hex/dec numeric character references: &#x1F680; or &#128640; (plus optional &#xFE0F;)
_RE_HTML_ENTITY = re.compile(
    r"&#(?:x([0-9A-Fa-f]{4,6})|(\d{4,7}));(?:\s*&#(?:x[Ff][Ee]0[Ff]|65039);)?"
)
# 2. JS/TS Unicode escapes: \u{1F680}, \uD83D\uDE80 (UTF-16 surrogate pair), \u26A0\uFE0F, \u26A1
_RE_JS_BRACE_ESC = re.compile(r"\\u\{([0-9A-Fa-f]{4,6})\}(?:\\u\{[Ff][Ee]0[Ff]\}|\\u[Ff][Ee]0[Ff])?")
_RE_JS_SURROGATE_ESC = re.compile(r"\\u([Dd][89AaBb][0-9A-Fa-f]{2})\\u([Dd][CcDdEeFf][0-9A-Fa-f]{2})")
_RE_JS_BMP_ESC = re.compile(r"\\u([0-9A-Fa-f]{4})(?:\\u([Ff][Ee]0[Ff]))?")
# 3. CSS escapes inside quotes/content: "\1F680" or "\01F680" or "\26A1"
_RE_CSS_ESC = re.compile(r"\\([0-9A-Fa-f]{4,6})(?=\s|[\"';})\\]|$)")


@dataclass(frozen=True)
class EmojiMatch:
    """Single emoji occurrence in a UI source line."""

    start: int
    end: int
    raw: str
    codepoints: str
    kind: str  # "literal" | "html_entity" | "js_escape" | "css_escape"


def is_direct_emoji_codepoint(cp: int) -> bool:
    """Return True if a single Unicode codepoint has default emoji presentation or is an SMP pictograph."""
    idx = bisect.bisect_right(_DIRECT_STARTS, cp) - 1
    if idx < 0:
        return False
    lo, hi = _ALL_DIRECT_EMOJI_RANGES[idx]
    return lo <= cp <= hi


def is_bmp_vs16_emoji_base(cp: int) -> bool:
    """Return True if a BMP codepoint renders as emoji when followed by U+FE0F."""
    if cp > 0xFFFF or (0xD800 <= cp <= 0xDFFF):
        return False
    return bool(_RE_BMP_XP_SINGLE.match(chr(cp)))


def format_codepoints(text: str) -> str:
    """Format a literal emoji cluster as 'U+1F680' or 'U+26A0 U+FE0F'."""
    return " ".join(f"U+{ord(ch):04X}" for ch in text)


@lru_cache(maxsize=4096)
def is_ui_source_path(rel_path: str) -> bool:
    """Return True if rel_path is a user-facing UI source file (excluding tests and fixtures)."""
    if not rel_path:
        return False
    norm = rel_path.replace("\\", "/")
    while norm.startswith("./"):
        norm = norm[2:]
    if norm.startswith("commit:") or norm == "COMMIT_EDITMSG":
        return False

    p = PurePosixPath(norm)
    parts_lower = [part.lower() for part in p.parts[:-1]]
    if any(part in _EXCLUDED_DIR_PARTS for part in parts_lower):
        return False
    if _RE_TEST_FILENAME.search(p.name):
        return False

    suffix = p.suffix.lower()
    return suffix in ALWAYS_UI_EXTENSIONS or suffix in UI_SCRIPT_EXTENSIONS


@lru_cache(maxsize=4096)
def _is_css_path(rel_path: str) -> bool:
    """Return True if rel_path has a stylesheet extension."""
    if not rel_path:
        return False
    return PurePosixPath(rel_path.replace("\\", "/")).suffix.lower() in CSS_EXTENSIONS


def _looks_like_regex_range(line: str, start: int, end: int) -> bool:
    """Avoid false positives on regex character-class ranges such as `[\\u{1F000}-\\u{1FAFF}]`."""
    before = line[start - 1] if start > 0 else ""
    after = line[end] if end < len(line) else ""
    if before == "-" and start >= 2 and line[start - 2] in ("}", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f", "A", "B", "C", "D", "E", "F"):
        return True
    if after == "-" and end + 2 < len(line) and line[end + 1] == "\\":
        return True
    return False


def find_ui_emojis(line: str, rel_path: str = "") -> list[EmojiMatch]:
    """Find all literal and escaped emoji occurrences on a single UI source line."""
    if not line:
        return []

    is_ascii = line.isascii()
    has_entity = "&#" in line
    has_js_esc = "\\u" in line
    has_css_esc = "\\" in line and _is_css_path(rel_path)
    # Every match of LITERAL_EMOJI_RE contains at least one non-ASCII codepoint (>= U+00A9).
    if is_ascii and not has_entity and not has_js_esc and not has_css_esc:
        return []

    matches: list[EmojiMatch] = []
    seen_spans: set[tuple[int, int]] = set()

    def _add(start: int, end: int, raw: str, codepoints: str, kind: str) -> None:
        if any(s <= start and end <= e for s, e in seen_spans):
            return
        seen_spans.add((start, end))
        matches.append(EmojiMatch(start=start, end=end, raw=raw, codepoints=codepoints, kind=kind))

    # 1. Literal Unicode emojis (impossible on pure-ASCII lines)
    if not is_ascii:
        for m in LITERAL_EMOJI_RE.finditer(line):
            raw = m.group(0)
            _add(m.start(), m.end(), raw, format_codepoints(raw), "literal")

    # 2. HTML numeric/hex entities (&#x1F680;, &#128640;, &#x26A0;&#xFE0F;)
    if has_entity:
        for m in _RE_HTML_ENTITY.finditer(line):
            raw = m.group(0)
            hex_part, dec_part = m.group(1), m.group(2)
            try:
                cp = int(hex_part, 16) if hex_part else int(dec_part, 10)
            except (TypeError, ValueError):
                continue
            has_vs16 = "fe0f" in raw.lower() or "65039" in raw
            if is_direct_emoji_codepoint(cp) or (has_vs16 and is_bmp_vs16_emoji_base(cp)):
                cps = f"U+{cp:04X} U+FE0F" if has_vs16 else f"U+{cp:04X}"
                _add(m.start(), m.end(), raw, cps, "html_entity")

    # 3. JS/TS Unicode escapes (\u{1F680}, \uD83D\uDE80, \u26A1, \u26A0\uFE0F)
    if has_js_esc:
        for m in _RE_JS_BRACE_ESC.finditer(line):
            if _looks_like_regex_range(line, m.start(), m.end()):
                continue
            cp = int(m.group(1), 16)
            has_vs16 = "fe0f" in m.group(0).lower()
            if is_direct_emoji_codepoint(cp) or (has_vs16 and is_bmp_vs16_emoji_base(cp)):
                cps = f"U+{cp:04X} U+FE0F" if has_vs16 else f"U+{cp:04X}"
                _add(m.start(), m.end(), m.group(0), cps, "js_escape")

        for m in _RE_JS_SURROGATE_ESC.finditer(line):
            if _looks_like_regex_range(line, m.start(), m.end()):
                continue
            hi = int(m.group(1), 16)
            lo = int(m.group(2), 16)
            cp = 0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
            if is_direct_emoji_codepoint(cp):
                _add(m.start(), m.end(), m.group(0), f"U+{cp:04X}", "js_escape")

        for m in _RE_JS_BMP_ESC.finditer(line):
            if _looks_like_regex_range(line, m.start(), m.end()):
                continue
            cp = int(m.group(1), 16)
            has_vs16 = bool(m.group(2))
            if is_direct_emoji_codepoint(cp) or (has_vs16 and is_bmp_vs16_emoji_base(cp)):
                cps = f"U+{cp:04X} U+FE0F" if has_vs16 else f"U+{cp:04X}"
                _add(m.start(), m.end(), m.group(0), cps, "js_escape")

    # 4. CSS Unicode escapes in stylesheet files (e.g., content: "\1F680";)
    if has_css_esc:
        for m in _RE_CSS_ESC.finditer(line):
            cp = int(m.group(1), 16)
            if is_direct_emoji_codepoint(cp):
                _add(m.start(), m.end(), m.group(0), f"U+{cp:04X}", "css_escape")

    if len(matches) > 1:
        matches.sort(key=lambda item: item.start)
    return matches
