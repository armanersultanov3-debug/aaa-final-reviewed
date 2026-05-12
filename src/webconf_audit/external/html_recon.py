from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from html.parser import HTMLParser


@dataclass(slots=True)
class ScriptTag:
    src: str
    integrity: str | None = None
    crossorigin: str | None = None
    nonce: str | None = None


@dataclass(slots=True)
class InlineScript:
    nonce: str | None = None
    body_hash_candidate: str | None = None


@dataclass(slots=True)
class HTMLRecon:
    external_scripts: list[ScriptTag] = field(default_factory=list)
    inline_scripts: list[InlineScript] = field(default_factory=list)


class _ScriptInventoryParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.external_scripts: list[ScriptTag] = []
        self.inline_scripts: list[InlineScript] = []
        self._current_inline_nonce: str | None = None
        self._current_inline_chunks: list[str] | None = None

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        if tag.lower() != "script":
            return

        normalized_attrs = {
            name.lower(): _normalize_html_attribute(value)
            for name, value in attrs
        }
        src = normalized_attrs.get("src")
        nonce = normalized_attrs.get("nonce")
        integrity = normalized_attrs.get("integrity")
        crossorigin = normalized_attrs.get("crossorigin")

        if src is not None:
            self.external_scripts.append(
                ScriptTag(
                    src=src,
                    integrity=integrity,
                    crossorigin=crossorigin,
                    nonce=nonce,
                )
            )
            self._current_inline_nonce = None
            self._current_inline_chunks = None
            return

        self._current_inline_nonce = nonce
        self._current_inline_chunks = []

    def handle_startendtag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        if tag.lower() != "script":
            return
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_data(self, data: str) -> None:
        if self._current_inline_chunks is None:
            return
        self._current_inline_chunks.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() != "script":
            return
        self._finalize_inline_script()

    def close(self) -> None:
        super().close()
        self._finalize_inline_script()

    def _finalize_inline_script(self) -> None:
        if self._current_inline_chunks is None:
            return
        body = "".join(self._current_inline_chunks)
        self.inline_scripts.append(
            InlineScript(
                nonce=self._current_inline_nonce,
                body_hash_candidate=hashlib.sha256(body.encode("utf-8")).hexdigest(),
            )
        )
        self._current_inline_nonce = None
        self._current_inline_chunks = None


def _normalize_html_attribute(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None


def parse_html_recon(html_text: str) -> HTMLRecon:
    parser = _ScriptInventoryParser()
    parser.feed(html_text)
    parser.close()
    return HTMLRecon(
        external_scripts=parser.external_scripts,
        inline_scripts=parser.inline_scripts,
    )


__all__ = [
    "HTMLRecon",
    "InlineScript",
    "ScriptTag",
    "parse_html_recon",
]
