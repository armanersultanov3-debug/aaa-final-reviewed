"""Internal helpers for the scope utils rule family.

Location: ``src/webconf_audit/local/nginx/rules/_scope_utils.py``.
"""

from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import BlockNode, DirectiveNode
from webconf_audit.local.nginx.parser.ast import ConfigAst

_REDIRECT_RETURN_CODES = {"301", "302", "307", "308"}
_REDIRECT_REWRITE_FLAGS = {"redirect", "permanent"}
_CATCH_ALL_REWRITE_PATTERNS = {
    ".*",
    ".+",
    "^(.*)$",
    "^.*$",
    "^/(.*)$",
    "^/.*$",
    "^/.+$",
}
_CONTENT_DIRECTIVES = {
    "alias",
    "fastcgi_pass",
    "grpc_pass",
    "proxy_pass",
    "root",
    "scgi_pass",
    "try_files",
    "uwsgi_pass",
}
_UNSAFE_CONTENT_HANDLER_DIRECTIVES = _CONTENT_DIRECTIVES - {"root"}
_SAFE_EXCEPTION_PREFIXES = ("/.well-known/acme-challenge/",)
_FRAGMENT_ONLY_NOTE = (
    "This directive may be inherited from the parent nginx.conf; analyze the "
    "root nginx.conf for a definitive result."
)


def fragment_only_context_metadata(config_ast: ConfigAst) -> dict[str, str]:
    if not _is_fragment_only_config(config_ast):
        return {}
    return {
        "analysis_context": "fragment_only",
        "confidence": "contextual",
        "note": _FRAGMENT_ONLY_NOTE,
    }


def skips_content_response_checks(server_block: BlockNode) -> bool:
    """Return true when a server block only redirects normal traffic.

    The classifier is deliberately conservative: narrow ACME challenge
    exceptions are allowed, but any other content-serving location keeps the
    normal content-response checks active.
    """
    locations = direct_child_locations(server_block)
    if _block_redirects(server_block):
        return _locations_are_redirects_or_safe_exceptions(locations)

    has_catch_all_redirect = any(
        is_catch_all_location(location) and _block_redirects(location)
        for location in locations
    )
    if not has_catch_all_redirect:
        return False

    return _locations_are_redirects_or_safe_exceptions(locations)


def _is_fragment_only_config(config_ast: ConfigAst) -> bool:
    top_level_server_blocks = [
        node
        for node in config_ast.nodes
        if isinstance(node, BlockNode) and node.name == "server"
    ]
    if not top_level_server_blocks:
        return False
    if any(isinstance(node, BlockNode) and node.name == "http" for node in config_ast.nodes):
        return False
    return all(_source_path_looks_like_fragment(block) for block in top_level_server_blocks)


def _source_path_looks_like_fragment(block: BlockNode) -> bool:
    file_path = block.source.file_path
    if not file_path:
        return False
    normalized = file_path.replace("\\", "/").lower()
    if "/conf.d/" in normalized or "/sites-enabled/" in normalized:
        return True
    return normalized.rsplit("/", 1)[-1] != "nginx.conf"


def _locations_are_redirects_or_safe_exceptions(locations: list[BlockNode]) -> bool:
    return all(
        is_safe_exception_location(location) or _block_redirects(location)
        for location in locations
    )


def direct_child_locations(block: BlockNode) -> list[BlockNode]:
    return [
        child
        for child in block.children
        if isinstance(child, BlockNode)
        and child.name == "location"
        and not _is_named_location(child)
    ]


def _block_redirects(block: BlockNode) -> bool:
    return any(
        isinstance(child, DirectiveNode)
        and (_return_redirects(child) or rewrite_redirects_all_requests(child))
        for child in block.children
    )


def _return_redirects(directive: DirectiveNode) -> bool:
    if directive.name != "return" or not directive.args:
        return False
    if len(directive.args) == 1:
        return _looks_like_absolute_redirect_target(directive.args[0])
    return (
        directive.args[0] in _REDIRECT_RETURN_CODES
        and _looks_like_redirect_target(directive.args[1])
    )


def rewrite_redirects_all_requests(directive: DirectiveNode) -> bool:
    return (
        directive.name == "rewrite"
        and len(directive.args) >= 3
        and directive.args[-1].lower() in _REDIRECT_REWRITE_FLAGS
        and _is_catch_all_rewrite_pattern(directive.args[0])
    )


def _is_catch_all_rewrite_pattern(pattern: str) -> bool:
    return pattern.strip() in _CATCH_ALL_REWRITE_PATTERNS


def _looks_like_redirect_target(value: str) -> bool:
    return _looks_like_absolute_redirect_target(value) or value.startswith("$")


def _looks_like_absolute_redirect_target(value: str) -> bool:
    normalized = value.lower()
    return normalized.startswith("http://") or normalized.startswith("https://")


def is_catch_all_location(location: BlockNode) -> bool:
    if location.args == ["/"]:
        return True
    return location.args == ["^~", "/"]


def _is_named_location(location: BlockNode) -> bool:
    return bool(location.args) and location.args[0].startswith("@")


def is_safe_exception_location(location: BlockNode) -> bool:
    path = _location_path(location)
    if path is None or not path.startswith(_SAFE_EXCEPTION_PREFIXES):
        return False
    return not _has_unsafe_content_handler(location)


def _location_path(location: BlockNode) -> str | None:
    if not location.args:
        return None
    if location.args[0] in {"=", "^~"} and len(location.args) > 1:
        return location.args[1]
    if location.args[0] in {"~", "~*"}:
        return None
    return location.args[0]


def _has_unsafe_content_handler(location: BlockNode) -> bool:
    return any(
        isinstance(child, DirectiveNode)
        and child.name in _UNSAFE_CONTENT_HANDLER_DIRECTIVES
        for child in location.children
    )


__all__ = [
    "direct_child_locations",
    "fragment_only_context_metadata",
    "is_catch_all_location",
    "is_safe_exception_location",
    "rewrite_redirects_all_requests",
    "skips_content_response_checks",
]
