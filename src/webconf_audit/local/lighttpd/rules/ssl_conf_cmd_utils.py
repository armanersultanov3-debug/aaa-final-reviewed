from __future__ import annotations

from webconf_audit.openssl_conf_policy import ssl_conf_option_state


def ssl_conf_cmd_entries(raw: str) -> dict[str, str]:
    stripped = raw.strip()
    if stripped.startswith("(") and stripped.endswith(")"):
        stripped = stripped[1:-1]

    entries: dict[str, str] = {}
    for item in split_tuple_items(stripped):
        if "=>" not in item:
            continue
        key, _, value = item.partition("=>")
        entries[unquote(key.strip()).lower()] = unquote(value.strip())
    return entries


def split_tuple_items(raw: str) -> list[str]:
    items: list[str] = []
    current: list[str] = []
    quote_char: str | None = None
    escaped = False

    for char in raw:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if quote_char is not None:
            current.append(char)
            if char == "\\":
                escaped = True
            elif char == quote_char:
                quote_char = None
            continue
        if char in {'"', "'"}:
            current.append(char)
            quote_char = char
            continue
        if char == ",":
            item = "".join(current).strip()
            if item:
                items.append(item)
            current = []
            continue
        current.append(char)

    item = "".join(current).strip()
    if item:
        items.append(item)
    return items


def ssl_conf_cmd_option_state(raw: str, option_name: str) -> bool | None:
    options = ssl_conf_cmd_entries(raw).get("options")
    if options is None:
        return None
    return ssl_conf_option_state(options, option_name)


def unquote(value: str) -> str:
    stripped = value.strip()
    if len(stripped) >= 2 and stripped[0] == stripped[-1] and stripped[0] in {'"', "'"}:
        return stripped[1:-1]
    return stripped


__all__ = [
    "ssl_conf_cmd_entries",
    "ssl_conf_cmd_option_state",
    "split_tuple_items",
    "unquote",
]
