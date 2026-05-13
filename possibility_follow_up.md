# Possible Follow-Up

## CodeRabbit note: Lighttpd listen-point source fallback

CodeRabbit suggested improving traceability in
`src/webconf_audit/local/normalizers/lighttpd_normalizer.py` inside
`_listen_point_from_socket_condition()`.

Current behavior:

- When `ssl_engine` is present, the resulting `NormalizedListenPoint.source`
  uses `ssl_engine.source`.
- When `ssl_engine` is absent, the code falls back to an empty
  `LighttpdSourceSpan()`.

Suggested improvement from CodeRabbit:

- Use the source of the socket condition itself instead of an empty fallback,
  i.e. conceptually `ssl_engine.source if ssl_engine else condition.source`.

Why this was skipped in the current PR:

- `LighttpdCondition` currently does not carry source metadata.
- The current model only stores:
  `variable`, `operator`, and `value`.
- Because of that, `condition.source` does not exist today.
- Implementing the suggestion correctly would require a broader follow-up:
  adding source/span metadata to the parsed Lighttpd condition model and
  propagating it through the parser/effective-config layers.

Possible future follow-up scope:

1. Add `source: LighttpdSourceSpan` to `LighttpdCondition` or store equivalent
   source metadata on the conditional scope.
2. Populate that source in the Lighttpd parser when block headers are parsed.
3. Update `_listen_point_from_socket_condition()` to use the condition source as
   the non-`ssl_engine` fallback.
4. Add/adjust tests to verify improved source traceability for
   `$SERVER["socket"]`-derived listen points.
