"""Reusable Apache authorization semantics for OS-root baseline evaluation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from webconf_audit.local.apache.parser import (
    ApacheBlockNode,
    ApacheConfigAst,
    ApacheDirectiveNode,
)
from webconf_audit.local.apache.root_directory import (
    DirectoryBlockOccurrence,
    collect_directory_block_occurrences,
    is_os_root_directory_block,
)
from webconf_audit.local.apache.rules._policy_semantics_utils import (
    explicit_module_inventory,
    module_explicitly_loaded,
)
from webconf_audit.local.normalized import SourceRef
from webconf_audit.models import AnalysisIssue

AuthorizationDecision = Literal[
    "deny_all",
    "not_deny_all",
    "indeterminate",
    "not_defined",
]
AuthorizationSyntax = Literal["modern", "legacy", "mixed", "none"]
AuthMergingMode = Literal["off", "and", "or", "not_set", "unknown"]

_AUTHZ_CONTAINER_BLOCKS = frozenset({"requireall", "requireany", "requirenone"})
_METHOD_RESTRICTION_BLOCKS = frozenset({"limit", "limitexcept"})
_STATIC_CONDITIONAL_BLOCKS = frozenset({"ifmodule", "ifdefine", "ifversion"})
_DYNAMIC_CONDITIONAL_BLOCKS = frozenset({"if", "else", "elseif"})
_LEGACY_DIRECTIVES = frozenset({"order", "allow", "deny", "satisfy"})
_INCOMPLETE_INCLUDE_CODES = frozenset(
    {
        "apache_include_cycle",
        "apache_include_not_found",
        "apache_include_parse_error",
        "apache_include_read_error",
        "apache_include_self_include",
    }
)
_CONDITIONAL_REQUIRE_PROVIDERS = frozenset(
    {
        "env",
        "group",
        "host",
        "ip",
        "local",
        "method",
        "user",
        "valid-user",
    }
)


@dataclass(frozen=True, slots=True)
class ApacheAuthorizationResult:
    decision: AuthorizationDecision
    syntax: AuthorizationSyntax
    evidence: tuple[SourceRef, ...]
    reasons: tuple[str, ...]
    auth_merging: AuthMergingMode


@dataclass(frozen=True, slots=True)
class ApacheRootAuthorizationAssessment:
    root_blocks: tuple[ApacheBlockNode, ...]
    effective: ApacheAuthorizationResult
    include_graph_complete: bool
    unsupported_constructs: tuple[SourceRef, ...]


@dataclass(frozen=True, slots=True)
class _DetailedAuthorizationResult:
    decision: AuthorizationDecision
    syntax: AuthorizationSyntax
    evidence: tuple[SourceRef, ...]
    reasons: tuple[str, ...]
    auth_merging: AuthMergingMode
    unsupported: tuple[SourceRef, ...] = ()
    grants_all: bool = False


@dataclass(frozen=True, slots=True)
class _FlattenedBlockState:
    modern_nodes: tuple[ApacheDirectiveNode | ApacheBlockNode, ...]
    legacy_directives: tuple[ApacheDirectiveNode, ...]
    auth_merging: AuthMergingMode
    auth_merging_source: SourceRef | None
    unsupported: tuple[SourceRef, ...]
    reasons: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _DecisionProjection:
    decision: Literal["deny_all", "not_deny_all", "indeterminate"]
    grants_all: bool
    syntax: AuthorizationSyntax


def evaluate_root_authorization(
    config_ast: ApacheConfigAst,
    *,
    issues: list[AnalysisIssue] | None = None,
) -> ApacheRootAuthorizationAssessment:
    """Evaluate the visible Apache ``<Directory />`` authorization baseline.

    ``issues`` is the current analysis-issue list from include resolution. It is
    used as evidence input for include-graph completeness; this function does
    not mutate the list.
    """

    modules = explicit_module_inventory(config_ast)
    all_occurrences = [
        occurrence
        for occurrence in collect_directory_block_occurrences(config_ast.nodes)
        if is_os_root_directory_block(occurrence.block)
    ]
    root_blocks = tuple(occurrence.block for occurrence in all_occurrences)
    include_graph_complete = _include_graph_complete(issues)
    include_refs = _include_issue_refs(issues)

    if not root_blocks:
        reasons = ("missing_root_block",)
        if not include_graph_complete:
            reasons += ("include_graph_incomplete",)
        result = ApacheAuthorizationResult(
            decision=(
                "not_defined" if include_graph_complete else "indeterminate"
            ),
            syntax="none",
            evidence=(),
            reasons=reasons,
            auth_merging="not_set",
        )
        return ApacheRootAuthorizationAssessment(
            root_blocks=(),
            effective=result,
            include_graph_complete=include_graph_complete,
            unsupported_constructs=include_refs,
        )

    context_results = _evaluate_root_contexts(all_occurrences, modules)

    effective = _select_effective_context_result(
        context_results,
        include_graph_complete=include_graph_complete,
        include_refs=include_refs,
    )
    return ApacheRootAuthorizationAssessment(
        root_blocks=root_blocks,
        effective=ApacheAuthorizationResult(
            decision=effective.decision,
            syntax=effective.syntax,
            evidence=effective.evidence,
            reasons=effective.reasons,
            auth_merging=effective.auth_merging,
        ),
        include_graph_complete=include_graph_complete,
        unsupported_constructs=tuple(
            _dedupe_refs((*effective.unsupported, *include_refs))
        ),
    )


def _evaluate_root_contexts(
    occurrences: list[DirectoryBlockOccurrence],
    modules: frozenset[str],
) -> list[_DetailedAuthorizationResult]:
    global_blocks = [entry for entry in occurrences if entry.virtualhost is None]
    vhosts = _unique_virtualhosts_by_identity(occurrences)

    contexts: list[list[DirectoryBlockOccurrence]] = []
    if global_blocks:
        contexts.append(global_blocks)
    for vhost in vhosts:
        if vhost is None:
            continue
        scoped = [entry for entry in occurrences if entry.virtualhost is vhost]
        contexts.append([*global_blocks, *scoped])

    if not contexts:
        contexts.append(occurrences)

    return [_evaluate_root_context(context, modules) for context in contexts]


def _evaluate_root_context(
    occurrences: list[DirectoryBlockOccurrence],
    modules: frozenset[str],
) -> _DetailedAuthorizationResult:
    ordered = sorted(
        occurrences,
        key=lambda entry: (0 if entry.virtualhost is None else 1, entry.order),
    )
    current: _DetailedAuthorizationResult | None = None

    for occurrence in ordered:
        block_result = _evaluate_root_block(occurrence.block, modules)
        if current is None:
            current = block_result
            continue
        current = _merge_root_results(current, block_result)

    if current is None:
        return _detailed_result(
            decision="not_defined",
            syntax="none",
            reasons=("missing_root_block",),
        )
    return current


def _evaluate_root_block(
    block: ApacheBlockNode,
    modules: frozenset[str],
) -> _DetailedAuthorizationResult:
    flattened = _flatten_root_block(block, modules)
    syntax = _block_syntax(flattened)

    if flattened.unsupported:
        return _detailed_result(
            decision="indeterminate",
            syntax=("mixed" if syntax == "mixed" else syntax),
            evidence=(_ref_from_node(block),),
            reasons=_merge_reason_sets(flattened.reasons, ("unsupported_constructs",)),
            auth_merging=flattened.auth_merging,
            unsupported=flattened.unsupported,
        )

    if syntax == "mixed":
        return _detailed_result(
            decision="indeterminate",
            syntax="mixed",
            evidence=(
                *tuple(_ref_from_node(node) for node in flattened.modern_nodes),
                *tuple(_ref_from_node(node) for node in flattened.legacy_directives),
            ),
            reasons=_merge_reason_sets(flattened.reasons, ("mixed_authorization_syntax",)),
            auth_merging=flattened.auth_merging,
        )

    if syntax == "modern":
        result = _evaluate_modern_nodes(flattened.modern_nodes, container_name="requireany")
        return _replace_auth_merging(result, flattened.auth_merging)

    if syntax == "legacy":
        result = _evaluate_legacy_directives(flattened.legacy_directives)
        return _replace_auth_merging(result, flattened.auth_merging)

    return _detailed_result(
        decision="not_defined",
        syntax="none",
        evidence=(_ref_from_node(block),),
        reasons=_merge_reason_sets(flattened.reasons, ("missing_authorization_directives",)),
        auth_merging=flattened.auth_merging,
        grants_all=True,
    )


def _flatten_root_block(
    block: ApacheBlockNode,
    modules: frozenset[str],
) -> _FlattenedBlockState:
    modern_nodes: list[ApacheDirectiveNode | ApacheBlockNode] = []
    legacy_directives: list[ApacheDirectiveNode] = []
    reasons: list[str] = []
    unsupported: list[SourceRef] = []
    auth_merging: AuthMergingMode = "not_set"
    auth_merging_source: SourceRef | None = None

    def walk(nodes: list[ApacheDirectiveNode | ApacheBlockNode]) -> None:
        nonlocal auth_merging, auth_merging_source

        for node in nodes:
            if isinstance(node, ApacheDirectiveNode):
                name = node.name.lower()
                if name == "authmerging":
                    auth_merging, reason = _parse_auth_merging(node)
                    auth_merging_source = _ref_from_node(node)
                    if reason is not None:
                        reasons.append(reason)
                        unsupported.append(_ref_from_node(node))
                    continue
                if name == "require":
                    modern_nodes.append(node)
                    continue
                if name in _LEGACY_DIRECTIVES:
                    legacy_directives.append(node)
                continue

            name = node.name.lower()
            if name in _AUTHZ_CONTAINER_BLOCKS | _METHOD_RESTRICTION_BLOCKS:
                modern_nodes.append(node)
                continue
            if name == "ifmodule":
                state = _ifmodule_state(node, modules)
                if state is True:
                    walk(node.children)
                    continue
                if state is None and _subtree_contains_root_auth_signal(node.children):
                    reasons.append("unknown_ifmodule_branch")
                    unsupported.append(_ref_from_node(node))
                continue
            if name in _STATIC_CONDITIONAL_BLOCKS:
                if _subtree_contains_root_auth_signal(node.children):
                    reasons.append("conditional_section_unknown")
                    unsupported.append(_ref_from_node(node))
                continue
            if name in _DYNAMIC_CONDITIONAL_BLOCKS:
                if _subtree_contains_root_auth_signal(node.children):
                    reasons.append("dynamic_if_section")
                    unsupported.append(_ref_from_node(node))
                continue

    walk(block.children)
    return _FlattenedBlockState(
        modern_nodes=tuple(modern_nodes),
        legacy_directives=tuple(legacy_directives),
        auth_merging=auth_merging,
        auth_merging_source=auth_merging_source,
        unsupported=tuple(_dedupe_refs(unsupported)),
        reasons=tuple(dict.fromkeys(reasons)),
    )


def _block_syntax(flattened: _FlattenedBlockState) -> AuthorizationSyntax:
    has_modern = bool(flattened.modern_nodes)
    has_legacy = bool(flattened.legacy_directives)
    if has_modern and has_legacy:
        return "mixed"
    if has_modern:
        return "modern"
    if has_legacy:
        return "legacy"
    return "none"


def _evaluate_modern_nodes(
    nodes: tuple[ApacheDirectiveNode | ApacheBlockNode, ...],
    *,
    container_name: str,
) -> _DetailedAuthorizationResult:
    if not nodes:
        return _detailed_result(
            decision="indeterminate",
            syntax="modern",
            reasons=("empty_authorization_container",),
        )

    child_results = [_evaluate_modern_node(node) for node in nodes]
    evidence = tuple(
        _ref
        for result in child_results
        for _ref in result.evidence
    )
    reasons = tuple(
        reason
        for result in child_results
        for reason in result.reasons
    )
    unsupported = tuple(
        ref
        for result in child_results
        for ref in result.unsupported
    )

    if unsupported:
        return _detailed_result(
            decision="indeterminate",
            syntax="modern",
            evidence=evidence,
            reasons=_merge_reason_sets(reasons, ("unsupported_constructs",)),
            unsupported=unsupported,
        )

    if container_name == "requireall":
        if any(result.decision == "deny_all" for result in child_results):
            deny_child = next(
                result for result in child_results if result.decision == "deny_all"
            )
            return _detailed_result(
                decision="deny_all",
                syntax="modern",
                evidence=deny_child.evidence,
                reasons=_merge_reason_sets(reasons, ("requireall_contains_deny_all",)),
            )
        if any(result.decision == "indeterminate" for result in child_results):
            return _detailed_result(
                decision="indeterminate",
                syntax="modern",
                evidence=evidence,
                reasons=_merge_reason_sets(reasons, ("requireall_indeterminate_child",)),
            )
        return _detailed_result(
            decision="not_deny_all",
            syntax="modern",
            evidence=evidence,
            reasons=_merge_reason_sets(reasons, ("requireall_permits_requests",)),
            grants_all=all(result.grants_all for result in child_results),
        )

    if container_name == "requireany":
        if any(result.decision == "not_deny_all" for result in child_results):
            permit_child = next(
                result
                for result in child_results
                if result.decision == "not_deny_all"
            )
            return _detailed_result(
                decision="not_deny_all",
                syntax="modern",
                evidence=permit_child.evidence,
                reasons=_merge_reason_sets(reasons, ("requireany_permissive_branch",)),
                grants_all=any(result.grants_all for result in child_results),
            )
        if any(result.decision == "indeterminate" for result in child_results):
            return _detailed_result(
                decision="indeterminate",
                syntax="modern",
                evidence=evidence,
                reasons=_merge_reason_sets(reasons, ("requireany_indeterminate_branch",)),
            )
        return _detailed_result(
            decision="deny_all",
            syntax="modern",
            evidence=evidence,
            reasons=_merge_reason_sets(reasons, ("requireany_all_branches_deny",)),
        )

    if container_name == "requirenone":
        if any(result.grants_all for result in child_results):
            grant_all_child = next(
                result for result in child_results if result.grants_all
            )
            return _detailed_result(
                decision="deny_all",
                syntax="modern",
                evidence=grant_all_child.evidence,
                reasons=_merge_reason_sets(reasons, ("requirenone_negates_grant_all",)),
            )
        if any(result.decision == "indeterminate" for result in child_results):
            return _detailed_result(
                decision="indeterminate",
                syntax="modern",
                evidence=evidence,
                reasons=_merge_reason_sets(reasons, ("requirenone_indeterminate_child",)),
            )
        if all(result.decision == "deny_all" for result in child_results):
            return _detailed_result(
                decision="not_deny_all",
                syntax="modern",
                evidence=evidence,
                reasons=_merge_reason_sets(
                    reasons,
                    ("requirenone_negates_all_denying_children",),
                ),
                grants_all=True,
            )
        return _detailed_result(
            decision="not_deny_all",
            syntax="modern",
            evidence=evidence,
            reasons=_merge_reason_sets(reasons, ("requirenone_permits_nonmatching_requests",)),
        )

    return _detailed_result(
        decision="indeterminate",
        syntax="modern",
        evidence=evidence,
        reasons=_merge_reason_sets(reasons, ("unsupported_authorization_container",)),
    )


def _evaluate_modern_node(
    node: ApacheDirectiveNode | ApacheBlockNode,
) -> _DetailedAuthorizationResult:
    if isinstance(node, ApacheDirectiveNode):
        return _evaluate_require_directive(node)

    name = node.name.lower()
    if name in _AUTHZ_CONTAINER_BLOCKS:
        return _evaluate_modern_nodes(
            tuple(node.children),
            container_name=name,
        )
    if name in _METHOD_RESTRICTION_BLOCKS:
        return _detailed_result(
            decision="not_deny_all",
            syntax="modern",
            evidence=(_ref_from_node(node),),
            reasons=("method_scoped_authorization",),
        )
    return _detailed_result(
        decision="indeterminate",
        syntax="modern",
        evidence=(_ref_from_node(node),),
        reasons=("unsupported_authorization_node",),
        unsupported=(_ref_from_node(node),),
    )


def _evaluate_require_directive(
    directive: ApacheDirectiveNode,
) -> _DetailedAuthorizationResult:
    args = [arg.lower() for arg in directive.args]
    ref = _ref_from_node(directive)
    if not args:
        return _detailed_result(
            decision="indeterminate",
            syntax="modern",
            evidence=(ref,),
            reasons=("require_missing_provider",),
            unsupported=(ref,),
        )

    if args[0] == "all" and len(args) >= 2:
        if args[1] in {"denied", "deny"}:
            return _detailed_result(
                decision="deny_all",
                syntax="modern",
                evidence=(ref,),
                reasons=("require_all_denied",),
            )
        if args[1] == "granted":
            return _detailed_result(
                decision="not_deny_all",
                syntax="modern",
                evidence=(ref,),
                reasons=("require_all_granted",),
                grants_all=True,
            )

    if args[0] == "not":
        return _detailed_result(
            decision="indeterminate",
            syntax="modern",
            evidence=(ref,),
            reasons=("negated_require_not_modeled",),
            unsupported=(ref,),
        )

    if args[0] == "expr":
        return _detailed_result(
            decision="indeterminate",
            syntax="modern",
            evidence=(ref,),
            reasons=("require_expr_not_modeled",),
            unsupported=(ref,),
        )

    if args[0] in _CONDITIONAL_REQUIRE_PROVIDERS:
        return _detailed_result(
            decision="not_deny_all",
            syntax="modern",
            evidence=(ref,),
            reasons=(f"require_{args[0]}_conditional",),
        )

    return _detailed_result(
        decision="indeterminate",
        syntax="modern",
        evidence=(ref,),
        reasons=("unsupported_require_provider",),
        unsupported=(ref,),
    )


def _evaluate_legacy_directives(
    directives: tuple[ApacheDirectiveNode, ...],
) -> _DetailedAuthorizationResult:
    order_value: str | None = None
    allow_all = False
    allow_conditional = False
    deny_all = False
    saw_legacy = False
    invalid = False
    invalid_refs: list[SourceRef] = []
    reasons: list[str] = []
    evidence: list[SourceRef] = []

    for directive in directives:
        ref = _ref_from_node(directive)
        evidence.append(ref)
        name = directive.name.lower()
        saw_legacy = True

        if name == "order":
            order_value = "".join(directive.args).replace(" ", "").lower()
            if order_value not in {"allow,deny", "deny,allow"}:
                invalid = True
                invalid_refs.append(ref)
                reasons.append("legacy_invalid_order")
            continue

        if name == "satisfy":
            if len(directive.args) != 1 or directive.args[0].lower() not in {"all", "any"}:
                invalid = True
                invalid_refs.append(ref)
                reasons.append("legacy_invalid_satisfy")
                continue
            reasons.append(f"legacy_satisfy_{directive.args[0].lower()}")
            continue

        if name not in {"allow", "deny"}:
            continue

        if len(directive.args) < 2 or directive.args[0].lower() != "from":
            invalid = True
            invalid_refs.append(ref)
            reasons.append("legacy_invalid_allow_deny")
            continue

        tokens = [arg.lower() for arg in directive.args[1:]]
        if any(token == "all" for token in tokens):
            if name == "allow":
                allow_all = True
            else:
                deny_all = True
            continue

        if name == "allow":
            allow_conditional = True

    if not saw_legacy:
        return _detailed_result(
            decision="not_defined",
            syntax="legacy",
            reasons=("missing_authorization_directives",),
        )

    if invalid or order_value is None:
        extra_reasons = ("legacy_order_missing",) if order_value is None else ()
        return _detailed_result(
            decision="indeterminate",
            syntax="legacy",
            evidence=tuple(evidence),
            reasons=_merge_reason_sets(reasons, extra_reasons),
            unsupported=tuple(invalid_refs),
        )

    if order_value == "allow,deny":
        if allow_all and not deny_all:
            return _detailed_result(
                decision="not_deny_all",
                syntax="legacy",
                evidence=tuple(evidence),
                reasons=_merge_reason_sets(reasons, ("legacy_allow_all_permissive",)),
                grants_all=True,
            )
        if allow_conditional and not deny_all:
            return _detailed_result(
                decision="not_deny_all",
                syntax="legacy",
                evidence=tuple(evidence),
                reasons=_merge_reason_sets(reasons, ("legacy_allow_conditional_permissive",)),
            )
        return _detailed_result(
            decision="deny_all",
            syntax="legacy",
            evidence=tuple(evidence),
            reasons=_merge_reason_sets(reasons, ("legacy_allow_deny_default_deny",)),
        )

    if deny_all and not allow_all and not allow_conditional:
        return _detailed_result(
            decision="deny_all",
            syntax="legacy",
            evidence=tuple(evidence),
            reasons=_merge_reason_sets(reasons, ("legacy_deny_all_without_allow_override",)),
        )
    return _detailed_result(
        decision="not_deny_all",
        syntax="legacy",
        evidence=tuple(evidence),
        reasons=_merge_reason_sets(reasons, ("legacy_deny_allow_default_allow",)),
        grants_all=not deny_all,
    )


def _merge_root_results(
    previous: _DetailedAuthorizationResult,
    current: _DetailedAuthorizationResult,
) -> _DetailedAuthorizationResult:
    if current.auth_merging == "unknown":
        return _detailed_result(
            decision="indeterminate",
            syntax=current.syntax,
            evidence=(*previous.evidence, *current.evidence),
            reasons=_merge_reason_sets(
                (*previous.reasons, *current.reasons),
                ("invalid_auth_merging",),
            ),
            unsupported=current.unsupported,
        )

    if current.auth_merging in {"not_set", "off"}:
        return current

    merged_syntax = _merge_syntax(previous.syntax, current.syntax)
    if merged_syntax == "mixed":
        return _detailed_result(
            decision="indeterminate",
            syntax="mixed",
            evidence=(*previous.evidence, *current.evidence),
            reasons=_merge_reason_sets(
                (*previous.reasons, *current.reasons),
                ("mixed_authorization_syntax",),
            ),
            unsupported=(*previous.unsupported, *current.unsupported),
        )

    return _combine_merge_results(previous, current, container_name=current.auth_merging)


def _combine_merge_results(
    previous: _DetailedAuthorizationResult,
    current: _DetailedAuthorizationResult,
    *,
    container_name: Literal["and", "or"],
) -> _DetailedAuthorizationResult:
    left = _decision_projection(previous)
    right = _decision_projection(current)
    evidence = (*previous.evidence, *current.evidence)
    reasons = (*previous.reasons, *current.reasons)
    unsupported = (*previous.unsupported, *current.unsupported)
    syntax = _merge_syntax(previous.syntax, current.syntax)

    if left.decision == "indeterminate" or right.decision == "indeterminate":
        return _detailed_result(
            decision="indeterminate",
            syntax=syntax,
            evidence=evidence,
            reasons=_merge_reason_sets(reasons, (f"auth_merging_{container_name}_indeterminate",)),
            unsupported=unsupported,
        )

    if container_name == "and":
        if left.decision == "deny_all" or right.decision == "deny_all":
            return _detailed_result(
                decision="deny_all",
                syntax=syntax,
                evidence=evidence,
                reasons=_merge_reason_sets(reasons, ("auth_merging_and_preserves_deny_all",)),
            )
        return _detailed_result(
            decision="not_deny_all",
            syntax=syntax,
            evidence=evidence,
            reasons=_merge_reason_sets(reasons, ("auth_merging_and_permits_requests",)),
            grants_all=left.grants_all and right.grants_all,
        )

    if left.decision == "not_deny_all" or right.decision == "not_deny_all":
        return _detailed_result(
            decision="not_deny_all",
            syntax=syntax,
            evidence=evidence,
            reasons=_merge_reason_sets(reasons, ("auth_merging_or_permissive_branch",)),
            grants_all=left.grants_all or right.grants_all,
        )
    return _detailed_result(
        decision="deny_all",
        syntax=syntax,
        evidence=evidence,
        reasons=_merge_reason_sets(reasons, ("auth_merging_or_all_branches_deny",)),
    )


def _select_effective_context_result(
    context_results: list[_DetailedAuthorizationResult],
    *,
    include_graph_complete: bool,
    include_refs: tuple[SourceRef, ...],
) -> _DetailedAuthorizationResult:
    fail_results = [
        result
        for result in context_results
        if result.decision in {"not_defined", "not_deny_all"}
    ]
    if fail_results:
        return fail_results[0]

    indeterminate_results = [
        result for result in context_results if result.decision == "indeterminate"
    ]
    if indeterminate_results:
        return indeterminate_results[0]

    if not include_graph_complete:
        return _detailed_result(
            decision="indeterminate",
            syntax=context_results[0].syntax if context_results else "none",
            evidence=tuple(
                ref
                for result in context_results
                for ref in result.evidence
            ),
            reasons=("include_graph_incomplete",),
            unsupported=include_refs,
        )

    return context_results[0]


def _parse_auth_merging(
    directive: ApacheDirectiveNode,
) -> tuple[AuthMergingMode, str | None]:
    if len(directive.args) != 1:
        return "unknown", "invalid_auth_merging"
    value = directive.args[0].lower()
    if value == "off":
        return "off", None
    if value == "and":
        return "and", None
    if value == "or":
        return "or", None
    return "unknown", "invalid_auth_merging"


def _ifmodule_state(
    block: ApacheBlockNode,
    modules: frozenset[str],
) -> bool | None:
    if not block.args:
        return False

    token = block.args[0].strip().strip('"').strip("'")
    negated = token.startswith("!")
    module_token = token[1:] if negated else token
    loaded = module_explicitly_loaded(modules, module_token)
    if loaded:
        return not negated
    if negated:
        return None
    return None


def _subtree_contains_root_auth_signal(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
) -> bool:
    for node in nodes:
        if isinstance(node, ApacheDirectiveNode):
            if node.name.lower() in {"authmerging", "require"} | _LEGACY_DIRECTIVES:
                return True
            continue
        if node.name.lower() in _AUTHZ_CONTAINER_BLOCKS | _METHOD_RESTRICTION_BLOCKS:
            return True
        if _subtree_contains_root_auth_signal(node.children):
            return True
    return False


def _include_graph_complete(issues: list[AnalysisIssue] | None) -> bool:
    if issues is None:
        return True
    return not any(issue.code in _INCOMPLETE_INCLUDE_CODES for issue in issues)


def _include_issue_refs(
    issues: list[AnalysisIssue] | None,
) -> tuple[SourceRef, ...]:
    if issues is None:
        return ()
    refs = [
        _ref_from_issue(issue)
        for issue in issues
        if issue.code in _INCOMPLETE_INCLUDE_CODES and issue.location is not None
    ]
    return tuple(_dedupe_refs(ref for ref in refs if ref is not None))


def _replace_auth_merging(
    result: _DetailedAuthorizationResult,
    auth_merging: AuthMergingMode,
) -> _DetailedAuthorizationResult:
    return _detailed_result(
        decision=result.decision,
        syntax=result.syntax,
        evidence=result.evidence,
        reasons=result.reasons,
        auth_merging=auth_merging,
        unsupported=result.unsupported,
        grants_all=result.grants_all,
    )


def _decision_projection(
    result: _DetailedAuthorizationResult,
) -> _DecisionProjection:
    if result.decision == "indeterminate":
        return _DecisionProjection(
            decision="indeterminate",
            grants_all=False,
            syntax=result.syntax,
        )
    if result.decision == "not_defined":
        return _DecisionProjection(
            decision="not_deny_all",
            grants_all=True,
            syntax=result.syntax,
        )
    return _DecisionProjection(
        decision=result.decision,
        grants_all=result.grants_all,
        syntax=result.syntax,
    )


def _unique_virtualhosts_by_identity(
    occurrences: list[DirectoryBlockOccurrence],
) -> list[ApacheBlockNode]:
    seen: set[int] = set()
    vhosts: list[ApacheBlockNode] = []
    for entry in occurrences:
        vhost = entry.virtualhost
        if vhost is None:
            continue
        identity = id(vhost)
        if identity in seen:
            continue
        seen.add(identity)
        vhosts.append(vhost)
    return vhosts


def _merge_syntax(
    left: AuthorizationSyntax,
    right: AuthorizationSyntax,
) -> AuthorizationSyntax:
    if left == "none":
        return right
    if right == "none":
        return left
    if left == right:
        return left
    return "mixed"


def _detailed_result(
    *,
    decision: AuthorizationDecision,
    syntax: AuthorizationSyntax,
    evidence: tuple[SourceRef, ...] = (),
    reasons: tuple[str, ...] = (),
    auth_merging: AuthMergingMode = "not_set",
    unsupported: tuple[SourceRef, ...] = (),
    grants_all: bool = False,
) -> _DetailedAuthorizationResult:
    return _DetailedAuthorizationResult(
        decision=decision,
        syntax=syntax,
        evidence=tuple(_dedupe_refs(evidence)),
        reasons=tuple(dict.fromkeys(reasons)),
        auth_merging=auth_merging,
        unsupported=tuple(_dedupe_refs(unsupported)),
        grants_all=grants_all,
    )


def _merge_reason_sets(
    reasons: tuple[str, ...] | list[str],
    extra: tuple[str, ...] | list[str],
) -> tuple[str, ...]:
    return tuple(dict.fromkeys((*reasons, *extra)))


def _ref_from_node(node: ApacheDirectiveNode | ApacheBlockNode) -> SourceRef:
    return SourceRef(
        server_type="apache",
        file_path=node.source.file_path or "<unknown>",
        line=node.source.line,
    )


def _ref_from_issue(issue: AnalysisIssue) -> SourceRef | None:
    if issue.location is None or issue.location.file_path is None:
        return None
    return SourceRef(
        server_type="apache",
        file_path=issue.location.file_path,
        line=issue.location.line,
        details=issue.code,
    )


def _dedupe_refs(refs: tuple[SourceRef, ...] | list[SourceRef] | tuple[SourceRef | None, ...]):
    seen: set[tuple[str, int | None, str | None]] = set()
    deduped: list[SourceRef] = []
    for ref in refs:
        if ref is None:
            continue
        key = (ref.file_path, ref.line, ref.details)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(ref)
    return deduped


__all__ = [
    "ApacheAuthorizationResult",
    "ApacheRootAuthorizationAssessment",
    "AuthorizationDecision",
    "AuthorizationSyntax",
    "evaluate_root_authorization",
]
