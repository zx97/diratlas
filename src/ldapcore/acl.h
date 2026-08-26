// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Manuel FLURY
//
// ACL parsing and static conflict analysis for OpenLDAP olcAccess values
// (slapd.access(5)). Pure string logic, no LDAP dependency, unit-testable.

#pragma once

#include <string>
#include <vector>

namespace diratlas::ldapcore {

/// One "by <subject> <rights>" clause inside an ACL rule.
struct AclClause {
    std::string subject;   ///< "*", "self", "anonymous", "users", "dn=...", ...
    std::string rights;    ///< "none", "auth", "compare", "search", "read",
                           ///< "write", "manage" (may be "read,search" or "+")
    std::string selector;  ///< optional connection selector: "ssf=128",
                           ///< "peername=IP=...", "sockurl=ldap://...", etc.
};

/// One parsed ACL rule: "to <target> by <subject> <rights> ...".
struct AclRule {
    std::string target;                 ///< raw target ("*", "attrs=...", "dn=...")
    std::vector<std::string> targetAttrs; ///< "*" (all) or explicit attr list
    std::string targetDn;               ///< non-empty for dn=... targets
    bool targetEntry{false};            ///< "to entry" / "to children"
    bool targetComplex{false};          ///< dn.subtree/one, filter, etc. — hard to model
    std::vector<AclClause> bys;         ///< ordered clauses
    std::string raw;                    ///< original value
};

/// Kind of ACL conflict detected by static analysis.
enum class AclConflictKind {
    None,
    Masked,      ///< a later rule can never match (fully covered by an earlier one)
    Overlap,     ///< two rules cover the same target/subject with different rights
    Order,       ///< a more specific subject comes after a broader one (first-match wins)
    Uncertain,   ///< involves a complex target we cannot fully model
};

struct AclConflict {
    AclConflictKind kind{ AclConflictKind::None };
    int first{-1};        ///< index of the earlier rule
    int second{-1};       ///< index of the later rule
    std::string detail;   ///< human-readable explanation
};

/// Parse a single olcAccess value into an AclRule (empty rule on failure).
AclRule parseAcl(const std::string &value);

/// Parse several olcAccess values in order (index == position in the ACL list).
std::vector<AclRule> parseAclValues(const std::vector<std::string> &values);

/// Static conflict analysis between rules, in evaluation order.
std::vector<AclConflict> analyzeAclConflicts(const std::vector<AclRule> &rules);

/// slapacl-style evaluation: walk the rules in order and return the rights
/// granted by the first matching rule/clause (first-match-wins). "none" is
/// returned when nothing matches. @p ruleIndex / @p clauseIndex receive the
/// matching position when found (-1 otherwise).
std::string evaluateAcl(const std::vector<AclRule> &rules,
                        const std::string &userDN,
                        const std::string &targetDN,
                        const std::string &attr,
                        int *ruleIndex = nullptr,
                        int *clauseIndex = nullptr);

/// ASCII graph of the relations between rules (which rule affects which
/// later rule), derived from @p conflicts. One node per rule, one edge per
/// conflict, labelled with the conflict kind.
std::string buildAclGraph(const std::vector<AclRule> &rules,
                          const std::vector<AclConflict> &conflicts);

/// Split a raw olcAccess/aci value into display lines: the "to <target>"
/// clause on the first line, then one indented "by <subject> <rights>" line
/// per clause. Quotes are preserved (syntax highlighting colours them). The
/// raw value is returned as a single line when there is no "by" clause.
std::vector<std::string> formatAclValueLines(const std::string &value);

/// Build a readable text report of @p rules and their @p conflicts. Rules are
/// printed one after another ("[n] to ... by ..."), and each conflict is
/// listed directly under the rule it concerns (the earlier rule in the pair,
/// or the single rule for grouped UNCERTAIN entries) instead of a separate
/// index-referenced list. Consecutive rules sharing a branch are separated by
/// a blank line; when @p withGraph is true, each finding is shown as a graph
/// edge ("MASKED ──► [n] to ...") under its rule instead of the plain text.
/// An empty string is returned for an empty rule set.
std::string buildAclReport(const std::vector<AclRule> &rules,
                           const std::vector<AclConflict> &conflicts,
                           bool withGraph = false);

} // namespace diratlas::ldapcore