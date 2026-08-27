// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Manuel FLURY
//
// ACL parsing and static conflict analysis for OpenLDAP olcAccess values
// (slapd.access(5)). Pure string logic, no LDAP dependency, unit-testable.

#pragma once

#include <string>
#include <vector>

namespace diratlas::ldapcore {

/// Which ACL grammar a rule was parsed from — drives the report columns.
enum class AclFormat {
    Slapd,   ///< OpenLDAP olcAccess: hierarchical levels (auth<...<manage)
    Aci,     ///< 389 DS / Red Hat / PingDirectory / ApacheDS (version 3.0)
    Oracle,  ///< Oracle OID: independent flags (browse, noadd, nodelete, ...)
};

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
    AclFormat format{AclFormat::Slapd}; ///< grammar the rule was parsed from
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

/// Split a raw olcAccess/aci value into display lines: the "to <target>"
/// clause on the first line, then one indented "by <subject> <rights>" line
/// per clause. Quotes are preserved (syntax highlighting colours them). The
/// raw value is returned as a single line when there is no "by" clause.
std::vector<std::string> formatAclValueLines(const std::string &value);

/// Rebuild a parsed rule as a single "to <target> by <subject> <rights> ..."
/// line (the suggested-rewrite form). Selectors are kept ("ssf=128 self").
std::string formatAclRule(const AclRule &rule);

/// Table dimensions used by buildAclReport(): the subject column width and
/// the box width. Callers that render several rule sets in one report can
/// compute the maxima across all of them and pass them as forcedSubjW /
/// forcedBoxW to buildAclReport() for a uniform table size.
struct AclReportSize {
    int subjW{8};   ///< by-subject column width
    int boxW{0};    ///< total box width
};

AclReportSize aclReportDimensions(const std::vector<AclRule> &rules,
                                  const std::vector<AclConflict> &conflicts = {},
                                  bool withGraph = false);

/// Build a readable text report of @p rules and their @p conflicts. All rules
/// are drawn inside one big box: the first rule's title in the top border,
/// following rules linked by ├─ separators, each rule followed by its
/// by-clause table (access levels as columns, granted one marked with ✓) and
/// its conflicts/graph edges as rows of the same box. When @p withGraph is
/// true, findings are shown as graph edges ("MASKED ──► [n] to ...").
/// @p forcedSubjW / @p forcedBoxW let the caller impose a uniform table size
/// across the whole report (see aclReportDimensions()); when negative, the
/// values are computed from this rule set.
std::string buildAclReport(const std::vector<AclRule> &rules,
                           const std::vector<AclConflict> &conflicts,
                           bool withGraph = false,
                           int forcedSubjW = -1,
                           int forcedBoxW = -1);

} // namespace diratlas::ldapcore