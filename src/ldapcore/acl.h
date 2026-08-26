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

} // namespace diratlas::ldapcore