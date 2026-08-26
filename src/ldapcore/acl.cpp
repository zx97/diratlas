// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Manuel FLURY

#include "acl.h"

#include <cctype>
#include <cstring>
#include <map>
#include <set>

namespace diratlas::ldapcore {

namespace {

// Split on whitespace, skipping quoted strings (slapd.access(5) allows
// double-quoted values containing spaces).
std::vector<std::string> tokenize(const std::string &s) {
    std::vector<std::string> out;
    size_t i = 0;
    while (i < s.size()) {
        while (i < s.size() && std::isspace(static_cast<unsigned char>(s[i]))) ++i;
        if (i >= s.size()) break;
        std::string tok;
        if (s[i] == '"') {
            ++i;
            while (i < s.size() && s[i] != '"') tok += s[i++];
            if (i < s.size()) ++i;  // closing quote
        } else {
            while (i < s.size() && !std::isspace(static_cast<unsigned char>(s[i]))) tok += s[i++];
        }
        out.push_back(tok);
    }
    return out;
}

// "attrs=a,b" -> {a,b}; "*" -> {"*"}.
std::vector<std::string> parseAttrs(const std::string &spec) {
    std::vector<std::string> out;
    size_t start = 0;
    while (start < spec.size()) {
        size_t comma = spec.find(',', start);
        std::string a = spec.substr(start, comma == std::string::npos ? std::string::npos : comma - start);
        if (!a.empty()) out.push_back(a);
        if (comma == std::string::npos) break;
        start = comma + 1;
    }
    if (out.empty()) out.push_back(spec);
    return out;
}

// Is @p dn equal to or a descendant of @p ancestor? (suffix RDN match)
bool dnIsAncestorOrSelf(const std::string &ancestor, const std::string &dn) {
    if (dn == ancestor) return true;
    if (dn.size() < ancestor.size() + 2) return false;
    if (dn.compare(dn.size() - ancestor.size(), ancestor.size(), ancestor) != 0) return false;
    return dn[dn.size() - ancestor.size() - 1] == ',';
}

// Split a dn= target ("dn.subtree=ou=x,dc=y", "dn.base=...", ...) into its
// scope kind and the base DN. Empty kind when the target is not a dn target.
std::pair<std::string, std::string> parseDnScope(const std::string &target) {
    static const char *kinds[] = {"dn.subtree", "dn.children", "dn.one",
                                  "dn.exact", "dn.base", "dn.regex", "dn"};
    for (const char *k : kinds) {
        size_t l = std::strlen(k);
        if (target.rfind(k, 0) == 0 && target.size() > l && target[l] == '=')
            return {k, target.substr(l + 1)};
    }
    return {"", ""};
}

// Does scope @p a fully contain scope @p b? "*" means "no DN restriction".
bool scopeCovers(const std::string &aKind, const std::string &aDn,
                 const std::string &bKind, const std::string &bDn) {
    if (aKind.empty()) return true;  // a restricts nothing -> covers everything
    if (bKind.empty()) return false;
    if (aKind == "dn" || aKind == "dn.base" || aKind == "dn.exact") {
        if (bKind == "dn" || bKind == "dn.base" || bKind == "dn.exact")
            return aDn == bDn;
        return false;  // a single entry does not cover a subtree
    }
    if (aKind == "dn.subtree") return dnIsAncestorOrSelf(aDn, bDn);
    if (aKind == "dn.one") {
        if (bKind == "dn" || bKind == "dn.base" || bKind == "dn.exact")
            return dnIsAncestorOrSelf(aDn, bDn) && bDn != aDn &&
                   bDn.compare(bDn.size() - aDn.size() - 1, 1, ",") == 0 &&
                   bDn.find(',') == bDn.size() - aDn.size() - 1;
        return aKind == bKind && aDn == bDn;
    }
    if (aKind == "dn.children") {
        if (bKind == "dn" || bKind == "dn.base" || bKind == "dn.exact")
            return dnIsAncestorOrSelf(aDn, bDn) && bDn != aDn;
        if (bKind == "dn.one" || bKind == "dn.children")
            return dnIsAncestorOrSelf(aDn, bDn);
        return false;
    }
    return false;
}

// Do the attribute lists of two rules share at least one attribute?
bool attrsOverlap(const AclRule &a, const AclRule &b) {
    bool aAll = a.targetAttrs.empty() || a.targetAttrs[0] == "*";
    bool bAll = b.targetAttrs.empty() || b.targetAttrs[0] == "*";
    if (aAll || bAll) return true;
    std::set<std::string> aset(a.targetAttrs.begin(), a.targetAttrs.end());
    for (const auto &x : b.targetAttrs)
        if (aset.count(x)) return true;
    return false;
}

// Does target A fully cover target B? (attrs AND dn scope)
bool targetCovers(const AclRule &a, const AclRule &b) {
    if (a.targetComplex || b.targetComplex) return false;
    bool aAll = a.targetAttrs.empty() || a.targetAttrs[0] == "*";
    bool bAll = b.targetAttrs.empty() || b.targetAttrs[0] == "*";
    if (!aAll && bAll) return false;
    if (!aAll) {
        // A covers B if every attr of B is in A
        std::set<std::string> aset(a.targetAttrs.begin(), a.targetAttrs.end());
        for (const auto &x : b.targetAttrs)
            if (!aset.count(x)) return false;
    }
    // The DN scope of A must contain the DN scope of B. When A covers all
    // attrs it still must not "cover" a wider or disjoint DN scope: a
    // dn.base=ou=X rule never covers "to *" (the catch-all is wider).
    auto sa = parseDnScope(a.targetDn);
    auto sb = parseDnScope(b.targetDn);
    return scopeCovers(sa.first, sa.second, sb.first, sb.second);
}

// Does subject A cover subject B? (A matches at least everyone B matches.)
// Conservative: only identical subjects and "*" (which matches everyone).
bool subjectCovers(const std::string &a, const std::string &b) {
    if (a == "*") return true;
    return a == b;
}

// Does every by-clause of rule B have a matching clause in rule A?
// Reports per-clause coverage so callers can distinguish a fully dead rule
// (Masked) from partially dead clauses (Order).
bool clausesCovered(const AclRule &a, const AclRule &b, std::vector<bool> &bCovered) {
    bCovered.assign(b.bys.size(), false);
    bool all = !b.bys.empty();
    for (size_t kb = 0; kb < b.bys.size(); ++kb) {
        for (const auto &ca : a.bys) {
            if (subjectCovers(ca.subject, b.bys[kb].subject)) {
                bCovered[kb] = true;
                break;
            }
        }
        if (!bCovered[kb]) all = false;
    }
    return all;
}

// Does a rule target match (targetDN, attr)?
bool targetMatches(const AclRule &r, const std::string &targetDN, const std::string &attr) {
    if (r.targetComplex) return true;  // can't model dn.regex/filter — assume match
    if (!r.targetDn.empty()) {
        // dn=... : the target DN must match the entry's scope, and the attr
        // must be covered (all when no attrs=).
        auto scope = parseDnScope(r.targetDn);
        if (!scope.first.empty()) {
            bool dnOk = false;
            if (scope.first == "dn" || scope.first == "dn.base" || scope.first == "dn.exact")
                dnOk = (targetDN == scope.second);
            else if (scope.first == "dn.subtree")
                dnOk = dnIsAncestorOrSelf(scope.second, targetDN);
            else if (scope.first == "dn.one")
                dnOk = targetDN != scope.second && dnIsAncestorOrSelf(scope.second, targetDN) &&
                       targetDN.compare(targetDN.size() - scope.second.size() - 1, 1, ",") == 0 &&
                       targetDN.find(',') == targetDN.size() - scope.second.size() - 1;
            else if (scope.first == "dn.children")
                dnOk = targetDN != scope.second && dnIsAncestorOrSelf(scope.second, targetDN);
            if (!dnOk) return false;
        }
        bool attrOk = r.targetAttrs.empty() || r.targetAttrs[0] == "*";
        for (const auto &a : r.targetAttrs)
            if (a == attr) attrOk = true;
        return attrOk;
    }
    bool all = r.targetAttrs.empty() || r.targetAttrs[0] == "*";
    if (all) return true;
    for (const auto &a : r.targetAttrs)
        if (a == attr) return true;
    return false;
}

// Does a by-clause subject match the requesting user?
bool subjectMatches(const std::string &subject, const std::string &userDN,
                    const std::string &targetDN) {
    if (subject == "*") return true;
    if (subject == "self") return userDN == targetDN;
    if (subject == "anonymous") return userDN.empty();
    if (subject == "users") return !userDN.empty();
    if (subject == "peers") return true;
    if (subject.rfind("dn", 0) == 0) {
        // dn=..., dn.base=..., dn.exact=..., dn.regex=...
        auto eq = subject.find('=');
        if (eq != std::string::npos) {
            std::string dn = subject.substr(eq + 1);
            return userDN == dn;
        }
        return false;
    }
    if (subject.rfind("group/", 0) == 0) return false;  // not modelled — no match
    return false;  // unknown subject — no match
}

} // namespace

AclRule parseAcl(const std::string &value) {
    AclRule r;
    r.raw = value;
    auto toks = tokenize(value);
    // skip the olcAccess numbering prefix ("{0}to * by ..." or "{0} to * by ...")
    if (!toks.empty() && toks[0].size() >= 2 && toks[0][0] == '{') {
        auto close = toks[0].find('}');
        if (close != std::string::npos) {
            std::string rest = toks[0].substr(close + 1);
            if (!rest.empty()) toks[0] = rest;
            else toks.erase(toks.begin());
        }
    }
    size_t i = 0;
    // optional leading "to"
    if (i < toks.size() && toks[i] == "to") ++i;
    // target: one or more tokens until "by"
    while (i < toks.size() && toks[i] != "by") {
        if (!r.target.empty()) r.target += " ";
        r.target += toks[i];
        ++i;
    }
    if (r.target.empty()) return r;

    // classify target
    if (r.target == "*" || r.target == "children" || r.target == "entry") {
        if (r.target == "entry" || r.target == "children") r.targetEntry = true;
        // "*" or children: all attrs
    } else if (r.target.rfind("attrs=", 0) == 0) {
        r.targetAttrs = parseAttrs(r.target.substr(6));
    } else if (r.target.rfind("dn", 0) == 0) {
        // "dn.subtree=ou=x,dc=y attrs=a,b": the optional attrs= part constrains
        // which attributes the rule applies to, so split it off the DN.
        std::string dnPart = r.target;
        auto attrsPos = dnPart.find(" attrs=");
        if (attrsPos != std::string::npos) {
            r.targetAttrs = parseAttrs(dnPart.substr(attrsPos + 7));
            dnPart = dnPart.substr(0, attrsPos);
        }
        // quotes are value delimiters in slapd.access(5), not part of the DN
        std::string clean;
        for (char ch : dnPart)
            if (ch != '"') clean += ch;
        r.targetDn = clean;
        auto scope = parseDnScope(dnPart);
        // dn.regex and filter cannot be modelled statically; the other dn
        // scopes are compared by hierarchy.
        r.targetComplex = scope.first == "dn.regex" ||
                          scope.first.empty();
    } else if (r.target.rfind("filter", 0) == 0) {
        r.targetComplex = true;
    } else {
        r.targetComplex = true;  // unknown target form
    }

    // by-clauses
    while (i < toks.size()) {
        if (toks[i] != "by") { ++i; continue; }
        ++i;
        AclClause c;
        if (i < toks.size()) { c.subject = toks[i]; ++i; }
        if (i < toks.size()) { c.rights = toks[i]; ++i; }
        if (!c.subject.empty() && !c.rights.empty()) {
            // quotes in slapd.access(5) are value delimiters, not part of
            // the subject (e.g. dn="cn=Admin,dc=example,dc=com")
            std::string subj;
            for (char ch : c.subject)
                if (ch != '"') subj += ch;
            c.subject = subj;
            r.bys.push_back(c);
        }
        // "on" (optional) clauses are ignored for static analysis
        if (i < toks.size() && toks[i] == "on") {
            ++i;
            while (i < toks.size() && toks[i] != "by") ++i;
        }
    }
    // A rule without any "by" clause is incomplete, treat as invalid.
    if (r.bys.empty()) return AclRule{};
    return r;
}

std::vector<AclRule> parseAclValues(const std::vector<std::string> &values) {
    std::vector<AclRule> out;
    for (const auto &v : values) {
        auto r = parseAcl(v);
        if (!r.target.empty() || !r.bys.empty()) out.push_back(r);
    }
    return out;
}

std::vector<AclConflict> analyzeAclConflicts(const std::vector<AclRule> &rules) {
    std::vector<AclConflict> out;

    // Pass 1 — complex targets (dn.regex, filter=, unknown forms): we cannot
    // model them statically. Group rules by their complex DN target (the raw
    // dn.regex/filter expression, without the per-rule attrs= list), so a
    // dozen per-attribute rules sharing one regex yield a single "check
    // manually" entry instead of one per rule.
    std::map<std::string, std::vector<size_t>> complexByTarget;
    for (size_t i = 0; i < rules.size(); ++i)
        if (rules[i].targetComplex) {
            std::string key = rules[i].targetDn.empty() ? rules[i].target
                                                        : rules[i].targetDn;
            complexByTarget[key].push_back(i);
        }
    for (const auto &kv : complexByTarget) {
        const auto &idxs = kv.second;
        // Rules sharing the target interact with the same later rules.
        std::string detail = "complex target — check manually against rules";
        bool any = false;
        for (size_t j = idxs.back() + 1; j < rules.size(); ++j) {
            const auto &b = rules[j];
            bool bRestricts = !b.targetDn.empty() ||
                              (!b.targetAttrs.empty() && b.targetAttrs[0] != "*");
            if (!bRestricts || !attrsOverlap(rules[idxs.front()], b)) continue;
            detail += " " + std::to_string(j + 1);
            any = true;
        }
        if (!any) continue;
        std::string which = "rules";
        for (size_t k = 0; k < idxs.size(); ++k) {
            if (k) which += ",";
            which += " " + std::to_string(idxs[k] + 1);
        }
        out.push_back({AclConflictKind::Uncertain,
                       static_cast<int>(idxs.front()),
                       static_cast<int>(idxs.back()),
                       which + " (" + kv.first + ") " + detail});
    }

    // Pass 2 — fully modelled rules: masking / dead clauses only. Overlap in
    // the literal sense is normal in slapd.access (first match wins); two
    // rules with intersecting targets are not a problem on their own.
    for (size_t i = 0; i < rules.size(); ++i) {
        const auto &a = rules[i];
        if (a.targetComplex) continue;
        for (size_t j = i + 1; j < rules.size(); ++j) {
            const auto &b = rules[j];
            if (b.targetComplex) continue;

            // Masked: rule j is fully covered by earlier rule i — its target
            // is contained and every by-clause has a matching clause in i, so
            // j can never be reached (first-match wins).
            if (targetCovers(a, b)) {
                std::vector<bool> bCovered;
                if (clausesCovered(a, b, bCovered)) {
                    out.push_back({AclConflictKind::Masked,
                                   static_cast<int>(i), static_cast<int>(j),
                                   "rule " + std::to_string(j + 1) +
                                   " is fully covered by rule " + std::to_string(i + 1)});
                    continue;
                }
                // Partially dead: i covers j's target but only some clauses —
                // the uncovered clauses can still fire, the covered ones cannot.
                for (size_t kb = 0; kb < bCovered.size(); ++kb) {
                    if (!bCovered[kb]) continue;
                    out.push_back({AclConflictKind::Order,
                                   static_cast<int>(i), static_cast<int>(j),
                                   "clause '" + b.bys[kb].subject + " " + b.bys[kb].rights +
                                   "' of rule " + std::to_string(j + 1) +
                                   " is never reached: rule " + std::to_string(i + 1) +
                                   " matches first"});
                }
                continue;
            }
        }
    }
    return out;
}

std::string evaluateAcl(const std::vector<AclRule> &rules,
                        const std::string &userDN,
                        const std::string &targetDN,
                        const std::string &attr,
                        int *ruleIndex, int *clauseIndex) {
    if (ruleIndex) *ruleIndex = -1;
    if (clauseIndex) *clauseIndex = -1;
    for (size_t i = 0; i < rules.size(); ++i) {
        if (!targetMatches(rules[i], targetDN, attr)) continue;
        for (size_t j = 0; j < rules[i].bys.size(); ++j) {
            if (!subjectMatches(rules[i].bys[j].subject, userDN, targetDN)) continue;
            if (ruleIndex) *ruleIndex = static_cast<int>(i);
            if (clauseIndex) *clauseIndex = static_cast<int>(j);
            return rules[i].bys[j].rights;
        }
    }
    return "none";
}

std::string buildAclGraph(const std::vector<AclRule> &rules,
                          const std::vector<AclConflict> &conflicts) {
    if (rules.empty()) return "  (no rules)\n";
    std::string out = "  Rule graph (first-match order; each rule shows the later\n";
    out += "  rules it affects):\n";
    std::vector<std::vector<const AclConflict *>> outgoing(rules.size());
    for (const auto &c : conflicts) {
        if (c.first >= 0 && c.first < static_cast<int>(rules.size()))
            outgoing[static_cast<size_t>(c.first)].push_back(&c);
    }
    for (size_t i = 0; i < rules.size(); ++i) {
        std::string label = "[" + std::to_string(i + 1) + "] to " + rules[i].target;
        if (!rules[i].bys.empty()) {
            label += "  by ";
            for (size_t k = 0; k < rules[i].bys.size(); ++k) {
                if (k) label += ", ";
                label += rules[i].bys[k].subject + " " + rules[i].bys[k].rights;
            }
        }
        if (outgoing[i].empty()) {
            out += "  " + label + "  (no outgoing relations)\n";
            continue;
        }
        out += "  " + label + "\n";
        for (size_t k = 0; k < outgoing[i].size(); ++k) {
            const auto *c = outgoing[i][k];
            bool last = (k + 1 == outgoing[i].size());
            out += last ? "   └─ " : "   ├─ ";
            switch (c->kind) {
                case AclConflictKind::Masked:   out += "MASKED"; break;
                case AclConflictKind::Overlap:  out += "OVERLAP"; break;
                case AclConflictKind::Order:    out += "ORDER"; break;
                default:                        out += "UNCERTAIN"; break;
            }
            out += " ──► [" + std::to_string(c->second + 1) + "] to " +
                   rules[static_cast<size_t>(c->second)].target + "\n";
        }
    }
    return out;
}

std::vector<std::string> formatAclValueLines(const std::string &value) {
    std::vector<std::string> out;
    // Split on " by " outside double quotes: the first part is the "to"
    // clause, each following part is one "by <subject> <rights>" clause.
    std::vector<std::string> parts;
    std::string cur;
    bool inQuote = false;
    size_t i = 0;
    while (i < value.size()) {
        char c = value[i];
        if (c == '"') inQuote = !inQuote;
        if (!inQuote && c == ' ' && value.compare(i, 4, " by ") == 0) {
            parts.push_back(cur);
            cur.clear();
            i += 4;
            continue;
        }
        cur += c;
        ++i;
    }
    parts.push_back(cur);
    if (parts.empty()) return {value};
    out.push_back(parts[0]);
    for (size_t k = 1; k < parts.size(); ++k)
        out.push_back("      by " + parts[k]);
    return out;
}

} // namespace diratlas::ldapcore