// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Manuel FLURY

#include "acl.h"

#include <cctype>
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

bool subjectOverlaps(const std::string &a, const std::string &b) {
    if (a == "*" || b == "*") return true;
    if (a == b) return true;
    // dn=... exact matches overlap only when identical; group/dn.base etc.
    // are treated as "check manually" only if both mention dn.
    if (a.rfind("dn", 0) == 0 || b.rfind("dn", 0) == 0) return false;
    return false;
}

int rightsLevel(const std::string &r) {
    if (r == "none") return 0;
    if (r == "auth" || r == "disclose") return 1;
    if (r == "compare") return 2;
    if (r == "search") return 3;
    if (r == "read") return 4;
    if (r == "write" || r == "add" || r == "delete") return 5;
    if (r == "manage") return 6;
    return -1;  // unknown / combined
}

// Does target A fully cover target B?
bool targetCovers(const AclRule &a, const AclRule &b) {
    if (a.targetComplex || b.targetComplex) return false;
    bool aAll = a.targetAttrs.empty() || a.targetAttrs[0] == "*";
    bool bAll = b.targetAttrs.empty() || b.targetAttrs[0] == "*";
    if (!aAll && bAll) return false;
    if (aAll) return true;
    // A covers B if every attr of B is in A
    std::set<std::string> aset(a.targetAttrs.begin(), a.targetAttrs.end());
    for (const auto &x : b.targetAttrs)
        if (!aset.count(x)) return false;
    return true;
}

bool targetOverlaps(const AclRule &a, const AclRule &b) {
    if (a.targetComplex || b.targetComplex) return true;  // uncertain -> flag
    bool aAll = a.targetAttrs.empty() || a.targetAttrs[0] == "*";
    bool bAll = b.targetAttrs.empty() || b.targetAttrs[0] == "*";
    if (aAll || bAll) return true;
    std::set<std::string> aset(a.targetAttrs.begin(), a.targetAttrs.end());
    for (const auto &x : b.targetAttrs)
        if (aset.count(x)) return true;
    return false;
}

// Does a rule target match (targetDN, attr)?
bool targetMatches(const AclRule &r, const std::string &targetDN, const std::string &attr) {
    if (r.targetComplex) return true;  // can't model dn.subtree/filter — assume match
    if (!r.targetDn.empty()) {
        // dn=... : exact entry target; attr applies if attr is covered (all when no attrs=)
        bool attrOk = r.targetAttrs.empty() || r.targetAttrs[0] == "*";
        for (const auto &a : r.targetAttrs)
            if (a == attr) attrOk = true;
        if (r.targetEntry) return attrOk;  // "to entry" + dn handled above
        return attrOk;  // simplified: dn target matches the given entry
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
        r.targetDn = r.target;
        r.targetComplex = r.target.rfind("dn.subtree", 0) == 0 ||
                          r.target.rfind("dn.one", 0) == 0 ||
                          r.target.rfind("dn.children", 0) == 0 ||
                          r.target.rfind("filter", 0) == 0;
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
    for (size_t i = 0; i < rules.size(); ++i) {
        const auto &a = rules[i];
        for (size_t j = i + 1; j < rules.size(); ++j) {
            const auto &b = rules[j];

            // A complex target in either rule: we cannot fully model it.
            if (a.targetComplex || b.targetComplex) {
                if (targetOverlaps(a, b)) {
                    out.push_back({AclConflictKind::Uncertain,
                                   static_cast<int>(i), static_cast<int>(j),
                                   "complex target — check manually"});
                }
                continue;
            }

            // Masked: rule j is fully covered by earlier rule i.
            if (targetCovers(a, b)) {
                bool anyOverlap = false;
                for (const auto &ca : a.bys)
                    for (const auto &cb : b.bys)
                        if (subjectOverlaps(ca.subject, cb.subject)) { anyOverlap = true; break; }
                if (anyOverlap || b.bys.empty()) {
                    out.push_back({AclConflictKind::Masked,
                                   static_cast<int>(i), static_cast<int>(j),
                                   "rule " + std::to_string(j + 1) +
                                   " is fully covered by rule " + std::to_string(i + 1)});
                    continue;
                }
            }

            // Overlap: targets intersect and some subject pair overlaps.
            if (targetOverlaps(a, b)) {
                for (const auto &ca : a.bys) {
                    for (const auto &cb : b.bys) {
                        if (!subjectOverlaps(ca.subject, cb.subject)) continue;
                        int la = rightsLevel(ca.rights);
                        int lb = rightsLevel(cb.rights);
                        if (la >= 0 && lb >= 0 && la != lb) {
                            out.push_back({AclConflictKind::Overlap,
                                           static_cast<int>(i), static_cast<int>(j),
                                           "overlap on '" + ca.subject + "': rule " +
                                           std::to_string(i + 1) + " grants '" + ca.rights +
                                           "', rule " + std::to_string(j + 1) +
                                           " grants '" + cb.rights + "'"});
                        } else if (la == -1 || lb == -1) {
                            out.push_back({AclConflictKind::Uncertain,
                                           static_cast<int>(i), static_cast<int>(j),
                                           "overlap with combined/unknown rights"});
                        }
                    }
                }
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

} // namespace diratlas::ldapcore