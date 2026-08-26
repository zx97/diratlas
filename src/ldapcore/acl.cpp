// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Manuel FLURY

#include "acl.h"
#include "utf8.h"

#include <algorithm>
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
// Slapd.access(5) style aliases are normalised: sub=subtree, onelevel=one,
// baseObject=base, exact=base (they are synonyms in the grammar).
std::pair<std::string, std::string> parseDnScope(const std::string &target) {
    struct Entry { const char *key; const char *kind; };
    static const Entry kinds[] = {
        {"dn.onelevel", "dn.one"},
        {"dn.baseobject", "dn.base"},
        {"dn.subtree", "dn.subtree"},
        {"dn.children", "dn.children"},
        {"dn.one", "dn.one"},
        {"dn.exact", "dn.exact"},
        {"dn.base", "dn.base"},
        {"dn.regex", "dn.regex"},
        {"dn.sub", "dn.subtree"},
        {"dn", "dn"},
    };
    for (const auto &e : kinds) {
        size_t l = std::strlen(e.key);
        if (target.rfind(e.key, 0) == 0 && target.size() > l && target[l] == '=')
            return {e.kind, target.substr(l + 1)};
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

    // ── ACI syntax (389 DS / Oracle / PingDirectory / ApacheDS) ──
    // (targetattr="a || b")(target="ldap:///dn")(targetfilter="...")(targetscope="subtree")
    // (version 3.0; acl "name"; allow (read, search) userdn="ldap:///self";)
    if (value.find("(version 3.0") != std::string::npos ||
        value.find("acl \"") != std::string::npos) {
        // Targets: iterate "(keyword = "..." )" groups before the version body.
        size_t pos = 0;
        while (pos < value.size() && value.find("(version 3.0", pos) != pos) {
            size_t open = value.find('(', pos);
            if (open == std::string::npos) break;
            size_t close = value.find(')', open);
            if (close == std::string::npos) break;
            std::string group = value.substr(open + 1, close - open - 1);
            auto eq = group.find('=');
            if (eq != std::string::npos) {
                std::string kw = group.substr(0, eq);
                while (!kw.empty() && kw.back() == ' ') kw.pop_back();
                std::string expr = group.substr(eq + 1);
                while (!expr.empty() && expr.front() == ' ') expr.erase(0, 1);
                // strip surrounding quotes
                if (expr.size() >= 2 && expr.front() == '"' && expr.back() == '"')
                    expr = expr.substr(1, expr.size() - 2);
                if (kw == "targetattr") {
                    // "a || b" → attrs list
                    size_t s = 0;
                    while (s <= expr.size()) {
                        size_t sep = expr.find("||", s);
                        std::string a = expr.substr(s, sep == std::string::npos
                                                        ? std::string::npos : sep - s);
                        while (!a.empty() && (a.front() == ' ' || a.front() == '\t')) a.erase(0, 1);
                        while (!a.empty() && (a.back() == ' ' || a.back() == '\t')) a.pop_back();
                        if (!a.empty()) r.targetAttrs.push_back(a);
                        if (sep == std::string::npos) break;
                        s = sep + 2;
                    }
                    if (!r.target.empty()) r.target += " ";
                    r.target += "attrs=" + expr;
                } else if (kw == "target") {
                    // "ldap:///dn" or "ldap:///..." → DN target
                    std::string dn = expr;
                    const std::string prefix = "ldap:///";
                    if (dn.rfind(prefix, 0) == 0) dn = dn.substr(prefix.size());
                    r.targetDn = dn;
                    if (!r.target.empty()) r.target += " ";
                    r.target += "dn=" + dn;
                } else if (kw == "targetscope") {
                    // subtree/onelevel/base → complex DN scope
                    r.targetComplex = true;
                    if (!r.target.empty()) r.target += " ";
                    r.target += "dn.scope=" + expr;
                } else if (kw == "targetfilter" || kw == "targattrfilters" ||
                           kw == "targetcontrol") {
                    r.targetComplex = true;
                    if (!r.target.empty()) r.target += " ";
                    r.target += kw + "=" + expr;
                }
            }
            pos = close + 1;
        }
        if (r.target.empty()) r.target = "*";

        // Body: one clause per "allow (rights) subject;" / "deny (rights) subject;".
        size_t body = value.find("(version 3.0");
        if (body == std::string::npos) body = 0;
        size_t p = body;
        while (p < value.size()) {
            size_t allow = value.find("allow", p);
            size_t deny = value.find("deny", p);
            size_t next = std::string::npos;
            bool isDeny = false;
            if (allow != std::string::npos && (deny == std::string::npos || allow < deny)) {
                next = allow; isDeny = false;
            } else if (deny != std::string::npos) {
                next = deny; isDeny = true;
            }
            if (next == std::string::npos) break;
            // rights in parentheses: "(read, search)"
            size_t rp = value.find('(', next);
            size_t rpEnd = value.find(')', rp);
            if (rp == std::string::npos || rpEnd == std::string::npos) break;
            std::string rights = value.substr(rp + 1, rpEnd - rp - 1);
            // subject until ';' (or end)
            size_t semi = value.find(';', rpEnd);
            std::string subject = value.substr(rpEnd + 1,
                (semi == std::string::npos ? value.size() : semi) - rpEnd - 1);
            // trim
            while (!subject.empty() && (subject.front() == ' ' || subject.front() == '\t'))
                subject.erase(0, 1);
            while (!subject.empty() && (subject.back() == ' ' || subject.back() == '\t'))
                subject.pop_back();
            if (isDeny) {
                if (!rights.empty()) rights = "none";  // deny = explicit none for that subject
            }
            // Normalise the ACI bind rule into a slapd-style subject.
            std::string subj = subject;
            const std::string pre = "ldap:///";
            if (subj.rfind("userdn=", 0) == 0) {
                subj = subj.substr(7);
                while (!subj.empty() && (subj.front() == '"' || subj.front() == ' '))
                    subj.erase(0, 1);
                while (!subj.empty() && subj.back() == '"') subj.pop_back();
                if (subj.rfind(pre, 0) == 0) subj = subj.substr(pre.size());
                if (subj == "anyone" || subj == "all" || subj == "parent") subj = "*";
            } else if (subj.rfind("groupdn=", 0) == 0) {
                subj = subj.substr(8);
                while (!subj.empty() && (subj.front() == '"' || subj.front() == ' '))
                    subj.erase(0, 1);
                while (!subj.empty() && subj.back() == '"') subj.pop_back();
                if (subj.rfind(pre, 0) == 0) subj = subj.substr(pre.size());
                subj = "group/" + subj;
            } else if (subj.rfind("userattr=", 0) == 0) {
                subj = "userattr=" + subj.substr(9);
            }
            AclClause c;
            c.rights = rights.empty() ? "none" : rights;
            c.subject = subj.empty() ? "*" : subj;
            r.bys.push_back(c);
            p = (semi == std::string::npos) ? value.size() : semi + 1;
        }
        if (r.bys.empty()) return AclRule{};
        return r;
    }

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
        // Optional connection selector prefix: "ssf=128", "transport_ssf=..",
        // "tls_ssf=..", "sasl_ssf=..", "peername=IP=...", "sockurl=...",
        // "sockname=...", "domain=..." — a value token with "=" that is not
        // a dn=/group=/set= subject. It conditions the clause on the
        // connection properties (slapd.access(5)).
        if (i < toks.size() &&
            (toks[i].rfind("ssf=", 0) == 0 ||
             toks[i].rfind("transport_ssf=", 0) == 0 ||
             toks[i].rfind("tls_ssf=", 0) == 0 ||
             toks[i].rfind("sasl_ssf=", 0) == 0 ||
             toks[i].rfind("peername=", 0) == 0 ||
             toks[i].rfind("sockurl=", 0) == 0 ||
             toks[i].rfind("sockname=", 0) == 0 ||
             toks[i].rfind("domain=", 0) == 0)) {
            c.selector = toks[i];
            ++i;
        }
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
            detail += " " + std::to_string(j);
            any = true;
        }
        if (!any) continue;
        std::string which = "rules";
        for (size_t k = 0; k < idxs.size(); ++k) {
            if (k) which += ",";
            which += " " + std::to_string(idxs[k]);
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
                                   "rule " + std::to_string(j) +
                                   " is fully covered by rule " + std::to_string(i)});
                    continue;
                }
                // Partially dead: i covers j's target but only some clauses —
                // the uncovered clauses can still fire, the covered ones cannot.
                for (size_t kb = 0; kb < bCovered.size(); ++kb) {
                    if (!bCovered[kb]) continue;
                    out.push_back({AclConflictKind::Order,
                                   static_cast<int>(i), static_cast<int>(j),
                                   "clause '" + b.bys[kb].subject + " " + b.bys[kb].rights +
                                   "' of rule " + std::to_string(j) +
                                   " is never reached: rule " + std::to_string(i) +
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

// Displayed subject of a by-clause: an optional connection selector (ssf=...,
// peername=...) is shown before the subject (e.g. "ssf=128 self").
static std::string displaySubject(const AclClause &cl) {
    return cl.selector.empty() ? cl.subject : cl.selector + " " + cl.subject;
}

AclReportSize aclReportDimensions(const std::vector<AclRule> &rules,
                                  const std::vector<AclConflict> &conflicts,
                                  bool withGraph) {
    // Right-hand columns of the by-clause table — full access level names,
    // including "none", so every clause has a matching check cell.
    static const struct { const char *name; int w; } cols[] = {
        {"none", 4}, {"auth", 4}, {"compare", 7}, {"search", 6},
        {"read", 4}, {"write", 5}, {"manage", 6},
    };
    const int nCols = 7;
    // The subject column fits the widest subject so the whole DN is shown.
    int subjW = 8;
    int rightsW = 0;
    for (int c = 0; c < nCols; c++) rightsW += cols[c].w + 1;
    int titleW = 0;
    for (size_t i = 0; i < rules.size(); ++i) {
        for (const auto &cl : rules[i].bys)
            subjW = std::max(subjW, diratlas::ldapcore::utf8Width(displaySubject(cl)));
        std::string title = "[" + std::to_string(i) + "] to " + rules[i].target;
        titleW = std::max(titleW, diratlas::ldapcore::utf8Width(title));
    }
    subjW = std::min(subjW, 90);
    // A short conflict row (e.g. "MASKED rule 2 is fully covered by rule 1")
    // should fit inside the box; cap long details (grouped UNCERTAIN rule
    // lists) so one huge line does not inflate every table of the report.
    int conflictW = 0;
    auto kindName = [](AclConflictKind k) -> const char * {
        switch (k) {
            case AclConflictKind::Masked:  return "MASKED";
            case AclConflictKind::Overlap: return "OVERLAP";
            case AclConflictKind::Order:   return "ORDER";
            default:                       return "UNCERTAIN";
        }
    };
    for (const auto &c : conflicts) {
        int w = 4 + diratlas::ldapcore::utf8Width(kindName(c.kind));
        if (withGraph) {
            if (c.second >= 0 && c.second < static_cast<int>(rules.size()))
                w += 6 + std::min(60, diratlas::ldapcore::utf8Width(
                    "[" + std::to_string(c.second) + "] to " +
                    rules[static_cast<size_t>(c.second)].target));
            if (!c.detail.empty())
                w += 4 + std::min(60, diratlas::ldapcore::utf8Width(c.detail));
        } else {
            w += 2 + std::min(60, diratlas::ldapcore::utf8Width(c.detail));
        }
        conflictW = std::max(conflictW, w);
    }
    AclReportSize s;
    s.subjW = subjW;
    s.boxW = std::max({titleW + 5, 12 + subjW + rightsW + 4, conflictW + 2});
    s.boxW = std::min(s.boxW, 110);  // keep one huge detail from bloating all bases
    return s;
}

std::string buildAclReport(const std::vector<AclRule> &rules,
                           const std::vector<AclConflict> &conflicts,
                           bool withGraph,
                           int forcedSubjW, int forcedBoxW) {
    if (rules.empty()) return "";
    std::string out;
    // Group conflicts by the rule they concern: the earlier rule of the pair
    // (or the single rule index for grouped UNCERTAIN entries), so each
    // conflict is printed directly under its rule.
    std::vector<std::vector<const AclConflict *>> byRule(rules.size());
    for (const auto &c : conflicts) {
        int anchor = (c.first >= 0) ? c.first : c.second;
        if (anchor >= 0 && anchor < static_cast<int>(rules.size()))
            byRule[static_cast<size_t>(anchor)].push_back(&c);
    }

    auto kindName = [](AclConflictKind k) -> const char * {
        switch (k) {
            case AclConflictKind::Masked:  return "MASKED";
            case AclConflictKind::Overlap: return "OVERLAP";
            case AclConflictKind::Order:   return "ORDER";
            default:                       return "UNCERTAIN";
        }
    };

    // Right-hand columns of the by-clause table — full access level names,
    // including "none" so every clause has a matching check cell.
    struct Col { const char *name; int w; };
    static const Col cols[] = {
        {"none", 4}, {"auth", 4}, {"compare", 7}, {"search", 6},
        {"read", 4}, {"write", 5}, {"manage", 6},
    };
    const int nCols = 7;

    // Highest access level named in a rights string (manage > write > read >
    // search > compare > auth); -1 for none/unknown/priv model.
    auto colFor = [](const std::string &r) -> int {
        std::string low = r;
        for (auto &c : low) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        // "none" / empty maps to the none column (0); then low→high levels.
        // "all" (ACI shorthand) equals manage.
        if (low.empty() || low.find("none") != std::string::npos) return 0;
        if (low.find("all") != std::string::npos) return 6;
        if (low.find("manage") != std::string::npos) return 6;
        if (low.find("write") != std::string::npos ||
            low.find("add") != std::string::npos ||
            low.find("delete") != std::string::npos) return 5;
        if (low.find("read") != std::string::npos) return 4;
        if (low.find("search") != std::string::npos) return 3;
        if (low.find("compare") != std::string::npos) return 2;
        if (low.find("auth") != std::string::npos) return 1;
        return 0;  // unknown → none column
    };

    auto padCols = [](const std::string &s, int w) -> std::string {
        std::string t = s;
        while (diratlas::ldapcore::utf8Width(t) < w) t += ' ';
        return t;
    };

    // Displayed subject of a by-clause (selector + subject).

    // ── Dimensions ──────────────────────────────────────────────
    // The whole report (all bases) uses one subject column width and one box
    // width so every table is the size of the widest one. Callers may pass
    // the global maxima; otherwise compute them from this rule set (which
    // already accounts for conflict rows, capped so one huge UNCERTAIN
    // detail does not inflate every box).
    int rightsW = 0;
    for (int c = 0; c < nCols; c++) rightsW += cols[c].w + 1;
    auto dims = aclReportDimensions(rules, conflicts, withGraph);
    int subjW = forcedSubjW >= 0 ? std::min(forcedSubjW, 90) : dims.subjW;
    int tableW = 12 + subjW + rightsW;          // "│  ├─ by " + subject + columns
    // boxW must always fit the table built with the actual subjW; a forced
    // global boxW may have been computed with a narrower subject column, so
    // re-derive it from the table whenever it is smaller.
    int boxW = forcedBoxW >= 0 ? std::max(forcedBoxW, tableW + 4)
                               : std::max(dims.boxW, tableW + 4);

    // Conflicts are rows of the box; build each line once for rendering.
    auto conflictLine = [&](const AclConflict *c, bool last) -> std::string {
        std::string line = std::string(last ? "\u2514\u2500 " : "\u251C\u2500 ");
        if (withGraph) {
            line += std::string(kindName(c->kind)) + " \u2500\u2500\u25BA [" +
                    std::to_string(c->second) + "] to " +
                    rules[static_cast<size_t>(c->second)].target;
            if (!c->detail.empty()) line += "  (" + c->detail + ")";
        } else {
            line += "! " + std::string(kindName(c->kind)) + " " + c->detail;
        }
        return line;
    };

    // ── One big box per base, rules linked by ├─ separators ──────
    for (size_t i = 0; i < rules.size(); ++i) {
        const auto &r = rules[i];
        std::string title = "[" + std::to_string(i) + "] to " + r.target;
        int tw = diratlas::ldapcore::utf8Width(title);

        // First rule: ┌─ <title> ─...─┐ ; following rules: ├─ <title> ─...─┤
        if (i == 0) {
            out += "\u250C\u2500 " + title + " ";
            for (int x = 4 + tw; x < boxW - 1; x++) out += "\u2500";
            out += "\u2510\n";
        } else {
            out += "\u251C\u2500 " + title + " ";
            for (int x = 4 + tw; x < boxW - 1; x++) out += "\u2500";
            out += "\u2524\n";
        }

        // Header row with the rights column names. The left part is just the
        // subject column's continuation ("│  │" padded to the same 9-column
        // prefix as "│  ├─ by "), not a by-clause, so no ├─ connector.
        {
            std::string body = "\u2502  \u2502     ";
            body += padCols("", subjW) + " \u2502 ";
            for (int c = 0; c < nCols; c++)
                body += padCols(cols[c].name, cols[c].w) + "\u2502";
            out += body + padCols("", boxW - 1 - diratlas::ldapcore::utf8Width(body)) +
                   "\u2502\n";
        }

        // One row per by-clause; the left ├─/└─ links each clause to the rule,
        // the table marks the granted access level with a check. Subjects
        // wider than the column wrap onto a continuation line so the whole
        // DN stays visible.
        for (size_t k = 0; k < r.bys.size(); ++k) {
            const auto &cl = r.bys[k];
            bool last = (k + 1 == r.bys.size());
            std::string conn = std::string(last ? "\u2514\u2500" : "\u251C\u2500");
            std::string subj = displaySubject(cl);
            int sw = diratlas::ldapcore::utf8Width(subj);
            int ci = colFor(cl.rights);

            // Row: "│  <conn> by <subj> │ <cells>│" padded to boxW.
            std::string line1 = "\u2502  " + conn + " by ";
            std::string remainder;
            if (sw <= subjW) {
                line1 += padCols(subj, subjW) + " \u2502 ";
            } else {
                // Wrap: first line shows the beginning, continuation line
                // carries the rest, indented under the "by " prefix.
                line1 += diratlas::ldapcore::utf8Truncate(subj, subjW - 1) + "\u2026" +
                         " \u2502 ";
                remainder = subj.substr(diratlas::ldapcore::utf8Truncate(
                    subj, subjW - 1).size());
            }
            for (int c = 0; c < nCols; c++) {
                std::string cell = (c == ci) ? "\u2713" : "";
                line1 += padCols(cell, cols[c].w) + "\u2502";
            }
            out += line1 + padCols("", boxW - 1 - diratlas::ldapcore::utf8Width(line1)) +
                   "\u2502\n";
            if (!remainder.empty()) {
                // Continuation line uses the same table layout (subject
                // column padded to subjW, then empty cells), so the right
                // border │ stays aligned and the columns stay closed.
                std::string line2 = "\u2502  \u2502     ";
                line2 += padCols(remainder, subjW) + " \u2502 ";
                for (int c = 0; c < nCols; c++)
                    line2 += padCols("", cols[c].w) + "\u2502";
                out += line2 + padCols("", boxW - 1 - diratlas::ldapcore::utf8Width(line2)) +
                       "\u2502\n";
            }
        }

        // Conflicts / graph edges for this rule, drawn as rows of the box.
        for (size_t k = 0; k < byRule[i].size(); ++k) {
            bool last = (k + 1 == byRule[i].size());
            // Keep the conflict row inside the box, at box width.
            std::string cell = "\u2502  " + conflictLine(byRule[i][k], last);
            if (diratlas::ldapcore::utf8Width(cell) > boxW - 1)
                cell = diratlas::ldapcore::utf8Truncate(cell, boxW - 2) + "\u2026";
            out += cell + padCols("", boxW - 1 - diratlas::ldapcore::utf8Width(cell)) +
                   "\u2502\n";
        }
    }

    // Bottom border.
    out += "\u2514";
    for (int x = 1; x < boxW - 1; x++) out += "\u2500";
    out += "\u2518\n";
    return out;
}

} // namespace diratlas::ldapcore