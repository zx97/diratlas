// test_acl.cpp — unit tests for ldapcore::acl (olcAccess parser + conflicts)
//
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Manuel FLURY

#include "../src/ldapcore/acl.h"
#include <cassert>
#include <iostream>

using diratlas::ldapcore::AclConflictKind;
using diratlas::ldapcore::analyzeAclConflicts;
using diratlas::ldapcore::buildAclReport;
using diratlas::ldapcore::evaluateAcl;
using diratlas::ldapcore::parseAcl;
using diratlas::ldapcore::parseAclValues;

static int failures = 0;

#define CHECK(cond)                                                          \
    do {                                                                     \
        if (!(cond)) {                                                       \
            std::cerr << "FAIL " << __FILE__ << ":" << __LINE__ << ": "      \
                      << #cond << std::endl;                                 \
            ++failures;                                                      \
        }                                                                    \
    } while (0)

int main() {
    // --- parseAcl: simple target ---
    {
        auto r = parseAcl("to * by * read");
        CHECK(r.target == "*");
        CHECK(r.targetAttrs.empty());
        CHECK(r.bys.size() == 1);
        CHECK(r.bys[0].subject == "*" && r.bys[0].rights == "read");
    }
    // --- attrs target with multiple by-clauses ---
    {
        auto r = parseAcl("to attrs=userPassword,shadowLastChange by self write by anonymous auth by * none");
        CHECK(r.target.rfind("attrs=", 0) == 0);
        CHECK(r.targetAttrs.size() == 2);
        CHECK(r.targetAttrs[0] == "userPassword");
        CHECK(r.targetAttrs[1] == "shadowLastChange");
        CHECK(r.bys.size() == 3);
        CHECK(r.bys[1].subject == "anonymous" && r.bys[1].rights == "auth");
        CHECK(r.bys[2].subject == "*" && r.bys[2].rights == "none");
    }
    // --- dn.subtree is modelled (not complex), dn.regex is complex ---
    {
        auto r = parseAcl("to dn.subtree=\"ou=people,dc=example,dc=com\" by * read");
        CHECK(!r.targetComplex);
        CHECK(!r.targetDn.empty());
        auto r2 = parseAcl("to dn.regex=\"^uid=.*,ou=people,dc=example,dc=com$\" by * read");
        CHECK(r2.targetComplex);
    }
    // --- dn style aliases: sub=subtree, onelevel=one, baseObject=base,
    //     exact=base behave identically ---
    {
        std::string child = "ou=Y,ou=X,dc=eu";
        CHECK(evaluateAcl(parseAclValues({"to dn.sub=\"ou=X,dc=eu\" by * read"}),
                          "u", child, "*") == "read");
        CHECK(evaluateAcl(parseAclValues({"to dn.onelevel=\"ou=X,dc=eu\" by * read"}),
                          "u", child, "*") == "read");
        CHECK(evaluateAcl(parseAclValues({"to dn.onelevel=\"ou=X,dc=eu\" by * read"}),
                          "u", "ou=X,dc=eu", "*") == "none");
        CHECK(evaluateAcl(parseAclValues({"to dn.baseObject=\"ou=X,dc=eu\" by * read"}),
                          "u", "ou=X,dc=eu", "*") == "read");
        CHECK(evaluateAcl(parseAclValues({"to dn.exact=\"ou=X,dc=eu\" by * read"}),
                          "u", child, "*") == "none");
    }
    // --- dn target with attrs= keeps both parts ---
    {
        auto r = parseAcl("to dn.regex=ou=People,dc=(.+),dc=europa,dc=eu attrs=cn by * read");
        CHECK(r.targetComplex);
        CHECK(r.targetDn.rfind("dn.regex", 0) == 0);
        CHECK(r.targetAttrs.size() == 1 && r.targetAttrs[0] == "cn");
    }
    // --- no overlap: disjoint attrs on dn targets ---
    {
        auto rules = parseAclValues({
            "to attrs=userPassword by * read",
            "to dn.regex=ou=People,dc=(.+),dc=europa,dc=eu attrs=cn by * write",
        });
        auto c = analyzeAclConflicts(rules);
        CHECK(c.empty());  // userPassword vs cn: nothing shared
    }
    // --- no overlap: disjoint dn scopes (same attrs) ---
    {
        auto rules = parseAclValues({
            "to dn.base=\"ou=TrustedApps,dc=europa,dc=eu\" by users read",
            "to dn.base=\"ou=AuthDomains,dc=europa,dc=eu\" by users write",
        });
        auto c = analyzeAclConflicts(rules);
        bool overlap = false;
        for (const auto &x : c)
            if (x.kind == AclConflictKind::Overlap) overlap = true;
        CHECK(!overlap);  // distinct subtrees: no common entry
    }
    // --- overlap: dn.subtree covers dn.base below it ---
    {
        auto rules = parseAclValues({
            "to dn.subtree=\"dc=europa,dc=eu\" by users read",
            "to dn.base=\"ou=People,dc=europa,dc=eu\" by users write",
        });
        auto c = analyzeAclConflicts(rules);
        bool overlap = false;
        for (const auto &x : c)
            if (x.kind == AclConflictKind::Overlap) overlap = true;
        // the broader subtree rule fully covers the base rule → the conflict
        // is reported as MASKED (rule 1 wins for the whole subtree)
        bool masked = false;
        for (const auto &x : c)
            if (x.kind == AclConflictKind::Masked && x.first == 0 && x.second == 1) masked = true;
        CHECK(overlap || masked);
        CHECK(masked);
    }
    // --- masked: broader dn.subtree + attrs=* covers narrower ---
    {
        auto rules = parseAclValues({
            "to dn.subtree=\"dc=europa,dc=eu\" attrs=* by users read",
            "to dn.base=\"ou=People,dc=europa,dc=eu\" attrs=cn by users read",
        });
        auto c = analyzeAclConflicts(rules);
        bool masked = false;
        for (const auto &x : c)
            if (x.kind == AclConflictKind::Masked && x.first == 0 && x.second == 1) masked = true;
        CHECK(masked);
    }
    // --- evaluateAcl: dn.subtree target matches entries below it ---
    {
        auto rules = parseAclValues({
            "to dn.subtree=\"ou=People,dc=europa,dc=eu\" attrs=cn by users read by * none",
        });
        CHECK(evaluateAcl(rules, "uid=bob,ou=People,dc=europa,dc=eu",
                          "uid=bob,ou=People,dc=europa,dc=eu", "cn") == "read");
        CHECK(evaluateAcl(rules, "uid=bob,ou=People,dc=europa,dc=eu",
                          "uid=bob,ou=People,dc=europa,dc=eu", "mail") == "none");
        CHECK(evaluateAcl(rules, "uid=bob,ou=People,dc=europa,dc=eu",
                          "uid=bob,ou=Other,dc=europa,dc=eu", "cn") == "none");
    }
    // --- scopes: dn.base acts on the exact entry only; dn.subtree includes
    //     the entry AND its descendants; dn.one children only; dn.children
    //     descendants only ---
    {
        std::string root = "ou=X,dc=eu";
        std::string child = "ou=Y,ou=X,dc=eu";
        std::string grand = "ou=Z,ou=Y,ou=X,dc=eu";
        CHECK(evaluateAcl(parseAclValues({"to dn.base=\"" + root + "\" by * read"}),
                          "u", root, "*") == "read");
        CHECK(evaluateAcl(parseAclValues({"to dn.base=\"" + root + "\" by * read"}),
                          "u", child, "*") == "none");
        CHECK(evaluateAcl(parseAclValues({"to dn.subtree=\"" + root + "\" by * read"}),
                          "u", root, "*") == "read");
        CHECK(evaluateAcl(parseAclValues({"to dn.subtree=\"" + root + "\" by * read"}),
                          "u", child, "*") == "read");
        CHECK(evaluateAcl(parseAclValues({"to dn.subtree=\"" + root + "\" by * read"}),
                          "u", grand, "*") == "read");
        CHECK(evaluateAcl(parseAclValues({"to dn.one=\"" + root + "\" by * read"}),
                          "u", root, "*") == "none");
        CHECK(evaluateAcl(parseAclValues({"to dn.one=\"" + root + "\" by * read"}),
                          "u", child, "*") == "read");
        CHECK(evaluateAcl(parseAclValues({"to dn.one=\"" + root + "\" by * read"}),
                          "u", grand, "*") == "none");
        CHECK(evaluateAcl(parseAclValues({"to dn.children=\"" + root + "\" by * read"}),
                          "u", root, "*") == "none");
        CHECK(evaluateAcl(parseAclValues({"to dn.children=\"" + root + "\" by * read"}),
                          "u", child, "*") == "read");
        CHECK(evaluateAcl(parseAclValues({"to dn.children=\"" + root + "\" by * read"}),
                          "u", grand, "*") == "read");
    }
    // --- scopes in conflict analysis: dn.base before dn.subtree (same DN)
    //     is NOT masked (subtree is wider); the reverse IS masked ---
    {
        auto rules = parseAclValues({
            "to dn.base=\"ou=X,dc=eu\" by users read",
            "to dn.subtree=\"ou=X,dc=eu\" by self write",
        });
        bool masked = false;
        for (const auto &x : analyzeAclConflicts(rules))
            if (x.kind == AclConflictKind::Masked) masked = true;
        CHECK(!masked);  // the subtree rule is not covered by the base rule

        auto rules2 = parseAclValues({
            "to dn.subtree=\"ou=X,dc=eu\" by self write by * none",
            "to dn.base=\"ou=X,dc=eu\" by users read",
        });
        bool masked2 = false;
        for (const auto &x : analyzeAclConflicts(rules2))
            if (x.kind == AclConflictKind::Masked && x.first == 0 && x.second == 1) masked2 = true;
        CHECK(masked2);  // dn.subtree includes the entry, so the base rule dies
    }
    // --- to entry ---
    {
        auto r = parseAcl("to entry by * read");
        CHECK(r.targetEntry);
    }
    // --- quoted token with space ---
    {
        auto r = parseAcl("to attrs=cn by dn=\"cn=Admin,dc=example,dc=com\" write");
        CHECK(r.bys.size() == 1);
        CHECK(r.bys[0].subject == "dn=cn=Admin,dc=example,dc=com");
    }

    // --- conflicts: masked rule ---
    {
        auto rules = parseAclValues({
            "to * by * read",
            "to attrs=userPassword by * write",
        });
        auto c = analyzeAclConflicts(rules);
        bool found = false;
        for (const auto &x : c)
            if (x.kind == AclConflictKind::Masked && x.first == 0 && x.second == 1) found = true;
        CHECK(found);
    }
    // --- conflicts: masked rule (attrs=* covers userPassword) ---
    {
        auto rules = parseAclValues({
            "to attrs=* by self write",
            "to attrs=userPassword by self read",
        });
        auto c = analyzeAclConflicts(rules);
        bool masked = false, overlap = false;
        for (const auto &x : c) {
            if (x.kind == AclConflictKind::Masked) masked = true;
            if (x.kind == AclConflictKind::Overlap) overlap = true;
        }
        // "attrs=* write" fully covers "attrs=userPassword read" → masked
        CHECK(masked);
        (void)overlap;
    }
    // --- no false positive: disjoint attrs ---
    {
        auto rules = parseAclValues({
            "to attrs=mail by * read",
            "to attrs=userPassword by * write",
        });
        auto c = analyzeAclConflicts(rules);
        bool found = false;
        for (const auto &x : c)
            if (x.kind == AclConflictKind::Overlap || x.kind == AclConflictKind::Masked) found = true;
        CHECK(!found);
    }
    // --- uncertain: complex target (dn.regex) ---
    {
        auto rules = parseAclValues({
            "to dn.regex=\"^ou=.*,dc=example,dc=com$\" by * read",
            "to attrs=uid by * write",
        });
        auto c = analyzeAclConflicts(rules);
        bool found = false;
        for (const auto &x : c)
            if (x.kind == AclConflictKind::Uncertain) found = true;
        CHECK(found);
    }
    // --- uncertain: one entry per complex rule, lists interacting rules ---
    {
        auto rules = parseAclValues({
            "to dn.regex=\"^ou=.*,dc=example,dc=com$\" by * read",
            "to dn.base=\"ou=Apps,dc=example,dc=com\" attrs=cn by * read",
            "to dn.base=\"ou=Other,dc=example,dc=com\" by * read",
            "to * by * read",           // catch-all: not listed
        });
        auto c = analyzeAclConflicts(rules);
        int uncertain = 0;
        for (const auto &x : c)
            if (x.kind == AclConflictKind::Uncertain) uncertain++;
        CHECK(uncertain == 1);           // one entry for the dn.regex rule
        bool listsTwo = false, listsCatchAll = false;
        for (const auto &x : c) {
            if (x.kind != AclConflictKind::Uncertain) continue;
            if (x.detail.find("1") != std::string::npos &&
                x.detail.find("2") != std::string::npos) listsTwo = true;
            if (x.detail.find("3") != std::string::npos) listsCatchAll = true;
        }
        CHECK(listsTwo);
        CHECK(!listsCatchAll);
    }
    // --- masked: catch-all never covers a dn.base rule (scope matters) ---
    {
        auto rules = parseAclValues({
            "to dn.base=\"ou=Apps,dc=example,dc=com\" by users read",
            "to * by * none",
        });
        auto c = analyzeAclConflicts(rules);
        bool masked = false;
        for (const auto &x : c)
            if (x.kind == AclConflictKind::Masked && x.first == 0 && x.second == 1) masked = true;
        CHECK(!masked);  // the dn.base rule is narrower; the catch-all does not mask it
    }
    // --- empty / malformed ---
    {
        auto r = parseAcl("garbage");
        CHECK(r.target.empty());
        auto rules = parseAclValues({""});
        CHECK(rules.empty());
    }

    // --- evaluateAcl: slapacl-style first-match ---
    {
        auto rules = parseAclValues({
            "to attrs=userPassword by self write by anonymous auth by * none",
            "to * by users read by * none",
        });
        int ri = -1, ci = -1;
        // self can write userPassword
        CHECK(evaluateAcl(rules, "uid=alice,ou=people,dc=x", "uid=alice,ou=people,dc=x",
                          "userPassword", &ri, &ci) == "write");
        CHECK(ri == 0 && ci == 0);
        // anonymous can only auth
        CHECK(evaluateAcl(rules, "", "uid=alice,ou=people,dc=x", "userPassword") == "auth");
        // an unrelated user gets none on userPassword
        CHECK(evaluateAcl(rules, "uid=bob,ou=people,dc=x", "uid=alice,ou=people,dc=x",
                          "userPassword") == "none");
        // users can read other attributes
        CHECK(evaluateAcl(rules, "uid=bob,ou=people,dc=x", "uid=alice,ou=people,dc=x",
                          "mail") == "read");
        // anonymous cannot read mail
        CHECK(evaluateAcl(rules, "", "uid=alice,ou=people,dc=x", "mail") == "none");
        // no rule matches an unknown attribute for anonymous
        CHECK(evaluateAcl(rules, "", "uid=alice,ou=people,dc=x", "foo") == "none");
    }
    // --- evaluateAcl: first matching rule wins, even with weaker rights ---
    {
        auto rules = parseAclValues({
            "to * by * read",
            "to attrs=userPassword by * write",
        });
        // rule 0 matches first → read wins, not write
        CHECK(evaluateAcl(rules, "uid=bob,ou=people,dc=x", "uid=bob,ou=people,dc=x",
                          "userPassword") == "read");
    }

    // --- evaluateAcl: dn.base subject ---
    {
        auto rules = parseAclValues({
            "to * by dn.base=\"gidNumber=1000+uidNumber=1000,cn=peercred,cn=external,cn=auth\" manage by * none",
        });
        CHECK(evaluateAcl(rules, "gidNumber=1000+uidNumber=1000,cn=peercred,cn=external,cn=auth",
                          "cn=config", "*") == "manage");
        CHECK(evaluateAcl(rules, "uid=bob,ou=people,dc=x", "cn=config", "*") == "none");
    }

    // --- buildAclReport withGraph: edges labelled with the conflict kind ---
    {
        auto rules = parseAclValues({
            "to * by * read",
            "to * by * none",
            "to attrs=userPassword by * write",
        });
        auto conflicts = analyzeAclConflicts(rules);
        std::string g = buildAclReport(rules, conflicts, true);
        CHECK(g.find("MASKED") != std::string::npos);
        CHECK(g.find("[1] to *") != std::string::npos);
        CHECK(g.find("[2] to attrs=userPassword") != std::string::npos);
    }
    // --- buildAclReport: empty rules ---
    {
        std::string g = buildAclReport({}, {});
        CHECK(g.empty());
    }

    // --- formatAclValueLines: one line per clause, quotes preserved ---
    {
        auto lines = diratlas::ldapcore::formatAclValueLines(
            "{0}to attrs=userPassword by self read by dn.base=\"cn=Admin,dc=eu\" manage by * none");
        CHECK(lines.size() == 4);
        CHECK(lines[0] == "{0}to attrs=userPassword");
        CHECK(lines[1] == "      by self read");
        CHECK(lines[2] == "      by dn.base=\"cn=Admin,dc=eu\" manage");
        CHECK(lines[3] == "      by * none");
    }
    // --- formatAclValueLines: no "by" → single line ---
    {
        auto lines = diratlas::ldapcore::formatAclValueLines("{0}to *");
        CHECK(lines.size() == 1 && lines[0] == "{0}to *");
    }
    // --- buildAclReport: conflict shown under its rule ---
    {
        auto rules = parseAclValues({
            "to * by * read",
            "to attrs=userPassword by * write",
        });
        auto c = analyzeAclConflicts(rules);
        std::string r = diratlas::ldapcore::buildAclReport(rules, c);
        CHECK(r.find("[0] to *") != std::string::npos);
        CHECK(r.find("[1] to attrs=userPassword") != std::string::npos);
        // the MASKED conflict is anchored under rule 1 (the earlier rule)
        size_t pos = r.find("MASKED");
        CHECK(pos != std::string::npos);
        CHECK(r.rfind("[0] to *", pos) < pos);   // rule 0 line is above the conflict
        CHECK(r.find("is fully covered") != std::string::npos);
    }
    // --- buildAclReport: branch separators only for multi-rule groups ---
    {
        auto rules = parseAclValues({
            "to dn.subtree=\"ou=People,dc=europa,dc=eu\" by users read",
            "to dn.regex=ou=People,dc=(.+),dc=europa,dc=eu attrs=cn by users read",
            "to dn.base=\"ou=Groups,dc=europa,dc=eu\" by users read",
        });
        std::string r = diratlas::ldapcore::buildAclReport(rules, {});
        // no heavy ══ separators; both rules listed in order
        CHECK(r.find("══") == std::string::npos);
        CHECK(r.find("[0] to dn.subtree=\"ou=People,dc=europa,dc=eu\"") != std::string::npos);
        CHECK(r.find("[1] to dn.regex=ou=People,dc=(.+),dc=europa,dc=eu attrs=cn") != std::string::npos);
        CHECK(r.find("[2] to dn.base=\"ou=Groups,dc=europa,dc=eu\"") != std::string::npos);
        // tree arrow used for conflicts
        CHECK(r.find("└─ ! ") == std::string::npos);  // no conflicts here
    }
    // --- buildAclReport: withGraph shows edges under the rule ---
    {
        auto rules = parseAclValues({
            "to * by * read",
            "to attrs=userPassword by * write",
        });
        auto c = analyzeAclConflicts(rules);
        std::string r = diratlas::ldapcore::buildAclReport(rules, c, true);
        CHECK(r.find("MASKED ──► [1] to attrs=userPassword") != std::string::npos);
        CHECK(r.find("(rule 1 is fully covered by rule 0)") != std::string::npos);
        CHECK(r.find("✓") != std::string::npos);  // the rights table has a check cell
        // without withGraph: plain conflict text
        std::string r2 = diratlas::ldapcore::buildAclReport(rules, c);
        CHECK(r2.find("! MASKED rule 1 is fully covered by rule 0") != std::string::npos);
    }
    // --- buildAclReport: rights table with checks ---
    {
        auto rules = parseAclValues({
            "to attrs=userPassword by self read by anonymous auth by * none",
        });
        std::string r = diratlas::ldapcore::buildAclReport(rules, {});
        CHECK(r.find("┌─ [0] to attrs=userPassword") != std::string::npos);
        CHECK(r.find("auth") != std::string::npos);
        CHECK(r.find("manage") != std::string::npos);  // full column name
        CHECK(r.find("✓") != std::string::npos);  // at least one check (read)
    }
    // --- buildAclReport: ssf selector is kept with the subject and rights ---
    {
        auto r = parseAcl("to * by ssf=128 self write by ssf=64 anonymous auth by * none");
        CHECK(r.bys.size() == 3);
        CHECK(r.bys[0].selector == "ssf=128" && r.bys[0].subject == "self" &&
              r.bys[0].rights == "write");
        CHECK(r.bys[1].selector == "ssf=64" && r.bys[1].subject == "anonymous" &&
              r.bys[1].rights == "auth");
        CHECK(r.bys[2].selector.empty() && r.bys[2].subject == "*" &&
              r.bys[2].rights == "none");
        std::string rep = diratlas::ldapcore::buildAclReport({r}, {});
        CHECK(rep.find("ssf=128 self") != std::string::npos);
        CHECK(rep.find("ssf=64 anonymous") != std::string::npos);
    }

    // --- ACI syntax (389 DS / Oracle / PingDirectory / ApacheDS) ---
    {
        // targetattr + userdn self
        auto r = parseAcl("(targetattr=\"cn || sn || mail\")(version 3.0; acl \"Read\"; "
                          "allow (read, search) userdn=\"ldap:///self\";)");
        CHECK(r.bys.size() == 1);
        CHECK(r.targetAttrs.size() == 3);
        CHECK(r.bys[0].subject == "self");
        CHECK(r.bys[0].rights.find("read") != std::string::npos);
        // target= + groupdn
        auto r2 = parseAcl("(target=\"ldap:///ou=People,dc=example,dc=com\")(targetattr=\"*\")"
                           "(version 3.0; acl \"All\"; allow (all) "
                           "groupdn=\"ldap:///cn=admins,ou=Groups,dc=example,dc=com\";)");
        CHECK(r2.bys.size() == 1);
        CHECK(r2.targetDn == "ou=People,dc=example,dc=com");
        CHECK(r2.bys[0].subject.rfind("group/", 0) == 0);
        CHECK(r2.bys[0].rights.find("all") != std::string::npos);
        // deny → none
        auto r3 = parseAcl("(version 3.0; acl \"Deny pw\"; deny (write) userattr=\"userPassword\";)");
        CHECK(r3.bys.size() == 1);
        CHECK(r3.bys[0].subject.rfind("userattr=", 0) == 0);
        // targetfilter → complex
        auto r4 = parseAcl("(targetattr=\"*\")(targetfilter=\"(objectClass=domain)\")"
                           "(version 3.0; acl \"Dom\"; allow (read) userdn=\"ldap:///anyone\";)");
        CHECK(r4.targetComplex);
        CHECK(r4.bys.size() == 1);
        CHECK(r4.bys[0].subject == "*");  // anyone → *
        // all maps to the manage column in the report
        std::string rep = diratlas::ldapcore::buildAclReport(
            {parseAcl("(targetattr=\"*\")(version 3.0; acl \"All\"; allow (all) userdn=\"ldap:///anyone\";)")},
            {});
        CHECK(rep.find("manage") != std::string::npos);
        CHECK(rep.find("✓") != std::string::npos);
    }

    // --- Oracle OID syntax: "access to entry by * (browse)" ---
    {
        auto r = parseAcl("access to entry by * (browse)");
        CHECK(r.targetEntry);
        CHECK(r.target == "entry");
        CHECK(r.bys.size() == 1);
        CHECK(r.bys[0].subject == "*" && r.bys[0].rights == "browse");
        // attr=(a, b) with spaces + dn with spaces
        auto r2 = parseAcl("access to attr=(orclstatsflag, orclstatsperiodicity,orcleventlevel) "
                           "by dn=\"cn=directory manager, o=IMC, c=us\" (browse, add, delete) "
                           "by * (browse, noadd, nodelete)");
        CHECK(r2.targetAttrs.size() == 3);
        CHECK(r2.bys.size() == 2);
        CHECK(r2.bys[0].subject == "dn=cn=directory manager, o=IMC, c=us");
        CHECK(r2.bys[0].rights == "browse, add, delete");
        CHECK(r2.bys[1].rights == "browse, noadd, nodelete");
        // group= quoted → group/
        auto r3 = parseAcl("access to attr=(*) by group=\"cn=admins,cn=groups\" (search, read)");
        CHECK(r3.bys.size() == 1);
        CHECK(r3.bys[0].subject == "group/cn=admins,cn=groups");
        // filter= and added_object_constraint → complex
        auto r4 = parseAcl("access to attr=(*) filter=(objectclass=inetorgperson) by * (read)");
        CHECK(r4.targetComplex);
        auto r5 = parseAcl("access to entry by group=\"cn=x\" added_object_constraint=(objectclass=orcluser*) "
                           "(browse, add) by * (browse)");
        CHECK(r5.targetComplex);
        CHECK(r5.bys.size() == 2);
        // deny/negated rights do not grant a level in the report
        std::string rep = diratlas::ldapcore::buildAclReport(
            {parseAcl("access to entry by * (browse, noadd, nodelete)")}, {});
        CHECK(rep.find("search") != std::string::npos);  // browse → search column
        // entry and attrs targets do not cover each other
        auto conflicts = analyzeAclConflicts(parseAclValues({
            "access to entry by * (browse)",
            "access to attr=(*) by * (search)",
        }));
        CHECK(conflicts.empty());
    }

    // --- 389 DS / RHDS: nested parens in targetfilter, negated targetattr ---
    {
        // targetfilter contains a parenthesised filter "(objectClass=x)" inside
        // the quoted group; the closing paren of the group must be found by
        // depth, not by the first ')'
        auto r = parseAcl("(targetattr=\"*\")(targetfilter=\"(objectClass=nsManagedDomain)\")"
                          "(version 3.0; acl \"Domain\"; allow (read,search) "
                          "groupdn=\"ldap:///cn=DomainAdmins,ou=Groups,dc=example,dc=com\";)");
        CHECK(r.targetComplex);
        CHECK(r.target.find("objectClass=nsManagedDomain") != std::string::npos);
        CHECK(r.bys.size() == 1);
        CHECK(r.bys[0].subject == "group/cn=DomainAdmins,ou=Groups,dc=example,dc=com");
        // negated targetattr (targetattr != "x") is a complex exclusion
        auto r2 = parseAcl("(targetattr != \"userPassword\")(version 3.0; acl \"Not pw\"; "
                           "allow (read) userdn=\"ldap:///anyone\";)");
        CHECK(r2.targetComplex);
        CHECK(r2.bys.size() == 1);
        CHECK(r2.bys[0].subject == "*");  // anyone → *
    }

    // --- RHDS: repeated targetattr, parenthesised bind rules, roledn, booleans ---
    {
        // repeated targetattr keyword: (targetattr="a" || targetattr="b" || ...)
        auto r = parseAcl("(targetattr=\"sn\" || targetattr=\"givenName\" || "
                          "targetattr = \"telephoneNumber\")(version 3.0; acl \"Names\"; "
                          "allow (read, search) userdn = \"ldap:///anyone\";)");
        CHECK(r.targetAttrs.size() == 3);
        CHECK(r.targetAttrs[0] == "sn" && r.targetAttrs[2] == "telephoneNumber");
        CHECK(r.target == "attrs=sn,givenName,telephoneNumber");
        CHECK(r.bys[0].subject == "*");  // anyone → *
        // parenthesised bind rule "(userdn = \"ldap:///self\")" → self
        auto r2 = parseAcl("(target = \"ldap:///ou=People,dc=example,dc=com\")"
                           "(version 3.0; acl \"Own\"; allow (search, read) "
                           "(userdn = \"ldap:///self\");)");
        CHECK(r2.bys[0].subject == "self");
        // roledn → role/
        auto r3 = parseAcl("(targetattr=\"manager\")(version 3.0; acl \"Role\"; "
                           "allow (search, read) roledn = \"ldap:///cn=HR,ou=People,dc=x\";)");
        CHECK(r3.bys[0].subject == "role/cn=HR,ou=People,dc=x");
        // compound bind rule (and/or) is kept raw, not split
        auto r4 = parseAcl("(targetattr = \"userPassword\")(version 3.0; acl \"SSF\"; "
                           "allow (write) (userdn = \"ldap:///self\") and (ssf >= \"128\");)");
        CHECK(r4.bys[0].subject.find(" and ") != std::string::npos);
    }

    if (failures == 0) {
        std::cout << "test_acl: all checks passed" << std::endl;
        return 0;
    }
    std::cerr << "test_acl: " << failures << " check(s) failed" << std::endl;
    return 1;
}