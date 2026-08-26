// test_acl.cpp — unit tests for ldapcore::acl (olcAccess parser + conflicts)
//
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Manuel FLURY

#include "../src/ldapcore/acl.h"
#include <cassert>
#include <iostream>

using diratlas::ldapcore::AclConflictKind;
using diratlas::ldapcore::analyzeAclConflicts;
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
    // --- dn.subtree is marked complex ---
    {
        auto r = parseAcl("to dn.subtree=\"ou=people,dc=example,dc=com\" by * read");
        CHECK(r.targetComplex);
        CHECK(!r.targetDn.empty());
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
    // --- uncertain: complex target ---
    {
        auto rules = parseAclValues({
            "to dn.subtree=\"ou=people,dc=example,dc=com\" by * read",
            "to attrs=uid by * write",
        });
        auto c = analyzeAclConflicts(rules);
        bool found = false;
        for (const auto &x : c)
            if (x.kind == AclConflictKind::Uncertain) found = true;
        CHECK(found);
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

    if (failures == 0) {
        std::cout << "test_acl: all checks passed" << std::endl;
        return 0;
    }
    std::cerr << "test_acl: " << failures << " check(s) failed" << std::endl;
    return 1;
}