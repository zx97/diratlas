// test_dn.cpp — unit tests for ldapcore::dn pure helpers
//
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Manuel FLURY
//
// This file is part of DirAtlas — an LDAP Directory Explorer.
//
// Licensed under the GNU Affero General Public License v3.0
// (https://www.gnu.org/licenses/agpl-3.0.txt).
//

#include "../src/ldapcore/dn.h"
#include <cassert>
#include <iostream>

using diratlas::ldapcore::braceIdx;
using diratlas::ldapcore::parentOf;
using diratlas::ldapcore::rdnOf;

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
    // braceIdx
    CHECK(braceIdx("{3}to * by * read") == 3);
    CHECK(braceIdx("{0}foo") == 0);
    CHECK(braceIdx("{42}") == 42);
    CHECK(braceIdx("no braces") == 0);
    CHECK(braceIdx("{notanumber}") == 0);
    CHECK(braceIdx("") == 0);

    // rdnOf / parentOf on plain DNs
    CHECK(rdnOf("cn=a,ou=b,dc=x") == "cn=a");
    CHECK(parentOf("cn=a,ou=b,dc=x") == "ou=b,dc=x");
    CHECK(rdnOf("cn=a") == "cn=a");
    CHECK(parentOf("cn=a") == "");
    CHECK(parentOf("") == "");

    // Escaped comma inside an RDN value must not split the DN.
    CHECK(rdnOf("cn=doe\\,john,ou=b,dc=x") == "cn=doe\\,john");
    CHECK(parentOf("cn=doe\\,john,ou=b,dc=x") == "ou=b,dc=x");

    if (failures == 0) {
        std::cout << "test_dn: all checks passed" << std::endl;
        return 0;
    }
    std::cerr << "test_dn: " << failures << " check(s) failed" << std::endl;
    return 1;
}