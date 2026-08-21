// test_attrdesc.cpp — unit tests for ldapcore::parseAttributeDescription
//
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Manuel FLURY
//
// This file is part of DirAtlas — an LDAP Directory Explorer.
//
// Licensed under the GNU Affero General Public License v3.0
// (https://www.gnu.org/licenses/agpl-3.0.txt).
//

#include "../src/ldapcore/attrdesc.h"
#include <cassert>
#include <iostream>

using diratlas::ldapcore::AttributeDescription;
using diratlas::ldapcore::parseAttributeDescription;

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
    AttributeDescription ad;

    // Plain attribute
    CHECK(parseAttributeDescription("cn", ad));
    CHECK(ad.type == "cn");
    CHECK(ad.plain());
    CHECK(ad.options.empty());
    CHECK(!ad.binary());

    // One option, case-insensitive
    CHECK(parseAttributeDescription("description;binary", ad));
    CHECK(ad.type == "description");
    CHECK(ad.options.size() == 1);
    CHECK(ad.options[0] == "binary");
    CHECK(ad.binary());

    // Multiple options + case mixing
    CHECK(parseAttributeDescription("cn;lang-EN;Binary", ad));
    CHECK(ad.type == "cn");
    CHECK(ad.options.size() == 2);
    CHECK(ad.options[0] == "lang-en");
    CHECK(ad.options[1] == "binary");
    CHECK(ad.binary());
    CHECK(ad.str() == "cn;lang-en;binary");

    // Type case-insensitive
    CHECK(parseAttributeDescription("JpegPhoto;binary", ad));
    CHECK(ad.type == "jpegphoto");
    CHECK(ad.binary());

    // OID-like type
    CHECK(parseAttributeDescription("2.5.4.3", ad));
    CHECK(ad.type == "2.5.4.3");
    CHECK(ad.plain());

    // Invalid inputs
    CHECK(!parseAttributeDescription("", ad));
    CHECK(!parseAttributeDescription(";binary", ad));   // empty type
    CHECK(!parseAttributeDescription("cn;", ad));        // empty option
    CHECK(!parseAttributeDescription("cn;lang en", ad)); // space in option
    CHECK(!parseAttributeDescription("cn extra", ad));   // space in type

    if (failures == 0) {
        std::cout << "test_attrdesc: all checks passed\n";
        return 0;
    }
    std::cerr << "test_attrdesc: " << failures << " failure(s)\n";
    return 1;
}
