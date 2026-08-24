// test_bytes.cpp — unit tests for ldapcore::bytes pure helpers
//
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Manuel FLURY
//
// This file is part of DirAtlas — an LDAP Directory Explorer.
//
// Licensed under the GNU Affero General Public License v3.0
// (https://www.gnu.org/licenses/agpl-3.0.txt).
//

#include "../src/ldapcore/bytes.h"
#include <cassert>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

using diratlas::ldapcore::base64Decode;
using diratlas::ldapcore::base64Encode;
using diratlas::ldapcore::bytesToHex;
using diratlas::ldapcore::isPrintable;
using diratlas::ldapcore::ldifSafeValue;
using diratlas::ldapcore::readLE32;
using diratlas::ldapcore::strToInt;
using diratlas::ldapcore::strToUInt;

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
    // bytesToHex
    CHECK(bytesToHex({}) == "");
    CHECK(bytesToHex({0x00, 0x01, 0xAB, 0xFF}) == "0001ABFF");
    CHECK(bytesToHex({0x0f}, false) == "0f");

    // readLE32
    CHECK(readLE32({0x01, 0x02, 0x03, 0x04}, 0) == 0x04030201u);
    CHECK(readLE32({0x01, 0x02}, 0) == 0);           // too short
    CHECK(readLE32({0x01, 0x02, 0x03, 0x04, 0x05}, 1) == 0x05040302u);

    // isPrintable
    CHECK(isPrintable({}));
    CHECK(isPrintable({'h', 'e', 'l', 'l', 'o'}));
    CHECK(isPrintable({'a', '\n', 'b', '\t', 'c', '\r', 'd'})); // LF/CR/TAB ok
    CHECK(!isPrintable({0x00, 0x01}));
    CHECK(!isPrintable({'a', 0x1F}));
    CHECK(!isPrintable({0x7F}));

    // strToInt
    CHECK(strToInt("42", -1) == 42);
    CHECK(strToInt("-7", 0) == -7);
    CHECK(strToInt("+9", 0) == 9);
    CHECK(strToInt("", 5) == 5);
    CHECK(strToInt("abc", 5) == 5);
    CHECK(strToInt("12x", 5) == 5);                  // trailing garbage
    CHECK(strToInt("99999999999999999999999", 5) == 5); // overflow

    // strToUInt
    CHECK(strToUInt("42", 0) == 42);
    CHECK(strToUInt("", 7) == 7);
    CHECK(strToUInt("-1", 7) == 7);
    CHECK(strToUInt("3.14", 7) == 7);

    // base64 round-trips
    CHECK(base64Encode("") == "");
    CHECK(base64Encode("f") == "Zg==");
    CHECK(base64Encode("fo") == "Zm8=");
    CHECK(base64Encode("foo") == "Zm9v");
    CHECK(base64Encode("foobar") == "Zm9vYmFy");
    std::string bin = "\x00\x01\x02\xff\xfe\x80";
    CHECK(base64Decode(base64Encode(bin)) == bin);
    CHECK(base64Decode("Zm9vYmFy") == "foobar");
    CHECK(base64Decode("Zm9v YmFy") == "foobar");    // whitespace ignored
    CHECK(base64Decode("Zm9vYg") == "foob");         // unpadded input accepted
    CHECK(base64Decode("!!!") == "");                // invalid chars

    // ldifSafeValue
    CHECK(ldifSafeValue("plain text"));
    CHECK(!ldifSafeValue(""));
    CHECK(!ldifSafeValue(" leading space"));
    CHECK(!ldifSafeValue(":leading colon"));
    CHECK(!ldifSafeValue("trailing "));
    CHECK(!ldifSafeValue("with\nnewline"));
    CHECK(!ldifSafeValue("non-ascii \xc3\xa9"));
    CHECK(!ldifSafeValue("control\x01"));

    if (failures == 0) {
        std::cout << "test_bytes: all checks passed" << std::endl;
        return 0;
    }
    std::cerr << "test_bytes: " << failures << " check(s) failed" << std::endl;
    return 1;
}