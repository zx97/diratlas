// test_attrs.cpp — unit tests for ldapcore::attrs pure helpers
//
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Manuel FLURY
//
// This file is part of DirAtlas — an LDAP Directory Explorer.
//
// Licensed under the GNU Affero General Public License v3.0
// (https://www.gnu.org/licenses/agpl-3.0.txt).
//

#include "../src/ldapcore/attrs.h"
#include <cassert>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

using diratlas::ldapcore::formatAttribute;
using diratlas::ldapcore::formatDuration;
using diratlas::ldapcore::formatTimestamp;
using diratlas::ldapcore::parseGeneralizedTime;

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
    // 2024-01-01T12:00:00Z == 1704110400
    const int64_t NOON_2024 = 1704110400;

    // parseGeneralizedTime
    CHECK(parseGeneralizedTime("20240101120000Z") == NOON_2024);
    CHECK(parseGeneralizedTime("20240101120000") == NOON_2024);      // no tz = UTC
    CHECK(parseGeneralizedTime("202401011200") == NOON_2024);        // no seconds
    CHECK(parseGeneralizedTime("20240101120000.123Z") == NOON_2024); // fraction ignored
    CHECK(parseGeneralizedTime("20240101120000+0100") == NOON_2024 - 3600);
    CHECK(parseGeneralizedTime("20240101120000-0500") == NOON_2024 + 5 * 3600);
    CHECK(parseGeneralizedTime("20240101130000+0100") == NOON_2024); // 13:00+01 == 12:00Z
    // garbage / out-of-range
    CHECK(parseGeneralizedTime("") == 0);
    CHECK(parseGeneralizedTime("garbage") == 0);
    CHECK(parseGeneralizedTime("20240101120000X") == 0);             // bad tz marker
    CHECK(parseGeneralizedTime("20241301120000Z") == 0);             // month 13
    CHECK(parseGeneralizedTime("20240100120000Z") == 0);             // day 0
    CHECK(parseGeneralizedTime("20240101126000Z") == 0);             // minute 60
    CHECK(parseGeneralizedTime("19691231235959Z") == 0);             // pre-1970

    // formatTimestamp
    CHECK(formatTimestamp(NOON_2024, "%Y-%m-%d %H:%M:%S") == "2024-01-01 12:00:00");
    CHECK(formatTimestamp(0, "%Y") == "1970");
    CHECK(formatTimestamp(0, "%Y", 1) == "1970"); // offset is applied but date stays 1970

    // formatDuration
    CHECK(formatDuration(0) == "0 seconds");
    CHECK(formatDuration(1) == "1 seconds");
    CHECK(formatDuration(60) == "1 minutes");
    CHECK(formatDuration(3600) == "1 hours");
    CHECK(formatDuration(86400) == "1 days");
    CHECK(formatDuration(90061) == "1 days 1 hours 1 minutes 1 seconds");

    // formatAttribute
    {
        auto out = formatAttribute("createtimestamp", {"20240101120000Z"}, {}, "%Y-%m-%d");
        CHECK(out.size() == 1);
        CHECK(out[0].formatted == "2024-01-01");
    }
    {
        // Non-printable bytes → HEX{...}
        auto out = formatAttribute("userCertificate", {"\x00\x01"},
                                   {{0x00, 0x01}}, "%Y");
        CHECK(out.size() == 1);
        CHECK(out[0].formatted == "HEX{0001}");
    }
    {
        // Plain text is kept as-is
        auto out = formatAttribute("cn", {"hello"}, {}, "%Y");
        CHECK(out.size() == 1);
        CHECK(out[0].formatted == "hello");
        CHECK(out[0].raw == "hello");
    }
    {
        // Empty values produce a single "(Empty)" row
        auto out = formatAttribute("cn", {}, {}, "%Y");
        CHECK(out.size() == 1);
        CHECK(out[0].formatted == "(Empty)");
    }

    if (failures == 0) {
        std::cout << "test_attrs: all checks passed" << std::endl;
        return 0;
    }
    std::cerr << "test_attrs: " << failures << " check(s) failed" << std::endl;
    return 1;
}