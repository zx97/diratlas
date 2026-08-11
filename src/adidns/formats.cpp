// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Manuel FLURY
//
// This file is part of DirAtlas — an LDAP Directory Explorer.
//
// Licensed under the GNU Affero General Public License v3.0
// (https://www.gnu.org/licenses/agpl-3.0.txt).
//
// Originally based on godap (github.com/Macmod/godap) — MIT license.

#include "formats.h"
#include <cmath>
#include <cstring>
#include <algorithm>
#include <chrono>

namespace diratlas::adidns {

std::string parseIP(const std::vector<uint8_t> &data) {
    if (data.size() == 4) {
        char buf[16];
        snprintf(buf, sizeof(buf), "%d.%d.%d.%d", data[0], data[1], data[2], data[3]);
        return buf;
    } else if (data.size() == 16) {
        char buf[40];
        snprintf(buf, sizeof(buf), "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
            data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15]);
        return buf;
    }
    return "";
}

std::vector<std::string> parseAddrArray(const std::vector<uint8_t> &data) {
    if (data.size() < 33) return {};
    uint8_t numIPs = data[0];
    auto addrArr = std::vector<uint8_t>(data.begin() + 32, data.end());

    std::vector<std::string> ips;
    for (int x = 0; x < numIPs && (x * 32 + 24) <= static_cast<int>(addrArr.size()); x++) {
        uint16_t family;
        memcpy(&family, &addrArr[x * 32], 2);
        if (family == 0x0002) {
            ips.push_back(parseIP(std::vector<uint8_t>(addrArr.begin() + x * 32 + 4, addrArr.begin() + x * 32 + 8)));
        } else if (family == 0x0017) {
            ips.push_back(parseIP(std::vector<uint8_t>(addrArr.begin() + x * 32 + 8, addrArr.begin() + x * 32 + 24)));
        }
    }
    return ips;
}

std::vector<std::string> parseIP4Array(const std::vector<uint8_t> &data) {
    if (data.empty()) return {};
    uint8_t numIP4s = data[0];
    if (data.size() < static_cast<size_t>(1 + 4 * numIP4s)) return {};

    std::vector<std::string> ips;
    for (int x = 0; x < numIP4s; x++) {
        auto ipData = std::vector<uint8_t>(data.begin() + 1 + x * 4, data.begin() + 1 + (x + 1) * 4);
        ips.push_back(parseIP(ipData));
    }
    return ips;
}

std::string formatHours(uint64_t val) {
    int days = 0;
    if (val > 24) days = static_cast<int>(val / 24);
    if (days > 0) {
        std::string text = std::to_string(days) + " days";
        if (val % 24 != 0)
            text += ", " + std::to_string(val % 24) + " hours";
        return text;
    }
    return std::to_string(val) + " hours";
}

int64_t msTimeToUnixTimestamp(uint64_t msTime) {
    if (msTime == 0) return -1;
    uint64_t secondsSince = msTime - 11644473600ULL;
    return static_cast<int64_t>(secondsSince);
}

uint32_t getCurrentMSTime() {
    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    auto hours = std::chrono::duration_cast<std::chrono::hours>(duration).count();
    return static_cast<uint32_t>(hours) + 3234576;
}

} // namespace diratlas::adidns
