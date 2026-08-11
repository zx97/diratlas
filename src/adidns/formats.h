// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Manuel FLURY
//
// This file is part of DirAtlas — an LDAP Directory Explorer.
//
// Licensed under the GNU Affero General Public License v3.0
// (https://www.gnu.org/licenses/agpl-3.0.txt).
//
// Originally based on godap (github.com/Macmod/godap) — MIT license.

#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace diratlas::adidns {

std::string parseIP(const std::vector<uint8_t> &data);
std::vector<std::string> parseAddrArray(const std::vector<uint8_t> &data);
std::vector<std::string> parseIP4Array(const std::vector<uint8_t> &data);
std::string formatHours(uint64_t val);
int64_t msTimeToUnixTimestamp(uint64_t msTime);
uint32_t getCurrentMSTime();

} // namespace diratlas::adidns
