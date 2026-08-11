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
#include <map>
#include <cstdint>

namespace diratlas {

struct FormattedAttrValue {
    std::string originalValue;
    std::string formattedValue;
};

struct FormattedAttr {
    std::vector<FormattedAttrValue> values;

    std::string valuesStr() const;
};

// Hex/byte utils
std::string endianConvert(const std::string &sd);
uint64_t hexToOffset(const std::string &hex);
uint32_t hexToUint32(const std::string &hex);
int hexToInt(const std::string &hex);
std::string hexToDecimalString(const std::string &hex);
std::string capitalize(const std::string &str);

// SID conversion
std::string convertSID(const std::string &hexSID);
std::string encodeSID(const std::string &sid);
bool isSID(const std::string &s);

// GUID conversion
std::string convertGUID(const std::string &hexGUID);
std::string encodeGUID(const std::string &guid);

// Time formatting
std::string formatLDAPTime(const std::string &val, const std::string &format, int offset);
std::string formatLDAPTime2(const std::string &val, const std::string &format, int offset);
std::string formatDuration(int64_t seconds);
int64_t parseMSDuration(const std::string &val);

// Bit flags
std::vector<std::string> parseUACFlags(int uacInt);
std::vector<std::string> parseBitFlags(uint32_t v, const std::map<uint32_t, std::string> &flagMap);
std::vector<std::string> parseSystemFlags(uint32_t v);

// LDAP attribute formatting (without ldap dependency - uses raw values)
std::vector<FormattedAttrValue> formatAttributeValues(
    const std::string &attrName,
    const std::vector<std::string> &values,
    const std::vector<std::vector<uint8_t>> &byteValues,
    const std::string &timeFormat,
    int timeOffset
);

} // namespace diratlas
