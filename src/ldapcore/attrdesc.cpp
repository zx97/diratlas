// attrdesc.cpp — AttributeDescription parsing (RFC 4512 §2.5.2)
//
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Manuel FLURY
//
// This file is part of DirAtlas — an LDAP Directory Explorer.
//
// Licensed under the GNU Affero General Public License v3.0
// (https://www.gnu.org/licenses/agpl-3.0.txt).
//

#include "attrdesc.h"

#include <cctype>

namespace diratlas::ldapcore {

namespace {
// An option name is keystring = (ALPHA / DIGIT) *( ALPHA / DIGIT / HYPHEN )
// (RFC 4512 §2.5.2). An attribute type is a descriptive name (LDAPOID /
// keystring); we accept letters, digits, hyphens and '.' for OIDs.
bool validTypeChar(char c) {
    return std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '.';
}
bool validOptionChar(char c) {
    return std::isalnum(static_cast<unsigned char>(c)) || c == '-';
}
std::string toLower(std::string s) {
    for (char &c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}
} // namespace

bool AttributeDescription::binary() const {
    for (const auto &o : options)
        if (o == "binary") return true;
    return false;
}

std::string AttributeDescription::str() const {
    std::string s = type;
    for (const auto &o : options) { s += ';'; s += o; }
    return s;
}

bool parseAttributeDescription(const std::string &desc, AttributeDescription &out) {
    out = AttributeDescription{};
    out.original = desc;
    if (desc.empty()) return false;

    size_t i = 0;
    while (i < desc.size() && desc[i] != ';') {
        if (!validTypeChar(desc[i])) return false;
        i++;
    }
    if (i == 0) return false;  // empty type
    out.type = toLower(desc.substr(0, i));

    // Options separated by ';'. A trailing ';' with no option is invalid.
    if (i == desc.size()) return true;  // no options
    if (desc[i] == ';') {
        i++;
        if (i == desc.size()) return false;  // trailing ';'
    }
    while (i < desc.size()) {
        size_t start = i;
        while (i < desc.size() && desc[i] != ';') {
            if (!validOptionChar(desc[i])) return false;
            i++;
        }
        if (i == start) return false;  // empty option (e.g. "cn;;x")
        out.options.push_back(toLower(desc.substr(start, i - start)));
        if (i < desc.size() && desc[i] == ';') {
            i++;
            if (i == desc.size()) return false;  // trailing ';'
        }
    }
    return true;
}

} // namespace diratlas::ldapcore
