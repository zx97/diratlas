// dn.cpp — pure DN string helpers (no LDAP dependency, unit-testable)
//
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Manuel FLURY
//
// This file is part of DirAtlas — an LDAP Directory Explorer.
//
// Licensed under the GNU Affero General Public License v3.0
// (https://www.gnu.org/licenses/agpl-3.0.txt).
//

#include "dn.h"
#include <cctype>

namespace diratlas::ldapcore {

int braceIdx(const std::string &val) {
    auto p = val.find('{');
    if (p == std::string::npos) return 0;
    auto q = val.find('}', p);
    if (q == std::string::npos) return 0;
    try { return std::stoi(val.substr(p + 1, q - p - 1)); }
    catch (...) { return 0; }
}

std::string parentOf(const std::string &dn) {
    // Split on the first unescaped comma; escaped commas (\,) are part of an RDN.
    for (size_t i = 0; i < dn.size(); ++i) {
        if (dn[i] == '\\') { ++i; continue; }
        if (dn[i] == ',') return dn.substr(i + 1);
    }
    return "";
}

std::string rdnOf(const std::string &dn) {
    for (size_t i = 0; i < dn.size(); ++i) {
        if (dn[i] == '\\') { ++i; continue; }
        if (dn[i] == ',') return dn.substr(0, i);
    }
    return dn;
}

std::string buildChildDn(const std::string &rdn, const std::string &parentDN) {
    if (parentDN.empty()) return rdn;
    return rdn + "," + parentDN;
}

} // namespace diratlas::ldapcore