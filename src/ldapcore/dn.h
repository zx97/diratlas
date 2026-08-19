// dn.h — pure DN string helpers (no LDAP dependency, unit-testable)
//
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Manuel FLURY
//
// This file is part of DirAtlas — an LDAP Directory Explorer.
//
// Licensed under the GNU Affero General Public License v3.0
// (https://www.gnu.org/licenses/agpl-3.0.txt).
//

#pragma once
#include <string>

namespace diratlas::ldapcore {

/** @brief Numeric index of a brace-numbered value ("{3}to * by * read" → 3), or 0. */
int braceIdx(const std::string &val);

/** @brief Parent DN of a distinguished name ("cn=a,ou=b,dc=x" → "ou=b,dc=x"). */
std::string parentOf(const std::string &dn);

/** @brief RDN of a distinguished name ("cn=a,ou=b,dc=x" → "cn=a"). */
std::string rdnOf(const std::string &dn);

/** @brief Child DN built from a parent and an RDN ("cn=x" + "ou=b,dc=y" → "cn=x,ou=b,dc=y"). */
std::string buildChildDn(const std::string &rdn, const std::string &parentDN);

} // namespace diratlas::ldapcore