// attrdesc.h — AttributeDescription parsing (RFC 4512 §2.5.2)
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
#include <vector>

namespace diratlas::ldapcore {

/// A parsed AttributeDescription (RFC 4512 §2.5.2): an attribute type plus
/// zero or more options, e.g. "cn;lang-en;binary" -> type "cn", options
/// ["lang-en", "binary"].
struct AttributeDescription {
    std::string type;                  ///< Attribute type (lower-cased)
    std::vector<std::string> options;  ///< Options (each lower-cased)
    /// The full original description string (unmodified).
    std::string original;
    /// Whether the :binary option is present.
    bool binary() const;
    /// True when there are no options.
    bool plain() const { return options.empty(); }
    /// Reconstruct "type;opt1;opt2" (lower-cased).
    std::string str() const;
};

/// Parse an AttributeDescription. Returns false on malformed input
/// (empty type, invalid characters). Options are lower-cased.
bool parseAttributeDescription(const std::string &desc, AttributeDescription &out);

} // namespace diratlas::ldapcore
