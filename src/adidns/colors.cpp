// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Manuel FLURY
//
// This file is part of DirAtlas — an LDAP Directory Explorer.
//
// Licensed under the GNU Affero General Public License v3.0
// (https://www.gnu.org/licenses/agpl-3.0.txt).
//
// Originally based on godap (github.com/Macmod/godap) — MIT license.

#include "colors.h"

namespace diratlas::adidns {

std::pair<std::string, bool> getPropCellColor(uint32_t propId, const std::string &cellValue) {
    if (cellValue == "Enabled") return {"green", true};
    if (cellValue == "Disabled" || cellValue == "None") return {"red", true};
    if (cellValue == "Unknown" || cellValue == "Not specified") return {"gray", true};

    if (propId == 0x00000001) {
        if (cellValue == "PRIMARY") return {"green", true};
        if (cellValue == "CACHE") return {"blue", true};
    }
    if (propId == 0x00000002) {
        if (cellValue == "None") return {"red", true};
        if (cellValue == "Nonsecure and secure") return {"yellow", true};
        if (cellValue == "Secure only") return {"green", true};
    }
    return {"", false};
}

} // namespace diratlas::adidns
