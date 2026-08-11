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
#include <cstdint>
#include <utility>

namespace diratlas::adidns {

std::pair<std::string, bool> getPropCellColor(uint32_t propId, const std::string &cellValue);

} // namespace diratlas::adidns
