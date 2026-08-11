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
#include <chrono>

namespace diratlas::formats {

std::string getTimeDistString(std::chrono::seconds diff);

} // namespace diratlas::formats
