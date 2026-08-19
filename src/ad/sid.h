// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Manuel FLURY
//
// Security Identifier (SID) handling for the Active Directory backend.
//
// A SID is a binary structure (MS-DTYP §2.4.2.1):
//   - revision (1 byte, currently 1)
//   - subAuthorityCount (1 byte)
//   - identifierAuthority (6 bytes, big-endian)
//   - subAuthorities (count × 4 bytes, little-endian)
//
// Its textual form (SDDL §2.4.2) is "S-<rev>-<authority>[-<sub>…]".
// Implemented independently from the wire layout, not from any other
// codebase.

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace diratlas::ad {

/// @brief Parse a raw binary SID and render its textual SDDL form.
/// Returns an empty optional when the buffer is too short (a valid SID
/// needs at least 8 bytes) or inconsistent (count too large for buffer).
std::optional<std::string> sidToText(const std::vector<uint8_t> &bytes);

} // namespace diratlas::ad