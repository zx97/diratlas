// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Manuel FLURY

#include "sid.h"

#include "../ldapcore/bytes.h"

namespace diratlas::ad {

std::optional<std::string> sidToText(const std::vector<uint8_t> &bytes) {
    if (bytes.size() < 8) return std::nullopt;
    const uint8_t revision = bytes[0];
    const uint8_t count = bytes[1];
    const size_t expected = 8 + static_cast<size_t>(count) * 4;
    if (bytes.size() < expected) return std::nullopt;

    // Identifier authority: 6 bytes, big-endian.
    uint64_t authority = 0;
    for (size_t i = 0; i < 6; ++i)
        authority = (authority << 8) | bytes[2 + i];

    std::string out = "S-" + std::to_string(revision) + "-" + std::to_string(authority);
    for (uint8_t i = 0; i < count; ++i) {
        size_t off = 8 + static_cast<size_t>(i) * 4;
        out += "-" + std::to_string(ldapcore::readLE32(bytes, off));
    }
    return out;
}

} // namespace diratlas::ad