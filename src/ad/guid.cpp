// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Manuel FLURY

#include "guid.h"

namespace diratlas::ad {

std::optional<std::string> guidToText(const std::vector<uint8_t> &bytes) {
    if (bytes.size() != 16) return std::nullopt;
    static const size_t groupSizes[5] = {4, 2, 2, 2, 6};
    std::string out;
    size_t off = 0;
    for (size_t g = 0; g < 5; ++g) {
        if (g > 0) out += '-';
        for (size_t i = 0; i < groupSizes[g]; ++i, ++off)
            out += "0123456789abcdef"[(bytes[off] >> 4) & 0x0F],
            out += "0123456789abcdef"[bytes[off] & 0x0F];
    }
    return out;
}

} // namespace diratlas::ad