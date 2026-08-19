// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Manuel FLURY
//
// GUID / UUID handling. The on-wire layout is the one defined by
// RFC 4122 (§4.1.2 "Layout and byte order"): time_low (4 bytes LE),
// time_mid (2 bytes LE), time_hi_and_version (2 bytes LE), then
// clock_seq and node as raw bytes. The textual form follows RFC 4122
// §3 ("xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx").

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace diratlas::ad {

/// @brief Format a 16-byte binary GUID into its canonical textual form.
/// Returns an empty optional when the buffer length is not 16.
std::optional<std::string> guidToText(const std::vector<uint8_t> &bytes);

} // namespace diratlas::ad