// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Manuel FLURY
//
// Low-level byte helpers used by the LDAP core and optional backends.
// Implemented independently from the wire formats documented in the
// relevant public specifications (RFC 4510+ for LDAP, MS-DTYP/MS-ADTS
// for the Windows backends).

#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace diratlas::ldapcore {

/// @brief Encode raw bytes as a hexadecimal string.
/// @param upper Use uppercase A-F when true (default).
std::string bytesToHex(const std::vector<uint8_t> &bytes, bool upper = true);

/// @brief Little-endian reader (x86/native wire order for binary LDAP attrs).
uint32_t readLE32(const std::vector<uint8_t> &b, size_t off);

/// @brief Return true if the byte range is a printable UTF-8-ish value
/// (no control bytes). Used to decide hex display for opaque attributes.
bool isPrintable(const std::vector<uint8_t> &b);

/// @brief Parse a decimal integer from a string without throwing.
/// @return The parsed value, or @p fallback on any conversion error.
int64_t strToInt(std::string_view s, int64_t fallback = 0);

/// @brief Parse an unsigned decimal integer from a string without throwing.
uint64_t strToUInt(std::string_view s, uint64_t fallback = 0);

/// @brief Encode a byte string as base64 (RFC 4648).
std::string base64Encode(const std::string &data);

/// @brief Decode a base64 string (RFC 4648). Whitespace is ignored.
/// @return The decoded bytes, or empty on any invalid character/padding.
std::string base64Decode(const std::string &data);

/// @brief Return true if @p v can be written as a plain LDIF safe-string
/// (RFC 2849 §5.1): printable ASCII, no leading space/colon, no trailing
/// space. Anything else (binary, control bytes, non-ASCII, empty) must be
/// base64-encoded (value written with the "::" form).
bool ldifSafeValue(const std::string &v);

} // namespace diratlas::ldapcore