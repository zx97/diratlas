// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Manuel FLURY
//
// Generic LDAP attribute formatting. This module knows nothing about
// Active Directory: it implements the purely generic LDAP presentations
// (RFC 4517 syntaxes: GeneralizedTime, Duration, Integer, Boolean,
// octet-string) plus safe fallbacks for opaque binary attributes.
//
// Backend-specific formatting (SID, GUID, UAC, security descriptors…)
// lives in the optional `ad` module and is only activated when the
// server flavour is detected as Microsoft Active Directory.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace diratlas::ldapcore {

/// One displayable value: original raw text plus a human-friendly form.
struct AttrValue {
    std::string raw;       ///< Original value as returned by the server
    std::string formatted; ///< Formatted for display
};

/// @brief Format the values of a single LDAP attribute generically.
///
/// Rules applied:
///  - GeneralizedTime (RFC 4517 §3.3.13): parsed with @p timeFormat.
///  - Durations in seconds (Integer syntax): rendered as human readable.
///  - Binary values that are not printable are shown as HEX{...}.
///  - Otherwise the original value is kept.
///
/// @param attrName   Attribute name (lower-cased by the caller for matches).
/// @param values     Text values from the server.
/// @param byteValues Raw binary values aligned by index with @p values.
/// @param timeFormat strftime-style format for GeneralizedTime.
std::vector<AttrValue> formatAttribute(
    const std::string &attrName,
    const std::vector<std::string> &values,
    const std::vector<std::vector<uint8_t>> &byteValues,
    const std::string &timeFormat = "%Y-%m-%d %H:%M:%S");

/// @brief Parse a GeneralizedTime string (YYYYMMDDHHMMSS[.fff][Z|±HHMM])
/// to a Unix timestamp. Returns 0 when unparseable.
int64_t parseGeneralizedTime(const std::string &val);

/// @brief Render a Unix timestamp using a strftime format.
std::string formatTimestamp(int64_t unixTime, const std::string &format,
                            int offsetHours = 0);

/// @brief Humanize a duration in seconds ("2 days 3 hours 4 minutes").
std::string formatDuration(int64_t seconds);

} // namespace diratlas::ldapcore