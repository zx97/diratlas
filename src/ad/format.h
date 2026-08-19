// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Manuel FLURY
//
// Active Directory attribute formatting. Only meaningful when the
// connected directory is a Microsoft AD (see LDAPConn::guessFlavor);
// a plain LDAP server never has these attribute names with these
// semantics. Exposed through a single entry point so callers can gate
// the whole backend with one runtime check.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace diratlas::ad {

/// One displayable value: raw text + formatted rendering.
struct AdAttrValue {
    std::string raw;
    std::string formatted;
};

/// @brief True when the attribute name belongs to the AD vocabulary
/// (SID, GUID, UAC, NT timestamps, durations…).
bool isAdAttribute(const std::string &attrName);

/// @brief Format the values of an AD-specific attribute.
///
/// Implemented for: objectSid/securityIdentifier, objectGUID/
/// schemaIDGUID/attributeSecurityGUID, userAccountControl, systemFlags,
/// trustAttributes, pwdProperties, searchFlags, primaryGroupID,
/// sAMAccountType, groupType, instanceType, NT timestamps
/// (lastLogonTimestamp, pwdLastSet, …), 100ns durations, lockout
/// thresholds and raw binary blobs.
///
/// Unrecognized attributes yield their original value untouched.
std::vector<AdAttrValue> formatAdAttribute(
    const std::string &attrName,
    const std::vector<std::string> &values,
    const std::vector<std::vector<uint8_t>> &byteValues,
    const std::string &timeFormat,
    int timeOffsetHours);

/// @brief Convert a Windows FILETIME (100 ns since 1601-01-01 UTC,
/// MS-DTYP §2.3.3) to a Unix timestamp. Returns 0 for the sentinel
/// "never" values (0 and 0x7FFFFFFFFFFFFFFF).
int64_t ntTimestampToUnix(int64_t fileTime, bool &isNever);

/// @brief Convert a 100 ns interval (e.g. maxPwdAge) to seconds,
/// flipping the sign so a negative value becomes positive.
int64_t ntIntervalToSeconds(const std::string &raw);

} // namespace diratlas::ad