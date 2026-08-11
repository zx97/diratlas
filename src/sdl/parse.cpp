// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Manuel FLURY
//
// This file is part of DirAtlas — an LDAP Directory Explorer.
//
// Licensed under the GNU Affero General Public License v3.0
// (https://www.gnu.org/licenses/agpl-3.0.txt).
//
// Originally based on godap (github.com/Macmod/godap) — MIT license.

#include "parse.h"
#include <cstdint>
#include <sstream>
#include <iomanip>
#include <cstring>

namespace diratlas::sdl {

static uint8_t hexCharToByte(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}

static std::vector<uint8_t> hexToBytes(const std::string &hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i + 1 < hex.length(); i += 2) {
        bytes.push_back((hexCharToByte(hex[i]) << 4) | hexCharToByte(hex[i+1]));
    }
    return bytes;
}

static std::string bytesToHex(const std::vector<uint8_t> &bytes) {
    static const char *hex = "0123456789ABCDEF";
    std::string result;
    for (auto b : bytes) {
        result += hex[(b >> 4) & 0xF];
        result += hex[b & 0xF];
    }
    return result;
}

static std::string toString(const std::vector<uint8_t> &bytes) {
    return std::string(bytes.begin(), bytes.end());
}

static std::string fmtHex(uint32_t v) {
    char buf[16];
    snprintf(buf, sizeof(buf), "0x%08X", v);
    return buf;
}

static std::string fmtHex2(uint16_t v) {
    char buf[16];
    snprintf(buf, sizeof(buf), "0x%04X", v);
    return buf;
}

static std::string fmtDec(uint32_t v) {
    return std::to_string(v);
}

static uint32_t read32(const std::vector<uint8_t> &bytes, size_t off) {
    uint32_t v;
    memcpy(&v, &bytes[off], 4);
    return v;
}

static uint16_t read16(const std::vector<uint8_t> &bytes, size_t off) {
    uint16_t v;
    memcpy(&v, &bytes[off], 2);
    return v;
}

static uint8_t read8(const std::vector<uint8_t> &bytes, size_t off) {
    return bytes[off];
}

// Convert SID bytes to S-1-5-... string
static std::string parseSID(const std::vector<uint8_t> &sidBytes) {
    if (sidBytes.size() < 8) return "";
    
    std::string sid = "S-" + std::to_string(sidBytes[0]);
    sid += "-" + std::to_string(read32(sidBytes, 2)); // Actually 6 bytes, but simplified
    
    // Proper handling: revision(1) + numAuth(1) + authority(6) + subAuths
    uint8_t numAuth = sidBytes[1];
    // Authority is big-endian 6 bytes at offset 2
    uint64_t authority = 0;
    for (int i = 0; i < 6; i++) {
        authority = (authority << 8) | sidBytes[2 + i];
    }
    sid = "S-" + std::to_string(sidBytes[0]) + "-" + std::to_string(authority);
    
    size_t off = 8;
    for (uint8_t i = 0; i < numAuth && off + 4 <= sidBytes.size(); i++) {
        sid += "-" + std::to_string(read32(sidBytes, off));
        off += 4;
    }
    return sid;
}

static ACL parseACL(const std::vector<uint8_t> &bytes, size_t offset) {
    ACL acl;
    if (offset + 8 > bytes.size()) return acl;

    uint8_t revision = read8(bytes, offset);
    uint8_t sbz1 = read8(bytes, offset + 1);
    uint16_t aclSize = read16(bytes, offset + 2);
    uint16_t aceCount = read16(bytes, offset + 4);
    uint16_t sbz2 = read16(bytes, offset + 6);

    acl.header.revision = fmtDec(revision);
    acl.header.sbz1 = fmtDec(sbz1);
    acl.header.aclSize = fmtDec(aclSize);
    acl.header.aceCount = fmtDec(aceCount);
    acl.header.sbz2 = fmtDec(sbz2);

    size_t aceOffset = offset + 8;
    for (uint16_t i = 0; i < aceCount && aceOffset + 4 <= bytes.size(); i++) {
        uint8_t aceType = read8(bytes, aceOffset);
        uint8_t aceFlags = read8(bytes, aceOffset + 1);
        uint16_t aceSize = read16(bytes, aceOffset + 2);
        
        if (aceSize < 4) break;
        if (aceOffset + aceSize > bytes.size()) break;

        auto aceBytes = std::vector<uint8_t>(bytes.begin() + aceOffset, bytes.begin() + aceOffset + aceSize);
        acl.aces.push_back(bytesToHex(aceBytes));
        aceOffset += aceSize;
    }

    return acl;
}

SecurityDescriptor newSD(const std::string &hexString) {
    SecurityDescriptor sd;
    auto bytes = hexToBytes(hexString);
    if (bytes.size() < 20) return sd;

    // Parse header (20 bytes)
    uint8_t revision = read8(bytes, 0);
    uint8_t sbz1 = read8(bytes, 1);
    uint16_t control = read16(bytes, 2);
    uint32_t offsetOwner = read32(bytes, 4);
    uint32_t offsetGroup = read32(bytes, 8);
    uint32_t offsetSacl = read32(bytes, 12);
    uint32_t offsetDacl = read32(bytes, 16);

    sd.header.revision = fmtDec(revision);
    sd.header.sbz1 = fmtDec(sbz1);
    sd.header.control = fmtHex2(control);
    sd.header.offsetOwner = fmtDec(offsetOwner);
    sd.header.offsetGroup = fmtDec(offsetGroup);
    sd.header.offsetSacl = fmtDec(offsetSacl);
    sd.header.offsetDacl = fmtDec(offsetDacl);

    // Parse Owner SID
    if (offsetOwner > 0 && offsetOwner < bytes.size()) {
        uint8_t sidLen = bytes[offsetOwner + 1] * 4 + 8; // 8 + numSubAuths*4
        if (offsetOwner + sidLen <= bytes.size()) {
            auto sidBytes = std::vector<uint8_t>(bytes.begin() + offsetOwner, bytes.begin() + offsetOwner + sidLen);
            sd.owner = parseSID(sidBytes);
        }
    }

    // Parse Group SID
    if (offsetGroup > 0 && offsetGroup < bytes.size()) {
        uint8_t sidLen = bytes[offsetGroup + 1] * 4 + 8;
        if (offsetGroup + sidLen <= bytes.size()) {
            auto sidBytes = std::vector<uint8_t>(bytes.begin() + offsetGroup, bytes.begin() + offsetGroup + sidLen);
            sd.group = parseSID(sidBytes);
        }
    }

    // Parse SACL
    if (offsetSacl > 0 && offsetSacl < bytes.size()) {
        sd.sacl = parseACL(bytes, offsetSacl);
    }

    // Parse DACL
    if (offsetDacl > 0 && offsetDacl < bytes.size()) {
        sd.dacl = parseACL(bytes, offsetDacl);
    }

    return sd;
}

} // namespace diratlas::sdl
