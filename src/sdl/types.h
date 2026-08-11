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
#include <vector>
#include <map>
#include <memory>
#include <cstdint>

namespace diratlas::sdl {

struct ACEHEADER {
    std::string aceType;
    std::string aceFlags;
    std::string aceSizeBytes;
};

struct BASIC_ACE {
    ACEHEADER header;
    std::string mask;
    std::string sid;
};

struct OBJECT_ACE {
    BASIC_ACE base;
    std::string flags;
    std::string objectType;
    std::string inheritedObjectType;
};

struct NOTIMPL_ACE {
    BASIC_ACE base;
    std::string rawHex;
};

struct ACLHEADER {
    std::string revision;
    std::string sbz1;
    std::string aclSize;
    std::string aceCount;
    std::string sbz2;
};

struct ACL {
    ACLHEADER header;
    std::vector<std::string> aces; // hex-encoded ACE strings
};

struct HEADER {
    std::string revision;
    std::string sbz1;
    std::string control;
    std::string offsetOwner;
    std::string offsetGroup;
    std::string offsetSacl;
    std::string offsetDacl;
};

struct SecurityDescriptor {
    HEADER header;
    ACL sacl;
    ACL dacl;
    std::string owner;
    std::string group;
};

SecurityDescriptor parseSD(const std::string &hexSD);

// ACE parsing helpers
std::string aceMaskToText(uint32_t mask, const std::string &guid = "");
std::string aceFlagsToText(uint8_t flags, const std::string &inheritedGuid = "");

// GUID maps
extern const std::map<std::string, std::string> AttributeGuids;
extern const std::map<std::string, std::string> ClassGuids;
extern const std::map<std::string, std::string> ExtendedGuids;
extern const std::map<std::string, std::string> ValidatedWriteGuids;
extern const std::map<std::string, std::string> PropertySetGuids;

// Access rights
extern const std::map<uint32_t, std::string> AccessRightsMap;

// ACE type and flag maps
extern const std::map<uint8_t, std::string> AceTypeMap;
extern const std::map<uint8_t, std::string> AceFlagsMap;

} // namespace diratlas::sdl
