// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Manuel FLURY
//
// This file is part of DirAtlas — an LDAP Directory Explorer.
//
// Licensed under the GNU Affero General Public License v3.0
// (https://www.gnu.org/licenses/agpl-3.0.txt).
//
// Originally based on godap (github.com/Macmod/godap) — MIT license.

#include "types.h"

namespace diratlas::sdl {

const std::map<uint32_t, std::string> AccessRightsMap = {
    {0x00000001, "Create Child"},
    {0x00000002, "Delete Child"},
    {0x00000004, "List Contents"},
    {0x00000008, "Write Self"},
    {0x00000010, "Read Property"},
    {0x00000020, "Write Property"},
    {0x00000040, "Delete Tree"},
    {0x00000080, "List Object"},
    {0x00000100, "Control Access"},
    {0x00010000, "Delete"},
    {0x00020000, "Read Control"},
    {0x00040000, "Write DACL"},
    {0x00080000, "Write Owner"},
    {0xF0000000, "Generic Read"},
    {0xF0000001, "Synchronize"},
    {0x00000000, "Full Control"},
    {0x00030000, "Read/Write Property"},
};

const std::map<uint8_t, std::string> AceTypeMap = {
    {0x00, "ACCESS_ALLOWED_ACE_TYPE"},
    {0x01, "ACCESS_DENIED_ACE_TYPE"},
    {0x02, "SYSTEM_AUDIT_ACE_TYPE"},
    {0x03, "SYSTEM_ALARM_ACE_TYPE"},
    {0x04, "ACCESS_ALLOWED_COMPOUND_ACE_TYPE"},
    {0x05, "ACCESS_ALLOWED_OBJECT_ACE_TYPE"},
    {0x06, "ACCESS_DENIED_OBJECT_ACE_TYPE"},
    {0x07, "SYSTEM_AUDIT_OBJECT_ACE_TYPE"},
    {0x08, "SYSTEM_ALARM_OBJECT_ACE_TYPE"},
    {0x09, "ACCESS_ALLOWED_CALLBACK_ACE_TYPE"},
    {0x0A, "ACCESS_DENIED_CALLBACK_ACE_TYPE"},
    {0x0B, "ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE"},
    {0x0C, "ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE"},
    {0x0D, "SYSTEM_AUDIT_CALLBACK_ACE_TYPE"},
    {0x0E, "SYSTEM_ALARM_CALLBACK_ACE_TYPE"},
    {0x0F, "SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE"},
    {0x10, "SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE"},
    {0x11, "SYSTEM_MANDATORY_LABEL_ACE_TYPE"},
    {0x12, "SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE"},
    {0x13, "SYSTEM_SCOPED_POLICY_ID_ACE_TYPE"},
};

const std::map<uint8_t, std::string> AceFlagsMap = {
    {0x01, "OBJECT_INHERIT_ACE"},
    {0x02, "CONTAINER_INHERIT_ACE"},
    {0x04, "NO_PROPAGATE_INHERIT_ACE"},
    {0x08, "INHERIT_ONLY_ACE"},
    {0x10, "INHERITED_ACE"},
    {0x40, "FAILED_ACCESS_ACE_FLAG"},
    {0x80, "SUCCESSFUL_ACCESS_ACE_FLAG"},
};

const std::map<std::string, std::string> AttributeGuids = {};
const std::map<std::string, std::string> ClassGuids = {};
const std::map<std::string, std::string> ExtendedGuids = {};
const std::map<std::string, std::string> ValidatedWriteGuids = {};
const std::map<std::string, std::string> PropertySetGuids = {};

std::string aceMaskToText(uint32_t mask, const std::string &guid) {
    if (mask == 0x1F01FF || mask == 0xFFFFFFFF) return "Full Control";

    std::vector<std::string> rights;

    // Standard rights
    if (mask & 0x00000001) rights.push_back("Create Child");
    if (mask & 0x00000002) rights.push_back("Delete Child");
    if (mask & 0x00000004) rights.push_back("List Contents");
    if (mask & 0x00000008) rights.push_back("Write Self");
    if (mask & 0x00000010) rights.push_back("Read Property");
    if (mask & 0x00000020) rights.push_back("Write Property");
    if (mask & 0x00000040) rights.push_back("Delete Tree");
    if (mask & 0x00000080) rights.push_back("List Object");
    if (mask & 0x00000100) rights.push_back("Control Access");
    if (mask & 0x00010000) rights.push_back("Delete");
    if (mask & 0x00020000) rights.push_back("Read Control");
    if (mask & 0x00040000) rights.push_back("Write DACL");
    if (mask & 0x00080000) rights.push_back("Write Owner");

    if (rights.empty()) rights.push_back("Unknown (" + std::to_string(mask) + ")");
    
    std::string result;
    for (size_t i = 0; i < rights.size(); i++) {
        if (i > 0) result += ", ";
        result += rights[i];
    }
    return result;
}

std::string aceFlagsToText(uint8_t flags, const std::string &inheritedGuid) {
    if (flags == 0) return "This object only";

    std::vector<std::string> scopes;
    if (flags & 0x01) scopes.push_back("Object inherit");
    if (flags & 0x02) scopes.push_back("Container inherit");
    if (flags & 0x04) scopes.push_back("No propagate");
    if (flags & 0x08) scopes.push_back("Inherit only");
    if (flags & 0x10) scopes.push_back("Inherited");

    std::string result;
    for (size_t i = 0; i < scopes.size(); i++) {
        if (i > 0) result += ", ";
        result += scopes[i];
    }
    return result;
}

} // namespace diratlas::sdl
