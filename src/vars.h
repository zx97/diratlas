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
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace diratlas {

// LDAP Flavors
enum class LDAPFlavor {
    MicrosoftAD,
    BasicLDAP
};

// userAccountControl flags
constexpr uint32_t UAC_SCRIPT                         = 0x00000001;
constexpr uint32_t UAC_ACCOUNTDISABLE                 = 0x00000002;
constexpr uint32_t UAC_HOMEDIR_REQUIRED               = 0x00000008;
constexpr uint32_t UAC_LOCKOUT                        = 0x00000010;
constexpr uint32_t UAC_PASSWD_NOTREQD                 = 0x00000020;
constexpr uint32_t UAC_PASSWD_CANT_CHANGE             = 0x00000040;
constexpr uint32_t UAC_ENCRYPTED_TEXT_PWD_ALLOWED     = 0x00000080;
constexpr uint32_t UAC_TEMP_DUPLICATE_ACCOUNT         = 0x00000100;
constexpr uint32_t UAC_NORMAL_ACCOUNT                 = 0x00000200;
constexpr uint32_t UAC_INTERDOMAIN_TRUST_ACCOUNT      = 0x00000800;
constexpr uint32_t UAC_WORKSTATION_TRUST_ACCOUNT      = 0x00001000;
constexpr uint32_t UAC_SERVER_TRUST_ACCOUNT           = 0x00002000;
constexpr uint32_t UAC_DONT_EXPIRE_PASSWORD           = 0x00010000;
constexpr uint32_t UAC_MNS_LOGON_ACCOUNT              = 0x00020000;
constexpr uint32_t UAC_SMARTCARD_REQUIRED             = 0x00040000;
constexpr uint32_t UAC_TRUSTED_FOR_DELEGATION         = 0x00080000;
constexpr uint32_t UAC_NOT_DELEGATED                  = 0x00100000;
constexpr uint32_t UAC_USE_DES_KEY_ONLY               = 0x00200000;
constexpr uint32_t UAC_DONT_REQ_PREAUTH               = 0x00400000;
constexpr uint32_t UAC_PASSWORD_EXPIRED               = 0x00800000;
constexpr uint32_t UAC_TRUSTED_TO_AUTH_FOR_DELEGATION = 0x01000000;
constexpr uint32_t UAC_PARTIAL_SECRETS_ACCOUNT        = 0x04000000;

// SD Control Flags
constexpr uint32_t SE_DACL_AUTO_INHERIT_REQ = 0x00000100;
constexpr uint32_t SE_DACL_AUTO_INHERITED   = 0x00000400;
constexpr uint32_t SE_DACL_SACL_DEFAULTED   = 0x00000008;
constexpr uint32_t SE_DACL_PRESENT          = 0x00000004;
constexpr uint32_t SE_DACL_PROTECTED        = 0x00001000;
constexpr uint32_t SE_GROUP_DEFAULTED       = 0x00000002;
constexpr uint32_t SE_OWNER_DEFAULTED       = 0x00000001;
constexpr uint32_t SE_RM_CONTROL_VALID      = 0x00004000;
constexpr uint32_t SE_SACL_AUTO_INHERIT_REQ = 0x00000200;
constexpr uint32_t SE_SACL_AUTO_INHERITED   = 0x00000800;
constexpr uint32_t SE_SACL_PRESENT          = 0x00000010;
constexpr uint32_t SE_SACL_PROTECTED        = 0x00002000;
constexpr uint32_t SE_SELF_RELATIVE         = 0x00008000;

struct FlagDesc {
    std::string present;
    std::string notPresent;
};

extern const std::map<uint32_t, FlagDesc> UacFlags;
extern const std::map<uint32_t, std::string> SystemFlags;
extern const std::map<int, std::string> SDControlFlags;
extern const std::map<int, std::string> RidMap;
extern const std::map<int, std::string> SAMAccountTypeMap;
extern const std::map<int, std::string> GroupTypeMap;
extern const std::map<int, std::string> InstanceTypeMap;
extern const std::map<uint32_t, std::string> TrustAttributeFlags;
extern const std::map<uint32_t, std::string> PwdPropertiesFlags;
extern const std::map<uint32_t, std::string> SearchFlagsMap;
extern const std::map<std::string, std::string> EmojiMap;
extern const std::map<std::string, std::string> WellKnownSIDsMap;

struct LibQuery {
    std::string title;
    std::string filter;
    std::string baseDN;
};

extern const std::map<std::string, std::vector<LibQuery>> PredefinedQueriesAD;
extern const std::map<std::string, std::vector<LibQuery>> PredefinedQueriesBasic;

} // namespace diratlas
