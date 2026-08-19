// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Manuel FLURY
//
// Factual constants of the Active Directory/LDAP-over-AD attribute
// vocabulary. These values are defined by the public Microsoft
// specifications (MS-ADTS userAccountControl/groupType/searchFlags,
// MS-DTYP SECURITY_DESCRIPTOR control flags, MS-SAMR SAM account
// types) and by RFC 4122 for UUIDs.
//
// This module is only active when the connected server is detected as
// Microsoft Active Directory (see diratlas::LDAPConn::guessFlavor).
// Generic LDAP servers never consult these tables.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace diratlas::ad {

/// userAccountControl flags (MS-ADTS §2.2.16 USER_ACCOUNT_CONTROL).
enum class UserAccountControl : uint32_t {
    Script = 0x00000001,
    AccountDisabled = 0x00000002,
    HomeDirRequired = 0x00000008,
    Lockout = 0x00000010,
    PasswordNotRequired = 0x00000020,
    PasswordCantChange = 0x00000040,
    EncryptedTextPasswordAllowed = 0x00000080,
    TempDuplicateAccount = 0x00000100,
    NormalAccount = 0x00000200,
    InterdomainTrustAccount = 0x00000800,
    WorkstationTrustAccount = 0x00001000,
    ServerTrustAccount = 0x00002000,
    DontExpirePassword = 0x00010000,
    MnsLogonAccount = 0x00020000,
    SmartcardRequired = 0x00040000,
    TrustedForDelegation = 0x00080000,
    NotDelegated = 0x00100000,
    UseDesKeyOnly = 0x00200000,
    DontRequirePreauth = 0x00400000,
    PasswordExpired = 0x00800000,
    TrustedToAuthForDelegation = 0x01000000,
    PartialSecretsAccount = 0x04000000,
};

/// SECURITY_DESCRIPTOR control flags (MS-DTYP §2.4.4 SECURITY_DESCRIPTOR).
enum class SdControl : uint32_t {
    OwnerDefaulted = 0x00000001,
    GroupDefaulted = 0x00000002,
    SaclPresent = 0x00000010,
    DaclPresent = 0x00000004,
    DaclAutoInheritReq = 0x00000100,
    DaclAutoInherited = 0x00000400,
    DaclProtected = 0x00001000,
    SaclAutoInheritReq = 0x00000200,
    SaclAutoInherited = 0x00000800,
    SaclProtected = 0x00002000,
    RmControlValid = 0x00004000,
    SelfRelative = 0x00008000,
};

/// sAMAccountType values (MS-SAMR §2.2.1.12).
enum class SamAccountType : uint32_t {
    DomainObject = 0x00000000,
    GroupObject = 0x10000000,
    NonSecurityGroup = 0x10000001,
    AliasObject = 0x20000000,
    NonSecurityAlias = 0x20000001,
    UserObject = 0x30000000,
    MachineAccount = 0x30000001,
    TrustAccount = 0x30000002,
    AppBasicGroup = 0x40000000,
    AppQueryGroup = 0x40000001,
};

/// groupType values (MS-ADTS §2.2.14).
enum class GroupType : uint32_t {
    GlobalDistribution = 0x00000002,
    DomainLocalDistribution = 0x00000004,
    UniversalDistribution = 0x00000008,
    GlobalSecurity = 0x80000002,
    DomainLocalSecurity = 0x80000004,
    Builtin = 0x80000005,
    UniversalSecurity = 0x80000008,
};

/// systemFlags / searchFlags common values (MS-ADTS schema attribute).
enum class SchemaFlag : uint32_t {
    AttrNotReplicated = 0x00000001,
    AttrReqPartialSetMember = 0x00000002,
    AttrIsConstructed = 0x00000004,
    AttrIsOperational = 0x00000008,
    SchemaBaseObject = 0x00000010,
    AttrIsRdn = 0x00000020,
    DisallowMoveOnDelete = 0x02000000,
    DomainDisallowMove = 0x04000000,
    DomainDisallowRename = 0x08000000,
    ConfigAllowLimitedMove = 0x10000000,
    ConfigAllowMove = 0x20000000,
    ConfigAllowRename = 0x40000000,
    DisallowDelete = 0x80000000,
};

/// trustAttributes (MS-ADTS §2.2.44 TRUSTED_DOMAIN_INFORMATION_EX).
enum class TrustAttribute : uint32_t {
    NonTransitive = 0x00000001,
    UplevelOnly = 0x00000002,
    QuarantinedDomain = 0x00000004,
    ForestTransitive = 0x00000008,
    CrossOrganization = 0x00000010,
    WithinForest = 0x00000020,
    TreatAsExternal = 0x00000040,
    UsesRc4Encryption = 0x00000080,
    CrossOrganizationNoTgtDelegation = 0x00000200,
    PimTrust = 0x00000400,
};

/// pwdProperties (MS-ADTS §2.2.9).
enum class PwdProperty : uint32_t {
    Complex = 0x00000001,
    NoAnonChange = 0x00000002,
    NoClearChange = 0x00000004,
    LockoutAdmins = 0x00000008,
    StoreClearText = 0x00000010,
    RefusePasswordChange = 0x00000020,
};

/// Search flags of the AD schema attribute (fATTINDEX bit 0 → bit 12).
enum class SearchFlag : uint32_t {
    AttIndex = 0x00000001,
    PdntAttIndex = 0x00000002,
    Anr = 0x00000004,
    PreserveOnDelete = 0x00000008,
    Copy = 0x00000010,
    TupleIndex = 0x00000020,
    SubtreeAttIndex = 0x00000040,
    Confidential = 0x00000080,
    NeverValueAudit = 0x00000100,
    RodcFilteredAttribute = 0x00000200,
    ExtendedLinkTracking = 0x00000400,
    BaseOnly = 0x00000800,
    PartitionSecret = 0x00001000,
};

/// Well-known RIDs under the domain SID (MS-DTYP §2.4.2.4 / MS-SAMR).
/// Returns a human-readable label or an empty string when unknown.
std::string ridToLabel(uint32_t rid);

/// @brief Expand a userAccountControl integer into a list of readable
/// flag descriptions ("Disabled", "NormalAccount", …).
std::vector<std::string> describeUserAccountControl(uint32_t uac);

/// @brief Expand an OR-ed bitmask against a table of {bit, label}.
std::vector<std::string> expandBitmask(uint32_t value,
                                       const std::vector<std::pair<uint32_t, std::string>> &table);

} // namespace diratlas::ad