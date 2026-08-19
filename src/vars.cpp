// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Manuel FLURY
//
// This file is part of DirAtlas — an LDAP Directory Explorer.
//
// Licensed under the GNU Affero General Public License v3.0
// (https://www.gnu.org/licenses/agpl-3.0.txt).
//

#include "vars.h"

namespace diratlas {

const std::map<uint32_t, FlagDesc> UacFlags = {
    {UAC_SCRIPT,                         {"Script", ""}},
    {UAC_ACCOUNTDISABLE,                 {"Disabled", "Enabled"}},
    {UAC_HOMEDIR_REQUIRED,               {"HomeDirRequired", ""}},
    {UAC_LOCKOUT,                        {"LockedOut", ""}},
    {UAC_PASSWD_NOTREQD,                 {"PwdNotRequired", ""}},
    {UAC_PASSWD_CANT_CHANGE,             {"CannotChangePwd", ""}},
    {UAC_ENCRYPTED_TEXT_PWD_ALLOWED,     {"EncryptedTextPwdAllowed", ""}},
    {UAC_TEMP_DUPLICATE_ACCOUNT,         {"TmpDuplicateAccount", ""}},
    {UAC_NORMAL_ACCOUNT,                 {"NormalAccount", ""}},
    {UAC_INTERDOMAIN_TRUST_ACCOUNT,      {"InterdomainTrustAccount", ""}},
    {UAC_WORKSTATION_TRUST_ACCOUNT,      {"WorkstationTrustAccount", ""}},
    {UAC_SERVER_TRUST_ACCOUNT,           {"ServerTrustAccount", ""}},
    {UAC_DONT_EXPIRE_PASSWORD,           {"DoNotExpirePwd", ""}},
    {UAC_MNS_LOGON_ACCOUNT,              {"MNSLogonAccount", ""}},
    {UAC_SMARTCARD_REQUIRED,             {"SmartcardRequired", ""}},
    {UAC_TRUSTED_FOR_DELEGATION,         {"TrustedForDelegation", ""}},
    {UAC_NOT_DELEGATED,                  {"NotDelegated", ""}},
    {UAC_USE_DES_KEY_ONLY,               {"UseDESKeyOnly", ""}},
    {UAC_DONT_REQ_PREAUTH,               {"DoNotRequirePreauth", ""}},
    {UAC_PASSWORD_EXPIRED,               {"PwdExpired", "PwdNotExpired"}},
    {UAC_TRUSTED_TO_AUTH_FOR_DELEGATION, {"TrustedToAuthForDelegation", ""}},
    {UAC_PARTIAL_SECRETS_ACCOUNT,        {"PartialSecretsAccount", ""}},
};

const std::map<uint32_t, std::string> SystemFlags = {
    {0x00000001, "FLAG_ATTR_NOT_REPLICATED"},
    {0x00000002, "FLAG_ATTR_REQ_PARTIAL_SET_MEMBER"},
    {0x00000004, "FLAG_ATTR_IS_CONSTRUCTED"},
    {0x00000008, "FLAG_ATTR_IS_OPERATIONAL"},
    {0x00000010, "FLAG_SCHEMA_BASE_OBJECT"},
    {0x00000020, "FLAG_ATTR_IS_RDN"},
    {0x02000000, "FLAG_DISALLOW_MOVE_ON_DELETE"},
    {0x04000000, "FLAG_DOMAIN_DISALLOW_MOVE"},
    {0x08000000, "FLAG_DOMAIN_DISALLOW_RENAME"},
    {0x10000000, "FLAG_CONFIG_ALLOW_LIMITED_MOVE"},
    {0x20000000, "FLAG_CONFIG_ALLOW_MOVE"},
    {0x40000000, "FLAG_CONFIG_ALLOW_RENAME"},
    {0x80000000, "FLAG_DISALLOW_DELETE"},
};

const std::map<int, std::string> SDControlFlags = {
    {SE_DACL_AUTO_INHERIT_REQ, "SE_DACL_AUTO_INHERIT_REQ"},
    {SE_DACL_AUTO_INHERITED,   "SE_DACL_AUTO_INHERITED"},
    {SE_DACL_SACL_DEFAULTED,   "SE_DACL_SACL_DEFAULTED"},
    {SE_DACL_PRESENT,          "SE_DACL_PRESENT"},
    {SE_DACL_PROTECTED,        "SE_DACL_PROTECTED"},
    {SE_GROUP_DEFAULTED,       "SE_GROUP_DEFAULTED"},
    {SE_OWNER_DEFAULTED,       "SE_OWNER_DEFAULTED"},
    {SE_RM_CONTROL_VALID,      "SE_RM_CONTROL_VALID"},
    {SE_SACL_AUTO_INHERIT_REQ, "SE_SACL_AUTO_INHERIT_REQ"},
    {SE_SACL_AUTO_INHERITED,   "SE_SACL_AUTO_INHERITED"},
    {SE_SACL_PRESENT,          "SE_SACL_PRESENT"},
    {SE_SACL_PROTECTED,        "SE_SACL_PROTECTED"},
    {SE_SELF_RELATIVE,         "SE_SELF_RELATIVE"},
};

const std::map<int, std::string> RidMap = {
    {500, "Administrator"},
    {501, "Guest"},
    {502, "KRBTGT"},
    {512, "Domain Admins"},
    {513, "Domain Users"},
    {514, "Domain Guests"},
    {515, "Domain Computers"},
    {516, "Domain Controllers"},
    {517, "Cert Publishers"},
    {518, "Schema Admins"},
    {519, "Enterprise Admins"},
    {520, "Group Policy Creator Owners"},
    {526, "Key Admins"},
    {527, "Enterprise Key Admins"},
    {553, "RAS and IAS Servers"},
    {554, "Trusted for Delegation Computers"},
    {555, "Protected Users"},
    {572, "Cloneable Domain Controllers"},
    {573, "Read-only Domain Controllers"},
    {590, "Backup Operators"},
    {591, "Print Operators"},
    {592, "Server Operators"},
    {593, "Account Operators"},
    {594, "Replicator"},
    {596, "Incoming Forest Trust Builders"},
    {597, "Performance Monitor Users"},
    {598, "Performance Log Users"},
    {599, "Windows Authorization Access Group"},
    {600, "Network Configuration Operators"},
    {601, "Incoming Forest Trust Builders"},
    {606, "Cryptographic Operators"},
    {607, "Event Log Readers"},
};

const std::map<int, std::string> SAMAccountTypeMap = {
    {0x00000000, "Domain Object"},
    {0x10000000, "Group Object"},
    {0x10000001, "Non-Security Group Object"},
    {0x30000000, "User Object"},
    {0x30000001, "Machine Account"},
    {0x20000000, "Alias Object"},
    {0x20000001, "Non-Security Alias Object"},
    {0x30000002, "Trust Account"},
    {0x40000000, "App Basic Group"},
    {0x40000001, "App Query Group"},
};

const std::map<int, std::string> GroupTypeMap = {
    {2, "Global Distribution Group"},
    {4, "Domain Local Distribution Group"},
    {8, "Universal Distribution Group"},
    {-2147483646, "Global Security Group"},
    {-2147483644, "Domain Local Security Group"},
    {-2147483643, "Builtin Group"},
    {-2147483640, "Universal Security Group"},
};

const std::map<int, std::string> InstanceTypeMap = {
    {1,  "NamingContextHead"},
    {2,  "NotInstantiatedReplica"},
    {4,  "WritableObject"},
    {8,  "ParentNamingContextHeld"},
    {16, "FirstNamingContextConstruction"},
    {32, "NamingContextRemovalFromDSA"},
};

const std::map<uint32_t, std::string> TrustAttributeFlags = {
    {0x00000001, "NON_TRANSITIVE"},
    {0x00000002, "UPLEVEL_ONLY"},
    {0x00000004, "QUARANTINED_DOMAIN"},
    {0x00000008, "FOREST_TRANSITIVE"},
    {0x00000010, "CROSS_ORGANIZATION"},
    {0x00000020, "WITHIN_FOREST"},
    {0x00000040, "TREAT_AS_EXTERNAL"},
    {0x00000080, "USES_RC4_ENCRYPTION"},
    {0x00000200, "CROSS_ORGANIZATION_NO_TGT_DELEGATION"},
    {0x00000400, "PIM_TRUST"},
    {0x00000800, "CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION"},
};

const std::map<uint32_t, std::string> PwdPropertiesFlags = {
    {0x00000001, "PASSWORD_COMPLEX"},
    {0x00000002, "PASSWORD_NO_ANON_CHANGE"},
    {0x00000004, "PASSWORD_NO_CLEAR_CHANGE"},
    {0x00000008, "LOCKOUT_ADMINS"},
    {0x00000010, "PASSWORD_STORE_CLEARTEXT"},
    {0x00000020, "REFUSE_PASSWORD_CHANGE"},
};

const std::map<uint32_t, std::string> SearchFlagsMap = {
    {0x00000001, "fATTINDEX"},
    {0x00000002, "fPDNTATTINDEX"},
    {0x00000004, "fANR"},
    {0x00000008, "fPRESERVEONDELETE"},
    {0x00000010, "fCOPY"},
    {0x00000020, "fTUPLEINDEX"},
    {0x00000040, "fSUBTREEATTINDEX"},
    {0x00000080, "fCONFIDENTIAL"},
    {0x00000100, "fNEVERVALUEAUDIT"},
    {0x00000200, "fRODCFilteredAttribute"},
    {0x00000400, "fEXTENDEDLINKTRACKING"},
    {0x00000800, "fBASEONLY"},
    {0x00001000, "fPARTITIONSECRET"},
};

const std::map<std::string, std::string> EmojiMap = {
    {"root", "\U0001F333"},
    {"user", "\U0001F464"},
    {"computer", "\U0001F4BB"},
    {"group", "\U0001F465"},
    {"organizationalUnit", "\U0001F4C2"},
    {"container", "\U0001F4C1"},
    {"groupOfNames", "\U0001F4C7"},
    {"domain", "\U0001F310"},
    {"domainDNS", "\U0001F517"},
    {"builtinDomain", "\U0001F3E0"},
    {"groupPolicyContainer", "\u2699\uFE0F"},
    {"foreignSecurityPrincipal", "\U0001F30D"},
    {"contact", "\U0001F4DE"},
    {"printQueue", "\U0001F5A8\uFE0F"},
    {"volume", "\U0001F4E6"},
    {"publicFolder", "\U0001F4EC"},
    {"serviceConnectionPoint", "\U0001F50C"},
    {"msExchExchangeServer", "\U0001F4E7"},
    {"msExchStorageGroup", "\U0001F5C3\uFE0F"},
    {"subnet", "\U0001F578\uFE0F"},
    {"site", "\U0001F4CD"},
    {"groupOfUniqueNames", "\U0001F4C7"},
    {"device", "\U0001F4BB"},
    {"posixAccount", "\U0001F194"},
    {"organization", "\U0001F3E2"},
};

const std::map<std::string, std::string> WellKnownSIDsMap = {
    {"S-1-0-0",    "Null SID"},
    {"S-1-1-0",    "Everyone"},
    {"S-1-2-0",    "Local"},
    {"S-1-2-1",    "Console Logon"},
    {"S-1-3-0",    "Creator Owner ID"},
    {"S-1-3-1",    "Creator Group ID"},
    {"S-1-3-2",    "Creator Owner Server"},
    {"S-1-3-3",    "Creator Group Server"},
    {"S-1-3-4",    "Owner Rights"},
    {"S-1-4",      "Non-Unique Authority"},
    {"S-1-5",      "NT Authority"},
    {"S-1-5-80-0", "All Services"},
    {"S-1-5-1",    "Dialup"},
    {"S-1-5-113",  "Local Account"},
    {"S-1-5-114",  "Local account and member of Administrators group"},
    {"S-1-5-2",    "Network"},
    {"S-1-5-3",    "Batch"},
    {"S-1-5-4",    "Interactive"},
    {"S-1-5-6",    "Service"},
    {"S-1-5-7",    "Anonymous Logon"},
    {"S-1-5-8",    "Proxy"},
    {"S-1-5-9",    "Enterprise Domain Controllers"},
    {"S-1-5-10",   "Self"},
    {"S-1-5-11",   "Authenticated Users"},
    {"S-1-5-12",   "Restricted Code"},
    {"S-1-5-13",   "Terminal Server User"},
    {"S-1-5-14",   "Remote Interactive Logon"},
    {"S-1-5-15",   "This Organization"},
    {"S-1-5-17",   "IUSR"},
    {"S-1-5-18",   "SYSTEM"},
    {"S-1-5-19",   "NT Authority (LocalService)"},
    {"S-1-5-20",   "Network Service"},
};

const std::map<std::string, std::vector<LibQuery>> PredefinedQueriesAD = {
    {"Enum", {
        {"All Organizational Units", "(objectCategory=organizationalUnit)", ""},
        {"All Containers", "(objectCategory=container)", ""},
        {"All Groups", "(objectCategory=group)", ""},
        {"All Computers", "(objectClass=computer)", ""},
        {"All Users", "(&(objectCategory=person)(objectClass=user))", ""},
        {"All Objects", "(objectClass=*)", ""},
    }},
    {"Users", {
        {"Recently Created Users", "(&(objectCategory=user)(whenCreated>=<timestamp1d>))", ""},
        {"Users With Description", "(&(objectCategory=user)(description=*))", ""},
        {"Users Without Email", "(&(objectCategory=user)(!(mail=*)))", ""},
        {"Likely Service Users", "(&(objectCategory=user)(sAMAccountName=*svc*))", ""},
        {"Disabled Users", "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=2))", ""},
        {"Expired Users", "(&(objectCategory=user)(accountExpires<=<timestamp>))", ""},
        {"Inactive Users", "(&(objectCategory=user)(lastLogonTimestamp<=<timestamp30d>))", ""},
    }},
    {"Computers", {
        {"Domain Controllers", "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))", ""},
        {"Non-DC Servers", "(&(objectCategory=computer)(operatingSystem=*server*)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))", ""},
        {"Stale Computers", "(&(objectCategory=computer)(!lastLogonTimestamp=*))", ""},
    }},
    {"Security", {
        {"High Privilege Users", "(&(objectCategory=user)(adminCount=1))", ""},
        {"Users With SPN", "(&(objectCategory=user)(servicePrincipalName=*))", ""},
        {"Users With SIDHistory", "(&(objectCategory=person)(objectClass=user)(sidHistory=*))", ""},
        {"Unconstrained Delegation Objects", "(userAccountControl:1.2.840.113556.1.4.803:=524288)", ""},
        {"Shadow Credentials Targets", "(msDS-KeyCredentialLink=*)", ""},
        {"Never Expire Password Users", "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))", ""},
        {"LockedOut Users", "(&(objectCategory=user)(lockoutTime>=1))", ""},
        {"Trusted Domains", "(objectClass=trustedDomain)", ""},
    }},
    {"Group Members", {
        {"Enterprise Admins", "(memberOf=CN=Enterprise Admins,CN=Users,DC=domain,DC=com)", ""},
        {"Domain Admins", "(memberOf=CN=Domain Admins,CN=Users,DC=domain,DC=com)", ""},
        {"Schema Admins", "(memberOf=CN=Schema Admins,CN=Users,DC=domain,DC=com)", ""},
        {"Backup Operators", "(memberOf=CN=Backup Operators,CN=Builtin,DC=domain,DC=com)", ""},
        {"Server Operators", "(memberOf=CN=Server Operators,CN=Builtin,DC=domain,DC=com)", ""},
    }},
};

const std::map<std::string, std::vector<LibQuery>> PredefinedQueriesBasic = {
    {"Enum", {
        {"All Organizations", "(objectClass=organization)", ""},
        {"All Users", "(|(objectClass=inetOrgPerson)(objectClass=posixAccount)(objectClass=person))", ""},
        {"All Groups", "(|(objectClass=posixGroup)(objectClass=groupOfNames)(objectClass=groupOfUniqueNames))", ""},
        {"All Computers", "(|(objectClass=ipHost)(objectClass=device))", ""},
        {"All Organizational Units", "(objectClass=organizationalUnit)", ""},
        {"All Objects", "(objectClass=*)", ""},
    }},
    {"Users", {
        {"Users With Email", "(&(mail=*)(|(objectClass=inetOrgPerson)(objectClass=posixAccount)(objectClass=person)))", ""},
        {"Users With SSH Keys", "(sshPublicKey=*)", ""},
    }},
    {"Groups", {
        {"Groups With Members (groupOfNames)", "(&(objectClass=groupOfNames)(member=*))", ""},
        {"Groups With Members (posixGroup)", "(&(objectClass=posixGroup)(memberUid=*))", ""},
    }},
};

} // namespace diratlas
