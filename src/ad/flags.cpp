// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Manuel FLURY

#include "flags.h"

#include <map>

namespace diratlas::ad {

std::string ridToLabel(uint32_t rid) {
    static const std::map<uint32_t, std::string> table = {
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
        {606, "Cryptographic Operators"},
        {607, "Event Log Readers"},
    };
    auto it = table.find(rid);
    return it == table.end() ? std::string() : it->second;
}

std::vector<std::string> expandBitmask(
    uint32_t value, const std::vector<std::pair<uint32_t, std::string>> &table) {
    std::vector<std::string> out;
    for (const auto &[bit, label] : table) {
        if (value & bit) out.push_back(label);
    }
    return out;
}

std::vector<std::string> describeUserAccountControl(uint32_t uac) {
    static const std::vector<std::pair<uint32_t, std::string>> table = {
        {0x00000001, "Script"},
        {0x00000002, "Disabled"},
        {0x00000008, "HomeDirRequired"},
        {0x00000010, "LockedOut"},
        {0x00000020, "PwdNotRequired"},
        {0x00000040, "CannotChangePwd"},
        {0x00000080, "EncryptedTextPwdAllowed"},
        {0x00000100, "TmpDuplicateAccount"},
        {0x00000200, "NormalAccount"},
        {0x00000800, "InterdomainTrustAccount"},
        {0x00001000, "WorkstationTrustAccount"},
        {0x00002000, "ServerTrustAccount"},
        {0x00010000, "DoNotExpirePwd"},
        {0x00020000, "MNSLogonAccount"},
        {0x00040000, "SmartcardRequired"},
        {0x00080000, "TrustedForDelegation"},
        {0x00100000, "NotDelegated"},
        {0x00200000, "UseDESKeyOnly"},
        {0x00400000, "DoNotRequirePreauth"},
        {0x00800000, "PwdExpired"},
        {0x01000000, "TrustedToAuthForDelegation"},
        {0x04000000, "PartialSecretsAccount"},
    };
    return expandBitmask(uac, table);
}

} // namespace diratlas::ad