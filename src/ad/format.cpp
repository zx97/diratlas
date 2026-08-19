// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Manuel FLURY

#include "format.h"

#include "../ldapcore/attrs.h"
#include "../ldapcore/bytes.h"
#include "flags.h"
#include "guid.h"
#include "sid.h"

#include <set>

namespace diratlas::ad {

namespace {

// NT timestamps: 100 ns ticks since 1601-01-01 UTC. Unix epoch offset:
// 11644473600 seconds between 1601-01-01 and 1970-01-01.
constexpr int64_t kUnixEpochOffsetSec = 11644473600LL;
constexpr int64_t kTicksPerSecond = 10000000LL;
constexpr int64_t kNeverHigh = INT64_MAX; // 0x7FFFFFFFFFFFFFFF

const std::set<std::string> &ntTimestampAttrs() {
    static const std::set<std::string> s = {
        "lastlogontimestamp", "accountexpires", "badpasswordtime",
        "lastlogoff", "lastlogon", "pwdlastset", "creationtime",
        "lockouttime", "msds-azureadpasswordexpirytime",
    };
    return s;
}

const std::set<std::string> &ntIntervalAttrs() {
    static const std::set<std::string> s = {
        "msds-maximumpasswordage", "msds-minimumpasswordage",
        "msds-lockoutduration", "msds-lockoutobservationwindow",
        "lockoutduration", "lockoutobservationwindow", "maxpwdage",
        "minpwdage", "forcelogoff", "msds-usertgtlifetime",
        "msds-computertgtlifetime", "msds-servicetgtlifetime",
    };
    return s;
}

} // namespace

bool isAdAttribute(const std::string &attrName) {
    static const std::set<std::string> names = {
        "objectsid", "securityidentifier", "objectguid",
        "schemaidguid", "attributesecurityguid", "useraccountcontrol",
        "systemflags", "trustattributes", "pwdproperties", "searchflags",
        "primarygroupid", "samaccounttype", "grouptype", "instancetype",
        "logonhours", "dsasignature", "omobjectclass", "cacertificate",
        "lockoutthreshold", "msds-lockoutthreshold", "minpwdlength",
        "msds-minimumpasswordlength",
    };
    if (names.count(attrName)) return true;
    if (ntTimestampAttrs().count(attrName)) return true;
    if (ntIntervalAttrs().count(attrName)) return true;
    return false;
}

int64_t ntTimestampToUnix(int64_t fileTime, bool &isNever) {
    isNever = (fileTime == 0 || fileTime == kNeverHigh);
    if (isNever) return 0;
    return (fileTime - kUnixEpochOffsetSec * kTicksPerSecond) / kTicksPerSecond;
}

int64_t ntIntervalToSeconds(const std::string &raw) {
    int64_t v = ldapcore::strToInt(raw, 0);
    if (v < 0) v = -v;
    return v / kTicksPerSecond;
}

std::vector<AdAttrValue> formatAdAttribute(
    const std::string &attrName,
    const std::vector<std::string> &values,
    const std::vector<std::vector<uint8_t>> &byteValues,
    const std::string &timeFormat,
    int timeOffsetHours) {
    std::vector<AdAttrValue> result;
    if (values.empty()) {
        result.push_back({"(Empty)", "(Empty)"});
        return result;
    }

    // Bitset attributes expand into one row per flag.
    if (attrName == "useraccountcontrol") {
        int64_t v = ldapcore::strToInt(values[0], 0);
        for (const auto &label : describeUserAccountControl(static_cast<uint32_t>(v)))
            result.push_back({values[0], label});
        return result;
    }
    if (attrName == "systemflags") {
        static const std::vector<std::pair<uint32_t, std::string>> table = {
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
        uint32_t v = static_cast<uint32_t>(ldapcore::strToUInt(values[0], 0));
        for (const auto &label : expandBitmask(v, table))
            result.push_back({values[0], label});
        return result;
    }
    if (attrName == "trustattributes") {
        static const std::vector<std::pair<uint32_t, std::string>> table = {
            {0x00000001, "NON_TRANSITIVE"}, {0x00000002, "UPLEVEL_ONLY"},
            {0x00000004, "QUARANTINED_DOMAIN"}, {0x00000008, "FOREST_TRANSITIVE"},
            {0x00000010, "CROSS_ORGANIZATION"}, {0x00000020, "WITHIN_FOREST"},
            {0x00000040, "TREAT_AS_EXTERNAL"}, {0x00000080, "USES_RC4_ENCRYPTION"},
            {0x00000200, "CROSS_ORGANIZATION_NO_TGT_DELEGATION"},
            {0x00000400, "PIM_TRUST"},
            {0x00000800, "CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION"},
        };
        uint32_t v = static_cast<uint32_t>(ldapcore::strToUInt(values[0], 0));
        for (const auto &label : expandBitmask(v, table))
            result.push_back({values[0], label});
        return result;
    }
    if (attrName == "pwdproperties") {
        static const std::vector<std::pair<uint32_t, std::string>> table = {
            {0x00000001, "PASSWORD_COMPLEX"}, {0x00000002, "PASSWORD_NO_ANON_CHANGE"},
            {0x00000004, "PASSWORD_NO_CLEAR_CHANGE"}, {0x00000008, "LOCKOUT_ADMINS"},
            {0x00000010, "PASSWORD_STORE_CLEARTEXT"}, {0x00000020, "REFUSE_PASSWORD_CHANGE"},
        };
        uint32_t v = static_cast<uint32_t>(ldapcore::strToUInt(values[0], 0));
        for (const auto &label : expandBitmask(v, table))
            result.push_back({values[0], label});
        return result;
    }
    if (attrName == "searchflags") {
        static const std::vector<std::pair<uint32_t, std::string>> table = {
            {0x00000001, "fATTINDEX"}, {0x00000002, "fPDNTATTINDEX"},
            {0x00000004, "fANR"}, {0x00000008, "fPRESERVEONDELETE"},
            {0x00000010, "fCOPY"}, {0x00000020, "fTUPLEINDEX"},
            {0x00000040, "fSUBTREEATTINDEX"}, {0x00000080, "fCONFIDENTIAL"},
            {0x00000100, "fNEVERVALUEAUDIT"}, {0x00000200, "fRODCFilteredAttribute"},
            {0x00000400, "fEXTENDEDLINKTRACKING"}, {0x00000800, "fBASEONLY"},
            {0x00001000, "fPARTITIONSECRET"},
        };
        uint32_t v = static_cast<uint32_t>(ldapcore::strToUInt(values[0], 0));
        for (const auto &label : expandBitmask(v, table))
            result.push_back({values[0], label});
        return result;
    }

    for (size_t idx = 0; idx < values.size(); ++idx) {
        const std::string &raw = values[idx];
        std::string formatted;

        if (attrName == "objectsid" || attrName == "securityidentifier") {
            if (idx < byteValues.size() && !byteValues[idx].empty()) {
                if (auto sid = sidToText(byteValues[idx]))
                    formatted = "SID{" + *sid + "}";
            }
        } else if (attrName == "objectguid" || attrName == "schemaidguid" ||
                   attrName == "attributesecurityguid") {
            if (idx < byteValues.size() && !byteValues[idx].empty()) {
                if (auto guid = guidToText(byteValues[idx]))
                    formatted = "GUID{" + *guid + "}";
            }
        } else if (ntTimestampAttrs().count(attrName)) {
            bool never = false;
            int64_t ts = ntTimestampToUnix(ldapcore::strToInt(raw, 0), never);
            if (never) {
                formatted = "(Never)";
            } else {
                formatted = ldapcore::formatTimestamp(ts, timeFormat, timeOffsetHours);
            }
        } else if (ntIntervalAttrs().count(attrName)) {
            int64_t secs = ntIntervalToSeconds(raw);
            if (attrName == "forcelogoff") {
                if (raw == "0") formatted = "(Instantly)";
                else if (raw == "-9223372036854775808") formatted = "(Never)";
                else formatted = ldapcore::formatDuration(secs);
            } else {
                formatted = secs == 0 ? "(None)" : ldapcore::formatDuration(secs);
            }
        } else if (attrName == "primarygroupid") {
            int64_t rid = ldapcore::strToInt(raw, 0);
            formatted = ridToLabel(static_cast<uint32_t>(rid));
        } else if (attrName == "samaccounttype") {
            static const std::vector<std::pair<uint32_t, std::string>> table = {
                {0x00000000, "Domain Object"}, {0x10000000, "Group Object"},
                {0x10000001, "Non-Security Group Object"},
                {0x20000000, "Alias Object"}, {0x20000001, "Non-Security Alias Object"},
                {0x30000000, "User Object"}, {0x30000001, "Machine Account"},
                {0x30000002, "Trust Account"}, {0x40000000, "App Basic Group"},
                {0x40000001, "App Query Group"},
            };
            uint32_t v = static_cast<uint32_t>(ldapcore::strToUInt(raw, 0));
            for (const auto &[bit, label] : table)
                if (v == bit) formatted = label;
        } else if (attrName == "grouptype") {
            static const std::vector<std::pair<uint32_t, std::string>> table = {
                {0x00000002, "Global Distribution Group"},
                {0x00000004, "Domain Local Distribution Group"},
                {0x00000008, "Universal Distribution Group"},
                {0x80000002, "Global Security Group"},
                {0x80000004, "Domain Local Security Group"},
                {0x80000005, "Builtin Group"},
                {0x80000008, "Universal Security Group"},
            };
            uint32_t v = static_cast<uint32_t>(ldapcore::strToUInt(raw, 0));
            for (const auto &[bit, label] : table)
                if (v == bit) formatted = label;
        } else if (attrName == "instancetype") {
            static const std::vector<std::pair<uint32_t, std::string>> table = {
                {1, "NamingContextHead"}, {2, "NotInstantiatedReplica"},
                {4, "WritableObject"}, {8, "ParentNamingContextHeld"},
                {16, "FirstNamingContextConstruction"},
                {32, "NamingContextRemovalFromDSA"},
            };
            uint32_t v = static_cast<uint32_t>(ldapcore::strToUInt(raw, 0));
            for (const auto &[bit, label] : table)
                if (v == bit) formatted = label;
        } else if (attrName == "logonhours" || attrName == "dsasignature" ||
                   attrName == "omobjectclass" || attrName == "cacertificate") {
            if (idx < byteValues.size() && !byteValues[idx].empty())
                formatted = "HEX{" + ldapcore::bytesToHex(byteValues[idx]) + "}";
        } else if (attrName == "lockoutthreshold" || attrName == "msds-lockoutthreshold" ||
                   attrName == "minpwdlength" || attrName == "msds-minimumpasswordlength") {
            if (raw == "0") formatted = "(None)";
        }

        if (formatted.empty()) formatted = raw;
        result.push_back({raw, formatted});
    }
    return result;
}

} // namespace diratlas::ad