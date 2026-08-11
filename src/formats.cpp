// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Manuel FLURY
//
// This file is part of DirAtlas — an LDAP Directory Explorer.
//
// Licensed under the GNU Affero General Public License v3.0
// (https://www.gnu.org/licenses/agpl-3.0.txt).
//
// Originally based on godap (github.com/Macmod/godap) — MIT license.

#include "formats.h"
#include "vars.h"
#include "formats/time_format.h"
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <ctime>
#include <vector>
#include <map>

namespace diratlas {

std::string FormattedAttr::valuesStr() const {
    std::string result;
    for (size_t i = 0; i < values.size(); i++) {
        if (i > 0) result += "; ";
        result += values[i].formattedValue;
    }
    return result;
}

std::string endianConvert(const std::string &sd) {
    std::string result = sd;
    size_t len = result.length();
    for (size_t i = 0, j = len - 2; i < j; i += 2, j -= 2) {
        std::swap(result[i], result[j]);
        std::swap(result[i+1], result[j+1]);
    }
    return result;
}

uint64_t hexToOffset(const std::string &hex) {
    uint64_t integer = std::stoull(endianConvert(hex), nullptr, 16);
    return integer * 2;
}

uint32_t hexToUint32(const std::string &hex) {
    return static_cast<uint32_t>(std::stoul(hex, nullptr, 16));
}

int hexToInt(const std::string &hex) {
    return static_cast<int>(std::stoll(hex, nullptr, 16));
}

std::string hexToDecimalString(const std::string &hex) {
    int64_t val = std::stoll(hex, nullptr, 16);
    return std::to_string(val);
}

std::string capitalize(const std::string &str) {
    if (str.empty()) return str;
    std::string result = str;
    result[0] = std::toupper(static_cast<unsigned char>(result[0]));
    return result;
}

static uint8_t hexCharToByte(char c) {
    if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
    if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
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

std::string convertSID(const std::string &hexSID) {
    std::string sid = "S-1";
    int numDashes = std::stoi(hexToDecimalString(hexSID.substr(2, 2)));
    sid += "-" + hexToDecimalString(hexSID.substr(4, 12));

    size_t lower = 16, upper = 24;
    for (int i = 1; i <= numDashes; i++) {
        sid += "-" + hexToDecimalString(endianConvert(hexSID.substr(lower, 8)));
        lower += 8;
        upper += 8;
    }
    return sid;
}

std::string encodeSID(const std::string &sid) {
    if (sid.length() < 2) return "";

    auto parts = std::vector<std::string>();
    std::string s = sid.substr(2);
    size_t pos = 0;
    std::string token;
    while ((pos = s.find('-')) != std::string::npos) {
        parts.push_back(s.substr(0, pos));
        s.erase(0, pos + 1);
    }
    parts.push_back(s);

    if (parts.size() < 3) return "";

    std::string hexSID;
    int revision = std::stoi(parts[0]);
    char buf[16];
    snprintf(buf, sizeof(buf), "%02X", revision);
    hexSID += buf;
    snprintf(buf, sizeof(buf), "%02X", (int)(parts.size() - 2));
    hexSID += buf;

    uint64_t authority = std::stoull(parts[1]);
    for (int i = 0; i < 6; i++) {
        snprintf(buf, sizeof(buf), "%02X", static_cast<uint8_t>((authority >> (8 * (5 - i))) & 0xFF));
        hexSID += buf;
    }

    for (size_t i = 2; i < parts.size(); i++) {
        uint32_t subAuth = static_cast<uint32_t>(std::stoul(parts[i]));
        std::vector<uint8_t> le(4);
        le[0] = subAuth & 0xFF;
        le[1] = (subAuth >> 8) & 0xFF;
        le[2] = (subAuth >> 16) & 0xFF;
        le[3] = (subAuth >> 24) & 0xFF;
        for (auto b : le) {
            snprintf(buf, sizeof(buf), "%02X", b);
            hexSID += buf;
        }
    }

    return hexSID;
}

bool isSID(const std::string &s) {
    return s.rfind("S-", 0) == 0;
}

std::string convertGUID(const std::string &portion) {
    auto p1 = endianConvert(portion.substr(0, 8));
    auto p2 = endianConvert(portion.substr(8, 4));
    auto p3 = endianConvert(portion.substr(12, 4));
    auto p4 = portion.substr(16, 4);
    auto p5 = portion.substr(20);
    return p1 + "-" + p2 + "-" + p3 + "-" + p4 + "-" + p5;
}

std::string encodeGUID(const std::string &guid) {
    auto tokens = std::vector<std::string>();
    std::string s = guid;
    size_t pos;
    while ((pos = s.find('-')) != std::string::npos) {
        tokens.push_back(s.substr(0, pos));
        s.erase(0, pos + 1);
    }
    tokens.push_back(s);

    if (tokens.size() != 5) return "";
    std::string result;
    result += endianConvert(tokens[0]);
    result += endianConvert(tokens[1]);
    result += endianConvert(tokens[2]);
    result += tokens[3];
    result += tokens[4];
    return result;
}

std::string formatLDAPTime(const std::string &val, const std::string &format, int offset) {
    std::tm tm = {};
    std::istringstream ss(val);
    ss >> std::get_time(&tm, "%Y%m%d%H%M%S");
    if (ss.fail()) return "Invalid date format";

    time_t t = timegm(&tm);
    t += offset * 3600;
    struct tm *adjusted = gmtime(&t);

    char buf[128];
    strftime(buf, sizeof(buf), format.c_str(), adjusted);
    
    auto elapsed = std::chrono::system_clock::from_time_t(t) - std::chrono::system_clock::now();
    auto secs = std::chrono::duration_cast<std::chrono::seconds>(-elapsed);
    auto distStr = formats::getTimeDistString(secs);

    return std::string(buf) + " " + distStr;
}

std::string formatLDAPTime2(const std::string &val, const std::string &format, int offset) {
    int64_t intVal;
    try {
        intVal = std::stoll(val);
    } catch (...) {
        return "(Invalid)";
    }

    int64_t unixTime = (intVal - 116444736000000000) / 10000000;
    time_t t = unixTime;
    t += offset * 3600;
    struct tm *adjusted = gmtime(&t);

    char buf[128];
    strftime(buf, sizeof(buf), format.c_str(), adjusted);

    auto tp = std::chrono::system_clock::from_time_t(unixTime);
    auto now = std::chrono::system_clock::now();
    auto diff = std::chrono::duration_cast<std::chrono::seconds>(now - tp);
    auto distStr = formats::getTimeDistString(diff);

    return std::string(buf) + " " + distStr;
}

std::string formatDuration(int64_t seconds) {
    if (seconds == 0) return "0 seconds";

    int days = static_cast<int>(seconds / 86400);
    seconds %= 86400;
    int hours = static_cast<int>(seconds / 3600);
    seconds %= 3600;
    int minutes = static_cast<int>(seconds / 60);
    seconds %= 60;

    std::string result;
    if (days > 0) result += std::to_string(days) + " days ";
    if (hours > 0) result += std::to_string(hours) + " hours ";
    if (minutes > 0) result += std::to_string(minutes) + " minutes ";
    if (seconds > 0) result += std::to_string(seconds) + " seconds";

    if (result.empty()) return "0 seconds";
    if (result.back() == ' ') result.pop_back();
    return result;
}

int64_t parseMSDuration(const std::string &val) {
    try {
        int64_t intVal = std::stoll(val);
        if (intVal < 0) intVal = -intVal;
        return intVal / 10000000;
    } catch (...) {
        return 0;
    }
}

std::vector<std::string> parseUACFlags(int uacInt) {
    std::vector<int> keys;
    for (const auto &[k, v] : UacFlags) {
        keys.push_back(static_cast<int>(k));
    }
    std::sort(keys.begin(), keys.end());

    std::vector<std::string> result;
    for (int flag : keys) {
        auto it = UacFlags.find(static_cast<uint32_t>(flag));
        if (uacInt & flag) {
            if (!it->second.present.empty())
                result.push_back(it->second.present);
        } else {
            if (!it->second.notPresent.empty())
                result.push_back(it->second.notPresent);
        }
    }
    return result;
}

std::vector<std::string> parseBitFlags(uint32_t v, const std::map<uint32_t, std::string> &flagMap) {
    std::vector<uint32_t> keys;
    for (const auto &[k, _] : flagMap) keys.push_back(k);
    std::sort(keys.begin(), keys.end());

    std::vector<std::string> result;
    for (auto bit : keys) {
        if (v & bit) {
            auto it = flagMap.find(bit);
            if (it != flagMap.end())
                result.push_back(it->second);
        }
    }
    return result;
}

std::vector<std::string> parseSystemFlags(uint32_t v) {
    std::vector<uint32_t> keys;
    for (const auto &[k, _] : SystemFlags) keys.push_back(k);
    std::sort(keys.begin(), keys.end());

    std::vector<std::string> result;
    for (auto bit : keys) {
        if (v & bit) {
            auto it = SystemFlags.find(bit);
            if (it != SystemFlags.end())
                result.push_back(it->second);
        }
    }
    return result;
}

std::vector<FormattedAttrValue> formatAttributeValues(
    const std::string &attrName,
    const std::vector<std::string> &values,
    const std::vector<std::vector<uint8_t>> &byteValues,
    const std::string &timeFormat,
    int timeOffset)
{
    std::vector<FormattedAttrValue> result;

    if (values.empty()) {
        result.push_back({"(Empty)", "(Empty)"});
        return result;
    }

    // Bitset attributes
    if (attrName == "userAccountControl") {
        int v = std::stoi(values[0]);
        auto flags = parseUACFlags(v);
        for (const auto &f : flags) {
            result.push_back({values[0], f});
        }
        return result;
    }
    if (attrName == "systemFlags") {
        uint32_t v = static_cast<uint32_t>(std::stoll(values[0]));
        auto flags = parseSystemFlags(v);
        for (const auto &f : flags) {
            result.push_back({values[0], f});
        }
        return result;
    }
    if (attrName == "trustAttributes") {
        uint32_t v = static_cast<uint32_t>(std::stoul(values[0]));
        auto flags = parseBitFlags(v, TrustAttributeFlags);
        for (const auto &f : flags) {
            result.push_back({values[0], f});
        }
        return result;
    }
    if (attrName == "pwdProperties") {
        uint32_t v = static_cast<uint32_t>(std::stoul(values[0]));
        auto flags = parseBitFlags(v, PwdPropertiesFlags);
        for (const auto &f : flags) {
            result.push_back({values[0], f});
        }
        return result;
    }
    if (attrName == "searchFlags") {
        uint32_t v = static_cast<uint32_t>(std::stoul(values[0]));
        auto flags = parseBitFlags(v, SearchFlagsMap);
        for (const auto &f : flags) {
            result.push_back({values[0], f});
        }
        return result;
    }

    for (size_t idx = 0; idx < values.size(); idx++) {
        std::string formatted;

        if (attrName == "objectSid" || attrName == "securityIdentifier") {
            if (idx < byteValues.size())
                formatted = "SID{" + convertSID(bytesToHex(byteValues[idx])) + "}";
        } else if (attrName == "objectGUID" || attrName == "schemaIDGUID" || attrName == "attributeSecurityGUID") {
            if (idx < byteValues.size())
                formatted = "GUID{" + convertGUID(bytesToHex(byteValues[idx])) + "}";
        } else if (attrName == "whenCreated" || attrName == "whenChanged") {
            formatted = formatLDAPTime(values[idx], timeFormat, timeOffset);
        } else if (attrName == "lastLogonTimestamp" || attrName == "accountExpires" ||
                   attrName == "badPasswordTime" || attrName == "lastLogoff" ||
                   attrName == "lastLogon" || attrName == "pwdLastSet" ||
                   attrName == "creationTime" || attrName == "lockoutTime") {
            if (values[idx] == "0" || (attrName == "accountExpires" && values[idx] == "9223372036854775807")) {
                formatted = "(Never)";
            } else {
                formatted = formatLDAPTime2(values[idx], timeFormat, timeOffset);
            }
        } else if (attrName == "primaryGroupID") {
            int rid = std::stoi(values[idx]);
            auto it = RidMap.find(rid);
            if (it != RidMap.end()) formatted = it->second;
        } else if (attrName == "sAMAccountType") {
            int typeId = std::stoi(values[idx]);
            auto it = SAMAccountTypeMap.find(typeId);
            if (it != SAMAccountTypeMap.end()) formatted = it->second;
        } else if (attrName == "groupType") {
            int typeId = std::stoi(values[idx]);
            auto it = GroupTypeMap.find(typeId);
            if (it != GroupTypeMap.end()) formatted = it->second;
        } else if (attrName == "instanceType") {
            int typeId = std::stoi(values[idx]);
            auto it = InstanceTypeMap.find(typeId);
            if (it != InstanceTypeMap.end()) formatted = it->second;
        } else if (attrName == "logonHours" || attrName == "dSASignature" ||
                   attrName == "oMObjectClass" || attrName == "cACertificate") {
            if (idx < byteValues.size())
                formatted = "HEX{" + bytesToHex(byteValues[idx]) + "}";
        } else if (attrName == "msDS-MaximumPasswordAge" || attrName == "msDS-MinimumPasswordAge" ||
                   attrName == "msDS-LockoutDuration" || attrName == "msDS-LockoutObservationWindow" ||
                   attrName == "lockoutDuration" || attrName == "lockOutObservationWindow" ||
                   attrName == "maxPwdAge" || attrName == "minPwdAge" || attrName == "forceLogoff" ||
                   attrName == "msDS-UserTGTLifetime" || attrName == "msDS-ComputerTGTLifetime" ||
                   attrName == "msDS-ServiceTGTLifetime") {
            int64_t secs = parseMSDuration(values[idx]);
            if (attrName == "forceLogoff") {
                if (values[idx] == "0") formatted = "(Instantly)";
                else if (values[idx] == "-9223372036854775808") formatted = "(Never)";
                else formatted = formatDuration(secs);
            } else {
                if (secs == 0) formatted = "(None)";
                else formatted = formatDuration(secs);
            }
        } else if (attrName == "lockoutThreshold" || attrName == "msDS-LockoutThreshold" ||
                   attrName == "minPwdLength" || attrName == "msDS-MinimumPasswordLength") {
            if (values[idx] == "0") formatted = "(None)";
        }

        if (formatted.empty()) formatted = values[idx];

        result.push_back({values[idx], formatted});
    }

    return result;
}

} // namespace diratlas
