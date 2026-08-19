// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Manuel FLURY

#include "attrs.h"

#include "bytes.h"

#include <cctype>
#include <cstdlib>
#include <ctime>

namespace diratlas::ldapcore {

namespace {

// RFC 4517 GeneralizedTime: YYYYMMDDHHMMSS[.fraction][Z|(+|-)HHMM]
// We tolerate missing seconds and missing timezone (treat as UTC).
bool parseDigits(const std::string &s, size_t &i, size_t n, int &out) {
    if (i + n > s.size()) return false;
    int v = 0;
    for (size_t k = 0; k < n; ++k) {
        if (!std::isdigit(static_cast<unsigned char>(s[i + k]))) return false;
        v = v * 10 + (s[i + k] - '0');
    }
    i += n;
    out = v;
    return true;
}

} // namespace

int64_t parseGeneralizedTime(const std::string &val) {
    if (val.size() < 12) return 0;
    size_t i = 0;
    int year = 0, month = 0, day = 0, hour = 0, minute = 0, second = 0;
    if (!parseDigits(val, i, 4, year)) return 0;
    if (!parseDigits(val, i, 2, month)) return 0;
    if (!parseDigits(val, i, 2, day)) return 0;
    if (!parseDigits(val, i, 2, hour)) return 0;
    if (!parseDigits(val, i, 2, minute)) return 0;
    // Seconds are optional in GeneralizedTime.
    if (i < val.size() && std::isdigit(static_cast<unsigned char>(val[i]))) {
        if (!parseDigits(val, i, 2, second)) return 0;
    }
    // Optional fractional part.
    if (i < val.size() && val[i] == '.') {
        while (i < val.size() && std::isdigit(static_cast<unsigned char>(val[i]))) ++i;
    }
    // Optional timezone: 'Z' or +HHMM / -HHMM. Default is UTC.
    int tzOffsetMin = 0;
    if (i < val.size()) {
        if (val[i] == 'Z' || val[i] == 'z') {
            ++i;
        } else if (val[i] == '+' || val[i] == '-') {
            int sign = (val[i] == '-') ? -1 : 1;
            ++i;
            int tzh = 0, tzm = 0;
            if (!parseDigits(val, i, 2, tzh)) return 0;
            if (i < val.size() && std::isdigit(static_cast<unsigned char>(val[i]))) {
                if (!parseDigits(val, i, 2, tzm)) return 0;
            }
            tzOffsetMin = sign * (tzh * 60 + tzm);
        } else {
            return 0; // trailing garbage
        }
    }

    // Basic range check (avoid timegm explosion on garbage).
    if (year < 1970 || year > 9999 || month < 1 || month > 12 ||
        day < 1 || day > 31 || hour > 23 || minute > 59 || second > 60)
        return 0;

    struct tm tm = {};
    tm.tm_year = year - 1900;
    tm.tm_mon = month - 1;
    tm.tm_mday = day;
    tm.tm_hour = hour;
    tm.tm_min = minute;
    tm.tm_sec = second;
    tm.tm_isdst = 0;
    time_t t = timegm(&tm);
    if (t == static_cast<time_t>(-1)) return 0;
    return static_cast<int64_t>(t) - tzOffsetMin * 60;
}

std::string formatTimestamp(int64_t unixTime, const std::string &format,
                            int offsetHours) {
    time_t t = static_cast<time_t>(unixTime) + offsetHours * 3600;
    struct tm *adjusted = gmtime(&t);
    if (!adjusted) return "";
    char buf[128];
    if (strftime(buf, sizeof(buf), format.c_str(), adjusted) == 0) return "";
    return buf;
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

std::vector<AttrValue> formatAttribute(
    const std::string &attrName,
    const std::vector<std::string> &values,
    const std::vector<std::vector<uint8_t>> &byteValues,
    const std::string &timeFormat) {
    std::vector<AttrValue> result;
    if (values.empty()) {
        result.push_back({"(Empty)", "(Empty)"});
        return result;
    }

    for (size_t idx = 0; idx < values.size(); ++idx) {
        const std::string &raw = values[idx];
        std::string formatted;

        if (attrName == "createtimestamp" || attrName == "modifytimestamp" ||
            attrName == "whencreated" || attrName == "whenchanged") {
            int64_t ts = parseGeneralizedTime(raw);
            if (ts != 0) formatted = formatTimestamp(ts, timeFormat);
        } else if (idx < byteValues.size() && !byteValues[idx].empty() &&
                   !isPrintable(byteValues[idx])) {
            formatted = "HEX{" + bytesToHex(byteValues[idx]) + "}";
        }

        if (formatted.empty()) formatted = raw;
        result.push_back({raw, formatted});
    }
    return result;
}

} // namespace diratlas::ldapcore