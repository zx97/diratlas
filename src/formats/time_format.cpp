// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Manuel FLURY
//
// This file is part of DirAtlas — an LDAP Directory Explorer.
//
// Licensed under the GNU Affero General Public License v3.0
// (https://www.gnu.org/licenses/agpl-3.0.txt).
//
// Originally based on godap (github.com/Macmod/godap) — MIT license.

#include "time_format.h"
#include <string>
#include <cmath>

namespace diratlas::formats {

std::string getTimeDistString(std::chrono::seconds diff) {
    auto total_sec = diff.count();
    if (total_sec == 0) {
        return "(0 seconds ago)";
    }

    bool future = total_sec < 0;
    if (future) {
        total_sec = -total_sec;
    }

    int days = static_cast<int>(total_sec / 86400);
    std::string result;

    if (days == 0) {
        int hours = static_cast<int>(total_sec / 3600);
        if (hours == 0) {
            int minutes = static_cast<int>(total_sec / 60);
            if (minutes == 0) {
                if (future) {
                    result = "(" + std::to_string(total_sec) + " seconds from now)";
                } else {
                    result = "(" + std::to_string(total_sec) + " seconds ago)";
                }
            } else if (minutes == 1) {
                result = future ? "(1 minute from now)" : "(1 minute ago)";
            } else {
                if (future) {
                    result = "(" + std::to_string(minutes) + " minutes from now)";
                } else {
                    result = "(" + std::to_string(minutes) + " minutes ago)";
                }
            }
        } else if (hours == 1) {
            result = future ? "(1 hour from now)" : "(1 hour ago)";
        } else {
            if (future) {
                result = "(" + std::to_string(hours) + " hours from now)";
            } else {
                result = "(" + std::to_string(hours) + " hours ago)";
            }
        }
    } else if (days == 1) {
        result = future ? "(tomorrow)" : "(yesterday)";
    } else {
        if (future) {
            result = "(" + std::to_string(days) + " days from now)";
        } else {
            result = "(" + std::to_string(days) + " days ago)";
        }
    }

    return result;
}

} // namespace diratlas::formats
