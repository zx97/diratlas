// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Manuel FLURY
//
// This file is part of DirAtlas — an LDAP Directory Explorer.
//
// Licensed under the GNU Affero General Public License v3.0
// (https://www.gnu.org/licenses/agpl-3.0.txt).
//

#include "attrs.h"
#include "../ldapcore/attrs.h"
#include "../ldapcore/attrdesc.h"
#include "../ldapcore/bytes.h"
#include "../ldapcore/utf8.h"
#include "../ad/format.h"
#include <ncurses.h>
#include <ctime>
#include <algorithm>
#include <set>
#include <cstring>
#include <cstdio>
#include <cctype>
#include <cwchar>

namespace diratlas::tui {

/** @brief strftime pattern used for timestamp rendering in the TUI. */
static const char *const kTuiTimeFormat = "%Y-%m-%d %H:%M:%S";

/** @brief Empty byte-vector placeholder for attributes without binary data. */
static const std::vector<std::vector<uint8_t>> emptyBytes;

/** @brief Lowercase a copy of an attribute name (formatters match lower-case names). */
static std::string lowerName(std::string s) {
    for (char &c : s)
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + 32);
    return s;
}

/** @brief Human-readable media label for known binary attributes, or nullptr. */
static const char *mediaLabelFor(const std::string &lower) {
    static const std::map<std::string, const char *> media = {
        {"jpegphoto", "image/jpeg"}, {"photo", "image/jpeg"}, {"jpeg", "image/jpeg"},
        {"thumbnailphoto", "image/jpeg"}, {"logo", "image"}, {"audio", "audio"},
        {"video", "video"}, {"usercertificate", "x509-certificate"},
        {"cacertificate", "x509-certificate"}, {"crosscertificatepair", "x509-cert-pair"},
        {"usersmimecertificate", "smime-certificate"},
    };
    auto it = media.find(lower);
    return it == media.end() ? nullptr : it->second;
}

/** @brief Collapse AD entries sharing the same raw value (bitmask flags expand to one entry per flag). */
static std::vector<std::string> mergeAdEntries(const std::vector<diratlas::ad::AdAttrValue> &entries) {
    std::vector<std::string> out;
    std::string curRaw;
    std::string cur;
    for (const auto &e : entries) {
        if (!cur.empty() && e.raw != curRaw) { out.push_back(cur); cur.clear(); }
        if (cur.empty()) curRaw = e.raw;
        if (!cur.empty()) cur += " | ";
        cur += e.formatted;
    }
    if (!cur.empty()) out.push_back(cur);
    return out;
}

/** @brief Text actually rendered for a row (formatted display, else raw value). */
static const std::string &displayOf(const AttrRow &row) {
    return row.display.empty() ? row.value : row.display;
}

namespace {
using diratlas::ldapcore::utf8Decode;
using diratlas::ldapcore::utf8Truncate;
using diratlas::ldapcore::utf8Width;
using diratlas::ldapcore::utf8Wrap;

// Short human descriptions for well-known RootDSE supported* OIDs /
// mechanism names, appended after the raw value in the attribute panel.
const std::map<std::string, const char*> kRootDseOidDesc = {
    // LDAP controls (RFC 4511/4525/4527/4528/2696/3672/4533/3296/4370...)
    {"1.2.840.113556.1.4.319", "Paged Results (RFC 2696)"},
    {"1.2.840.113556.1.4.805", "Tree Delete (AD)"},
    {"1.2.840.113556.1.4.1339", "DirSync (AD)"},
    {"1.2.840.113556.1.4.1340", "DirSync (AD)"},
    {"1.3.6.1.1.12", "Assertion (RFC 4528)"},
    {"1.3.6.1.1.13.1", "Pre-Read (RFC 4527)"},
    {"1.3.6.1.1.13.2", "Post-Read (RFC 4527)"},
    {"1.3.6.1.1.22", "Don't Use Copy (RFC 6171)"},
    {"1.3.6.1.4.1.4203.1.9.1.1", "Sync Request (RFC 4533)"},
    {"1.3.6.1.4.1.4203.1.10.1", "Subentries (RFC 3672)"},
    {"1.3.6.1.4.1.42.2.27.8.5.1", "Password Policy (ppolicy)"},
    {"1.3.6.1.4.1.42.2.27.9.5.8", "Password Policy (ppolicy)"},
    {"2.16.840.1.113730.3.4.2", "ManageDsaIT (RFC 3296)"},
    {"2.16.840.1.113730.3.4.18", "Proxy Authorization (RFC 4370)"},
    // Extended operations
    {"1.3.6.1.4.1.1466.20037", "StartTLS (RFC 4511)"},
    {"1.3.6.1.4.1.4203.1.11.1", "Password Modify (RFC 3062)"},
    {"1.3.6.1.4.1.4203.1.11.3", "Who am I (RFC 4532)"},
    {"1.3.6.1.1.8", "Cancel (RFC 3909)"},
    // Features / capabilities
    {"1.3.6.1.1.14", "Modify-Increment (RFC 4525)"},
    {"1.3.6.1.4.1.4203.1.5.1", "All Operational Attrs (RFC 3673)"},
    {"1.3.6.1.4.1.4203.1.5.2", "True/False Filters (RFC 4526)"},
    {"1.3.6.1.4.1.4203.1.5.3", "Language Tag Options (RFC 3866)"},
    {"1.3.6.1.4.1.4203.1.5.4", "Language Range Options (RFC 3866)"},
    // SASL mechanism names
    {"GSSAPI", "Kerberos"},
    {"EXTERNAL", "TLS client cert"},
    {"DIGEST-MD5", "HTTP Digest"},
    {"CRAM-MD5", "CRAM-MD5"},
    {"SCRAM-SHA-1", "SCRAM"},
    {"SCRAM-SHA-256", "SCRAM"},
    {"PLAIN", "Plain text"},
};

// Return " (description)" when value is a known supported* OID/mechanism.
std::string rootDseValueDesc(const std::string &attrName, const std::string &value) {
    if (attrName.rfind("supported", 0) != 0) return "";
    auto it = kRootDseOidDesc.find(value);
    if (it == kRootDseOidDesc.end()) return "";
    return std::string("  (") + it->second + ")";
}
} // namespace

/** @brief Check if an attribute name is a recognised LDAP timestamp field. */
static bool isTimestampAttr(const std::string &name) {
    static const std::set<std::string> ts = {
        "whenCreated", "whenChanged",
        "lastLogonTimestamp", "accountExpires",
        "badPasswordTime", "lastLogoff",
        "lastLogon", "pwdLastSet",
        "creationTime", "lockoutTime"
    };
    return ts.count(name) > 0;
}

/** @brief Check if an attribute uses Windows NT epoch timestamps (1601-01-01). */
static bool isWinTimestamp(const std::string &name) {
    static const std::set<std::string> wts = {
        "lastLogonTimestamp", "accountExpires",
        "badPasswordTime", "lastLogoff",
        "lastLogon", "pwdLastSet",
        "creationTime", "lockoutTime"
    };
    return wts.count(name) > 0;
}

/** @brief Parse a generalised LDAP timestamp (YYYYMMDDhhmmssZ) to time_t. */
static time_t parseLDAPTimestamp(const std::string &val) {
    if (val.size() < 14) return 0;
    struct tm tm = {};
    tm.tm_year = std::stoi(val.substr(0, 4)) - 1900;
    tm.tm_mon  = std::stoi(val.substr(4, 2)) - 1;
    tm.tm_mday = std::stoi(val.substr(6, 2));
    tm.tm_hour = std::stoi(val.substr(8, 2));
    tm.tm_min  = std::stoi(val.substr(10, 2));
    tm.tm_sec  = std::stoi(val.substr(12, 2));
    return timegm(&tm);
}

/** @brief Parse a Windows NT timestamp (100-ns intervals since 1601-01-01) to time_t. */
static time_t parseWinTimestamp(const std::string &val) {
    try {
        int64_t intVal = std::stoll(val);
        if (intVal == 0 || intVal == 9223372036854775807LL) return 0;
        int64_t unixTime = (intVal - 116444736000000000LL) / 10000000LL;
        return static_cast<time_t>(unixTime);
    } catch (...) { return 0; }
}

/**
 * @brief Choose a colour index for a timestamp value based on how recent it is.
 *
 * Returns CP_ATTR_TIME_NEW (< 1 hour), CP_ATTR_TIME_OLD (< 1 day),
 * CP_ATTR_TIME_VERY_OLD (>= 1 day), or the default CP_ATTR_VALUE.
 */
int AttrsWidget::timestampColor(const std::string &attrName,
                                 const std::string &value) const {
    if (!isTimestampAttr(attrName) || value.empty())
        return CP_ATTR_VALUE;
    time_t ts = isWinTimestamp(attrName)
        ? parseWinTimestamp(value) : parseLDAPTimestamp(value);
    if (ts == 0) return CP_ATTR_VALUE;
    double diff = difftime(time(nullptr), ts);
    if (diff < 0) diff = 0;
    if (diff < 3600) return CP_ATTR_TIME_NEW;
    if (diff < 86400) return CP_ATTR_TIME_OLD;
    return CP_ATTR_TIME_VERY_OLD;
}

/**
 * @brief Parse MUST (mandatory) attribute names from an objectClass schema definition.
 *
 * Looks for " MUST (...)" and extracts $ -separated attribute names.
 */
static void parseMUST(const std::string &ocDef, std::set<std::string> &out) {
    // Find MUST parenthesized list
    auto mpos = ocDef.find(" MUST ");
    if (mpos == std::string::npos) return;
    mpos += 6;
    if (mpos >= ocDef.size()) return;

    // Skip opening paren if present
    size_t start = mpos;
    if (ocDef[start] == '(') start++;

    // Find closing: look for ')' followed by space and MAY/END
    size_t end = ocDef.find(')', start);
    if (end == std::string::npos) return;

    std::string list = ocDef.substr(start, end - start);
    // Split on $
    size_t p = 0, q;
    while ((q = list.find('$', p)) != std::string::npos) {
        std::string attr = list.substr(p, q - p);
        attr.erase(0, attr.find_first_not_of(" \t\r\n"));
        attr.erase(attr.find_last_not_of(" \t\r\n") + 1);
        if (!attr.empty()) out.insert(attr);
        p = q + 1;
    }
    std::string attr = list.substr(p);
    attr.erase(0, attr.find_first_not_of(" \t\r\n"));
    attr.erase(attr.find_last_not_of(" \t\r\n") + 1);
    if (!attr.empty()) out.insert(attr);
}

/// @brief Extract $ -separated attribute names from a " MAY (...)" list (RFC 4512).
static void parseMAY(const std::string &ocDef, std::set<std::string> &out) {
    auto mpos = ocDef.find(" MAY ");
    if (mpos == std::string::npos) return;
    mpos += 5;
    if (mpos >= ocDef.size()) return;
    size_t start = mpos;
    if (ocDef[start] == '(') start++;
    size_t end = ocDef.find(')', start);
    if (end == std::string::npos) return;
    std::string list = ocDef.substr(start, end - start);
    size_t p = 0, q;
    while ((q = list.find('$', p)) != std::string::npos) {
        std::string attr = list.substr(p, q - p);
        attr.erase(0, attr.find_first_not_of(" \t\r\n"));
        attr.erase(attr.find_last_not_of(" \t\r\n") + 1);
        if (!attr.empty()) out.insert(attr);
        p = q + 1;
    }
    std::string attr = list.substr(p);
    attr.erase(0, attr.find_first_not_of(" \t\r\n"));
    attr.erase(attr.find_last_not_of(" \t\r\n") + 1);
    if (!attr.empty()) out.insert(attr);
}

/**
 * @brief Determine mandatory attributes for a set of objectClasses by querying the subschema.
 *
 * Fetches the subschemaSubentry from RootDSE, retrieves all objectClass
 * definitions, matches the entry's classes, and collects MUST attributes.
 */
std::set<std::string> getMandatoryAttrs(LDAPConn &conn,
                                         const std::vector<std::string> &objectClasses) {
    std::set<std::string> result;
    if (objectClasses.empty()) return result;

    // Find subschema entry
    auto rootDSE = conn.searchOne("", "(objectClass=*)", {"subschemaSubentry"}, false);
    std::string subschemaDN = rootDSE.getAttr("subschemaSubentry");
    if (subschemaDN.empty()) return result;

    // Fetch objectClasses from subschema
    auto subschema = conn.searchOne(subschemaDN, "(objectClass=*)", {"objectClasses"}, false);
    auto allOCs = subschema.getAttrs("objectClasses");

    // For each objectClass of the entry, find its schema definition
    for (const auto &ocName : objectClasses) {
        for (const auto &ocDef : allOCs) {
            // Match NAME 'ocName' or NAME "ocName"
            std::string needle = " NAME '" + ocName + "'";
            auto npos = ocDef.find(needle);
            if (npos == std::string::npos) {
                needle = " NAME \"" + ocName + "\"";
                npos = ocDef.find(needle);
            }
            if (npos == std::string::npos) continue;
            parseMUST(ocDef, result);
            break;
        }
    }

    return result;
}

// Forward declaration for base64 helper used in show()
static std::string maybeDecodeBase64(const std::string &val);

static constexpr int MAX_VISIBLE_VALS = 3;

/**
 * @brief Extract the SUP (superior class) name from an objectClass schema definition.
 *
 * Example: ( 2.5.6.6 NAME 'person' SUP top STRUCTURAL ... ) → "top"
 * Handles simple SUP and SUP ( class1 $ class2 ) syntax.
 */
static std::string parseSUP(const std::string &ocDef) {
    auto p = ocDef.find(" SUP ");
    if (p == std::string::npos) return "";
    p += 5;
    auto end = ocDef.find_first_of(" )", p);
    if (end == std::string::npos) return "";
    // Handle SUP ( class1 $ class2 )
    if (ocDef[p] == '(') {
        p = ocDef.find_first_not_of(" \t(", p);
        if (p == std::string::npos || p >= end) return "";
        auto dollar = ocDef.find('$', p);
        if (dollar != std::string::npos && dollar < end)
            return ocDef.substr(p, dollar - p);
        return ocDef.substr(p, end - p);
    }
    return ocDef.substr(p, end - p);
}

/// @brief Extract the NAME field from an objectClass schema definition.
static std::string parseOCName(const std::string &ocDef) {
    auto namePos = ocDef.find(" NAME '");
    if (namePos == std::string::npos) {
        namePos = ocDef.find(" NAME \"");
        if (namePos == std::string::npos) return "";
    }
    namePos += 7; // skip " NAME '"
    auto nameEnd = ocDef.find('\'', namePos);
    if (nameEnd == std::string::npos) nameEnd = ocDef.find('"', namePos);
    if (nameEnd == std::string::npos) return "";
    return ocDef.substr(namePos, nameEnd - namePos);
}

std::vector<std::string> listObjectClasses(LDAPConn &conn) {
    std::vector<std::string> names;
    auto rootDSE = conn.searchOne("", "(objectClass=*)", {"subschemaSubentry"}, false);
    auto subschemaDN = rootDSE.getAttr("subschemaSubentry");
    if (subschemaDN.empty()) return names;
    auto subschema = conn.searchOne(subschemaDN, "(objectClass=*)", {"objectClasses"}, false);
    auto allDefs = subschema.getAttrs("objectClasses");
    for (const auto &def : allDefs) {
        std::string name = parseOCName(def);
        if (!name.empty()) names.push_back(name);
    }
    std::sort(names.begin(), names.end());
    names.erase(std::unique(names.begin(), names.end()), names.end());
    return names;
}

std::set<std::string> getInheritedMandatoryAttrs(LDAPConn &conn,
                                                  const std::string &objectClass) {
    std::set<std::string> result;
    if (objectClass.empty()) return result;
    auto rootDSE = conn.searchOne("", "(objectClass=*)", {"subschemaSubentry"}, false);
    auto subschemaDN = rootDSE.getAttr("subschemaSubentry");
    if (subschemaDN.empty()) return result;
    auto subschema = conn.searchOne(subschemaDN, "(objectClass=*)", {"objectClasses"}, false);
    auto allDefs = subschema.getAttrs("objectClasses");

    // Walk the SUP chain (person → inetOrgPerson → ...) collecting each
    // ancestor's MUST attributes so required fields are all prefilled.
    std::string cur = objectClass;
    std::set<std::string> visited;
    while (!cur.empty() && visited.insert(cur).second) {
        bool found = false;
        for (const auto &def : allDefs) {
            if (parseOCName(def) != cur) continue;
            parseMUST(def, result);
            cur = parseSUP(def);
            found = true;
            break;
        }
        if (!found) break;
    }
    return result;
}

std::set<std::string> getAllowedAttrs(LDAPConn &conn,
                                      const std::vector<std::string> &objectClasses) {
    std::set<std::string> result;
    if (objectClasses.empty()) return result;
    auto rootDSE = conn.searchOne("", "(objectClass=*)", {"subschemaSubentry"}, false);
    auto subschemaDN = rootDSE.getAttr("subschemaSubentry");
    if (subschemaDN.empty()) return result;
    auto subschema = conn.searchOne(subschemaDN, "(objectClass=*)", {"objectClasses"}, false);
    auto allDefs = subschema.getAttrs("objectClasses");

    for (const auto &oc : objectClasses) {
        std::string cur = oc;
        std::set<std::string> visited;
        while (!cur.empty() && visited.insert(cur).second) {
            bool found = false;
            for (const auto &def : allDefs) {
                if (parseOCName(def) != cur) continue;
                parseMUST(def, result);
                parseMAY(def, result);
                cur = parseSUP(def);
                found = true;
                break;
            }
            if (!found) break;
        }
    }
    return result;
}

std::string objectClassKind(LDAPConn &conn, const std::string &className) {
    if (className.empty()) return "";
    auto rootDSE = conn.searchOne("", "(objectClass=*)", {"subschemaSubentry"}, false);
    auto subschemaDN = rootDSE.getAttr("subschemaSubentry");
    if (subschemaDN.empty()) return "";
    auto subschema = conn.searchOne(subschemaDN, "(objectClass=*)", {"objectClasses"}, false);
    auto allDefs = subschema.getAttrs("objectClasses");
    for (const auto &def : allDefs) {
        if (parseOCName(def) != className) continue;
        if (def.find(" STRUCTURAL") != std::string::npos) return "STRUCTURAL";
        if (def.find(" AUXILIARY") != std::string::npos) return "AUXILIARY";
        if (def.find(" ABSTRACT") != std::string::npos) return "ABSTRACT";
        return "";
    }
    return "";
}

/**
 * @brief Build hierarchy depth for each objectClass by walking SUP chains.
 *
 * "top" has depth 0. Each class that inherits from another gets
 * depth = parent_depth + 1. Unresolved classes get depth 1.
 */
static void computeOCDepths(const std::vector<std::string> &allDefs,
                             std::map<std::string, int> &depths,
                             std::map<std::string, std::string> &supMap) {
    supMap.clear();
    depths.clear();
    depths["top"] = 0;

    for (const auto &def : allDefs) {
        // Extract NAME
        auto namePos = def.find(" NAME '");
        if (namePos == std::string::npos) {
            namePos = def.find(" NAME \"");
            if (namePos == std::string::npos) continue;
        }
        namePos += 7; // skip " NAME '"
        auto nameEnd = def.find('\'', namePos);
        if (nameEnd == std::string::npos) nameEnd = def.find('"', namePos);
        if (nameEnd == std::string::npos) continue;
        std::string name = def.substr(namePos, nameEnd - namePos);
        std::string sup = parseSUP(def);
        if (!sup.empty()) {
            supMap[name] = sup;
        }
    }

    // Compute depths by walking SUP chains
    bool changed = true;
    while (changed) {
        changed = false;
        for (const auto &[name, sup] : supMap) {
            if (depths.find(name) != depths.end()) continue;
            auto it = depths.find(sup);
            if (it != depths.end()) {
                depths[name] = it->second + 1;
                changed = true;
            }
        }
    }
    // Any remaining unmapped classes get depth 1
    for (const auto &[name, sup] : supMap) {
        if (depths.find(name) == depths.end())
            depths[name] = 1;
    }
}

/**
 * @brief Fetch objectClass schema definitions and compute hierarchy depths.
 *
 * @return OCSchemaInfo with depths and SUP map for type/superiority sorting.
 */
OCSchemaInfo loadOCSchema(LDAPConn &conn) {
    OCSchemaInfo info;
    auto rootDSE = conn.searchOne("", "(objectClass=*)", {"subschemaSubentry"}, false);
    auto subschemaDN = rootDSE.getAttr("subschemaSubentry");
    if (subschemaDN.empty()) return info;
    auto subschema = conn.searchOne(subschemaDN, "(objectClass=*)", {"objectClasses"}, false);
    auto allDefs = subschema.getAttrs("objectClasses");
    computeOCDepths(allDefs, info.depths, info.supMap);
    return info;
}

/**
 * @brief Display an LDAP entry's attributes in the panel.
 *
 * Builds sorted AttrRow list with the following sort order:
 *   1. objectClass always first
 *   2. Mandatory attributes (bold in UI)
 *   3. Regular attributes
 *   4. Operational attributes (italic in UI)
 *
 * Within each group, attributes are sorted alphabetically.
 * Schema attribute values (objectClasses, attributeTypes, etc.) are
 * sorted by OID. Multi-valued attributes with {N} prefix braces are
 * sorted numerically. Values beyond MAX_VISIBLE_VALS are collapsed
 * into a "[+N more]" toggle row.
 *
 * @param entry      The LDAP entry whose attributes to show.
 * @param mandatory  Set of attribute names that are mandatory per schema.
 * @param ocInfo     Optional objectClass schema info (supMap/depths from loadOCSchema).
 */
void AttrsWidget::show(const LDAPEntry &entry, const std::set<std::string> &mandatory,
                       const OCSchemaInfo *ocInfo) {
    entry_ = entry;
    rows_.clear();
    maxNameW_ = 0;

    // Prune collapsed_ entries that no longer exist in this entry
    for (auto it = collapsed_.begin(); it != collapsed_.end(); ) {
        if (entry.attributes.find(it->first) == entry.attributes.end())
            it = collapsed_.erase(it);
        else
            ++it;
    }

    // Build temporary rows grouped by attribute
    struct AttrGroup {
        std::vector<AttrRow> vals;
        bool op{false};
        bool mand{false};
    };
    std::map<std::string, AttrGroup> groups;
    std::vector<std::string> attrOrder;

    for (const auto &attrName : entry.attributeNames) {
        auto it = entry.attributes.find(attrName);
        if (it == entry.attributes.end()) continue;

        bool op = isOperationalAttr(attrName) ||
                  (attrSchema_ && attrSchema_->operational(lowerName(attrName)));
        bool mand = mandatory.count(attrName) > 0;

        const std::string lower = lowerName(attrName);
        // Base type (RFC 4512 §2.5.2) used for schema/formatting decisions.
        std::string baseType = lower;
        diratlas::ldapcore::AttributeDescription ad;
        if (diratlas::ldapcore::parseAttributeDescription(attrName, ad) && !ad.options.empty())
            baseType = ad.type;
        const auto bit = entry.binaryAttributes.find(attrName);
        const std::vector<std::vector<uint8_t>> &byteVals =
            (bit == entry.binaryAttributes.end()) ? emptyBytes : bit->second;

        // Per-value display strings (formatters expect lower-cased base type)
        std::vector<std::string> disp;
        if (ad.binary()) {
            // RFC 4512 §2.5.2: the ;binary option requests OCTET STRING
            // interpretation, so render every value as HEX bytes even when the
            // server returned a plain string.
            for (size_t vi = 0; vi < it->second.size(); ++vi) {
                const auto &bytes = (vi < byteVals.size()) ? byteVals[vi]
                    : std::vector<uint8_t>(it->second[vi].begin(), it->second[vi].end());
                disp.push_back("HEX{" + diratlas::ldapcore::bytesToHex(bytes) + "}");
            }
        } else if (flavor_ == LDAPFlavor::MicrosoftAD && diratlas::ad::isAdAttribute(baseType)) {
            disp = mergeAdEntries(diratlas::ad::formatAdAttribute(
                baseType, it->second, byteVals, kTuiTimeFormat, 0));
        } else {
            auto gen = diratlas::ldapcore::formatAttribute(baseType, it->second, byteVals, kTuiTimeFormat);
            for (const auto &g : gen)
                disp.push_back(g.formatted);
        }

        // RootDSE supported* attributes: append a short human description
        // for known OIDs / SASL mechanisms (rendered in a distinct colour).
        std::vector<size_t> noteOffsets;
        if (lower.rfind("supported", 0) == 0) {
            noteOffsets.resize(disp.size(), std::string::npos);
            for (size_t vi = 0; vi < disp.size() && vi < it->second.size(); ++vi) {
                std::string d = rootDseValueDesc(lower, it->second[vi]);
                if (!d.empty()) {
                    noteOffsets[vi] = disp[vi].size();
                    disp[vi] += d;
                }
            }
        }

        for (size_t vi = 0; vi < it->second.size(); ++vi) {
            AttrRow row;
            row.name = attrName;
            row.value = it->second[vi];
            row.operational = op;
            row.mandatory = mand;
            row.attrName = attrName;
            if (vi < noteOffsets.size())
                row.noteOffset = noteOffsets[vi];

            // Media attributes keep a compact label instead of the raw binary
            std::string showText;
            if (const char *label = mediaLabelFor(lower)) {
                size_t n = (vi < byteVals.size()) ? byteVals[vi].size() : row.value.size();
                if (n > 0) {
                    char buf[96];
                    std::snprintf(buf, sizeof(buf), "[%s, %zu bytes]", label, n);
                    showText = buf;
                }
            }
            if (showText.empty()) {
                showText = (vi < disp.size()) ? disp[vi] : row.value;
                if (showText == row.value) {
                    // Try base64 decoding for printable values
                    std::string dec = maybeDecodeBase64(row.value);
                    if (!dec.empty() && dec != row.value)
                        showText = "<b64> " + dec;
                }
                // The panel wraps by width, not by embedded newlines, so strip
                // any newlines/carriage returns from the display text (the full
                // decoded value with newlines is shown in the Enter popup).
                for (auto &c : showText)
                    if (c == '\n' || c == '\r') c = ' ';
                // Large untyped binary blobs collapse to a compact placeholder
                if (showText.compare(0, 4, "HEX{") == 0) {
                    size_t n = (vi < byteVals.size()) ? byteVals[vi].size() : row.value.size();
                    if (n > 1024) {
                        char buf[96];
                        std::snprintf(buf, sizeof(buf), "[octet-stream, %zu bytes]", n);
                        showText = buf;
                    }
                }
            }
            if (showText != row.value)
                row.display = showText;

            groups[baseType].vals.push_back(row);
            groups[baseType].op = op;
            groups[baseType].mand = mand;
        }
        if (!it->second.empty()) {
            bool seen = (std::find(attrOrder.begin(), attrOrder.end(), baseType) != attrOrder.end());
            if (!seen)
                attrOrder.push_back(baseType);
        }
    }

    // Show the full inherited SUP chain for each listed objectClass. Classes
    // not present in the attribute are marked "(implicit from <parent>)";
    // explicitly listed classes are shown without a marker.
    if (ocInfo && !ocInfo->supMap.empty() &&
        entry.attributes.count("objectClass") > 0) {
        std::set<std::string> listed;
        for (const auto &oc : entry.getAttrs("objectClass")) {
            std::string l;
            for (char c : oc) l += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            listed.insert(l);
        }
        std::set<std::string> shownImplicit;
        for (const auto &oc : entry.getAttrs("objectClass")) {
            std::string cur = oc;
            std::string parent;
            int guard = 0;
            while (guard++ < 32) {
                auto it = ocInfo->supMap.find(cur);
                if (it == ocInfo->supMap.end()) break;
                parent = it->second;
                std::string pl;
                for (char c : parent) pl += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                if (listed.count(pl)) break;   // parent is explicit; nothing implicit above it
                if (shownImplicit.count(pl)) break;
                shownImplicit.insert(pl);
                AttrRow row;
                row.name = "objectClass";
                row.value = parent;
                row.operational = true;
                row.attrName = "objectClass";
                row.display = parent + "  (implicit from " + cur + ")";
                groups["objectclass"].vals.push_back(row);
                cur = parent;
            }
        }
    }

    // Sort: objectClass first, then mandatory, then regular, then operational; alphabetically within each group
    std::sort(attrOrder.begin(), attrOrder.end(),
        [&](const std::string &a, const std::string &b) {
            // objectClass always first
            if (a == "objectClass") return true;
            if (b == "objectClass") return false;
            bool aMand = groups[a].mand;
            bool bMand = groups[b].mand;
            bool aOp = groups[a].op;
            bool bOp = groups[b].op;
            int catA = aMand ? 0 : (aOp ? 2 : 1);
            int catB = bMand ? 0 : (bOp ? 2 : 1);
            if (catA != catB) return catA < catB;
            return a < b;
        });

    // Sort schema attribute values by OID
    {
        auto extractOID = [](const std::string &val) -> std::string {
            auto p = val.find('(');
            if (p == std::string::npos) return "";
            p = val.find_first_not_of(" \t(", p);
            if (p == std::string::npos) return "";
            auto end = val.find_first_of(" \t", p);
            if (end == std::string::npos) return val.substr(p);
            return val.substr(p, end - p);
        };
        std::set<std::string> schemaAttrs = {
            "attributeTypes", "objectClasses", "matchingRules",
            "matchingRuleUse", "ldapSyntaxes", "dITContentRules",
            "dITStructureRules", "nameForms",
            "olcSchemaConfig", "olcAttributeTypes", "olcObjectClasses",
            "olcAccess", "olcLimits",
        };
        for (auto &[name, g] : groups) {
            if (schemaAttrs.count(name) && g.vals.size() > 1) {
                std::sort(g.vals.begin(), g.vals.end(),
                    [&](const AttrRow &a, const AttrRow &b) {
                        return extractOID(a.value) < extractOID(b.value);
                    });
            }
        }
    }

    // Sort values by {N} index for attributes with curly-brace numbering
    {
        auto extractBraceIdx = [](const std::string &val) -> int {
            auto p = val.find('{');
            if (p == std::string::npos) return 0;
            auto q = val.find('}', p);
            if (q == std::string::npos) return 0;
            try { return std::stoi(val.substr(p + 1, q - p - 1)); }
            catch (...) { return 0; }
        };
        for (auto &[name, g] : groups) {
            if (g.vals.size() > 1 && g.vals[0].value.find('{') == 0) {
                // At least the first value starts with {N} — sort all by brace index
                bool allBraced = true;
                for (const auto &v : g.vals) {
                    if (v.value.empty() || v.value[0] != '{') { allBraced = false; break; }
                }
                if (allBraced) {
                    std::sort(g.vals.begin(), g.vals.end(),
                        [&](const AttrRow &a, const AttrRow &b) {
                            return extractBraceIdx(a.value) < extractBraceIdx(b.value);
                        });
                }
            }
        }
    }

    // Sort objectClass values by hierarchy depth, root first (top-down):
    // top (0) → person (1) → organizationalPerson (2) → inetOrgPerson (3).
    // Implicit rows (value not directly in the entry) sort after their explicit
    // parent; unknowns sort last.
    {
        auto &g = groups["objectclass"];
        if (!g.vals.empty()) {
            std::stable_sort(g.vals.begin(), g.vals.end(),
                [&](const AttrRow &a, const AttrRow &b) {
                    int da = (ocInfo && !ocInfo->supMap.empty()) ? ocInfo->depth(a.value) : 99;
                    int db = (ocInfo && !ocInfo->supMap.empty()) ? ocInfo->depth(b.value) : 99;
                    if (da != db) return da < db;   // shallower class (root) first
                    return a.display < b.display;
                });
        }
    }

    // Flatten to rows: collapse multi-valued attrs when toggled
    for (const auto &attrName : attrOrder) {
        auto &g = groups[attrName];
        bool collapsed = (collapsed_.find(attrName) != collapsed_.end())
            ? collapsed_[attrName] : false;
        int n = static_cast<int>(g.vals.size());

        if (collapsed && n > 3) {
            // Only first 3 values + "[+N more]" toggle
            for (int i = 0; i < 3; i++) {
                rows_.push_back(g.vals[i]);
                maxNameW_ = std::max(maxNameW_, static_cast<int>(g.vals[i].name.size()));
            }
            AttrRow toggle;
            toggle.isToggle = true;
            toggle.attrName = attrName;
            toggle.numHidden = n - 3;
            toggle.name = attrName;
            toggle.value = "[+" + std::to_string(n - 3) + " more]";
            toggle.operational = g.op;
            toggle.mandatory = g.mand;
            rows_.push_back(toggle);
        } else {
            for (int i = 0; i < n; i++) {
                rows_.push_back(g.vals[i]);
                maxNameW_ = std::max(maxNameW_, static_cast<int>(g.vals[i].name.size()));
            }
        }
    }

    if (maxNameW_ > 25) maxNameW_ = 25;
    scrollOffset_ = 0;
    selected_ = 0;
}

/**
 * @brief Try to decode a base64 string. Only returns decoded text if it looks
 *        genuinely like base64 (padding, slashes, pluses) and decodes to readable text.
 */
static std::string maybeDecodeBase64(const std::string &val) {
    if (val.size() < 8 || val.size() % 4 != 0) return "";
    // Must only contain valid base64 characters
    int special = 0;
    for (char c : val) {
        if (c == '+' || c == '/') special++;
        else if (c == '=') { /* padding OK at end */ }
        else if (!isalnum(c)) return "";
    }
    // Only decode if there's at least one + or /, or has padding
    // (purely alphanumeric strings like passwords are NOT base64)
    bool hasPadding = (val.size() >= 2 && val[val.size()-1] == '=');
    if (special == 0 && !hasPadding) return "";

    static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::vector<int> rev(256, -1);
    for (int i = 0; i < 64; i++) rev[static_cast<int>(b64[i])] = i;

    std::string dec;
    int buf = 0, bits = 0;
    for (char c : val) {
        if (c == '=') break;
        int v = rev[static_cast<unsigned char>(c)];
        if (v < 0) return "";
        buf = (buf << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            dec += static_cast<char>((buf >> bits) & 0xFF);
        }
    }
    // Check result is printable and doesn't look like garbage.
    // UTF-8 multi-byte text (bytes >= 0x80) is treated as printable so
    // decoded config files with accents (e.g. pwdCheckModuleArg) pass.
    if (dec.empty()) return "";
    int printable = 0;
    for (unsigned char c : dec) {
        if (c >= 32 || c == '\n' || c == '\t' || c == '\r') printable++;
        else return "";  // binary control byte -> not text
    }
    // At least 80% must be printable ASCII (reject binary garbage)
    if (printable * 5 < static_cast<int>(dec.size()) * 4) return "";
    return dec;
}

/** @brief True for attributes whose values are schema/config definitions
 * (subschema attributeTypes/objectClasses, cn=config olc*, ppolicy module
 * args) where syntax highlighting is meaningful. Plain data attributes
 * (descriptions, cn, o, ...) must not be highlighted: the tokeniser colours
 * uppercase words and brackets red, which is wrong for free text. */
static bool isSchemaLikeAttr(const std::string &name) {
    if (name.rfind("olc", 0) == 0) return true;
    static const std::set<std::string> s = {
        "objectclasses", "attributetypes", "ldapsyntaxes",
        "matchingrules", "matchingruleuse", "nameforms",
        "ditcontentrules", "ditstructurerules", "structuralobjectclass",
        "governingstructurerule", "dependson",
        "pwdcheckmodulearg",
    };
    return s.count(name) > 0;
}

/**
 * @brief Tokenise and syntax-highlight a schema definition value.
 *
 * Parsed tokens:
 *   - Parentheses     → dim dark red
 *   - Quoted strings  → green
 *   - OIDs (digits)   → bold green (CP_ATTR_TIME_NEW)
 *   - UPPERCASE keywords → bold dark red (CP_ATTR_TIME_VERY_OLD)
 *   - Known config keywords (to, by, dn, attrs, filter, etc.) → bold dark red
 *   - Dollar sign ($) → bold with CP_ATTR_OP
 */
static void drawSchemaValue(WINDOW *win, int y, int x, int maxW,
                             const std::string &val, int defaultColor, attr_t defaultAttr) {
    // Tokenize: OIDs, keywords, quoted strings, parens, punctuation
    size_t i = 0;
    int cx = x;
    while (i < val.size() && cx < x + maxW) {
        // Skip whitespace
        if (val[i] == ' ' || val[i] == '\t') {
            int ws = 0;
            while (i + ws < val.size() && (val[i + ws] == ' ' || val[i + ws] == '\t'))
                ws++;
            if (cx + ws > x + maxW) ws = x + maxW - cx;
            cx += ws;
            i += ws;
            continue;
        }

        int color = defaultColor;
        attr_t attr = defaultAttr;
        int len = 1;

        // Multi-byte UTF-8 characters are emitted whole so non-ASCII values
        // (e.g. description;lang-* in Cyrillic/Greek) are never split.
        if (static_cast<unsigned char>(val[i]) >= 0x80) {
            int ulen = 0;
            utf8Decode(val, i, &ulen);
            len = ulen;
        }
        // Parentheses, curly braces, square brackets
        else if (val[i] == '(' || val[i] == ')' ||
            val[i] == '{' || val[i] == '}' ||
            val[i] == '[' || val[i] == ']') {
            color = CP_ATTR_TIME_VERY_OLD;
            attr = A_DIM;
            len = 1;
        }
        // Quoted string
        else if (val[i] == '\'' || val[i] == '"') {
            char q = val[i];
            color = CP_STATUS_OK;
            attr = A_NORMAL;
            auto end = val.find(q, i + 1);
            len = (end != std::string::npos) ? static_cast<int>(end - i + 1)
                                             : static_cast<int>(val.size() - i);
        }
        // OID (digit sequence)
        else if (val[i] >= '0' && val[i] <= '9') {
            color = CP_ATTR_TIME_NEW;
            attr = A_BOLD;
            auto end = val.find_first_not_of("0123456789.", i);
            len = (end != std::string::npos) ? static_cast<int>(end - i)
                                             : static_cast<int>(val.size() - i);
        }
        // Word (any letter, digit, dot, or dash) — check for uppercase keyword or known config keyword
        else if (isalnum(val[i]) || val[i] == '.' || val[i] == '-') {
            auto end = val.find_first_of(" \t(){}[]\",", i);
            if (end == std::string::npos) end = val.size();
            len = static_cast<int>(end - i);
            std::string word = val.substr(i, len);
            // Numeric-only "words" (OIDs or wrapped continuation like ".115.1")
            // are green, never red.
            bool hasLetter = false;
            for (char c : word)
                if (std::isalpha(static_cast<unsigned char>(c))) { hasLetter = true; break; }
            if (!hasLetter) {
                color = CP_ATTR_TIME_NEW;
                attr = A_BOLD;
            } else {
            bool allUpper = true;
            for (char c : word) { if (islower(c)) { allUpper = false; break; } }
            if (allUpper) {
                color = CP_ATTR_TIME_VERY_OLD;
                attr = A_BOLD;
            } else {
                // Known lowercase config keywords (olcAccess, olcLimits, etc.)
                static const std::set<std::string> kw = {
                    "to", "by", "dn", "dn.exact", "dn.base", "dn.one",
                    "dn.subtree", "dn.children", "attrs", "filter",
                    "self", "anonymous", "users", "peers", "sockurl",
                    "none", "auth", "read", "write", "manage",
                    "break", "continue", "stop",
                    "size", "time", "size.unlimited", "time.unlimited",
                    "soft", "hard",
                    "set", "expand", "domain", "host",
                    // Boolean / config values
                    "TRUE", "FALSE", "true", "false", "yes", "no",
                    "on", "off", "enabled", "disabled",
                    "unlimited", "unrestricted",
                    "normal", "never", "instant",
                    "local", "remote", "proxy", "sasl", "simple",
                    "max", "min", "default",
                };
                // Also highlight dotted keywords (e.g. "soft=" prefix)
                if (word.back() == '=' || word.back() == '{') {
                    std::string base = word.substr(0, word.size() - 1);
                    if (kw.count(base)) {
                        color = CP_ATTR_TIME_VERY_OLD;
                        attr |= A_BOLD;
                    }
                }
                if (kw.count(word)) {
                    color = CP_ATTR_TIME_VERY_OLD;
                    attr |= A_BOLD;
                }
            }
            }
        }
        // Dollar sign (MUST/MAY separator)
        else if (val[i] == '$') {
            color = CP_ATTR_OP;
            attr = A_BOLD;
            len = 1;
        }

        if (len > maxW - (cx - x))
            len = maxW - (cx - x);

        if (len > 0) {
            wattron(win, COLOR_PAIR(color) | attr);
            if (len == 1) {
                mvwaddch(win, y, cx, val[i]);
                cx++;
            } else {
                mvwaddstr(win, y, cx, val.substr(i, static_cast<size_t>(len)).c_str());
                cx += utf8Width(val.substr(i, static_cast<size_t>(len)));
            }
            wattroff(win, COLOR_PAIR(color) | attr);
            i += len;
        } else {
            i++;
        }
    }
    }

/**
 * @brief Render the attributes panel into an ncurses window.
 *
 * Layout:
 *   Row 0: column headers ("Attribute" / "Value")
 *   Row 1+: attribute rows with word-wrapped values
 *
 * Features:
 *   - Attribute/value columns with configurable width
 *   - Word-wrapping for long values
 *   - Auto-collapse multi-valued attributes when they exceed available height
 *   - Schema syntax highlighting via drawSchemaValue()
 *   - Timestamp colouring based on recency
 *   - Search mode indicator at bottom
 *   - Full-row cursor highlight for selected row
 */
void AttrsWidget::draw(WINDOW *win, bool focused) {
    werase(win);
    int maxY, maxX;
    getmaxyx(win, maxY, maxX);

    // Column headers — blue underline style, NOT reverse (to avoid confusion with selection)
    if (maxY > 0 && maxX > 5) {
        wattron(win, COLOR_PAIR(CP_HEADER) | A_BOLD);
        std::string hdr = " Attribute";
        mvwaddstr(win, 0, 0, hdr.c_str());
        int valCol = maxNameW_ + 2;
        if (valCol < 12) valCol = 12;
        if (valCol < maxX) {
            for (int x = hdr.size(); x < valCol; x++)
                mvwaddch(win, 0, x, ' ');
            wattron(win, COLOR_PAIR(CP_HEADER));
            mvwaddstr(win, 0, valCol, "Value");
        }
        wattroff(win, COLOR_PAIR(CP_HEADER) | A_BOLD);
    }

    int nameW = maxNameW_;
    if (nameW < 10) nameW = 10;
    if (nameW > maxX / 2) nameW = maxX / 2;
    int valW = maxX - nameW - 2;
    if (valW < 5) valW = 5;

    // Build visual line mapping for word-wrap
    struct VInfo { int vstart; int vlines; };
    std::vector<VInfo> vinfo;
    int totalV;
    {
        int v = 0;
        for (const auto &r : rows_) {
            int lines = 1;
            if (!r.isToggle && valW > 10)
                lines = static_cast<int>(utf8Wrap(displayOf(r), valW).size());
            vinfo.push_back({v, lines});
            v += lines;
        }
        totalV = v;
    }

    int dataH = maxY - 1;
    if (dataH < 0) dataH = 0;

    // Clamp selected_ to AttrRow range, map to visual line
    if (selected_ >= static_cast<int>(rows_.size())) selected_ = 0;
    int selV = (selected_ < static_cast<int>(vinfo.size())) ? vinfo[selected_].vstart : 0;

    // dataH is already set above from auto-collapse check

    // Scroll in visual line space — keep selection visible
    int scrollMaxV = std::max(0, totalV - dataH);
    if (scrollOffset_ > scrollMaxV && scrollMaxV >= 0) scrollOffset_ = scrollMaxV;
    if (scrollOffset_ < 0) scrollOffset_ = 0;
    if (selV < scrollOffset_) scrollOffset_ = selV;
    if (selV >= scrollOffset_ + dataH && dataH > 0)
        scrollOffset_ = std::max(0, selV - dataH + 1);
    // Clamp to valid range
    if (scrollOffset_ > scrollMaxV && scrollMaxV >= 0) scrollOffset_ = scrollMaxV;
    if (scrollOffset_ < 0) scrollOffset_ = 0;

    int y = 1;
    for (int i = 0; i < static_cast<int>(rows_.size()) && y < maxY; i++) {
        const auto &row = rows_[i];
        int nlines = vinfo[i].vlines;
        bool sel = (selected_ == i && focused);

        // Build styles once
        int nameColor = CP_ATTR_NAME;
        attr_t nameAttr = A_NORMAL;
        int valColor = CP_ATTR_VALUE;
        attr_t valAttr = A_NORMAL;

        if (row.isToggle) {
            nameColor = CP_ATTR_OP;
            valColor = CP_ATTR_NAME;
            valAttr = A_BOLD;
        } else {
            if (row.operational) {
                nameAttr = A_ITALIC;
                if (row.name == "contextCSN" || row.name == "entryCSN") {
                    valColor = CP_ATTR_REPL;
                    valAttr = A_NORMAL;
                } else {
                    valColor = CP_ATTR_OP;
                    valAttr = A_ITALIC;
                }
            }
            if (row.mandatory) { nameAttr |= A_BOLD; valAttr |= A_BOLD; }
            if (!row.operational && isTimestampAttr(row.name)) {
                valColor = timestampColor(row.name, row.value);
                // Recent timestamps render bold green ("light green") so they
                // stay distinct from the plain green operational values.
                if (valColor == CP_ATTR_TIME_NEW) valAttr |= A_BOLD;
            }
            // objectClass rows (explicit + implicit SUP chain) share one colour.
            if (row.attrName == "objectClass") valColor = CP_ATTR_OC;
        }

        bool matchSearch = !searchStr_.empty() && !row.isToggle
            && (displayOf(row).find(searchStr_) != std::string::npos
             || row.name.find(searchStr_) != std::string::npos);
        bool useSyntaxHL = !row.isToggle && !matchSearch && isSchemaLikeAttr(lowerName(row.name));

        for (int L = 0; L < nlines && y < maxY; L++) {
            int v = vinfo[i].vstart + L;
            if (v < scrollOffset_ || v >= scrollOffset_ + dataH) continue;

            // Attribute name with full-row highlight when selected
            if (L == 0) {
                if (sel && focused) {
                    // Highlight entire name area with cursor colors
                    wattron(win, COLOR_PAIR(CP_TREE_CURSOR) | A_BOLD);
                    mvwaddch(win, y, 0, '>');
                    std::string nm = row.isToggle ? "" : row.name;
                    if (static_cast<int>(nm.size()) > nameW - 1)
                        nm = nm.substr(0, nameW - 1);
                    mvwaddstr(win, y, 1, nm.c_str());
                    // Fill remaining name area with cursor background
                    for (int c = 1 + static_cast<int>(nm.size()); c < nameW; c++)
                        mvwaddch(win, y, c, ' ');
                    wattroff(win, COLOR_PAIR(CP_TREE_CURSOR) | A_BOLD);
                } else {
                    mvwaddch(win, y, 0, ' ');
                    wattron(win, COLOR_PAIR(nameColor) | nameAttr);
                    std::string nm = row.isToggle ? "" : row.name;
                    if (static_cast<int>(nm.size()) > nameW - 1)
                        nm = nm.substr(0, nameW - 1);
                    mvwaddstr(win, y, 1, nm.c_str());
                    wattroff(win, COLOR_PAIR(nameColor) | nameAttr);
                }
            }

            // Value segment for this wrapped line
            const std::string &showText = displayOf(row);
            auto segs = utf8Wrap(showText, valW);
            std::string seg = (L < static_cast<int>(segs.size())) ? segs[L] : std::string();

            // Byte offset of this segment inside showText (segments are
            // consecutive substrings of showText).
            size_t segOff = 0;
            for (int k = 0; k < L && k < static_cast<int>(segs.size()); k++)
                segOff += segs[k].size();
            size_t noteOff = row.noteOffset;

            if (useSyntaxHL && !seg.empty()) {
                drawSchemaValue(win, y, nameW + 2, valW, seg, valColor, valAttr);
            } else if (noteOff != std::string::npos && !seg.empty() && segOff + seg.size() > noteOff) {
                // The value carries an annotated note (e.g. supported* OID
                // description): render the note in a distinct colour.
                size_t cut = (noteOff > segOff) ? noteOff - segOff : 0;
                std::string vpart = (cut < seg.size()) ? seg.substr(0, cut) : seg;
                std::string npart = (cut < seg.size()) ? seg.substr(cut) : "";
                if (!vpart.empty()) {
                    wattron(win, COLOR_PAIR(valColor) | valAttr);
                    mvwaddstr(win, y, nameW + 2, vpart.c_str());
                    wattroff(win, COLOR_PAIR(valColor) | valAttr);
                }
                if (!npart.empty()) {
                    wattron(win, COLOR_PAIR(CP_ATTR_TIME_OLD) | A_NORMAL);
                    mvwaddstr(win, y, nameW + 2 + utf8Width(vpart), npart.c_str());
                    wattroff(win, COLOR_PAIR(CP_ATTR_TIME_OLD) | A_NORMAL);
                }
            } else {
                if (matchSearch) { valColor = CP_STATUS_OK; valAttr |= A_BOLD; }
                wattron(win, COLOR_PAIR(valColor) | valAttr);
                if (!seg.empty())
                    mvwaddstr(win, y, nameW + 2, seg.c_str());
                wattroff(win, COLOR_PAIR(valColor) | valAttr);
            }
            y++;
        }
    }

    // Draw search mode indicator
    if (searchMode_) {
        int sx, sy;
        getmaxyx(win, sy, sx);
        wattron(win, COLOR_PAIR(CP_TREE_CURSOR));
        std::string hint = " Search: " + searchStr_ + "_";
        if (static_cast<int>(hint.size()) > sx - 2)
            hint = hint.substr(0, sx - 5) + "...";
        mvwaddstr(win, sy - 1, 0, hint.c_str());
        wattroff(win, COLOR_PAIR(CP_TREE_CURSOR));
    }

    // Draw edit mode indicator and inline editor
    if (editMode_) {
        int sx, sy;
        getmaxyx(win, sy, sx);
        std::string attrHint = (editRow_ >= 0 && editRow_ < static_cast<int>(rows_.size()))
            ? rows_[editRow_].name : "";
        std::string prefix = " Edit " + attrHint + ": ";

        // Draw the entire edit line with reverse video
        wattron(win, COLOR_PAIR(CP_MENU_ACTIVE) | A_BOLD);
        mvwaddstr(win, sy - 1, 0, prefix.c_str());

        // Draw characters before cursor
        int cx = static_cast<int>(prefix.size());
        int i = 0;
        for (; i < editPos_ && cx < sx - 1; i++, cx++)
            mvwaddch(win, sy - 1, cx, editStr_[i]);

        // Blinking cursor at editPos_
        if (cx < sx - 1) {
            char cursorCh = (i < static_cast<int>(editStr_.size())) ? editStr_[i] : ' ';
            wattron(win, A_BLINK | A_REVERSE);
            mvwaddch(win, sy - 1, cx, cursorCh);
            wattroff(win, A_BLINK | A_REVERSE);
            cx++;
            i++;
        }

        // Remaining characters after cursor
        for (; i < static_cast<int>(editStr_.size()) && cx < sx - 1; i++, cx++)
            mvwaddch(win, sy - 1, cx, editStr_[i]);

        // Clear rest of line
        for (; cx < sx; cx++)
            mvwaddch(win, sy - 1, cx, ' ');

        wattroff(win, COLOR_PAIR(CP_MENU_ACTIVE) | A_BOLD);
        wmove(win, sy - 1, static_cast<int>(prefix.size() + editPos_));
        curs_set(1);
        leaveok(win, FALSE);
    } else {
        curs_set(0);
    }
}

/// @brief Save the current selection position before a toggle expand/collapse, so it can be restored.
void AttrsWidget::saveTogglePos() {
    toggleAttr_.clear();
    toggleOffset_ = 0;
    if (selected_ < 0 || selected_ >= static_cast<int>(rows_.size())) return;
    toggleAttr_ = rows_[selected_].isToggle ? rows_[selected_].attrName : rows_[selected_].name;
    // Count how many rows of this attr are above selected_ (for multi-valued)
    toggleOffset_ = 0;
    for (int i = selected_ - 1; i >= 0; i--) {
        if (rows_[i].name == toggleAttr_ && !rows_[i].isToggle)
            toggleOffset_++;
        else if (rows_[i].name != toggleAttr_)
            break;
    }
}

/// @brief Restore the selection position saved by saveTogglePos() after toggling.
void AttrsWidget::restoreTogglePos() {
    if (toggleAttr_.empty()) return;
    // Find position of toggleAttr_ and apply offset
    int count = 0;
    for (int i = 0; i < static_cast<int>(rows_.size()); i++) {
        if (rows_[i].name == toggleAttr_ && !rows_[i].isToggle) {
            if (count == toggleOffset_) {
                selected_ = i;
                return;
            }
            count++;
        }
    }
    // Fallback: find the first occurrence
    for (int i = 0; i < static_cast<int>(rows_.size()); i++) {
        if (rows_[i].name == toggleAttr_) {
            selected_ = i;
            return;
        }
    }
}

/**
 * @brief Process keyboard input for the attributes panel.
 *
 * In search mode: typing builds a search string, Enter/Escape exits.
 * Otherwise:
 *   Up/Down      → navigate rows
 *   PgUp/PgDn    → jump 10 rows
 *   Enter        → toggle collapsed values, or navigate to a DN value
 *   /            → enter search-in-value mode
 *
 * When Enter is pressed on a value that looks like a DN (contains '=' and ','),
 * goToDN_ is set for the app to navigate the tree to that DN.
 *
 * @param ch Key code from wgetch().
 * @return true if the key was consumed, false otherwise.
 */
bool AttrsWidget::handleKey(int ch) {
    // Edit mode: type to edit value
    if (editMode_) {
        if (ch == '\n' || ch == '\r' || ch == KEY_ENTER) {
            editMode_ = false;
            goToDN_ = "CONFIRM:" + editStr_ + "|" + editOrig_ + "|" + rows_[editRow_].name;
            return true;
        }
        if (ch == 27) { editMode_ = false; return true; }
        if (ch == KEY_LEFT) {
            if (editPos_ > 0) editPos_--;
            return true;
        }
        if (ch == KEY_RIGHT) {
            if (editPos_ < static_cast<int>(editStr_.size())) editPos_++;
            return true;
        }
        if (ch == KEY_HOME) { editPos_ = 0; return true; }
        if (ch == KEY_END) { editPos_ = static_cast<int>(editStr_.size()); return true; }
        if (ch == KEY_DC) {
            if (editPos_ < static_cast<int>(editStr_.size()))
                editStr_.erase(editPos_, 1);
            return true;
        }
        if (ch == KEY_BACKSPACE || ch == 127 || ch == 8) {
            if (editPos_ > 0) {
                editStr_.erase(editPos_ - 1, 1);
                editPos_--;
            }
            return true;
        }
        if (ch >= 32 && ch <= 126) {
            editStr_.insert(editPos_, 1, static_cast<char>(ch));
            editPos_++;
            return true;
        }
        return true;
    }

    // Search mode: type to build search string
    if (searchMode_) {
        if (ch == '\n' || ch == '\r' || ch == KEY_ENTER || ch == 27) {
            setSearchMode(false);
            return true;
        }
        if (ch == KEY_BACKSPACE || ch == 127 || ch == 8) {
            if (!searchStr_.empty()) searchStr_.pop_back();
            return true;
        }
        if (ch >= 32 && ch <= 126) {
            searchStr_ += static_cast<char>(ch);
            return true;
        }
        return true;
    }

    switch (ch) {
    case KEY_UP:
        if (selected_ > 0)
            selected_--;
        return true;
    case KEY_DOWN:
        if (selected_ + 1 < static_cast<int>(rows_.size()))
            selected_++;
        return true;
    case KEY_PPAGE:
        if (selected_ > 10)
            selected_ -= 10;
        else
            selected_ = 0;
        return true;
    case KEY_NPAGE:
        if (selected_ + 10 < static_cast<int>(rows_.size()))
            selected_ += 10;
        else
            selected_ = static_cast<int>(rows_.size()) - 1;
        return true;
    case '\n':
    case '\r':
    case KEY_ENTER:
        if (selected_ >= 0 && selected_ < static_cast<int>(rows_.size())) {
            // Toggle collapse/expand
            if (rows_[selected_].isToggle) {
                saveTogglePos();
                const std::string &an = rows_[selected_].attrName;
                bool cur = (collapsed_.find(an) != collapsed_.end()) ? collapsed_[an] : false;
                collapsed_[an] = !cur;
                show(entry_);
                restoreTogglePos();
                return true;
            }
            // If the raw value is base64 that decodes to readable text, open
            // a popup with the decoded content (e.g. pwdCheckModuleArg).
            const std::string &val = rows_[selected_].value;
            std::string dec = maybeDecodeBase64(val);
            if (!dec.empty() && dec != val) {
                goToDN_ = "VIEWB64:" + rows_[selected_].name + "|" + dec;
                return true;
            }
            // Values with embedded newlines, or that wrap beyond the visible
            // panel, open a full-content popup with a scrollbar.
            const std::string &disp = displayOf(rows_[selected_]);
            int valW = std::max(10, COLS - maxNameW_ - 4);
            int visibleLines = std::max(5, LINES - 8);
            int needLines = (static_cast<int>(disp.size()) + valW - 1) / valW;
            if (needLines > visibleLines || val.find('\n') != std::string::npos) {
                // Prefer the raw value when it is readable text (keeps embedded
                // newlines); fall back to the formatted display for HEX/binary.
                bool rawIsText = !val.empty();
                for (unsigned char c : val)
                    if (c < 0x20 && c != '\n' && c != '\r' && c != '\t') { rawIsText = false; break; }
                goToDN_ = "VIEWFULL:" + rows_[selected_].name + "|" + (rawIsText ? val : disp);
                return true;
            }
            // If value looks like a DN, load that entry
            if (val.find('=') != std::string::npos && val.find(',') != std::string::npos) {
                goToDN_ = val;
                return true;
            }
        }
        return false;
    case '-':
    case '_':
        // Collapse the selected multi-valued attribute (hide all but first 3 values)
        if (selected_ >= 0 && selected_ < static_cast<int>(rows_.size())) {
            const std::string &an = rows_[selected_].name;
            if (!an.empty()) {
                collapsed_[an] = true;
                show(entry_);
                return true;
            }
        }
        return false;
    case '+':
    case '=':
        // Expand the selected collapsed attribute
        if (selected_ >= 0 && selected_ < static_cast<int>(rows_.size())) {
            const std::string &an = rows_[selected_].name;
            if (!an.empty() && collapsed_.find(an) != collapsed_.end() && collapsed_[an]) {
                collapsed_[an] = false;
                show(entry_);
                return true;
            }
        }
        return false;
    default:
        return false;
    }
}

/**
 * @brief Determine if an attribute is operational (server-generated metadata).
 *
 * Includes standard LDAP operational attrs, AD-specific msDS-*,
 * Exchange msExch*, entryCSN, and contextCSN.
 */
bool isOperationalAttr(const std::string &name) {
    static const char *ops[] = {
        "createTimestamp", "modifyTimestamp",
        "creatorsName", "modifiersName",
        "entryDN", "entryUUID",
        "subschemaSubentry",
        "hasSubordinates", "numSubordinates",
        "structuralObjectClass",
        "governingStructureRule",
        "pwdChangedTime", "pwdAccountLockedTime",
        "memberOf",
        "ldapSyntaxes", "matchingRules",
        "matchingRuleUse", "attributeTypes",
        "objectClasses", "dITContentRules",
        "dITStructureRules", "nameForms",
        "supportedControl", "supportedExtension",
        "supportedFeatures", "supportedCapabilities",
        "supportedLDAPVersion", "supportedSASLMechanisms",
        "namingContexts", "altServer",
        "vendorName", "vendorVersion",
        "monitorContext",
        nullptr
    };
    for (int i = 0; ops[i]; i++) {
        if (name == ops[i]) return true;
    }
    if (name == "entryCSN") return true;
    if (name == "contextCSN") return true;
    if (name.rfind("msDS-", 0) == 0) return true;
    if (name.rfind("msExch", 0) == 0) return true;
    return false;
}

bool AttrSchemaInfo::singleValue(const std::string &lowerType) const {
    auto it = defs.find(lowerType);
    if (it == defs.end()) return false;  // unknown -> assume multi-valued (prudent)
    // SINGLE-VALUE is a keyword token in the attributeType definition.
    return it->second.find("SINGLE-VALUE") != std::string::npos ||
           it->second.find("SINGLE VALUE") != std::string::npos;
}

bool AttrSchemaInfo::noUserModification(const std::string &lowerType) const {
    auto it = defs.find(lowerType);
    if (it == defs.end()) return false;  // unknown -> assume user-modifiable (prudent)
    return it->second.find("NO-USER-MODIFICATION") != std::string::npos ||
           it->second.find("NO-USER-MODIFICATION ") != std::string::npos;
}

bool AttrSchemaInfo::operational(const std::string &lowerType) const {
    auto it = defs.find(lowerType);
    if (it == defs.end()) return false;
    const std::string &d = it->second;
    return d.find("USAGE directoryOperation") != std::string::npos ||
           d.find("USAGE distributedOperation") != std::string::npos ||
           d.find("USAGE dSAOperation") != std::string::npos;
}

AttrSchemaInfo loadAttrSchema(LDAPConn &conn) {
    AttrSchemaInfo info;
    auto rootDSE = conn.searchOne("", "(objectClass=*)", {"subschemaSubentry"}, false);
    std::string subschemaDN = rootDSE.getAttr("subschemaSubentry");
    if (subschemaDN.empty()) return info;
    auto subschema = conn.searchOne(subschemaDN, "(objectClass=*)", {"attributeTypes"}, false);
    auto allDefs = subschema.getAttrs("attributeTypes");
    for (const auto &def : allDefs) {
        // Extract the NAME 'x' (or NAME "x") — first occurrence after the OID.
        size_t namePos = def.find(" NAME '");
        char quote = '\'';
        if (namePos == std::string::npos) {
            namePos = def.find(" NAME \"");
            quote = '"';
        }
        if (namePos == std::string::npos) continue;
        namePos += 7;  // skip " NAME '"
        size_t nameEnd = def.find(quote, namePos);
        if (nameEnd == std::string::npos) continue;
        std::string name = def.substr(namePos, nameEnd - namePos);
        if (name.empty()) continue;
        std::string lower;
        for (char c : name)
            lower += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        info.defs[lower] = def;
    }
    return info;
}

} // namespace diratlas::tui
