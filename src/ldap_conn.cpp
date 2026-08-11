// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Manuel FLURY
//
// This file is part of DirAtlas — an LDAP Directory Explorer.
//
// Licensed under the GNU Affero General Public License v3.0
// (https://www.gnu.org/licenses/agpl-3.0.txt).
//
// Originally based on godap (github.com/Macmod/godap) — MIT license.

#include "ldap_conn.h"
#include "formats.h"
#include <cstring>
#include <sstream>
#include <algorithm>
#include <lber.h>

namespace diratlas {

// ── LDAPEntry implementation ─────────────────────────────

std::string LDAPEntry::getAttr(const std::string &name) const {
    auto it = attributes.find(name);
    if (it != attributes.end() && !it->second.empty())
        return it->second[0];
    return "";
}

std::vector<std::string> LDAPEntry::getAttrs(const std::string &name) const {
    auto it = attributes.find(name);
    if (it != attributes.end()) return it->second;
    return {};
}

std::vector<uint8_t> LDAPEntry::getRawAttr(const std::string &name) const {
    auto it = binaryAttributes.find(name);
    if (it != binaryAttributes.end() && !it->second.empty())
        return it->second[0];
    return {};
}

std::vector<std::vector<uint8_t>> LDAPEntry::getRawAttrs(const std::string &name) const {
    auto it = binaryAttributes.find(name);
    if (it != binaryAttributes.end()) return it->second;
    return {};
}

// ── LDAPConn: Construction / Destruction ────────────────

LDAPConn::LDAPConn() {}

LDAPConn::~LDAPConn() {
    if (ld) {
        ldap_unbind_ext(ld, nullptr, nullptr);
    }
}

// ── Static Helpers ──────────────────────────────────────

/** @brief Escape special characters for use in LDAP filters. */
std::string LDAPConn::escapeFilter(const std::string &filter) {
    std::string result;
    for (char c : filter) {
        switch (c) {
            case '*': result += "\\2a"; break;
            case '(': result += "\\28"; break;
            case ')': result += "\\29"; break;
            case '\\': result += "\\5c"; break;
            case '\0': result += "\\00"; break;
            default: result += c;
        }
    }
    return result;
}

/** @brief Build a filter searching by sAMAccountName (non-DN) or distinguishedName (DN). */
std::string LDAPConn::samOrDN(const std::string &object, bool &isSam) {
    isSam = (object.find('=') == std::string::npos);
    if (isSam) {
        return "(sAMAccountName=" + escapeFilter(object) + ")";
    }
    return "(distinguishedName=" + escapeFilter(object) + ")";
}

std::string LDAPConn::cnUidOrDN(const std::string &object, bool &isCnOrUid) {
    isCnOrUid = (object.find('=') == std::string::npos);
    auto escaped = escapeFilter(object);
    if (isCnOrUid) {
        return "(|(cn=" + escaped + ")(uid=" + escaped + "))";
    }
    return "(entryDN=" + escaped + ")";
}

/** @brief Auto-choose the best query filter based on identifier format and server flavour. */
std::string LDAPConn::guessQueryFilter(const std::string &identifier, LDAPFlavor flavor) {
    bool unused;
    if (flavor == LDAPFlavor::MicrosoftAD) {
        return samOrDN(identifier, unused);
    }
    return cnUidOrDN(identifier, unused);
}

// ── Connection ──────────────────────────────────────────

/**
 * @brief Initialise the LDAP session and apply connection options.
 *
 * Flow:
 *   1. Unbind any previous session.
 *   2. ldap_initialize() with the given URI.
 *   3. Set protocol version to LDAPv3.
 *   4. Apply TLS options from tlsOpts (CA cert, cert, key, reqcert).
 *   5. If insecure, force LDAP_OPT_X_TLS_NEVER.
 *   6. Disable async connection.
 *
 * @param uri         LDAP URI (ldap://, ldaps://, ldapi://).
 * @param insecure    Skip TLS verification when true.
 * @param socksProxy  SOCKS proxy address (currently unused by libldap).
 * @return true on success, false on failure.
 */
bool LDAPConn::connect(const std::string &uri,
                        bool insecure, const std::string &socksProxy) {
    if (ld) {
        ldap_unbind_ext(ld, nullptr, nullptr);
        ld = nullptr;
    }

    int rc = ldap_initialize(&ld, uri.c_str());
    if (rc != LDAP_SUCCESS) {
        ld = nullptr;
        lastError = ldap_err2string(rc);
        return false;
    }

    rc = ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &ldapVersion);
    if (rc != LDAP_OPT_SUCCESS) return false;

    if (debug_) {
        ldap_set_option(ld, LDAP_OPT_DEBUG_LEVEL, &debug_);
    }

    // Set a global timeout for all operations
    { struct timeval tv = {timelimit > 0 ? timelimit : 10, 0};
      ldap_set_option(ld, LDAP_OPT_TIMEOUT, &tv); }

    // Apply TLS options from ldaprc
    if (!tlsOpts.cacert.empty())
        ldap_set_option(ld, LDAP_OPT_X_TLS_CACERTFILE, tlsOpts.cacert.c_str());
    if (!tlsOpts.cacertdir.empty())
        ldap_set_option(ld, LDAP_OPT_X_TLS_CACERTDIR, tlsOpts.cacertdir.c_str());
    if (!tlsOpts.cert.empty())
        ldap_set_option(ld, LDAP_OPT_X_TLS_CERTFILE, tlsOpts.cert.c_str());
    if (!tlsOpts.key.empty())
        ldap_set_option(ld, LDAP_OPT_X_TLS_KEYFILE, tlsOpts.key.c_str());
    if (tlsOpts.reqcert >= 0)
        ldap_set_option(ld, LDAP_OPT_X_TLS_REQUIRE_CERT, &tlsOpts.reqcert);

    if (insecure) {
        int val = LDAP_OPT_X_TLS_NEVER;
        ldap_set_option(ld, LDAP_OPT_X_TLS_REQUIRE_CERT, &val);
    }

    int async = 0;
    ldap_set_option(ld, LDAP_OPT_CONNECT_ASYNC, &async);

    connected = true;
    return true;
}

/** @brief Set alias dereferencing option on the LDAP handle. */
bool LDAPConn::setDeref(int deref) {
    if (!ld) return false;
    return ldap_set_option(ld, LDAP_OPT_DEREF, &deref) == LDAP_OPT_SUCCESS;
}

/** @brief Initiate StartTLS on the connected session. */
bool LDAPConn::startTLS() {
    if (!ld) return false;
    lastErrno = 0;
    lastError.clear();
    int rc = ldap_start_tls_s(ld, nullptr, nullptr);
    lastErrno = rc;
    lastError = formatError(rc, ld);
    return rc == LDAP_SUCCESS;
}

// ── Authentication ──────────────────────────────────────

bool LDAPConn::bind(const std::string &username, const std::string &password) {
    return simpleBind(username, password);
}

// Retrieve the LDAP diagnostic message (additional error info from the server)
/** @brief Retrieve the LDAP diagnostic message (extra error info from the server). */
static std::string getDiagMsg(LDAP *ld) {
    if (!ld) return "";
    char *msg = nullptr;
    ldap_get_option(ld, LDAP_OPT_DIAGNOSTIC_MESSAGE, &msg);
    std::string result;
    if (msg) {
        result = msg;
        ldap_memfree(msg);
    }
    return result;
}

/**
 * @brief Build a full error string from LDAP result code + diagnostic message.
 *
 * Format: "ldap_err2string(rc) (code) - diagnostic message"
 */
std::string LDAPConn::formatError(int rc, LDAP *ld) {
    std::string s = ldap_err2string(rc);
    if (rc != LDAP_SUCCESS) {
        s += " (" + std::to_string(rc) + ")";
        std::string diag = getDiagMsg(ld);
        if (!diag.empty())
            s += " - " + diag;
    }
    return s;
}

/**
 * @brief Perform a simple (username/password) bind via ldap_sasl_bind_s.
 *
 * Uses LDAP_SASL_SIMPLE mechanism. Empty username = anonymous.
 */
bool LDAPConn::simpleBind(const std::string &username, const std::string &password) {
    if (!ld) return false;

    lastErrno = 0;
    lastError.clear();

    const char *dn = username.empty() ? nullptr : username.c_str();

    BerValue cred;
    BerValue *credptr = nullptr;
    if (!password.empty()) {
        cred.bv_val = const_cast<char*>(password.c_str());
        cred.bv_len = password.size();
        credptr = &cred;
    }

    int rc = ldap_sasl_bind_s(ld, dn, LDAP_SASL_SIMPLE, credptr,
                              nullptr, nullptr, nullptr);
    lastErrno = rc;
    lastError = formatError(rc, ld);
    return rc == LDAP_SUCCESS;
}

/** @brief SASL EXTERNAL bind — uses client certificate for authentication. */
bool LDAPConn::externalBind() {
    if (!ld) return false;
    BerValue cred;
    cred.bv_val = nullptr;
    cred.bv_len = 0;
    int rc = ldap_sasl_bind_s(ld, "", "EXTERNAL", &cred, nullptr, nullptr, nullptr);
    lastErrno = rc;
    lastError = formatError(rc, ld);
    return rc == LDAP_SUCCESS;
}

/** @brief No-op SASL interaction callback (used for non-interactive mechanisms like EXTERNAL). */
static int saslNullInteract(LDAP *ld_, unsigned flags_, void *defaults_, void *in_) {
    (void)ld_; (void)flags_; (void)defaults_; (void)in_;
    return LDAP_SUCCESS;
}

/**
 * @brief Perform an interactive SASL bind for arbitrary mechanisms.
 *
 * Calls ldap_sasl_interactive_bind_s with a no-op interaction callback
 * suitable for mechanisms like GSSAPI that handle their own credential
 * acquisition.
 *
 * @param mech    SASL mechanism name (e.g. "GSSAPI", "EXTERNAL").
 * @param authzId Authorization ID (unused in current implementation).
 */
bool LDAPConn::saslBind(const std::string &mech, const std::string &authzId) {
    if (!ld) return false;
    lastErrno = 0;
    lastError.clear();

    const char *dn = nullptr;
    const char *mechStr = mech.c_str();
    unsigned saslFlags = LDAP_SASL_QUIET;

    int rc = ldap_sasl_interactive_bind_s(ld, dn, mechStr, nullptr, nullptr,
                                          saslFlags, saslNullInteract, nullptr);

    lastErrno = rc;
    lastError = formatError(rc, ld);
    return rc == LDAP_SUCCESS;
}

// ── Search ──────────────────────────────────────────────

/**
 * @brief Perform an LDAP search with paging, controls, and partial-result support.
 *
 * Flow:
 *   1. Build attribute list string and char* array.
 *   2. Merge showDeleted control (1.2.840.113556.1.4.417) with user-supplied controls.
 *   3. Call ldap_search_ext_s with paging and time limit.
 *   4. Accept partial results (size/time/admin limit exceeded: rc 3,4,11).
 *   5. Iterate result entries and populate LDAPEntry objects with all attributes.
 *
 * @param baseDN      Search base distinguished name.
 * @param scope       LDAP_SCOPE_BASE / ONELEVEL / SUBTREE.
 * @param filter      LDAP filter string.
 * @param attrs       Attribute list to retrieve (empty = "*,+").
 * @param showDeleted Include deleted objects (AD tombstone control).
 * @param results     Output vector of entries.
 * @return true if the search call succeeded (including partial results).
 */
bool LDAPConn::search(const std::string &baseDN, int scope, const std::string &filter,
                       const std::vector<std::string> &attrs, bool showDeleted,
                       std::vector<LDAPEntry> &results) {
    if (!ld) return false;

    results.clear();

    std::string attrsStr;
    for (const auto &a : attrs) {
        if (!attrsStr.empty()) attrsStr += ",";
        attrsStr += a;
    }
    if (attrsStr.empty()) attrsStr = "*,+";

    // Build char* array for attrs
    std::vector<const char*> attrsArray;
    std::string attrCopy = attrsStr;
    char *token = strtok(attrCopy.data(), ",");
    while (token) {
        attrsArray.push_back(token);
        token = strtok(nullptr, ",");
    }
    attrsArray.push_back(nullptr);

    // Build combined controls list: showDeleted + user controls
    LDAPControl **srvCtrls = nullptr;
    LDAPControl showDeletedCtrl;
    bool hasDeletedCtrl = showDeleted;

    if (hasDeletedCtrl) {
        showDeletedCtrl.ldctl_oid = const_cast<char*>("1.2.840.113556.1.4.417");
        showDeletedCtrl.ldctl_value.bv_val = nullptr;
        showDeletedCtrl.ldctl_value.bv_len = 0;
        showDeletedCtrl.ldctl_iscritical = 1;
    }

    // Build user control array
    LDAPControl **userCtrls = buildControlArray();
    int userCount = 0;
    if (userCtrls) {
        while (userCtrls[userCount]) userCount++;
    }

    // Merge: allocate combined array
    int totalCtls = (hasDeletedCtrl ? 1 : 0) + userCount;
    if (totalCtls > 0) {
        srvCtrls = static_cast<LDAPControl**>(malloc((totalCtls + 1) * sizeof(LDAPControl*)));
        int idx = 0;
        if (hasDeletedCtrl)
            srvCtrls[idx++] = &showDeletedCtrl;
        for (int i = 0; i < userCount; i++)
            srvCtrls[idx++] = userCtrls[i];
        srvCtrls[idx] = nullptr;
    }
    free(userCtrls);

    struct timeval tv;
    tv.tv_sec = timelimit;
    tv.tv_usec = 0;

    LDAPMessage *res = nullptr;
    int rc = ldap_search_ext_s(ld, baseDN.c_str(), scope,
                                filter.c_str(), const_cast<char**>(attrsArray.data()),
                                0, srvCtrls, nullptr, &tv,
                                pagingSize, &res);

    free(srvCtrls);

    // Accept partial results even on limit-exceeded errors
    bool partial = (rc == 4 || rc == 3 || rc == 11); // size/time/admin limit

    if (rc != LDAP_SUCCESS && !partial) {
        if (res) ldap_msgfree(res);
        lastErrno = rc;
        lastError = formatError(rc, ld);
        return false;
    }

    if (partial) {
        lastErrno = rc;
        lastError = formatError(rc, ld);
    }

    for (LDAPMessage *msg = ldap_first_entry(ld, res); msg != nullptr;
         msg = ldap_next_entry(ld, msg)) {
        LDAPEntry entry;

        char *dn = ldap_get_dn(ld, msg);
        if (dn) {
            entry.dn = dn;
            ldap_memfree(dn);
        }

        BerElement *ber = nullptr;
        char *attr = ldap_first_attribute(ld, msg, &ber);
        while (attr) {
            std::string attrName = attr;

            BerValue **bvals = ldap_get_values_len(ld, msg, attr);
            if (bvals) {
                int count = ldap_count_values_len(bvals);
                std::vector<std::string> strVals;
                std::vector<std::vector<uint8_t>> binVals;
                for (int i = 0; i < count; i++) {
                    strVals.push_back(std::string(bvals[i]->bv_val, bvals[i]->bv_len));
                    binVals.push_back(std::vector<uint8_t>(bvals[i]->bv_val,
                                                           bvals[i]->bv_val + bvals[i]->bv_len));
                }
                entry.attributes[attrName] = strVals;
                entry.binaryAttributes[attrName] = binVals;
                entry.attributeNames.push_back(attrName);
                ldap_value_free_len(bvals);
            }

            ldap_memfree(attr);
            attr = ldap_next_attribute(ld, msg, ber);
        }
        if (ber) ber_free(ber, 0);

        results.push_back(std::move(entry));
    }

    ldap_msgfree(res);
    return true;
}

/** @brief Convenience: base-scope search returning the first (only) result entry. */
LDAPEntry LDAPConn::searchOne(const std::string &baseDN, const std::string &filter,
                               const std::vector<std::string> &attrs, bool showDeleted) {
    std::vector<LDAPEntry> results;
    if (search(baseDN, LDAP_SCOPE_BASE, filter, attrs, showDeleted, results)) {
        if (!results.empty()) return results[0];
    }
    return {};
}

// ── Info / Discovery ────────────────────────────────────

/**
 * @brief Locate the default root DN from namingContexts.
 *
 * Skips Schema, Configuration, AD DNS zones, and access log
 * contexts. Prefers domain-like DNs (starting with DC=).
 *
 * @param rootDN Output string set to the discovered DN.
 * @return true if a suitable root DN was found.
 */
bool LDAPConn::findRootDN(std::string &rootDN) {
    auto contexts = findNamingContexts();
    std::string fallback;

    for (const auto &ctx : contexts) {
        // Skip Schema, Configuration, and AD-specific DNS zones
        if (ctx.size() >= 10 && ctx.compare(0, 10, "CN=Schema,") == 0) continue;
        if (ctx.size() >= 18 && ctx.compare(0, 18, "CN=Configuration,") == 0) continue;
        if (ctx.size() >= 18 && ctx.compare(0, 18, "DC=DomainDnsZones") == 0) continue;
        if (ctx.size() >= 19 && ctx.compare(0, 19, "DC=ForestDnsZones") == 0) continue;
        // Skip access/audit log contexts
        if (ctx.size() >= 14 && ctx.compare(0, 14, "CN=accesslog") == 0) continue;
        if (ctx.size() >= 14 && ctx.compare(0, 14, "cn=accesslog") == 0) continue;

        // Prefer domain-like DNs (starting with DC= or dc=)
        if (ctx.size() >= 3 && (ctx[0] == 'D' || ctx[0] == 'd') &&
            (ctx[1] == 'C' || ctx[1] == 'c') && ctx[2] == '=') {
            rootDN = ctx;
            return true;
        }

        // Keep first non-avoidable as fallback
        if (fallback.empty())
            fallback = ctx;
    }

    if (!fallback.empty()) {
        rootDN = fallback;
        return true;
    }
    return false;
}

/** @brief Fetch the list of namingContexts from the RootDSE. */
std::vector<std::string> LDAPConn::findNamingContexts() {
    auto entry = searchOne("", "(objectClass=*)", {"namingContexts"}, false);
    return entry.getAttrs("namingContexts");
}

/**
 * @brief Extract the DNS domain FQDN from the RootDSE.
 *
 * Tries ldapServiceName first (extracts part after '@'), then
 * falls back to extracting DC= components from defaultNamingContext.
 */
std::string LDAPConn::findRootFQDN() {
    auto entry = searchOne("", "(objectClass=*)", {"ldapServiceName", "namingContexts", "defaultNamingContext"}, false);
    // Try ldapServiceName first
    auto ldapSN = entry.getAttr("ldapServiceName");
    if (!ldapSN.empty()) {
        auto pos = ldapSN.find('@');
        if (pos != std::string::npos)
            return ldapSN.substr(pos + 1);
    }
    // Fallback: extract domain from defaultNamingContext
    auto defaultCtx = entry.getAttr("defaultNamingContext");
    if (!defaultCtx.empty()) {
        std::string result;
        auto parts = std::vector<std::string>();
        std::string s = defaultCtx;
        size_t pos;
        while ((pos = s.find(',')) != std::string::npos) {
            parts.push_back(s.substr(0, pos));
            s.erase(0, pos + 1);
        }
        parts.push_back(s);
        for (const auto &p : parts) {
            if (p.size() > 3 && (p[0] == 'D' || p[0] == 'd') &&
                (p[1] == 'C' || p[1] == 'c') && p[2] == '=') {
                if (!result.empty()) result += ".";
                result += p.substr(3);
            }
        }
        return result;
    }
    return "";
}

/**
 * @brief Detect the LDAP server flavour by checking RootDSE objectClass.
 *
 * If "OpenLDAProotDSE" is present, flavour is BasicLDAP;
 * otherwise defaults to MicrosoftAD.
 */
void LDAPConn::guessFlavor() {
    auto entry = searchOne("", "(objectClass=*)", {"objectClass"}, false);
    auto classes = entry.getAttrs("objectClass");
    for (const auto &c : classes) {
        if (c == "OpenLDAProotDSE") {
            flavor = LDAPFlavor::BasicLDAP;
            return;
        }
    }
    flavor = LDAPFlavor::MicrosoftAD;
}

// ── Group Operations ────────────────────────────────────

/** @brief Find all direct members of a group via memberOf back-linking. */
bool LDAPConn::queryGroupMembers(const std::string &groupDN, std::vector<LDAPEntry> &members) {
    auto escaped = escapeFilter(groupDN);
    std::string filter = "(memberOf=" + escaped + ")";
    return search(defaultRootDN, LDAP_SCOPE_SUBTREE, filter,
                  {"sAMAccountName", "objectCategory", "objectSid"}, false, members);
}

/**
 * @brief Recursively resolve nested group membership.
 *
 * If maxDepth < 0, uses AD's LDAP_MATCHING_RULE_IN_CHAIN (1.2.840.113556.1.4.1941)
 * for a single-query transitive expansion. Otherwise BFS up to maxDepth.
 */
bool LDAPConn::queryGroupMembersDeep(const std::string &groupDN, int maxDepth,
                                      std::vector<LDAPEntry> &members) {
    if (maxDepth < 0) {
        auto escaped = escapeFilter(groupDN);
        std::string filter = "(memberOf:1.2.840.113556.1.4.1941:=" + escaped + ")";
        return search(defaultRootDN, LDAP_SCOPE_SUBTREE, filter,
                      {"sAMAccountName", "objectCategory", "objectSid"}, false, members);
    }
    std::vector<std::pair<std::string, int>> queue = {{groupDN, 0}};
    std::map<std::string, bool> seen;

    while (!queue.empty() && queue[0].second <= maxDepth) {
        auto [currentDN, depth] = queue[0];
        queue.erase(queue.begin());

        std::vector<LDAPEntry> currentMembers;
        if (!queryGroupMembers(currentDN, currentMembers)) continue;

        for (auto &entry : currentMembers) {
            if (seen.find(entry.dn) != seen.end()) continue;
            seen[entry.dn] = true;
            members.push_back(entry);

            auto categories = entry.getAttr("objectCategory");
            if (categories.find("CN=Group") == 0) {
                queue.push_back({entry.dn, depth + 1});
            }
        }
    }
    return true;
}

/** @brief Find all groups that the given object is a direct member of. */
bool LDAPConn::queryObjectGroups(const std::string &objectDN, std::vector<LDAPEntry> &groups) {
    std::string filter = "(member=" + objectDN + ")";
    return search(defaultRootDN, LDAP_SCOPE_SUBTREE, filter,
                  {"name", "objectCategory", "objectSid"}, false, groups);
}

/** @brief Add a member DN to a group's member attribute. */
bool LDAPConn::addMemberToGroup(const std::string &memberDN, const std::string &groupDN) {
    LDAPMod mod;
    std::vector<const char*> values = {memberDN.c_str(), nullptr};
    mod.mod_op = LDAP_MOD_ADD;
    mod.mod_type = const_cast<char*>("member");
    mod.mod_vals.modv_strvals = const_cast<char**>(values.data());

    LDAPMod *mods[] = {&mod, nullptr};
    int rc = ldap_modify_ext_s(ld, groupDN.c_str(), mods, nullptr, nullptr);
    return rc == LDAP_SUCCESS;
}

/** @brief Remove a member DN from a group's member attribute. */
bool LDAPConn::removeMemberFromGroup(const std::string &memberDN, const std::string &groupDN) {
    LDAPMod mod;
    std::vector<const char*> values = {memberDN.c_str(), nullptr};
    mod.mod_op = LDAP_MOD_DELETE;
    mod.mod_type = const_cast<char*>("member");
    mod.mod_vals.modv_strvals = const_cast<char**>(values.data());

    LDAPMod *mods[] = {&mod, nullptr};
    int rc = ldap_modify_ext_s(ld, groupDN.c_str(), mods, nullptr, nullptr);
    return rc == LDAP_SUCCESS;
}

// ── Object CRUD ─────────────────────────────────────────

/** @brief Delete an LDAP object by DN. */
bool LDAPConn::deleteObject(const std::string &dn) {
    int rc = ldap_delete_ext_s(ld, dn.c_str(), nullptr, nullptr);
    return rc == LDAP_SUCCESS;
}

/** @brief Add values to an attribute (LDAP_MOD_ADD). */
bool LDAPConn::addAttribute(const std::string &dn, const std::string &attr,
                             const std::vector<std::string> &values) {
    LDAPMod mod;
    std::vector<const char*> vals;
    for (const auto &v : values) vals.push_back(v.c_str());
    vals.push_back(nullptr);

    mod.mod_op = LDAP_MOD_ADD;
    mod.mod_type = const_cast<char*>(attr.c_str());
    mod.mod_vals.modv_strvals = const_cast<char**>(vals.data());

    LDAPMod *mods[] = {&mod, nullptr};
    int rc = ldap_modify_ext_s(ld, dn.c_str(), mods, nullptr, nullptr);
    return rc == LDAP_SUCCESS;
}

/** @brief Replace all values of an attribute (LDAP_MOD_REPLACE). */
bool LDAPConn::modifyAttribute(const std::string &dn, const std::string &attr,
                                const std::vector<std::string> &values) {
    LDAPMod mod;
    std::vector<const char*> vals;
    for (const auto &v : values) vals.push_back(v.c_str());
    vals.push_back(nullptr);

    mod.mod_op = LDAP_MOD_REPLACE;
    mod.mod_type = const_cast<char*>(attr.c_str());
    mod.mod_vals.modv_strvals = const_cast<char**>(vals.data());

    LDAPMod *mods[] = {&mod, nullptr};
    int rc = ldap_modify_ext_s(ld, dn.c_str(), mods, nullptr, nullptr);
    lastErrno = rc;
    lastError = formatError(rc, ld);
    return rc == LDAP_SUCCESS;
}

/** @brief Delete an entire attribute (all values) from an object. */
bool LDAPConn::deleteAttribute(const std::string &dn, const std::string &attr) {
    LDAPMod mod;
    mod.mod_op = LDAP_MOD_DELETE;
    mod.mod_type = const_cast<char*>(attr.c_str());
    mod.mod_vals.modv_strvals = nullptr;

    LDAPMod *mods[] = {&mod, nullptr};
    int rc = ldap_modify_ext_s(ld, dn.c_str(), mods, nullptr, nullptr);
    return rc == LDAP_SUCCESS;
}

/** @brief Delete specific values from an attribute (LDAP_MOD_DELETE with values). */
bool LDAPConn::deleteAttributeValues(const std::string &dn, const std::string &attr,
                                      const std::vector<std::string> &values) {
    LDAPMod mod;
    std::vector<const char*> vals;
    for (const auto &v : values) vals.push_back(v.c_str());
    vals.push_back(nullptr);

    mod.mod_op = LDAP_MOD_DELETE;
    mod.mod_type = const_cast<char*>(attr.c_str());
    mod.mod_vals.modv_strvals = const_cast<char**>(vals.data());

    LDAPMod *mods[] = {&mod, nullptr};
    int rc = ldap_modify_ext_s(ld, dn.c_str(), mods, nullptr, nullptr);
    return rc == LDAP_SUCCESS;
}

/**
 * @brief Move/rename an LDAP object via ldap_rename_s.
 *
 * The targetDN is split into the new RDN (first component) and
 * the new parent DN (remaining components).
 */
bool LDAPConn::moveObject(const std::string &sourceDN, const std::string &targetDN) {
    auto parts = std::vector<std::string>();
    std::string s = targetDN;
    size_t pos;
    while ((pos = s.find(',')) != std::string::npos) {
        parts.push_back(s.substr(0, pos));
        s.erase(0, pos + 1);
    }
    parts.push_back(s);

    if (parts.empty()) return false;

    std::string newRDN = parts[0];
    std::string newParent;
    for (size_t i = 1; i < parts.size(); i++) {
        if (!newParent.empty()) newParent += ",";
        newParent += parts[i];
    }

    int rc = ldap_rename_s(ld, sourceDN.c_str(), newRDN.c_str(),
                            newParent.empty() ? nullptr : newParent.c_str(),
                            1, nullptr, nullptr);
    return rc == LDAP_SUCCESS;
}

/**
 * @brief Reset a user's password by writing unicodePwd (UTF-16LE).
 *
 * The password is quoted (required by AD), converted to UTF-16LE,
 * and sent as a LDAP_MOD_BVALUES replace operation on the unicodePwd
 * attribute.
 */
bool LDAPConn::resetPassword(const std::string &dn, const std::string &newPassword) {
    std::string quoted = "\"" + newPassword + "\"";
    // Convert to UTF-16LE (assumes ASCII for simplicity)
    std::vector<uint8_t> utf16;
    for (char c : quoted) {
        utf16.push_back(static_cast<uint8_t>(c));
        utf16.push_back(0);
    }

    BerValue bval;
    bval.bv_val = reinterpret_cast<char*>(utf16.data());
    bval.bv_len = utf16.size();

    LDAPMod mod;
    mod.mod_op = LDAP_MOD_REPLACE | LDAP_MOD_BVALUES;
    mod.mod_type = const_cast<char*>("unicodePwd");
    BerValue *bvals[] = {&bval, nullptr};
    mod.mod_vals.modv_bvals = bvals;

    LDAPMod *mods[] = {&mod, nullptr};
    int rc = ldap_modify_ext_s(ld, dn.c_str(), mods, nullptr, nullptr);
    return rc == LDAP_SUCCESS;
}

// ── Object Creation ─────────────────────────────────────

/**
 * @brief Build an LDAPMod array from a map of attribute → values.
 * Caller must free with freeAddMods().
 */
static LDAPMod** buildAddMods(const std::map<std::string, std::vector<std::string>> &attrs) {
    size_t n = attrs.size();
    LDAPMod **mods = static_cast<LDAPMod**>(calloc(n + 1, sizeof(LDAPMod*)));
    size_t i = 0;
    for (const auto &[attrName, values] : attrs) {
        mods[i] = static_cast<LDAPMod*>(calloc(1, sizeof(LDAPMod)));
        mods[i]->mod_op = LDAP_MOD_ADD;
        mods[i]->mod_type = strdup(attrName.c_str());
        mods[i]->mod_vals.modv_strvals = static_cast<char**>(calloc(values.size() + 1, sizeof(char*)));
        for (size_t j = 0; j < values.size(); j++) {
            mods[i]->mod_vals.modv_strvals[j] = strdup(values[j].c_str());
        }
        mods[i]->mod_vals.modv_strvals[values.size()] = nullptr;
        i++;
    }
    mods[i] = nullptr;
    return mods;
}

/** @brief Free an LDAPMod array allocated by buildAddMods(). */
static void freeAddMods(LDAPMod **mods) {
    if (!mods) return;
    for (size_t i = 0; mods[i] != nullptr; i++) {
        free(mods[i]->mod_type);
        if (mods[i]->mod_vals.modv_strvals) {
            for (size_t j = 0; mods[i]->mod_vals.modv_strvals[j] != nullptr; j++) {
                free(mods[i]->mod_vals.modv_strvals[j]);
            }
            free(mods[i]->mod_vals.modv_strvals);
        }
        free(mods[i]);
    }
    free(mods);
}

/** @brief Create a new LDAP object with the given attributes. */
bool LDAPConn::addObject(const std::string &dn,
                          const std::map<std::string, std::vector<std::string>> &attrs) {
    auto mods = buildAddMods(attrs);
    int rc = ldap_add_ext_s(ld, dn.c_str(), mods, nullptr, nullptr);
    freeAddMods(mods);
    return rc == LDAP_SUCCESS;
}

/** @brief Convenience: create a group object under parentDN. */
bool LDAPConn::addGroup(const std::string &name, const std::string &parentDN) {
    std::string dn = "CN=" + name + "," + parentDN;
    return addObject(dn, {
        {"objectClass", {"top", "group"}},
        {"cn", {name}},
        {"sAMAccountName", {name}},
    });
}

/** @brief Convenience: create an organizationalUnit under parentDN. */
bool LDAPConn::addOU(const std::string &name, const std::string &parentDN) {
    std::string dn = "OU=" + name + "," + parentDN;
    return addObject(dn, {
        {"objectClass", {"top", "organizationalUnit"}},
        {"cn", {name}},
    });
}

/** @brief Convenience: create a user object under parentDN. */
bool LDAPConn::addUser(const std::string &name, const std::string &parentDN) {
    std::string dn = "CN=" + name + "," + parentDN;
    auto fqdn = findRootFQDN();
    std::map<std::string, std::vector<std::string>> objAttrs = {
        {"objectClass", {"top", "person", "organizationalPerson", "user"}},
        {"cn", {name}},
        {"sAMAccountName", {name}},
    };
    if (!fqdn.empty())
        objAttrs["userPrincipalName"] = {name + "@" + fqdn};
    return addObject(dn, objAttrs);
}

/** @brief Convenience: create a computer object under parentDN. */
bool LDAPConn::addComputer(const std::string &name, const std::string &parentDN) {
    std::string dn = "CN=" + name + "," + parentDN;
    return addObject(dn, {
        {"objectClass", {"top", "computer"}},
        {"cn", {name}},
        {"sAMAccountName", {name + "$"}},
        {"userAccountControl", {"4096"}},
    });
}

/** @brief Convenience: create a container object under parentDN. */
bool LDAPConn::addContainer(const std::string &name, const std::string &parentDN) {
    std::string dn = "CN=" + name + "," + parentDN;
    return addObject(dn, {
        {"objectClass", {"top", "container"}},
    });
}

// ── Security Descriptor ─────────────────────────────────

/**
 * @brief Fetch the nTSecurityDescriptor of an object as a hex string.
 *
 * Accepts either a sAMAccountName (subtree search) or a full DN (base search).
 */
bool LDAPConn::getSecurityDescriptor(const std::string &object, std::string &hexSD) {
    std::string filter;
    std::string base;
    bool isSam = (object.find('=') == std::string::npos);

    if (isSam) {
        filter = "(sAMAccountName=" + escapeFilter(object) + ")";
        base = defaultRootDN;
    } else {
        filter = "(&)";
        base = object;
    }

    std::vector<LDAPEntry> results;
    int scope = isSam ? LDAP_SCOPE_SUBTREE : LDAP_SCOPE_BASE;
    if (!search(base, scope, filter, {"nTSecurityDescriptor"}, false, results))
        return false;

    if (results.empty()) return false;
    auto raw = results[0].getRawAttr("nTSecurityDescriptor");
    if (raw.empty()) return false;

    static const char *hex = "0123456789ABCDEF";
    for (auto b : raw) {
        hexSD += hex[(b >> 4) & 0xF];
        hexSD += hex[b & 0xF];
    }
    return true;
}

/**
 * @brief Replace the nTSecurityDescriptor of an object with a new hex-encoded SD.
 *
 * Accepts sAMAccountName (auto-resolved to DN) or a full DN.
 */
bool LDAPConn::modifyDACL(const std::string &object, const std::string &newSD) {
    std::string dn = object;
    if (object.find('=') == std::string::npos) {
        dn = findFirstAttr("(sAMAccountName=" + escapeFilter(object) + ")",
                            "distinguishedName");
        if (dn.empty()) return false;
    }

    BerValue bval;
    bval.bv_val = const_cast<char*>(newSD.c_str());
    bval.bv_len = newSD.size();

    LDAPMod mod;
    mod.mod_op = LDAP_MOD_REPLACE | LDAP_MOD_BVALUES;
    mod.mod_type = const_cast<char*>("nTSecurityDescriptor");
    BerValue *bvals[] = {&bval, nullptr};
    mod.mod_vals.modv_bvals = bvals;

    LDAPMod *mods[] = {&mod, nullptr};
    int rc = ldap_modify_ext_s(ld, dn.c_str(), mods, nullptr, nullptr);
    return rc == LDAP_SUCCESS;
}

// ── Schema ──────────────────────────────────────────────

/**
 * @brief Fetch schema objectClasses and attributeTypes from the server.
 *
 * Queries the subschemaSubentry (or schemaNamingContext for AD) and
 * extracts NAME/OID pairs from the raw schema definitions.
 */
bool LDAPConn::findSchemaClassesAndAttributes(std::map<std::string, std::string> &classes,
                                               std::map<std::string, std::string> &attrs) {
    // Standard LDAP: query cn=subschema for subschemaSubentry
    auto rootDSE = searchOne("", "(objectClass=*)", {"subschemaSubentry"}, false);
    std::string subschemaDN = rootDSE.getAttr("subschemaSubentry");
    if (subschemaDN.empty()) {
        // Fallback: try the schemaNamingContext (AD-style)
        rootDSE = searchOne("", "(objectClass=*)", {"schemaNamingContext"}, false);
        subschemaDN = rootDSE.getAttr("schemaNamingContext");
    }
    if (subschemaDN.empty()) return false;

    // Try to get the subschema entry directly
    auto subschema = searchOne(subschemaDN, "(objectClass=*)",
                                {"objectClasses", "attributeTypes"}, false);
    auto objClasses = subschema.getAttrs("objectClasses");
    auto attrTypes = subschema.getAttrs("attributeTypes");

    // Parse attribute types (simplified NAME extraction)
    for (const auto &at : attrTypes) {
        // Format: "( 1.3.6.1.4.1.1466.115.121.1.26 NAME 'label' ... )"
        auto pos = at.find(" NAME '");
        if (pos == std::string::npos)
            pos = at.find(" NAME \"");
        if (pos != std::string::npos) {
            pos += 7; // skip " NAME '"
            auto end = at.find('\'', pos);
            if (end == std::string::npos)
                end = at.find('"', pos);
            if (end != std::string::npos) {
                std::string name = at.substr(pos, end - pos);
                auto oidPos = at.find_first_of("0123456789");
                if (oidPos != std::string::npos) {
                    auto oidEnd = at.find(' ', oidPos);
                    std::string oid = at.substr(oidPos, oidEnd - oidPos);
                    attrs[name] = oid;
                }
            }
        }
    }

    // Parse object class names
    for (const auto &oc : objClasses) {
        auto pos = oc.find(" NAME '");
        if (pos == std::string::npos)
            pos = oc.find(" NAME \"");
        if (pos != std::string::npos) {
            pos += 7;
            auto end = oc.find('\'', pos);
            if (end == std::string::npos)
                end = oc.find('"', pos);
            if (end != std::string::npos) {
                classes[oc.substr(pos, end - pos)] = oc;
            }
        }
    }

    return !attrTypes.empty() || !objClasses.empty();
}

// ── AD Integrated DNS ──────────────────────────────────

/**
 * @brief Enumerate DNS zones (DomainDnsZones or ForestDnsZones).
 * @param name     Optional zone name filter (empty = all zones).
 * @param isForest If true, query ForestDnsZones; otherwise DomainDnsZones.
 */
bool LDAPConn::getADIDNSZones(const std::string &name, bool isForest,
                               std::vector<adidns::DNSZone> &zones) {
    std::string zoneContainer = isForest ? "ForestDnsZones" : "DomainDnsZones";
    std::string queryDN = "CN=MicrosoftDNS,DC=" + zoneContainer + "," + defaultRootDN;
    std::string filter = "(objectClass=dnsZone)";
    if (!name.empty()) {
        filter = "(&" + filter + "(name=" + escapeFilter(name) + "))";
    }

    std::vector<LDAPEntry> zoneEntries;
    if (!search(queryDN, LDAP_SCOPE_ONELEVEL, filter, {"name", "dNSProperty"}, false, zoneEntries))
        return false;

    for (const auto &ze : zoneEntries) {
        adidns::DNSZone zone;
        zone.dn = ze.dn;
        zone.name = ze.getAttr("name");

        auto propStrs = ze.getRawAttrs("dNSProperty");
        for (const auto &propBytes : propStrs) {
            adidns::DNSProperty prop;
            prop.decode(propBytes);
            zone.props.push_back(prop);
        }
        zones.push_back(zone);
    }
    return true;
}

/** @brief Fetch a single DNS node by its DN, including its dnsRecord entries. */
bool LDAPConn::getADIDNSNode(const std::string &nodeDN, adidns::DNSNode &node) {
    std::vector<LDAPEntry> entries;
    if (!search(nodeDN, LDAP_SCOPE_BASE, "(objectClass=dnsNode)",
                {"name", "dnsRecord"}, false, entries))
        return false;
    if (entries.empty()) return false;

    node.dn = entries[0].dn;
    node.name = entries[0].getAttr("name");

    auto recBytes = entries[0].getRawAttrs("dnsRecord");
    for (const auto &rb : recBytes) {
        adidns::DNSRecord rec;
        rec.decode(rb);
        node.records.push_back(rec);
    }
    return true;
}

/** @brief Enumerate all DNS nodes in a zone (one level deep). */
bool LDAPConn::getADIDNSNodes(const std::string &zoneDN, std::vector<adidns::DNSNode> &nodes) {
    std::vector<LDAPEntry> entries;
    if (!search(zoneDN, LDAP_SCOPE_ONELEVEL, "(objectClass=dnsNode)",
                {"name", "dnsRecord"}, false, entries))
        return false;

    for (const auto &entry : entries) {
        adidns::DNSNode node;
        node.dn = entry.dn;
        node.name = entry.getAttr("name");

        auto recBytes = entry.getRawAttrs("dnsRecord");
        for (const auto &rb : recBytes) {
            adidns::DNSRecord rec;
            rec.decode(rb);
            node.records.push_back(rec);
        }
        nodes.push_back(node);
    }
    return true;
}

/** @brief Create a new AD-integrated DNS zone. */
bool LDAPConn::addADIDNSZone(const std::string &name,
                              const std::vector<adidns::DNSProperty> &props, bool isForest) {
    std::string zoneContainer = isForest ? "ForestDnsZones" : "DomainDnsZones";
    std::string zoneDN = "DC=" + name + ",CN=MicrosoftDNS,DC=" + zoneContainer + "," + defaultRootDN;

    return addObject(zoneDN, {
        {"objectClass", {"top", "dnsZone"}},
        {"cn", {"Zone"}},
        {"name", {name}},
    });
}

/** @brief Create a new DNS node in an existing zone. */
bool LDAPConn::addADIDNSNode(const std::string &nodeName, const std::string &zoneDN,
                              const std::vector<adidns::DNSRecord> &records) {
    std::string nodeDN = "DC=" + nodeName + "," + zoneDN;
    return addObject(nodeDN, {
        {"objectClass", {"top", "dnsNode"}},
        {"name", {nodeName}},
    });
}

/** @brief Add DNS records (dnsRecord multi-valued add) to an existing node. */
bool LDAPConn::addADIDNSRecords(const std::string &nodeDN,
                                 const std::vector<adidns::DNSRecord> &records) {
    for (const auto &rec : records) {
        auto encoded = rec.encode();
        BerValue bval;
        bval.bv_val = reinterpret_cast<char*>(encoded.data());
        bval.bv_len = encoded.size();

        LDAPMod mod;
        mod.mod_op = LDAP_MOD_ADD | LDAP_MOD_BVALUES;
        mod.mod_type = const_cast<char*>("dnsRecord");
        BerValue *bvals[] = {&bval, nullptr};
        mod.mod_vals.modv_bvals = bvals;

        LDAPMod *mods[] = {&mod, nullptr};
        int rc = ldap_modify_ext_s(ld, nodeDN.c_str(), mods, nullptr, nullptr);
        if (rc != LDAP_SUCCESS) return false;
    }
    return true;
}

bool LDAPConn::replaceADIDNSRecords(const std::string &nodeDN,
                                     const std::vector<adidns::DNSRecord> &records) {
    LDAPMod modDel;
    modDel.mod_op = LDAP_MOD_DELETE;
    modDel.mod_type = const_cast<char*>("dnsRecord");
    modDel.mod_vals.modv_strvals = nullptr;
    LDAPMod *mods[] = {&modDel, nullptr};
    ldap_modify_ext_s(ld, nodeDN.c_str(), mods, nullptr, nullptr);

    return addADIDNSRecords(nodeDN, records);
}

// ── SID Resolution ─────────────────────────────────────

/**
 * @brief Resolve an object's objectSid to a human-readable SID string.
 *
 * The raw binary SID is hex-encoded then formatted via convertSID().
 */
std::string LDAPConn::findSIDForObject(const std::string &object) {
    (void)WellKnownSIDsMap;
    bool unused;
    auto filter = samOrDN(object, unused);
    std::string sidAttr = findFirstAttr(filter, "objectSid");
    if (sidAttr.empty()) return "";

    static const char *hexChars = "0123456789ABCDEF";
    std::string hexSID;
    for (auto b : sidAttr) {
        hexSID += hexChars[(static_cast<uint8_t>(b) >> 4) & 0xF];
        hexSID += hexChars[static_cast<uint8_t>(b) & 0xF];
    }
    return convertSID(hexSID);
}

/**
 * @brief Look up a sAMAccountName by SID string.
 *
 * Checks WellKnownSIDsMap first, then searches the directory.
 */
std::string LDAPConn::findSamForSID(const std::string &sid) {
    auto it = WellKnownSIDsMap.find(sid);
    if (it != WellKnownSIDsMap.end()) return it->second;

    std::string filter = "(objectSID=" + sid + ")";
    std::vector<LDAPEntry> results;
    if (!search(defaultRootDN, LDAP_SCOPE_SUBTREE, filter, {"sAMAccountName"}, false, results))
        return "";

    if (!results.empty()) return results[0].getAttr("sAMAccountName");
    return "";
}

/** @brief Search for the first object matching a filter and return a single attribute value. */
std::string LDAPConn::findFirstAttr(const std::string &filter, const std::string &attr) {
    std::vector<LDAPEntry> results;
    if (!search(defaultRootDN, LDAP_SCOPE_SUBTREE, filter, {attr}, false, results))
        return "";
    if (!results.empty()) return results[0].getAttr(attr);
    return "";
}

} // namespace diratlas

// ── LDAP Controls ──────────────────────────────────────────
// Build and manage LDAPControl arrays for the -E flag.

namespace diratlas {

/** @brief Convert the internal control list to a LDAPControl** array (malloc'd, caller frees). */
LDAPControl **LDAPConn::buildControlArray() const {
    if (ctrls_.empty()) return nullptr;
    auto **arr = static_cast<LDAPControl**>(calloc(ctrls_.size() + 1, sizeof(LDAPControl*)));
    for (size_t i = 0; i < ctrls_.size(); i++) {
        arr[i] = static_cast<LDAPControl*>(malloc(sizeof(LDAPControl)));
        arr[i]->ldctl_oid = strdup(ctrls_[i].oid.c_str());
        arr[i]->ldctl_iscritical = ctrls_[i].critical ? 1 : 0;
        if (!ctrls_[i].value.empty()) {
            arr[i]->ldctl_value.bv_val = static_cast<char*>(malloc(ctrls_[i].value.size()));
            memcpy(arr[i]->ldctl_value.bv_val, ctrls_[i].value.data(), ctrls_[i].value.size());
            arr[i]->ldctl_value.bv_len = ctrls_[i].value.size();
        } else {
            arr[i]->ldctl_value.bv_val = nullptr;
            arr[i]->ldctl_value.bv_len = 0;
        }
    }
    arr[ctrls_.size()] = nullptr;
    return arr;
}

/** @brief Register a user-supplied LDAP control (added to all subsequent searches). */
void LDAPConn::addControl(const LdapControl &ctrl) {
    ctrls_.push_back(ctrl);
}

/** @brief Clear all previously registered user controls. */
void LDAPConn::clearControls() {
    ctrls_.clear();
}

/** @brief BER-encode a signed 32-bit integer (tag 0x02 + length + bytes). */
static std::vector<uint8_t> berEncodeInt(int32_t val) {
    std::vector<uint8_t> ber;
    bool neg = val < 0;
    uint32_t u = static_cast<uint32_t>(val);
    std::vector<uint8_t> bytes;
    while (u) { bytes.push_back(u & 0xFF); u >>= 8; }
    if (bytes.empty()) bytes.push_back(0);
    if (neg && bytes.back() & 0x80) bytes.push_back(0xFF);
    if (!neg && bytes.back() & 0x80) bytes.push_back(0x00);
    std::reverse(bytes.begin(), bytes.end());
    ber.push_back(0x02);
    ber.push_back(static_cast<uint8_t>(bytes.size()));
    ber.insert(ber.end(), bytes.begin(), bytes.end());
    return ber;
}

/**
 * @brief Parse a -E control specification string.
 *
 * Supported formats:
 *   [!]manageDSAit     → 2.16.840.1.113730.3.4.2
 *   [!]noop            → 1.3.6.1.4.1.4203.1.10.2
 *   [!]relax           → 1.3.6.1.4.1.4203.1.10.1
 *   [!]domainScope     → 1.3.6.1.4.1.1466.101.119.1
 *   [!]dontUseCopy     → 2.16.840.1.113730.3.4.18
 *   [!]subentries=true|false
 *   [!]pr=<size>[/cookie]
 *   [!]<OID>[:=<val>|::<b64>]
 *
 * @param spec     Raw spec string.
 * @param oid      Output: control OID.
 * @param critical Output: critical flag (set by leading '!').
 * @param value    Output: decoded control value.
 * @return true if the spec was recognised.
 */
bool LDAPConn::parseControlSpec(const std::string &spec,
                                 std::string &oid, bool &critical,
                                 std::vector<uint8_t> &value) {
    critical = false;
    size_t pos = 0;
    if (pos < spec.size() && spec[pos] == '!') { critical = true; pos++; }
    auto eq = spec.find('=', pos);
    std::string ext = spec.substr(pos, eq - pos);
    std::string param = (eq != std::string::npos) ? spec.substr(eq + 1) : "";

    if (ext == "manageDSAit")   { oid = "2.16.840.1.113730.3.4.2"; return true; }
    if (ext == "noop")          { oid = "1.3.6.1.4.1.4203.1.10.2"; return true; }
    if (ext == "relax")         { oid = "1.3.6.1.4.1.4203.1.10.1"; return true; }
    if (ext == "domainScope")   { oid = "1.3.6.1.4.1.1466.101.119.1"; return true; }
    if (ext == "dontUseCopy")   { oid = "2.16.840.1.113730.3.4.18"; return true; }
    if (ext == "sessiontracking") {
        oid = "1.3.6.1.4.1.21008.108.63.1";
        // Optional value: username
        if (!param.empty())
            value.assign(param.begin(), param.end());
        return true;
    }

    if (ext == "subentries") {
        oid = "1.3.6.1.4.1.4203.1.10.1";
        if (param == "true") value = berEncodeInt(1);
        else if (param == "false") value = berEncodeInt(0);
        return true;
    }

    if (ext == "pr" || ext == "paged") {
        oid = "1.2.840.113556.1.4.319";
        if (!param.empty()) {
            int size = std::stoi(param.substr(0, param.find('/')));
            value.assign(reinterpret_cast<const uint8_t*>(&size),
                         reinterpret_cast<const uint8_t*>(&size) + sizeof(size));
        }
        return true;
    }

    if (ext.find('.') != std::string::npos ||
        (ext.size() > 2 && ext[0] >= '0' && ext[0] <= '9')) {
        oid = ext;
        size_t colon = oid.find(":=");
        if (colon != std::string::npos) {
            value.assign(param.begin(), param.end());
            oid = oid.substr(0, colon);
        } else {
            size_t dcolon = oid.find("::");
            if (dcolon != std::string::npos) {
                oid = oid.substr(0, dcolon);
                value.assign(param.begin(), param.end());
            }
        }
        return true;
    }

    return false;
}

} // namespace diratlas
