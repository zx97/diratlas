// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Manuel FLURY
//
// This file is part of DirAtlas — an LDAP Directory Explorer.
//
// Licensed under the GNU Affero General Public License v3.0
// (https://www.gnu.org/licenses/agpl-3.0.txt).
//

#include "ldap_conn.h"
#include "ldapcore/bytes.h"
#include "log.h"
#include <cstring>
#include <sstream>
#include <algorithm>
#include <lber.h>

namespace diratlas {

// ── LDAPEntry implementation ─────────────────────────────

namespace {
// LDAP attribute names are case-insensitive (RFC 4512); servers may return
// a different casing than the caller asks for (e.g. "subschemasubentry" vs
// "subschemaSubentry"), so fall back to a case-insensitive key scan.
bool keyEqCi(const std::string &a, const std::string &b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i])))
            return false;
    }
    return true;
}
template <typename Map>
typename Map::const_iterator findKeyCi(const Map &m, const std::string &name) {
    auto it = m.find(name);
    if (it != m.end()) return it;
    for (it = m.begin(); it != m.end(); ++it) {
        if (keyEqCi(it->first, name)) return it;
    }
    return m.end();
}
} // namespace

std::string LDAPEntry::getAttr(const std::string &name) const {
    auto it = findKeyCi(attributes, name);
    if (it != attributes.end() && !it->second.empty())
        return it->second[0];
    return "";
}

std::vector<std::string> LDAPEntry::getAttrs(const std::string &name) const {
    auto it = findKeyCi(attributes, name);
    if (it != attributes.end()) return it->second;
    return {};
}

// ── LDAPConn: Construction / Destruction ────────────────

LDAPConn::LDAPConn() {}

LDAPConn::~LDAPConn() {
    if (ld) {
        ldap_unbind_ext(ld, nullptr, nullptr);
    }
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
 *   5. Apply network connect timeout (networkTimeout, if set).
 *   6. Disable async connection.
 *
 * @param uri         LDAP URI (ldap://, ldaps://, ldapi://).
 * @param socksProxy  SOCKS proxy address (currently unused by libldap).
 * @return true on success, false on failure.
 */
bool LDAPConn::connect(const std::string &uri,
                        const std::string & /*socksProxy*/) {
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
    diratlas::dbgLog(diratlas::LDAP_DEBUG_CONNS, "connect: ldap_initialize(" + uri + ")");

    rc = ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &ldapVersion);
    if (rc != LDAP_OPT_SUCCESS) return false;
    diratlas::dbgLog(diratlas::LDAP_DEBUG_CONNS, "connect: protocol v" + std::to_string(ldapVersion));

    // Alias dereferencing policy (-a) — setDeref() may have been called
    // before connect(), so the stored value is applied to the live handle.
    ldap_set_option(ld, LDAP_OPT_DEREF, &deref_);

    if (debug_) {
        ldap_set_option(ld, LDAP_OPT_DEBUG_LEVEL, &debug_);
    }

    // Set a global timeout for all operations
    { struct timeval tv = {timelimit > 0 ? timelimit : 10, 0};
      ldap_set_option(ld, LDAP_OPT_TIMEOUT, &tv);
      diratlas::dbgLog(diratlas::LDAP_DEBUG_CONNS, "connect: timelimit=" + std::to_string(tv.tv_sec) + "s"); }

    // Set network connect timeout (-o nettimeout)
    if (networkTimeout > 0) {
        struct timeval ntv = {networkTimeout, 0};
        ldap_set_option(ld, LDAP_OPT_NETWORK_TIMEOUT, &ntv);
        diratlas::dbgLog(diratlas::LDAP_DEBUG_CONNS, "connect: network-timeout=" + std::to_string(networkTimeout) + "s");
    }

    // Apply TLS options from ldaprc
    if (!tlsOpts.cacert.empty())
        ldap_set_option(ld, LDAP_OPT_X_TLS_CACERTFILE, tlsOpts.cacert.c_str());
    if (!tlsOpts.cacertdir.empty())
        ldap_set_option(ld, LDAP_OPT_X_TLS_CACERTDIR, tlsOpts.cacertdir.c_str());
    if (!tlsOpts.cert.empty())
        ldap_set_option(ld, LDAP_OPT_X_TLS_CERTFILE, tlsOpts.cert.c_str());
    if (!tlsOpts.key.empty())
        ldap_set_option(ld, LDAP_OPT_X_TLS_KEYFILE, tlsOpts.key.c_str());
    if (tlsOpts.reqcert >= 0) {
        ldap_set_option(ld, LDAP_OPT_X_TLS_REQUIRE_CERT, &tlsOpts.reqcert);
        diratlas::dbgLog(diratlas::LDAP_DEBUG_CONNS, "connect: tls_reqcert=" + std::to_string(tlsOpts.reqcert));
    }

    int async = 0;
    ldap_set_option(ld, LDAP_OPT_CONNECT_ASYNC, &async);

    connected = true;
    return true;
}

/** @brief Set alias dereferencing policy. Applied on the live handle now, or
 *         stored and applied by connect() if called before the connection. */
bool LDAPConn::setDeref(int deref) {
    deref_ = deref;
    if (!ld) return false;
    return ldap_set_option(ld, LDAP_OPT_DEREF, &deref_) == LDAP_OPT_SUCCESS;
}

/** @brief Initiate StartTLS on the connected session. */
bool LDAPConn::startTLS() {
    if (!ld) return false;
    lastErrno = 0;
    lastError.clear();
    int rc = ldap_start_tls_s(ld, nullptr, nullptr);
    lastErrno = rc;
    lastError = formatError(rc, ld);
    diratlas::dbgLog(diratlas::LDAP_DEBUG_CONNS, "starttls: ldap_start_tls_s -> " + std::to_string(rc)
        + (rc == LDAP_SUCCESS ? " (ok)" : " (" + lastError + ")"));
    return rc == LDAP_SUCCESS;
}

std::string LDAPConn::whoAmI() {
    if (!ld) return "";
    lastErrno = 0;
    lastError.clear();
    struct berval *authzid = nullptr;
    int rc = ldap_whoami_s(ld, &authzid, nullptr, nullptr);
    if (rc != LDAP_SUCCESS) {
        lastErrno = rc;
        lastError = formatError(rc, ld);
        return "";
    }
    std::string out;
    if (authzid && authzid->bv_val && authzid->bv_len > 0)
        out.assign(authzid->bv_val, authzid->bv_len);
    else
        out = "anonymous"; // RFC 4532: empty authzID == anonymous connection
    if (authzid) ber_bvfree(authzid);
    return out;
}

bool LDAPConn::passwordModify(const std::string &user, const std::string &oldPw,
                              const std::string &newPw, std::string &generatedPw) {
    if (!ld) return false;
    lastErrno = 0;
    lastError.clear();
    struct berval *userBv = nullptr, *oldBv = nullptr, *newBv = nullptr;
    struct berval userV = {0, nullptr}, oldV = {0, nullptr}, newV = {0, nullptr};
    if (!user.empty()) { userV.bv_val = const_cast<char*>(user.c_str()); userV.bv_len = user.size(); userBv = &userV; }
    if (!oldPw.empty()) { oldV.bv_val = const_cast<char*>(oldPw.c_str()); oldV.bv_len = oldPw.size(); oldBv = &oldV; }
    if (!newPw.empty()) { newV.bv_val = const_cast<char*>(newPw.c_str()); newV.bv_len = newPw.size(); newBv = &newV; }
    struct berval gen = {0, nullptr};
    int rc = ldap_passwd_s(ld, userBv, oldBv, newBv, &gen, nullptr, nullptr);
    if (rc != LDAP_SUCCESS) {
        lastErrno = rc;
        lastError = formatError(rc, ld);
        return false;
    }
    generatedPw.clear();
    if (gen.bv_val) {
        generatedPw.assign(gen.bv_val, gen.bv_len);
        ber_memfree(gen.bv_val);
    }
    return true;
}

bool LDAPConn::cancelOperation(int msgid) {
    if (!ld) return false;
    lastErrno = 0;
    lastError.clear();
    int rc = ldap_cancel_s(ld, msgid, nullptr, nullptr);
    lastErrno = rc;
    lastError = formatError(rc, ld);
    return rc == LDAP_SUCCESS;
}

bool LDAPConn::abandon(int msgid) {
    if (!ld) return false;
    lastErrno = 0;
    lastError.clear();
    // ldap_abandon_ext returns a non-zero value only for API misuse, not for a
    // server error, and the server never sends an Abandon response (RFC 4511
    // §4.11), so report success when the request was handed to the wire.
    int rc = ldap_abandon_ext(ld, msgid, nullptr, nullptr);
    lastErrno = rc;
    lastError = formatError(rc, ld);
    return rc == LDAP_SUCCESS;
}

bool LDAPConn::extendedOp(const std::string &oid, const std::vector<uint8_t> &req,
                          std::vector<uint8_t> &res) {
    if (!ld) return false;
    lastErrno = 0;
    lastError.clear();
    struct berval reqBv = {0, nullptr};
    if (!req.empty()) { reqBv.bv_val = const_cast<char*>(reinterpret_cast<const char*>(req.data())); reqBv.bv_len = req.size(); }
    char *retoid = nullptr;
    struct berval *retdata = nullptr;
    int rc = ldap_extended_operation_s(ld, oid.c_str(), req.empty() ? nullptr : &reqBv,
                                       nullptr, nullptr, &retoid, &retdata);
    if (rc != LDAP_SUCCESS) {
        lastErrno = rc;
        lastError = formatError(rc, ld);
        return false;
    }
    res.clear();
    if (retdata && retdata->bv_val) res.assign(reinterpret_cast<const uint8_t*>(retdata->bv_val),
                                               reinterpret_cast<const uint8_t*>(retdata->bv_val) + retdata->bv_len);
    if (retdata) ber_bvfree(retdata);
    if (retoid) ber_memfree(retoid);
    return true;
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
 * Empty username = anonymous bind. Always passes a non-NULL BerValue
 * (empty for anonymous) exactly as ldapsearch does; passing NULL makes
 * libldap encode an undecodable BindRequest on Symas builds.
 */
bool LDAPConn::simpleBind(const std::string &username, const std::string &password) {
    if (!ld) return false;

    lastErrno = 0;
    lastError.clear();

    BerValue cred = {0, nullptr};
    if (!password.empty()) {
        cred.bv_val = const_cast<char*>(password.c_str());
        cred.bv_len = password.size();
    }

    int rc = ldap_sasl_bind_s(ld, username.empty() ? nullptr : username.c_str(),
                              LDAP_SASL_SIMPLE, &cred, nullptr, nullptr, nullptr);
    lastErrno = rc;
    lastError = formatError(rc, ld);
    diratlas::dbgLog(diratlas::LDAP_DEBUG_STATS, "bind: simple dn=" + username + " -> " + std::to_string(rc)
        + (rc == LDAP_SUCCESS ? " (ok)" : " (" + lastError + ")"));
    return rc == LDAP_SUCCESS;
}

/** @brief No-op SASL interaction callback (used for non-interactive mechanisms). */
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
bool LDAPConn::saslBind(const std::string &mech, const std::string &authzId,
                        const std::string &authcid, const std::string &realm,
                        const std::string &secprops, bool noCanon,
                        bool interactive) {
    if (!ld) return false;
    lastErrno = 0;
    lastError.clear();

    if (!authzId.empty())
        ldap_set_option(ld, LDAP_OPT_X_SASL_AUTHZID, authzId.c_str());
    if (!authcid.empty())
        ldap_set_option(ld, LDAP_OPT_X_SASL_AUTHCID, authcid.c_str());
    if (!realm.empty())
        ldap_set_option(ld, LDAP_OPT_X_SASL_REALM, realm.c_str());
    if (!secprops.empty())
        ldap_set_option(ld, LDAP_OPT_X_SASL_SECPROPS, secprops.c_str());
    if (noCanon) {
        int v = 1;
        ldap_set_option(ld, LDAP_OPT_X_SASL_NOCANON, &v);
    }

    const char *dn = nullptr;
    // Empty mech means "pick the library/SASL default" (like ldapsearch
    // without -Y): pass nullptr so libldap negotiates its configured default
    // mechanism instead of trying a literal empty mechanism name.
    const char *mechStr = mech.empty() ? nullptr : mech.c_str();
    unsigned saslFlags = interactive ? 0 : LDAP_SASL_QUIET;

    int rc = ldap_sasl_interactive_bind_s(ld, dn, mechStr, nullptr, nullptr,
                                          saslFlags, saslNullInteract, nullptr);

    lastErrno = rc;
    lastError = formatError(rc, ld);
    return rc == LDAP_SUCCESS;
}

// ── Search ──────────────────────────────────────────────

// Forward declaration: freeUserControls() is defined in the Controls
// section near the end of this file, after search().
static void freeUserControls(LDAPControl **arr);

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
                       std::vector<LDAPEntry> &results, bool attrsonly) {
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
    LDAPControl **userCtrls = buildControlArray();
    int userCount = 0;
    if (userCtrls) {
        while (userCtrls[userCount]) userCount++;
    }
    // If the caller already supplied a paged-results control (-E pr=…),
    // leave paging to that control and do a single search as before.
    bool userPaging = false;
    for (const auto &c : ctrls_)
        if (c.oid == "1.2.840.113556.1.4.319") { userPaging = true; break; }

    struct timeval tv;
    tv.tv_sec = timelimit;
    tv.tv_usec = 0;

    // Per-request size limit: honour an explicit -z limit, otherwise page size.
    int pageSize = (sizelimit > 0 && sizelimit < static_cast<int>(pagingSize))
                   ? sizelimit : static_cast<int>(pagingSize);

    LDAPMessage *res = nullptr;
    int rc = LDAP_SUCCESS;
    BerValue cookie = {0, nullptr};
    bool paging = !userPaging && pageSize > 0;
    int msgid = 0;

    do {
        LDAPControl *pageCtrl = nullptr;
        if (paging) {
            if (ldap_create_page_control(ld, pageSize, &cookie, 0, &pageCtrl) != LDAP_SUCCESS)
                pageCtrl = nullptr;
        }

        LDAPControl showDeletedCtrl;
        LDAPControl **srvCtrls = nullptr;
        int totalCtls = (showDeleted ? 1 : 0) + userCount + (pageCtrl ? 1 : 0);
        if (totalCtls > 0) {
            srvCtrls = static_cast<LDAPControl**>(malloc((totalCtls + 1) * sizeof(LDAPControl*)));
            int idx = 0;
            if (showDeleted) {
                showDeletedCtrl.ldctl_oid = const_cast<char*>("1.2.840.113556.1.4.417");
                showDeletedCtrl.ldctl_value.bv_val = nullptr;
                showDeletedCtrl.ldctl_value.bv_len = 0;
                showDeletedCtrl.ldctl_iscritical = 1;
                srvCtrls[idx++] = &showDeletedCtrl;
            }
            for (int i = 0; i < userCount; i++)
                srvCtrls[idx++] = userCtrls[i];
            if (pageCtrl)
                srvCtrls[idx++] = pageCtrl;
            srvCtrls[idx] = nullptr;
        }

        rc = ldap_search_ext(ld, baseDN.c_str(), scope,
                             filter.c_str(), const_cast<char**>(attrsArray.data()),
                             attrsonly ? 1 : 0, srvCtrls, nullptr, &tv,
                             sizelimit, &msgid);

        free(srvCtrls);
        if (pageCtrl) ldap_control_free(pageCtrl);

        if (rc != LDAP_SUCCESS) {
            if (cookie.bv_val) ber_memfree(cookie.bv_val);
            freeUserControls(userCtrls);
            lastErrno = rc;
            lastError = formatError(rc, ld);
            diratlas::dbgLog(diratlas::LDAP_DEBUG_STATS, "search: ldap_search_ext -> " + std::to_string(rc)
                + " (" + lastError + ")");
            return false;
        }

        struct timeval pageTv = {timelimit, 0};
        rc = ldap_result(ld, msgid, LDAP_MSG_ALL, &pageTv, &res);
        if (rc < 0) {
            if (res) ldap_msgfree(res);
            if (cookie.bv_val) ber_memfree(cookie.bv_val);
            freeUserControls(userCtrls);
            int err = rc;
            ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER, &err);
            lastErrno = err;
            lastError = formatError(err, ld);
            return false;
        }
        if (rc == 0) {
            ldap_abandon_ext(ld, msgid, nullptr, nullptr);
            if (res) ldap_msgfree(res);
            if (cookie.bv_val) ber_memfree(cookie.bv_val);
            freeUserControls(userCtrls);
            lastErrno = LDAP_TIMEOUT;
            lastError = formatError(LDAP_TIMEOUT, ld);
            return false;
        }

        // Parse the result code and fetch response controls (incl. paged results)
        int errcode = 0;
        char *matched = nullptr;
        char *diagmsg = nullptr;
        LDAPControl **rctrls = nullptr;
        ldap_parse_result(ld, res, &errcode, &matched, &diagmsg, nullptr, &rctrls, 0);

        // Accept partial results even on limit-exceeded errors
        bool partial = (errcode == 4 || errcode == 3 || errcode == 11);

        if (errcode != LDAP_SUCCESS && !partial) {
            if (res) ldap_msgfree(res);
            if (matched) ldap_memfree(matched);
            if (diagmsg) ldap_memfree(diagmsg);
            if (rctrls) ldap_controls_free(rctrls);
            if (cookie.bv_val) ber_memfree(cookie.bv_val);
            freeUserControls(userCtrls);
            lastErrno = errcode;
            lastError = formatError(errcode, ld);
            diratlas::dbgLog(diratlas::LDAP_DEBUG_STATS, "search: result err=" + std::to_string(errcode)
                + " (" + lastError + ")");
            return false;
        }

        if (partial) {
            lastErrno = errcode;
            lastError = formatError(errcode, ld);
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

                // With attrsonly=1 the server sends attribute descriptions
                // without values: ldap_get_values_len() may return NULL then,
                // so the attribute name must be registered regardless.
                entry.attributeNames.push_back(attrName);

                BerValue **bvals = ldap_get_values_len(ld, msg, attr);
                if (bvals) {
                    int count = ldap_count_values_len(bvals);
                    std::vector<std::string> strVals;
                    std::vector<std::vector<uint8_t>> binVals;
                    for (int i = 0; i < count; i++) {
                        if (bvals[i]->bv_val && bvals[i]->bv_len > 0) {
                            strVals.push_back(std::string(bvals[i]->bv_val, bvals[i]->bv_len));
                            binVals.push_back(std::vector<uint8_t>(bvals[i]->bv_val,
                                                                   bvals[i]->bv_val + bvals[i]->bv_len));
                        } else {
                            strVals.emplace_back();
                            binVals.emplace_back();
                        }
                    }
                    entry.attributes[attrName] = strVals;
                    entry.binaryAttributes[attrName] = binVals;
                    ldap_value_free_len(bvals);
                }

                ldap_memfree(attr);
                attr = ldap_next_attribute(ld, msg, ber);
            }
            if (ber) ber_free(ber, 0);

            results.push_back(std::move(entry));
            if (sizelimit > 0 && static_cast<int>(results.size()) >= sizelimit) {
                if (res) ldap_msgfree(res);
                if (matched) ldap_memfree(matched);
                if (diagmsg) ldap_memfree(diagmsg);
                if (rctrls) ldap_controls_free(rctrls);
                if (cookie.bv_val) ber_memfree(cookie.bv_val);
                freeUserControls(userCtrls);
                return true;
            }
        }

        if (!paging) {
            if (res) { ldap_msgfree(res); res = nullptr; }
            if (matched) ldap_memfree(matched);
            if (diagmsg) ldap_memfree(diagmsg);
            if (rctrls) ldap_controls_free(rctrls);
            break;
        }

        // Extract the paged-results response control (OID 1.2.840.113556.1.4.319)
        BerValue nextCookie = {0, nullptr};
        bool hasNext = false;
        if (rctrls) {
            for (int i = 0; rctrls[i]; i++) {
                if (rctrls[i]->ldctl_oid &&
                    strcmp(rctrls[i]->ldctl_oid, "1.2.840.113556.1.4.319") == 0) {
                    ber_int_t estSize = 0;
                    if (ldap_parse_pageresponse_control(ld, rctrls[i], &estSize, &nextCookie) == LDAP_SUCCESS
                        && nextCookie.bv_len > 0) {
                        hasNext = true;
                    }
                    break;
                }
            }
        }

        if (res) { ldap_msgfree(res); res = nullptr; }
        if (matched) ldap_memfree(matched);
        if (diagmsg) ldap_memfree(diagmsg);
        if (rctrls) ldap_controls_free(rctrls);

        if (!hasNext) {
            if (nextCookie.bv_val) ber_memfree(nextCookie.bv_val);
            break;
        }
        if (cookie.bv_val) ber_memfree(cookie.bv_val);
        cookie = nextCookie;
    } while (true);

    if (res) ldap_msgfree(res);
    if (cookie.bv_val) ber_memfree(cookie.bv_val);
    freeUserControls(userCtrls);
    diratlas::dbgLog(diratlas::LDAP_DEBUG_STATS, "search: done, " + std::to_string(results.size()) + " entry/entries");
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

namespace {
// Build a NULL-terminated char* array from a comma-joined attribute list.
// The returned pointers reference the provided std::string's buffer, which
// must therefore outlive the array (same pattern as LDAPConn::search).
std::vector<const char*> buildAttrArray(std::string &joined) {
    std::vector<const char*> out;
    char *copy = joined.data();
    char *token = strtok(copy, ",");
    while (token) { out.push_back(token); token = strtok(nullptr, ","); }
    out.push_back(nullptr);
    return out;
}
} // namespace

bool LDAPConn::persistentSearch(const std::string &baseDN, int scope,
                                const std::string &filter,
                                const std::vector<std::string> &attrs, int maxWaitSec,
                                const std::function<bool(const std::string &dn,
                                                         const std::string &change)> &callback) {
    if (!ld) return false;
    lastErrno = 0;
    lastError.clear();
    std::string attrsJoined;
    for (const auto &a : attrs) {
        if (!attrsJoined.empty()) attrsJoined += ",";
        attrsJoined += a;
    }
    if (attrsJoined.empty()) attrsJoined = "*,+";
    auto attrArray = buildAttrArray(attrsJoined);

    // RFC 4533-style persistent search control (draft-ietf-ldapext-psearch):
    // changeTypes=all (7), changesOnly=false, returnECs=true.
    LDAPControl psCtrl;
    BerValue psVal{};
    struct berval created = {};
    if (ldap_create_persistentsearch_control_value(ld, 7, 0, 1, &created) == LDAP_SUCCESS) {
        psVal.bv_val = created.bv_val;
        psVal.bv_len = created.bv_len;
    }
    psCtrl.ldctl_oid = const_cast<char*>(LDAP_CONTROL_PERSIST_REQUEST);
    psCtrl.ldctl_value = psVal;
    psCtrl.ldctl_iscritical = 1;

    LDAPControl *srvCtrls[] = {&psCtrl, nullptr};
    struct timeval tv = {maxWaitSec, 0};
    int msgid = 0;
    int rc = ldap_search_ext(ld, baseDN.c_str(), scope, filter.c_str(),
                             const_cast<char**>(attrArray.data()), 0,
                             srvCtrls, nullptr, &tv, 0, &msgid);
    if (created.bv_val) ber_memfree(created.bv_val);
    if (rc != LDAP_SUCCESS) {
        lastErrno = rc;
        lastError = formatError(rc, ld);
        return false;
    }

    bool ended = false;
    while (!ended) {
        LDAPMessage *res = nullptr;
        struct timeval wait = {maxWaitSec, 0};
        rc = ldap_result(ld, msgid, LDAP_MSG_ONE, &wait, &res);
        if (rc == -1) {
            int err = LDAP_UNAVAILABLE;
            ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER, &err);
            lastErrno = err;
            lastError = formatError(err, ld);
            return false;
        }
        if (rc == 0) {
            lastErrno = LDAP_TIMEOUT;
            lastError = formatError(LDAP_TIMEOUT, ld);
            return false;
        }

        int msgtype = ldap_msgtype(res);
        if (msgtype == LDAP_RES_SEARCH_ENTRY) {
            char *dn = ldap_get_dn(ld, res);
            std::string dnStr = dn ? dn : "";
            if (dn) ldap_memfree(dn);

            std::string change = "entry";
            LDAPControl **rctrls = nullptr;
            ldap_parse_result(ld, res, nullptr, nullptr, nullptr, nullptr, &rctrls, 0);
            if (rctrls) {
                for (int i = 0; rctrls[i]; i++) {
                    if (rctrls[i]->ldctl_oid &&
                        strcmp(rctrls[i]->ldctl_oid, LDAP_CONTROL_PERSIST_ENTRY_CHANGE_NOTICE) == 0 &&
                        rctrls[i]->ldctl_value.bv_val && rctrls[i]->ldctl_value.bv_len >= 5) {
                        // BER: SEQUENCE { ENUMERATED changeType, ... } → type at byte 4
                        switch (rctrls[i]->ldctl_value.bv_val[4]) {
                            case 1: change = "add"; break;
                            case 2: change = "delete"; break;
                            case 4: change = "modify"; break;
                            case 8: change = "moddn"; break;
                            default: change = "entry"; break;
                        }
                    }
                }
                ldap_controls_free(rctrls);
            }
            if (callback && !callback(dnStr, change)) {
                ldap_msgfree(res);
                ldap_abandon_ext(ld, msgid, nullptr, nullptr);
                return true;
            }
        } else if (msgtype == LDAP_RES_SEARCH_RESULT) {
            int errcode = 0;
            ldap_parse_result(ld, res, &errcode, nullptr, nullptr, nullptr, nullptr, 0);
            lastErrno = errcode;
            lastError = formatError(errcode, ld);
            ended = true;
        }
        ldap_msgfree(res);
    }
    return true;
}

bool LDAPConn::syncRefreshOnly(const std::string &baseDN, int scope,
                               const std::string &filter,
                               const std::vector<std::string> &attrs,
                               std::vector<LDAPEntry> &results, std::string &cookie) {
    if (!ld) return false;
    lastErrno = 0;
    lastError.clear();
    results.clear();
    cookie.clear();
    std::string attrsJoined;
    for (const auto &a : attrs) {
        if (!attrsJoined.empty()) attrsJoined += ",";
        attrsJoined += a;
    }
    if (attrsJoined.empty()) attrsJoined = "*,+";
    auto attrArray = buildAttrArray(attrsJoined);

    // RFC 4533 syncRequestValue: SEQUENCE { mode ENUMERATED (1=refreshOnly) }
    BerElement *ber = ber_alloc_t(LBER_USE_DER);
    if (!ber) return false;
    ber_printf(ber, "{e}", 1);
    struct berval bv = {};
    ber_flatten2(ber, &bv, 1);

    LDAPControl syncCtrl;
    syncCtrl.ldctl_oid = const_cast<char*>(LDAP_CONTROL_SYNC);
    syncCtrl.ldctl_value = bv;
    syncCtrl.ldctl_iscritical = 1;
    LDAPControl *srvCtrls[] = {&syncCtrl, nullptr};

    struct timeval tv = {timelimit, 0};
    int msgid = 0;
    int rc = ldap_search_ext(ld, baseDN.c_str(), scope, filter.c_str(),
                             const_cast<char**>(attrArray.data()), 0,
                             srvCtrls, nullptr, &tv, sizelimit, &msgid);
    if (rc != LDAP_SUCCESS) {
        lastErrno = rc;
        lastError = formatError(rc, ld);
        return false;
    }

    LDAPMessage *res = nullptr;
    rc = ldap_result(ld, msgid, LDAP_MSG_ALL, &tv, &res);
    if (rc <= 0) {
        if (res) ldap_msgfree(res);
        lastErrno = rc == 0 ? LDAP_TIMEOUT : LDAP_UNAVAILABLE;
        lastError = formatError(lastErrno, ld);
        return false;
    }

    LDAPControl **rctrls = nullptr;
    ldap_parse_result(ld, res, nullptr, nullptr, nullptr, nullptr, &rctrls, 0);
    if (rctrls) {
        for (int i = 0; rctrls[i]; i++) {
            // SyncDoneValue ::= SEQUENCE { cookie OCTET STRING OPTIONAL, ... }
            if (rctrls[i]->ldctl_oid &&
                strcmp(rctrls[i]->ldctl_oid, LDAP_CONTROL_SYNC_DONE) == 0 &&
                rctrls[i]->ldctl_value.bv_val && rctrls[i]->ldctl_value.bv_len >= 4) {
                BerValue val = rctrls[i]->ldctl_value;
                // skip SEQUENCE tag+len, expect OCTET STRING tag
                size_t off = 0;
                if (val.bv_val[off] == 0x30) {
                    off++;
                    if ((val.bv_val[off] & 0x80) == 0) off += 1;
                    else off += 1 + (val.bv_val[off] & 0x7F);
                }
                if (off + 2 <= val.bv_len && val.bv_val[off] == 0x04) {
                    size_t len = val.bv_val[off + 1];
                    if (len < 128 && off + 2 + len <= val.bv_len)
                        cookie.assign(reinterpret_cast<char*>(val.bv_val + off + 2), len);
                }
            }
        }
        ldap_controls_free(rctrls);
    }

    for (LDAPMessage *msg = ldap_first_entry(ld, res); msg != nullptr;
         msg = ldap_next_entry(ld, msg)) {
        LDAPEntry entry;
        char *dn = ldap_get_dn(ld, msg);
        if (dn) { entry.dn = dn; ldap_memfree(dn); }
        BerElement *ber2 = nullptr;
        char *attr = ldap_first_attribute(ld, msg, &ber2);
        while (attr) {
            entry.attributeNames.push_back(attr);
            BerValue **bvals = ldap_get_values_len(ld, msg, attr);
            if (bvals) {
                int count = ldap_count_values_len(bvals);
                std::vector<std::string> strVals;
                std::vector<std::vector<uint8_t>> binVals;
                for (int i = 0; i < count; i++) {
                    if (bvals[i]->bv_val && bvals[i]->bv_len > 0) {
                        strVals.push_back(std::string(bvals[i]->bv_val, bvals[i]->bv_len));
                        binVals.push_back(std::vector<uint8_t>(bvals[i]->bv_val,
                                                               bvals[i]->bv_val + bvals[i]->bv_len));
                    } else {
                        strVals.emplace_back();
                        binVals.emplace_back();
                    }
                }
                entry.attributes[attr] = strVals;
                entry.binaryAttributes[attr] = binVals;
                ldap_value_free_len(bvals);
            }
            ldap_memfree(attr);
            attr = ldap_next_attribute(ld, msg, ber2);
        }
        if (ber2) ber_free(ber2, 0);
        results.push_back(std::move(entry));
    }
    if (res) ldap_msgfree(res);
    return true;
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

std::vector<std::string> LDAPConn::getCapabilities(const std::string &what) {
    auto entry = searchOne("", "(objectClass=*)", {what}, false);
    return entry.getAttrs(what);
}

/**
 * @brief Detect the LDAP server family from the RootDSE.
 *
 * Detection order:
 *   MicrosoftAD  - rootDomainNamingContext / forestFunctionality /
 *                  domainFunctionality present, or vendorName is Microsoft.
 *   EDirectoryLDAP - vendorName Novell/NetIQ/OpenText, or vendorVersion
 *                  mentions "eDirectory", or NDSDsRootDSE objectClass.
 *   IBMLDAP      - vendorName contains "IBM", or ibm-* rootDSE attributes.
 *   NetscapeLDAP - vendorName is 389/Netscape/Sun/Oracle/Red Hat, or
 *                  rootNamingContext present.
 *   StandardLDAP - otherwise (OpenLDAProotDSE present, or default).
 */
void LDAPConn::guessFlavor() {
    auto entry = searchOne("", "(objectClass=*)",
        {"objectClass", "vendorName", "vendorVersion", "rootDomainNamingContext",
         "rootNamingContext", "forestFunctionality", "domainFunctionality",
         "supportedControl", "ibm-enabledcapabilities", "ibm-serverId",
         "ibmdirectoryversion"}, false);

    // Microsoft AD
    if (!entry.getAttr("rootDomainNamingContext").empty() ||
        !entry.getAttr("forestFunctionality").empty() ||
        !entry.getAttr("domainFunctionality").empty()) {
        flavor = LDAPFlavor::MicrosoftAD;
        return;
    }

    std::string vendor = entry.getAttr("vendorName");
    std::string vl = vendor;
    std::transform(vl.begin(), vl.end(), vl.begin(), ::tolower);
    std::string ver = entry.getAttr("vendorVersion");
    std::string verl = ver;
    std::transform(verl.begin(), verl.end(), verl.begin(), ::tolower);

    if (vl.find("microsoft") != std::string::npos) {
        flavor = LDAPFlavor::MicrosoftAD;
        return;
    }

    // eDirectory (Novell/NetIQ/OpenText) — vendor names and "eDirectory"
    // in vendorVersion, or the NDS-specific rootDSE objectClass.
    if (vl.find("novell") != std::string::npos ||
        vl.find("netiq") != std::string::npos ||
        vl.find("opentext") != std::string::npos ||
        verl.find("edirectory") != std::string::npos) {
        flavor = LDAPFlavor::EDirectoryLDAP;
        return;
    }
    for (const auto &c : entry.getAttrs("objectClass"))
        if (c == "NDSDsRootDSE") { flavor = LDAPFlavor::EDirectoryLDAP; return; }

    // IBM Security Verify Directory / Tivoli — "IBM" vendor or ibm-* attrs.
    if (vl.find("ibm") != std::string::npos ||
        !entry.getAttr("ibm-enabledcapabilities").empty() ||
        !entry.getAttr("ibm-serverId").empty() ||
        !entry.getAttr("ibmdirectoryversion").empty()) {
        flavor = LDAPFlavor::IBMLDAP;
        return;
    }

    // Netscape lineage
    if (vl.find("389") != std::string::npos ||
        vl.find("netscape") != std::string::npos ||
        vl.find("sun") != std::string::npos ||
        vl.find("oracle") != std::string::npos ||
        vl.find("red hat") != std::string::npos ||
        !entry.getAttr("rootNamingContext").empty()) {
        flavor = LDAPFlavor::NetscapeLDAP;
        return;
    }

    // Basic LDAP fallback (unless already identified as another family above)
    if (flavor == LDAPFlavor::MicrosoftAD)
        flavor = LDAPFlavor::StandardLDAP;

    // Capture a server version string when available: vendorVersion on the
    // RootDSE, or OpenLDAP's cn=Monitor/monitoredInfo (e.g. "slapd 2.6.13").
    if (!ver.empty())
        serverVersion = ver;
    else if (flavor == LDAPFlavor::StandardLDAP) {
        auto mon = searchOne("cn=Monitor", "(objectClass=*)", {"monitoredInfo"}, false);
        serverVersion = mon.getAttr("monitoredInfo");
        // Strip a leading "OpenLDAP: " so the version reads cleanly.
        const std::string prefix = "OpenLDAP: ";
        if (serverVersion.compare(0, prefix.size(), prefix) == 0)
            serverVersion = serverVersion.substr(prefix.size());
    }
}

// ── Object CRUD ─────────────────────────────────────────

/** @brief Delete an LDAP object by DN. */
bool LDAPConn::deleteObject(const std::string &dn) {
    int rc = ldap_delete_ext_s(ld, dn.c_str(), nullptr, nullptr);
    lastErrno = rc;
    lastError = formatError(rc, ld);
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
    lastErrno = rc;
    lastError = formatError(rc, ld);
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

/** @brief Atomically replace one value of an attribute (DELETE old + ADD new). */
bool LDAPConn::replaceAttributeValue(const std::string &dn, const std::string &attr,
                                     const std::string &oldValue, const std::string &newValue) {
    if (oldValue == newValue) return true;

    LDAPMod del;
    const char* delVals[] = {oldValue.c_str(), nullptr};
    del.mod_op = LDAP_MOD_DELETE;
    del.mod_type = const_cast<char*>(attr.c_str());
    del.mod_vals.modv_strvals = const_cast<char**>(delVals);

    LDAPMod add;
    const char* addVals[] = {newValue.c_str(), nullptr};
    add.mod_op = LDAP_MOD_ADD;
    add.mod_type = const_cast<char*>(attr.c_str());
    add.mod_vals.modv_strvals = const_cast<char**>(addVals);

    LDAPMod *mods[] = {&del, &add, nullptr};
    int rc = ldap_modify_ext_s(ld, dn.c_str(), mods, nullptr, nullptr);
    lastErrno = rc;
    lastError = formatError(rc, ld);
    return rc == LDAP_SUCCESS;
}

bool LDAPConn::modifyIncrement(const std::string &dn, const std::string &attr,
                               const std::string &delta) {
    if (!ld) return false;
    lastErrno = 0;
    lastError.clear();

    // RFC 4525: the delta is carried as the attribute value (ASCII integer).
    LDAPMod mod;
    BerValue bv{};
    bv.bv_val = const_cast<char*>(delta.data());
    bv.bv_len = static_cast<ber_len_t>(delta.size());
    BerValue *bvals[] = {&bv, nullptr};
    mod.mod_op = LDAP_MOD_INCREMENT;
    mod.mod_type = const_cast<char*>(attr.c_str());
    mod.mod_bvalues = bvals;

    LDAPMod *mods[] = {&mod, nullptr};
    int rc = ldap_modify_ext_s(ld, dn.c_str(), mods, nullptr, nullptr);
    lastErrno = rc;
    lastError = formatError(rc, ld);
    diratlas::dbgLog(diratlas::LDAP_DEBUG_STATS, "modify-increment: " + attr + " " + delta
        + " on " + dn + " -> " + std::to_string(rc));
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
    lastErrno = rc;
    lastError = formatError(rc, ld);
    return rc == LDAP_SUCCESS;
}

/** @brief Remove a single value of an attribute (LDAP_MOD_DELETE with value). */
bool LDAPConn::deleteAttributeValue(const std::string &dn, const std::string &attr,
                                    const std::string &value) {    LDAPMod mod;
    const char* vals[] = {value.c_str(), nullptr};
    mod.mod_op = LDAP_MOD_DELETE;
    mod.mod_type = const_cast<char*>(attr.c_str());
    mod.mod_vals.modv_strvals = const_cast<char**>(vals);

    LDAPMod *mods[] = {&mod, nullptr};
    int rc = ldap_modify_ext_s(ld, dn.c_str(), mods, nullptr, nullptr);
    lastErrno = rc;
    lastError = formatError(rc, ld);
    return rc == LDAP_SUCCESS;
}

int LDAPConn::compare(const std::string &dn, const std::string &attr,
                      const std::string &value) {
    BerValue bv{};
    bv.bv_val = const_cast<char*>(value.data());
    bv.bv_len = static_cast<ber_len_t>(value.size());
    int rc = ldap_compare_ext_s(ld, dn.c_str(), attr.c_str(), &bv,
                                nullptr, nullptr);
    lastErrno = rc;
    lastError = formatError(rc, ld);
    if (rc == LDAP_COMPARE_TRUE) return 1;
    if (rc == LDAP_COMPARE_FALSE) return 0;
    return -1;
}

/** @brief Rename and/or move an entry (RFC 4511 ModifyDN). */
bool LDAPConn::renameObject(const std::string &dn, const std::string &newRdn,
                            bool deleteOldRdn, const std::string &newSuperior) {
    const char* superior = newSuperior.empty() ? nullptr : newSuperior.c_str();
    int rc = ldap_rename_s(ld, dn.c_str(),
                           const_cast<char*>(newRdn.c_str()),
                           superior, deleteOldRdn ? 1 : 0,
                           nullptr, nullptr);
    lastErrno = rc;
    lastError = formatError(rc, ld);
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
    lastErrno = rc;
    lastError = formatError(rc, ld);
    return rc == LDAP_SUCCESS;
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

/** @brief Free a control array previously returned by buildControlArray(). */
static void freeUserControls(LDAPControl **arr) {
    if (!arr) return;
    for (int i = 0; arr[i]; i++) {
        free(arr[i]->ldctl_oid);
        free(arr[i]->ldctl_value.bv_val);
        free(arr[i]);
    }
    free(arr);
}

/** @brief Register a user-supplied LDAP control (added to all subsequent searches). */
void LDAPConn::addControl(const LdapControl &ctrl) {
    ctrls_.push_back(ctrl);
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

/** @brief BER-encode a BOOLEAN (tag 0x01, true=0xFF / false=0x00). */
static std::vector<uint8_t> berEncodeBool(bool val) {
    return {0x01, 0x01, static_cast<uint8_t>(val ? 0xFF : 0x00)};
}

/** @brief BER-encode an OCTET STRING (tag 0x04). */
static std::vector<uint8_t> berEncodeOctet(const std::string &s) {
    if (s.size() > 127) return {};
    std::vector<uint8_t> ber = {0x04, static_cast<uint8_t>(s.size())};
    ber.insert(ber.end(), s.begin(), s.end());
    return ber;
}

/** @brief BER-encode an ENUMERATED value (tag 0x0A). */
static std::vector<uint8_t> berEncodeEnum(int32_t val) {
    std::vector<uint8_t> ber = berEncodeInt(val);
    if (!ber.empty()) ber[0] = 0x0A;
    return ber;
}

/** @brief Wrap existing BER TLVs into a SEQUENCE (tag 0x30). */
static std::vector<uint8_t> berWrapSeq(const std::vector<uint8_t> &content) {
    if (content.size() > 127) return {};
    std::vector<uint8_t> ber = {0x30, static_cast<uint8_t>(content.size())};
    ber.insert(ber.end(), content.begin(), content.end());
    return ber;
}

/**
 * @brief Split a comma-separated or slash-separated attribute list.
 */
static std::vector<std::string> splitAttrList(const std::string &s) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : s) {
        if (c == ',' || c == '/' || c == ' ') {
            if (!cur.empty()) { out.push_back(cur); cur.clear(); }
        } else {
            cur += c;
        }
    }
    if (!cur.empty()) out.push_back(cur);
    return out;
}

/** @brief Copy a struct berval into a vector<uint8_t>. */
static void bervalToVector(const struct berval &bv, std::vector<uint8_t> &out) {
    out.assign(reinterpret_cast<const uint8_t*>(bv.bv_val),
               reinterpret_cast<const uint8_t*>(bv.bv_val) + bv.bv_len);
}

/** @brief Parse a control spec prefix "[!]name[=param]" into its parts. */
static bool splitControlSpec(const std::string &spec, bool &critical,
                             std::string &ext, std::string &param) {
    critical = false;
    size_t pos = 0;
    if (pos < spec.size() && spec[pos] == '!') { critical = true; pos++; }
    auto eq = spec.find('=', pos);
    ext = spec.substr(pos, eq - pos);
    if (eq != std::string::npos) param = spec.substr(eq + 1);
    return !ext.empty();
}

/**
 * @brief Parse a -e/-E control specification string without a connection.
 *
 * Supports the flag-only / simple-valued controls that don't need an LDAP
 * handle (OID + optional BER-encoded value). The MLDAPCreateComplex__*
 * group (paged results, sorting, VLV, assertions, ...) is handled by
 * addControlSpec() which requires a live LDAP handle.
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
    std::string ext, param;
    value.clear();
    if (!splitControlSpec(spec, critical, ext, param)) return false;

    auto flagOnly = [&](const char *oidStr) {
        oid = oidStr;
        return true;
    };

    if (ext == "manageDSAit")   return flagOnly(LDAP_CONTROL_MANAGEDSAIT);
    if (ext == "manageDIT" || ext == "relax") return flagOnly(LDAP_CONTROL_RELAX);
    if (ext == "noop")          return flagOnly(LDAP_CONTROL_NOOP);
    if (ext == "domainScope")   return flagOnly(LDAP_CONTROL_X_DOMAIN_SCOPE);
    if (ext == "dontUseCopy")   return flagOnly(LDAP_CONTROL_DONTUSECOPY);
    if (ext == "showDeleted")   return flagOnly(LDAP_CONTROL_X_SHOW_DELETED);
    if (ext == "serverNotif")   return flagOnly(LDAP_CONTROL_X_SERVER_NOTIFICATION);
    if (ext == "accountUsability") return flagOnly(LDAP_CONTROL_X_ACCOUNT_USABILITY);
    if (ext == "ppolicy")       return flagOnly(LDAP_CONTROL_PASSWORDPOLICYREQUEST);
    // PingDS / Netscape flag controls (no value)
    if (ext == "realAttributesOnly" || ext == "realAttrsonly")
        return flagOnly("2.16.840.1.113730.3.4.17");
    if (ext == "virtualAttributesOnly" || ext == "virtualAttrsonly")
        return flagOnly("2.16.840.1.113730.3.4.19");

    if (ext == "subentries") {
        oid = LDAP_CONTROL_SUBENTRIES;
        value = berEncodeBool(param == "true" || param.empty());
        return true;
    }

    if (ext == "chaining") {
        // LDAP_CONTROL_X_CHAINING_BEHAVIOR ::= SEQUENCE { resolve ENUMERATED,
        // continuation ENUMERATED OPTIONAL }
        oid = LDAP_CONTROL_X_CHAINING_BEHAVIOR;
        int resolve = LDAP_CHAINING_PREFERRED;
        std::string continuation;
        auto sl = param.find('/');
        if (sl != std::string::npos) {
            std::string r = param.substr(0, sl);
            continuation = param.substr(sl + 1);
            if (r == "chainingPreferred") resolve = LDAP_CHAINING_PREFERRED;
            else if (r == "chainingRequired") resolve = LDAP_CHAINING_REQUIRED;
            else if (r == "referralsPreferred") resolve = LDAP_REFERRALS_PREFERRED;
            else if (r == "referralsRequired") resolve = LDAP_REFERRALS_REQUIRED;
            else return false;
        } else if (param == "chainingPreferred") resolve = LDAP_CHAINING_PREFERRED;
        else if (param == "chainingRequired") resolve = LDAP_CHAINING_REQUIRED;
        else if (param == "referralsPreferred") resolve = LDAP_REFERRALS_PREFERRED;
        else if (param == "referralsRequired") resolve = LDAP_REFERRALS_REQUIRED;
        else if (!param.empty()) return false;

        auto content = berEncodeEnum(resolve);
        if (!continuation.empty()) {
            int cont = LDAP_CHAINING_PREFERRED;
            if (continuation == "chainingPreferred") cont = LDAP_CHAINING_PREFERRED;
            else if (continuation == "chainingRequired") cont = LDAP_CHAINING_REQUIRED;
            else if (continuation == "referralsPreferred") cont = LDAP_REFERRALS_PREFERRED;
            else if (continuation == "referralsRequired") cont = LDAP_REFERRALS_REQUIRED;
            else return false;
            auto ce = berEncodeEnum(cont);
            content.insert(content.end(), ce.begin(), ce.end());
        }
        value = berWrapSeq(content);
        return !value.empty();
    }

    if (ext == "sync") {
        // LDAP_CONTROL_SYNC ::= SEQUENCE { mode ENUMERATED, cookie OCTET STRING OPTIONAL }
        oid = LDAP_CONTROL_SYNC;
        std::string modeStr, cookie;
        auto cm = param.find('/');
        if (cm != std::string::npos) {
            modeStr = param.substr(0, cm);
            cookie = param.substr(cm + 1);
        } else {
            modeStr = param;
        }
        int mode = -1;
        if (modeStr == "ro" || modeStr == "refreshOnly") mode = 1;
        else if (modeStr == "rp" || modeStr == "refreshAndPersist") mode = 3;
        else return false;
        auto content = berEncodeEnum(mode);
        if (!cookie.empty()) {
            auto co = berEncodeOctet(cookie);
            if (co.empty()) return false;
            content.insert(content.end(), co.begin(), co.end());
        }
        value = berWrapSeq(content);
        return !value.empty();
    }

    if (ext == "pr" || ext == "paged") {
        // RFC 2696: SEQUENCE { size INTEGER, cookie OCTET STRING }
        oid = LDAP_CONTROL_PAGEDRESULTS;
        int size = 0;
        std::string sizeStr = param.substr(0, param.find('/'));
        if (!sizeStr.empty()) {
            try { size = std::stoi(sizeStr); }
            catch (...) { return false; }
        }
        value = berWrapSeq(berEncodeInt(size));
        return !value.empty();
    }

    if (ext == "extendedDn") {
        oid = LDAP_CONTROL_X_EXTENDED_DN;
        int flag = 0;
        if (!param.empty()) {
            try { flag = std::stoi(param); }
            catch (...) { return false; }
        }
        value = berEncodeInt(flag);
        return true;
    }

    if (ext == "tz" || ext == "timezone") {
        oid = "1.3.6.1.4.1.4203.1.10.2";  // draft-ietf-ldapext-tz
        value = berEncodeOctet(param);
        return !param.empty() || !value.empty();
    }

    if (ext == "sessiontracking") {
        // <draft-wahl-ldap-session-03> value:
        // SEQUENCE { sessionSourceIp OCTET STRING,
        //            sessionSourceName OCTET STRING,
        //            formatOID OCTET STRING,
        //            sessionTrackingIdentifier OCTET STRING }
        // Mirrors OpenLDAP ldap_create_session_tracking_value().
        oid = LDAP_CONTROL_X_SESSION_TRACKING;
        std::vector<uint8_t> content;
        auto ip = berEncodeOctet("");
        auto name = berEncodeOctet("");
        auto fmt = berEncodeOctet(LDAP_CONTROL_X_SESSION_TRACKING_USERNAME);
        auto id = berEncodeOctet(param);
        if (fmt.empty() || id.empty()) return false;
        content.insert(content.end(), ip.begin(), ip.end());
        content.insert(content.end(), name.begin(), name.end());
        content.insert(content.end(), fmt.begin(), fmt.end());
        content.insert(content.end(), id.begin(), id.end());
        value = berWrapSeq(content);
        return !value.empty();
    }

    if (ext == "transactionID" || ext == "transactionId") {
        // PingDS proprietary: control value is the UTF-8 transaction ID
        oid = "1.3.6.1.4.1.36733.2.1.5.1";
        if (param.empty()) return false;
        value = berEncodeOctet(param);
        return !value.empty();
    }

    if (ext == "effectiverights" || ext == "getEffectiveRights") {
        // <draft-ietf-ldapext-acl-model> request value:
        // SEQUENCE { authzId OCTET STRING,
        //            attributes SEQUENCE OF OCTET STRING }
        oid = "1.3.6.1.4.1.42.2.27.9.5.2";
        std::string authzId = param;
        std::vector<std::string> attrs;
        auto sep = param.find('/');
        if (sep != std::string::npos) {
            authzId = param.substr(0, sep);
            attrs = splitAttrList(param.substr(sep + 1));
        }
        if (authzId.empty()) return false;
        std::vector<uint8_t> content = berEncodeOctet(authzId);
        std::vector<uint8_t> attrSeq;
        for (auto &a : attrs) {
            auto oct = berEncodeOctet(a);
            if (oct.empty()) return false;
            attrSeq.insert(attrSeq.end(), oct.begin(), oct.end());
        }
        auto attrsWrap = berWrapSeq(attrSeq);
        if (attrsWrap.empty()) return false;
        content.insert(content.end(), attrsWrap.begin(), attrsWrap.end());
        value = berWrapSeq(content);
        return !value.empty();
    }

    if (ext.find('.') != std::string::npos ||
        (ext.size() > 2 && ext[0] >= '0' && ext[0] <= '9')) {
        // Generic control: "!<oid>" or "<oid>:=<value>" / "<oid>::<b64value>"
        oid = ext;
        size_t colon = param.find(':');
        if (!param.empty() && param[0] == ':' && colon == 0) {
            value.assign(param.begin() + 1, param.end());
        } else if (!param.empty() && param[0] == ':' && param.size() > 1 && param[1] == ':') {
            std::string b64 = param.substr(2);
            std::string decoded = diratlas::ldapcore::base64Decode(b64);
            value.assign(decoded.begin(), decoded.end());
        } else if (!param.empty()) {
            value.assign(param.begin(), param.end());
        }
        return true;
    }

    return false;
}

/**
 * @brief Build a control from an OpenLDAP ldapsearch-style -e/-E spec.
 *
 * Requires a live LDAP handle (call after connect()). Delegates simple
 * flags to parseControlSpec() and handles the value-bearing controls that
 * need libldap's BER builders (paged results, server-side sort, VLV,
 * assertions, matched-values, persistent search, deref, directory sync,
 * extended DN, proxied authorization, read-before/after).
 */
bool LDAPConn::addControlSpec(const std::string &spec, std::string &error) {
    if (!ld) { error = "no LDAP connection (call after connect())"; return false; }

    std::string ext, param;
    bool critical = false;
    if (!splitControlSpec(spec, critical, ext, param)) {
        error = "empty control specification";
        return false;
    }

    LdapControl ctrl;
    ctrl.critical = critical;

    if (ext == "pr" || ext == "paged") {
        // RFC 2696 paged results: SEQUENCE { size INTEGER, cookie OCTET STRING }
        std::string sizeStr = param.substr(0, param.find('/'));
        ber_int_t size = 0;
        if (!sizeStr.empty()) {
            try { size = std::stoi(sizeStr); } catch (...) {
                error = "invalid paged-results size: " + sizeStr; return false;
            }
        }
        struct berval bv = {};
        if (ldap_create_page_control_value(ld, size, nullptr, &bv) != LDAP_SUCCESS) {
            error = "failed to encode paged-results control"; return false;
        }
        ctrl.oid = LDAP_CONTROL_PAGEDRESULTS;
        bervalToVector(bv, ctrl.value);
        ber_memfree(bv.bv_val);
        ctrls_.push_back(ctrl);
        return true;
    }

    if (ext == "sss" || ext == "sort") {
        // RFC 2891 server-side sort: SEQUENCE OF sortKeyList
        LDAPSortKey **keys = nullptr;
        if (ldap_create_sort_keylist(&keys, const_cast<char*>(param.c_str())) != LDAP_SUCCESS) {
            error = "invalid sort key list: " + param; return false;
        }
        struct berval bv = {};
        int rc = ldap_create_sort_control_value(ld, keys, &bv);
        ldap_free_sort_keylist(keys);
        if (rc != LDAP_SUCCESS) { error = "failed to encode sort control"; return false; }
        ctrl.oid = LDAP_CONTROL_SORTREQUEST;
        bervalToVector(bv, ctrl.value);
        ber_memfree(bv.bv_val);
        ctrls_.push_back(ctrl);
        return true;
    }

    if (ext == "vlv") {
        // ldapv3-vlv-09: before/after(/offset/count|:value)
        // format: <before>/<after>(/<offset>/<count>|:<value>)
        LDAPVLVInfo info = {};
        std::vector<std::string> parts;
        std::string cur;
        for (char c : param) {
            if (c == '/') { parts.push_back(cur); cur.clear(); }
            else cur += c;
        }
        parts.push_back(cur);
        if (parts.size() < 2) { error = "VLV requires <before>/<after>"; return false; }
        try {
            info.ldvlv_before_count = std::stoi(parts[0]);
            info.ldvlv_after_count = std::stoi(parts[1]);
            if (parts.size() >= 4) {
                info.ldvlv_offset = std::stoi(parts[2]);
                info.ldvlv_count = std::stoi(parts[3]);
            }
        } catch (...) { error = "invalid VLV spec: " + param; return false; }
        if (parts.size() == 3 && !parts[2].empty() && parts[2][0] == ':') {
            std::string val = parts[2].substr(1);
            info.ldvlv_attrvalue = static_cast<struct berval*>(ber_memalloc(sizeof(struct berval)));
            ber_str2bv(val.c_str(), 0, 0, info.ldvlv_attrvalue);
        }
        struct berval bv = {};
        int rc = ldap_create_vlv_control_value(ld, &info, &bv);
        if (info.ldvlv_attrvalue) ber_bvfree(info.ldvlv_attrvalue);
        if (rc != LDAP_SUCCESS) { error = "failed to encode VLV control"; return false; }
        ctrl.oid = LDAP_CONTROL_VLVREQUEST;
        bervalToVector(bv, ctrl.value);
        ber_memfree(bv.bv_val);
        ctrls_.push_back(ctrl);
        return true;
    }

    if (ext == "assert" || ext == "assertion") {
        // RFC 4528: control value is the filter
        if (param.empty()) { error = "assert requires a filter value"; return false; }
        struct berval bv = {};
        if (ldap_create_assertion_control_value(ld, const_cast<char*>(param.c_str()), &bv) != LDAP_SUCCESS) {
            error = "invalid assertion filter: " + param; return false;
        }
        ctrl.oid = LDAP_CONTROL_ASSERT;
        bervalToVector(bv, ctrl.value);
        ber_memfree(bv.bv_val);
        ctrls_.push_back(ctrl);
        return true;
    }

    if (ext == "mv" || ext == "matchedValues" || ext == "matchingRuleValues") {
        // RFC 3876: value is a "values return filter"
        if (param.empty()) { error = "mv requires a filter value"; return false; }
        BerElement *ber = ber_alloc_t(LBER_USE_DER);
        if (!ber || ldap_put_vrFilter(ber, param.c_str()) == -1) {
            if (ber) ber_free(ber, 1);
            error = "invalid matched-values filter: " + param; return false;
        }
        struct berval bv = {};
        ber_flatten2(ber, &bv, 1);
        ctrl.oid = LDAP_CONTROL_VALUESRETURNFILTER;
        bervalToVector(bv, ctrl.value);
        ber_memfree(bv.bv_val);
        ctrls_.push_back(ctrl);
        return true;
    }

    if (ext == "ps" || ext == "persistentSearch") {
        // draft-ietf-ldapext-psearch: changetypes/changesonly/echg
        std::string a, b, c;
        auto s1 = param.find('/');
        if (s1 != std::string::npos) {
            a = param.substr(0, s1);
            auto s2 = param.find('/', s1 + 1);
            if (s2 != std::string::npos) {
                b = param.substr(s1 + 1, s2 - s1 - 1);
                c = param.substr(s2 + 1);
            } else {
                b = param.substr(s1 + 1);
            }
        } else {
            a = param;
        }
        int changetypes = 0;
        if (!a.empty()) { try { changetypes = std::stoi(a); } catch (...) { changetypes = LDAP_CONTROL_PERSIST_ENTRY_CHANGE_ADD | LDAP_CONTROL_PERSIST_ENTRY_CHANGE_MODIFY | LDAP_CONTROL_PERSIST_ENTRY_CHANGE_DELETE; } }
        int changesonly = 0;
        if (!b.empty()) { try { changesonly = std::stoi(b); } catch (...) { changesonly = 1; } }
        int echg = 0;
        if (!c.empty()) { try { echg = std::stoi(c); } catch (...) { echg = 0; } }
        struct berval bv = {};
        if (ldap_create_persistentsearch_control_value(ld, changetypes, changesonly, echg, &bv) != LDAP_SUCCESS) {
            error = "failed to encode persistent-search control"; return false;
        }
        ctrl.oid = LDAP_CONTROL_PERSIST_REQUEST;
        bervalToVector(bv, ctrl.value);
        ber_memfree(bv.bv_val);
        ctrls_.push_back(ctrl);
        return true;
    }

    if (ext == "deref") {
        // LDAP_CONTROL_X_DEREF ::= SEQUENCE OF SEQUENCE { derefAttr, SEQUENCE OF attrs }
        // syntax: derefAttr:attr[,...][;derefAttr:attr[,...]]
        std::vector<std::string> specs;
        std::string cur;
        for (char c : param) {
            if (c == ';') { specs.push_back(cur); cur.clear(); }
            else cur += c;
        }
        specs.push_back(cur);
        if (param.empty()) { error = "deref requires specs"; return false; }
        size_t n = specs.size();
        LDAPDerefSpec *ds = static_cast<LDAPDerefSpec*>(ldap_memcalloc(n + 1, sizeof(LDAPDerefSpec)));
        size_t i = 0;
        for (auto &spec_ : specs) {
            auto colon = spec_.find(':');
            if (colon == std::string::npos) {
                ldap_memfree(ds);
                error = "invalid deref spec: " + spec_; return false;
            }
            ds[i].derefAttr = ldap_strdup(spec_.substr(0, colon).c_str());
            auto attrs = splitAttrList(spec_.substr(colon + 1));
            ds[i].attributes = static_cast<char**>(ldap_memcalloc(attrs.size() + 1, sizeof(char*)));
            for (size_t j = 0; j < attrs.size(); j++)
                ds[i].attributes[j] = ldap_strdup(attrs[j].c_str());
            i++;
        }
        struct berval bv = {};
        int rc = ldap_create_deref_control_value(ld, ds, &bv);
        for (size_t k = 0; k < n; k++) {
            if (ds[k].derefAttr) ldap_memfree(ds[k].derefAttr);
            if (ds[k].attributes) {
                for (char **p = ds[k].attributes; *p; p++) ldap_memfree(*p);
                ldap_memfree(ds[k].attributes);
            }
        }
        ldap_memfree(ds);
        if (rc != LDAP_SUCCESS) { error = "failed to encode deref control"; return false; }
        ctrl.oid = LDAP_CONTROL_X_DEREF;
        bervalToVector(bv, ctrl.value);
        ber_memfree(bv.bv_val);
        ctrls_.push_back(ctrl);
        return true;
    }

    if (ext == "dirSync") {
        // MS AD DirSync: flags/maxAttrCount[/cookie]
        if (param.empty()) { error = "dirSync requires !flags/maxAttrCount[/cookie]"; return false; }
        std::string flagsStr, maxStr, cookieStr;
        auto s1 = param.find('/');
        if (s1 != std::string::npos) {
            flagsStr = param.substr(0, s1);
            auto s2 = param.find('/', s1 + 1);
            if (s2 != std::string::npos) {
                maxStr = param.substr(s1 + 1, s2 - s1 - 1);
                cookieStr = param.substr(s2 + 1);
            } else {
                maxStr = param.substr(s1 + 1);
            }
        } else {
            flagsStr = param;
        }
        int flags = 0, maxAttrCount = 0;
        try { flags = std::stoi(flagsStr); } catch (...) { error = "invalid dirSync flags"; return false; }
        if (!maxStr.empty()) { try { maxAttrCount = std::stoi(maxStr); } catch (...) {} }
        struct berval cookieBv = {};
        if (!cookieStr.empty())
            ber_str2bv(cookieStr.c_str(), 0, 0, &cookieBv);
        struct berval bv = {};
        int rc = ldap_create_dirsync_value(ld, flags, maxAttrCount, &cookieBv, &bv);
        if (cookieBv.bv_val) ber_memfree(cookieBv.bv_val);
        if (rc != LDAP_SUCCESS) { error = "failed to encode dirSync control"; return false; }
        ctrl.oid = LDAP_CONTROL_X_DIRSYNC;
        bervalToVector(bv, ctrl.value);
        ber_memfree(bv.bv_val);
        ctrls_.push_back(ctrl);
        return true;
    }

    if (ext == "proxydn") {
        // Draft-weltman-ldapv3-proxy-04 (v1): value is the proxied authzID
        if (param.empty()) { error = "proxydn requires a proxied DN"; return false; }
        ctrl.oid = "2.16.840.1.113730.3.4.12";
        ctrl.value.assign(param.begin(), param.end());
        ctrls_.push_back(ctrl);
        return true;
    }

    if (ext == "authzid" || ext == "proxyauthz" || ext == "proxyAuthz") {
        // RFC 4370 (v2): control value is the authzID
        if (param.empty()) { error = "authzid requires an authorization ID"; return false; }
        ctrl.oid = LDAP_CONTROL_PROXY_AUTHZ;
        ctrl.value.assign(param.begin(), param.end());
        ctrls_.push_back(ctrl);
        return true;
    }

    if (ext == "bauthzid") {
        // RFC 3829: request the authzID of the bound user
        ctrl.oid = LDAP_CONTROL_AUTHZID_REQUEST;
        ctrls_.push_back(ctrl);
        return true;
    }

    if (ext == "preread" || ext == "postread") {
        // RFC 4527: SEQUENCE OF attribute descriptions
        if (param.empty()) { error = ext + " requires an attribute list"; return false; }
        std::string oidStr = (ext == "preread") ? LDAP_CONTROL_PRE_READ : LDAP_CONTROL_POST_READ;
        auto attrs = splitAttrList(param);
        std::vector<uint8_t> content;
        for (auto &a : attrs) {
            auto oct = berEncodeOctet(a);
            if (oct.empty()) { error = "attribute list too long"; return false; }
            content.insert(content.end(), oct.begin(), oct.end());
        }
        auto seq = berWrapSeq(content);
        if (seq.empty()) { error = "attribute list too long"; return false; }
        ctrl.oid = oidStr;
        ctrl.value = seq;
        ctrls_.push_back(ctrl);
        return true;
    }

    // Flag-only and generic controls (no handle needed)
    std::string oidStr;
    std::vector<uint8_t> value;
    if (parseControlSpec(spec, oidStr, critical, value)) {
        ctrl.oid = oidStr;
        ctrl.value = std::move(value);
        ctrls_.push_back(ctrl);
        return true;
    }

    error = "unknown control spec: " + spec;
    return false;
}

} // namespace diratlas
