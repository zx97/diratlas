// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Manuel FLURY
//
// This file is part of DirAtlas — an LDAP Directory Explorer.
//
// Licensed under the GNU Affero General Public License v3.0
// (https://www.gnu.org/licenses/agpl-3.0.txt).
//

#pragma once
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <ldap.h>

#include "vars.h"

namespace diratlas {

/**
 * @brief Represents a single LDAP entry (directory object).
 *
 * Stores both string-form and raw-binary attribute values, plus
 * an ordered list of attribute names as returned by the server.
 */
struct LDAPEntry {
    std::string dn;                                ///< Distinguished name
    std::map<std::string, std::vector<std::string>> attributes;           ///< String attribute values
    std::map<std::string, std::vector<std::vector<uint8_t>>> binaryAttributes; ///< Raw binary values
    std::vector<std::string> attributeNames;       ///< Ordered attribute list from server

    /// @brief Get first string value for an attribute (or "").
    std::string getAttr(const std::string &name) const;
    /// @brief Get all string values for an attribute.
    std::vector<std::string> getAttrs(const std::string &name) const;
    /// @brief Get first raw binary value for an attribute.
    std::vector<uint8_t> getRawAttr(const std::string &name) const;
    /// @brief Get all raw binary values for an attribute.
    std::vector<std::vector<uint8_t>> getRawAttrs(const std::string &name) const;
};

/**
 * @brief Wrapper around OpenLDAP's libldap for LDAP operations.
 *
 * Manages connection lifecycle, authentication, search and CRUD
 * operations against an LDAP server.
 */
class LDAPConn {
public:
    LDAPConn();
    ~LDAPConn();

    // ── Connection ────────────────────────────────────────
    /** @brief Initialise an LDAP session handle and apply TLS options. */
    bool connect(const std::string &uri, const std::string &socksProxy = "");
    /** @brief Negotiate StartTLS on an existing connection. */
    bool startTLS();
    /** @brief Set the LDAP protocol version (2 or 3). */
    void setProtocolVersion(int version) { ldapVersion = version; }

    // ── Authentication ────────────────────────────────────
    /** @brief Alias for simpleBind(). */
    bool bind(const std::string &username, const std::string &password);
    /** @brief Simple (username/password) SASL bind. */
    bool simpleBind(const std::string &username, const std::string &password);
    /** @brief SASL interactive bind for arbitrary mechanisms (GSSAPI, etc.). */
    bool saslBind(const std::string &mech, const std::string &authzId = "",
                  const std::string &authcid = "", const std::string &realm = "",
                  const std::string &secprops = "", bool noCanon = false,
                  bool interactive = false);

    // ── Extended operations ───────────────────────────────
    /** @brief RFC 4532 "Who am I?": return the server-reported authzID. */
    std::string whoAmI();
    /** @brief RFC 3062 Password Modify. Returns generated password if requested. */
    bool passwordModify(const std::string &user, const std::string &oldPw,
                        const std::string &newPw, std::string &generatedPw);
    /** @brief RFC 3909 Cancel an in-flight operation by its message ID. */
    bool cancelOperation(int msgid);
    /**
     * @brief RFC 4511 §4.11 Abandon an in-flight operation by message ID.
     * Unlike Cancel, Abandon gets no server response and is a fire-and-forget
     * client-side request.
     */
    bool abandon(int msgid);
    /** @brief Send an arbitrary extended request and read its response value. */
    bool extendedOp(const std::string &oid, const std::vector<uint8_t> &req,
                    std::vector<uint8_t> &res);

    // ── Search / Query ────────────────────────────────────
    /** @brief Perform an LDAP search with paging and control support. */
    bool search(const std::string &baseDN, int scope, const std::string &filter,
                const std::vector<std::string> &attrs, bool showDeleted,
                std::vector<LDAPEntry> &results, bool attrsonly = false);
    /** @brief Convenience: base-scope search returning a single entry. */
    LDAPEntry searchOne(const std::string &baseDN, const std::string &filter,
                         const std::vector<std::string> &attrs, bool showDeleted);

    /**
     * @brief RFC 4533 Persistent Search: keep the search open and report
     *        entry changes as they happen, until the server sends the final
     *        result, maxWaitSec elapses, or the callback returns false.
     * @param callback Invoked once per changed entry with its DN and a
     *        human-readable change kind ("add"/"modify"/"delete"/"entry").
     *        Return false to stop the loop.
     * @return true if the loop ended cleanly (final result received).
     */
    bool persistentSearch(const std::string &baseDN, int scope,
                          const std::string &filter,
                          const std::vector<std::string> &attrs, int maxWaitSec,
                          const std::function<bool(const std::string &dn,
                                                   const std::string &change)> &callback);
    /**
     * @brief RFC 4533 Sync (refreshOnly mode): one refresh pass that returns
     *        all matching entries plus the sync cookie for the next pass.
     */
    bool syncRefreshOnly(const std::string &baseDN, int scope,
                         const std::string &filter,
                         const std::vector<std::string> &attrs,
                         std::vector<LDAPEntry> &results, std::string &cookie);

    /** @brief Auto-detect the root DN from namingContexts. */
    bool findRootDN(std::string &rootDN);
    /** @brief Fetch the list of namingContexts from the RootDSE. */
    std::vector<std::string> findNamingContexts();
    /**
     * @brief Read RootDSE capability attributes.
     * @param what "supportedCapabilities" | "supportedFeatures" |
     *             "supportedControl" | "supportedExtension".
     * @return The raw values of that RootDSE attribute.
     */
    std::vector<std::string> getCapabilities(const std::string &what);
    /** @brief Detect backend flavour (MicrosoftAD vs StandardLDAP). */
    void guessFlavor();

    // ── Object CRUD ───────────────────────────────────────
    bool deleteObject(const std::string &dn);
    bool addAttribute(const std::string &dn, const std::string &attr, const std::vector<std::string> &values);
    bool modifyAttribute(const std::string &dn, const std::string &attr, const std::vector<std::string> &values);
    bool deleteAttribute(const std::string &dn, const std::string &attr);
    /** @brief Remove a single value of an attribute (LDAP_MOD_DELETE with value). */
    bool deleteAttributeValue(const std::string &dn, const std::string &attr,
                              const std::string &value);
    /** @brief Atomically replace one value of an attribute (DELETE old + ADD new). */
    bool replaceAttributeValue(const std::string &dn, const std::string &attr,
                               const std::string &oldValue, const std::string &newValue);
    /**
     * @brief RFC 4525 Modify-Increment: add a signed integer delta to an
     *        attribute value without a read-modify-write round trip.
     * @param dn    The entry DN.
     * @param attr  AttributeDescription (type, and optionally ;options).
     * @param delta Signed integer delta, e.g. "5" or "-2".
     * @return true on success; on failure getLastError() holds the message.
     */
    bool modifyIncrement(const std::string &dn, const std::string &attr,
                         const std::string &delta);
    /**
     * @brief RFC 4511 §4.10 Compare: check whether an attribute value matches.
     * @param dn    The entry DN.
     * @param attr  AttributeDescription (type, and optionally ;options).
     * @param value The assertion value to compare against.
     * @return 1 if the attribute value matches, 0 if it does not,
     *         -1 on protocol error (see getLastError()).
     */
    int compare(const std::string &dn, const std::string &attr, const std::string &value);

    // ── Object Naming (moddn) ─────────────────────────────
    /**
     * @brief Rename and/or move an entry (RFC 4511 ModifyDN).
     *
     * @param dn            Current distinguished name of the entry.
     * @param newRdn        New RDN, e.g. "cn=newname" (no parent part).
     * @param deleteOldRdn  True to delete the old RDN attribute value from the entry.
     * @param newSuperior   New parent DN, or "" to keep the entry under its
     *                      current parent (rename only).
     * @return true on success; on failure getLastError() holds the message.
     */
    bool renameObject(const std::string &dn, const std::string &newRdn,
                      bool deleteOldRdn, const std::string &newSuperior = "");

    // ── Object Creation ───────────────────────────────────
    bool addObject(const std::string &dn, const std::map<std::string, std::vector<std::string>> &attrs);

    // ── Options ───────────────────────────────────────────
    /** @brief Set alias dereferencing policy. */
    bool setDeref(int deref); // LDAP_DEREF_NEVER/SEARCH/FIND/ALWAYS
    /** @brief Set OpenLDAP debug level. */
    void setDebug(int level) { debug_ = level; }
    /** @brief Format an LDAP result code into a human-readable string. */
    static std::string formatError(int rc, LDAP *ld = nullptr);

    // ── LDAP Controls (-E) ────────────────────────────────
    /**
     * @brief Describes a single LDAP control (OID + critical flag + value).
     */
    struct LdapControl {
        std::string oid;                  ///< Control OID string
        bool critical{false};             ///< Criticality flag
        std::vector<uint8_t> value;       ///< Opaque control value
    };
    void addControl(const LdapControl &ctrl);
    std::vector<LdapControl> &controls() { return ctrls_; }

    /** @brief Build a LDAPControl** array from ctrls_ (caller must free). */
    LDAPControl **buildControlArray() const;

    /** @brief Parse -E spec "[!]ext[=extparam]" into oid/critical/value. */
    static bool parseControlSpec(const std::string &spec,
                                  std::string &oid, bool &critical,
                                  std::vector<uint8_t> &value);

    /**
     * @brief Parse and register an OpenLDAP-compatible -e / -E extension.
     *
     * Must be called after connect() (the underlying LDAP handle is needed to
     * build controls). Supports the same extensions as OpenLDAP's ldapsearch:
     * assert, authzid, bauthzid, chaining, dontUseCopy, manageDSAit, noop,
     * ppolicy, postread, preread, proxydn, proxyauthz, relax, sessiontracking,
     * tz, domainScope, mv, pr, ps, sss, subentries, sync, vlv, deref, dirSync,
     * extendedDn, showDeleted, serverNotif, accountUsability, effectiverights,
     * realAttributesOnly, virtualAttributesOnly, transactionID, and generic
     * "[!]<oid>[=:<value>|=::<b64>]".
     *
     * @param spec  Raw -e/-E argument.
     * @param error Filled with a human-readable error on failure.
     * @return true on success, false with `error` set otherwise.
     */
    bool addControlSpec(const std::string &spec, std::string &error);

    /// Detected backend flavour
    LDAPFlavor flavor{LDAPFlavor::MicrosoftAD};
    /// Detected server version string (e.g. "slapd 2.6.13"), may be empty
    std::string serverVersion;
    /// Default root DN for searches
    std::string defaultRootDN;
    /// LDAP paging size (0 = off; ldapsearch-compatible default. Some
    /// servers misbehave with the paged-results control, so paging is opt-in
    /// via --simplePageSize or -E pr=.)
    uint32_t pagingSize{0};
    /// Search size limit (number of entries; 0 = unlimited, -z)
    int sizelimit{0};
    /// Operation time limit in seconds
    int timelimit{10};
    /// Network connect timeout in seconds (0 = libldap default, -o nettimeout)
    int networkTimeout{0};
    /// Last LDAP error code
    int lastErrno{0};
    /// Last LDAP error message
    std::string lastError;

    const std::string &getLastError() const { return lastError; }
    int getLastErrno() const { return lastErrno; }

    /** @brief TLS configuration (filled from ldaprc, applied inside connect()). */
    struct {
        std::string cacert;      ///< CA certificate file path
        std::string cacertdir;   ///< CA certificate directory
        std::string cert;        ///< Client certificate file
        std::string key;         ///< Client private key file
        int reqcert{-1};         ///< Certificate requirement level (-1 = unset)
    } tlsOpts;

private:
    LDAP *ld{nullptr};                     ///< libldap session handle
    bool connected{false};
    int debug_{0};
    int ldapVersion{LDAP_VERSION3};
    std::vector<LdapControl> ctrls_;
};

} // namespace diratlas
