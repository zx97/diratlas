// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Manuel FLURY
//
// This file is part of DirAtlas — an LDAP Directory Explorer.
//
// Licensed under the GNU Affero General Public License v3.0
// (https://www.gnu.org/licenses/agpl-3.0.txt).
//
// Originally based on godap (github.com/Macmod/godap) — MIT license.

#pragma once
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <ldap.h>

#include "vars.h"
#include "adidns/types.h"

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
 * Manages connection lifecycle, authentication, search, CRUD,
 * group membership, Active Directory DNS, security descriptors,
 * and schema introspection.
 */
class LDAPConn {
public:
    LDAPConn();
    ~LDAPConn();

    // ── Connection ────────────────────────────────────────
    /** @brief Initialise an LDAP session handle and apply TLS options. */
    bool connect(const std::string &uri,
                 bool insecure, const std::string &socksProxy = "");
    /** @brief Negotiate StartTLS on an existing connection. */
    bool startTLS();

    // ── Authentication ────────────────────────────────────
    /** @brief Alias for simpleBind(). */
    bool bind(const std::string &username, const std::string &password);
    /** @brief Simple (username/password) SASL bind. */
    bool simpleBind(const std::string &username, const std::string &password);
    /** @brief SASL EXTERNAL bind (client certificate). */
    bool externalBind();
    /** @brief SASL interactive bind for arbitrary mechanisms (GSSAPI, etc.). */
    bool saslBind(const std::string &mech, const std::string &authzId = "");

    // ── Search / Query ────────────────────────────────────
    /** @brief Perform an LDAP search with paging and control support. */
    bool search(const std::string &baseDN, int scope, const std::string &filter,
                const std::vector<std::string> &attrs, bool showDeleted,
                std::vector<LDAPEntry> &results);
    /** @brief Convenience: base-scope search returning a single entry. */
    LDAPEntry searchOne(const std::string &baseDN, const std::string &filter,
                         const std::vector<std::string> &attrs, bool showDeleted);

    /** @brief Auto-detect the root DN from namingContexts. */
    bool findRootDN(std::string &rootDN);
    /** @brief Retrieve all namingContexts from RootDSE. */
    std::vector<std::string> findNamingContexts();
    /** @brief Extract the DNS domain (FQDN) from RootDSE attributes. */
    std::string findRootFQDN();
    /** @brief Detect backend flavour (MicrosoftAD vs BasicLDAP). */
    void guessFlavor();

    // ── Group Operations ──────────────────────────────────
    bool queryGroupMembers(const std::string &groupDN, std::vector<LDAPEntry> &members);
    bool queryGroupMembersDeep(const std::string &groupDN, int maxDepth, std::vector<LDAPEntry> &members);
    bool queryObjectGroups(const std::string &objectDN, std::vector<LDAPEntry> &groups);
    bool addMemberToGroup(const std::string &memberDN, const std::string &groupDN);
    bool removeMemberFromGroup(const std::string &memberDN, const std::string &groupDN);

    // ── Object CRUD ───────────────────────────────────────
    bool deleteObject(const std::string &dn);
    bool addAttribute(const std::string &dn, const std::string &attr, const std::vector<std::string> &values);
    bool modifyAttribute(const std::string &dn, const std::string &attr, const std::vector<std::string> &values);
    bool deleteAttribute(const std::string &dn, const std::string &attr);
    bool deleteAttributeValues(const std::string &dn, const std::string &attr, const std::vector<std::string> &values);
    bool moveObject(const std::string &sourceDN, const std::string &targetDN);
    bool resetPassword(const std::string &dn, const std::string &newPassword);

    // ── Object Creation ───────────────────────────────────
    bool addObject(const std::string &dn, const std::map<std::string, std::vector<std::string>> &attrs);
    bool addGroup(const std::string &name, const std::string &parentDN);
    bool addOU(const std::string &name, const std::string &parentDN);
    bool addUser(const std::string &name, const std::string &parentDN);
    bool addComputer(const std::string &name, const std::string &parentDN);
    bool addContainer(const std::string &name, const std::string &parentDN);

    // ── Security Descriptor ───────────────────────────────
    bool getSecurityDescriptor(const std::string &object, std::string &hexSD);
    bool modifyDACL(const std::string &object, const std::string &newSD);

    // ── Schema ────────────────────────────────────────────
    bool findSchemaClassesAndAttributes(std::map<std::string, std::string> &classes,
                                         std::map<std::string, std::string> &attrs);

    // ── AD Integrated DNS ─────────────────────────────────
    bool getADIDNSZones(const std::string &name, bool isForest, std::vector<adidns::DNSZone> &zones);
    bool getADIDNSNode(const std::string &nodeDN, adidns::DNSNode &node);
    bool getADIDNSNodes(const std::string &zoneDN, std::vector<adidns::DNSNode> &nodes);
    bool addADIDNSZone(const std::string &name, const std::vector<adidns::DNSProperty> &props, bool isForest);
    bool addADIDNSNode(const std::string &nodeName, const std::string &zoneDN,
                        const std::vector<adidns::DNSRecord> &records);
    bool addADIDNSRecords(const std::string &nodeDN, const std::vector<adidns::DNSRecord> &records);
    bool replaceADIDNSRecords(const std::string &nodeDN, const std::vector<adidns::DNSRecord> &records);

    // ── SID Resolution ────────────────────────────────────
    std::string findSIDForObject(const std::string &object);
    std::string findSamForSID(const std::string &sid);
    std::string findFirstAttr(const std::string &filter, const std::string &attr);

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
    void clearControls();
    std::vector<LdapControl> &controls() { return ctrls_; }

    /** @brief Build a LDAPControl** array from ctrls_ (caller must free). */
    LDAPControl **buildControlArray() const;

    /** @brief Parse -E spec "[!]ext[=extparam]" into oid/critical/value. */
    static bool parseControlSpec(const std::string &spec,
                                  std::string &oid, bool &critical,
                                  std::vector<uint8_t> &value);

    /// Detected backend flavour
    LDAPFlavor flavor{LDAPFlavor::MicrosoftAD};
    /// Default root DN for searches
    std::string defaultRootDN;
    /// LDAP paging size
    uint32_t pagingSize{800};
    /// Operation time limit in seconds
    int timelimit{10};
    /// Last LDAP error code
    int lastErrno{0};
    /// Last LDAP error message
    std::string lastError;

    const std::string &getLastError() const { return lastError; }
    int getLastErrno() const { return lastErrno; }

    // ── Static Helpers ────────────────────────────────────
    static std::string escapeFilter(const std::string &filter);
    static std::string samOrDN(const std::string &object, bool &isSam);
    static std::string cnUidOrDN(const std::string &object, bool &isCnOrUid);
    static std::string guessQueryFilter(const std::string &identifier, LDAPFlavor flavor);

private:
    LDAP *ld{nullptr};                     ///< libldap session handle
    bool connected{false};
    int debug_{0};
    int ldapVersion{LDAP_VERSION3};
    std::vector<LdapControl> ctrls_;

public:
    /** @brief TLS configuration (filled from ldaprc, applied inside connect()). */
    struct {
        std::string cacert;      ///< CA certificate file path
        std::string cacertdir;   ///< CA certificate directory
        std::string cert;        ///< Client certificate file
        std::string key;         ///< Client private key file
        int reqcert{-1};         ///< Certificate requirement level (-1 = unset)
    } tlsOpts;

    bool buildSearchRequest(const std::string &baseDN, int scope, const std::string &filter,
                            const std::vector<std::string> &attrs, bool showDeleted,
                            LDAPControl ***srvCtrls, std::string &attrsStr);
};

} // namespace diratlas
