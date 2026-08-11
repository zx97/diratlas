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

namespace diratlas {

/**
 * @brief Configuration parsed from ldap.conf / .ldaprc files.
 *
 * Mirrors the standard OpenLDAP client configuration keywords.
 * Fields are only set if the user has not already supplied a CLI
 * equivalent (first-write-wins pattern in main.cpp).
 */
struct LdapRcConfig {
    /// LDAP URI (URI keyword)
    std::string uri;
    /// Default search base DN (BASE)
    std::string base;
    /// Search time limit in seconds (TIMELIMIT/TIMEOUT)
    int timelimit{10};
    /// Size limit, 0 = unlimited (SIZELIMIT)
    int sizelimit{0};
    /// Network timeout in seconds (NETWORK_TIMEOUT)
    int networkTimeout{30};
    /// Alias dereferencing: 0=never, 1=search, 2=find, 3=always (DEREF)
    int deref{0};
    /// Whether to chase referrals (REFERRALS)
    bool referrals{true};

    /// Bind DN (BINDDN)
    std::string binddn;
    /// SASL mechanism (SASL_MECH)
    std::string saslMech;
    /// SASL realm (SASL_REALM)
    std::string saslRealm;
    /// SASL authorization ID (SASL_AUTHZ_ID)
    std::string saslAuthzId;
    /// SASL security properties (SASL_SECPROPS)
    std::string saslSecProps;

    /// TLS CA certificate file path (TLS_CACERT)
    std::string tlsCACert;
    /// TLS CA certificate directory (TLS_CACERTDIR)
    std::string tlsCACertDir;
    /// TLS client certificate file (TLS_CERT)
    std::string tlsCert;
    /// TLS client private key file (TLS_KEY)
    std::string tlsKey;
    /** TLS certificate requirement level (TLS_REQCERT)
     *  -1 = not set, 0=never, 1=allow, 2=try, 3=demand */
    int tlsReqCert{-1};
    /** TLS CRL checking level (TLS_CRLCHECK)
     *  -1 = not set, 0=none, 1=peer, 2=all */
    int tlsCRLCheck{-1};
};

/**
 * @brief Read system and user ldaprc configuration files.
 *
 * Skips all files if the LDAPNOINIT environment variable is set.
 * Later files override earlier ones:
 *   1. /etc/ldap/ldap.conf
 *   2. ~/.ldaprc
 *   3. ./.ldaprc  (project-local)
 *
 * @param cfg    Output struct populated with parsed values.
 * @param debug  If true, print which files are read and values set.
 */
void readLdapRc(LdapRcConfig &cfg, bool debug = false);

} // namespace diratlas
