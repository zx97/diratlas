// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Manuel FLURY
//
// This file is part of DirAtlas — an LDAP Directory Explorer.
//
// Licensed under the GNU Affero General Public License v3.0
// (https://www.gnu.org/licenses/agpl-3.0.txt).
//

#include "ldaprc.h"
#include <cstdlib>
#include <fstream>
#include <string>
#include <algorithm>
#include <pwd.h>
#include <unistd.h>
#include <iostream>

namespace diratlas {

/// @brief Check whether LDAPNOINIT env var is set (skips all config files).
static bool noInit() {
    const char *v = getenv("LDAPNOINIT");
    return v && v[0] != '\0';
}

/// @brief Resolve the user's home directory from $HOME or passwd entry.
static std::string homeDir() {
    const char *home = getenv("HOME");
    if (home) return home;
    struct passwd *pw = getpwuid(getuid());
    if (pw && pw->pw_dir) return pw->pw_dir;
    return "";
}

/**
 * @brief Parse a single line from an ldaprc configuration file.
 *
 * Strips comments (#) and leading/trailing whitespace, then matches
 * the keyword (case-insensitive) against known directives:
 *   URI, BASE, BINDDN, SASL_MECH, SASL_REALM, SASL_AUTHZ_ID,
 *   SASL_SECPROPS, TIMELIMIT, SIZELIMIT, NETWORK_TIMEOUT, TIMEOUT,
 *   DEREF, REFERRALS, TLS_CACERT, TLS_CACERTDIR, TLS_CERT, TLS_KEY,
 *   TLS_REQCERT, TLS_CRLCHECK
 *
 * Fields are only written if their default value is still in place
 * (first-write-wins pattern to let CLI flags take precedence).
 *
 * @param line  Raw line from the config file.
 * @param cfg   Configuration struct to populate.
 */
static void parseLine(const std::string &line, LdapRcConfig &cfg) {
    std::string s = line;
    auto hash = s.find('#');
    if (hash != std::string::npos) s = s.substr(0, hash);
    auto first = s.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return;
    auto last = s.find_last_not_of(" \t\r\n");
    s = s.substr(first, last - first + 1);

    auto space = s.find_first_of(" \t");
    if (space == std::string::npos) return;
    std::string key = s.substr(0, space);
    std::string val = s.substr(space + 1);
    first = val.find_first_not_of(" \t");
    if (first != std::string::npos) val = val.substr(first);
    last = val.find_last_not_of(" \t\r\n");
    if (last != std::string::npos) val = val.substr(0, last + 1);

    for (auto &c : key) c = toupper(c);

    if (key == "URI")                { if (cfg.uri.empty()) cfg.uri = val; }
    else if (key == "BASE")          { if (cfg.base.empty()) cfg.base = val; }
    else if (key == "BINDDN")        { if (cfg.binddn.empty()) cfg.binddn = val; }
    else if (key == "SASL_MECH")     { if (cfg.saslMech.empty()) cfg.saslMech = val; }
    else if (key == "SASL_REALM")    { if (cfg.saslRealm.empty()) cfg.saslRealm = val; }
    else if (key == "SASL_AUTHZ_ID") { if (cfg.saslAuthzId.empty()) cfg.saslAuthzId = val; }
    else if (key == "SASL_SECPROPS") { if (cfg.saslSecProps.empty()) cfg.saslSecProps = val; }
    else if (key == "TIMELIMIT")     { if (cfg.timelimit == 10) { try { cfg.timelimit = std::stoi(val); } catch (...) {} } }
    else if (key == "SIZELIMIT")     { if (cfg.sizelimit == 0) { try { cfg.sizelimit = std::stoi(val); } catch (...) {} } }
    else if (key == "NETWORK_TIMEOUT") { if (cfg.networkTimeout == 0) { try { cfg.networkTimeout = std::stoi(val); } catch (...) {} } }
    else if (key == "TIMEOUT")       { if (cfg.timelimit == 10) { try { cfg.timelimit = std::stoi(val); } catch (...) {} } }
    else if (key == "DEREF") {
        if (cfg.deref == 0) {
            if (val == "never") cfg.deref = 0;
            else if (val == "search") cfg.deref = 1;
            else if (val == "find") cfg.deref = 2;
            else if (val == "always") cfg.deref = 3;
            else { try { cfg.deref = std::stoi(val); } catch (...) {} }
        }
    }
    else if (key == "REFERRALS") {
        if (val == "0" || val == "off" || val == "no") cfg.referrals = false;
        else cfg.referrals = true;
    }
    else if (key == "TLS_CACERT")    { if (cfg.tlsCACert.empty()) cfg.tlsCACert = val; }
    else if (key == "TLS_CACERTDIR") { if (cfg.tlsCACertDir.empty()) cfg.tlsCACertDir = val; }
    else if (key == "TLS_CERT")      { if (cfg.tlsCert.empty()) cfg.tlsCert = val; }
    else if (key == "TLS_KEY")       { if (cfg.tlsKey.empty()) cfg.tlsKey = val; }
    else if (key == "TLS_REQCERT") {
        if (cfg.tlsReqCert < 0) {
            if (val == "never") cfg.tlsReqCert = 0;
            else if (val == "allow") cfg.tlsReqCert = 1;
            else if (val == "try") cfg.tlsReqCert = 2;
            else if (val == "demand") cfg.tlsReqCert = 3;
            else { try { cfg.tlsReqCert = std::stoi(val); } catch (...) {} }
        }
    }
    else if (key == "TLS_CRLCHECK") {
        if (cfg.tlsCRLCheck < 0) {
            if (val == "none") cfg.tlsCRLCheck = 0;
            else if (val == "peer") cfg.tlsCRLCheck = 1;
            else if (val == "all") cfg.tlsCRLCheck = 2;
        }
    }
}

/**
 * @brief Parse all lines from a single config file.
 * @param path  Absolute or relative path to the file.
 * @param cfg   Configuration struct to populate.
 */
static void parseFile(const std::string &path, LdapRcConfig &cfg, bool debug = false, bool ldifComments = false) {
    std::ifstream f(path);
    if (!f.is_open()) {
        if (debug) std::cerr << "[ldaprc] Skipping " << path << " (not found)" << std::endl;
        return;
    }
    if (ldifComments) std::cout << "# [ldaprc] Reading " << path << std::endl;
    else std::cerr << "[ldaprc] Reading " << path << std::endl;
    std::string line;
    while (std::getline(f, line)) {
        parseLine(line, cfg);
    }
    if (debug) {
        if (!cfg.uri.empty()) std::cerr << "[ldaprc]   uri = " << cfg.uri << std::endl;
        if (!cfg.base.empty()) std::cerr << "[ldaprc]   base = " << cfg.base << std::endl;
        if (!cfg.binddn.empty()) std::cerr << "[ldaprc]   binddn = " << cfg.binddn << std::endl;
        if (!cfg.saslMech.empty()) std::cerr << "[ldaprc]   sasl_mech = " << cfg.saslMech << std::endl;
        if (!cfg.tlsCACert.empty()) std::cerr << "[ldaprc]   tls_cacert = " << cfg.tlsCACert << std::endl;
        if (!cfg.tlsCert.empty()) std::cerr << "[ldaprc]   tls_cert = " << cfg.tlsCert << std::endl;
        if (!cfg.tlsKey.empty()) std::cerr << "[ldaprc]   tls_key = " << cfg.tlsKey << std::endl;
    }
}

/**
 * @brief Read all ldaprc files in priority order.
 *
 * Order (later overrides earlier):
 *   /etc/ldap/ldap.conf  →  ~/.ldaprc  →  ./.ldaprc
 *
 * Entirely skipped when LDAPNOINIT is set (see noInit()).
 *
 * @param cfg  Output struct to populate.
 */
void readLdapRc(LdapRcConfig &cfg, bool debug, bool ldifComments) {
    if (noInit()) {
        if (debug) std::cerr << "[ldaprc] Skipping all files (LDAPNOINIT is set)" << std::endl;
        return;
    }
    parseFile("/etc/ldap/ldap.conf", cfg, debug, ldifComments);
    std::string home = homeDir();
    if (!home.empty())
        parseFile(home + "/.ldaprc", cfg, debug, ldifComments);
    parseFile(".ldaprc", cfg, debug, ldifComments);
}

} // namespace diratlas
