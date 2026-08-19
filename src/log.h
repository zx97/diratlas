// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Manuel FLURY
//
// This file is part of DirAtlas — an LDAP Directory Explorer.
//
// Licensed under the GNU Affero General Public License v3.0
// (https://www.gnu.org/licenses/agpl-3.0.txt).

#pragma once
#include <iostream>
#include <string>

namespace diratlas {

// Debug levels follow OpenLDAP's loglevel(5) semantics: additive
// subsystem bits, not increasing verbosity levels.  A message tagged
// with a bit is emitted when that bit is set in g_debugLevel (or when
// g_debugLevel == -1, meaning "everything").
//
//   -d 1      (0x1)    trace        function calls / application steps
//   -d 2      (0x2)    packets      debug packet handling
//   -d 4      (0x4)    args         heavy trace debugging (function args)
//   -d 8      (0x8)    conns        connection management
//   -d 16     (0x10)   BER          print packets sent and received (hex+ASCII)
//   -d 32     (0x20)   filter       search filter processing
//   -d 64     (0x40)   config       configuration file processing
//   -d 128    (0x80)   ACL          access control list processing
//   -d 256    (0x100)  stats        connections, LDAP operations, results
//   -d 512    (0x200)  stats2       stats2 log entries sent
//   -d 1024   (0x400)  shell        shell backend communication
//   -d 2048   (0x800)  parse        entry parsing
//   -d 16384  (0x4000) sync         LDAPSync replication
//   -d 32768  (0x8000) none         only messages logged whatever the level
//   -d -1               everything   (all bits)
//
// The same integer is handed to libldap via LDAP_OPT_DEBUG_LEVEL, so
// -d 16 (BER) also makes libldap dump raw packets in hex+ASCII on stderr.
enum : int {
    LDAP_DEBUG_TRACE   = 0x0001, // function calls / app steps
    LDAP_DEBUG_PACKETS = 0x0002, // packet handling
    LDAP_DEBUG_ARGS    = 0x0004, // heavy trace (function args)
    LDAP_DEBUG_CONNS   = 0x0008, // connection management
    LDAP_DEBUG_BER     = 0x0010, // packets sent/received, hex+ASCII
    LDAP_DEBUG_FILTER  = 0x0020, // search filter processing
    LDAP_DEBUG_CONFIG  = 0x0040, // configuration file processing
    LDAP_DEBUG_ACL     = 0x0080, // ACL processing
    LDAP_DEBUG_STATS   = 0x0100, // connections, LDAP ops, results
    LDAP_DEBUG_STATS2  = 0x0200, // log entries sent
    LDAP_DEBUG_SHELL   = 0x0400, // shell backend communication
    LDAP_DEBUG_PARSE   = 0x0800, // entry parsing
    LDAP_DEBUG_SYNC    = 0x4000, // LDAPSync replication
    LDAP_DEBUG_NONE    = 0x8000, // messages logged regardless of level
    LDAP_DEBUG_ANY     = -1,     // everything
};

// Global debug bitmask (OpenLDAP loglevel semantics).
inline int g_debugLevel = 0;

// Emit a debug message to stderr (never stdout, so CLI LDIF output stays
// clean).  Tag with a subsystem bit from the enum above.
inline void dbgLog(int bit, const std::string &msg) {
    if (g_debugLevel == LDAP_DEBUG_ANY || (g_debugLevel & bit) != 0)
        std::cerr << "[debug] " << msg << '\n';
}

// Human-readable name for a debug bit (used by -d help / config dump).
inline const char *debugBitName(int bit) {
    switch (bit) {
        case LDAP_DEBUG_TRACE:   return "trace";
        case LDAP_DEBUG_PACKETS: return "packets";
        case LDAP_DEBUG_ARGS:    return "args";
        case LDAP_DEBUG_CONNS:   return "conns";
        case LDAP_DEBUG_BER:     return "BER";
        case LDAP_DEBUG_FILTER:  return "filter";
        case LDAP_DEBUG_CONFIG:  return "config";
        case LDAP_DEBUG_ACL:     return "ACL";
        case LDAP_DEBUG_STATS:   return "stats";
        case LDAP_DEBUG_STATS2:  return "stats2";
        case LDAP_DEBUG_SHELL:   return "shell";
        case LDAP_DEBUG_PARSE:   return "parse";
        case LDAP_DEBUG_SYNC:    return "sync";
        case LDAP_DEBUG_NONE:    return "none";
        default:                 return "?";
    }
}

} // namespace diratlas