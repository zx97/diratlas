// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Manuel FLURY
//
// This file is part of DirAtlas — an LDAP Directory Explorer.
//
// Licensed under the GNU Affero General Public License v3.0
// (https://www.gnu.org/licenses/agpl-3.0.txt).
//

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <cstdlib>
#include <strings.h>
#include <cstdio>
#include <algorithm>
#include <getopt.h>
#include <unistd.h>

#include "ldap_conn.h"
#include "tui/app.h"
#include "vars.h"
#include "embedded.hpp"
#include "banner.hpp"
#include "ldaprc.h"
#include "ldapcore/bytes.h"
#include "log.h"

#ifndef BUILD_NUMBER
#define BUILD_NUMBER 0
#endif
#ifndef BUILD_HASH
#define BUILD_HASH "nogit"
#endif
#ifndef BUILD_DATE
#define BUILD_DATE "unknown"
#endif
#ifndef BUILD_HOSTNAME
#define BUILD_HOSTNAME "unknown"
#endif

/// @brief Compile timestamp from __DATE__/__TIME__ formatted as "YYYYMMDD-HHMMSS".
static std::string compileTimestamp() {
    // __DATE__ is "Mmm dd yyyy" (e.g. "Aug 11 2026"); __TIME__ is "hh:mm:ss".
    static const char* months[] = {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
    };
    int mon = 0, day = 0, year = 0;
    char monStr[4] = {};
    if (std::sscanf(__DATE__, "%3s %d %d", monStr, &day, &year) == 3) {
        for (int i = 0; i < 12; ++i) {
            if (std::strcmp(monStr, months[i]) == 0) {
                mon = i + 1;
                break;
            }
        }
    }
    int hh = 0, mm = 0, ss = 0;
    std::sscanf(__TIME__, "%d:%d:%d", &hh, &mm, &ss);
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%04d%02d%02d-%02d%02d%02d",
                  year, mon, day, hh, mm, ss);
    return buf;
}

/// @brief Whether the terminal supports ANSI colour on stdout.
///        Colour is only used when stdout is a TTY, TERM is set and not
///        "dumb", and NO_COLOR is not set (https://no-color.org).
static bool terminalSupportsColor() {
    if (!isatty(STDOUT_FILENO)) return false;
    const char *noColor = std::getenv("NO_COLOR");
    if (noColor && *noColor) return false;
    const char *term = std::getenv("TERM");
    if (!term || !*term) return false;
    if (std::strcmp(term, "dumb") == 0) return false;
    return true;
}

/// @brief Print the DirAtlas banner to @p out, colourised only when the
///        terminal supports it (see terminalSupportsColor).
static void printBanner(std::ostream &out = std::cout) {
    out << (terminalSupportsColor() ? diratlas::bannerRandom() : diratlas::bannerPlain());
}

/// @brief Build the version string from compile-time defines.
static std::string buildVersion() {
    std::string id;
    if (std::string(BUILD_HASH) == "nogit") {
        // No git available: use "build #<hostname>-<date>-<time>" so the
        // build host is captured at compile time, not at runtime.
        id = "build #" + std::string(BUILD_HOSTNAME) + "-" + compileTimestamp();
    } else {
        id = "Build #" + std::to_string(BUILD_NUMBER)
             + " (" + BUILD_HASH + ") " + BUILD_DATE;
    }
    return "DirAtlas v" VERSION "\n"
           "Copyright (c) 2026 Manuel FLURY - AGPL-3.0-or-later\n" + id;
}

/// @brief Parse an OpenLDAP -d debug level: decimal, 0x hex, or -1 (everything).
///        Returns 0 on invalid input so a bad flag degrades to no debugging
///        instead of aborting the whole command line.
static int parseDebugLevel(const char *s) {
    if (!s || !*s) return 0;
    char *end = nullptr;
    long v = std::strtol(s, &end, 0);
    if (end == s) return 0;
    return static_cast<int>(v);
}

/**
 * @brief Aggregate of all command-line and ldaprc configuration.
 *
 * Populated from getopt_long parsing, then supplemented by
 * readLdapRc() for values not already set via CLI flags.
 */
struct Config {
    /// LDAP URI (ldap://, ldaps://, ldapi://)
    std::string ldapUri;
    /// Full bind DN for simple authentication
    std::string binddn;
    /// Bind password (plaintext)
    std::string password;
    /// Path to file containing the password
    std::string passfile;
    /// Search base DN (default: auto-detected from RootDSE)
    std::string base = "";
    /// LDAP search filter (default: (objectClass=*))
    std::string searchFilter = "(objectClass=*)";
    /// Requested attribute list (positional args after the filter, CLI only)
    std::vector<std::string> cliAttrs;
    /// Prefix tree nodes with emoji icons (TUI only)
    bool emojis = true;
    /// Colorize TUI output
    bool colors = true;
    /// Format attribute values (timestamps, SIDs, GUIDs, UAC, etc.)
    bool format = true;
    /// Expand multi-valued attributes by default
    bool expand = true;
    /// Maximum number of values to show per attribute (default: 20)
    int attrLimit = 20;
    /// Cache LDAP entries in memory
    bool cache = true;
    /// Include deleted/tombstone objects
    bool deleted = false;
    /// LDAP operation time limit in seconds (-l)
    int timelimit = 10;
    /// StartTLS mode: 0=none, 1=try, 2=require (-Z / -ZZ)
    int starttls = 0;
    /// LDIF output level (-L repeatable): 0=extended, 1=LDIFv1, 2=no comments, 3=no version
    int ldif = 0;
    /// SOCKS proxy address
    std::string socksProxy;
    /// Alias dereferencing (-a): 0=never, 1=search, 2=find, 3=always
    int deref = 0;
    /// Search scope (-s): 0=base, 1=one, 2=sub, 3=children (0 = CLI default)
    int scope = 0;
    /// Search size limit (-z): entries; 0 = unlimited
    int sizelimit = 0;
    /// LDAP protocol version (-P): 2 or 3
    int protocolVersion = 3;
    /// Explicit -x flag (simple auth)
    bool simpleAuth = false;
    /// SASL mechanism (-Y, e.g. EXTERNAL, GSSAPI)
    std::string saslMech;
    /// SASL authcid (-U)
    std::string saslAuthcid;
    /// SASL realm (-R)
    std::string saslRealm;
    /// SASL authzid (-X)
    std::string saslAuthzId;
    /// SASL security properties (-O)
    std::string saslSecProps;
    /// Do not canonicalize SASL host name (-N)
    bool saslNoCanon = false;
    /// Suppress SASL bind output (-Q)
    bool saslQuiet = false;
    /// SASL interactive mode (-I)
    bool saslInteractive = false;
    /// OpenLDAP debug level (-d)
    int debug = 0;
    /// Raw -e / -E control specs from CLI
    std::vector<std::string> ctrlSpecs;
    /// -A: retrieve attribute names only (no values)
    bool attrsonly = false;
    /// --countEntries: print "Total number of matching entries" summary
    bool countEntries = false;
    /// -c: continue processing on errors instead of stopping
    bool continueOnError = false;
    /// -f FILE: read search filters from file (one RFC 4515 filter per line)
    std::string filterFile;
    /// --wrapColumn N / -o ldif_wrap=N: wrap LDIF output at N columns (0 = none)
    int wrapColumn = 0;
    /// --simplePageSize N: internal paged-results page size (0 = default 800)
    int simplePageSize = 0;
    /// -S attr: client-side sort of results (mirrors OpenLDAP ldapsearch -S)
    std::string sortAttr;
    /// --whoami: run RFC 4532 "Who am I?" after bind and print the authzID
    bool whoami = false;
    /// --passwd-modify[=user]: RFC 3062 password change; user empty = bind DN
    bool passwdModify = false;
    /// --passwd-modify[=user]: explicit target user DN
    std::string passwdUser;
    /// --passwd-old <pw>: RFC 3062 old password
    std::string passwdOld;
    /// --passwd-new <pw>: RFC 3062 new password (empty => server generates)
    std::string passwdNew;
    /// --cancel <msgid>: RFC 3909 cancel an in-flight operation by msgid
    int cancelMsgid = -1;
    /// --extended-op <oid>[:hex]: generic extended operation request
    std::string extOpSpec;
    // ---- TLS options filled from -o / ldaprc ----
    std::string tlsCACert;
    std::string tlsCACertDir;
    std::string tlsCert;
    std::string tlsKey;
    int tlsReqCert{-1};
    /// Network timeout in seconds (-o nettimeout=)
    int networkTimeout{0};
    /// Timestamp display format: "EU", "US", "ISO8601", or Go-style custom
    std::string timeFormat = "EU";
    /// Directory for exported data
    std::string exportDir = "data";
    /// Backend flavor: "auto", "basic", "netscape", "edirectory", "ibm", "msad" (auto = RootDSE detection)
    std::string backendFlavor = "auto";
    /// Run in CLI mode (no TUI)
    bool cli = false;
    /// Whether --filter was explicitly set (distinguishes from default)
    bool filterSet = false;
    /// Whether -b / -s were explicitly set (distinguishes ""/base from unset)
    bool baseSet = false;
    bool scopeSet = false;
    /// Timezone offset in hours for timestamp display
    int timeOffset = 0;
};

/// @brief Print help text listing all CLI flags, grouped by category.
static void printUsage(const char *prog) {
    printBanner(std::cerr);
    std::cerr << buildVersion() << "\n\n"
              << "usage: " << prog << " [options] [filter [attributes...]]\n"
              << "where:\n"
              << "  filter        RFC 4515 compliant LDAP search filter\n"
              << "  attributes    whitespace-separated list of attribute descriptions\n"
              << "                which may include:\n"
              << "                  1.1   no attributes\n"
              << "                  *     all user attributes\n"
              << "                  +     all operational attributes\n\n"
              << "Search options:\n"
              << "  -a deref   one of never (default), always, search, or find\n"
              << "  -A         retrieve attribute names only (no values)\n"
              << "  -b basedn  base dn for search\n"
              << "  -c         continuous operation mode (do not stop on errors)\n"
              << "  -f file    read search filters from file (one per line)\n"
              << "  -l limit   time limit in seconds (default: 10)\n"
              << "  -L         print responses in LDIFv1 format\n"
              << "  -LL        print responses in LDIF format without comments\n"
              << "  -LLL       print responses in LDIF format without comments and version\n"
              << "  -s scope   one of base, one, sub or children (search scope)\n"
              << "  -S attr    sort the results by attribute `attr'\n"
              << "  -z limit   size limit in entries (0 = unlimited)\n"
              << "  -E [!]<ext>[=<extparam>] search extensions (pr=, sss=, vlv=, ...)\n\n"
              << "Common options:\n"
              << "  -d level   set LDAP debugging level (additive bits, -1=all, hex ok)\n"
              << "  -D binddn  bind DN\n"
              << "  -e [!]<ext>[=<extparam>] general extensions (assert=, postread=, ...)\n"
              << "  -H URI     LDAP Uniform Resource Identifier(s)\n"
              << "  -I         use SASL Interactive mode\n"
              << "  -M         enable manageDSAit control (-MM critical)\n"
              << "  -N         do not use reverse DNS to canonicalize SASL host name\n"
              << "  -o <opt>[=<optparam>] any libldap ldap.conf options, plus\n"
              << "                ldif_wrap=<width>, nettimeout=<timeout>\n"
              << "  -O props   SASL security properties\n"
              << "  -P version protocol version (default: 3)\n"
              << "  -Q         use SASL Quiet mode\n"
              << "  -R realm   SASL realm\n"
              << "  -U authcid SASL authentication identity\n"
              << "  -V         print version info\n"
              << "  -w passwd  bind password (for simple authentication)\n"
              << "  -W         prompt for bind password\n"
              << "  -x         Simple authentication (default is SASL)\n"
              << "  -X authzid SASL authorization identity\n"
              << "  -y file    read bind password from file\n"
              << "  -Y mech    SASL mechanism\n"
              << "  -Z         Start TLS request (-ZZ to require)\n\n"
              << "DirAtlas CLI options (with --cli):\n"
              << "  --cli                 CLI mode (no TUI)\n"
              << "  --filter <f>          Search filter (default: (objectClass=*))\n"
              << "  --simplePageSize <n>  Paged results page size (default: 800)\n"
              << "  --wrapColumn <n>      Wrap LDIF output at n columns (-o ldif_wrap=)\n"
              << "  --countEntries        Print total number of matching entries\n"
              << "  --deleted             Include deleted objects\n"
              << "  --whoami              Run RFC 4532 Who am I? and print the authzID\n"
              << "  --passwd-modify[=dn]  RFC 3062 password change (user = bind DN if omitted)\n"
              << "  --passwd-old <pw>     RFC 3062 old password\n"
              << "  --passwd-new <pw>     RFC 3062 new password (omit: server generates)\n"
              << "  --cancel <msgid>      RFC 3909 cancel an operation by message id\n"
              << "  --extended-op <oid>[:hex]  Generic extended operation\n\n"
              << "DirAtlas TUI options (default mode):\n"
              << "  --emojis              Prefix tree nodes with emojis\n"
              << "  --colors              Colorize output\n"
              << "  --format              Format attribute values (timestamps, SIDs, ...)\n"
              << "  --expand              Expand multi-value attributes\n"
              << "  --limit <n>           Attribute value limit (default: 20)\n"
              << "  --timefmt <f>         Time format (EU, US, ISO8601, or custom)\n"
              << "  --offset <h>          Time offset in hours for timestamps\n"
              << "  --exportdir <d>       Export directory (default: data)\n"
              << "  --cache               Cache entries (future use)\n"
              << "  --socks <p>           SOCKS proxy\n\n"
              << "Config: /etc/ldap/ldap.conf, ~/.ldaprc, ./.ldaprc\n"
              << "  See ldap.conf(5) for all options. Set LDAPNOINIT=1 to skip.\n\n"
              << "Subcommands:\n"
              << "  doc                   Print full documentation\n"
              << "  license               Print AGPL-3.0 license\n"
              << "  -h, --help            Print this help\n";
}

/// @brief Read a file (or stdin via "-") into a string.
static std::string readFile(const std::string &path) {
    if (path == "-") {
        std::string line;
        std::getline(std::cin, line);
        return line;
    }
    std::ifstream f(path);
    if (!f.is_open()) return "";
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

/// @brief Print an LDIF record line, folding long lines at @p width columns.
/// Continuation lines start with a single space (RFC 2849). width <= 0
/// disables wrapping. @p prefix must already contain the "attr: " form.
static void printLdifWrapped(const std::string &prefix, const std::string &val, int width) {
    const std::string cont = " ";
    if (width <= 0 || static_cast<long>(prefix.size() + val.size()) <= width) {
        std::cout << prefix << val << '\n';
        return;
    }
    std::string cur = prefix;
    size_t i = 0;
    while (i < val.size()) {
        if (val[i] == ' ') {
            if (cur.size() + 1 > static_cast<size_t>(width)) {
                std::cout << cur << '\n';
                cur = cont;
            } else {
                cur += ' ';
            }
            ++i;
            continue;
        }
        size_t j = val.find(' ', i);
        if (j == std::string::npos) j = val.size();
        size_t wlen = j - i;
        std::string word = val.substr(i, wlen);
        if (cur.size() + wlen > static_cast<size_t>(width) && cur.size() > prefix.size()) {
            std::cout << cur << '\n';
            cur = cont;
        }
        if (wlen >= static_cast<size_t>(width)) {
            size_t off = 0;
            if (cur.size() > prefix.size()) { std::cout << cur << '\n'; cur = cont; }
            while (off < wlen) {
                size_t take = (static_cast<size_t>(width) > cur.size())
                    ? static_cast<size_t>(width) - cur.size() : 1;
                take = std::min(take, wlen - off);
                cur += word.substr(off, take);
                off += take;
                if (off < wlen) { std::cout << cur << '\n'; cur = cont; }
            }
        } else {
            cur += word;
        }
        i = j;
    }
    if (!cur.empty() && cur != cont)
        std::cout << cur << '\n';
}

/// @brief Print version and build info then exit.
static void printVersion() {
    printBanner();
    std::cout << buildVersion() << std::endl;
}

/// @brief Print full documentation text (ASCII art) then exit.
static void printDocumentation() {
    std::cout << R"RAW(╔══════════════════════════════════════════════════════════════╗
║                     DirAtlas v)RAW" << VERSION << R"RAW(                         ║
║            LDAP Directory Explorer (terminal TUI)            ║
╚══════════════════════════════════════════════════════════════╝

Copyright (c) 2026 Manuel FLURY – AGPL-3.0-or-later

───────────────────────────────────────────────────────────────
MODULES

  src/main.cpp          CLI parsing, LDAP session, TUI launch
  src/ldap_conn.*       OpenLDAP libldap wrapper
  src/ldapcore/*        Generic LDAP formatting (GeneralizedTime,
                        durations, binary/HEX, byte helpers, DN helpers)
  src/ad/*              Active Directory (SID, GUID, flags, NT timestamps)
  src/vars.*            Constants, maps, emoji, predefined queries
  src/tui/*             ncurses TUI: tree, attrs panel, search
  tests/*               unit tests (ctest)

───────────────────────────────────────────────────────────────
ARCHITECTURE

  main.cpp ──► ldap_conn.* (libldap) ──► LDAP server
     │
     ├─► [--cli] search loop ──► LDIF output
     └─► tui::App (event loop + worker thread)
             ├─ TreeWidget  (hierarchy browser)
             └─ AttrsWidget (attribute panel)
                     │ flavour-gated formatting
                     ├─ ad/*       (Microsoft AD: SID, GUID, flags, NT time)
                     └─ ldapcore/* (generic: GeneralizedTime, durations, HEX)
  Config: CLI flags > ldaprc (ldap.conf / ~/.ldaprc / ./.ldaprc)

───────────────────────────────────────────────────────────────
FLAGS (ldapsearch-compatible)

  Connection:
    -H <uri>         LDAP URI (ldap:// ldaps:// ldapi://)
    -Z               StartTLS (try; -ZZ to require)
    -l <sec>         Time limit (default: 10)
    -z <n>           Size limit in entries (0 = unlimited)
    -a <mode>        Alias deref: never, search, find, always
    -P <2|3>         LDAP protocol version (default: 3)
    -o <opt>[=<p>]   ldap.conf option (tls_reqcert=never, nettimeout, ...)
    --socks <proxy>  SOCKS proxy

  Authentication:
    -D <binddn>      Bind DN
    -w <password>    Bind password
    -W               Prompt for password (interactive)
    -y <file>        Read password from file
    -Y <mech>        SASL mechanism (EXTERNAL, GSSAPI, DIGEST-MD5, ...)
    -U <authcid>     SASL authentication identity
    -R <realm>       SASL realm
    -X <authzid>     SASL authorization identity
    -O <props>       SASL security properties
    -N               Do not canonicalize SASL host name
    -I               SASL interactive mode (prompt as needed)
    -Q               SASL quiet mode (never prompt)
    -x               Simple bind (default is SASL, like ldapsearch)

  Search / Display:
    -b <base>        Search base DN
    -s <scope>       Search scope: base, one, sub, children
    --filter <f>     Filter (default: (objectClass=*))
    --deleted        Include deleted objects
    --emojis         Prefix tree nodes with emojis (TUI only)
    --colors / --format / --expand
    --limit <n> / --timefmt / --offset
    --cache / --exportdir <dir>
    --cli            CLI mode (no TUI)

  Controls (-e general, -E search extension):
    -M               Enable manageDSAit control (-MM critical)
    -e manageDSAit   Manage DSA IT
    -e sessiontracking=<app>
    -e effectiverights=<authzId>/<attrs>  Get Effective Rights
    -e realAttributesOnly / -e virtualAttributesOnly
    -e transactionID=<id>
    -E pr=<size>     Paged results
    -E sss=<attr>    Server-side sort
    -E subentries=true
    -e !assert=<filter>  Assertion control (critical)

───────────────────────────────────────────────────────────────
KEYBOARD

  Tab / Shift+Tab   Rotate focus (Tree <-> Attrs <-> Filter)
  ↑ ↓              Navigate tree / scroll attributes
  → / +            Expand tree node
  ← / -            Collapse tree node
  Enter            Select node (load attrs); moves focus to the
                   attributes panel so F2 edit works immediately
  g                Jump the tree back to the RootDSE
  /                Tree: focus filter bar with search base
                   Attrs: enter search-in-value mode
  h, H, ?          Show the keyboard help popup
  PgUp / PgDn      Jump 10 lines
  r                Refresh subtree
  F1..F8, F11/F12  Open menus (File / Edit / Settings)
  F9 / F10         Previous / next theme
  F2               Attrs panel: enter inline edit mode
  Esc              Cancel background operation / close menu / leave edit
  q                Quit

  Function keys are recognised in several terminal encodings:
  SS3 (\EO..), CSI (\E[n~) and Konsole (\E[[A-L), so they work
  under PuTTY, xterm and Konsole without configuration.

───────────────────────────────────────────────────────────────
TUI OPERATIONS (background threads)

  Every LDAP operation that can block (loading a subtree, fetching
  an entry, CRUD writes, LDIF export) runs on a dedicated worker
  thread, never on the UI thread.  The ncurses loop stays
  responsive and Esc cancels the running operation.

  main loop (UI)                    worker_ thread (LDAP)
  ─────────────                     ───────────────────
  getch() ─► handleKey()
      │                                │
      │  loadChildren / searchOne      │
      │  write op / export             ▼
      │  ──────────────────────────► conn_.search(...)
      ▼                                │
  pendingUpdate_ / pendingLog_  ◄──────┘  result
      │
      ▼
  draw()

  If an operation takes longer than ~1s, a "Operation in progress"
  popup appears with the current task and an "(Esc to cancel)" hint.

───────────────────────────────────────────────────────────────
EDITING (CRUD)

  All write operations (add, modify, rename, move, delete) run on
  the background worker thread and refresh the tree / entry on
  success; Esc cancels while running.

  Edit menu (or F2 on the attrs panel):
    • Add entry          pick an objectClass from the server schema,
                         pre-filled with its inherited MUST attributes
    • Duplicate entry    copy the current entry under a new RDN /
                         parent (same objectClass and values)
    • Rename / Move      edit the RDN and/or parent DN (moddn)
    • Delete entry       destructive — always asks for Y/N first
    • Add attribute      prompt for attribute name + value
    • Delete attribute   destructive — asks for Y/N first;
                         multi-valued attributes prompt per value
  p / P              Paste: duplicate the entry currently in the
                     clipboard (set by copy in the tree panel)
  Inline edit (F2):  Enter to confirm, Esc to cancel; editing an
                     RDN attribute (cn, ou, uid, dc) triggers a
                     real moddn instead of a value replacement.
  All destructive operations use a consistent [Y]es / [N]o prompt.

───────────────────────────────────────────────────────────────
ATTRIBUTES PANEL

  • objectClass always first, values sorted by schema hierarchy
    (top → SUP chain → alphabetical)
  • Then mandatory (bold), regular, operational (italic)
  • Schema attrs (attributeTypes, objectClasses, matchingRules,
    ldapSyntaxes, olcSchemaConfig, …) syntax-highlighted:
    – OIDs in bold green, keywords in bold dark red,
      quoted strings in green, parens dim
  • Multi-valued attrs collapse after 3 values;
    Enter on [+N more] / [- hide] to toggle
  • Press / to search values (green highlight on match)
  • DN shown as panel title

───────────────────────────────────────────────────────────────
TREE PANEL

  • Without -b: the tree root is the RootDSE (empty DN); its
    namingContexts + configContext + monitorContext +
    subschemaSubentry are listed as children.
  • With -b <base>: the tree root is the search base itself, and
    its children are loaded with a onelevel search.  Press g to
    jump back to the RootDSE at any time.
  • Each context verified accessible before appearing
  • Filter (/ to focus bar): search results shown as virtual
    children, replaced on next search

───────────────────────────────────────────────────────────────
BANNER

  On startup the colour banner picks one of 8 gradient palettes at
  random (green, blue, cyan, magenta, orange, red, emerald,
  lavender).  Colour is used only when the terminal supports it
  (TTY + TERM != dumb + no NO_COLOR); otherwise a plain banner is
  shown.  It appears on TUI exit, --help and --version, and is
  kept off the CLI LDIF output.

───────────────────────────────────────────────────────────────
EMOJIS

  👤 user    👥 group    💻 computer    📂 OU    📁 container
  🌐 domain  🔗 domainDNS  ⚙️ GPO/config
  📊 monitor sections  🔌 Connections  🧵 Threads  🕐 Time  …
  📖 subschema  🗄️ Database  🏗️ Backend

───────────────────────────────────────────────────────────────
LICENSE

  DirAtlas is free software distributed under the GNU Affero
  General Public License v3.0 or later (AGPL-3.0-or-later).
  Copyright (c) 2026 Manuel FLURY.

  You may redistribute it and/or modify it under the terms of the
  AGPL-3.0.  A copy of the full license text is embedded in the
  binary; run `diratlas license` to print it.

───────────────────────────────────────────────────────────────
EXAMPLES (by option)

  # Basic connect & bind
  -H ldap://server:389 -D 'cn=admin,dc=example,dc=com' -w secret
  -H ldaps://server:636 -D 'cn=admin,dc=example,dc=com' -W                # prompt for pw
  -H ldap://server:389 -D 'cn=admin,dc=example,dc=com' -y passfile.txt     # password from file

  # StartTLS (-Z) and LDAPI
  -H ldap://server:389 -Z -D 'cn=admin,dc=example,dc=com' -w secret        # upgrade to TLS
  -H ldap://server:389 -ZZ -D 'cn=admin,dc=example,dc=com' -w secret       # require TLS
  -H ldapi://%2fvar%2frun%2fslapd.sock                                     # Unix socket

  # SASL authentication
  -H ldapi://%2fvar%2frun%2fslapd.sock -Y EXTERNAL -Q                      # SASL EXTERNAL
  -H ldap://server:389 -Y GSSAPI -Q                                         # Kerberos/GSSAPI
  -H ldap://server:389 -Y DIGEST-MD5 -D 'cn=admin,dc=example,dc=com' -w secret

  # Search / scope
  -H ldap://server:389 -b 'dc=example,dc=com' -D 'cn=admin,…' -w secret
  -H ldap://server:389 -b 'cn=config' -Y EXTERNAL -Q                        # cn=config backend
  -s sub                                                                     # subtree search (default)
  --filter '(uid=john)'                                                      # add search filter
  --deleted                                                                  # include tombstone entries
  -E pr=500                                                                  # paged results
  -a search                                                                  # alias dereferencing

  # Controls (ldapsearch: -e general, -E search extension)
  -e manageDSAit                                                             # manage DSA IT
  -e sessiontracking=myapp                                                   # session tracking
  -e effectiverights=dn:uid=admin/objectClass                               # effective rights
  -E !pr=100/noprompt                                                        # paged results, critical
  -E sss=uid                                                                 # server-side sort
  -E subentries=true                                                         # include subentries

  # Timeouts & limitations
  -l 30                                                                      # time limit 30s
  -z 1000                                                                    # size limit 1000 entries
  -H ldap://server:389 -l 5 -b 'dc=example,dc=com'                          # time limit 5s

  # LDAP config file (ldap.conf / .ldaprc)
  # Set LDAPNOINIT=1 to skip all config files
  # See ldap.conf(5) for TLS_CACERT, TLS_REQCERT, SASL_MECH, BASE, URI, …
  # -o tls_reqcert=never    # skip TLS verification (ldapsearch-style)

  # SOCKS proxy
  --socks socks5://127.0.0.1:1080                                            # tunnel via SSH -D 1080
  -H ldap://internal-server:389 -D 'cn=admin,dc=…' -w secret

  # Display options
  --colors --emojis --format --expand                                        # all default ON (TUI)
  --limit 50                                                                 # max values per attribute
  --timefmt ISO8601                                                          # ISO dates
  --offset 2                                                                 # UTC+2h for timestamps

  # Misc
  -d 0x10                                                                    # OpenLDAP loglevel: BER packet hex+ASCII dump
  --cli                                                                      # CLI mode (no TUI)
  --whoami                                                                   # RFC 4532 who am I?
  --passwd-modify 'cn=user,dc=…' --passwd-old oldpw --passwd-new newpw       # RFC 3062
  --extended-op 1.3.6.1.4.1.26027.1.6.2                                      # PingDS conn id
  -V                                                                         # show version
  doc                                                                       # show this help
  license                                                                   # show AGPL-3.0 license
  -h, --help                                                                # option reference

For option reference: diratlas --help
)RAW" << std::endl;
}

int main(int argc, char **argv) {
    Config cfg;                          ///< Aggregate of all CLI + rc configuration

    // Seed the global debug logger with the raw -d value before any step runs.
    for (int i = 1; i < argc; i++) {
        if (std::strcmp(argv[i], "-d") == 0 || std::strncmp(argv[i], "-d", 2) == 0) {
            const char *v = (std::strcmp(argv[i], "-d") == 0 && i + 1 < argc) ? argv[i + 1] : argv[i] + 2;
            diratlas::g_debugLevel = parseDebugLevel(v);
        }
    }

    // ── Handle special "command" arguments (version / doc / license / help) ──
    if (argc > 1) {
        if (strcmp(argv[1], "version") == 0) {
            printVersion(); return 0;
        }
        if (strcmp(argv[1], "doc") == 0 || strcmp(argv[1], "--doc") == 0) {
            printDocumentation(); return 0;
        }
        if (strcmp(argv[1], "license") == 0) {
            std::cout << diratlas::LICENSE_TEXT << std::endl; return 0;
        }
        if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
            printUsage(argv[0]); return 0;
        }
    }



    static struct option long_options[] = {
        {"uri",        required_argument, nullptr, 'H'},
        {"binddn",     required_argument, nullptr, 'D'},
        {"password",   required_argument, nullptr, 'w'},
        {"passfile",   required_argument, nullptr, 'y'},
        {"base",       required_argument, nullptr, 'b'},
        {"timelimit",  required_argument, nullptr, 'l'},
        {"deref",      required_argument, nullptr, 'a'},
        {"scope",      required_argument, nullptr, 's'},
        {"sizelimit",  required_argument, nullptr, 'z'},
        {"debug",      required_argument, nullptr, 'd'},
        {"version",    no_argument,       nullptr, 'V'},
        {"option",     required_argument, nullptr, 'o'},
        {"protocol",   required_argument, nullptr, 'P'},
        {"starttls",   no_argument,       nullptr, 'Z'},
        {"mech",       required_argument, nullptr, 'Y'},
        {"quiet",      no_argument,       nullptr, 'Q'},
        {"ldif",       no_argument,       nullptr, 'L'},
        {"authcid",    required_argument, nullptr, 'U'},
        {"realm",      required_argument, nullptr, 'R'},
        {"authzid",    required_argument, nullptr, 'X'},
        {"saslsecprops", required_argument, nullptr, 'O'},
        {"nocanon",    no_argument,       nullptr, 'N'},
        {"interactive", no_argument,      nullptr, 'I'},
        {"manageDSAit", no_argument,      nullptr, 'M'},
        {"control",    required_argument, nullptr, 'E'},
        {"typesonly",  no_argument,       nullptr, 'A'},
        {"continue",   no_argument,       nullptr, 'c'},
        {"filterfile", required_argument, nullptr, 'f'},
        {"sort",       required_argument, nullptr, 'S'},
        {"countEntries", no_argument,     nullptr, 0},
        {"wrapColumn", required_argument, nullptr, 0},
        {"nowrap",     no_argument,       nullptr, 0},
        {"simplePageSize", required_argument, nullptr, 0},
        {"whoami",     no_argument,       nullptr, 0},
        {"passwd-modify", optional_argument, nullptr, 0},
        {"passwd-old", required_argument, nullptr, 0},
        {"passwd-new", required_argument, nullptr, 0},
        {"cancel",     required_argument, nullptr, 0},
        {"extended-op", required_argument, nullptr, 0},
        {"cli",        no_argument,       nullptr, 0},
        {"doc",        no_argument,       nullptr, 0},
        {"socks",      required_argument, nullptr, 0},
        {"filter",     required_argument, nullptr, 0},
        {"deleted",    no_argument,       nullptr, 0},
        {"emojis",     no_argument,       nullptr, 0},
        {"colors",     no_argument,       nullptr, 0},
        {"format",     no_argument,       nullptr, 0},
        {"expand",     no_argument,       nullptr, 0},
        {"limit",      required_argument, nullptr, 0},
        {"cache",      no_argument,       nullptr, 0},
        {"timefmt",    required_argument, nullptr, 0},
        {"offset",     required_argument, nullptr, 0},
        {"exportdir",  required_argument, nullptr, 0},
        {"help",       no_argument,       nullptr, 'h'},
        {nullptr, 0, nullptr, 0}
    };

    // ── Parse CLI flags via getopt_long ──
    int opt;
    int option_index = 0;
    bool promptPw = false;

    while ((opt = getopt_long(argc, argv, "H:D:w:Wy:b:l:a:s:z:d:Vo:P:ZhY:Qe:E:U:R:X:O:MN:I:xLAcf:S:",
                              long_options, &option_index)) != -1) {
        (void)opt;
        switch (opt) {
            case 0: {
                std::string name = long_options[option_index].name;
                if (name == "cli") cfg.cli = true;
                else if (name == "countEntries") cfg.countEntries = true;
                else if (name == "wrapColumn") cfg.wrapColumn = std::stoi(optarg);
                else if (name == "nowrap") cfg.wrapColumn = 0;
                else if (name == "simplePageSize") cfg.simplePageSize = std::stoi(optarg);
                else if (name == "whoami") cfg.whoami = true;
                else if (name == "passwd-modify") { cfg.passwdModify = true; if (optarg) cfg.passwdUser = optarg; }
                else if (name == "passwd-old") cfg.passwdOld = optarg;
                else if (name == "passwd-new") cfg.passwdNew = optarg;
                else if (name == "cancel") cfg.cancelMsgid = std::stoi(optarg);
                else if (name == "extended-op") cfg.extOpSpec = optarg;
                else if (name == "doc") { printDocumentation(); return 0; }
                else if (name == "filter") { cfg.searchFilter = optarg; cfg.filterSet = true; }
                else if (name == "deleted") cfg.deleted = true;
                else if (name == "cache") cfg.cache = true;
                else if (name == "emojis") cfg.emojis = true;
                else if (name == "colors") cfg.colors = true;
                else if (name == "format") cfg.format = true;
                else if (name == "expand") cfg.expand = true;
                else if (name == "limit") cfg.attrLimit = std::stoi(optarg);
                else if (name == "timefmt") cfg.timeFormat = optarg;
                else if (name == "offset") cfg.timeOffset = std::stoi(optarg);
                else if (name == "exportdir") cfg.exportDir = optarg;
                else if (name == "socks") cfg.socksProxy = optarg;
                break;
            }
            case 'a': {
                std::string m = optarg;
                if (m == "never") cfg.deref = 0;
                else if (m == "search") cfg.deref = 1;
                else if (m == "find") cfg.deref = 2;
                else if (m == "always") cfg.deref = 3;
                break;
            }
            case 's': {
                std::string m = optarg;
                cfg.scopeSet = true;
                if (m == "base") cfg.scope = 0;
                else if (m == "one") cfg.scope = 1;
                else if (m == "sub") cfg.scope = 2;
                else if (m == "children") cfg.scope = 3;
                break;
            }
            case 'z': cfg.sizelimit = std::stoi(optarg); break;
            case 'd': cfg.debug = parseDebugLevel(optarg); break;
            case 'V': printVersion(); return 0;
            case 'P': cfg.protocolVersion = std::stoi(optarg); break;
            case 'U': cfg.saslAuthcid = optarg; break;
            case 'R': cfg.saslRealm = optarg; break;
            case 'X': cfg.saslAuthzId = optarg; break;
            case 'O': cfg.saslSecProps = optarg; break;
            case 'N': cfg.saslNoCanon = true; break;
            case 'I': cfg.saslInteractive = true; break;
            case 'M': {
                // -M enables manageDSAit control; -MM makes it critical (ldapsearch).
                auto it = std::find(cfg.ctrlSpecs.begin(), cfg.ctrlSpecs.end(), "manageDSAit");
                if (it != cfg.ctrlSpecs.end()) *it = "!manageDSAit";
                else cfg.ctrlSpecs.push_back("manageDSAit");
                break;
            }
            case 'o': {
                std::string s = optarg;
                auto eq = s.find('=');
                std::string key = (eq == std::string::npos) ? s : s.substr(0, eq);
                std::string val = (eq == std::string::npos) ? "" : s.substr(eq + 1);
                for (auto &c : key) c = toupper(c);
                if (key == "TLS_REQCERT") {
                    if (val == "never") cfg.tlsReqCert = 0;
                    else if (val == "allow") cfg.tlsReqCert = 1;
                    else if (val == "try") cfg.tlsReqCert = 2;
                    else if (val == "demand" || val == "hard") cfg.tlsReqCert = 3;
                } else if (key == "TLS_CACERT") cfg.tlsCACert = val;
                else if (key == "TLS_CACERTDIR") cfg.tlsCACertDir = val;
                else if (key == "TLS_CERT") cfg.tlsCert = val;
                else if (key == "TLS_KEY") cfg.tlsKey = val;
                else if (key == "NETTIMEOUT") { try { cfg.networkTimeout = std::stoi(val); } catch (...) {} }
                else if (key == "SIZELIMIT") { try { cfg.sizelimit = std::stoi(val); } catch (...) {} }
                else if (key == "TIMELIMIT") { try { cfg.timelimit = std::stoi(val); } catch (...) {} }
                else if (key == "LDIF_WRAP") {
                    if (val == "no") cfg.wrapColumn = 0;
                    else { try { int w = std::stoi(val); if (w > 0) cfg.wrapColumn = w; } catch (...) {} }
                }
                else std::cerr << "Warning: unknown -o option: " << s << std::endl;
                break;
            }
            case 'H': cfg.ldapUri = optarg; break;
            case 'Y': cfg.saslMech = optarg; break;
            case 'Q': cfg.saslQuiet = true; break;
            case 'L': ++cfg.ldif; break;
            case 'x': cfg.simpleAuth = true; cfg.saslMech.clear(); break;
            case 'A': cfg.attrsonly = true; break;
            case 'c': cfg.continueOnError = true; break;
            case 'f': cfg.filterFile = optarg; break;
            case 'S': cfg.sortAttr = optarg; break;
            case 'E': case 'e': cfg.ctrlSpecs.push_back(optarg); break;
            case 'D': cfg.binddn = optarg; break;
            case 'w': cfg.password = optarg; break;
            case 'W': promptPw = true; break;
            case 'y': cfg.passfile = optarg; break;
            case 'b': cfg.base = optarg; cfg.baseSet = true; break;
            case 'l': cfg.timelimit = std::stoi(optarg); break;
            case 'Z': cfg.starttls = (cfg.starttls < 2) ? cfg.starttls + 1 : 2; break;
            case 'h': printUsage(argv[0]); return 0;
            default: printUsage(argv[0]); return 1;
        }
    }

    // ── Option implications (ldapsearch semantics) ──
    // A bind password (-w/-W/-y) only makes sense for simple authentication,
    // so it implies -x unless an explicit SASL mechanism (-Y) was requested.
    if (!cfg.password.empty() || promptPw || !cfg.passfile.empty())
        if (cfg.saslMech.empty())
            cfg.simpleAuth = true;

    // ── Read ldaprc files and merge with CLI config ──
    // CLI values take precedence (rc fields only set if target is empty/default).
    {
        diratlas::LdapRcConfig rc;
        readLdapRc(rc, cfg.debug, cfg.cli);
        if (cfg.ldapUri.empty()) cfg.ldapUri = rc.uri;
        if (!cfg.baseSet && cfg.base.empty()) cfg.base = rc.base;
        if (cfg.binddn.empty()) cfg.binddn = rc.binddn;
        if (cfg.saslMech.empty() && !cfg.simpleAuth) cfg.saslMech = rc.saslMech;
        else if (cfg.simpleAuth && !rc.saslMech.empty())
            std::cerr << "[config] -x overrides SASL_MECH=" << rc.saslMech << " from ldaprc" << std::endl;
        if (cfg.timelimit == 10) cfg.timelimit = rc.timelimit;
        if (cfg.sizelimit == 0) cfg.sizelimit = rc.sizelimit;
        if (cfg.saslRealm.empty()) cfg.saslRealm = rc.saslRealm;
        if (cfg.saslAuthzId.empty()) cfg.saslAuthzId = rc.saslAuthzId;
        if (cfg.saslSecProps.empty()) cfg.saslSecProps = rc.saslSecProps;
        if (cfg.deref == 0) cfg.deref = rc.deref;
        if (cfg.tlsReqCert < 0 && rc.tlsReqCert >= 0)
            cfg.tlsReqCert = rc.tlsReqCert;
        if (cfg.tlsCACert.empty()) cfg.tlsCACert = rc.tlsCACert;
        if (cfg.tlsCACertDir.empty()) cfg.tlsCACertDir = rc.tlsCACertDir;
        if (cfg.tlsCert.empty()) cfg.tlsCert = rc.tlsCert;
        if (cfg.tlsKey.empty()) cfg.tlsKey = rc.tlsKey;
        if (cfg.networkTimeout == 0) cfg.networkTimeout = rc.networkTimeout;
    }

    // ── Positional argument as URI fallback ──
    if (cfg.ldapUri.empty()) {
        if (optind < argc) {
            std::string pos = argv[optind];
            // Accept a full URI ("ldaps://host") or a bare host:port; only
            // prefix "ldap://" when no scheme is already present.
            if (pos.find("://") == std::string::npos)
                cfg.ldapUri = "ldap://" + pos;
            else
                cfg.ldapUri = pos;
        } else {
            std::cerr << "Error: use -H <ldapuri> to specify the LDAP server\n\n";
            printUsage(argv[0]);
            return 1;
        }
    }

    // ── Positional filter and attribute list (ldapsearch-compatible) ──
    // With -H given, remaining arguments are: [filter] [attr...]
    if (optind < argc && !cfg.ldapUri.empty()) {
        if (argv[optind][0] == '(') {
            cfg.searchFilter = argv[optind];
            cfg.filterSet = true;
            optind++;
        }
        for (; optind < argc; optind++)
            cfg.cliAttrs.push_back(argv[optind]);
    }

    // ── Handle password from prompt or file ──
    if (promptPw) {
        std::cout << "Password: ";
        std::getline(std::cin, cfg.password);
    }
    if (!cfg.passfile.empty()) {
        auto pw = readFile(cfg.passfile);
        if (!pw.empty())
            cfg.password = pw;
    }

    // ── Resolve time format presets → Go-style layout string ──
    if (cfg.timeFormat == "EU" || cfg.timeFormat.empty()) {
        cfg.timeFormat = "02/01/2006 15:04:05";
    } else if (cfg.timeFormat == "US") {
        cfg.timeFormat = "01/02/2006 15:04:05";
    } else if (cfg.timeFormat == "ISO8601") {
        cfg.timeFormat = "2006-01-02 15:04:05";
    }

    // ── Initialise LDAP connection handle ──
    diratlas::LDAPConn conn;
    conn.setDeref(cfg.deref);
    conn.timelimit = cfg.timelimit;
    conn.sizelimit = cfg.sizelimit;
    if (cfg.simplePageSize > 0)
        conn.pagingSize = static_cast<uint32_t>(cfg.simplePageSize);
    conn.networkTimeout = cfg.networkTimeout;
    conn.setProtocolVersion(cfg.protocolVersion);
    if (cfg.debug)
        conn.setDebug(cfg.debug);

    // ── Apply TLS options to connection handle ──
    conn.tlsOpts.cacert = cfg.tlsCACert;
    conn.tlsOpts.cacertdir = cfg.tlsCACertDir;
    conn.tlsOpts.cert = cfg.tlsCert;
    conn.tlsOpts.key = cfg.tlsKey;
    conn.tlsOpts.reqcert = cfg.tlsReqCert;

    // Debug: dump effective configuration after merging CLI + ldaprc
    if (cfg.debug) {
        std::cerr << "[config] Effective configuration:" << std::endl;
        std::cerr << "  uri      = " << cfg.ldapUri << std::endl;
        std::cerr << "  base     = " << cfg.base << std::endl;
        std::cerr << "  binddn   = " << cfg.binddn << std::endl;
        std::cerr << "  sasl_mech= " << cfg.saslMech << std::endl;
        std::cerr << "  timelimit= " << cfg.timelimit << std::endl;
        std::cerr << "  deref    = " << cfg.deref << std::endl;
        if (cfg.simpleAuth) std::cerr << "  auth     = simple (-x)" << std::endl;
        else if (!cfg.saslMech.empty()) std::cerr << "  auth     = SASL (" << cfg.saslMech << ")" << std::endl;
        else std::cerr << "  auth     = SASL (default, no -x)" << std::endl;
        std::cerr << "  debug    = " << cfg.debug << " (0x" << std::hex << cfg.debug << std::dec << ")" << std::endl;
        for (int bit = 0x1; bit <= 0x8000; bit <<= 1)
            if (cfg.debug & bit)
                std::cerr << "    - " << diratlas::debugBitName(bit) << " (0x" << std::hex << bit << std::dec << ")" << std::endl;
    }

    diratlas::dbgLog(diratlas::LDAP_DEBUG_TRACE, "CLI: " + std::to_string(argc - 1) + " argument(s), uri=" + cfg.ldapUri
        + ", base=" + cfg.base + ", scope=" + std::to_string(cfg.scopeSet ? cfg.scope : LDAP_SCOPE_ONELEVEL)
        + (cfg.scopeSet ? "" : " (default one)") + ", cli=" + (cfg.cli ? "yes" : "no"));

    // ── Connect to LDAP server ──
    // Progress notes are always "# ..." comments in CLI mode so the
    // LDIF stream stays comment-safe at every -L/-LL/-LLL level.
    auto note = [&](const std::string &msg) {
        if (cfg.cli) {
            std::cout << "# " << msg << std::endl;
        } else {
            std::cout << msg << std::endl;
        }
    };
    note("Connecting to " + cfg.ldapUri + "...");
    diratlas::dbgLog(diratlas::LDAP_DEBUG_TRACE, "connect: uri=" + cfg.ldapUri);
    if (!conn.connect(cfg.ldapUri, cfg.socksProxy)) {
        std::cerr << "Failed to connect to LDAP server" << std::endl;
        return 1;
    }
    diratlas::dbgLog(diratlas::LDAP_DEBUG_TRACE, "connect: ok");

    // ── Register -e/-E control specs after connect (needs the live handle) ──
    // An explicit paged-results spec (-E pr=<size>) maps to the internal
    // paging engine instead of a user control, so the multi-page loop in
    // search() keeps control of the RFC 2696 cookie.
    std::vector<std::string> pending = cfg.ctrlSpecs;
    for (const auto &spec : pending) {
        std::string stripped = (spec.size() > 1 && spec[0] == '!') ? spec.substr(1) : spec;
        if (stripped.rfind("pr=", 0) == 0) {
            std::string ps = stripped.substr(3);
            auto slash = ps.find('/');
            if (slash != std::string::npos) ps = ps.substr(0, slash);
            try { conn.pagingSize = static_cast<uint32_t>(std::stoi(ps)); }
            catch (...) { std::cerr << "Warning: bad -E pr= page size: " << spec << std::endl; }
            continue;
        }
        std::string err;
        if (!conn.addControlSpec(spec, err))
            std::cerr << "Warning: " << err << std::endl;
    }

    // ── StartTLS negotiation (try or require) ──
    if (cfg.starttls > 0) {
        diratlas::dbgLog(diratlas::LDAP_DEBUG_TRACE, "starttls: negotiating (" + std::string(cfg.starttls == 2 ? "required" : "try") + ")");
        bool ok = conn.startTLS();
        if (!ok && cfg.starttls == 2) {
            std::cerr << "StartTLS required (-ZZ) but failed: " << conn.getLastError() << std::endl;
            return 1;
        }
        if (ok) {
            note("StartTLS established");
            diratlas::dbgLog(diratlas::LDAP_DEBUG_TRACE, "starttls: established");
        } else {
            note("StartTLS not available (proceeding without TLS)");
            diratlas::dbgLog(diratlas::LDAP_DEBUG_TRACE, "starttls: failed - " + conn.getLastError());
        }
    }

    // ── Authenticate (ldapsearch semantics) ──
    //   -x      → simple bind (with -D/-w, or anonymous)
    //   -Y mech → SASL with that mechanism
    //   neither → SASL by default (mech from ldaprc, else library default);
    //             -D/-w are offered as SASL authcid/password
    if (cfg.simpleAuth) {
        note("Auth: simple bind (-x)");
        diratlas::dbgLog(diratlas::LDAP_DEBUG_TRACE, "bind: simple dn=" + cfg.binddn + (cfg.password.empty() ? " (no password)" : " (password set)"));
        if (!conn.simpleBind(cfg.binddn, cfg.password)) {
            std::cerr << "Bind failed: " << conn.getLastError() << std::endl;
            return 1;
        }
        note("Bind successful");
        diratlas::dbgLog(diratlas::LDAP_DEBUG_TRACE, "bind: simple ok");
    } else if (!cfg.saslMech.empty()) {
        note("Auth: SASL (" + cfg.saslMech + ")");
        diratlas::dbgLog(diratlas::LDAP_DEBUG_TRACE, "bind: SASL mech=" + cfg.saslMech + (cfg.saslAuthcid.empty() ? "" : " authcid=" + cfg.saslAuthcid));
        if (!conn.saslBind(cfg.saslMech, cfg.saslAuthzId, cfg.saslAuthcid,
                           cfg.saslRealm, cfg.saslSecProps, cfg.saslNoCanon,
                           cfg.saslInteractive)) {
            std::cerr << "SASL bind (" << cfg.saslMech << ") failed: "
                      << conn.getLastError() << std::endl;
            return 1;
        }
        if (!cfg.saslQuiet)
            note("SASL bind (" + cfg.saslMech + ") successful");
        diratlas::dbgLog(diratlas::LDAP_DEBUG_TRACE, "bind: SASL ok");
    } else {
        note("Auth: SASL (default, no -x; use -x for simple bind)");
        diratlas::dbgLog(diratlas::LDAP_DEBUG_TRACE, "bind: SASL default, authcid=" + (cfg.saslAuthcid.empty() ? cfg.binddn : cfg.saslAuthcid));
        if (!conn.saslBind("", cfg.saslAuthzId, cfg.saslAuthcid.empty() ? cfg.binddn : cfg.saslAuthcid,
                           cfg.saslRealm, cfg.saslSecProps, cfg.saslNoCanon,
                           cfg.saslInteractive)) {
            std::cerr << "SASL bind (default) failed: " << conn.getLastError() << std::endl;
            std::cerr << "  Use -x for simple bind, or -Y <mech> to pick a SASL mechanism." << std::endl;
            return 1;
        }
        if (!cfg.saslQuiet)
            note("SASL bind successful");
        diratlas::dbgLog(diratlas::LDAP_DEBUG_TRACE, "bind: SASL default ok");
    }

    // ── RFC 4532 "Who am I?" extended operation ──
    if (cfg.whoami) {
        std::string authzid = conn.whoAmI();
        if (authzid.empty()) {
            std::cerr << "Who am I? failed: " << conn.getLastError() << std::endl;
            return 1;
        }
        std::cout << "authzID: " << authzid << std::endl;
        if (cfg.cli) return 0;
    }

    // ── RFC 3062 Password Modify extended operation ──
    if (cfg.passwdModify) {
        std::string generated;
        if (!conn.passwordModify(cfg.passwdUser, cfg.passwdOld, cfg.passwdNew, generated)) {
            std::cerr << "Password modify failed: " << conn.getLastError() << std::endl;
            return 1;
        }
        std::cout << "Password modified";
        if (!generated.empty())
            std::cout << " (generated: " << generated << ")";
        std::cout << std::endl;
        if (cfg.cli) return 0;
    }

    // ── RFC 3909 Cancel extended operation ──
    if (cfg.cancelMsgid >= 0) {
        if (!conn.cancelOperation(cfg.cancelMsgid)) {
            std::cerr << "Cancel failed: " << conn.getLastError() << std::endl;
            return 1;
        }
        std::cout << "Cancel sent for msgid " << cfg.cancelMsgid << std::endl;
        if (cfg.cli) return 0;
    }

    // ── Generic extended operation (e.g. PingDS Get Connection ID) ──
    if (!cfg.extOpSpec.empty()) {
        std::string oid = cfg.extOpSpec;
        std::vector<uint8_t> req, res;
        auto colon = oid.find(':');
        if (colon != std::string::npos) {
            std::string hex = oid.substr(colon + 1);
            oid = oid.substr(0, colon);
            for (size_t i = 0; i + 1 < hex.size(); i += 2)
                req.push_back(static_cast<uint8_t>(std::stoi(hex.substr(i, 2), nullptr, 16)));
        }
        if (!conn.extendedOp(oid, req, res)) {
            std::cerr << "Extended op " << oid << " failed: " << conn.getLastError() << std::endl;
            return 1;
        }
        std::cout << "Extended op " << oid << " succeeded (" << res.size() << " bytes response)";
        if (!res.empty()) {
            std::cout << ": ";
            for (size_t i = 0; i < res.size(); ++i)
                std::cout << std::hex << std::setw(2) << std::setfill('0')
                          << static_cast<unsigned>(res[i]) << std::dec;
        }
        std::cout << std::endl;
        if (cfg.cli) return 0;
    }

    // ── Detect backend flavour (auto / basic / netscape / edirectory / ibm / msad) ──
    if (cfg.backendFlavor == "auto") conn.guessFlavor();
    else if (cfg.backendFlavor == "basic") conn.flavor = diratlas::LDAPFlavor::StandardLDAP;
    else if (cfg.backendFlavor == "netscape") conn.flavor = diratlas::LDAPFlavor::NetscapeLDAP;
    else if (cfg.backendFlavor == "edirectory") conn.flavor = diratlas::LDAPFlavor::EDirectoryLDAP;
    else if (cfg.backendFlavor == "ibm") conn.flavor = diratlas::LDAPFlavor::IBMLDAP;
    else conn.flavor = diratlas::LDAPFlavor::MicrosoftAD;
    const char *flavorName =
        (conn.flavor == diratlas::LDAPFlavor::MicrosoftAD) ? "MicrosoftAD"
        : (conn.flavor == diratlas::LDAPFlavor::NetscapeLDAP) ? "NetscapeLDAP"
        : (conn.flavor == diratlas::LDAPFlavor::EDirectoryLDAP) ? "EDirectoryLDAP"
        : (conn.flavor == diratlas::LDAPFlavor::IBMLDAP) ? "IBMLDAP"
        : "StandardLDAP";
    note(std::string("Server type: ") + flavorName
        + (conn.serverVersion.empty() ? "" : " (" + conn.serverVersion + ")"));
    diratlas::dbgLog(diratlas::LDAP_DEBUG_TRACE, "flavor: " + std::string(flavorName)
        + (conn.serverVersion.empty() ? "" : " version=" + conn.serverVersion));
    // ── Auto-detect search base from RootDSE if not supplied ──
    if (!cfg.baseSet) {
        if (!conn.findRootDN(cfg.base)) {
            std::cerr << "Could not find root DN" << std::endl; return 1;
        }
        note("Root DN: " + cfg.base);
        diratlas::dbgLog(diratlas::LDAP_DEBUG_TRACE, "base: auto-detected " + cfg.base);
    }
    conn.defaultRootDN = cfg.base;
    diratlas::dbgLog(diratlas::LDAP_DEBUG_TRACE, "base: " + cfg.base);

    // ── CLI mode: one-shot query, no TUI ──
    if (cfg.cli) {
        std::vector<std::string> filters;
        if (!cfg.filterFile.empty()) {
            std::string content = readFile(cfg.filterFile);
            if (content.empty()) {
                std::cerr << "Error: cannot read filter file: " << cfg.filterFile << std::endl;
                return 1;
            }
            std::istringstream iss(content);
            std::string line;
            while (std::getline(iss, line)) {
                auto first = line.find_first_not_of(" \t\r\n");
                if (first == std::string::npos || line[first] == '#') continue;
                filters.push_back(line.substr(first));
            }
            if (filters.empty()) {
                std::cerr << "Error: no filters in " << cfg.filterFile << std::endl;
                return 1;
            }
        } else {
            filters.push_back(cfg.searchFilter);
        }

        int scope = cfg.scopeSet ? cfg.scope : LDAP_SCOPE_ONELEVEL;
        const auto &attrs = cfg.cliAttrs.empty()
            ? std::vector<std::string>{"*", "name", "objectClass", "cn", "ou", "dc"}
            : cfg.cliAttrs;
        int totalEntries = 0;
        bool hadError = false;

        // ldapsearch reports its defaults; do the same so the user sees the
        // exact query that will run when -s / filter / attrs were omitted.
        {
            const char *scopeName = (scope == LDAP_SCOPE_BASE) ? "base"
                : (scope == LDAP_SCOPE_ONELEVEL) ? "one"
                : (scope == LDAP_SCOPE_SUBORDINATE) ? "children" : "sub";
            std::string eff = "Search: base <" + cfg.base + "> scope " + scopeName
                + (cfg.scopeSet ? "" : " (default)");
            eff += " filter " + (cfg.filterSet ? filters.front() : "(objectClass=*) (default)");
            eff += std::string(" attrs ") + (cfg.cliAttrs.empty() ? "default (* name objectClass cn ou dc)" : "explicit");
            note(eff);
            diratlas::dbgLog(diratlas::LDAP_DEBUG_TRACE, "search: effective " + eff);
        }

        for (const auto &filter : filters) {
            std::vector<diratlas::LDAPEntry> results;
            diratlas::dbgLog(diratlas::LDAP_DEBUG_STATS, "search: base=" + cfg.base + " scope=" + std::to_string(scope)
                + " filter=" + filter + " attrs=" + std::to_string(attrs.size()));
            bool ok = conn.search(cfg.base, scope, filter, attrs, cfg.deleted, results, cfg.attrsonly);
            if (!ok) {
                const char *scopeName = (scope == LDAP_SCOPE_BASE) ? "base"
                    : (scope == LDAP_SCOPE_ONELEVEL) ? "one"
                    : (scope == LDAP_SCOPE_SUBORDINATE) ? "children" : "sub";
                std::cerr << "Query failed: " << conn.getLastError() << std::endl;
                std::cerr << "  request: base <" << cfg.base << "> scope " << scopeName
                          << " filter " << filter << std::endl;
                diratlas::dbgLog(diratlas::LDAP_DEBUG_STATS, "search: FAILED - " + conn.getLastError());
                hadError = true;
                if (!cfg.continueOnError) return 1;
                continue;
            }
            totalEntries += static_cast<int>(results.size());
            if (filters.size() > 1)
                note("Filter: " + filter);
            note("Found " + std::to_string(results.size()) + " objects at " + cfg.base);
            diratlas::dbgLog(diratlas::LDAP_DEBUG_STATS, "search: " + std::to_string(results.size()) + " result(s)");

            // -S attr : local sort of the result entries (mirrors OpenLDAP
            // ldapsearch, which sorts client-side via ldap_sort_entries()).
            // This is NOT a server-side sort control (that would be -E sss=).
            if (!cfg.sortAttr.empty()) {
                std::sort(results.begin(), results.end(),
                    [&cfg](const diratlas::LDAPEntry &a, const diratlas::LDAPEntry &b) {
                        auto av = a.getAttrs(cfg.sortAttr);
                        auto bv = b.getAttrs(cfg.sortAttr);
                        if (av.empty() && bv.empty()) return false;
                        if (av.empty()) return true;   // entries without the attr first
                        if (bv.empty()) return false;
                        return strcasecmp(av[0].c_str(), bv[0].c_str()) < 0;
                    });
            }

            if (cfg.ldif == 0) {
                std::cout << "# extended LDIF" << std::endl;
            } else if (cfg.ldif < 3) {
                std::cout << "version: 1" << std::endl << std::endl;
            }
            if (cfg.ldif < 2) {
                const char *scopeName = (scope == LDAP_SCOPE_BASE) ? "baseObject"
                    : (scope == LDAP_SCOPE_ONELEVEL) ? "oneLevel"
                    : (scope == LDAP_SCOPE_SUBORDINATE) ? "children" : "subtree";
                std::cout << "#" << std::endl
                          << "# LDAPv3" << std::endl
                          << "# base <" << cfg.base << "> with scope " << scopeName << std::endl
                          << "# filter: " << filter << std::endl
                          << "# requesting: ";
                if (attrs.empty()) std::cout << "ALL";
                else for (const auto &a : attrs) std::cout << a << " ";
                std::cout << std::endl << "#" << std::endl;
            }
            for (const auto &entry : results) {
                if (cfg.ldif < 2 && !entry.dn.empty())
                    std::cout << "# " << entry.dn << std::endl;
                printLdifWrapped("dn: ", entry.dn, cfg.wrapColumn);
                for (const auto &attr : entry.attributeNames) {
                    if (cfg.attrsonly) {
                        std::cout << attr << ":" << std::endl;
                        continue;
                    }
                    for (const auto &val : entry.getAttrs(attr)) {
                        if (diratlas::ldapcore::ldifSafeValue(val))
                            printLdifWrapped(attr + ": ", val, cfg.wrapColumn);
                        else
                            printLdifWrapped(attr + ":: ", diratlas::ldapcore::base64Encode(val), cfg.wrapColumn);
                    }
                }
                std::cout << std::endl;
            }
        }

        if (cfg.countEntries)
            std::cout << "# Total number of matching entries: " << totalEntries << std::endl;
        return hadError ? 1 : 0;
    }

    // ── Launch TUI with optional initial filter and base ──
    // Guard: ncurses would busy-loop redrawing when stdin is not a terminal
    // (pipes, redirects, CI). Refuse to start instead of spamming the output.
    if (!isatty(STDIN_FILENO)) {
        std::cerr << "TUI requires a terminal on stdin; use --cli for scripted use."
                  << std::endl;
        return 1;
    }
    std::string tuiFilter = cfg.filterSet ? cfg.searchFilter : "";
    // Build bind identity string
    std::string bindId;
    if (!cfg.saslMech.empty())
        bindId = cfg.saslMech;
    else if (!cfg.binddn.empty())
        bindId = cfg.binddn;
    else
        bindId = "anonymous";

    int rc;
    {
        // App must be destroyed (endwin restores the terminal) BEFORE the
        // banner is printed, so the ANSI banner renders on a clean terminal.
        diratlas::tui::App app;
        if (!app.init(conn, tuiFilter, cfg.base, cfg.ldapUri, bindId, cfg.baseSet)) {
            std::cerr << "Failed to initialize TUI" << std::endl;
            return 1;
        }
        rc = app.run();
    }
    printBanner();
    return rc;
}
