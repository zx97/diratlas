// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Manuel FLURY
//
// This file is part of DirAtlas — an LDAP Directory Explorer.
//
// Licensed under the GNU Affero General Public License v3.0
// (https://www.gnu.org/licenses/agpl-3.0.txt).
//
// Originally based on godap (github.com/Macmod/godap) — MIT license.

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <fstream>
#include <sstream>
#include <cstring>
#include <getopt.h>

#include "ldap_conn.h"
#include "tui/app.h"
#include "formats.h"
#include "vars.h"
#include "sdl/parse.h"
#include "adidns/types.h"
#include "embedded.hpp"
#include "ldaprc.h"

#ifndef BUILD_NUMBER
#define BUILD_NUMBER 0
#endif
#ifndef BUILD_DATE
#define BUILD_DATE "unknown"
#endif

/// @brief Build the version string from compile-time defines.
static std::string buildVersion() {
    return "DirAtlas v" VERSION "\n"
           "Copyright (c) 2026 Manuel FLURY - AGPL-3.0-or-later\n"
           "Originally based on godap (github.com/Macmod/godap) - MIT license\n"
           "Build #" + std::to_string(BUILD_NUMBER) + " (" BUILD_DATE ")";
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
    /// Domain for GSSAPI/NTLM (older godap compat, prefer -Y GSSAPI)
    std::string domain;
    /// Use Kerberos ticket (deprecated, use -Y GSSAPI instead)
    bool kerberos = false;
    /// Search base DN (default: auto-detected from RootDSE)
    std::string base = "";
    /// LDAP search filter (default: (objectClass=*))
    std::string searchFilter = "(objectClass=*)";
    /// Prefix tree nodes with emoji icons
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
    /// LDAP operation time limit in seconds
    int timelimit = 10;
    /// Skip TLS certificate verification (can also be set via ldaprc TLS_REQCERT)
    bool insecure = false;
    /// StartTLS mode: 0=none, 1=try, 2=require (-Z / -ZZ)
    int starttls = 0;
    /// SOCKS proxy address
    std::string socksProxy;
    /// Alias dereferencing: 0=never, 1=search, 2=find, 3=always
    int deref = 0;
    /// Explicit -x flag (simple auth)
    bool simpleAuth = false;
    /// SASL mechanism (e.g. EXTERNAL, GSSAPI)
    std::string saslMech;
    /// Suppress SASL bind output
    bool saslQuiet = false;
    /// OpenLDAP debug level
    int debug = 0;
    /// Raw -E control specs from CLI
    std::vector<std::string> ctrlSpecs;
    // ---- TLS options filled from ldaprc ----
    std::string tlsCACert;
    std::string tlsCACertDir;
    std::string tlsCert;
    std::string tlsKey;
    int tlsReqCert{-1};
    /// Timestamp display format: "EU", "US", "ISO8601", or Go-style custom
    std::string timeFormat = "EU";
    /// Directory for exported data
    std::string exportDir = "data";
    /// Backend flavor: "msad", "basic", "auto"
    std::string backendFlavor = "msad";
    /// Run in CLI mode (no TUI)
    bool cli = false;
    /// Whether --filter was explicitly set (distinguishes from default)
    bool filterSet = false;
    /// Load schema GUIDs on initialisation
    bool loadSchema = false;
    /// LDAP paging size (default: 800)
    uint32_t pagingSize = 800;
    /// Timezone offset in hours for timestamp display
    int timeOffset = 0;
    /// Attribute sort order: "none", "asc", "desc"
    std::string attrSort = "none";
};

/// @brief Print help text listing all CLI flags, grouped by category.
static void printUsage(const char *prog) {
    std::cerr << buildVersion() << "\n\n"
              << "Usage: " << prog << " -H <ldapuri> [options]\n\n"
              << "Standard LDAP options (see ldap.conf(5) man page):\n"
              << "  -H, --uri <uri>       LDAP URI (ldap:// ldaps:// ldapi://)\n"
              << "  -D, --binddn <dn>     Bind DN\n"
              << "  -w, --password <pw>   Bind password\n"
              << "  -W                    Prompt for password (interactive)\n"
              << "  -y, --passfile <f>    Read password from file\n"
              << "  -b, --base <dn>       Search base DN\n"
              << "  -l, --timelimit <s>   Time limit (default: 10)\n"
              << "  -Z, --starttls        StartTLS (try; -ZZ to require)\n"
              << "  -Y, --mech <mech>     SASL mechanism (e.g. EXTERNAL, GSSAPI)\n"
              << "  -Q, --quiet           SASL quiet mode\n"
              << "  -x                    Simple authentication (default)\n"
              << "  -e, -E, --control [!]ext[=p]  LDAP control (ext or search extension)\n"
              << "  --deref <mode>        Alias deref: never,search,find,always\n\n"
              << "DirAtlas-specific:\n"
              << "  --filter <f>          Search filter (default: (objectClass=*))\n"
              << "  --socks <p>           SOCKS proxy\n"
              << "  --deleted             Include deleted objects\n"
              << "  --paging <n>          Paging size (default: 800)\n"
              << "  --emojis              Prefix tree nodes with emojis\n"
              << "  --colors              Colorize output\n"
              << "  --format              Format attribute values\n"
              << "  --expand              Expand multi-value attributes\n"
              << "  --limit <n>           Attribute value limit (default: 20)\n"
              << "  --attrsort <m>        Sort attrs: none, asc, desc\n"
              << "  --timefmt <f>         Time format (EU, US, ISO8601, or custom)\n"
              << "  --offset <h>          Time offset in hours for timestamps\n"
              << "  --exportdir <d>       Export directory (default: data)\n"
              << "  --cache               Cache entries (future use)\n"
              << "  --debug               Enable debug output\n"
              << "  --cli                 CLI mode (no TUI)\n\n"
              << "Config: /etc/ldap/ldap.conf, ~/.ldaprc, ./.ldaprc\n"
              << "  See ldap.conf(5) for all options. Set LDAPNOINT=1 to skip.\n\n"
              << "Subcommands:\n"
              << "  version               Print version and build info\n"
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

/// @brief Print version and build info then exit.
static void printVersion() {
    std::cout << buildVersion() << std::endl;
}

/// @brief Print full documentation text (ASCII art) then exit.
static void printDocumentation() {
    std::cout << R"RAW(╔══════════════════════════════════════════════════════════════╗
║                     DirAtlas v)RAW" << VERSION << R"RAW(                         ║
║              LDAP Directory Explorer (C++ port)              ║
╚══════════════════════════════════════════════════════════════╝

Copyright (c) 2025 Manuel FLURY – AGPL-3.0-or-later
Originally based on godap (github.com/Macmod/godap) – MIT license

───────────────────────────────────────────────────────────────
MODULES

  src/main.cpp          CLI parsing, LDAP session, TUI launch
  src/ldap_conn.*       OpenLDAP libldap wrapper
  src/formats.*         LDAP attribute formatting (SID, GUID,
                        timestamps, UAC, durations, enums)
  src/vars.*            Constants, maps, emoji, predefined queries
  src/formats/time_format.*  Human-readable time distance
  src/adidns/*          AD-integrated DNS record types & parsing
  src/sdl/*             Security Descriptor Library (DACL/ACE)
  src/tui/*             ncurses TUI: tree, attrs panel, search

───────────────────────────────────────────────────────────────
FLAGS (ldapsearch-compatible)

  Connection:
    -H <uri>         LDAP URI (ldap:// ldaps:// ldapi://)
    -Z               StartTLS (try; -ZZ to require)
    -I, --insecure   Skip TLS verification
    -l <sec>         Time limit (default: 10)
    --deref <mode>   Alias deref: never,search,find,always
    --socks <proxy>  SOCKS proxy

  Authentication:
    -D <binddn>      Bind DN
    -w <password>    Bind password
    -W               Prompt for password (interactive)
    -y <file>        Read password from file
    --hash <hash>    NTLM hash
    --kerberos       Use Kerberos ticket (KRB5CCNAME)
    --crt / --key    Certificate pair (PEM)
    --pfx            PKCS#12 file

  Search / Display:
    -b <base>        Search base DN
    --filter <f>     Filter (default: (objectClass=*))
    --backend <f>    Backend: msad, basic, auto
    --deleted        Include deleted objects
    --paging <n>     Paging size (default: 800)
    --schema         Load schema on init
    --emojis         Prefix tree nodes with emojis
    --colors / --format / --expand
    --limit <n> / --attrsort / --timefmt / --offset
    --cache / --exportdir <dir>
    --cli            CLI mode (no TUI)

───────────────────────────────────────────────────────────────
KEYBOARD

  Tab / Shift+Tab   Rotate focus (Tree <-> Attrs <-> Filter)
  ↑ ↓              Navigate tree / scroll attributes
  → / +            Expand tree node
  ← / -            Collapse tree node
  Enter            Select node (load attrs) / expand collapse
  /                Tree: focus filter bar with search base
                   Attrs: enter search-in-value mode
  PgUp / PgDn      Jump 10 lines
  r                Refresh subtree
  Esc              Cancel background operation
  q                Quit

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

  • RootDSE (empty DN) as root
  • All namingContexts + configContext + monitorContext +
    subschemaSubentry listed as children
  • Each context verified accessible before appearing
  • Filter (/ to focus bar): search results shown as virtual
    children, replaced on next search

───────────────────────────────────────────────────────────────
EMOJIS

  👤 user    👥 group    💻 computer    📂 OU    📁 container
  🌐 domain  🔗 domainDNS  ⚙️ GPO/config
  📊 monitor sections  🔌 Connections  🧵 Threads  🕐 Time  …
  📖 subschema  🗄️ Database  🏗️ Backend

───────────────────────────────────────────────────────────────
PORT NOTES

  Original: godap (github.com/Macmod/godap) – 30+ Go files
  This C++ port retains the same architecture:
    formats  →  C++ port (SID/GUID/UAC/timestamp formatting)
    adidns   →  C++ port (DNS_RPC record binary parsing)
    sdl      →  C++ port (security descriptor binary parsing)
    ldap_conn → OpenLDAP libldap (was go-ldap)
    tui       → ncurses (was tcell/tview)

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
  --filter '(uid=john)'                                                      # add search filter
  --deleted                                                                  # include tombstone entries
  --paging 500                                                               # paging size
  --deref search                                                             # alias dereferencing

  # Controls (ldapsearch: -e general, -E search extension)
  -e manageDSAit                                                             # manage DSA IT
  -e sessiontracking=myapp                                                   # session tracking
  -E !pr=100/noprompt                                                        # paged results, critical
  -E sss=uid                                                                 # server-side sort
  -E subentries=true                                                         # include subentries

  # Timeouts & limitations
  -l 30                                                                      # time limit 30s
  -H ldap://server:389 -l 5 -b 'dc=example,dc=com'                          # time limit 5s

  # LDAP config file (ldap.conf / .ldaprc)
  # Set LDAPNOINIT=1 to skip all config files
  # See ldap.conf(5) for TLS_CACERT, TLS_REQCERT, SASL_MECH, BASE, URI, …

  # SOCKS proxy
  --socks socks5://127.0.0.1:1080                                            # tunnel via SSH -D 1080
  -H ldap://internal-server:389 -D 'cn=admin,dc=…' -w secret

  # Display options
  --colors --emojis --format --expand                                        # all default ON
  --limit 50                                                                 # max values per attribute
  --attrsort asc                                                             # sort attributes A-Z
  --timefmt ISO8601                                                          # ISO dates
  --offset 2                                                                 # UTC+2h for timestamps

  # Misc
  --debug                                                                    # OpenLDAP debug output
  --cli                                                                      # CLI mode (no TUI)
  version                                                                   # show version
  doc                                                                       # show this help
  license                                                                   # show AGPL-3.0 license
  -h, --help                                                                # option reference

For option reference: diratlas --help
)RAW" << std::endl;
}

int main(int argc, char **argv) {
    Config cfg;                          ///< Aggregate of all CLI + rc configuration

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
        {"starttls",   no_argument,       nullptr, 'Z'},
        {"mech",       required_argument, nullptr, 'Y'},
        {"quiet",      no_argument,       nullptr, 'Q'},
        {"control",    required_argument, nullptr, 'E'},
        {"cli",        no_argument,       nullptr, 0},
        {"doc",        no_argument,       nullptr, 0},
        {"debug",      no_argument,       nullptr, 0},
        {"deref",      required_argument, nullptr, 0},
        {"socks",      required_argument, nullptr, 0},
        {"filter",     required_argument, nullptr, 0},
        {"deleted",    no_argument,       nullptr, 0},
        {"paging",     required_argument, nullptr, 0},
        {"emojis",     no_argument,       nullptr, 0},
        {"colors",     no_argument,       nullptr, 0},
        {"format",     no_argument,       nullptr, 0},
        {"expand",     no_argument,       nullptr, 0},
        {"limit",      required_argument, nullptr, 0},
        {"cache",      no_argument,       nullptr, 0},
        {"attrsort",   required_argument, nullptr, 0},
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

    while ((opt = getopt_long(argc, argv, "H:D:w:Wy:b:l:ZhY:QE:e:x", long_options, &option_index)) != -1) {
        (void)opt;
        switch (opt) {
            case 0: {
                std::string name = long_options[option_index].name;
                if (name == "cli") cfg.cli = true;
                else if (name == "debug") cfg.debug = 1;
                else if (name == "doc") { printDocumentation(); return 0; }
                else if (name == "filter") { cfg.searchFilter = optarg; cfg.filterSet = true; }
                else if (name == "deleted") cfg.deleted = true;
                else if (name == "cache") cfg.cache = true;
                else if (name == "schema") cfg.loadSchema = true;
                else if (name == "emojis") cfg.emojis = true;
                else if (name == "colors") cfg.colors = true;
                else if (name == "format") cfg.format = true;
                else if (name == "expand") cfg.expand = true;
                else if (name == "limit") cfg.attrLimit = std::stoi(optarg);
                else if (name == "paging") cfg.pagingSize = std::stoul(optarg);
                else if (name == "attrsort") cfg.attrSort = optarg;
                else if (name == "timefmt") cfg.timeFormat = optarg;
                else if (name == "offset") cfg.timeOffset = std::stoi(optarg);
                else if (name == "exportdir") cfg.exportDir = optarg;
                else if (name == "socks") cfg.socksProxy = optarg;
                else if (name == "deref") {
                    std::string m = optarg;
                    if (m == "never") cfg.deref = 0;
                    else if (m == "search") cfg.deref = 1;
                    else if (m == "find") cfg.deref = 2;
                    else if (m == "always") cfg.deref = 3;
                }
                break;
            }
            case 'H': cfg.ldapUri = optarg; break;
            case 'Y': cfg.saslMech = optarg; break;
            case 'Q': cfg.saslQuiet = true; break;
            case 'x': cfg.simpleAuth = true; cfg.saslMech.clear(); break;
            case 'E': case 'e': cfg.ctrlSpecs.push_back(optarg); break;
            case 'D': cfg.binddn = optarg; break;
            case 'w': cfg.password = optarg; break;
            case 'W': promptPw = true; break;
            case 'y': cfg.passfile = optarg; break;
            case 'b': cfg.base = optarg; break;
            case 'l': cfg.timelimit = std::stoi(optarg); break;
            case 'Z': cfg.starttls = (cfg.starttls < 2) ? cfg.starttls + 1 : 2; break;
            case 'h': printUsage(argv[0]); return 0;
            default: printUsage(argv[0]); return 1;
        }
    }

    // ── Read ldaprc files and merge with CLI config ──
    // CLI values take precedence (rc fields only set if target is empty/default).
    {
        diratlas::LdapRcConfig rc;
        readLdapRc(rc, cfg.debug);
        if (cfg.ldapUri.empty()) cfg.ldapUri = rc.uri;
        if (cfg.base.empty()) cfg.base = rc.base;
        if (cfg.binddn.empty()) cfg.binddn = rc.binddn;
        if (cfg.saslMech.empty() && !cfg.simpleAuth) cfg.saslMech = rc.saslMech;
        else if (cfg.simpleAuth && !rc.saslMech.empty() && cfg.debug)
            std::cerr << "[config] -x overrides SASL_MECH=" << rc.saslMech << " from ldaprc" << std::endl;
        if (cfg.timelimit == 10) cfg.timelimit = rc.timelimit;
        if (cfg.deref == 0) cfg.deref = rc.deref;
        if (!cfg.insecure && rc.tlsReqCert >= 0)
            cfg.tlsReqCert = rc.tlsReqCert;
        if (cfg.tlsCACert.empty()) cfg.tlsCACert = rc.tlsCACert;
        if (cfg.tlsCACertDir.empty()) cfg.tlsCACertDir = rc.tlsCACertDir;
        if (cfg.tlsCert.empty()) cfg.tlsCert = rc.tlsCert;
        if (cfg.tlsKey.empty()) cfg.tlsKey = rc.tlsKey;
    }

    // ── Positional argument as URI fallback ──
    if (cfg.ldapUri.empty()) {
        if (optind < argc) {
            cfg.ldapUri = "ldap://" + std::string(argv[optind]);
        } else {
            std::cerr << "Error: use -H <ldapuri> to specify the LDAP server\n\n";
            printUsage(argv[0]);
            return 1;
        }
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
        else std::cerr << "  auth     = anonymous" << std::endl;
    }

    // ── Parse -E control specs and register with connection ──
    for (const auto &spec : cfg.ctrlSpecs) {
        diratlas::LDAPConn::LdapControl ctrl;
        bool ok = diratlas::LDAPConn::parseControlSpec(spec, ctrl.oid, ctrl.critical, ctrl.value);
        if (ok)
            conn.addControl(ctrl);
        else
            std::cerr << "Warning: unknown control spec: " << spec << std::endl;
    }

    // ── Connect to LDAP server ──
    std::cout << "Connecting to " << cfg.ldapUri << "..." << std::endl;
    if (!conn.connect(cfg.ldapUri, cfg.insecure, cfg.socksProxy)) {
        std::cerr << "Failed to connect to LDAP server" << std::endl;
        return 1;
    }

    // ── Detect backend flavour (auto / basic / msad) ──
    if (cfg.backendFlavor == "auto") conn.guessFlavor();
    else if (cfg.backendFlavor == "basic") conn.flavor = diratlas::LDAPFlavor::BasicLDAP;
    else conn.flavor = diratlas::LDAPFlavor::MicrosoftAD;

    // ── StartTLS negotiation (try or require) ──
    if (cfg.starttls > 0) {
        bool ok = conn.startTLS();
        if (!ok && cfg.starttls == 2) {
            std::cerr << "StartTLS required (-ZZ) but failed: " << conn.getLastError() << std::endl;
            return 1;
        }
        if (ok) {
            std::cout << "StartTLS established" << std::endl;
        } else {
            std::cout << "StartTLS not available (proceeding without TLS)" << std::endl;
        }
    }

    // ── Authenticate: SASL (-Y) / simple bind / anonymous ──
    if (!cfg.saslMech.empty()) {
        if (!conn.saslBind(cfg.saslMech)) {
            std::cerr << "SASL bind (" << cfg.saslMech << ") failed: "
                      << conn.getLastError() << std::endl;
            return 1;
        }
        if (!cfg.saslQuiet)
            std::cout << "SASL bind (" << cfg.saslMech << ") successful" << std::endl;
    } else if (!cfg.binddn.empty() || !cfg.password.empty()) {
        std::string bindUser = cfg.binddn;
        if (!cfg.binddn.empty() && !cfg.domain.empty() &&
            cfg.binddn.find('@') == std::string::npos &&
            cfg.binddn.find(',') == std::string::npos)
            bindUser = cfg.binddn + "@" + cfg.domain;
        if (!conn.simpleBind(bindUser, cfg.password)) {
            std::cerr << "Bind failed: " << conn.getLastError() << std::endl;
            return 1;
        }
        std::cout << "Bind successful" << std::endl;
    } else {
        if (!conn.simpleBind("", "")) {
            std::cerr << "Anonymous bind failed: " << conn.getLastError() << std::endl;
            return 1;
        }
        std::cout << "Anonymous bind successful" << std::endl;
    }

    // ── Auto-detect search base from RootDSE if not supplied ──
    if (cfg.base.empty()) {
        if (!conn.findRootDN(cfg.base)) {
            std::cerr << "Could not find root DN" << std::endl; return 1;
        }
        std::cout << "Root DN: " << cfg.base << std::endl;
    }
    conn.defaultRootDN = cfg.base;

    // ── CLI mode: one-shot query, no TUI ──
    if (cfg.cli) {
        std::vector<diratlas::LDAPEntry> results;
        if (conn.search(cfg.base, LDAP_SCOPE_ONELEVEL, cfg.searchFilter,
                        {"*", "name", "objectClass", "cn", "ou", "dc"}, cfg.deleted, results)) {
            std::cout << "Found " << results.size() << " objects at " << cfg.base << std::endl;
            for (const auto &entry : results) {
                std::string name;
                for (const auto &n : {"name", "cn", "ou", "dc", "uid"}) {
                    auto v = entry.getAttr(n);
                    if (!v.empty()) { name = v; break; }
                }
                if (name.empty()) {
                    auto parts = std::vector<std::string>();
                    std::string s = entry.dn;
                    size_t pos;
                    while ((pos = s.find(',')) != std::string::npos) {
                        parts.push_back(s.substr(0, pos));
                        s.erase(0, pos + 1);
                    }
                    parts.push_back(s);
                    if (!parts.empty()) {
                        auto eqPos = parts[0].find('=');
                        if (eqPos != std::string::npos)
                            name = parts[0].substr(eqPos + 1);
                    }
                }
                std::cout << "  " << name << " (" << entry.dn << ")" << std::endl;
            }
        } else {
            std::cerr << "Query failed" << std::endl; return 1;
        }
        return 0;
    }

    // ── Launch TUI with optional initial filter and base ──
    diratlas::tui::App app;
    std::string tuiFilter = cfg.filterSet ? cfg.searchFilter : "";
    // Build bind identity string
    std::string bindId;
    if (!cfg.saslMech.empty())
        bindId = cfg.saslMech;
    else if (!cfg.binddn.empty())
        bindId = cfg.binddn;
    else if (cfg.kerberos)
        bindId = "GSSAPI";
    else
        bindId = "anonymous";

    if (!app.init(conn, tuiFilter, cfg.base, cfg.ldapUri, bindId)) {
        std::cerr << "Failed to initialize TUI" << std::endl;
        return 1;
    }
    return app.run();
}
