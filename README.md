# DirAtlas

LDAP Directory Explorer — a text-mode LDAP browser with a ncurses TUI.

Copyright (c) 2026 Manuel FLURY — AGPL-3.0-or-later

## Prerequisites

- C++20 compiler (GCC 11+, Clang 14+)
- CMake 3.20+
- OpenLDAP development headers (`ldap.h`, `libldap`, `liblber`)
- ncurses development headers

## Build

```sh
# if openldap-devel is installed system-wide
make clean && make

# if you compiled OpenLDAP yourself
make LDAP_ROOT=/path/to/openldap-prefix

# or with separate include/lib dirs
make LDAP_INCLUDE_DIR=/path/to/include LDAP_LIB_DIR=/path/to/lib
```

The build number is derived from git (commit count + short hash) at configure
time; it falls back to a hostname/date string when git is absent, so a source
copy still builds. Sanitizers can be enabled with `cmake -DSANITIZER=<type> ..`
(`address`, `memory`, `thread`, `undefined`, `leak`).

## Usage

Command-line options are ldapsearch-compatible (short options match
OpenLDAP tools; GNU long options are also accepted):

```sh
./build/diratlas -H ldap://server:389 -D 'cn=admin,dc=example,dc=com' -w secret
./build/diratlas -H ldapi://%2fvar%2frun%2fslapd.sock
./build/diratlas -H ldap://server:11389 -Z -D 'cn=admin,dc=example,dc=com' -W
./build/diratlas -H ldap://server:389 -b 'dc=example,dc=com' -s sub --filter '(uid=john)'
./build/diratlas -H ldap://server:389 -o tls_reqcert=never     # skip TLS verification

./build/diratlas doc          # full embedded documentation
./build/diratlas -V           # version
./build/diratlas --abandon 42      # RFC 4511 abandon msgid 42
./build/diratlas --increment uidNumber=5 -b 'uid=u,dc=example,dc=com'  # RFC 4525
./build/diratlas --capabilities    # RootDSE supportedCapabilities
./build/diratlas --sync-refresh-only -b dc=example,dc=com  # RFC 4533 sync pass
./build/diratlas -Y EXTERNAL -H ldapi://%2fvar%2frun%2fslapd.sock \
    -b 'olcDatabase={1}mdb,cn=config' --acl-check          # analyse ACLs
./build/diratlas -Y EXTERNAL -H ldapi://%2fvar%2frun%2fslapd.sock \
    -b 'olcDatabase={1}mdb,cn=config' --acl-check \
    --acl-user 'gidNumber=1000+uidNumber=1000,cn=peercred,cn=external,cn=auth'
    # slapacl-style evaluation: which rule/clause actually grants this user
./build/diratlas -Y EXTERNAL -H ldapi://%2fvar%2frun%2fslapd.sock \
    -b 'olcDatabase={1}mdb,cn=config' --acl-check --acl-graph
    # also print the rule-relation graph (which rule affects which later rule)
```

See `diratlas --help` or `diratlas doc` for the full option reference.
TUI-only display options (--emojis, --colors, --format, --expand, ...)
are only used in TUI mode and never in `--cli` mode.

## Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│                            main.cpp                                │
│   CLI parsing (getopt_long, ldapsearch-compatible)                 │
│   ldaprc merge (system → user → project, CLI wins)                 │
│   session bootstrap, extended ops, CLI/LDIF or TUI launch          │
└───────────────────────────────┬────────────────────────────────────┘
                                │ LDAPConn
                                ▼
┌────────────────────────────────────────────────────────────────────┐
│                            ldap_conn.*                             │
│   LDAPConn — OpenLDAP libldap wrapper                              │
│   • connect / StartTLS / simple+SASL bind                          │
│   • search (RFC 2696 paging, controls, deleted objects)            │
│   • CRUD (add/modify/replace/delete) and object creation           │
│   • extended ops (RFC 4532 whoami, RFC 3062 passwd-modify,         │
│     RFC 3909 cancel, generic OID)                                  │
│   • flavour auto-detection (MicrosoftAD vs BasicLDAP)              │
│   • LDAPEntry: string + raw-binary attribute storage               │
└───────────────────────────────┬────────────────────────────────────┘
                                │ libldap (ldap.h)
                                ▼
                       ┌─────────────────┐
                       │   LDAP server   │
                       └─────────────────┘

            ┌────────────────────┬─────────────────────┐
            ▼                    ▼                     ▼
   ┌─────────────────┐  ┌──────────────────┐  ┌──────────────────┐
   │   tui/          │  │   ldapcore/      │  │   ad/            │
   │   ncurses UI    │  │   generic LDAP   │  │   AD specifics   │
   │                 │  │   formatting     │  │   (optional)     │
   │ App (event loop,│  │   RFC 4517:      │  │   SID, GUID,     │
   │  worker thread) │  │   GeneralizedTime│  │   UAC/flags,     │
   │ TreeWidget      │  │   durations,     │  │   NT timestamps, │
   │ AttrsWidget     │  │   HEX/binary     │  │   100ns intervals│
   └─────────────────┘  └──────────────────┘  └──────────────────┘
```

### Component responsibilities

| Module | Responsibility |
|--------|----------------|
| `src/main.cpp` | CLI parsing, config merge, connection/session setup, CLI mode, TUI launch |
| `src/ldap_conn.*` | Thin wrapper over OpenLDAP `libldap`; connection, auth, search, CRUD, controls, extended ops |
| `src/ldaprc.*` | Read `/etc/ldap/ldap.conf`, `~/.ldaprc`, `./.ldaprc`; values only fill gaps left by CLI flags |
| `src/vars.*` | Constants, flag maps (UAC, systemFlags, SD control…), emoji map, predefined queries |
| `src/embedded.hpp` | Embedded AGPL-3.0 license and `doc` help text |
| `src/ldapcore/` | Generic LDAP attribute formatting (RFC 4517 syntaxes) + byte helpers; **no AD knowledge** |
| `src/ad/` | Active Directory attribute formatting; only activated when flavour is Microsoft AD |
| `src/tui/` | ncurses interface: `App` (event loop/windows/menus), `TreeWidget` (browser), `AttrsWidget` (attribute panel) |

### Startup flow

```
main()
  │
  ├─ handle subcommands (version / doc / license / help)
  ├─ parse getopt_long → Config
  ├─ readLdapRc() ────────────────► /etc/ldap/ldap.conf, ~/.ldaprc, ./.ldaprc
  ├─ positional URI/filter/attrs (ldapsearch-compatible)
  ├─ resolve time format presets (EU / US / ISO8601 / custom)
  ├─ LDAPConn::connect(uri, socks) ──► ldap_initialize(), protocol v3,
  │                                    TLS opts, timeouts, async off
  ├─ conn.addControlSpec(-e / -E) ──► register controls on the live handle
  ├─ conn.startTLS()                (only with -Z / -ZZ)
  ├─ authenticate:
  │     ├─ SASL  (-Y)              conn.saslBind()
  │     ├─ simple(-D/-w, -W, -y)   conn.simpleBind()
  │     └─ anonymous               conn.simpleBind("", "")
  ├─ extended ops (--whoami, --passwd-modify, --cancel, --extended-op)
  ├─ flavour: conn.guessFlavor()   RootDSE objectClass → MSAD | BasicLDAP
  ├─ base:    conn.findRootDN()    only if -b was not given
  │
  ├─ [ --cli ]  ───────────► search loop (paging) → LDIF output → exit
  └─ [ TUI ]   ────────────► App::init(conn, filter, base, uri, bindId)
                             └─► App::run() event loop
```

### TUI event loop and background threading

LDAP calls that could block (loading a subtree, fetching an entry) never run
on the UI thread. `App` spawns a worker thread per operation and hands
results back through a small pending-update slot, so the ncurses loop stays
responsive (and Esc can cancel a running operation).

```
                    ┌───────────────────────────────┐
                    │        App::run()             │  UI thread
                    └──────────────┬────────────────┘
                                   │ getch()
                                   ▼
                             handleKey(ch)
                                   │
              ┌────────────────────┴─────────────────────┐
              ▼                                          ▼
      expandTreeNode()                           loadSelectedEntry()
      tree_->loadChildren(node)                  conn_->searchOne(dn)
      (subtree browse)                          + getMandatoryAttrs()
              │                                          │
              │        spawn worker thread               │
              ▼                                          ▼
      ┌───────────────────┐                     ┌────────────────────┐
      │ worker_ thread:   │                     │ worker_ thread:    │
      │  loadChildren     │                     │  searchOne +       │
      │  rebuildVisible   │                     │  mandatory attrs   │
      └─────────┬─────────┘                     └─────────┬──────────┘
                │                                        │
                └────────── pendingUpdate_.store(true)   │
                            pendingEntry_ / pendingLog_  │
                                                        ▼
                                        (main loop, next iteration)
                                        attrs_->show(pendingEntry_)
                                                        │
                                                        ▼
                                                  draw()
```

State shared with the worker is `std::atomic` (`loading_`, `cancel_`,
`pendingUpdate_`); the transferred `LDAPEntry` is only touched by the UI
thread, which avoids a data race on `AttrsWidget`.

### Editing (CRUD)

All write operations (add, modify, rename, move, delete) go through the same
worker thread as reads (`App::runWriteOp`) and refresh the tree or the
displayed entry only after the server confirmed the change, so the UI never
blocks and stays consistent with the directory.

```
        handleKey(ch)                 ┌─ worker_ thread ─────────────┐
             │                        │                              │
   ┌─────────┴──────────┐             │  addObject / modifyAttribute │
   │ pendingConfirm_?   │  confirm    │  deleteObject / renameObject │
   │  (y/n/Esc prompt)  │────────────►│  deleteAttributeValue        │
   └─────────┬──────────┘             │                              │
             │ accepted               │  on success:                 │
             ▼                        │    pendingLog_ (ok message)  │
       runWriteOp(op)                 │    pendingRefreshTree_ /     │
             │                        │    pendingReloadEntry_       │
             └───────────────────────►└──────────────────────────────┘
                                                │
                                                ▼
                                  (main loop) tree_->refresh() /
                                  loadSelectedEntry() → draw()
```

Destructive operations (delete entry, delete attribute, rename/move) always
ask for explicit confirmation (`pendingConfirm_`, `[Y]es / [N]o / Esc`) before
the write is scheduled. Multi-valued attribute deletion prompts per value.

Key editing actions (all in the **Edit** menu, `F1..F8` open the menu bar):

| Action | Menu item | Notes |
|--------|-----------|-------|
| Add entry | `Edit ▸ Add entry` | objectClass picker from the server subschema; the form is pre-filled with the inherited MUST attributes |
| Duplicate entry | `Edit ▸ Duplicate entry` (or `p` / `P`) | copies the current entry (objectClass + values, operational attrs dropped) under a new RDN / parent |
| Rename / Move | `Edit ▸ Rename / Move entry` | edit the RDN and/or parent DN — a real `moddn` (`ldap_rename_s`), not an attribute replace |
| Delete entry | `Edit ▸ Delete entry` | confirm prompt |
| Add attribute | `Edit ▸ Add attribute` | name + value prompt; **schema-checked** (see below) |
| Delete attribute | `Edit ▸ Delete attribute` | confirm prompt; per-value prompt for multi-valued |
| Attribute context menu | `F2` on the attributes panel | **dynamic** menu with schema-aware actions (see below) |
| Refresh entry | `F5` | reloads the currently selected entry from the server |

### Attribute context menu (F2)

Pressing `F2` on an attribute row opens a **dynamic** menu whose items are
filtered by the server schema (`attributeTypes` from the subschema):

```
        F2 (attrs panel)
              │
              ▼
        appAttrMenu()
              │
              ├─ Edit value                        (always)
              ├─ Modify attribute options          (if the type has ;options, RFC 4512 §2.5.2)
              ├─ Add value                         (if multi-valued & not NO-USER-MODIFICATION)
              ├─ Duplicate value                   (if multi-valued & a value is selected)
              ├─ Delete value                      (if multi-valued & a value is selected)
              └─ Delete attribute                  (unless NO-USER-MODIFICATION)
```

Actions that the schema does not allow are simply not offered, so a
`SINGLE-VALUE` attribute never shows Add/Duplicate/Delete-value.

### Schema-aware attribute insertion

When adding an attribute (`appAddAttr`), DirAtlas validates it against the
entry's objectClasses before writing:

```
appAddAttr(attr, value)
   │
   ├─ attr == objectClass ?
   │     ├─ class defined in subschema ?  ─ no ─► reject ("not defined in schema")
   │     └─ yes ─► note the new class's inherited MUST not yet present
   │
   └─ other attribute
         └─ in getAllowedAttrs(objectClasses) ?  (MUST ∪ MAY, via SUP chain)
               ─ no ─► reject ("not allowed by objectClass (...)")

getAllowedAttrs = ⋃ for each objectClass: MUST ∪ MAY (walking SUP ancestors)
```

### Attribute options (RFC 4512 §2.5.2)

`cn;lang-en`, `jpegPhoto;binary` and similar **AttributeDescriptions** are
parsed by `ldapcore::attrdesc` (type + options, case-insensitive). Variants
sharing the same base type are **grouped** under it in the panel, and the base
type drives schema/formatting decisions while the full description (with
options) is used for reads and writes. `F2 ▸ Modify attribute options` lets you
rename the type or edit the option list.

### Attribute formatting pipeline

Attribute display is flavour-gated: the `ad` backend is only consulted when
the server was detected as Microsoft Active Directory; plain LDAP servers
fall back to the generic `ldapcore` formatters.

```
LDAPEntry (string + raw binary values)
   │
   ▼
AttrsWidget::show()
   │
   ├─ objectClass  → sorted by schema inheritance depth (loadOCSchema)
   ├─ mandatory    → bold (getMandatoryAttrs via subschema query)
   │
   ▼  for each attribute (lower-cased name)
   │
   ├─ flavour == MicrosoftAD && ad::isAdAttribute(name)?
   │       │ yes
   │       ▼
   │   ad::formatAdAttribute()      ┌─ objectSid/objectGUID → text
   │       │                        ├─ userAccountControl / systemFlags /
   │       │                        │    trustAttributes / pwdProperties /
   │       │                        │    searchFlags → bitmask expansion
   │       │                        ├─ NT timestamps (1601 epoch) → human date
   │       │                        └─ 100ns intervals → human duration
   │       │ no
   │       ▼
   └─ ldapcore::formatAttribute()   ┌─ GeneralizedTime (RFC 4517) → strftime
           │                        ├─ non-printable binary → HEX{...}
           │                        └─ anything else → raw value
           ▼
      AttrRow (raw + display) → ncurses rendering
```

### Module layout

```
src/
├── main.cpp          CLI parsing, config merge, session bootstrap, LDIF output
├── ldap_conn.h/.cpp  LDAPConn (libldap wrapper) + LDAPEntry
├── ldaprc.h/.cpp     ldap.conf / .ldaprc loader (LDAPNOINIT to skip)
├── vars.h/.cpp       constants, flag maps, emoji map, predefined queries
├── embedded.hpp      embedded LICENSE text + `doc` documentation
├── ldapcore/         generic LDAP formatting — no AD knowledge
│   ├── attrs.h/.cpp  GeneralizedTime, timestamps, durations, HEX fallback
│   ├── attrdesc.h/.cpp  AttributeDescription parser (RFC 4512 §2.5.2: type + ;options)
│   ├── bytes.h/.cpp  hex, base64, LE32, printability, safe int parsing,
│   │                 LDIF safe-string check
│   ├── acl.h/.cpp    olcAccess/aci parsing, conflict analysis,
│   │                 slapacl-style evaluation (no LDAP dependency,
│   │                 unit-tested)
│   ├── utf8.h/.cpp   UTF-8 decode, display width, truncate/wrap by columns
│   └── dn.h/.cpp     pure DN helpers (rdnOf, parentOf, braceIdx) — no LDAP
│                     dependency, unit-tested
├── ad/               Active Directory specifics — only used for AD servers
│   ├── format.h/.cpp AD attribute formatting, NT time/interval conversion
│   ├── flags.h/.cpp  UAC, systemFlags, bitmask expansion, RID labels
│   ├── guid.h/.cpp   GUID → text
│   └── sid.h/.cpp    SID → text
├── tui/              ncurses interface
│   ├── tui.h         colour pairs, themes, menus, layout constants
│   ├── app.h/.cpp    App: windows, event loop, worker thread, menus, splitter
│   ├── tree.h/.cpp   TreeWidget/TreeNode: hierarchy browser, search results
│   └── attrs.h/.cpp  AttrsWidget: attribute panel, schema lookup, inline edit
└── tests/            unit tests (ctest): `test_dn`, `test_attrdesc`,
                     `test_bytes`, `test_attrs`, `test_utf8`, `test_acl`
```

### Tests

Pure string helpers live in `src/ldapcore/` with no LDAP dependency so they
can be unit-tested without a server:

```sh
cmake --build build -j
ctest --test-dir build --output-on-failure
```

### Display colours and annotations

- Attribute values are **UTF-8 aware**: multi-byte characters (Cyrillic,
  Greek, emoji) are never split when wrapping or truncating, and a
  non-UTF-8 environment locale falls back to `C.UTF-8`.
- **objectClass** rows (explicit + inherited `(implicit from …)` chain) are
  shown in a dedicated orange.
- **Operational** attribute values are green; recent timestamps (< 1 h) are
  bold green ("light green").
- On the RootDSE, **`supported*`** values carry a short human description
  (e.g. `Paged Results (RFC 2696)`) rendered in yellow so it is clearly an
  annotation, not part of the value.
- When the RootDSE does not expose `namingContexts`, DirAtlas falls back to
  the empty base so the tree still opens; exposed contexts that are not
  readable with the current bind stay visible (marked with ⚠️).
- **ACL values** (`olcAccess`, `aci`, `orclentrylevelaci`): Enter opens a
  popup showing the raw value with semantic syntax colours; the analysis
  reports real problems only — **masked rules** (never reached because an
  earlier rule covers them), **dead clauses**, and **complex targets**
  (`dn.regex`/`filter=`) grouped per target for manual review. Plain
  overlapping rules are normal in slapd.access (first match wins), so they
  are not reported. `s` saves the full report to `diratlas_acl_0001.txt`.
