// banner.hpp
//
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Manuel FLURY
//
// This file is part of DirAtlas — an LDAP Directory Explorer.
//
// Licensed under the GNU Affero General Public License v3.0
// (https://www.gnu.org/licenses/agpl-3.0.txt).
//

#pragma once

namespace diratlas {

// ANSI banner (256-color gradient), embedded so it can be printed in the
// help screen and on exit.  Kept in sync with ansi_banner.utf8.
inline const char* BANNER_TEXT =
    "\033[38;5;34m╔═══════════════════════════════════════════════════════════════════╗\n"
    "\033[38;5;46m║    ██████╗ ██╗██████╗  █████╗ ████████╗██╗      █████╗ ███████╗   ║\033[38;5;34m\n"
    "\033[38;5;40m║    ██╔══██╗██║██╔══██╗██╔══██╗╚══██╔══╝██║     ██╔══██╗██╔════╝   ║\033[38;5;34m\n"
    "\033[38;5;40m║    ██║  ██║██║██████╔╝███████║   ██║   ██║     ███████║███████╗   ║\033[38;5;34m\n"
    "\033[38;5;34m║    ██║  ██║██║██╔══██╗██╔══██║   ██║   ██║     ██╔══██║╚════██║   ║\033[38;5;34m\n"
    "\033[38;5;28m║    ██████╔╝██║██║  ██║██║  ██║   ██║   ███████╗██║  ██║███████║   ║\033[38;5;34m\n"
    "\033[38;5;22m║    ╚═════╝ ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚══════╝   ║\033[38;5;34m\n"
    "\033[38;5;28m║                      LDAP Directory Explorer                      ║\033[38;5;34m\n"
    "\033[38;5;34m╚═══════════════════════════════════════════════════════════════════╝\n"
    "\033[0m\n"
    ;

// Plain (no ANSI colour) copy of the same banner, for terminals that do not
// support colour or when output is redirected.  Kept in sync with the
// colour version above.
inline const char* BANNER_TEXT_PLAIN =
    "╔═══════════════════════════════════════════════════════════════════╗\n"
    "║    ██████╗ ██╗██████╗  █████╗ ████████╗██╗      █████╗ ███████╗   ║\n"
    "║    ██╔══██╗██║██╔══██╗██╔══██╗╚══██╔══╝██║     ██╔══██╗██╔════╝   ║\n"
    "║    ██║  ██║██║██████╔╝███████║   ██║   ██║     ███████║███████╗   ║\n"
    "║    ██║  ██║██║██╔══██╗██╔══██║   ██║   ██║     ██╔══██║╚════██║   ║\n"
    "║    ██████╔╝██║██║  ██║██║  ██║   ██║   ███████╗██║  ██║███████║   ║\n"
    "║    ╚═════╝ ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚══════╝   ║\n"
    "║                      LDAP Directory Explorer                      ║\n"
    "╚═══════════════════════════════════════════════════════════════════╝\n"
    "\n"
    ;

} // namespace diratlas