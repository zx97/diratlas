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
#include <array>
#include <random>
#include <string>

namespace diratlas {

// The 9 lines of the banner (top border, 7 letter lines, bottom border),
// stored without colour so any gradient can be applied at render time.
inline constexpr std::array<const char*, 9> BANNER_LINES = {
    "╔═══════════════════════════════════════════════════════════════════╗",
    "║    ██████╗ ██╗██████╗  █████╗ ████████╗██╗      █████╗ ███████╗   ║",
    "║    ██╔══██╗██║██╔══██╗██╔══██╗╚══██╔══╝██║     ██╔══██╗██╔════╝   ║",
    "║    ██║  ██║██║██████╔╝███████║   ██║   ██║     ███████║███████╗   ║",
    "║    ██║  ██║██║██╔══██╗██╔══██║   ██║   ██║     ██╔══██║╚════██║   ║",
    "║    ██████╔╝██║██║  ██║██║  ██║   ██║   ███████╗██║  ██║███████║   ║",
    "║    ╚═════╝ ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚══════╝   ║",
    "║                      LDAP Directory Explorer                      ║",
    "╚═══════════════════════════════════════════════════════════════════╝",
};

// Plain (no ANSI colour) copy of the banner, for terminals that do not
// support colour or when output is redirected.
inline std::string bannerPlain() {
    std::string out;
    for (const auto *line : BANNER_LINES) {
        out += line;
        out += '\n';
    }
    out += '\n';
    return out;
}

// Each colour variant is a 9-element array of 256-colour indexes, one per
// banner line (top border, 7 letter lines, bottom border).
using BannerGradient = std::array<int, 9>;

inline constexpr std::array<BannerGradient, 8> BANNER_GRADIENTS = {{
    // 1. Vert (dégradé d'origine)
    {{34, 46, 40, 40, 34, 28, 22, 28, 34}},
    // 2. Bleu
    {{33, 39, 38, 37, 36, 32, 24, 31, 33}},
    // 3. Cyan / turquoise
    {{37, 45, 43, 43, 37, 31, 23, 37, 37}},
    // 4. Magenta / violet
    {{200, 213, 207, 141, 129, 99, 92, 135, 200}},
    // 5. Orange / ambre
    {{208, 214, 220, 178, 172, 130, 94, 179, 208}},
    // 6. Rouge / rose
    {{196, 203, 209, 174, 167, 124, 88, 161, 196}},
    // 7. Émeraude
    {{35, 42, 48, 43, 37, 29, 23, 36, 35}},
    // 8. Lavande / indigo
    {{111, 117, 123, 69, 63, 57, 56, 104, 111}},
}};

// Build the colour banner using the given gradient index (0-based).
inline std::string bannerColored(size_t idx) {
    const auto &g = BANNER_GRADIENTS[idx % BANNER_GRADIENTS.size()];
    std::string out;
    for (size_t i = 0; i < BANNER_LINES.size(); i++) {
        out += "\033[38;5;";
        out += std::to_string(g[i]);
        out += "m";
        out += BANNER_LINES[i];
        out += "\033[0m\n";
    }
    out += '\n';
    return out;
}

// Select a colour variant at random.
inline std::string bannerRandom() {
    static std::mt19937 rng{std::random_device{}()};
    std::uniform_int_distribution<size_t> dist(0, BANNER_GRADIENTS.size() - 1);
    return bannerColored(dist(rng));
}

} // namespace diratlas