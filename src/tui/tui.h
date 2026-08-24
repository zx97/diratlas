// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Manuel FLURY
//
// This file is part of DirAtlas — an LDAP Directory Explorer.
//
// Licensed under the GNU Affero General Public License v3.0
// (https://www.gnu.org/licenses/agpl-3.0.txt).
//

#pragma once
#include <ncurses.h>
#include <string>
#include <vector>

namespace diratlas::tui {

enum ColorPair {
    CP_HEADER         = 1,
    CP_HEADER_BG      = 2,
    CP_STATUS_OK      = 3,
    CP_STATUS_WARN    = 4,
    CP_STATUS_ERR     = 5,
    CP_TREE_NORMAL    = 6,
    CP_TREE_DELETED   = 7,
    CP_TREE_DISABLED  = 8,
    CP_ATTR_NAME      = 9,
    CP_ATTR_VALUE     = 10,
    CP_ATTR_OP        = 11,
    CP_ATTR_TIME_NEW  = 12,
    CP_ATTR_TIME_OLD  = 13,
    CP_ATTR_TIME_VERY_OLD = 14,
    CP_INPUT          = 15,
    CP_LOG            = 16,
    CP_SELECTED       = 17,
    CP_TREE_CURSOR    = 18,
    CP_BORDER         = 19,
    CP_HEADER_SEP     = 20,
    CP_MENU           = 21,
    CP_MENU_ACTIVE    = 22,
    CP_MENU_ITEM      = 23,
    CP_ATTR_REPL      = 24,
};

// Color theme: maps each ColorPair to foreground/background.
// Index 0 is unused (ncurses reserves pair 0); pairs 1..CP_ATTR_REPL are used.
struct ColorTheme {
    std::string name;
    int pairs[25][2]; // [colorpair][fg, bg], -1 = default
};

extern const ColorTheme themeDefault;
extern const ColorTheme themeMonochrome;
extern const std::vector<ColorTheme> themes;

constexpr int HEADER_BAR_H = 1;
constexpr int INPUT_BAR_H = 1;
constexpr int STATUS_BAR_H = 1;
constexpr int LOG_BAR_H = 1;
constexpr int BORDER_W = 1;
constexpr int TREE_RATIO = 55;
constexpr int ATTR_RATIO = 45;

// Menu bar items
struct MenuItem {
    std::string label;
    int key;           // F-key or 0
};

struct Menu {
    std::string label;
    std::vector<MenuItem> items;
};

extern const std::vector<Menu> menus;

bool isOperationalAttr(const std::string &name);

} // namespace diratlas::tui
