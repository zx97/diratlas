// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Manuel FLURY
//
// This file is part of DirAtlas — an LDAP Directory Explorer.
//
// Licensed under the GNU Affero General Public License v3.0
// (https://www.gnu.org/licenses/agpl-3.0.txt).
//

#include "app.h"
#include "tree.h"
#include "attrs.h"
#include "../ldapcore/bytes.h"
#include "../ldapcore/dn.h"
#include "../ldapcore/attrdesc.h"
#include "../ldapcore/acl.h"
#include <ncurses.h>
#include <locale.h>
#include <langinfo.h>
#include <cstring>
#include <algorithm>
#include <chrono>
#include <fstream>
#include <sstream>
#include <thread>

namespace diratlas::tui {

// ── Color themes ──────────────────────────────────────────────
const ColorTheme themeDefault = {
    "Default",
    {
        {0, 0},                                 // [0] unused (ncurses pair 0)
        /* CP_HEADER            */ {COLOR_WHITE, COLOR_BLUE},
        /* CP_HEADER_BG         */ {COLOR_BLACK, COLOR_WHITE},
        /* CP_STATUS_OK         */ {COLOR_GREEN,  -1},
        /* CP_STATUS_WARN       */ {COLOR_YELLOW, -1},
        /* CP_STATUS_ERR        */ {COLOR_RED,    -1},
        /* CP_TREE_NORMAL       */ {COLOR_WHITE,  -1},
        /* CP_TREE_DELETED      */ {COLOR_RED,    -1},
        /* CP_TREE_DISABLED     */ {COLOR_YELLOW, -1},
        /* CP_ATTR_NAME         */ {COLOR_CYAN,   -1},
        /* CP_ATTR_VALUE        */ {COLOR_WHITE,  -1},
        /* CP_ATTR_OP           */ {COLOR_GREEN,  -1},
        /* CP_ATTR_TIME_NEW     */ {COLOR_GREEN,  -1},
        /* CP_ATTR_TIME_OLD     */ {COLOR_YELLOW, -1},
        /* CP_ATTR_TIME_VERY_OLD*/ {COLOR_RED,    -1},
        /* CP_INPUT             */ {COLOR_WHITE,  -1},
        /* CP_LOG               */ {COLOR_WHITE,  -1},
        /* CP_SELECTED          */ {COLOR_BLACK,  COLOR_WHITE},
        /* CP_TREE_CURSOR       */ {COLOR_BLACK,  COLOR_WHITE},
        /* CP_BORDER            */ {COLOR_WHITE,  COLOR_BLUE},
        /* CP_HEADER_SEP        */ {COLOR_WHITE,  COLOR_BLUE},
        /* CP_MENU              */ {COLOR_WHITE,  COLOR_BLUE},
        /* CP_MENU_ACTIVE       */ {COLOR_BLACK,  COLOR_WHITE},
        /* CP_MENU_ITEM         */ {COLOR_WHITE,  -1},
        /* CP_ATTR_REPL         */ {COLOR_MAGENTA, -1},
        /* CP_ATTR_OC           */ {208, -1},
    }
};

const ColorTheme themeMonochrome = {
    "Monochrome",
    {
        {0, 0},
        {COLOR_WHITE, -1}, {COLOR_WHITE, -1}, {COLOR_WHITE, -1},
        {COLOR_WHITE, -1}, {COLOR_WHITE, -1},
        {COLOR_WHITE, -1}, {COLOR_WHITE, -1}, {COLOR_WHITE, -1},
        {COLOR_WHITE, -1}, {COLOR_WHITE, -1}, {COLOR_WHITE, -1},
        {COLOR_WHITE, -1}, {COLOR_WHITE, -1}, {COLOR_WHITE, -1},
        {COLOR_WHITE, -1}, {COLOR_WHITE, -1},
        {COLOR_BLACK, COLOR_WHITE}, {COLOR_BLACK, COLOR_WHITE},
        {COLOR_WHITE, -1}, {COLOR_WHITE, -1},
        {COLOR_WHITE, -1}, {COLOR_BLACK, COLOR_WHITE}, {COLOR_WHITE, -1},
        {COLOR_WHITE, -1}, {COLOR_WHITE, -1},
    }
};

const ColorTheme themeHighContrast = {
    "High Contrast",
    {
        {0, 0},
        {COLOR_YELLOW, -1}, {COLOR_WHITE, COLOR_BLUE},
        {COLOR_GREEN,  -1}, {COLOR_YELLOW, -1}, {COLOR_RED,    -1},
        {COLOR_WHITE,  -1}, {COLOR_RED,    -1}, {COLOR_YELLOW, -1},
        {COLOR_CYAN,   -1}, {COLOR_WHITE,  -1}, {COLOR_GREEN,  -1},
        {COLOR_GREEN,  -1}, {COLOR_YELLOW, -1}, {COLOR_RED,    -1},
        {COLOR_WHITE,  -1}, {COLOR_WHITE,  -1},
        {COLOR_BLACK,  COLOR_WHITE},
        {COLOR_BLACK,  COLOR_WHITE},
        {COLOR_YELLOW, -1}, {COLOR_YELLOW, -1},
        {COLOR_YELLOW, -1}, {COLOR_BLACK,  COLOR_WHITE}, {COLOR_WHITE, -1},
        {COLOR_MAGENTA, -1}, {208, -1},
    }
};

const ColorTheme themeLight = {
    "Light",
    {
        {0, 0},
        {COLOR_WHITE, COLOR_BLUE}, {COLOR_BLACK, COLOR_WHITE},
        {COLOR_BLACK, -1}, {COLOR_BLACK, -1}, {COLOR_BLACK, -1},
        {COLOR_BLACK, -1}, {COLOR_RED,   -1}, {COLOR_BLACK, -1},
        {COLOR_BLUE,  -1}, {COLOR_BLACK, -1}, {COLOR_GREEN, -1},
        {COLOR_BLACK, -1}, {COLOR_BLACK, -1}, {COLOR_RED,   -1},
        {COLOR_BLACK, -1}, {COLOR_BLACK, -1},
        {COLOR_BLACK, COLOR_WHITE},
        {COLOR_BLACK, COLOR_WHITE},
        {COLOR_BLACK, -1}, {COLOR_BLACK, -1},
        {COLOR_BLACK, -1}, {COLOR_BLUE,  COLOR_WHITE}, {COLOR_BLACK, -1},
        {COLOR_BLUE,  -1}, {208, -1},
    }
};

const ColorTheme themeSolarized = {
    "Solarized",
    {
        {0, 0},
        {COLOR_CYAN,   -1}, {COLOR_WHITE, COLOR_BLUE},
        {COLOR_GREEN,  -1}, {COLOR_YELLOW, -1}, {COLOR_RED,    -1},
        {COLOR_WHITE,  -1}, {COLOR_RED,    -1}, {COLOR_YELLOW, -1},
        {COLOR_BLUE,   -1}, {COLOR_WHITE,  -1}, {COLOR_GREEN,  -1},
        {COLOR_GREEN,  -1}, {COLOR_YELLOW, -1}, {COLOR_RED,    -1},
        {COLOR_WHITE,  -1}, {COLOR_WHITE,  -1},
        {COLOR_BLACK,  COLOR_WHITE},
        {COLOR_BLACK,  COLOR_WHITE},
        {COLOR_CYAN,   -1}, {COLOR_CYAN,   -1},
        {COLOR_CYAN,   -1}, {COLOR_BLACK,  COLOR_CYAN}, {COLOR_WHITE, -1},
        {COLOR_MAGENTA, -1}, {208, -1},
    }
};

const ColorTheme themeGruvbox = {
    "Gruvbox",
    {
        {0, 0},
        {COLOR_YELLOW, -1}, {COLOR_BLACK, COLOR_WHITE},
        {COLOR_GREEN,  -1}, {COLOR_YELLOW, -1}, {COLOR_RED,    -1},
        {COLOR_WHITE,  -1}, {COLOR_RED,    -1}, {COLOR_YELLOW, -1},
        {COLOR_GREEN,  -1}, {COLOR_WHITE,  -1}, {COLOR_GREEN,  -1},
        {COLOR_GREEN,  -1}, {COLOR_YELLOW, -1}, {COLOR_RED,    -1},
        {COLOR_WHITE,  -1}, {COLOR_WHITE,  -1},
        {COLOR_BLACK,  COLOR_WHITE},
        {COLOR_BLACK,  COLOR_WHITE},
        {COLOR_YELLOW, -1}, {COLOR_YELLOW, -1},
        {COLOR_YELLOW, -1}, {COLOR_BLACK,  COLOR_YELLOW}, {COLOR_WHITE, -1},
        {COLOR_MAGENTA, -1}, {208, -1},
    }
};

const ColorTheme themeLinux = {
    "Linux Console",
    {
        {0, 0},
        {COLOR_WHITE, COLOR_BLUE}, {COLOR_WHITE, COLOR_BLUE},
        {COLOR_GREEN, -1}, {COLOR_YELLOW, -1}, {COLOR_RED, -1},
        {COLOR_WHITE, -1}, {COLOR_RED,  -1}, {COLOR_YELLOW, -1},
        {COLOR_WHITE, -1}, {COLOR_WHITE, -1}, {COLOR_GREEN, -1},
        {COLOR_GREEN, -1}, {COLOR_YELLOW, -1}, {COLOR_RED,   -1},
        {COLOR_WHITE, -1}, {COLOR_WHITE, -1},
        {COLOR_BLACK, COLOR_WHITE},
        {COLOR_BLACK, COLOR_WHITE},
        {COLOR_WHITE, -1}, {COLOR_WHITE, -1},
        {COLOR_WHITE, -1}, {COLOR_BLACK, COLOR_WHITE}, {COLOR_WHITE, -1},
        {COLOR_MAGENTA, -1}, {208, -1},
    }
};

const std::vector<ColorTheme> themes = {
    themeDefault, themeMonochrome, themeHighContrast, themeLight,
    themeSolarized, themeGruvbox, themeLinux
};

// ── Menu bar ──────────────────────────────────────────────────
// Menu action IDs (0 = no action, negative = keyboard shortcut in ASCII, positive = action index)
enum MenuAction {
    M_NONE = 0,
    M_EXPORT_LDIF = 1,
    M_ADD_ENTRY = 2,
    M_DEL_ENTRY = 3,
    M_ADD_ATTR = 4,
    M_DEL_ATTR = 5,
    M_MOVE_ENTRY = 6,
    M_DUPLICATE_ENTRY = 7,
};

const std::vector<Menu> menus = {
    {" File ", {
        {"Export to LDIF",  M_EXPORT_LDIF},
        {"", 0},
        {"Quit",             'q'},
    }},
    {" Edit ", {
        {"Add entry",        M_ADD_ENTRY},
        {"Duplicate entry",  M_DUPLICATE_ENTRY},
        {"Rename / Move entry", M_MOVE_ENTRY},
        {"Delete entry",     M_DEL_ENTRY},
        {"", 0},
        {"Add attribute",    M_ADD_ATTR},
        {"Delete attribute", M_DEL_ATTR},
    }},
    {" Settings ", {
        {"Next theme  F10",  0},
        {"Prev theme  F9",   0},
    }},
};

} // namespace diratlas::tui

namespace diratlas::tui {

App::App() {}

App::~App() {
    cancel_.store(true);
    if (worker_.joinable())
        worker_.join();
    destroyWindows();
    if (stdscr)
        endwin();
}

bool App::initNCurses() {
    setlocale(LC_ALL, "");
    // Fall back to a known UTF-8 locale when the environment locale is
    // invalid or non-UTF-8 (e.g. LANG=UTF-8), so ncursesw renders
    // multi-byte characters (emoji, Cyrillic, Greek) correctly.
    const char *codeset = nl_langinfo(CODESET);
    if (!codeset || (strcmp(codeset, "UTF-8") != 0 && strcmp(codeset, "utf-8") != 0)) {
        if (!setlocale(LC_ALL, "C.UTF-8"))
            setlocale(LC_ALL, "C.utf8");
    }

    initscr();
    if (!stdscr) return false;

    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    curs_set(0);
    timeout(100);
    mousemask(ALL_MOUSE_EVENTS | REPORT_MOUSE_POSITION, nullptr);
    mouseinterval(0);

    if (has_colors()) {
        start_color();
        use_default_colors();
        applyTheme(themes[themeIdx_]);
    }

    return true;
}

void App::createWindows() {
    int rows, cols;
    getmaxyx(stdscr, rows, cols);

    int topY = HEADER_BAR_H;
    int afterHeader = topY + INPUT_BAR_H;
    int middleH = rows - afterHeader - STATUS_BAR_H - LOG_BAR_H;
    if (middleH < 3) middleH = 3;

    int halfW = cols * splitRatio_ / 100;
    int half2W = cols - halfW;
    if (halfW < 5) halfW = 5;
    if (half2W < 5) half2W = 5;

    headerWin_ = newwin(HEADER_BAR_H, cols, 0, 0);
    inputWin_  = newwin(INPUT_BAR_H,  cols, topY, 0);
    treeBox_   = newwin(middleH, halfW, afterHeader, 0);
    attrBox_   = newwin(middleH, half2W, afterHeader, halfW);

    int innerH = middleH - 2;
    int innerW_tree = halfW - 2;
    int innerW_attr = half2W - 2;
    if (innerH < 1) innerH = 1;
    if (innerW_tree < 1) innerW_tree = 1;
    if (innerW_attr < 1) innerW_attr = 1;

    treeWin_ = derwin(treeBox_,  innerH, innerW_tree,  1, 1);
    attrWin_ = derwin(attrBox_,  innerH, innerW_attr,  1, 1);
    // Allow cursor positioning in these windows (for edit mode)
    leaveok(attrWin_, FALSE);
    statusWin_ = newwin(STATUS_BAR_H, cols, afterHeader + middleH, 0);
    logWin_    = newwin(LOG_BAR_H,    cols, afterHeader + middleH + STATUS_BAR_H, 0);
}

void App::destroyWindows() {
    auto del = [](WINDOW *&w) { if (w) { delwin(w); w = nullptr; } };
    del(headerWin_); del(inputWin_); del(treeWin_); del(treeBox_);
    del(attrWin_); del(attrBox_); del(statusWin_); del(logWin_);
    del(menuWin_);
}

bool App::init(LDAPConn &conn, const std::string &initFilter,
               const std::string &initBase,
               const std::string &serverUri,
               const std::string &bindIdentity,
               bool baseExplicit) {
    conn_ = &conn;
    serverUri_ = serverUri;
    bindIdentity_ = bindIdentity;
    baseExplicit_ = baseExplicit;
    if (!initNCurses()) return false;

    tree_ = std::make_unique<TreeWidget>(conn);
    // When no explicit -b was given, start at the RootDSE (empty root) even
    // though conn may have auto-detected a default root DN.
    tree_->loadRoot(baseExplicit ? initBase : "");

    // Auto-fit tree width based on initial content
    int cols = getmaxx(stdscr);
    int maxW = tree_->maxLineWidth() + 4;
    int autoRatio = maxW * 100 / std::max(cols, 1);
    if (autoRatio < 20) autoRatio = 20;
    if (autoRatio > 60) autoRatio = 60;
    splitRatio_ = autoRatio;

    createWindows();

    attrs_ = std::make_unique<AttrsWidget>();
    attrs_->setFlavor(conn_->flavor);
    attrSchema_ = loadAttrSchema(*conn_);
    attrs_->setAttrSchema(&attrSchema_);

    // If a CLI filter was provided, execute search immediately
    if (!initFilter.empty()) {
        filter_ = initFilter;
        std::string base = initBase.empty() ? conn_->defaultRootDN : initBase;
        log_ = "Search: " + filter_ + "  base=" + base;
        tree_->showSearchResults(filter_, base);
        // Load first result's attributes
        if (tree_->selectedDN().empty()) {
            auto first = tree_->currentNode();
            if (first && !first->children.empty())
                first = first->children[0].get();
            if (first) {
                currentDN_ = first->dn;
                LDAPEntry entry = conn_->searchOne(currentDN_, "(objectClass=*)",
                                                     {"*", "+"}, false);
                if (!entry.attributeNames.empty()) {
                    auto objClasses = entry.getAttrs("objectClass");
                    auto mandatory = getMandatoryAttrs(getOCSchema(), objClasses);
                    const auto &ocsi = getOCSchema();
                    attrs_->show(entry, mandatory, &ocsi);
                }
            }
        }
        status_ = "Search results: " + filter_;
        log_ = std::to_string(tree_->visibleCount()) + " results  Tab=switch  q=quit";
        return true;
    }

    // Initial RootDSE load: synchronous so UI is ready immediately
    std::string dn = tree_->selectedDN();
    currentDN_ = dn;
    LDAPEntry entry = conn_->searchOne(dn, "(objectClass=*)", {"*", "+"}, false);
    if (!entry.attributeNames.empty()) {
        auto objClasses = entry.getAttrs("objectClass");
        auto mandatory = getMandatoryAttrs(getOCSchema(), objClasses);
        const auto &ocsi = getOCSchema();
        attrs_->show(entry, mandatory, &ocsi);
    }
    log_ = dn.empty() ? "RootDSE" : dn;

    status_ = "Connected";
    log_ = "Tab=switch  q=quit  Enter=select  +/-=expand  Esc=cancel";
    return true;
}

int App::readKey() {
    int ch = getch();
    if (ch != 27) return ch;

    // Possibly a CSI sequence. Read the following characters with a short
    // timeout so lone Escape still works immediately.
    int c2 = getch();
    if (c2 != '[') {
        if (c2 == ERR) return 27;
        // Not a CSI sequence: return the Escape, and keep c2 buffered.
        ungetch(c2);
        return 27;
    }
    // Some Konsole layouts emit \E[[A (ESC [ [ A) for F1, \E[[B for F2, ...
    int c3 = getch();
    if (c3 == '[') {
        int c4 = getch();
        if (c4 >= 'A' && c4 <= 'L') {
            int f = (c4 - 'A') + 1;   // A->F1 ... L->F12
            if (f >= 1 && f <= 12)
                return KEY_F(f);
        }
        return 27;
    }
    // Gather digits until '~' (CSI F-key form \E[n~).
    int num = 0;
    bool have = false;
    int d = c3;
    for (int i = 0; i < 3; i++) {
        if (d >= '0' && d <= '9') {
            num = num * 10 + (d - '0');
            have = true;
        } else if (d == '~' && have) {
            // Map CSI F-key codes to ncurses KEY_F(n).
            // 11..15,17..21,23,24 -> F1..F12
            int f = -1;
            if (num >= 11 && num <= 15)      f = num - 10;
            else if (num >= 17 && num <= 21) f = num - 11;
            else if (num == 23)              f = 11;
            else if (num == 24)              f = 12;
            if (f >= 1 && f <= 12)
                return KEY_F(f);
            return 27;
        } else {
            return 27;
        }
        d = getch();
    }
    return 27;
}

int App::run() {
    running_ = true;

    while (running_) {
        int ch = readKey();

        if (ch == KEY_RESIZE) {
            destroyWindows();
            createWindows();
            if (tree_) tree_->resize();
            clear();
            refresh();
            draw();
            continue;
        }

        // Mouse events
        if (ch == KEY_MOUSE) {
            MEVENT ev;
            if (getmouse(&ev) == OK) {
                // Tree/attr border is at column `splitPos`. The border windows
                // treeBox_ and attrBox_ share this boundary.
                int splitPos = (COLS * splitRatio_ / 100);
                int borderCol = splitPos - 1; // the border column of treeBox_

                if (ev.bstate & BUTTON1_PRESSED) {
                    // Check if click is near the splitter border (±2 cols)
                    if (ev.x >= borderCol - 2 && ev.x <= borderCol + 2) {
                        draggingSplit_ = true;
                    }
                }
                if (draggingSplit_) {
                    // Snap splitter to current mouse column
                    int newRatio = ev.x * 100 / COLS;
                    if (newRatio < 20) newRatio = 20;
                    if (newRatio > 80) newRatio = 80;
                    if (newRatio != splitRatio_) {
                        splitRatio_ = newRatio;
                        destroyWindows();
                        createWindows();
                        if (tree_) tree_->resize();
                        clear();
                        refresh();
                    }
                    if (ev.bstate & BUTTON1_RELEASED)
                        draggingSplit_ = false;
                }
            }
            continue;
        }

        // Escape: cancel loading, close menus, or exit edit mode
        if (ch == 27) {
            if (loading_.load()) {
                cancel_.store(true);
                setLog("Canceling...");
                continue;
            }
            if (attrs_ && attrs_->editMode_) {
                attrs_->handleKey(27);
                continue;
            }
            if (activeMenu_ >= 0) {
                activeMenu_ = -1;
                activeMenuItem_ = -1;
                touchwin(stdscr);
                continue;
            }
        }

        if (ch != ERR)
            handleKey(ch);

        // Apply pending UI update from worker thread
        if (pendingUpdate_.load()) {
            if (!pendingEntry_.attributeNames.empty())
                attrs_->show(pendingEntry_, pendingMandatory_, &pendingOcInfo_);
            if (!pendingLog_.empty()) log_ = pendingLog_;
            pendingUpdate_.store(false);
            pendingEntry_ = {};
            pendingMandatory_.clear();
            pendingOcInfo_ = OCSchemaInfo{};
            pendingLog_.clear();
        }

        // Post-write refresh requested by a successful worker write.
        if (pendingRefreshTree_.load()) {
            pendingRefreshTree_.store(false);
            if (tree_) tree_->refresh();
        }
        if (pendingReloadEntry_.load()) {
            pendingReloadEntry_.store(false);
            loadSelectedEntry();
        }

        // Reset status when loading finishes
        if (!loading_.load() && status_ != "Connected")
            status_ = "Connected";

        draw();
    }

    return 0;
}

void App::draw() {
    // Update loading indicator in status bar
    if (loading_.load()) {
        status_ = loadingMsg_;
        if (cancel_.load())
            status_ += " [canceling...]";
        else
            status_ += " \u23F3"; // hourglass
    }

    drawMenuBar();
    drawInputBar();

    if (treeBox_) {
        wattron(treeBox_, COLOR_PAIR(CP_BORDER));
        box(treeBox_, 0, 0);
        wattroff(treeBox_, COLOR_PAIR(CP_BORDER));
        mvwaddstr(treeBox_, 0, 2, " Directory Tree ");
        if (focus_ == FOCUS_TREE)
            mvwaddch(treeBox_, 0, 0, '>' | A_BOLD);
    }

    if (attrBox_) {
        wattron(attrBox_, COLOR_PAIR(CP_BORDER));
        box(attrBox_, 0, 0);
        wattroff(attrBox_, COLOR_PAIR(CP_BORDER));
        std::string title = " " + currentDN_ + " ";
        if (currentDN_.empty()) title = " RootDSE ";
        int maxT = getmaxx(attrBox_) - 4;
        if (static_cast<int>(title.size()) > maxT) {
            if (maxT > 10)
                title = ".." + title.substr(title.size() - maxT + 2);
            else
                title = title.substr(0, maxT);
        }
        mvwaddstr(attrBox_, 0, 2, title.c_str());
        if (focus_ == FOCUS_ATTRS)
            mvwaddch(attrBox_, 0, 0, '>' | A_BOLD);
    }

    tree_->draw(treeWin_, focus_ == FOCUS_TREE);
    attrs_->draw(attrWin_, focus_ == FOCUS_ATTRS);
    // Force content window refresh before border refresh (prevents ghost chars)
    wnoutrefresh(treeWin_);
    wnoutrefresh(attrWin_);

    wnoutrefresh(treeBox_);
    wnoutrefresh(attrBox_);

    drawStatusBar();
    drawLogBar();
    wnoutrefresh(headerWin_);
    wnoutrefresh(inputWin_);
    wnoutrefresh(statusWin_);
    wnoutrefresh(logWin_);
    // Show cursor during edit mode (last refresh wins for cursor position)
    if (attrs_ && attrs_->editMode_) {
        curs_set(1);
        // Also disable leaveok on all windows so cursor can move
    } else {
        curs_set(0);
    }
    // Draw dropdown menu last (on top of everything, directly on stdscr)
    if (activeMenu_ >= 0) {
        const auto &menu = menus[activeMenu_];
        int mx = 0;
        for (int i = 0; i < activeMenu_; i++)
            mx += static_cast<int>(menus[i].label.size());
        int my = 1;
        // Size the dropdown to the widest item label so nothing is truncated.
        int mw = static_cast<int>(menu.label.size()) + 4;
        for (const auto &item : menu.items)
            if (!item.label.empty())
                mw = std::max(mw, static_cast<int>(item.label.size()) + 4);
        if (mw > getmaxx(stdscr) - mx - 2)
            mw = getmaxx(stdscr) - mx - 2;
        int items = 0;
        // Count every row (including separators / empty labels) because the
        // draw loop increments dy for empty items too.
        items = static_cast<int>(menu.items.size());
        int mh = items + 2;
        // Clamp to fit screen
        if (my + mh >= LINES) mh = LINES - my - 1;
        if (mh < 3) mh = 3;
        // Background
        wattron(stdscr, COLOR_PAIR(CP_BORDER));
        for (int r = 0; r < mh; r++)
            for (int c = 0; c < mw; c++)
                mvwaddch(stdscr, my + r, mx + c, ' ');
        wattroff(stdscr, COLOR_PAIR(CP_BORDER));
        // Border
        wattron(stdscr, COLOR_PAIR(CP_BORDER) | A_BOLD);
        for (int c = 1; c < mw - 1; c++) {
            mvwaddch(stdscr, my, mx + c, '-');
            mvwaddch(stdscr, my + mh - 1, mx + c, '-');
        }
        for (int r = 1; r < mh - 1; r++) {
            mvwaddch(stdscr, my + r, mx, '|');
            mvwaddch(stdscr, my + r, mx + mw - 1, '|');
        }
        mvwaddch(stdscr, my, mx, '+');
        mvwaddch(stdscr, my, mx + mw - 1, '+');
        mvwaddch(stdscr, my + mh - 1, mx, '+');
        mvwaddch(stdscr, my + mh - 1, mx + mw - 1, '+');
        mvwaddstr(stdscr, my, mx + 2, (" " + menu.label + " ").c_str());
        wattroff(stdscr, COLOR_PAIR(CP_BORDER) | A_BOLD);
        // Items
        int dy = 1;
        for (int it = 0; it < static_cast<int>(menu.items.size()); it++) {
            const auto &item = menu.items[it];
            if (item.label.empty()) { dy++; continue; }
            int cp = (it == activeMenuItem_) ? CP_MENU_ACTIVE : CP_MENU_ITEM;
            wattron(stdscr, COLOR_PAIR(cp) | A_BOLD);
            std::string txt = " " + item.label + " ";
            if (static_cast<int>(txt.size()) > mw - 2)
                txt = txt.substr(0, mw - 5) + "...";
            mvwaddstr(stdscr, my + dy, mx + 1, txt.c_str());
            wattroff(stdscr, COLOR_PAIR(cp) | A_BOLD);
            dy++;
        }
        wnoutrefresh(stdscr);
    }

    // Show a "working" popup while a background operation runs (threshold
    // avoids a flicker on sub-200ms ops but still gives immediate feedback).
    if (loading_.load() &&
        std::chrono::steady_clock::now() - loadingStart_ > std::chrono::milliseconds(200)) {
        int pw = 46, ph = 5;
        int py = (LINES - ph) / 2, px = (COLS - pw) / 2;
        if (py < 0) py = 0;
        if (px < 0) px = 0;
        wattron(stdscr, COLOR_PAIR(CP_STATUS_WARN) | A_BOLD);
        for (int r = 0; r < ph; r++)
            for (int c = 0; c < pw; c++)
                mvwaddch(stdscr, py + r, px + c, ' ');
        wattroff(stdscr, COLOR_PAIR(CP_STATUS_WARN) | A_BOLD);
        wattron(stdscr, COLOR_PAIR(CP_STATUS_WARN) | A_BOLD);
        mvwaddstr(stdscr, py, px + 2, " Operation in progress ");
        mvwaddstr(stdscr, py + 2, px + 2, ("  " + loadingMsg_).substr(0, pw - 4).c_str());
        mvwaddstr(stdscr, py + 3, px + 2, "  (Esc to cancel)");
        wattroff(stdscr, COLOR_PAIR(CP_STATUS_WARN) | A_BOLD);
        wnoutrefresh(stdscr);
    }
    doupdate();
}

void App::applyTheme(const ColorTheme &t) {
    for (int i = 1; i <= CP_ATTR_OC; i++) {
        int fg = t.pairs[i][0];
        int bg = t.pairs[i][1];
        if (fg < 0 && bg < 0)
            init_pair(i, COLOR_WHITE, -1);
        else
            init_pair(i, fg, bg);
    }
}

void App::drawMenuBar() {
    if (!headerWin_) return;
    int maxX = getmaxx(headerWin_);
    werase(headerWin_);

    // Draw menu labels
    int x = 0;
    for (int m = 0; m < static_cast<int>(menus.size()); m++) {
        bool active = (activeMenu_ == m);
        if (active) {
            wattron(headerWin_, COLOR_PAIR(CP_MENU_ACTIVE) | A_BOLD);
        } else {
            wattron(headerWin_, COLOR_PAIR(CP_MENU));
        }
        std::string label = "F" + std::to_string(m + 1) + " " + menus[m].label;
        mvwaddstr(headerWin_, 0, x, label.c_str());
        wattroff(headerWin_, active ? (COLOR_PAIR(CP_MENU_ACTIVE) | A_BOLD)
                                    : COLOR_PAIR(CP_MENU));
        x += static_cast<int>(label.size());
    }

    // (dropdown drawn at end of draw() on stdscr)

    // Theme indicator on the right
    int themeX = maxX - static_cast<int>(themes[themeIdx_].name.size()) - 3;
    if (themeX > x + 5) {
        wattron(headerWin_, COLOR_PAIR(CP_HEADER));
        mvwaddstr(headerWin_, 0, themeX, (" " + themes[themeIdx_].name + " ").c_str());
        wattroff(headerWin_, COLOR_PAIR(CP_HEADER));
    }

    wattroff(headerWin_, COLOR_PAIR(CP_HEADER) | A_BOLD);
}

void App::drawInputBar() {
    if (!inputWin_) return;
    werase(inputWin_);

    bool focused = (focus_ == FOCUS_INPUT);
    wbkgd(inputWin_, focused ? COLOR_PAIR(CP_TREE_CURSOR) : COLOR_PAIR(CP_HEADER_BG));

    std::string label = " Filter: ";
    mvwaddstr(inputWin_, 0, 0, label.c_str());

    std::string display = filter_;
    int maxW = getmaxx(inputWin_) - static_cast<int>(label.size()) - 2;
    if (static_cast<int>(display.size()) > maxW)
        display = display.substr(display.size() - maxW);
    mvwaddstr(inputWin_, 0, static_cast<int>(label.size()), display.c_str());

    if (focused)
        mvwaddch(inputWin_, 0, static_cast<int>(label.size() + display.size()), '_' | A_BLINK);
}

void App::drawStatusBar() {
    if (!statusWin_) return;
    int maxX = getmaxx(statusWin_);
    werase(statusWin_);
    int cp = loading_.load()
        ? (cancel_.load() ? CP_STATUS_ERR : CP_STATUS_WARN)
        : CP_STATUS_OK;
    wattron(statusWin_, COLOR_PAIR(cp));

    // Build status: server URI
    std::string s;
    if (!serverUri_.empty())
        s = serverUri_;
    else if (conn_)
        s = conn_->defaultRootDN.empty() ? "LDAP" : conn_->defaultRootDN;

    // Append detected server type (e.g. "OpenLDAP", "Active Directory", ...)
    if (conn_) {
        const char *type;
        switch (conn_->flavor) {
            case diratlas::LDAPFlavor::MicrosoftAD:   type = "Active Directory"; break;
            case diratlas::LDAPFlavor::NetscapeLDAP:  type = "Netscape/389 DS";   break;
            case diratlas::LDAPFlavor::EDirectoryLDAP:type = "eDirectory";        break;
            case diratlas::LDAPFlavor::IBMLDAP:       type = "IBM Verify Dir";    break;
            default:                                  type = "OpenLDAP";          break;
        }
        s += "  [" + std::string(type) + "]";
    }

    // Append bind identity (DN or SASL mech)
    if (!bindIdentity_.empty()) {
        if (!s.empty()) s += "  |  ";
        s += bindIdentity_;
        if (static_cast<int>(s.size()) > maxX - 3)
            s = s.substr(0, maxX - 6) + "...";
    }

    mvwaddstr(statusWin_, 0, 0, s.c_str());
    wattroff(statusWin_, COLOR_PAIR(cp));
}

void App::drawLogBar() {
    if (!logWin_) return;
    werase(logWin_);
    wattron(logWin_, COLOR_PAIR(CP_LOG));

    std::string hints;
    if (!pendingConfirm_.empty()) {
        hints = "y=confirm  n=cancel  Esc=abort";
    } else if (attrs_ && attrs_->editMode_) {
        hints = "type=edit  Enter=apply  Esc=cancel  Left/Right=move  Home/End";
    } else if (attrs_ && attrs_->searchMode_) {
        hints = "type=search  Enter=done  Esc=cancel";
    } else if (focus_ == FOCUS_TREE) {
        hints = "Up/Dn=move  Enter=open  +/-=expand  g=RootDSE  /=search  y=copy  p=paste  h=help  q=quit";
    } else if (focus_ == FOCUS_ATTRS) {
        hints = "Up/Dn=move  Enter=open  +/-=expand  F2=edit  /=search  h=help  Tab=tree";
    } else if (focus_ == FOCUS_INPUT) {
        hints = "type=filter  Enter=search  Esc=cancel";
    }

    std::string line;
    if (!log_.empty())
        line = log_ + (hints.empty() ? "" : "   " + hints);
    else
        line = hints;
    if (static_cast<int>(line.size()) > getmaxx(logWin_))
        line = line.substr(line.size() - getmaxx(logWin_));

    // Error / warning detection: the message drives the bar colour so a
    // failure stands out instead of blending in with the hints. Errors blink
    // in light red, warnings are steady yellow.
    std::string low = log_;
    for (auto &c : low) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    bool isErr = low.find("rejected") != std::string::npos ||
                 low.find("failed") != std::string::npos ||
                 low.find("cannot") != std::string::npos ||
                 low.find("required") != std::string::npos ||
                 low.find("not allowed") != std::string::npos ||
                 low.find("no actions") != std::string::npos ||
                 low.find("nothing to duplicate") != std::string::npos ||
                 low.find("select an entry first") != std::string::npos ||
                 low.find("position cursor") != std::string::npos ||
                 low.find("no parent") != std::string::npos ||
                 low.find("error") != std::string::npos ||
                 low.find("empty value") != std::string::npos;
    bool isWarn = low.find("warning") != std::string::npos ||
                  low.find("will require") != std::string::npos ||
                  low.find("cancelled") != std::string::npos ||
                  low.find("cancel") != std::string::npos;

    int color = CP_LOG;
    attr_t attr = A_NORMAL;
    if (isErr) {
        color = CP_STATUS_ERR;
        attr = A_BOLD | A_BLINK;
    } else if (isWarn) {
        color = CP_STATUS_WARN;
        attr = A_BOLD;
    }
    wattron(logWin_, COLOR_PAIR(color) | attr);
    mvwaddstr(logWin_, 0, 0, line.c_str());
    wattroff(logWin_, COLOR_PAIR(color) | attr);
}

void App::handleKey(int ch) {
    // Ignore input while a background operation is running (except Escape already handled)
    if (loading_.load()) return;

    // Pending destructive confirmation (delete/rename/delete-attr): y or n
    // short-circuits everything else so no other handler can consume the key.
    if (!pendingConfirm_.empty()) {
        if (ch == 'y' || ch == 'Y' || ch == 'n' || ch == 'N' || ch == 27)
            applyPendingConfirm(static_cast<char>(ch));
        return;
    }

    // (Escape handling moved to event loop above)

    // F9 = previous theme, F10 = next theme (before menu F-key handler)
    if (ch == KEY_F(9)) {
        themeIdx_ = (themeIdx_ == 0) ? static_cast<int>(themes.size()) - 1 : themeIdx_ - 1;
        applyTheme(themes[themeIdx_]);
        return;
    }
    if (ch == KEY_F(10)) {
        themeIdx_ = (themeIdx_ + 1) % static_cast<int>(themes.size());
        applyTheme(themes[themeIdx_]);
        return;
    }

    // F2 in attributes panel: context menu for the attribute under the cursor.
    if (ch == KEY_F(2) && focus_ == FOCUS_ATTRS) {
        appAttrMenu();
        return;
    }

    // F5 = refresh the currently selected entry from the server.
    if (ch == KEY_F(5)) {
        loadSelectedEntry();
        return;
    }

    // F-keys: open menus (F1-F8, F11-F12 only)
    if (ch >= KEY_F(1) && ch <= KEY_F(12)) {
        int idx = ch - KEY_F(1);
        if (idx < static_cast<int>(menus.size())) {
            if (activeMenu_ == idx) {
                // Execute menu item if dropdown is open and item selected
                if (activeMenuItem_ >= 0 &&
                    activeMenuItem_ < static_cast<int>(menus[idx].items.size())) {
                    const auto &item = menus[idx].items[activeMenuItem_];
                    if (item.key == 'q') { running_ = false; }
                    else if (item.key == M_EXPORT_LDIF) { appExportLdif(); }
                    else if (item.key == M_ADD_ENTRY) { appAddEntry(); }
                    else if (item.key == M_DEL_ENTRY) { appDeleteEntry(); }
                    else if (item.key == M_ADD_ATTR) { appAddAttr(); }
                    else if (item.key == M_DEL_ATTR) { appDeleteAttr(); }
                    else if (item.key == M_MOVE_ENTRY) { appMoveEntry(); }
                    else if (item.key == M_DUPLICATE_ENTRY) { appDuplicateEntry(); }
                }
                activeMenu_ = -1;
                activeMenuItem_ = -1;
                touchwin(stdscr);
            } else {
                activeMenu_ = idx;
                activeMenuItem_ = -1;
            }
        }
        return;
    }

    // Navigate dropdown menus with arrows
    if (activeMenu_ >= 0) {
        int n = static_cast<int>(menus[activeMenu_].items.size());
        if (ch == KEY_DOWN) {
            do {
                activeMenuItem_ = (activeMenuItem_ + 1) % n;
            } while (menus[activeMenu_].items[activeMenuItem_].label.empty() && n > 1);
            return;
        }
        if (ch == KEY_UP) {
            do {
                activeMenuItem_ = (activeMenuItem_ <= 0) ? n - 1 : activeMenuItem_ - 1;
            } while (menus[activeMenu_].items[activeMenuItem_].label.empty() && n > 1);
            return;
        }
        if (ch == '\n' || ch == '\r' || ch == KEY_ENTER) {
            if (activeMenuItem_ >= 0 &&
                activeMenuItem_ < static_cast<int>(menus[activeMenu_].items.size())) {
                const auto &item = menus[activeMenu_].items[activeMenuItem_];
                if (item.key == 'q') { running_ = false; }
                else if (item.key == M_EXPORT_LDIF) { appExportLdif(); }
                else if (item.key == M_ADD_ENTRY) { appAddEntry(); }
                else if (item.key == M_DEL_ENTRY) { appDeleteEntry(); }
                else if (item.key == M_ADD_ATTR) { appAddAttr(); }
                else if (item.key == M_DEL_ATTR) { appDeleteAttr(); }
                else if (item.key == M_MOVE_ENTRY) { appMoveEntry(); }
                else if (item.key == M_DUPLICATE_ENTRY) { appDuplicateEntry(); }
            }
            activeMenu_ = -1;
            activeMenuItem_ = -1;
            return;
        }
        return; // consume any key while menu open
    }

    if (ch == '\t') {
        if (focus_ == FOCUS_TREE) focus_ = FOCUS_ATTRS;
        else if (focus_ == FOCUS_ATTRS) focus_ = FOCUS_INPUT;
        else focus_ = FOCUS_TREE;
        return;
    }

    if (ch == KEY_BTAB) {
        if (focus_ == FOCUS_TREE) focus_ = FOCUS_INPUT;
        else if (focus_ == FOCUS_ATTRS) focus_ = FOCUS_TREE;
        else focus_ = FOCUS_ATTRS;
        return;
    }

    if (focus_ == FOCUS_INPUT) {
        if (ch == '\n' || ch == '\r' || ch == KEY_ENTER) {
            if (!filter_.empty()) {
                // If searchBase_ wasn't set via '/', use current tree selection
                if (searchBase_.empty())
                    searchBase_ = tree_ ? tree_->selectedDN() : "";
                log_ = "Filter: " + filter_ + "  base=" + (searchBase_.empty() ? "RootDSE" : searchBase_);
                if (tree_) {
                    tree_->showSearchResults(filter_, searchBase_);
                    int n = tree_->lastResultCount();
                    std::string err = tree_->lastSearchError();
                    if (!err.empty())
                        log_ = "Search error: " + err;
                    else
                        log_ = std::to_string(n) + " results for " + filter_;
                }
                focus_ = FOCUS_TREE;
            } else {
                // Clear filter: restore normal tree
                if (tree_) tree_->clearVirtual();
                searchBase_.clear();
            }
        } else if (ch == 27) { // Escape exits input mode without action
            searchBase_.clear();
            focus_ = FOCUS_TREE;
        } else if (ch == KEY_BACKSPACE || ch == 127 || ch == 8) {
            if (!filter_.empty()) filter_.pop_back();
        } else if (ch >= 32 && ch <= 126) {
            filter_ += static_cast<char>(ch);
        }
        return;
    }

    if (ch == 'q' || ch == 'Q') { running_ = false; return; }

    // h / H / ? : show the keyboard help popup
    if (ch == 'h' || ch == 'H' || ch == '?') { showHelp(); return; }

    // '/' in tree: focus filter bar, set search base to current node
    if (ch == '/' && focus_ == FOCUS_TREE) {
        searchBase_ = tree_->selectedDN();
        focus_ = FOCUS_INPUT;
        filter_.clear();
        log_ = std::string("Search base: ") + (searchBase_.empty() ? "RootDSE" : searchBase_);
        return;
    }

    // '/' in attrs: enter search mode
    if (ch == '/' && focus_ == FOCUS_ATTRS) {
        attrs_->setSearchMode(true);
        return;
    }

    if (focus_ == FOCUS_TREE) {
        // y = yank/copy selected entry DN to clipboard
        if (ch == 'y' || ch == 'Y') {
            std::string dn = tree_->selectedDN();
            if (!dn.empty()) {
                clipboard_ = dn;
                log_ = "Copied entry: " + dn;
            }
            return;
        }
        // p = paste: create copy of clipboard entry under selected parent
        if ((ch == 'p' || ch == 'P') && !clipboard_.empty()) {
            appDuplicateEntry(clipboard_);
            return;
        }
        // g = go to the RootDSE (jump the tree back to the directory root)
        if (ch == 'g' || ch == 'G') {
            tree_->loadRoot("");
            currentDN_ = tree_->selectedDN();
            loadSelectedEntry();
            status_ = "RootDSE";
            log_ = "At RootDSE  (press g to re-root here)";
            return;
        }

        if (ch == '\n' || ch == '\r' || ch == KEY_ENTER) {
            tree_->handleKey(ch);
            if (tree_->selectionConfirmed()) {
                tree_->clearConfirmed();
                loadSelectedEntry();
                // Keep focus on the tree; Tab switches to the attributes panel.
            }
        } else if (ch == KEY_RIGHT || ch == '+') {
            auto *node = tree_->currentNode();
            if (node && node->hasChildren && !node->expanded) {
                if (node->children.empty())
                    expandTreeNode(node);
                else
                    tree_->handleKey(ch);
            }
        } else {
            tree_->handleKey(ch);
        }
    } else if (focus_ == FOCUS_ATTRS) {
        // 'y'/'Y' while CONFIRM is shown → apply pending edit FIRST
        if ((ch == 'y' || ch == 'Y') && !pendingEditAttr_.empty()) {
            if (!currentDN_.empty()) {
                std::string dn = currentDN_;
                std::string attr = pendingEditAttr_;
                std::string oldV = pendingEditOld_;
                std::string newV = pendingEditNew_;
                // Validate the edited value against the attribute syntax
                // before sending it; unknown syntaxes are skipped.
                if (attrSchema_.defs.empty())
                    attrSchema_ = loadAttrSchema(*conn_);
                std::string attrLower;
                for (char c : attr)
                    attrLower += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                std::string editErr = attrSchema_.validateValue(attrLower, newV);
                if (!editErr.empty()) {
                    setLog("Edit rejected: '" + newV.substr(0, 60) + "' — " + editErr);
                    pendingEditAttr_.clear();
                    pendingEditNew_.clear();
                    pendingEditOld_.clear();
                    return;
                }
                auto allVals = attrs_->getAttrValues(attr);
                bool braced = !allVals.empty();
                for (const auto &v : allVals)
                    if (v.empty() || v[0] != '{') { braced = false; break; }
                if (braced) {
                    // Brace-numbered values are order-sensitive ({0},{1},...):
                    // rebuild the full list with the edited value replaced and
                    // send one LDAP_MOD_REPLACE so {N} ordering is preserved.
                    for (auto &v : allVals)
                        if (v == oldV) { v = newV; break; }
                    std::stable_sort(allVals.begin(), allVals.end(),
                        [](const std::string &a, const std::string &b) {
                            return ldapcore::braceIdx(a) < ldapcore::braceIdx(b);
                        });
                    runWriteOp([this, dn, attr, allVals]() {
                                   return conn_->modifyAttribute(dn, attr, allVals);
                               },
                               "Applied: " + attr + " = " + newV, "Modify failed",
                               false, true);
                } else {
                    // Ordinary attribute: atomically swap just the edited value,
                    // leaving all other values untouched (no full REPLACE).
                    runWriteOp([this, dn, attr, oldV, newV]() {
                                   return conn_->replaceAttributeValue(dn, attr, oldV, newV);
                               },
                               "Applied: " + attr + " = " + newV, "Modify failed",
                               false, true);
                }
            }
            pendingEditAttr_.clear();
            pendingEditNew_.clear();
            pendingEditOld_.clear();
            return;
        }
        // y = yank/copy selected value to clipboard
        if (ch == 'y' || ch == 'Y') {
            int sr = attrs_->selectedRow();
            if (sr >= 0 && sr < attrs_->rowCount()) {
                clipboard_ = attrs_->getValue(sr);
                log_ = "Copied: " + clipboard_.substr(0, 60);
            }
            return;
        }
        // p = paste clipboard over selected value (enters edit mode)
        if ((ch == 'p' || ch == 'P') && !clipboard_.empty()) {
            int sr = attrs_->selectedRow();
            if (sr >= 0 && sr < attrs_->rowCount()) {
                attrs_->editMode_ = true;
                attrs_->editRow_ = sr;
                attrs_->editOrig_ = attrs_->getValue(sr);
                attrs_->editStr_ = clipboard_;
                attrs_->editPos_ = static_cast<int>(clipboard_.size());
                log_ = "Pasted: " + clipboard_.substr(0, 60);
            }
            return;
        }
        attrs_->handleKey(ch);
        // Check for edit confirmation from attrs
        if (attrs_->goToDN_.find("CONFIRM:") == 0) {
            std::string conf = attrs_->goToDN_;
            attrs_->goToDN_.clear();
            auto p1 = conf.find(':');
            auto p2 = conf.find('|', p1 + 1);
            auto p3 = conf.find('|', p2 + 1);
            if (p1 != std::string::npos && p2 != std::string::npos && p3 != std::string::npos) {
                std::string newVal = conf.substr(p1 + 1, p2 - p1 - 1);
                std::string oldVal = conf.substr(p2 + 1, p3 - p2 - 1);
                std::string attrName = conf.substr(p3 + 1);
                if (newVal != oldVal && !currentDN_.empty()) {
                    // Check if this is an RDN attribute (cn, ou, uid, dc) — warn about rename
                    bool isRDN = (attrName == "cn" || attrName == "ou" ||
                                  attrName == "uid" || attrName == "dc");
                    if (isRDN) {
                        // Renaming an RDN attribute is a server-side ModifyDN
                        // operation (RFC 4511), not a plain attribute edit.
                        std::string newRdn = attrName + "=" + newVal;
                        log_ = "RENAME: " + attrName + " will rename the entry! "
                               "'" + oldVal + "' → '" + newVal + "'. Y to confirm, N to cancel.";
                        pendingConfirm_ = "rename:" + currentDN_ + "|" + newRdn;
                    } else {
                        log_ = "MODIFY: " + attrName + " '" + oldVal + "' → '" + newVal
                               + "'. Y to confirm, N to cancel.";
                        // Store pending modification
                        pendingEditAttr_ = attrName;
                        pendingEditNew_ = newVal;
                        pendingEditOld_ = oldVal;
                    }
                } else {
                    log_ = "No change";
                }
            }
        }
        // Check if a DN was selected for navigation

        if (attrs_->goToDN_.find("ACLVIEW:") == 0) {
            std::string attr = attrs_->goToDN_.substr(8);
            attrs_->goToDN_.clear();
            // Merged view: every ACL attribute of the entry (orclaci +
            // orclentrylevelaci + aci + olcAccess ...) is analysed together,
            // because Oracle evaluates entry-level and prescriptive rules
            // additively — a single attribute would hide inter-attribute
            // conflicts. Each rule keeps its origin attribute.
            auto pairs = attrs_->getAclValuesMerged();
            std::vector<std::string> vals;
            std::vector<std::string> origins;
            for (const auto &[an, v] : pairs) {
                vals.push_back(v);
                origins.push_back(an);
            }
            if (vals.empty()) { setLog("No ACL values on " + currentDN_); return; }
            auto rules = diratlas::ldapcore::parseAclValues(vals);
            auto conflicts = diratlas::ldapcore::analyzeAclConflicts(rules);
            // The popup shows the raw ACL values with syntax colours, one
            // "by" clause per indented line (never wrapped mid-rule); the
            // full interpreted report is saved to a file with 's'.
            std::string content;
            for (size_t v = 0; v < vals.size(); ++v) {
                if (v) content += "\n";
                // Prefix with the origin attribute so the source is visible.
                content += "[" + origins[v] + "] ";
                auto fl = diratlas::ldapcore::formatAclValueLines(vals[v]);
                if (fl.empty()) { content += vals[v]; continue; }
                for (size_t k = 0; k < fl.size(); ++k) {
                    if (k) content += "\n";
                    content += fl[k];
                }
            }
            std::string report = diratlas::ldapcore::buildAclReport(rules, conflicts, true);
            if (!rules.empty()) {
                std::vector<std::string> users;
                if (!bindIdentity_.empty()) users.push_back(bindIdentity_);
                users.push_back("");  // anonymous
                for (const auto &u : users) {
                    std::string label = u.empty() ? "anonymous" : u;
                    report += "\nEvaluation (slapacl-style) for " + label + ":\n";
                    report += "  to " + currentDN_ + " (entry): " +
                              diratlas::ldapcore::evaluateAcl(rules, u, currentDN_, "entry") + "\n";
                    report += "  to attrs=userPassword: " +
                              diratlas::ldapcore::evaluateAcl(rules, u, currentDN_, "userPassword") + "\n";
                    report += "  to attrs=*: " +
                              diratlas::ldapcore::evaluateAcl(rules, u, currentDN_, "*") + "\n";
                }
            }
            std::string title = "ACL " + attr;
            if (origins.size() > 1) title = "ACL (merged: " + origins[0] + " +" +
                                           std::to_string(origins.size() - 1) + ")";
            showValuePopup(title, content, "", currentDN_, report, true);
        } else if (attrs_->goToDN_.find("VIEWFULL:") == 0) {
            std::string rest = attrs_->goToDN_.substr(9);
            attrs_->goToDN_.clear();
            auto sep = rest.find('|');
            std::string attr = (sep == std::string::npos) ? "" : rest.substr(0, sep);
            std::string content = (sep == std::string::npos) ? rest : rest.substr(sep + 1);
            showValuePopup("Full value", content, "", currentDN_);
        } else if (attrs_->goToDN_.find("VIEWB64:") == 0) {
            std::string rest = attrs_->goToDN_.substr(8);
            attrs_->goToDN_.clear();
            auto sep = rest.find('|');
            std::string attr = (sep == std::string::npos) ? "" : rest.substr(0, sep);
            std::string content = (sep == std::string::npos) ? rest : rest.substr(sep + 1);
            showValuePopup("Decoded value", content, attr, currentDN_);
        } else if (!attrs_->goToDN_.empty() && attrs_->goToDN_ != "APPLY_EDIT" && attrs_->goToDN_.find("CONFIRM:") != 0) {
            std::string targetDN = attrs_->goToDN_;
            attrs_->goToDN_.clear();
            // Try to load the DN entry
            loadingMsg_ = "Loading " + targetDN;
            LDAPEntry entry = conn_->searchOne(targetDN, "(objectClass=*)",
                                                 {"*", "+"}, false);
            if (!entry.attributeNames.empty()) {
                auto objClasses = entry.getAttrs("objectClass");
                auto mandatory = getMandatoryAttrs(getOCSchema(), objClasses);
                const auto &ocsi = getOCSchema();
                attrs_->show(entry, mandatory, &ocsi);
                currentDN_ = targetDN;
                log_ = targetDN;
            } else {
                log_ = "Entry not found: " + targetDN;
            }
        }
    }
}

void App::expandTreeNode(void *nodePtr) {
    auto *node = static_cast<TreeNode*>(nodePtr);
    if (!node) return;

    cancel_.store(false);
    loading_.store(true);
    loadingStart_ = std::chrono::steady_clock::now();
    loadingMsg_ = "Loading " + node->name;

    // Wait for worker thread to finish or be canceled
    if (worker_.joinable())
        worker_.join();

    worker_ = std::thread([this, node]() {
        try {
            tree_->loadChildren(node);
            if (!cancel_.load()) {
                std::string err = tree_->lastChildError();
                // Always expand the node, even on partial errors (size limit, etc.)
                node->expanded = true;
                tree_->rebuildVisible();
                tree_->ensureVisible();
                if (!err.empty()) {
                    int cnt = static_cast<int>(node->children.size());
                    pendingLog_ = "Partial (" + std::to_string(cnt) + " entries): " + err;
                }
                pendingUpdate_.store(true);
            }
        } catch (...) {
            // ignore
        }
        loading_.store(false);
    });
}

const OCSchemaInfo &App::getOCSchema() {
    if (!ocSchemaLoaded_) {
        ocSchema_ = loadOCSchema(*conn_);
        ocSchemaLoaded_ = true;
    }
    return ocSchema_;
}

void App::loadSelectedEntry() {
    if (!tree_) return;
    std::string dn = tree_->selectedDN();
    currentDN_ = dn;

    cancel_.store(false);
    loading_.store(true);
    loadingStart_ = std::chrono::steady_clock::now();
    loadingMsg_ = dn.empty() ? "Loading RootDSE" : "Loading " + dn;

    if (worker_.joinable())
        worker_.join();

    worker_ = std::thread([this, dn]() {
        try {
            LDAPEntry entry = conn_->searchOne(dn, "(objectClass=*)", {"*", "+"}, false);
            if (!cancel_.load()) {
                if (!entry.attributeNames.empty()) {
                    auto objClasses = entry.getAttrs("objectClass");
                    pendingMandatory_ = getMandatoryAttrs(getOCSchema(), objClasses);
                    pendingOcInfo_ = getOCSchema();
                    pendingEntry_ = std::move(entry);
                    pendingLog_ = dn.empty() ? "RootDSE" : dn;
                } else {
                    pendingLog_ = "Failed to load: " + (dn.empty() ? "RootDSE" : dn);
                }
                pendingUpdate_.store(true);
            }
        } catch (...) {
            pendingLog_ = "Error loading: " + (dn.empty() ? "RootDSE" : dn);
            pendingUpdate_.store(true);
        }
        loading_.store(false);
    });
}

void App::setStatus(const std::string &msg) { status_ = msg; }
void App::setLog(const std::string &msg) { log_ = msg; }

} // namespace diratlas::tui

namespace diratlas::tui {

int App::appPickList(const std::string &title, const std::vector<std::string> &items,
                     int &sel) {
    if (items.empty()) return 0;
    timeout(-1);  // blocking input for the popup

    const int maxRows = 14;
    int rows = std::min(maxRows, static_cast<int>(items.size())) + 3;
    int cols = 60;
    int sy = (LINES - rows) / 2;
    int sx = (COLS - cols) / 2;
    if (sy < 0) sy = 0;
    if (sx < 0) sx = 0;

    int top = 0;
    if (sel < 0) sel = 0;
    if (sel >= static_cast<int>(items.size())) sel = static_cast<int>(items.size()) - 1;

    while (true) {
        if (sel < top) top = sel;
        if (sel >= top + maxRows) top = sel - maxRows + 1;

        // Draw popup background and border
        wattron(stdscr, COLOR_PAIR(CP_BORDER) | A_BOLD);
        for (int r = 0; r < rows; r++)
            for (int c = 0; c < cols; c++)
                mvwaddch(stdscr, sy + r, sx + c, ' ');
        wattroff(stdscr, COLOR_PAIR(CP_BORDER) | A_BOLD);
        for (int c = 1; c < cols - 1; c++) {
            mvwaddch(stdscr, sy, sx + c, '-');
            mvwaddch(stdscr, sy + rows - 1, sx + c, '-');
        }
        for (int r = 1; r < rows - 1; r++) {
            mvwaddch(stdscr, sy + r, sx, '|');
            mvwaddch(stdscr, sy + r, sx + cols - 1, '|');
        }
        mvwaddch(stdscr, sy, sx, '+'); mvwaddch(stdscr, sy, sx + cols - 1, '+');
        mvwaddch(stdscr, sy + rows - 1, sx, '+'); mvwaddch(stdscr, sy + rows - 1, sx + cols - 1, '+');

        // Title
        wattron(stdscr, COLOR_PAIR(CP_HEADER) | A_BOLD);
        mvwaddstr(stdscr, sy, sx + 2, (" " + title + " ").c_str());
        wattroff(stdscr, COLOR_PAIR(CP_HEADER) | A_BOLD);

        // Items (scrollable window)
        int fy = sy + 2;
        for (int i = top; i < top + maxRows && i < static_cast<int>(items.size()); i++) {
            bool active = (i == sel);
            if (active) wattron(stdscr, COLOR_PAIR(CP_TREE_CURSOR));
            mvwaddstr(stdscr, fy, sx + 2, items[i].c_str());
            if (active) wattroff(stdscr, COLOR_PAIR(CP_TREE_CURSOR));
            fy++;
        }

        // Help line
        wattron(stdscr, COLOR_PAIR(CP_ATTR_OP));
        mvwaddstr(stdscr, sy + rows - 2, sx + 2, "Up/Down=move  Enter=select  Esc=cancel");
        wattroff(stdscr, COLOR_PAIR(CP_ATTR_OP));

        wnoutrefresh(stdscr);
        doupdate();

        int ch = getch();
        if (ch == 27) { timeout(100); touchwin(stdscr); return 0; }
        if (ch == '\n' || ch == '\r' || ch == KEY_ENTER) { timeout(100); touchwin(stdscr); return 1; }
        if (ch == KEY_UP) { if (sel > 0) sel--; }
        else if (ch == KEY_DOWN) { if (sel + 1 < static_cast<int>(items.size())) sel++; }
        else if (ch == KEY_PPAGE) { sel -= maxRows; if (sel < 0) sel = 0; }
        else if (ch == KEY_NPAGE) { sel += maxRows; if (sel >= static_cast<int>(items.size())) sel = static_cast<int>(items.size()) - 1; }
    }
}

void App::showHelp() {
    const std::vector<std::string> lines = {
        "  Navigation",
        "    Up/Down, PgUp/PgDn   move through the tree / attributes",
        "    Left / Right (+/-)   collapse / expand a node",
        "    Enter                select the entry under the cursor",
        "    Tab / Shift-Tab      switch focus (tree / attributes / filter)",
        "    /                    enter filter mode (search from current node)",
        "    g                    jump back to the RootDSE",
        "  Commands",
        "    q                    quit",
        "    y                    copy selected entry DN (clipboard)",
        "    p                    paste / duplicate clipboard entry",
        "    F2                   edit a value (attributes panel)",
        "    F1..F8, F11, F12     open a menu from the top bar",
        "    h, H, ?              show this help",
        "  Editing",
        "    All writes are confirmed (y/n) and run on a background thread.",
        "    Esc cancels a running operation.",
    };
    timeout(-1);
    const int cols = 64;
    int rows = static_cast<int>(lines.size()) + 4;
    int sy = (LINES - rows) / 2;
    int sx = (COLS - cols) / 2;
    if (sy < 0) sy = 0;
    if (sx < 0) sx = 0;
    if (sy + rows >= LINES) { rows = LINES - sy - 1; sy = 0; }

    wattron(stdscr, COLOR_PAIR(CP_BORDER) | A_BOLD);
    for (int r = 0; r < rows; r++)
        for (int c = 0; c < cols; c++)
            mvwaddch(stdscr, sy + r, sx + c, ' ');
    wattroff(stdscr, COLOR_PAIR(CP_BORDER) | A_BOLD);
    for (int c = 1; c < cols - 1; c++) {
        mvwaddch(stdscr, sy, sx + c, '-');
        mvwaddch(stdscr, sy + rows - 1, sx + c, '-');
    }
    for (int r = 1; r < rows - 1; r++) {
        mvwaddch(stdscr, sy + r, sx, '|');
        mvwaddch(stdscr, sy + r, sx + cols - 1, '|');
    }
    mvwaddch(stdscr, sy, sx, '+'); mvwaddch(stdscr, sy, sx + cols - 1, '+');
    mvwaddch(stdscr, sy + rows - 1, sx, '+'); mvwaddch(stdscr, sy + rows - 1, sx + cols - 1, '+');
    wattron(stdscr, COLOR_PAIR(CP_HEADER) | A_BOLD);
    mvwaddstr(stdscr, sy, sx + 2, " DirAtlas Help ");
    wattroff(stdscr, COLOR_PAIR(CP_HEADER) | A_BOLD);
    int fy = sy + 2;
    for (const auto &ln : lines) {
        if (fy >= sy + rows - 1) break;
        if (!ln.empty() && ln[1] != ' ') {
            wattron(stdscr, COLOR_PAIR(CP_ATTR_OP) | A_BOLD);
            mvwaddstr(stdscr, fy, sx + 1, ln.c_str());
            wattroff(stdscr, COLOR_PAIR(CP_ATTR_OP) | A_BOLD);
        } else {
            mvwaddstr(stdscr, fy, sx + 1, ln.c_str());
        }
        fy++;
    }
    wattron(stdscr, COLOR_PAIR(CP_ATTR_OP));
    mvwaddstr(stdscr, sy + rows - 2, sx + 2, "Press any key to close");
    wattroff(stdscr, COLOR_PAIR(CP_ATTR_OP));
    wnoutrefresh(stdscr);
    doupdate();
    getch();
    timeout(100);
    touchwin(stdscr);
    touchwin(headerWin_); touchwin(inputWin_); touchwin(treeWin_);
    touchwin(attrWin_); touchwin(statusWin_); touchwin(logWin_);
    clear();
    refresh();
    draw();
}

void App::showValuePopup(const std::string &title, const std::string &content,
                         const std::string &attrName, const std::string &dn,
                         const std::string &saveContent, bool aclHighlight) {
    timeout(-1);  // blocking input for the popup

    std::string current = content;
    bool edited = false;

    for (;;) {
        // Popup width: use most of the terminal for long ACL values instead of
        // a fixed 72 columns (which wrapped rules mid-clause).
        int cols = std::min(COLS - 4, 130);
        if (cols < 60) cols = 60;

        // Split content into lines (preserving embedded newlines). Long
        // physical lines are wrapped to the popup width so nothing is hidden
        // off-screen; ACL values are pre-formatted per clause and are never
        // re-wrapped (a rule must stay on its own lines).
        const int wrapWidth = cols - 2;
        std::vector<std::string> lines;
        {
            std::string cur;
            auto flush = [&]() {
                if (aclHighlight) {
                    lines.push_back(cur);
                } else {
                    while (static_cast<int>(cur.size()) > wrapWidth) {
                        lines.push_back(cur.substr(0, wrapWidth));
                        cur.erase(0, wrapWidth);
                    }
                    lines.push_back(cur);
                }
                cur.clear();
            };
            for (char c : current) {
                if (c == '\n') flush();
                else cur += c;
            }
            flush();
        }

        // Popup sized to fit content, capped to the terminal.
        int maxRows = LINES - 4;
        int rows = std::min<int>(maxRows, static_cast<int>(lines.size()) + 5);
        if (rows < 7) rows = 7;
        int sy = (LINES - rows) / 2;
        int sx = (COLS - cols) / 2;
        if (sy < 0) sy = 0;
        if (sx < 0) sx = 0;

        int scroll = 0;
        int hscroll = 0;
        int contentH = rows - 3;
        for (;;) {
            // Drop shadow behind the popup so it stands out from the
            // attribute panel underneath (whose ACL values are also coloured).
            wattron(stdscr, COLOR_PAIR(CP_BORDER) | A_DIM);
            for (int r = 1; r <= rows; r++)
                for (int c = 1; c <= cols; c++)
                    mvwaddch(stdscr, sy + r, sx + c, ' ');
            wattroff(stdscr, COLOR_PAIR(CP_BORDER) | A_DIM);

            // Opaque popup background — the panel behind must not bleed through
            // between the coloured ACL tokens. Uses the terminal background
            // (A_NORMAL), which matches the transparent (-1) background of
            // every ACL syntax pair, so tokens and fill stay consistent.
            wattron(stdscr, A_NORMAL);
            for (int r = 0; r < rows; r++)
                for (int c = 0; c < cols; c++)

                    mvwaddch(stdscr, sy + r, sx + c, ' ');
            wattroff(stdscr, A_NORMAL);

            // Popup frame in blue, distinct from the content colours.
            wattron(stdscr, COLOR_PAIR(CP_BORDER));
            for (int c = 1; c < cols - 1; c++) {
                mvwaddch(stdscr, sy, sx + c, '-');
                mvwaddch(stdscr, sy + rows - 1, sx + c, '-');
            }
            for (int r = 1; r < rows - 1; r++) {
                mvwaddch(stdscr, sy + r, sx, '|');
                mvwaddch(stdscr, sy + r, sx + cols - 1, '|');
            }
            mvwaddch(stdscr, sy, sx, '+'); mvwaddch(stdscr, sy, sx + cols - 1, '+');
            mvwaddch(stdscr, sy + rows - 1, sx, '+'); mvwaddch(stdscr, sy + rows - 1, sx + cols - 1, '+');
            wattron(stdscr, COLOR_PAIR(CP_HEADER) | A_BOLD);
            mvwaddstr(stdscr, sy, sx + 2, (" " + title + " ").c_str());
            wattroff(stdscr, COLOR_PAIR(CP_BORDER));
            wattroff(stdscr, COLOR_PAIR(CP_HEADER) | A_BOLD);

            int fy = sy + 1;
            int lineEnd = std::min<int>(static_cast<int>(lines.size()), scroll + contentH);
            for (int i = scroll; i < lineEnd && fy < sy + rows - 1; i++, fy++) {
                if (aclHighlight) {
                    // One rule per set of lines, never wrapped: horizontal
                    // scroll reveals what does not fit. drawAclValue skips the
                    // partial first word so colours never shift with hscroll.
                    std::string seg = lines[i];
                    if (hscroll < static_cast<int>(seg.size()))
                        seg = seg.substr(hscroll);
                    drawAclValue(stdscr, fy, sx + 1, cols - 2, seg, CP_ATTR_VALUE, A_NORMAL, hscroll);
                } else {
                    mvwaddstr(stdscr, fy, sx + 1, lines[i].c_str());
                }
            }

            // Bottom bar: [Edit] button (only when writable) + hints
            int hintY = sy + rows - 2;
            std::string hints = "Esc=close";
            if (!saveContent.empty()) hints += "   s=save";
            if (!attrName.empty() && !dn.empty()) {
                hints += "   [Enter Edit]  F2=edit";
            }
            if (aclHighlight) {
                bool wide = false;
                for (const auto &l : lines)
                    if (static_cast<int>(l.size()) > cols - 2) { wide = true; break; }
                if (wide) hints += "   \u2190/\u2192=hscroll";
            }
            if (static_cast<int>(lines.size()) > contentH)
                hints += "   Up/Dn=scroll  (" + std::to_string(scroll + 1) + "-" +
                        std::to_string(lineEnd) + "/" + std::to_string(lines.size()) + ")";
            wattron(stdscr, COLOR_PAIR(CP_ATTR_OP));
            mvwaddstr(stdscr, hintY, sx + 2, hints.c_str());
            wattroff(stdscr, COLOR_PAIR(CP_ATTR_OP));

        wnoutrefresh(stdscr);
        doupdate();

        int ch = getch();
            if (ch == 27 || ch == 'q' || ch == 'Q') goto done;
            if (ch == KEY_UP && scroll > 0) scroll--;
            if (ch == KEY_DOWN && scroll + contentH < static_cast<int>(lines.size())) scroll++;
            if (ch == KEY_PPAGE) scroll = std::max(0, scroll - contentH);
            if (ch == KEY_NPAGE)
                scroll = std::min<int>(std::max(0, static_cast<int>(lines.size()) - contentH),
                                       scroll + contentH);
            if (ch == KEY_HOME) scroll = 0;
            if (ch == KEY_END)
                scroll = std::max(0, static_cast<int>(lines.size()) - contentH);
            if (aclHighlight) {
                int maxH = 0;
                for (const auto &l : lines)
                    if (static_cast<int>(l.size()) > maxH) maxH = static_cast<int>(l.size());
                maxH = std::max(0, maxH - (cols - 2));
                if (ch == KEY_LEFT && hscroll > 0) hscroll -= 8;
                if (ch == KEY_RIGHT && hscroll < maxH) hscroll += 8;
                if (ch == KEY_HOME) hscroll = 0;
                if (ch == KEY_END) hscroll = maxH;
            }
            // Save the report to a file (ACL popups offer a full report).
            if (!saveContent.empty() && (ch == 's' || ch == 'S')) {
                for (int n = 1;; ++n) {
                    char buf[64];
                    std::snprintf(buf, sizeof(buf), "diratlas_acl_%04d.txt", n);
                    std::string path = buf;
                    std::ifstream probe(path);
                    if (!probe.good()) {
                        std::ofstream out(path);
                        if (out.is_open()) {
                            out << saveContent;
                            setLog("Saved ACL report to " + path);
                        } else {
                            setLog("Cannot write " + path);
                        }
                        break;
                    }
                }
                goto done;
            }
            // Edit button / F2: open the multi-line editor on the decoded text.
            if (!attrName.empty() && !dn.empty() &&
                (ch == '\n' || ch == '\r' || ch == KEY_ENTER || ch == KEY_F(2))) {
                std::string editedContent = current;
                if (editTextPopup("Edit " + attrName + " (decoded)", editedContent)) {
                    current = editedContent;
                    edited = true;
                    break;  // redraw the popup with the new content
                }
            }
        }

        // After editing, offer to write the change back (re-encoded in base64).
        if (edited) {
            // Detect format and validate before proposing the write.
            std::string v = detectAndValidateFormat(current, attrName);
            if (!v.empty() && v.compare(0, 4, "ERR:") == 0) {
                setLog("Edit rejected: " + v.substr(4));
                break;
            }
            if (!v.empty()) {
                // Non-blocking warning: ask for explicit confirmation.
                setLog("Warning: " + v + ".  Y to write anyway, N to cancel.");
                timeout(-1);  // blocking confirmation prompt
                // Redraw so the warning is visible before blocking on input.
                draw();
                for (;;) {
                    int a = getch();
                    if (a == 'y' || a == 'Y') break;
                    if (a == 'n' || a == 'N' || a == 27) { setLog("Edit cancelled"); draw(); goto done; }
                }
            }
            // Re-encode and write on the worker thread.
            std::string newB64 = diratlas::ldapcore::base64Encode(current);
            std::vector<std::string> newVals = {newB64};
            runWriteOp([this, dn, attrName, newVals]() {
                            return conn_->modifyAttribute(dn, attrName, newVals);
                        },
                        "Updated " + attrName + " (base64 re-encoded)", "Update failed",
                        false, true);
            break;
        }
    }
done:
    timeout(100);
    touchwin(stdscr);
    touchwin(headerWin_); touchwin(inputWin_); touchwin(treeWin_);
    touchwin(attrWin_); touchwin(statusWin_); touchwin(logWin_);
    clear();
    refresh();
    draw();
}

bool App::editTextPopup(const std::string &title, std::string &content) {
    timeout(-1);  // blocking input for the popup

    // Represent the text as a list of lines for line-based editing.
    std::vector<std::string> lines;
    {
        std::string cur;
        for (char c : content) {
            if (c == '\n') { lines.push_back(cur); cur.clear(); }
            else cur += c;
        }
        lines.push_back(cur);
    }
    if (lines.empty()) lines.push_back("");

    const int cols = 72;
    const int rows = LINES - 6;
    if (rows < 8) { timeout(100); return false; }
    int sy = (LINES - rows) / 2;
    int sx = (COLS - cols) / 2;
    if (sy < 0) sy = 0;
    if (sx < 0) sx = 0;
    const int contentH = rows - 3;

    int curLine = 0;
    int curCol = static_cast<int>(lines[0].size());
    int scroll = 0;
    curs_set(1);

    for (;;) {
        if (curLine < scroll) scroll = curLine;
        if (curLine >= scroll + contentH) scroll = curLine - contentH + 1;

        // Border + title
        wattron(stdscr, COLOR_PAIR(CP_BORDER) | A_BOLD);
        for (int r = 0; r < rows; r++)
            for (int c = 0; c < cols; c++)
                mvwaddch(stdscr, sy + r, sx + c, ' ');
        wattroff(stdscr, COLOR_PAIR(CP_BORDER) | A_BOLD);
        for (int c = 1; c < cols - 1; c++) {
            mvwaddch(stdscr, sy, sx + c, '-');
            mvwaddch(stdscr, sy + rows - 1, sx + c, '-');
        }
        for (int r = 1; r < rows - 1; r++) {
            mvwaddch(stdscr, sy + r, sx, '|');
            mvwaddch(stdscr, sy + r, sx + cols - 1, '|');
        }
        mvwaddch(stdscr, sy, sx, '+'); mvwaddch(stdscr, sy, sx + cols - 1, '+');
        mvwaddch(stdscr, sy + rows - 1, sx, '+'); mvwaddch(stdscr, sy + rows - 1, sx + cols - 1, '+');
        wattron(stdscr, COLOR_PAIR(CP_HEADER) | A_BOLD);
        mvwaddstr(stdscr, sy, sx + 2, (" " + title + " ").c_str());
        wattroff(stdscr, COLOR_PAIR(CP_HEADER) | A_BOLD);

        // Draw lines (with line numbers)
        for (int i = 0; i < contentH && scroll + i < static_cast<int>(lines.size()); i++) {
            int fy = sy + 1 + i;
            bool active = (scroll + i == curLine);
            if (active) wattron(stdscr, COLOR_PAIR(CP_TREE_CURSOR));
            std::string num = std::to_string(scroll + i + 1);
            mvwaddstr(stdscr, fy, sx + 1, num.c_str());
            std::string seg = lines[scroll + i];
            if (static_cast<int>(seg.size()) > cols - 6)
                seg = seg.substr(0, cols - 6);
            mvwaddstr(stdscr, fy, sx + 4, seg.c_str());
            if (active) wattroff(stdscr, COLOR_PAIR(CP_TREE_CURSOR));
        }

        // Bottom bar
        wattron(stdscr, COLOR_PAIR(CP_ATTR_OP));
        std::string hint = "Enter=newline  Backspace=del  [F2/Ctrl-X Save]  Esc=cancel";
        mvwaddstr(stdscr, sy + rows - 2, sx + 2, hint.c_str());
        wattroff(stdscr, COLOR_PAIR(CP_ATTR_OP));

        wnoutrefresh(stdscr);
        doupdate();

        // Place the cursor on the current line/column
        {
            int cw = curCol;
            if (cw > cols - 6) cw = cols - 6;
            wmove(stdscr, sy + 1 + (curLine - scroll), sx + 4 + cw);
        }

        int ch = getch();
        if (ch == 27) {  // Esc = cancel
            curs_set(0); timeout(100); touchwin(stdscr); return false;
        }
        if (ch == KEY_F(2) || ch == 24 || (ch == '\n' && false)) {  // F2 / Ctrl-X = save
            // Rebuild content from lines.
            std::string out;
            for (size_t i = 0; i < lines.size(); i++) {
                if (i) out += '\n';
                out += lines[i];
            }
            content = out;
            curs_set(0); timeout(100); touchwin(stdscr); return true;
        }
        if (ch == KEY_UP) { if (curLine > 0) curLine--; if (curLine < (int)lines.size()) curCol = std::min(curCol, (int)lines[curLine].size()); }
        else if (ch == KEY_DOWN) { if (curLine + 1 < (int)lines.size()) { curLine++; curCol = std::min(curCol, (int)lines[curLine].size()); } }
        else if (ch == KEY_LEFT) { if (curCol > 0) curCol--; }
        else if (ch == KEY_RIGHT) { if (curCol < (int)lines[curLine].size()) curCol++; }
        else if (ch == KEY_HOME) { curCol = 0; }
        else if (ch == KEY_END) { curCol = (int)lines[curLine].size(); }
        else if (ch == KEY_DC) {
            if (curCol < (int)lines[curLine].size()) lines[curLine].erase(curCol, 1);
            else if (curLine + 1 < (int)lines.size()) {
                lines[curLine] += lines[curLine + 1];
                lines.erase(lines.begin() + curLine + 1);
            }
        }
        else if (ch == KEY_BACKSPACE || ch == 127 || ch == 8) {
            if (curCol > 0) { lines[curLine].erase(curCol - 1, 1); curCol--; }
            else if (curLine > 0) {
                curCol = (int)lines[curLine - 1].size();
                lines[curLine - 1] += lines[curLine];
                lines.erase(lines.begin() + curLine);
                curLine--;
            }
        }
        else if (ch == '\n' || ch == '\r') {  // split line
            std::string right = lines[curLine].substr(curCol);
            lines[curLine] = lines[curLine].substr(0, curCol);
            lines.insert(lines.begin() + curLine + 1, right);
            curLine++;
            curCol = 0;
        }
        else if (ch >= 32 && ch <= 126) {  // printable char
            lines[curLine].insert(curCol, 1, (char)ch);
            curCol++;
        }
    }
}

std::string App::validatePpmConfig(const std::string &content) {
    // Each non-empty, non-comment line must be: <param> <value> [min minForPoint max].
    // class-* entries carry the extra numeric triple; plain params must be ints.
    static const std::set<std::string> intParams = {
        "minQuality", "checkRDN", "maxConsecutivePerClass", "useCracklib"
    };
    std::istringstream ss(content);
    std::string line;
    int lineno = 0;
    while (std::getline(ss, line)) {
        lineno++;
        std::string t = line;
        // Trim leading whitespace.
        size_t b = t.find_first_not_of(" \t");
        if (b == std::string::npos) continue;              // blank line
        if (t[b] == '#') continue;                          // comment
        std::istringstream ls(t.substr(b));
        std::string param, value;
        if (!(ls >> param)) return "line " + std::to_string(lineno) + ": missing parameter";
        if (!(ls >> value)) {
            // A parameter with no value is silently ignored by ppm (default
            // applies); only class-* lines require a value.
            if (param.compare(0, 6, "class-") == 0)
                return "line " + std::to_string(lineno) + ": class '" + param + "' has no value";
            continue;
        }
        if (param.compare(0, 6, "class-") == 0) {
            int min, mfp, max;
            if (!(ls >> min >> mfp >> max))
                return "line " + std::to_string(lineno) + ": class '" + param + "' needs <value> <min> <minForPoint> <max>";
        } else if (intParams.count(param)) {
            std::string extra;
            if (ls >> extra)
                return "line " + std::to_string(lineno) + ": parameter '" + param + "' takes a single value";
        }
    }
    return "";
}

namespace {
// Helper: check a string is valid UTF-8 (rejects stray continuation/control bytes).
bool validUtf8(const std::string &s) {
    size_t i = 0;
    while (i < s.size()) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        if (c < 0x80) { i++; continue; }
        int extra;
        if ((c & 0xE0) == 0xC0) extra = 1;
        else if ((c & 0xF0) == 0xE0) extra = 2;
        else if ((c & 0xF8) == 0xF0) extra = 3;
        else return false;
        if (i + extra >= s.size()) return false;
        for (int k = 1; k <= extra; k++) {
            if ((static_cast<unsigned char>(s[i + k]) & 0xC0) != 0x80)
                return false;
        }
        i += extra + 1;
    }
    return true;
}

// Helper: balanced delimiters (parens, braces, brackets, angle brackets).
std::string checkBalanced(const std::string &s, const char *openSet, const char *closeSet,
                          const char *label) {
    int depth = 0;
    for (char c : s) {
        if (strchr(openSet, c)) depth++;
        else if (strchr(closeSet, c)) {
            depth--;
            if (depth < 0)
                return std::string("unbalanced '") + label + "': too many closing delimiters";
        }
    }
    if (depth > 0)
        return std::string("unbalanced '") + label + "': " + std::to_string(depth) + " unclosed";
    return "";
}
} // namespace

std::string App::detectAndValidateFormat(const std::string &content, const std::string &attrName) {
    // ppm config: explicit attr name, or detected "param value" line shape.
    if (attrName == "pwdCheckModuleArg")
        return validatePpmConfig(content);

    std::string trimmed = content;
    size_t b = trimmed.find_first_not_of(" \t\r\n");
    if (b != std::string::npos) trimmed = trimmed.substr(b);
    if (trimmed.empty()) return "";  // empty content is always acceptable

    // UTF-8 validity is a generic sanity check for any text payload.
    if (!validUtf8(content))
        return "ERR: content is not valid UTF-8";

    // JSON detection: starts with { or [ (with surrounding whitespace only).
    if (trimmed[0] == '{' || trimmed[0] == '[') {
        std::string bErr = checkBalanced(content, "{[", "}]", "braces/brackets");
        if (!bErr.empty()) return "ERR: JSON-ish content: " + bErr;
        return "";  // structural balance OK; treat as valid
    }
    // XML detection: starts with '<'.
    if (trimmed[0] == '<') {
        std::string bErr = checkBalanced(content, "<", ">", "angle brackets");
        if (!bErr.empty()) return "ERR: XML-ish content: " + bErr;
        return "";
    }

    // Generic text: report unbalanced delimiters as a warning (not blocking),
    // since plain text may legitimately contain unmatched quotes/delimiters.
    std::string warn;
    warn += checkBalanced(content, "([{", ")]}", "parentheses/braces/brackets");
    if (!warn.empty()) return warn;
    return "";
}

int App::appPopupForm(const std::string &title,
                      std::vector<std::pair<std::string, std::string*>> &fields,
                      bool *checkbox) {
    timeout(-1);  // blocking input for the popup

    int rows = static_cast<int>(fields.size()) + 4 + (checkbox ? 1 : 0);
    int cols = 50;
    int sy = (LINES - rows) / 2;
    int sx = (COLS - cols) / 2;
    if (sy < 0) sy = 0;
    if (sx < 0) sx = 0;
    if (sy + rows >= LINES) rows = LINES - sy - 1;
    if (rows < 5) rows = 5;

    // Value display area: [sx+20 .. sx+cols-2)
    const int valX = sx + 20;
    const int valW = cols - 22;

    curs_set(1);
    bool done = false;
    int focus = 0;
    bool checked = false;
    // Per-field cursor position and horizontal scroll offset.
    std::vector<int> curPos(fields.size(), 0);
    std::vector<int> scrollOff(fields.size(), 0);
    for (size_t i = 0; i < fields.size(); i++)
        curPos[i] = static_cast<int>(fields[i].second->size());

    while (!done) {
        // Draw popup
        wattron(stdscr, COLOR_PAIR(CP_BORDER) | A_BOLD);
        for (int r = 0; r < rows; r++)
            for (int c = 0; c < cols; c++)
                mvwaddch(stdscr, sy + r, sx + c, ' ');
        wattroff(stdscr, COLOR_PAIR(CP_BORDER) | A_BOLD);
        // Border
        for (int c = 1; c < cols - 1; c++) {
            mvwaddch(stdscr, sy, sx + c, '-');
            mvwaddch(stdscr, sy + rows - 1, sx + c, '-');
        }
        for (int r = 1; r < rows - 1; r++) {
            mvwaddch(stdscr, sy + r, sx, '|');
            mvwaddch(stdscr, sy + r, sx + cols - 1, '|');
        }
        mvwaddch(stdscr, sy, sx, '+'); mvwaddch(stdscr, sy, sx + cols - 1, '+');
        mvwaddch(stdscr, sy + rows - 1, sx, '+'); mvwaddch(stdscr, sy + rows - 1, sx + cols - 1, '+');

        // Title
        wattron(stdscr, COLOR_PAIR(CP_HEADER) | A_BOLD);
        mvwaddstr(stdscr, sy, sx + 2, (" " + title + " ").c_str());
        wattroff(stdscr, COLOR_PAIR(CP_HEADER) | A_BOLD);

        // Fields
        int fy = sy + 2;
        for (size_t i = 0; i < fields.size(); i++) {
            bool active = (static_cast<int>(i) == focus);
            if (active) wattron(stdscr, COLOR_PAIR(CP_TREE_CURSOR));
            mvwaddstr(stdscr, fy, sx + 2, fields[i].first.c_str());
            if (active) wattroff(stdscr, COLOR_PAIR(CP_TREE_CURSOR));
            const std::string &full = *fields[i].second;
            if (active) {
                // Keep the cursor visible: scroll the window so the cursor
                // stays within [scroll, scroll+valW).
                if (curPos[i] < scrollOff[i]) scrollOff[i] = curPos[i];
                if (curPos[i] > scrollOff[i] + valW - 1) scrollOff[i] = curPos[i] - valW + 1;
            }
            std::string win;
            if (scrollOff[i] < static_cast<int>(full.size()))
                win = full.substr(scrollOff[i], valW);
            if (active) {
                int caret = curPos[i] - scrollOff[i];
                if (caret < 0) caret = 0;
                if (caret > valW - 1) caret = valW - 1;
                for (int c = 0; c < valW; c++) {
                    char chc = (c < static_cast<int>(win.size())) ? win[c] : ' ';
                    if (c == caret) {
                        wattron(stdscr, COLOR_PAIR(CP_SELECTED));
                        mvwaddch(stdscr, fy, valX + c, chc);
                        wattroff(stdscr, COLOR_PAIR(CP_SELECTED));
                    } else {
                        mvwaddch(stdscr, fy, valX + c, chc);
                    }
                }
                if (full.empty())
                    mvwaddstr(stdscr, fy, valX, "(empty)");
            } else {
                if (win.empty()) win = "(empty)";
                mvwaddstr(stdscr, fy, valX, win.c_str());
            }
            fy++;
        }

        // Checkbox
        if (checkbox) {
            bool active = (static_cast<int>(fields.size()) == focus);
            if (active) wattron(stdscr, COLOR_PAIR(CP_TREE_CURSOR));
            mvwaddstr(stdscr, fy, sx + 2, (std::string("[") + (checked ? "X" : " ") + "] Export operational attrs").c_str());
            if (active) wattroff(stdscr, COLOR_PAIR(CP_TREE_CURSOR));
        }

        // Help line
        wattron(stdscr, COLOR_PAIR(CP_ATTR_OP));
        mvwaddstr(stdscr, sy + rows - 2, sx + 2, "Tab=next  Enter=confirm  Esc=cancel");
        wattroff(stdscr, COLOR_PAIR(CP_ATTR_OP));

        wnoutrefresh(stdscr);
        doupdate();

        // Place the real ncurses cursor on the active field so typing appears
        // in the right place (curs_set(1) is active).
        if (focus >= 0 && focus < static_cast<int>(fields.size())) {
            int caret = curPos[focus] - scrollOff[focus];
            if (caret < 0) caret = 0;
            if (caret > valW - 1) caret = valW - 1;
            wmove(stdscr, sy + 2 + focus, valX + caret);
        } else {
            wmove(stdscr, sy + 2 + static_cast<int>(fields.size()), sx + 2);
        }

        int ch = getch();
        if (ch == 27) { done = true; timeout(100); return 0; }
        if (ch == '\t') {
            int total = static_cast<int>(fields.size()) + (checkbox ? 1 : 0);
            focus = (focus + 1) % total;
            continue;
        }
        if (ch == '\n' || ch == '\r' || ch == KEY_ENTER) { done = true; timeout(100); return 1; }
        if (checkbox && focus == static_cast<int>(fields.size()) && (ch == ' ' || ch == '\t')) {
            checked = !checked;
            continue;
        }
        // Text input for focused field
        if (focus >= 0 && focus < static_cast<int>(fields.size())) {
            std::string &val = *(fields[focus].second);
            int &cp = curPos[focus];
            if (ch == KEY_LEFT) { if (cp > 0) cp--; continue; }
            if (ch == KEY_RIGHT) { if (cp < static_cast<int>(val.size())) cp++; continue; }
            if (ch == KEY_HOME) { cp = 0; continue; }
            if (ch == KEY_END) { cp = static_cast<int>(val.size()); continue; }
            if (ch == KEY_DC) {
                if (cp < static_cast<int>(val.size())) val.erase(cp, 1);
                continue;
            }
            if (ch == KEY_BACKSPACE || ch == 127 || ch == 8) {
                if (cp > 0 && !val.empty()) { val.erase(cp - 1, 1); cp--; }
                continue;
            }
            if (ch >= 32 && ch <= 126) {
                val.insert(cp, 1, static_cast<char>(ch));
                cp++;
                continue;
            }
        }
    }
    if (checkbox) *checkbox = checked;
    timeout(100);
    curs_set(0);
    touchwin(stdscr);
    return 0;
}

void App::appExportLdif() {
    std::string baseDN = tree_ ? tree_->selectedDN() : "";
    if (baseDN.empty()) {
        setLog("Export: position cursor on a tree node first");
        return;
    }
    std::string filter = "(objectClass=*)";
    std::string filename = "diratlas_export_0001.ldif";
    bool exportOp = false;
    std::vector<std::pair<std::string, std::string*>> fields = {
        {"Search base:", &baseDN}, {"Filter:", &filter}, {"Filename:", &filename},
    };
    if (appPopupForm("Export to LDIF", fields, &exportOp) == 0) {
        setLog("Export cancelled"); return;
    }
    setLog("Exporting to " + filename + " ...");
    // Run export in background
    loadingMsg_ = "Exporting to " + filename;
    loading_.store(true);
    loadingStart_ = std::chrono::steady_clock::now();
    cancel_.store(false);
    if (worker_.joinable()) worker_.join();
    worker_ = std::thread([this, baseDN, filter, filename, exportOp]() {
        std::ofstream out(filename);
        if (!out.is_open()) {
            pendingLog_ = "Cannot write " + filename; pendingUpdate_.store(true);
            loading_.store(false); return;
        }
        std::vector<std::string> attrs = {"*"};
        if (exportOp) attrs.push_back("+");

        std::vector<LDAPEntry> entries;
        if (!conn_->search(baseDN, LDAP_SCOPE_SUBTREE, filter, attrs, false, entries)) {
            out.close();
            pendingLog_ = "Export failed: " + conn_->getLastError();
            pendingUpdate_.store(true);
            loading_.store(false);
            return;
        }

        int total = 0;
        for (auto &e : entries) {
            if (cancel_.load()) break;
            out << "dn: " << e.dn << "\n";
            for (auto &an : e.attributeNames) {
                auto it = e.attributes.find(an);
                if (it == e.attributes.end()) continue;
                for (auto &v : it->second) {
                    if (v.empty())
                        out << an << ":\n";
                    else if (ldapcore::ldifSafeValue(v))
                        out << an << ": " << v << "\n";
                    else
                        out << an << ":: " << ldapcore::base64Encode(v) << "\n";
                }
            }
            out << "\n";
            total++;
        }
        out.close();
        pendingLog_ = "Exported " + std::to_string(total) + " entries to " + filename;
        pendingUpdate_.store(true);
        loading_.store(false);
    });
}

void App::appDeleteEntry() {
    std::string dn = tree_ ? tree_->selectedDN() : "";
    if (dn.empty()) { setLog("Delete: position cursor on an entry first"); return; }
    pendingConfirm_ = "delete:" + dn;
    setLog("Delete " + dn + "?  [Y]es / [N]o");
}

void App::appDeleteAttr() {
    std::string dn = tree_ ? tree_->selectedDN() : "";
    if (dn.empty()) { setLog("Delete attr: select an entry first"); return; }
    // Get attribute name from attrs panel or prompt
    std::string attrName;
    if (attrs_ && attrs_->selectedRow() >= 0 && attrs_->selectedRow() < attrs_->rowCount())
        attrName = attrs_->getAttrName(attrs_->selectedRow());
    if (attrName.empty()) {
        std::vector<std::pair<std::string, std::string*>> fields = {{"Attribute:", &attrName}};
        if (appPopupForm("Delete Attribute", fields, nullptr) == 0) return;
    }
    if (attrName.empty()) { setLog("Attribute name required"); return; }

    // A selected value deletes just that value; otherwise the whole attribute.
    std::string val;
    if (attrs_ && attrs_->selectedRow() >= 0 && attrs_->selectedRow() < attrs_->rowCount())
        val = attrs_->getValue(attrs_->selectedRow());
    std::vector<std::string> allVals = attrs_ ? attrs_->getAttrValues(attrName) : std::vector<std::string>{};

    // Removing an objectClass value: refuse to drop the last STRUCTURAL class,
    // otherwise the server rejects with "no structural object class provided".
    {
        std::string attrLower;
        for (char c : attrName)
            attrLower += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (attrLower == "objectclass" && !val.empty()) {
        LDAPEntry cur = conn_->searchOne(dn, "(objectClass=*)", {"*"}, false);
        std::vector<std::string> ocs = cur.getAttrs("objectClass");
        // Count how many of the remaining classes (after removing val) are STRUCTURAL.
        std::string target = val;
        int structuralRemaining = 0;
        for (const auto &oc : ocs) {
            if (oc == target) continue;
            if (objectClassKind(*conn_, oc) == "STRUCTURAL")
                structuralRemaining++;
        }
        if (structuralRemaining == 0) {
            setLog("Delete rejected: '" + val + "' is the last STRUCTURAL objectClass; "
                   "the entry would have no structural class");
            return;
        }
        }
    }

    if (!val.empty() && allVals.size() > 1) {
        pendingConfirm_ = "delval:" + dn + "|" + attrName + "|" + val;
        setLog("Delete value of " + attrName + "?  [Y]es / [N]o");
    } else {
        pendingConfirm_ = "delattr:" + dn + "|" + attrName;
        setLog("Delete attribute " + attrName + "?  [Y]es / [N]o");
    }
}

void App::appAttrMenu() {
    if (!attrs_) return;
    int sr = attrs_->selectedRow();
    if (sr < 0 || sr >= attrs_->rowCount()) return;
    std::string attrFull = attrs_->getAttrName(sr);  // may include ;options
    if (attrFull.empty()) return;

    // Split type / options (RFC 4512 §2.5.2).
    diratlas::ldapcore::AttributeDescription ad;
    bool parsed = diratlas::ldapcore::parseAttributeDescription(attrFull, ad);
    std::string attrType = parsed ? ad.type : attrFull;
    std::string val = attrs_->getValue(sr);

    // Lazily load the attribute schema (only once per session).
    if (attrSchema_.defs.empty())
        attrSchema_ = loadAttrSchema(*conn_);

    // Schema lookups use lower-case keys; entry attribute names keep the
    // server's case, so lower-case the type before the lookup.
    std::string lowerType;
    for (char c : attrType)
        lowerType += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

    bool multi = parsed && !attrSchema_.singleValue(lowerType);
    bool prot = parsed && attrSchema_.noUserModification(lowerType);

    // Build the contextual action list (schema-aware).
    std::vector<std::string> actions;
    std::vector<char> keys;  // parallel action codes
    actions.push_back("Edit value"); keys.push_back('e');
    if (parsed && !ad.options.empty()) {
        actions.push_back("Modify attribute options"); keys.push_back('o');
    }
    if (multi && !prot) {
        actions.push_back("Add value"); keys.push_back('a');
        if (!val.empty()) {
            actions.push_back("Duplicate value"); keys.push_back('d');
            actions.push_back("Delete value"); keys.push_back('v');
        }
    }
    if (!prot) {
        actions.push_back("Delete attribute"); keys.push_back('x');
    }
    if (actions.empty()) { setLog("No actions available for " + attrFull); return; }

    int sel = 0;
    if (appPickList("Attribute: " + attrFull, actions, sel) == 0) { setLog("Cancelled"); return; }
    char code = keys[sel];

    switch (code) {
    case 'e':
        attrs_->editMode_ = true;
        attrs_->editRow_ = sr;
        attrs_->editOrig_ = val;
        attrs_->editStr_ = val;
        attrs_->editPos_ = static_cast<int>(val.size());
        log_ = "Editing " + attrFull + ": " + val.substr(0, 60);
        break;
    case 'o':
        appAttrOptions();
        break;
    case 'a':
        appAddAttr(attrFull);
        break;
    case 'd':
        appAttrDuplicateValue();
        break;
    case 'v':
        appDeleteAttr();
        break;
    case 'x':
        appDeleteAttr();
        break;
    }
}

void App::appAttrDuplicateValue() {
    std::string dn = tree_ ? tree_->selectedDN() : "";
    if (dn.empty()) { setLog("Duplicate value: select an entry first"); return; }
    int sr = attrs_->selectedRow();
    if (sr < 0 || sr >= attrs_->rowCount()) return;
    std::string attr = attrs_->getAttrName(sr);
    std::string val = attrs_->getValue(sr);
    if (attr.empty() || val.empty()) { setLog("Duplicate value: nothing to duplicate"); return; }
    // "Duplicate" = copy the value as a base for a NEW value: prefill the
    // form, let the user edit, then add the edited value. Adding the value
    // unchanged would just fail with "already exists".
    std::string newVal = val;
    std::vector<std::pair<std::string, std::string*>> fields = {
        {"Attribute:", &attr}, {"Value:", &newVal},
    };
    if (appPopupForm("Duplicate Value", fields, nullptr) == 0) { setLog("Duplicate value cancelled"); return; }
    if (newVal.empty()) { setLog("Duplicate value: empty value"); return; }

    // Reject an exact duplicate of an existing value before sending it.
    // Equality follows the attribute's matching rule (case-sensitive for
    // caseExactMatch, case-insensitive for caseIgnoreMatch); when the schema
    // is unknown we fall back to an exact compare.
    if (attrSchema_.defs.empty())
        attrSchema_ = loadAttrSchema(*conn_);
    std::string attrLower;
    for (char c : attr)
        attrLower += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    bool cs = attrSchema_.caseSensitive(attrLower);
    std::vector<std::string> existing = attrs_ ? attrs_->getAttrValues(attr) : std::vector<std::string>{};
    for (const auto &e : existing) {
        bool same = cs ? (e == newVal) : true;
        if (!cs) {
            std::string a = e, b = newVal;
            for (auto &c : a) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            for (auto &c : b) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            same = (a == b);
        }
        if (same) { setLog("Duplicate value rejected: value already exists for " + attr); return; }
    }
    std::string syntaxErr = attrSchema_.validateValue(attrLower, newVal);
    if (!syntaxErr.empty()) {
        setLog("Duplicate value rejected: '" + newVal.substr(0, 60) + "' — " + syntaxErr);
        return;
    }

    runWriteOp([this, dn, attr, newVal]() {
                   return conn_->addAttribute(dn, attr, {newVal});
               },
               "Added " + attr + " = " + newVal.substr(0, 60), "Duplicate value failed", false, true);
}

void App::appAttrOptions() {
    if (!attrs_) return;
    int sr = attrs_->selectedRow();
    if (sr < 0 || sr >= attrs_->rowCount()) return;
    std::string attrFull = attrs_->getAttrName(sr);
    std::string dn = tree_ ? tree_->selectedDN() : "";

    diratlas::ldapcore::AttributeDescription ad;
    if (!diratlas::ldapcore::parseAttributeDescription(attrFull, ad)) {
        setLog("Cannot parse attribute options"); return;
    }
    // Rebuild a comma-free option list, e.g. "binary,lang-en".
    std::string optStr;
    for (const auto &o : ad.options) {
        if (!optStr.empty()) optStr += ",";
        optStr += o;
    }
    std::vector<std::pair<std::string, std::string*>> fields = {
        {"Attribute type:", &ad.type},
        {"Options (comma):", &optStr},
    };
    if (appPopupForm("Attribute Options", fields, nullptr) == 0) { setLog("Cancelled"); return; }

    // Rebuild the new AttributeDescription "type;opt1;opt2".
    std::string newDesc = ad.type;
    std::string opts = optStr;
    std::string tok;
    std::istringstream iss(opts);
    while (std::getline(iss, tok, ',')) {
        std::string t = tok;
        size_t b = t.find_first_not_of(" \t");
        if (b == std::string::npos) continue;
        t = t.substr(b);
        size_t e = t.find_last_not_of(" \t");
        if (e != std::string::npos) t = t.substr(0, e + 1);
        if (t.empty()) continue;
        newDesc += ";";
        newDesc += t;
    }

    if (newDesc == attrFull) { setLog("No change to options"); return; }
    std::string oldDesc = attrFull;
    // Replace the attribute description (delete old, add new). Value preserved.
    std::string val = attrs_->getValue(sr);
    runWriteOp([this, dn, oldDesc, newDesc, val]() {
                   bool ok = conn_->deleteAttribute(dn, oldDesc);
                   if (!ok) return false;
                   return conn_->addAttribute(dn, newDesc, {val});
               },
               "Renamed " + oldDesc + " → " + newDesc, "Rename attribute failed", false, true);
}

void App::runWriteOp(const std::function<bool()> &op, const std::string &okMsg,
                     const std::string &failMsg, bool refreshTree, bool reloadEntry) {    if (worker_.joinable()) worker_.join();
    cancel_.store(false);
    loading_.store(true);
    loadingStart_ = std::chrono::steady_clock::now();
    loadingMsg_ = okMsg;
    worker_ = std::thread([this, op, okMsg, failMsg, refreshTree, reloadEntry]() {
        bool ok = false;
        try { ok = op(); } catch (...) { ok = false; }
        if (cancel_.load()) { loading_.store(false); return; }
        pendingLog_ = ok ? okMsg : failMsg + ": " + conn_->getLastError();
        if (ok && refreshTree) pendingRefreshTree_.store(true);
        if (ok && reloadEntry) pendingReloadEntry_.store(true);
        pendingUpdate_.store(true);
        loading_.store(false);
    });
}

void App::applyPendingConfirm(char ans) {
    std::string cmd = pendingConfirm_;
    pendingConfirm_.clear();
    if (ans != 'y' && ans != 'Y') { setLog("Cancelled"); return; }

    auto p1 = cmd.find(':');
    if (p1 == std::string::npos) return;
    std::string kind = cmd.substr(0, p1);
    std::string rest = cmd.substr(p1 + 1);

    if (kind == "delete") {
        std::string dn = rest;
        runWriteOp([this, dn]() { return conn_->deleteObject(dn); },
                    "Deleted: " + dn, "Delete failed", true);
    } else if (kind == "delattr") {
        auto bar = rest.find('|');
        if (bar == std::string::npos) return;
        std::string dn = rest.substr(0, bar);
        std::string attr = rest.substr(bar + 1);
        runWriteOp([this, dn, attr]() { return conn_->deleteAttribute(dn, attr); },
                    "Deleted " + attr + " from " + dn, "Delete attr failed", false, true);
    } else if (kind == "delval") {
        auto bar1 = rest.find('|');
        if (bar1 == std::string::npos) return;
        auto bar2 = rest.find('|', bar1 + 1);
        if (bar2 == std::string::npos) return;
        std::string dn = rest.substr(0, bar1);
        std::string attr = rest.substr(bar1 + 1, bar2 - bar1 - 1);
        std::string val = rest.substr(bar2 + 1);
        runWriteOp([this, dn, attr, val]() { return conn_->deleteAttributeValue(dn, attr, val); },
                    "Deleted value of " + attr + " from " + dn, "Delete value failed", false, true);
    } else if (kind == "rename") {
        auto bar = rest.find('|');
        if (bar == std::string::npos) return;
        std::string dn = rest.substr(0, bar);
        std::string newRdn = rest.substr(bar + 1);
        runWriteOp([this, dn, newRdn]() { return conn_->renameObject(dn, newRdn, true); },
                    "Renamed: " + dn + " → " + newRdn + "," + ldapcore::parentOf(dn), "Rename failed", true);
    } else if (kind == "move") {
        // Move keeps the RDN unchanged and supplies a new parent (newSuperior).
        auto bar = rest.find('|');
        if (bar == std::string::npos) return;
        std::string dn = rest.substr(0, bar);
        std::string newSuperior = rest.substr(bar + 1);
        runWriteOp([this, dn, newSuperior]() {
                        return conn_->renameObject(dn, ldapcore::rdnOf(dn), false, newSuperior);
                    },
                    "Moved: " + dn + " → " + newSuperior, "Move failed", true);
    }
}

void App::appAddEntry() {
    std::string parentDN = tree_ ? tree_->selectedDN() : "";
    if (parentDN.empty()) { setLog("Add: position cursor on the parent entry first"); return; }

    // Let the user pick an objectClass from the server subschema.
    auto classNames = listObjectClasses(*conn_);
    std::string objectClass = "inetOrgPerson";
    if (!classNames.empty()) {
        int sel = 0;
        auto it = std::find(classNames.begin(), classNames.end(), objectClass);
        if (it != classNames.end()) sel = static_cast<int>(it - classNames.begin());
        if (appPickList("ObjectClass", classNames, sel) == 0) { setLog("Add cancelled"); return; }
        objectClass = classNames[sel];
    }

    // Prefill the form with the schema-mandatory attributes of the class.
    std::string rdn = "cn=newentry";
    std::vector<std::pair<std::string, std::string*>> fields = {
        {"Parent DN:", &parentDN}, {"RDN:", &rdn}, {"ObjectClass:", &objectClass},
    };
    std::vector<std::string> mustNames;
    std::vector<std::string> mustVals;
    auto mandatory = getInheritedMandatoryAttrs(*conn_, objectClass);
    // Reserve both vectors up front: `fields` stores pointers into `mustVals`
    // (`&mustVals.back()`), so a later emplace_back reallocation would dangle
    // them and crash the form (use-after-free). Reserving prevents reallocation.
    mustNames.reserve(mandatory.size());
    mustVals.reserve(mandatory.size());
    for (const auto &must : mandatory) {
        if (must == "top") continue;
        mustNames.push_back(must);
        mustVals.emplace_back();
        fields.emplace_back(must + ":", &mustVals.back());
    }
    if (appPopupForm("Add Entry", fields, nullptr) == 0) { setLog("Add cancelled"); return; }

    std::string dn = rdn + "," + parentDN;
    std::map<std::string, std::vector<std::string>> attrs = {
        {"objectClass", {"top", objectClass}},
    };
    // Extract attribute name from RDN
    auto eq = rdn.find('=');
    if (eq != std::string::npos) {
        std::string rdnAttr = rdn.substr(0, eq);
        attrs[rdnAttr] = {rdn.substr(eq + 1)};
    }
    for (size_t i = 0; i < mustNames.size(); i++)
        if (!mustVals[i].empty()) attrs[mustNames[i]] = {mustVals[i]};
    runWriteOp([this, dn, attrs]() { return conn_->addObject(dn, attrs); },
               "Created: " + dn, "Add failed", true);
}

void App::appDuplicateEntry(const std::string &sourceDN) {
    std::string srcDN = sourceDN.empty() ? (tree_ ? tree_->selectedDN() : "") : sourceDN;
    if (srcDN.empty()) { setLog("Duplicate: position cursor on an entry first"); return; }
    std::string parentDN = ldapcore::parentOf(srcDN);
    if (parentDN.empty()) { setLog("Duplicate: entry has no parent (RootDSE)"); return; }

    // Load the source attributes, ask for a new RDN, then re-add under the parent.
    LDAPEntry src = conn_->searchOne(srcDN, "(objectClass=*)", {"*"}, false);
    if (src.attributeNames.empty()) {
        setLog("Duplicate failed: cannot read " + srcDN);
        return;
    }
    std::string rdn = ldapcore::rdnOf(srcDN);
    std::vector<std::pair<std::string, std::string*>> fields = {
        {"Source DN:", &srcDN},
        {"New RDN:", &rdn},
        {"Parent DN:", &parentDN},
    };
    if (appPopupForm("Duplicate Entry", fields, nullptr) == 0) { setLog("Duplicate cancelled"); return; }
    std::string newDN = rdn + "," + parentDN;
    if (newDN == srcDN) { setLog("Duplicate: RDN unchanged"); return; }

    std::map<std::string, std::vector<std::string>> attrs;
    for (const auto &an : src.attributeNames) {
        // Skip server-generated operational attributes and the
        // objectClass list (recomputed from the source below).
        if (an == "objectClass") continue;
        if (isOperationalAttr(an)) continue;
        attrs[an] = src.getAttrs(an);
    }
    attrs["objectClass"] = src.getAttrs("objectClass");
    runWriteOp([this, newDN, attrs]() { return conn_->addObject(newDN, attrs); },
               "Duplicated: " + srcDN + " → " + newDN, "Duplicate failed", true);
}

void App::appAddAttr(const std::string &presetName) {
    std::string dn = tree_ ? tree_->selectedDN() : "";
    if (dn.empty()) { setLog("Add attr: select an entry first"); return; }
    std::string attrName = presetName;
    std::string attrValue;
    std::vector<std::pair<std::string, std::string*>> fields = {
        {"Attribute:", &attrName}, {"Value:", &attrValue},
    };
    if (appPopupForm("Add Attribute", fields, nullptr) == 0) { setLog("Add attr cancelled"); return; }
    if (attrName.empty()) { setLog("Attribute name required"); return; }

    // Lower-case base type (ignore any ;options for the schema lookup).
    diratlas::ldapcore::AttributeDescription ad;
    std::string baseType = attrName;
    if (diratlas::ldapcore::parseAttributeDescription(attrName, ad))
        baseType = ad.type;
    std::string lower;
    for (char c : baseType)
        lower += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

    // Load the entry's objectClasses and the attributes they allow.
    LDAPEntry cur = conn_->searchOne(dn, "(objectClass=*)", {"*"}, false);
    if (cur.attributeNames.empty()) { setLog("Add attr failed: cannot read " + dn); return; }
    std::vector<std::string> ocs = cur.getAttrs("objectClass");

    if (lower == "objectclass") {
        auto allClasses = listObjectClasses(*conn_);
        std::string cls = attrValue;
        std::string clsLower;
        for (char c : cls) clsLower += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        bool known = false;
        for (const auto &c : allClasses) {
            std::string cl;
            for (char x : c) cl += static_cast<char>(std::tolower(static_cast<unsigned char>(x)));
            if (cl == clsLower) { known = true; break; }
        }
        if (!known) {
            setLog("Add objectClass rejected: '" + cls + "' is not defined in the server schema");
            return;
        }
        // Note the MUST attributes the new class requires.
        std::string missing;
        auto need = getInheritedMandatoryAttrs(*conn_, cls);
        std::set<std::string> have;
        for (const auto &an : cur.attributeNames)
            have.insert(an);
        for (const auto &m : need) {
            if (m == "top") continue;
            if (!have.count(m)) {
                if (!missing.empty()) missing += ", ";
                missing += m;
            }
        }
        if (!missing.empty())
            setLog("Adding objectClass '" + cls + "' will require missing attribute(s): " + missing);
        runWriteOp([this, dn, attrName, attrValue]() {
                       return conn_->addAttribute(dn, attrName, {attrValue});
                   },
                   "Added " + attrName + " to " + dn, "Add attr failed", false, true);
        return;
    }

    auto allowed = getAllowedAttrs(*conn_, ocs);
    // The schema names keep their case (olcLogLevel, ...), so compare
    // case-insensitively against the lower-cased type the user typed.
    bool allowedMatch = false;
    if (!allowed.empty()) {
        for (const auto &a : allowed) {
            std::string al;
            for (char c : a)
                al += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            if (al == lower) { allowedMatch = true; break; }
        }
    }
    if (!allowed.empty() && !allowedMatch) {
        std::string ocList;
        for (size_t i = 0; i < ocs.size(); i++) {
            if (i) ocList += ", ";
            ocList += ocs[i];
        }
        setLog("Add rejected: '" + attrName + "' is not allowed by objectClass (" + ocList + ")");
        return;
    }

    // Validate the value against the attribute syntax (Integer, Boolean,
    // time, DN, ...) before sending it; unknown syntaxes are skipped so a
    // server whose schema is not fully published is not wrongly blocked.
    if (attrSchema_.defs.empty())
        attrSchema_ = loadAttrSchema(*conn_);
    std::string syntaxErr = attrSchema_.validateValue(lower, attrValue);
    if (!syntaxErr.empty()) {
        setLog("Add rejected: '" + attrValue.substr(0, 60) + "' for " + attrName +
               " — " + syntaxErr);
        return;
    }

    runWriteOp([this, dn, attrName, attrValue]() {
                   return conn_->addAttribute(dn, attrName, {attrValue});
               },
               "Added " + attrName + " to " + dn, "Add attr failed", false, true);
}

void App::appMoveEntry() {
    std::string dn = tree_ ? tree_->selectedDN() : "";
    if (dn.empty()) { setLog("Move: position cursor on an entry first"); return; }
    std::string rdn = ldapcore::rdnOf(dn);
    std::string newSuperior = ldapcore::parentOf(dn);
    std::vector<std::pair<std::string, std::string*>> fields = {
        {"Entry DN:", &dn}, {"New RDN:", &rdn}, {"New parent:", &newSuperior},
    };
    if (appPopupForm("Rename / Move Entry", fields, nullptr) == 0) { setLog("Move cancelled"); return; }
    if (newSuperior == ldapcore::parentOf(dn)) {
        pendingConfirm_ = "rename:" + dn + "|" + rdn;
        setLog("Rename " + dn + " → " + rdn + "?  [Y]es / [N]o");
    } else {
        pendingConfirm_ = "move:" + dn + "|" + newSuperior;
        setLog("Move " + dn + " under " + newSuperior + "?  [Y]es / [N]o");
    }
}

} // namespace diratlas::tui
