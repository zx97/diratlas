// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Manuel FLURY
//
// This file is part of DirAtlas — an LDAP Directory Explorer.
//
// Licensed under the GNU Affero General Public License v3.0
// (https://www.gnu.org/licenses/agpl-3.0.txt).
//

#pragma once
#include "tui.h"
#include "../ldap_conn.h"
#include <memory>
#include <string>
#include <set>
#include <atomic>
#include <thread>
#include <functional>

namespace diratlas::tui {

class TreeWidget;
class AttrsWidget;

/**
 * @brief Top-level ncurses TUI application.
 *
 * Manages the event loop, panel creation, keyboard dispatch,
 * background worker threads for async LDAP queries, and the
 * menu bar / colour theme system.
 *
 * Thread safety: LDAP operations run on a background thread
 * (worker_). Results are transferred to the main loop via a
 * pending update mechanism (pendingUpdate_ / pendingEntry_)
 * to avoid data races on the AttrsWidget.
 */
class App {
public:
    App();
    ~App();

    /** @brief Initialise ncurses, create windows, load tree root. */
    bool init(LDAPConn &conn, const std::string &initFilter = "",
              const std::string &initBase = "",
              const std::string &serverUri = "",
              const std::string &bindIdentity = "");
    /** @brief Enter the main event loop (returns on quit). */
    int run();
    /** @brief Signal the event loop to exit. */
    void stop() { running_ = false; }

    /** @brief Set a status bar message (repainted next draw cycle). */
    void setStatus(const std::string &msg);
    /** @brief Append a message to the log bar. */
    void setLog(const std::string &msg);

    /** @brief Check whether a background operation was cancelled. */
    bool isCanceled() const { return cancel_.load(); }
    /** @brief Reset the cancel flag for the next operation. */
    void resetCancel() { cancel_.store(false); }

private:
    bool initNCurses();
    void applyTheme(const ColorTheme &t);
    void createWindows();
    void destroyWindows();
    void draw();
    void handleKey(int ch);
    void loadSelectedEntry();
    void expandTreeNode(void *nodePtr);
    void appExportLdif();
    void appDeleteEntry();
    void appAddEntry();
    void appAddAttr();
    void appDeleteAttr();
    void appMoveEntry();
    void appDuplicateEntry(const std::string &sourceDN = "");
    void applyPendingConfirm(char ans);
    /** @brief Run a write operation on the worker thread; reports via pendingLog_.
     *  @param refreshTree Reload the tree after a successful write.
     *  @param reloadEntry Reload the displayed entry after a successful write. */
    void runWriteOp(const std::function<bool()> &op, const std::string &okMsg,
                    const std::string &failMsg, bool refreshTree = false,
                    bool reloadEntry = false);
    int appPopupForm(const std::string &title,
                     std::vector<std::pair<std::string, std::string*>> &fields,
                     bool *checkbox = nullptr);
    /** @brief Scrollable list picker; returns 1 on Enter, 0 on Esc. */
    int appPickList(const std::string &title, const std::vector<std::string> &items,
                    int &sel);
    void drawMenuBar();
    void drawInputBar();
    void drawStatusBar();
    void drawLogBar();

    LDAPConn *conn_{nullptr};
    std::unique_ptr<TreeWidget> tree_;    ///< Tree panel widget
    std::unique_ptr<AttrsWidget> attrs_;  ///< Attributes panel widget

    WINDOW *treeBox_{nullptr};
    WINDOW *attrBox_{nullptr};
    WINDOW *treeWin_{nullptr};
    WINDOW *attrWin_{nullptr};
    WINDOW *headerWin_{nullptr};
    WINDOW *inputWin_{nullptr};
    WINDOW *statusWin_{nullptr};
    WINDOW *logWin_{nullptr};
    WINDOW *menuWin_{nullptr};

    enum Focus { FOCUS_TREE, FOCUS_ATTRS, FOCUS_INPUT };
    Focus focus_{FOCUS_TREE};             ///< Currently focused panel
    bool running_{false};                 ///< Event loop flag
    std::string status_;                  ///< Status bar text
    std::string log_;                     ///< Log bar text
    std::string filter_;                  ///< Active LDAP filter string
    std::string currentDN_;               ///< DN of last-selected entry

    // ── Background operation support ──
    std::atomic<bool> loading_{false};    ///< Background LDAP search in progress
    std::atomic<bool> cancel_{false};     ///< Cancel signal for worker thread
    std::thread worker_;                  ///< Background thread handle
    std::string loadingMsg_;              ///< Message shown during load

    /// When '/' is pressed, this stores the search base DN
    std::string searchBase_;

    /// Clipboard for copy/paste (used from attrs panel)
    std::string clipboard_;

    /// Connection info for status bar
    std::string serverUri_;
    std::string bindIdentity_;

    /// Pending edit confirmation (two-step: Enter edits, 'a' applies)
    std::string pendingEditAttr_;
    std::string pendingEditNew_;
    std::string pendingEditOld_;

    /// Pending destructive operation awaiting y/n confirmation.
    /// Empty = no pending confirmation. Values: "delete:DN", "delattr:DN|ATTR",
    /// "delval:DN|ATTR|VALUE", "rename:DN|NEWRDN".
    std::string pendingConfirm_;

    /// Set by the write worker on success to ask the main loop to refresh.
    std::atomic<bool> pendingRefreshTree_{false};
    std::atomic<bool> pendingReloadEntry_{false};

    // ── Menu / colour theme ──
    int themeIdx_{0};                     ///< Active colour theme index
    int activeMenu_{-1};                  ///< Open menu index (-1 = none)
    int activeMenuItem_{-1};              ///< Highlighted menu item index

    // ── Mouse / splitter ──
    bool draggingSplit_{false};           ///< Dragging the tree/attrs splitter
    int splitRatio_{TREE_RATIO};          ///< Current tree/attrs split ratio

    // ── Pending UI update from worker thread ──
    /// Set true by worker when new entry data is ready for the UI thread
    std::atomic<bool> pendingUpdate_{false};
    LDAPEntry pendingEntry_;              ///< Entry awaiting display
    std::set<std::string> pendingMandatory_;  ///< Mandatory attrs for pending entry
    std::string pendingLog_;              ///< Log message from background operation
};

} // namespace diratlas::tui
