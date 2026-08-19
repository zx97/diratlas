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
#include <vector>

namespace diratlas::tui {

/**
 * @brief A single node in the LDAP browser tree.
 *
 * Each node corresponds to an LDAP entry. Children are stored
 * as owning unique_ptrs; parent is a raw pointer for upward traversal.
 */
struct TreeNode {
    std::string name;                                    ///< Display name (RDN + optional emoji)
    std::string dn;                                      ///< Distinguished name of the entry
    std::vector<std::unique_ptr<TreeNode>> children;     ///< Child nodes (owned)
    bool expanded{false};                                ///< Whether children are visible
    bool hasChildren{false};                             ///< Whether the entry has LDAP children
    bool deleted{false};                                 ///< Entry is deleted/tombstoned
    bool disabled{false};                                ///< Account is disabled (UAC bit)
    bool isRootDSE{false};                               ///< The special RootDSE node (empty DN)
    bool isVirtual{false};                               ///< Search result node, cleared on refresh
    std::string loadError;                               ///< Error from last loadChildren (e.g. size limit)
    TreeNode *parent{nullptr};                           ///< Parent node (non-owning)
    int depth{0};                                        ///< Nesting depth (root = 0)
};

/**
 * @brief Tree widget for browsing LDAP directory objects.
 *
 * Displays a hierarchical tree with expand/collapse, emoji prefixes,
 * scrollable viewport, and virtual search-result nodes.
 * Supports background-thread loading via loadChildren().
 */
class TreeWidget {
public:
    explicit TreeWidget(LDAPConn &conn);
    ~TreeWidget() = default;

    /** @brief Render the tree into the given ncurses window. */
    void draw(WINDOW *win, bool focused);
    /** @brief Process keyboard input (navigation, expand/collapse, confirm). */
    bool handleKey(int ch);
    /** @brief Initialise the tree with a root DN and load first-level children. */
    void loadRoot(const std::string &rootDN);
    /** @brief Reload the entire tree from scratch. */
    void refresh();
    /** @brief Invalidate cached window dimensions (call on resize). */
    void resize() { maxY_ = 0; }
    /** @brief Return the DN of the currently selected node. */
    std::string selectedDN() const;
    /** @brief Check if the user pressed Enter on a node (selection confirmed). */
    bool selectionConfirmed() const { return confirmed_; }
    /** @brief Reset the confirmation flag. */
    void clearConfirmed() { confirmed_ = false; }
    /** @brief Get the currently selected TreeNode pointer. */
    TreeNode *currentNode() const { return selected_; }
    /** @brief Compute the widest line across all visible nodes. */
    int maxLineWidth() const;
    /** @brief Number of visible (expanded) nodes. */
    int visibleCount() const { return static_cast<int>(visible_.size()); }
    /** @brief Number of results from the last search. */
    int lastResultCount() const { return lastResultCount_; }
    /** @brief Error message from the last search. */
    std::string lastSearchError() const { return lastSearchError_; }
    /** @brief Error message from the last child load. */
    std::string lastChildError() const { return lastChildError_; }

    /** @brief Run a search and display results as virtual child nodes. */
    void showSearchResults(const std::string &filter, const std::string &baseDN);
    /** @brief Remove all virtual (search result) nodes from the tree. */
    void clearVirtual();

    /// @brief Load children for a node (may be called from background thread).
    TreeNode *loadChildren(TreeNode *node);
    /// @brief Rebuild the linear visible_ vector from the expanded tree.
    void rebuildVisible();
    /// @brief Ensure the selected node is within the visible viewport.
    void ensureVisible();

private:
    /// @brief Recursive helper for rebuildVisible().
    void buildVisibleRecursive(TreeNode *node);

    LDAPConn &conn_;                      ///< LDAP connection reference
    std::unique_ptr<TreeNode> root_;      ///< Root node (RootDSE)
    std::vector<TreeNode*> visible_;      ///< Flattened list of visible nodes
    TreeNode *selected_{nullptr};         ///< Currently selected node
    int scrollOffset_{0};                 ///< Scroll offset in visible_ lines
    int maxY_{0};                         ///< Cached window height
    bool confirmed_{false};               ///< Enter was pressed on the selection
    std::string rootDN_;                  ///< Root DN for this tree
    int lastResultCount_{0};              ///< Count from the last search
    std::string lastSearchError_;         ///< Error from the last search
    std::string lastChildError_;          ///< Error from the last child load
};

} // namespace diratlas::tui
