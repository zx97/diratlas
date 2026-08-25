// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Manuel FLURY
//
// This file is part of DirAtlas — an LDAP Directory Explorer.
//
// Licensed under the GNU Affero General Public License v3.0
// (https://www.gnu.org/licenses/agpl-3.0.txt).
//

#include "tree.h"
#include "../vars.h"
#include "../ldapcore/utf8.h"
#include <ncurses.h>
#include <algorithm>
#include <functional>

namespace {
using diratlas::ldapcore::utf8Decode;
using diratlas::ldapcore::utf8Truncate;

/**
 * @brief Choose an emoji for an LDAP entry based on its objectClass or DN pattern.
 *
 * Matches objectClass names against EmojiMap first, then falls back to
 * DN pattern matching (monitor subtree sections, OU, DC, schema, config).
 */
std::string entryEmoji(const diratlas::LDAPEntry &entry) {
    auto classes = entry.getAttrs("objectClass");
    for (const auto &oc : classes) {
        auto it = diratlas::EmojiMap.find(oc);
        if (it != diratlas::EmojiMap.end())
            return it->second;
    }
    // Fallback by DN
    if (entry.dn.empty()) return "\U0001F333"; // 🌳 root

    // Monitor subtree: emoji by section name
    if (entry.dn.find(",cn=Monitor") != std::string::npos ||
        entry.dn.find(",CN=Monitor") != std::string::npos ||
        entry.dn == "cn=Monitor") {
        auto dnUpper = entry.dn;
        for (auto &c : dnUpper) c = toupper(c);
        if (dnUpper.find("CN=CONNECTIONS") == 0)   return "\U0001F50C"; // 🔌
        if (dnUpper.find("CN=OPERATIONS") == 0)    return "\u2699\uFE0F"; // ⚙️
        if (dnUpper.find("CN=STATISTICS") == 0)    return "\U0001F4CA"; // 📊
        if (dnUpper.find("CN=DATABASE") == 0)      return "\U0001F5C4\uFE0F"; // 🗄️
        if (dnUpper.find("CN=BACKEND") == 0)       return "\U0001F3D7\uFE0F"; // 🏗️
        if (dnUpper.find("CN=THREADS") == 0)       return "\U0001F9F5"; // 🧵
        if (dnUpper.find("CN=TIME") == 0)          return "\U0001F550"; // 🕐
        if (dnUpper.find("CN=CURRENT") == 0)       return "\U0001F504"; // 🔄
        if (dnUpper.find("CN=TOTAL") == 0)         return "\U0001F4C8"; // 📈
        if (dnUpper.find("CN=LOG") == 0)           return "\U0001F4CB"; // 📋
        if (dnUpper.find("CN=LISTENERS") == 0)     return "\U0001F442"; // 👂
        if (dnUpper.find("CN=DNSCACHE") == 0)      return "\U0001F4BE"; // 💾
        if (dnUpper.find("CN=ENTRIES") == 0)       return "\U0001F4DD"; // 📝
        if (dnUpper.find("CN=WAITERS") == 0)       return "\u23F3";    // ⏳
        if (dnUpper.find("CN=CACHE") == 0)         return "\U0001F5B1\uFE0F"; // 🖱️
        return "\U0001F4F1"; // 📱 generic monitor
    }

    if (entry.dn.find("OU=") == 0 || entry.dn.find("ou=") == 0)
        return "\U0001F4C2"; // 📂 folder
    if (entry.dn.find("DC=") == 0 || entry.dn.find("dc=") == 0)
        return "\U0001F310"; // 🌐 globe
    if (entry.dn.find("CN=Schema") == 0 || entry.dn.find("cn=schema") == 0)
        return "\u2699\uFE0F"; // ⚙️ gear
    if (entry.dn.find("CN=config") == 0 || entry.dn.find("cn=Config") == 0)
        return "\u2699\uFE0F"; // ⚙️ gear
    return "";
}

} // anonymous namespace

namespace diratlas::tui {

/** @brief Extract the value portion of the first RDN component (e.g. "uid=foo" → "foo"). */
static std::string rdnValue(const std::string &dn) {
    auto pos = dn.find(',');
    std::string rdn = (pos == std::string::npos) ? dn : dn.substr(0, pos);
    auto eq = rdn.find('=');
    if (eq != std::string::npos)
        return rdn.substr(eq + 1);
    return rdn;
}

TreeWidget::TreeWidget(LDAPConn &conn)
    : conn_(conn) {}

/**
 * @brief Initialise the tree with a root node and load its children.
 *
 * Creates the "RootDSE" root node with isRootDSE=true, then
 * immediately calls loadChildren() to discover naming contexts,
 * config context, monitor context, and subschema subentry.
 */
void TreeWidget::loadRoot(const std::string &rootDN) {
    rootDN_ = rootDN;
    root_ = std::make_unique<TreeNode>();
    root_->dn = rootDN;
    root_->depth = 0;
    root_->hasChildren = true;

    if (rootDN.empty()) {
        // No base given: root is the RootDSE (empty DN), showing naming contexts.
        root_->name = "RootDSE";
        root_->isRootDSE = true;
    } else {
        // Explicit base (-b): the tree starts at the search base itself, not
        // at the RootDSE.  Its children are loaded via a normal onelevel search.
        root_->name = "\U0001F4CC " + rootDN;
        root_->isRootDSE = false;
    }

    loadChildren(root_.get());
    rebuildVisible();

    if (!visible_.empty())
        selected_ = visible_[0];
}

/**
 * @brief Load (or reload) the children of a tree node from LDAP.
 *
 * Special handling for RootDSE nodes: collects namingContexts,
 * configContext, monitorContext, and subschemaSubentry, verifies
 * each is accessible, and assigns emoji prefixes.
 *
 * For normal nodes: performs a ONELEVEL search with standard
 * display attributes, skipping self-referencing and ancestor
 * entries to prevent infinite loops. Adds emoji via entryEmoji(),
 * detects deleted/disabled state. Children are sorted by {N}
 * numeric index first, then alphabetically.
 *
 * @param node The tree node to populate.
 * @return The same node for chaining.
 */
TreeNode *TreeWidget::loadChildren(TreeNode *node) {
    if (!node) return node;

    node->children.clear();

    if (node->isRootDSE) {
        // Collect all contexts from RootDSE
        auto rootEntry = conn_.searchOne("", "(objectClass=*)",
                                          {"namingContexts", "configContext",
                                           "monitorContext", "defaultNamingContext",
                                           "subschemaSubentry"}, false);
        std::vector<std::string> allContexts;

        // namingContexts (main suffixes)
        for (const auto &ctx : rootEntry.getAttrs("namingContexts"))
            allContexts.push_back(ctx);

        // configContext (cn=config)
        auto cfgCtx = rootEntry.getAttr("configContext");
        if (!cfgCtx.empty())
            allContexts.push_back(cfgCtx);

        // monitorContext (cn=Monitor)
        auto monCtx = rootEntry.getAttr("monitorContext");
        if (!monCtx.empty())
            allContexts.push_back(monCtx);

        // subschemaSubentry (schema definition entry)
        auto ssCtx = rootEntry.getAttr("subschemaSubentry");
        if (!ssCtx.empty())
            allContexts.push_back(ssCtx);

        // Add custom base DN from -b option if specified and not already in list
        if (!rootDN_.empty()) {
            bool found = false;
            for (const auto &ctx : allContexts) {
                if (ctx == rootDN_) { found = true; break; }
            }
            if (!found) {
                allContexts.push_back(rootDN_);
            }
        }

        for (const auto &ctx : allContexts) {
            auto child = std::make_unique<TreeNode>();
            child->dn = ctx;
            child->name = ctx;
            child->parent = node;
            child->depth = node->depth + 1;
            // Verify the context is accessible
            std::vector<LDAPEntry> verify;
            bool accessible = conn_.search(ctx, LDAP_SCOPE_BASE,
                                           "(objectClass=*)", {"dn"}, false, verify);
            if (accessible) {
                child->hasChildren = true;
                // Add emoji based on context type
                if (ctx == rootDN_ && !rootDN_.empty())
                    child->name = "\U0001F4CC " + ctx;    // clipboard for custom base
                else if (ctx.find("cn=config") == 0 || ctx.find("CN=Config") == 0)
                    child->name = "\u2699\uFE0F " + ctx;  // gear
                else if (ctx.find("cn=monitor") == 0 || ctx.find("CN=Monitor") == 0)
                    child->name = "\U0001F4CA " + ctx;    // bar chart
                else if (ctx.find("cn=subschema") == 0 || ctx.find("CN=Subschema") == 0)
                    child->name = "\U0001F4D6 " + ctx;    // book
                else
                    child->name = "\U0001F310 " + ctx;    // globe
            } else {
                // Context exposed but not readable with this bind (e.g. AD
                // requires authentication for the suffixes): keep the node
                // visible so the exposed suffixes are not hidden.
                child->hasChildren = false;
                child->loadError = conn_.lastError;
            }
            node->children.push_back(std::move(child));
        }
        node->hasChildren = !node->children.empty();
        return node;
    }

    // Normal LDAP search for children
    // AD-specific attributes (isDeleted, userAccountControl) are only
    // requested on Microsoft AD servers; OpenLDAP has no such attributes.
    std::vector<std::string> attrs = {"name", "cn", "ou", "dc", "uid", "objectClass", "+"};
    if (conn_.flavor == LDAPFlavor::MicrosoftAD) {
        attrs.push_back("isDeleted");
        attrs.push_back("userAccountControl");
    }

    std::vector<LDAPEntry> results;
    bool searchOk = conn_.search(node->dn, LDAP_SCOPE_ONELEVEL, "(objectClass=*)",
                      attrs, false, results);
    if (!searchOk) {
        node->hasChildren = false;
        lastChildError_ = conn_.lastError;
        if (!conn_.lastError.empty()) {
            lastChildError_ += " (" + std::to_string(conn_.lastErrno) + ")";
        }
        return node;
    }
    // Partial results (limit exceeded but some entries returned)
    int lim = conn_.lastErrno;
    if (lim == 4 || lim == 3 || lim == 11) {
        lastChildError_ = conn_.lastError;
        node->loadError = lastChildError_;
    } else {
        lastChildError_.clear();
        node->loadError.clear();
    }

    for (auto &entry : results) {
        // Skip self-referencing entries (chaining can return the queried DN itself)
        if (entry.dn == node->dn)
            continue;

        // Skip ancestors to prevent infinite loops
        bool isAncestor = false;
        for (TreeNode *p = node->parent; p; p = p->parent) {
            if (entry.dn == p->dn) { isAncestor = true; break; }
        }
        if (isAncestor) continue;

        auto child = std::make_unique<TreeNode>();
        child->dn = entry.dn;
        child->parent = node;
        child->depth = node->depth + 1;

        // Show RDN key + value from DN (e.g. "uid=fluryma", "cn=John Doe")
        auto eq = entry.dn.find('=');
        auto comma = entry.dn.find(',');
        if (eq != std::string::npos) {
            std::string rdnPart = (comma == std::string::npos) ? entry.dn : entry.dn.substr(0, comma);
            child->name = rdnPart;
        } else {
            child->name = rdnValue(entry.dn);
        }

        // Add emoji prefix
        std::string emoji = entryEmoji(entry);
        if (!emoji.empty())
            child->name = emoji + " " + child->name;

        child->deleted = (entry.getAttr("isDeleted") == "TRUE");

        auto uac = entry.getAttr("userAccountControl");
        if (!uac.empty()) {
            try {
                uint32_t uacVal = static_cast<uint32_t>(std::stoul(uac));
                child->disabled = (uacVal & 0x0002) != 0;
            } catch (...) {}
        }

        child->hasChildren = true;
        node->children.push_back(std::move(child));
    }

    // Sort children: numeric {N} index first, then alphabetically by name
    std::sort(node->children.begin(), node->children.end(),
        [](const std::unique_ptr<TreeNode> &a, const std::unique_ptr<TreeNode> &b) {
            auto extractIdx = [](const std::string &dn) -> int {
                auto brace = dn.find('{');
                if (brace == std::string::npos) return 0;
                auto close = dn.find('}', brace);
                if (close == std::string::npos) return 0;
                try { return std::stoi(dn.substr(brace + 1, close - brace - 1)); }
                catch (...) { return 0; }
            };
            int ia = extractIdx(a->dn);
            int ib = extractIdx(b->dn);
            if (ia != ib) return ia < ib;
            return a->name < b->name;
        });

    node->hasChildren = !results.empty();
    return node;
}

/// @brief Rebuild the linear visible_ vector from the expanded tree structure.
void TreeWidget::rebuildVisible() {
    visible_.clear();
    if (!root_) return;
    buildVisibleRecursive(root_.get());
}

/// @brief Recursively append expanded nodes to visible_ (depth-first pre-order).
void TreeWidget::buildVisibleRecursive(TreeNode *node) {
    if (!node) return;
    visible_.push_back(node);
    if (node->expanded) {
        for (auto &child : node->children)
            buildVisibleRecursive(child.get());
    }
}

/**
 * @brief Ensure the selected_ node is visible and scrollOffset_ is valid.
 *
 * If selected_ has been removed (e.g. virtual nodes cleared),
 * resets to the first visible node.
 */
void TreeWidget::ensureVisible() {
    if (visible_.empty()) {
        scrollOffset_ = 0;
        return;
    }

    if (!selected_) {
        selected_ = visible_[0];
        scrollOffset_ = 0;
        return;
    }

    auto it = std::find(visible_.begin(), visible_.end(), selected_);
    if (it == visible_.end()) {
        selected_ = visible_[0];
        scrollOffset_ = 0;
        return;
    }

    int idx = static_cast<int>(it - visible_.begin());
    if (idx < scrollOffset_)
        scrollOffset_ = idx;
}

/**
 * @brief Render the tree panel into an ncurses window.
 *
 * Draws all visible (expanded) nodes with indentation based on depth.
 * Each line shows: [+]/[-] expander + emoji + RDN name.
 * Selected row is highlighted with CP_TREE_CURSOR when focused.
 * Deleted and disabled nodes use distinct colour pairs.
 * Clears remaining rows to avoid ghosting.
 */
void TreeWidget::draw(WINDOW *win, bool focused) {
    // Force a full redraw to eliminate ghost characters from collapsed content
    redrawwin(win);
    wbkgd(win, COLOR_PAIR(CP_TREE_NORMAL));
    werase(win);

    int maxX;
    getmaxyx(win, maxY_, maxX);

    ensureVisible();

    int scrollMax = std::max(0, static_cast<int>(visible_.size()) - maxY_);
    if (scrollOffset_ > scrollMax)
        scrollOffset_ = scrollMax;
    if (scrollOffset_ < 0)
        scrollOffset_ = 0;

    if (selected_) {
        auto it = std::find(visible_.begin(), visible_.end(), selected_);
        if (it != visible_.end()) {
            int idx = static_cast<int>(it - visible_.begin());
            if (idx < scrollOffset_)
                scrollOffset_ = idx;
            if (idx >= scrollOffset_ + maxY_)
                scrollOffset_ = std::max(0, idx - maxY_ + 1);
        }
    }

    int y = 0;
    for (int i = scrollOffset_; i < static_cast<int>(visible_.size()) && y < maxY_; i++) {
        TreeNode *node = visible_[i];

        int cp = CP_TREE_NORMAL;
        if (node->deleted)
            cp = CP_TREE_DELETED;
        else if (node->disabled)
            cp = CP_TREE_DISABLED;

        bool isSelected = (node == selected_);

        // Set color pair for this row — wattrset replaces all previous attributes
        if (isSelected && focused)
            wattrset(win, COLOR_PAIR(CP_TREE_CURSOR) | A_BOLD);
        else
            wattrset(win, COLOR_PAIR(cp));

        // Draw the node text
        {
            int indent = node->depth * 2;
            std::string line;
            if (node->hasChildren)
                line += node->expanded ? "[-]" : "[+]";
            else
                line += "   ";
            // Warning emoji if node has a load error
            if (!node->loadError.empty())
                line += " \u26A0\uFE0F";
            line += " " + node->name;
            int avail = maxX - 1 - indent;
            if (avail < 0) avail = 0;
            if (static_cast<int>(line.size()) > avail)
                line = utf8Truncate(line, avail);
            if (!line.empty())
                mvwaddstr(win, y, indent, line.c_str());
        }

        // Reset all attributes so the next row starts clean.
        // wattrset replaces all attributes including color pair.
        wattrset(win, A_NORMAL);

        y++;
    }
    // Clear remaining lines — use explicit spaces to force overwrite
    if (y < maxY_) {
        wattron(win, COLOR_PAIR(CP_TREE_NORMAL));
        for (; y < maxY_; y++) {
            wmove(win, y, 0);
            for (int x = 0; x < maxX; x++)
                waddch(win, ' ');
        }
        wattroff(win, COLOR_PAIR(CP_TREE_NORMAL));
    }
}

/**
 * @brief Process keyboard input for the tree panel.
 *
 * Keys handled:
 *   Up/Down        → navigate
 *   PgUp/PgDn      → jump 10 lines
 *   Right/+        → expand node (loads children if needed)
 *   Left/-         → collapse node or go to parent
 *   Enter          → confirm selection (sets confirmed_ flag)
 *
 * @param ch Key code from wgetch().
 * @return true if the key was consumed, false otherwise.
 */
bool TreeWidget::handleKey(int ch) {
    if (visible_.empty() || !selected_)
        return false;

    auto it = std::find(visible_.begin(), visible_.end(), selected_);
    if (it == visible_.end())
        return false;

    int idx = static_cast<int>(it - visible_.begin());

    switch (ch) {
    case KEY_UP:
        if (idx > 0) {
            selected_ = visible_[idx - 1];
            if (idx - 1 < scrollOffset_)
                scrollOffset_ = idx - 1;
        }
        return true;

    case KEY_DOWN:
        if (idx + 1 < static_cast<int>(visible_.size())) {
            selected_ = visible_[idx + 1];
            if (idx - scrollOffset_ + 1 >= maxY_)
                scrollOffset_++;
        }
        return true;

    case KEY_PPAGE: {
        int target = idx - 10;
        if (target < 0) target = 0;
        if (target >= 0 && target < static_cast<int>(visible_.size())) {
            selected_ = visible_[target];
            scrollOffset_ = target;
        }
        return true;
    }
    case KEY_NPAGE: {
        int target = idx + 10;
        if (target >= static_cast<int>(visible_.size()))
            target = static_cast<int>(visible_.size()) - 1;
        if (target >= 0 && target < static_cast<int>(visible_.size())) {
            selected_ = visible_[target];
            scrollOffset_ = target - maxY_ + 1;
            if (scrollOffset_ < 0) scrollOffset_ = 0;
        }
        return true;
    }

    case KEY_RIGHT:
    case '+':
        if (selected_->hasChildren && !selected_->expanded) {
            if (selected_->children.empty())
                loadChildren(selected_);
            selected_->expanded = true;
            rebuildVisible();
            ensureVisible();
        }
        return true;

    case KEY_LEFT:
    case '-':
        if (selected_->expanded) {
            selected_->expanded = false;
            rebuildVisible();
            ensureVisible();
        } else if (selected_->parent && selected_->parent->parent) {
            selected_ = selected_->parent;
            ensureVisible();
        }
        return true;

    case '\n':
    case '\r':
    case KEY_ENTER:
        confirmed_ = true;
        return true;

    default:
        return false;
    }
}

/**
 * @brief Run an LDAP search and display results as virtual child nodes.
 *
 * Creates a "Search Results (N)" group node under the target subtree.
 * Each result is added as a virtual child with emoji and RDN name.
 * Results are leaves (no further expansion).
 * Previous virtual nodes (including prior search results) are cleared
 * before adding new ones.
 *
 * @param rawFilter LDAP filter string (auto-wrapped in parens if missing).
 * @param baseDN    Search base; if empty, uses the tree root DN.
 */
void TreeWidget::showSearchResults(const std::string &rawFilter, const std::string &baseDN) {
    clearVirtual();
    if (!root_) return;

    // Auto-wrap filter in parentheses if missing
    std::string filter = rawFilter;
    if (filter.find('(') == std::string::npos)
        filter = "(" + filter + ")";

    // Find the target node
    TreeNode *target = root_.get();
    if (!baseDN.empty()) {
        // Walk tree to find the node matching baseDN
        std::function<void(TreeNode*)> find = [&](TreeNode *n) {
            if (!n) return;
            if (n->dn == baseDN) { target = n; return; }
            for (auto &c : n->children) find(c.get());
        };
        find(root_.get());
    }

    // Query LDAP for matching entries under baseDN
    std::vector<LDAPEntry> results;
    bool searchOk = conn_.search(baseDN, LDAP_SCOPE_SUBTREE, filter,
                      {"name", "cn", "ou", "dc", "uid", "objectClass",
                       "isDeleted", "userAccountControl", "+"},
                      false, results);
    if (!searchOk) {
        lastSearchError_ = conn_.lastError;
        if (!conn_.lastError.empty())
            lastSearchError_ += " (" + std::to_string(conn_.lastErrno) + ")";
    } else {
        lastSearchError_.clear();
    }
    lastResultCount_ = static_cast<int>(results.size());

    // Clear any existing virtual search-group node on target
    auto it = target->children.begin();
    while (it != target->children.end()) {
        if ((*it)->isVirtual)
            it = target->children.erase(it);
        else
            ++it;
    }

    // Create a virtual "Search Results" group node
    auto group = std::make_unique<TreeNode>();
    std::string grpName = "\U0001F50D Search Results (" + std::to_string(results.size()) + ")";
    if (!lastSearchError_.empty())
        grpName += " [" + lastSearchError_ + "]";
    group->name = grpName;
    group->dn = baseDN;
    group->parent = target;
    group->depth = target->depth + 1;
    group->isVirtual = true;
    group->hasChildren = true;
    auto *groupPtr = group.get();
    target->children.push_back(std::move(group));

    // Add search results as children of the group node
    for (auto &entry : results) {
        if (entry.dn == baseDN) continue; // skip the base itself

        auto child = std::make_unique<TreeNode>();
        child->dn = entry.dn;
        child->parent = groupPtr;
        child->depth = groupPtr->depth + 1;
        child->isVirtual = true;

        auto eq = entry.dn.find('=');
        auto comma = entry.dn.find(',');
        if (eq != std::string::npos) {
            std::string rdnPart = (comma == std::string::npos) ? entry.dn : entry.dn.substr(0, comma);
            child->name = rdnPart;
        } else {
            child->name = rdnValue(entry.dn);
        }

        std::string emoji = entryEmoji(entry);
        if (!emoji.empty())
            child->name = emoji + " " + child->name;

        child->deleted = (entry.getAttr("isDeleted") == "TRUE");
        auto uac = entry.getAttr("userAccountControl");
        if (!uac.empty()) {
            try {
                uint32_t uacVal = static_cast<uint32_t>(std::stoul(uac));
                child->disabled = (uacVal & 0x0002) != 0;
            } catch (...) {}
        }
        child->hasChildren = false; // search results are leaves

        groupPtr->children.push_back(std::move(child));
    }

    // Expand target and the group node, then rebuild
    target->expanded = true;
    groupPtr->expanded = true;
    rebuildVisible();
    ensureVisible();

    // Select first result if any
    if (!visible_.empty()) selected_ = visible_[0];
}

/**
 * @brief Remove all virtual nodes (search results) from the tree.
 *
 * Recursively purges nodes with isVirtual=true. If the current
 * selection was virtual, moves selection to its parent.
 */
void TreeWidget::clearVirtual() {
    if (!root_) return;

    // Remove all virtual nodes recursively
    std::function<void(TreeNode*)> clean = [&](TreeNode *n) {
        if (!n) return;
        auto &ch = n->children;
        ch.erase(std::remove_if(ch.begin(), ch.end(),
            [](const auto &c) { return c->isVirtual; }), ch.end());
        for (auto &c : ch) clean(c.get());
    };
    clean(root_.get());

    // If current selection is virtual, move to parent
    if (selected_ && selected_->isVirtual) {
        selected_ = selected_->parent ? selected_->parent : root_.get();
    }

    rebuildVisible();
    ensureVisible();
}

/**
 * @brief Reload the entire tree from scratch (clears virtuals, reloads root children).
 */
void TreeWidget::refresh() {
    clearVirtual();
    if (!root_) return;
    root_->children.clear();
    root_->expanded = false;
    loadChildren(root_.get());
    rebuildVisible();
    if (!visible_.empty())
        selected_ = visible_[0];
    scrollOffset_ = 0;
}

/// @brief Compute the maximum line width (depth + indent + name) across all visible nodes.
int TreeWidget::maxLineWidth() const {
    int maxW = 0;
    for (auto *n : visible_) {
        int w = n->depth * 2 + 4 + static_cast<int>(n->name.size());
        if (w > maxW) maxW = w;
    }
    return maxW;
}

/// @brief Return the DN of the currently selected tree node (or empty string).
std::string TreeWidget::selectedDN() const {
    return selected_ ? selected_->dn : "";
}

} // namespace diratlas::tui
