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
#include <string>
#include <vector>
#include <set>
#include <map>
#include <utility>

namespace diratlas::tui {

/**
 * @brief A single row in the attribute display panel.
 *
 * Represents one attribute-value pair. Multi-valued attributes
 * may collapse into a single toggle row ("[+N more]") when
 * the number of values exceeds MAX_VISIBLE_VALS.
 */
struct AttrRow {
    std::string name;              ///< Attribute name
    std::string value;             ///< Raw attribute value (used for editing and yank)
    std::string display;           ///< Optional formatted text shown instead of @p value
    bool operational{false};       ///< True for server-generated operational attributes
    bool mandatory{false};         ///< True if the attribute is MUST per schema
    bool isToggle{false};          ///< True for "[+N more]" / "[hide]" toggle rows
    int numHidden{0};              ///< Number of hidden values behind this toggle
    std::string attrName;          ///< Attribute name this toggle belongs to
};

/**
 * @brief Determine mandatory attributes for a set of objectClasses by querying the subschema.
 * @return A set of attribute names that are MUST for the given classes.
 */
std::set<std::string> getMandatoryAttrs(LDAPConn &conn,
                                         const std::vector<std::string> &objectClasses);

/**
 * @brief List every objectClass NAME defined in the server subschema, sorted.
 * @return Sorted unique class names, or empty if the subschema is unreachable.
 */
std::vector<std::string> listObjectClasses(LDAPConn &conn);

/**
 * @brief Collect MUST attributes for one objectClass, walking its SUP chain
 *        so inherited requirements (e.g. person → inetOrgPerson) are included.
 */
std::set<std::string> getInheritedMandatoryAttrs(LDAPConn &conn,
                                                  const std::string &objectClass);

/**
 * @brief ObjectClass hierarchy information from the subschema.
 *
 * Used to sort objectClass values by inheritance depth
 * (top → most-derived) in the attributes panel.
 */
struct OCSchemaInfo {
    std::map<std::string, int> depths;             ///< Class name → depth (top=0)
    std::map<std::string, std::string> supMap;     ///< Class name → parent class name
    /** @brief Get depth for a class, defaulting to 99 if unknown. */
    int depth(const std::string &oc) const {
        auto it = depths.find(oc);
        return (it != depths.end()) ? it->second : 99;
    }
};
/** @brief Fetch objectClass schema definitions and build hierarchy depths. */
OCSchemaInfo loadOCSchema(LDAPConn &conn);

/**
 * @brief Attribute display panel.
 *
 * Shows all attributes of a selected LDAP entry with sorting,
 * syntax highlighting, word wrapping, and timestamp colouring.
 */
class AttrsWidget {
public:
    AttrsWidget() = default;
    ~AttrsWidget() = default;

    /** @brief Display an entry's attributes. */
    void show(const LDAPEntry &entry, const std::set<std::string> &mandatory = {},
              const std::map<std::string, int> *ocDepths = nullptr);
    /** @brief Reload and display the entry at the given DN. */
    void refresh(LDAPConn &conn, const std::string &dn);
    /** @brief Render the attributes panel. */
    void draw(WINDOW *win, bool focused);
    /** @brief Handle keyboard input (navigation, toggle, search, DN jump). */
    bool handleKey(int ch);
    /** @brief Enter/exit search-in-value mode. */
    void setSearchMode(bool on) { searchMode_ = on; if (!on) searchStr_.clear(); }
    /** @brief Whether search mode is active. */
    bool searchMode() const { return searchMode_; }
    /** @brief Accessors for edit mode (used from App). */
    int selectedRow() const { return selected_; }
    int rowCount() const { return static_cast<int>(rows_.size()); }
    std::string getValue(int i) const { return (i >= 0 && i < static_cast<int>(rows_.size())) ? rows_[i].value : ""; }
    std::string getAttrName(int i) const { return (i >= 0 && i < static_cast<int>(rows_.size())) ? rows_[i].name : ""; }
    /** @brief All raw values of the given attribute from the displayed entry. */
    std::vector<std::string> getAttrValues(const std::string &attr) const {
        return entry_.getAttrs(attr);
    }

    /** @brief Set the server flavour; gates AD-specific attribute formatting. */
    void setFlavor(LDAPFlavor flavor) { flavor_ = flavor; }

    /// Per-attribute collapse state (true = collapsed, showing "[+N more]")
    std::map<std::string, bool> collapsed_;

    /// Search mode flag
    bool searchMode_{false};
    /// Current search string
    std::string searchStr_;

    /// Edit mode: F2 on a value enters inline editing
    bool editMode_{false};
    std::string editStr_;
    int editRow_{-1};
    std::string editOrig_;
    int editPos_{0}; ///< cursor position within editStr_

    /// Set by handleKey when Enter is pressed on a value that looks like a DN
    std::string goToDN_;

private:
    /** @brief Choose a colour for timestamp values based on age. */
    int timestampColor(const std::string &attrName, const std::string &value) const;
    /** @brief Save current selection before toggle expand/collapse. */
    void saveTogglePos();
    /** @brief Restore selection after toggle expand/collapse. */
    void restoreTogglePos();

    LDAPEntry entry_;                    ///< The currently displayed entry
    std::vector<AttrRow> rows_;          ///< Flat row list for display
    int scrollOffset_{0};                ///< Visual line scroll offset
    int selected_{0};                    ///< Index into rows_ of the selected row
    int maxNameW_{0};                    ///< Max attribute name width (for column alignment)
    std::string toggleAttr_;            ///< Attribute name saved for toggle position restore
    int toggleOffset_{0};               ///< Value offset within the attribute for position restore
    LDAPFlavor flavor_{LDAPFlavor::MicrosoftAD}; ///< Server flavour; gates AD-specific formatting
};

} // namespace diratlas::tui
