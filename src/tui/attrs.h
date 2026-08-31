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
    size_t noteOffset{std::string::npos}; ///< Byte offset in @p display where the annotated note starts
    bool operational{false};       ///< True for server-generated operational attributes
    bool mandatory{false};         ///< True if the attribute is MUST per schema
    bool isToggle{false};          ///< True for "[+N more]" / "[hide]" toggle rows
    int numHidden{0};              ///< Number of hidden values behind this toggle
    std::string attrName;          ///< Attribute name this toggle belongs to
};

struct OCSchemaInfo;

/**
 * @brief Determine mandatory attributes for a set of objectClasses by querying the subschema.
 * @return A set of attribute names that are MUST for the given classes.
 */
std::set<std::string> getMandatoryAttrs(const OCSchemaInfo &ocInfo,
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
 * @brief Collect all attributes allowed (MUST ∪ MAY) for the given objectClasses,
 *        walking each class's SUP chain so inherited members are included.
 */
std::set<std::string> getAllowedAttrs(LDAPConn &conn,
                                      const std::vector<std::string> &objectClasses);
/**
 * @brief Return the objectClass kind of a class: "STRUCTURAL", "AUXILIARY",
 *        "ABSTRACT", or "" when unknown.
 */
std::string objectClassKind(LDAPConn &conn, const std::string &className);

/**
 * @brief ObjectClass hierarchy information from the subschema.
 *
 * Used to sort objectClass values by inheritance depth
 * (top → most-derived) in the attributes panel.
 */
struct OCSchemaInfo {
    std::map<std::string, int> depths;             ///< Class name → depth (top=0)
    std::map<std::string, std::string> supMap;     ///< Class name → parent class name
    std::vector<std::string> defs;                 ///< Raw objectClasses definitions
    /** @brief Get depth for a class, defaulting to 99 if unknown. */
    int depth(const std::string &oc) const {
        auto it = depths.find(oc);
        return (it != depths.end()) ? it->second : 99;
    }
};
/** @brief Fetch objectClass schema definitions and build hierarchy depths. */
OCSchemaInfo loadOCSchema(LDAPConn &conn);

/**
 * @brief Schema information about attribute types, loaded from the subschema
 *        `attributeTypes` (RFC 4512). Used to decide which operations are
 *        allowed on a value (e.g. duplicate / add only if multi-valued) and
 *        to validate / compare values (matching rule, syntax).
 */
struct AttrSchemaInfo {
    /// attributeType name (lower-case) → parsed definition.
    std::map<std::string, std::string> defs;
    /// attributeType name (lower-case) → EQUALITY matching rule name/OID.
    std::map<std::string, std::string> equality;
    /// attributeType name (lower-case) → SUBSTR matching rule name/OID.
    std::map<std::string, std::string> substr;
    /// attributeType name (lower-case) → SYNTAX OID.
    std::map<std::string, std::string> syntax;
    /// attributeType name (lower-case) → numeric OID.
    std::map<std::string, std::string> oid;
    /// attributeType name (lower-case) → SUP parent (for inherited
    /// EQUALITY/SYNTAX/SUBSTR, e.g. cn SUP name).
    std::map<std::string, std::string> sup;
    /// ldapSyntaxes OID → human description ("Directory String", ...).
    std::map<std::string, std::string> syntaxDesc;
    /// matchingRules name (lower-case) → definition (OID, SYNTAX, ...).
    std::map<std::string, std::string> matchingRules;
    /// matchingRuleUse: attribute type (lower-case) → matching rule names.
    std::map<std::string, std::set<std::string>> matchingRuleUse;

    /// Whether the named type is defined in the subschema.
    bool known(const std::string &lowerType) const { return defs.count(lowerType) > 0; }
    /// Whether the attribute is SINGLE-VALUE (default: false when unknown).
    bool singleValue(const std::string &lowerType) const;
    /// Whether the attribute is NO-USER-MODIFICATION (default: false).
    bool noUserModification(const std::string &lowerType) const;
    /// Whether the attribute is operational per RFC 4512 (USAGE
    /// directoryOperation / distributedOperation / dSAOperation).
    bool operational(const std::string &lowerType) const;
    /// Whether value comparisons are case-sensitive, from the EQUALITY
    /// matching rule (caseExactMatch → true, caseIgnoreMatch → false,
    /// unknown → false so equal values are not wrongly distinct).
    bool caseSensitive(const std::string &lowerType) const;
    /// Whether the attribute supports substring matching (SUBSTR present or
    /// listed in matchingRuleUse with a substring rule).
    bool supportsSubstring(const std::string &lowerType) const;
    /// Human-readable syntax name of the attribute ("Directory String",
    /// "Integer", ...), from SYNTAX OID + ldapSyntaxes. Empty when unknown.
    std::string syntaxName(const std::string &lowerType) const;
    /// Validate a value against the attribute syntax before sending it to the
    /// server. Returns "" when acceptable (or syntax unknown), otherwise a
    /// short human-readable reason.
    std::string validateValue(const std::string &lowerType,
                              const std::string &value) const;
};
/** @brief Load attributeTypes, ldapSyntaxes, matchingRules and matchingRuleUse
 *         from the server subschema. Returns empty maps when the subschema is
 *         unreachable so callers degrade gracefully. */
AttrSchemaInfo loadAttrSchema(LDAPConn &conn);

/**
 * @brief Syntax-highlight one line of an ACL value (olcAccess/aci) into @p win.
 *
 * Semantic colours: to/by bold dark red, rights green, "none" red, subject
 * selectors yellow, quoted DNs green. Shared with the ACL popup renderer.
 */
void drawAclValue(WINDOW *win, int y, int x, int maxW,
                  const std::string &val, int defaultColor, attr_t defaultAttr);

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
              const OCSchemaInfo *ocInfo = nullptr);
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
    /** @brief All ACL/ACI values of every ACL attribute of the displayed
     *         entry, flattened in entry attribute order. Each entry of the
     *         returned pairs is (attribute name, value). */
    std::vector<std::pair<std::string, std::string>> getAclValuesMerged() const;

    /** @brief Set the server flavour; gates AD-specific attribute formatting. */
    void setFlavor(LDAPFlavor flavor) { flavor_ = flavor; }
    /** @brief Set the attributeTypes schema for schema-driven decisions. */
    void setAttrSchema(const AttrSchemaInfo *schema) { attrSchema_ = schema; }

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
    const AttrSchemaInfo *attrSchema_{nullptr}; ///< attributeTypes schema (owned by App)
};

} // namespace diratlas::tui
