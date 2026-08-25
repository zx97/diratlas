// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Manuel FLURY
//
// UTF-8 helpers used by the display code: decode code points, compute
// display width (wcwidth), truncate and wrap without splitting a character.

#pragma once

#include <string>
#include <vector>

namespace diratlas::ldapcore {

/// @brief Decode the UTF-8 code point starting at s[i].
/// @return The code point; on invalid input the raw byte is returned.
/// @param len Receives the byte length of the sequence (1 for invalid/ASCII).
unsigned utf8Decode(const std::string &s, size_t i, int *len);

/// @brief Display width of a string in terminal columns (wcwidth sum).
int utf8Width(const std::string &s);

/// @brief Truncate s to at most maxCols display columns, never splitting
///        a multi-byte UTF-8 character.
std::string utf8Truncate(const std::string &s, int maxCols);

/// @brief Wrap s into visual lines of at most maxCols display columns,
///        never splitting a multi-byte UTF-8 character.
std::vector<std::string> utf8Wrap(const std::string &s, int maxCols);

} // namespace diratlas::ldapcore