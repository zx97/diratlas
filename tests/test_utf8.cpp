// test_utf8.cpp — unit tests for ldapcore::utf8 display helpers
//
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Manuel FLURY
//
// Regression guards for the display code that used to split multi-byte
// UTF-8 characters (emoji, Cyrillic, Greek) when truncating/wrapping.

#include "../src/ldapcore/utf8.h"
#include <clocale>
#include <cassert>
#include <iostream>
#include <string>
#include <vector>

using diratlas::ldapcore::utf8Decode;
using diratlas::ldapcore::utf8Truncate;
using diratlas::ldapcore::utf8Width;
using diratlas::ldapcore::utf8Wrap;

static int failures = 0;

#define CHECK(cond)                                                          \
    do {                                                                     \
        if (!(cond)) {                                                       \
            std::cerr << "FAIL " << __FILE__ << ":" << __LINE__ << ": "      \
                      << #cond << std::endl;                                 \
            ++failures;                                                      \
        }                                                                    \
    } while (0)

int main() {
    // wcwidth needs a UTF-8 locale; C.UTF-8 is available on the test hosts.
    if (!setlocale(LC_ALL, "C.UTF-8"))
        setlocale(LC_ALL, "C.utf8");

    // utf8Decode
    {
        int len = 0;
        CHECK(utf8Decode("A", 0, &len) == 0x41 && len == 1);
        CHECK(utf8Decode("\xC3\xA9", 0, &len) == 0xE9 && len == 2);         // é
        CHECK(utf8Decode("\xE2\x82\xAC", 0, &len) == 0x20AC && len == 3);   // €
        CHECK(utf8Decode("\xF0\x9F\x8C\x90", 0, &len) == 0x1F310 && len == 4); // 🌐
        CHECK(utf8Decode("\xFF", 0, &len) == 0xFF && len == 1);             // invalid lead
        CHECK(utf8Decode("\xC3" "A", 0, &len) == 0xC3 && len == 1);        // bad continuation
        CHECK(utf8Decode("\xC3", 0, &len) == 0xC3 && len == 1);             // truncated seq
    }

    // utf8Width
    CHECK(utf8Width("") == 0);
    CHECK(utf8Width("abc") == 3);
    CHECK(utf8Width("\xC5\xA1") == 1);          // š (1 column)
    CHECK(utf8Width("\xF0\x9F\x8C\x90") == 2);  // 🌐 (2 columns)
    CHECK(utf8Width("a\xF0\x9F\x8C\x90""b") == 4); // 1+2+1

    // utf8Truncate — never splits a character
    CHECK(utf8Truncate("abc", 2) == "ab");
    CHECK(utf8Truncate("abc", 0) == "");
    CHECK(utf8Truncate("abc", 10) == "abc");
    CHECK(utf8Truncate("a\xF0\x9F\x8C\x90""b", 2) == "a");       // emoji would overflow
    CHECK(utf8Truncate("a\xF0\x9F\x8C\x90""b", 3) == "a\xF0\x9F\x8C\x90"); // fits exactly
    CHECK(utf8Truncate("\xC5\xA1\xC5\xA1", 1) == "\xC5\xA1");    // š š -> 1
    CHECK(utf8Truncate("\xC5\xA1\xC5\xA1", 2) == "\xC5\xA1\xC5\xA1"); // 2 cols

    // utf8Wrap — visual lines by columns, never splitting a char
    {
        auto w = utf8Wrap("abc", 2);
        CHECK(w.size() == 2 && w[0] == "ab" && w[1] == "c");
    }
    {
        auto w = utf8Wrap("", 5);
        CHECK(w.size() == 1 && w[0] == "");
    }
    {
        auto w = utf8Wrap("hello", 2);
        CHECK(w.size() == 3 && w[0] == "he" && w[1] == "ll" && w[2] == "o");
    }
    {
        auto w = utf8Wrap("a\xF0\x9F\x8C\x90""b", 2);
        // "a" (1) then 🌐 (2) overflows -> "a"; then "🌐" (2) fits; "b" alone
        CHECK(w.size() == 3 && w[0] == "a" && w[1] == "\xF0\x9F\x8C\x90" && w[2] == "b");
    }
    {
        auto w = utf8Wrap("\xF0\x9F\x8C\x90", 1);
        CHECK(w.size() == 1 && w[0] == "\xF0\x9F\x8C\x90"); // wide char overflows, still kept
    }
    {
        // Cyrillic (2-byte, 1 column) wraps by columns
        auto w = utf8Wrap("\xD0\x92\xD1\x8A\xD0\xBD", 2); // "Вън"
        CHECK(w.size() == 2 && w[0] == "\xD0\x92\xD1\x8A" && w[1] == "\xD0\xBD");
    }

    if (failures == 0) {
        std::cout << "test_utf8: all checks passed" << std::endl;
        return 0;
    }
    std::cerr << "test_utf8: " << failures << " check(s) failed" << std::endl;
    return 1;
}