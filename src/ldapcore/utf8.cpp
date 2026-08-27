// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Manuel FLURY

#include "utf8.h"

#include <cwchar>

namespace diratlas::ldapcore {

unsigned utf8Decode(const std::string &s, size_t i, int *len) {
    unsigned char c = static_cast<unsigned char>(s[i]);
    if (c < 0x80) { *len = 1; return c; }
    int n = 0;
    unsigned cp = 0;
    if ((c & 0xE0) == 0xC0)      { n = 2; cp = c & 0x1F; }
    else if ((c & 0xF0) == 0xE0) { n = 3; cp = c & 0x0F; }
    else if ((c & 0xF8) == 0xF0) { n = 4; cp = c & 0x07; }
    else { *len = 1; return c; }
    if (i + n > s.size()) { *len = 1; return c; }
    for (int k = 1; k < n; k++) {
        unsigned char cc = static_cast<unsigned char>(s[i + k]);
        if ((cc & 0xC0) != 0x80) { *len = 1; return c; }
        cp = (cp << 6) | (cc & 0x3F);
    }
    *len = n;
    return cp;
}

int utf8Width(const std::string &s) {
    int w = 0;
    size_t i = 0;
    while (i < s.size()) {
        int l = 0;
        int cw = wcwidth(static_cast<wchar_t>(utf8Decode(s, i, &l)));
        // wcwidth returns -1 for printable chars the C locale does not know
        // (box-drawing, em dash, ...); they still occupy 1 terminal column.
        if (cw < 0) cw = 1;
        w += cw;
        i += static_cast<size_t>(l);
    }
    return w;
}

std::string utf8Truncate(const std::string &s, int maxCols) {
    if (maxCols <= 0) return "";
    size_t i = 0;
    int cols = 0;
    while (i < s.size()) {
        int len = 0;
        int cw = wcwidth(static_cast<wchar_t>(utf8Decode(s, i, &len)));
        if (cw < 0) cw = 1;
        if (cols + cw > maxCols) break;
        i += static_cast<size_t>(len);
        cols += cw;
    }
    return s.substr(0, i);
}

std::vector<std::string> utf8Wrap(const std::string &s, int maxCols) {
    std::vector<std::string> out;
    if (s.empty()) { out.push_back(""); return out; }
    if (maxCols < 1) maxCols = 1;
    size_t i = 0;
    while (i < s.size()) {
        // Build one line. Remember the last space so a long line can break
        // at a word boundary instead of in the middle of a word.
        size_t lineStart = i;
        std::string line;
        int cols = 0;
        size_t lastSpace = std::string::npos;  // index into line (after a space)
        while (i < s.size()) {
            int len = 0;
            int cw = wcwidth(static_cast<wchar_t>(utf8Decode(s, i, &len)));
            if (cw < 0) cw = 1;
            if (cols + cw > maxCols && cols > 0) {
                if (lastSpace != std::string::npos && lastSpace < line.size()) {
                    // Cut after the last space: line keeps chars before it,
                    // i rewinds to just past that space.
                    size_t keep = lastSpace;  // line[lastSpace] is the space
                    i = lineStart + keep + 1;
                    line = line.substr(0, keep);
                }
                break;
            }
            line.append(s, i, static_cast<size_t>(len));
            cols += cw;
            i += static_cast<size_t>(len);
            if (line.back() == ' ') lastSpace = line.size() - 1;
        }
        if (!line.empty() && line.back() == ' ' && i < s.size()) line.pop_back();
        out.push_back(line);
    }
    return out;
}

} // namespace diratlas::ldapcore