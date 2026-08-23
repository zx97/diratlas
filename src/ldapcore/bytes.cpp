// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Manuel FLURY

#include "bytes.h"

#include <cctype>

namespace diratlas::ldapcore {

std::string bytesToHex(const std::vector<uint8_t> &bytes, bool upper) {
    static const char *lower = "0123456789abcdef";
    static const char *upperHex = "0123456789ABCDEF";
    const char *table = upper ? upperHex : lower;
    std::string out;
    out.reserve(bytes.size() * 2);
    for (uint8_t b : bytes) {
        out += table[b >> 4];
        out += table[b & 0x0F];
    }
    return out;
}

uint32_t readLE32(const std::vector<uint8_t> &b, size_t off) {
    if (off + 4 > b.size()) return 0;
    return static_cast<uint32_t>(b[off]) |
           static_cast<uint32_t>(b[off + 1]) << 8 |
           static_cast<uint32_t>(b[off + 2]) << 16 |
           static_cast<uint32_t>(b[off + 3]) << 24;
}

bool isPrintable(const std::vector<uint8_t> &b) {
    for (uint8_t x : b) {
        // LF, CR and TAB are legitimate text whitespace, not binary markers.
        if (x == '\n' || x == '\r' || x == '\t') continue;
        if (x < 0x20 || x == 0x7F) return false;
    }
    return true;
}

int64_t strToInt(std::string_view s, int64_t fallback) {
    if (s.empty()) return fallback;
    bool neg = false;
    size_t i = 0;
    if (s[0] == '-') { neg = true; i = 1; }
    else if (s[0] == '+') { i = 1; }
    if (i >= s.size()) return fallback;
    uint64_t acc = 0;
    for (; i < s.size(); ++i) {
        if (!std::isdigit(static_cast<unsigned char>(s[i]))) return fallback;
        acc = acc * 10 + static_cast<uint64_t>(s[i] - '0');
        if (acc > static_cast<uint64_t>(INT64_MAX)) return fallback;
    }
    return neg ? -static_cast<int64_t>(acc) : static_cast<int64_t>(acc);
}

uint64_t strToUInt(std::string_view s, uint64_t fallback) {
    if (s.empty()) return fallback;
    uint64_t acc = 0;
    for (char c : s) {
        if (!std::isdigit(static_cast<unsigned char>(c))) return fallback;
        acc = acc * 10 + static_cast<uint64_t>(c - '0');
    }
    return acc;
}

std::string base64Encode(const std::string &data) {
    static const char tbl[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((data.size() + 2) / 3) * 4);
    size_t i = 0;
    for (; i + 3 <= data.size(); i += 3) {
        uint32_t n = (static_cast<unsigned char>(data[i]) << 16) |
                     (static_cast<unsigned char>(data[i + 1]) << 8) |
                     static_cast<unsigned char>(data[i + 2]);
        out += tbl[(n >> 18) & 63];
        out += tbl[(n >> 12) & 63];
        out += tbl[(n >> 6) & 63];
        out += tbl[n & 63];
    }
    size_t rem = data.size() - i;
    if (rem == 1) {
        uint32_t n = static_cast<unsigned char>(data[i]) << 16;
        out += tbl[(n >> 18) & 63];
        out += tbl[(n >> 12) & 63];
        out += "==";
    } else if (rem == 2) {
        uint32_t n = (static_cast<unsigned char>(data[i]) << 16) |
                     (static_cast<unsigned char>(data[i + 1]) << 8);
        out += tbl[(n >> 18) & 63];
        out += tbl[(n >> 12) & 63];
        out += tbl[(n >> 6) & 63];
        out += '=';
    }
    return out;
}

bool ldifSafeValue(const std::string &v) {
    if (v.empty()) return false;
    unsigned char first = static_cast<unsigned char>(v[0]);
    if (first == ' ' || first == ':') return false;
    if (static_cast<unsigned char>(v.back()) == ' ') return false;
    for (unsigned char c : v) {
        if (c < 0x20 || c > 0x7E) return false;
    }
    return true;
}

namespace {
int b64Val(unsigned char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}
} // namespace

std::string base64Decode(const std::string &data) {
    std::string out;
    int acc = 0, bits = 0;
    for (unsigned char c : data) {
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') continue;
        if (c == '=') break;
        int v = b64Val(c);
        if (v < 0) return {};
        acc = (acc << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out += static_cast<char>((acc >> bits) & 0xFF);
        }
    }
    return out;
}

} // namespace diratlas::ldapcore