// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Manuel FLURY
//
// This file is part of DirAtlas — an LDAP Directory Explorer.
//
// Licensed under the GNU Affero General Public License v3.0
// (https://www.gnu.org/licenses/agpl-3.0.txt).
//
// Originally based on godap (github.com/Macmod/godap) — MIT license.

#include "types.h"
#include "formats.h"
#include <cstring>
#include <sstream>
#include <ctime>

namespace diratlas::adidns {

const std::map<uint16_t, std::string> DnsRecordTypes = {
    {0x0000, "ZERO"}, {0x0001, "A"}, {0x0002, "NS"},
    {0x0003, "MD"}, {0x0004, "MF"}, {0x0005, "CNAME"},
    {0x0006, "SOA"}, {0x0007, "MB"}, {0x0008, "MG"},
    {0x0009, "MR"}, {0x000A, "NULL"}, {0x000B, "WKS"},
    {0x000C, "PTR"}, {0x000D, "HINFO"}, {0x000E, "MINFO"},
    {0x000F, "MX"}, {0x0010, "TXT"}, {0x0011, "RP"},
    {0x0012, "AFSDB"}, {0x0013, "X25"}, {0x0014, "ISDN"},
    {0x0015, "RT"}, {0x0018, "SIG"}, {0x0019, "KEY"},
    {0x001C, "AAAA"}, {0x001D, "LOC"}, {0x001E, "NXT"},
    {0x0021, "SRV"}, {0x0022, "ATMA"}, {0x0023, "NAPTR"},
    {0x0027, "DNAME"}, {0x002B, "DS"}, {0x002E, "RRSIG"},
    {0x002F, "NSEC"}, {0x0030, "DNSKEY"}, {0x0031, "DHCID"},
    {0x0032, "NSEC3"}, {0x0033, "NSEC3PARAM"}, {0x0034, "TLSA"},
    {0x00FF, "ALL"}, {0xFF01, "WINS"}, {0xFF02, "WINSR"},
};

uint16_t findRecordType(const std::string &typeStr) {
    for (const auto &[k, v] : DnsRecordTypes) {
        if (typeStr == v) return k;
    }
    return 0;
}

const std::vector<DcPromoFlag> dcPromoFlags = {
    {0x00000000, "No change to existing zone storage."},
    {0x00000001, "Zone is to be moved to the DNS domain partition."},
    {0x00000002, "Zone is to be moved to the DNS forest partition."},
};

std::string findDcPromoDescription(uint32_t value) {
    for (const auto &flag : dcPromoFlags) {
        if (flag.value == value) return flag.description;
    }
    return "Unknown DcPromo flag";
}

const std::vector<DNSPropertyId> dnsPropertyIds = {
    {0x00000001, "TYPE"}, {0x00000002, "ALLOW_UPDATE"},
    {0x00000008, "SECURE_TIME"}, {0x00000010, "NOREFRESH_INTERVAL"},
    {0x00000020, "REFRESH_INTERVAL"}, {0x00000040, "AGING_STATE"},
    {0x00000011, "SCAVENGING_SERVERS"}, {0x00000012, "AGING_ENABLED_TIME"},
    {0x00000080, "DELETED_FROM_HOSTNAME"}, {0x00000081, "MASTER_SERVERS"},
    {0x00000082, "AUTO_NS_SERVERS"}, {0x00000083, "DCPROMO_CONVERT"},
    {0x00000090, "SCAVENGING_SERVERS_DA"}, {0x00000091, "MASTER_SERVERS_DA"},
    {0x00000092, "AUTO_NS_SERVERS_DA"}, {0x00000100, "NODE_DBFLAGS"},
};

std::string findPropName(uint32_t id) {
    for (const auto &propId : dnsPropertyIds) {
        if (propId.id == id) return propId.name;
    }
    return "UNKNOWN";
}

// DNSRecord
std::vector<uint8_t> DNSRecord::encode() const {
    std::vector<uint8_t> buf;
    auto append = [&](const auto &val) {
        auto ptr = reinterpret_cast<const uint8_t*>(&val);
        buf.insert(buf.end(), ptr, ptr + sizeof(val));
    };
    append(dataLength);
    append(type);
    buf.push_back(version);
    buf.push_back(rank);
    append(flags);
    append(serial);
    auto ttlBE = __builtin_bswap32(ttlSeconds);
    append(ttlBE);
    append(reserved);
    append(timestamp);
    buf.insert(buf.end(), data.begin(), data.end());
    return buf;
}

bool DNSRecord::decode(const std::vector<uint8_t> &bytes) {
    if (bytes.size() < 20) return false;
    size_t off = 0;
    auto read16 = [&]() -> uint16_t {
        uint16_t v;
        memcpy(&v, &bytes[off], 2); off += 2;
        return v;
    };
    auto read32 = [&]() -> uint32_t {
        uint32_t v;
        memcpy(&v, &bytes[off], 4); off += 4;
        return v;
    };
    dataLength = read16();
    type = read16();
    version = bytes[off++];
    rank = bytes[off++];
    flags = read16();
    serial = read32();
    uint32_t ttlBE;
    memcpy(&ttlBE, &bytes[off], 4); off += 4;
    ttlSeconds = __builtin_bswap32(ttlBE);
    reserved = read32();
    timestamp = read32();
    if (off + dataLength > bytes.size()) return false;
    data.assign(bytes.begin() + off, bytes.begin() + off + dataLength);
    return true;
}

std::string DNSRecord::printType() const {
    auto it = DnsRecordTypes.find(type);
    return (it != DnsRecordTypes.end()) ? it->second : "Unknown";
}

int64_t DNSRecord::unixTimestamp() const {
    uint64_t msTime = static_cast<uint64_t>(timestamp) * 3600;
    return msTimeToUnixTimestamp(msTime);
}

std::vector<uint8_t> DNSProperty::encode() const {
    std::vector<uint8_t> buf;
    auto append = [&](const auto &val) {
        auto ptr = reinterpret_cast<const uint8_t*>(&val);
        buf.insert(buf.end(), ptr, ptr + sizeof(val));
    };
    append(dataLength);
    append(nameLength);
    append(flag);
    append(version);
    append(id);
    buf.insert(buf.end(), data.begin(), data.end());
    buf.push_back(name);
    return buf;
}

bool DNSProperty::decode(const std::vector<uint8_t> &bytes) {
    if (bytes.size() < 20) return false;
    size_t off = 0;
    auto read32 = [&]() -> uint32_t {
        uint32_t v;
        memcpy(&v, &bytes[off], 4); off += 4;
        return v;
    };
    dataLength = read32();
    nameLength = read32();
    flag = read32();
    version = read32();
    id = read32();
    if (off + dataLength > bytes.size()) return false;
    data.assign(bytes.begin() + off, bytes.begin() + off + dataLength);
    off += dataLength;
    name = bytes[off];
    return true;
}

std::string DNSProperty::printFormat(const std::string &timeFormat) const {
    uint64_t propVal = 0;
    if (data.size() >= 8) memcpy(&propVal, data.data(), 8);

    switch (id) {
        case 0x00000001: {
            switch (propVal) {
                case 0: return "CACHE";
                case 1: return "PRIMARY";
                case 2: return "SECONDARY";
                case 3: return "STUB";
                case 4: return "FORWARDER";
                default: return "UNKNOWN";
            }
        }
        case 0x00000002: {
            switch (propVal) {
                case 0: return "None";
                case 1: return "Nonsecure and secure";
                case 2: return "Secure only";
                default: return "Unknown";
            }
        }
        case 0x00000008: {
            int64_t ts = msTimeToUnixTimestamp(propVal);
            if (ts != -1) {
                time_t t = ts;
                struct tm *gmt = gmtime(&t);
                char buf[64];
                strftime(buf, sizeof(buf), timeFormat.c_str(), gmt);
                return buf;
            }
            return "Not specified";
        }
        case 0x00000010: case 0x00000020:
            return formatHours(propVal);
        case 0x00000012: {
            uint64_t msTime = propVal * 3600;
            int64_t ts = msTimeToUnixTimestamp(msTime);
            if (ts != -1) {
                time_t t = ts;
                struct tm *gmt = gmtime(&t);
                char buf[64];
                strftime(buf, sizeof(buf), timeFormat.c_str(), gmt);
                return buf;
            }
            return "Not specified";
        }
        case 0x00000080:
            return std::string(data.begin(), data.end());
        case 0x00000040:
            return (propVal == 1) ? "Enabled" : "Disabled";
        case 0x00000090: case 0x00000091: case 0x00000092: {
            auto addrs = parseAddrArray(data);
            std::string result;
            for (size_t i = 0; i < addrs.size(); i++) {
                if (i > 0) result += ", ";
                result += addrs[i];
            }
            return result;
        }
        case 0x00000083: {
            switch (propVal) {
                case 0: return "No change";
                case 1: return "Move to DNS domain partition";
                case 2: return "Move to DNS forest partition";
                default: return "Unknown";
            }
        }
        case 0x00000082: case 0x00000011: {
            auto addrs = parseIP4Array(data);
            std::string result;
            for (size_t i = 0; i < addrs.size(); i++) {
                if (i > 0) result += ", ";
                result += addrs[i];
            }
            return result;
        }
        default:
            return std::string(data.begin(), data.end());
    }
}

DNSRecord makeDNSRecord(const RecordData &rec, uint16_t recType, uint32_t ttl) {
    uint32_t serial = 1;
    uint32_t msTime = getCurrentMSTime();
    auto data = rec.encode();
    return {
        static_cast<uint16_t>(data.size()), recType,
        0x05, 0xF0, 0x0000,
        serial, ttl,
        0x00000000, msTime, data
    };
}

// Name parsing
std::string parseRpcName(const std::vector<uint8_t> &data, size_t &offset) {
    if (offset >= data.size()) return "";
    uint8_t nameLen = data[offset++];
    if (offset + nameLen > data.size()) return "";
    std::string result(data.begin() + offset, data.begin() + offset + nameLen);
    offset += nameLen;
    return result;
}

bool encodeRpcName(std::vector<uint8_t> &buf, const std::string &name) {
    buf.push_back(static_cast<uint8_t>(name.size()));
    buf.insert(buf.end(), name.begin(), name.end());
    return true;
}

std::string parseCountName(const std::vector<uint8_t> &data, size_t &offset) {
    if (offset + 2 > data.size()) return "";
    offset++; // skip raw name len
    uint8_t labelCnt = data[offset++];
    std::vector<std::string> labels;
    for (uint8_t i = 0; i < labelCnt; i++) {
        if (offset >= data.size()) return "";
        uint8_t labLen = data[offset++];
        if (offset + labLen > data.size()) return "";
        labels.push_back(std::string(data.begin() + offset, data.begin() + offset + labLen));
        offset += labLen;
    }
    offset++; // NULL terminator
    std::string result;
    for (size_t i = 0; i < labels.size(); i++) {
        if (i > 0) result += ".";
        result += labels[i];
    }
    return result;
}

bool encodeCountName(std::vector<uint8_t> &buf, const std::string &name) {
    auto labels = std::vector<std::string>();
    std::string s = name;
    size_t pos = 0;
    std::string token;
    while ((pos = s.find('.')) != std::string::npos) {
        labels.push_back(s.substr(0, pos));
        s.erase(0, pos + 1);
    }
    labels.push_back(s);

    buf.push_back(static_cast<uint8_t>(name.size() + 2));
    buf.push_back(static_cast<uint8_t>(labels.size()));
    for (const auto &label : labels) {
        buf.push_back(static_cast<uint8_t>(label.size()));
        buf.insert(buf.end(), label.begin(), label.end());
    }
    buf.push_back(0);
    return true;
}

// Record implementations
void ARecord::parse(const std::vector<uint8_t> &data) {
    address = parseIP(data);
}
std::vector<uint8_t> ARecord::encode() const {
    std::vector<uint8_t> buf(4);
    // Simple IP string to bytes conversion
    unsigned int a, b, c, d;
    if (sscanf(address.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
        buf[0] = a; buf[1] = b; buf[2] = c; buf[3] = d;
    }
    return buf;
}

void AAAARecord::parse(const std::vector<uint8_t> &data) {
    address = parseIP(data);
}
std::vector<uint8_t> AAAARecord::encode() const {
    std::vector<uint8_t> buf(16);
    // For simplicity, store as-is
    unsigned int parts[16] = {0};
    int n = sscanf(address.c_str(), "%x:%x:%x:%x:%x:%x:%x:%x",
        &parts[0], &parts[1], &parts[2], &parts[3],
        &parts[4], &parts[5], &parts[6], &parts[7]);
    if (n > 0) {
        for (int i = 0; i < 8 && i < n; i++) {
            buf[i*2] = (parts[i] >> 8) & 0xFF;
            buf[i*2+1] = parts[i] & 0xFF;
        }
    }
    return buf;
}

void RecordNodeName::parse(const std::vector<uint8_t> &data) {
    size_t offset = 0;
    nameNode = parseCountName(data, offset);
}
std::vector<uint8_t> RecordNodeName::encode() const {
    std::vector<uint8_t> buf;
    encodeCountName(buf, nameNode);
    return buf;
}

void RecordString::parse(const std::vector<uint8_t> &data) {
    size_t offset = 0;
    while (offset < data.size()) {
        auto s = parseRpcName(data, offset);
        if (!s.empty()) strData.push_back(s);
    }
}
std::vector<uint8_t> RecordString::encode() const {
    std::vector<uint8_t> buf;
    for (const auto &s : strData) {
        encodeRpcName(buf, s);
    }
    return buf;
}

void RecordMailError::parse(const std::vector<uint8_t> &data) {
    size_t offset = 0;
    mailBX = parseCountName(data, offset);
    errorMailBX = parseCountName(data, offset);
}
std::vector<uint8_t> RecordMailError::encode() const {
    std::vector<uint8_t> buf;
    encodeCountName(buf, mailBX);
    encodeCountName(buf, errorMailBX);
    return buf;
}

void RecordNamePreference::parse(const std::vector<uint8_t> &data) {
    if (data.size() < 2) return;
    preference = (data[0] << 8) | data[1];
    size_t offset = 2;
    exchange = parseCountName(data, offset);
}
std::vector<uint8_t> RecordNamePreference::encode() const {
    std::vector<uint8_t> buf;
    buf.push_back((preference >> 8) & 0xFF);
    buf.push_back(preference & 0xFF);
    encodeCountName(buf, exchange);
    return buf;
}

void SOARecord::parse(const std::vector<uint8_t> &data) {
    if (data.size() < 20) return;
    auto r32 = [&](size_t off) { return (data[off] << 24) | (data[off+1] << 16) | (data[off+2] << 8) | data[off+3]; };
    serial = r32(0); refresh = r32(4); retry = r32(8);
    expire = r32(12); minimumTTL = r32(16);
    size_t offset = 20;
    namePrimaryServer = parseCountName(data, offset);
    zoneAdminEmail = parseCountName(data, offset);
}
std::vector<uint8_t> SOARecord::encode() const {
    std::vector<uint8_t> buf;
    auto w32 = [&](uint32_t v) {
        buf.push_back((v >> 24) & 0xFF);
        buf.push_back((v >> 16) & 0xFF);
        buf.push_back((v >> 8) & 0xFF);
        buf.push_back(v & 0xFF);
    };
    w32(serial); w32(refresh); w32(retry); w32(expire); w32(minimumTTL);
    encodeCountName(buf, namePrimaryServer);
    encodeCountName(buf, zoneAdminEmail);
    return buf;
}

void NULLRecord::parse(const std::vector<uint8_t> &data) { rawData = data; }
std::vector<uint8_t> NULLRecord::encode() const { return rawData; }

void WKSRecord::parse(const std::vector<uint8_t> &data) {
    if (data.size() < 5) return;
    address = parseIP(std::vector<uint8_t>(data.begin(), data.begin() + 4));
    protocol = data[4];
    bitMask.assign(data.begin() + 5, data.end());
}
std::vector<uint8_t> WKSRecord::encode() const {
    std::vector<uint8_t> buf;
    unsigned int a,b,c,d;
    if (sscanf(address.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
        buf.push_back(a); buf.push_back(b); buf.push_back(c); buf.push_back(d);
    }
    buf.push_back(protocol);
    buf.insert(buf.end(), bitMask.begin(), bitMask.end());
    return buf;
}

void SRVRecord::parse(const std::vector<uint8_t> &data) {
    if (data.size() < 6) return;
    priority = (data[0] << 8) | data[1];
    weight = (data[2] << 8) | data[3];
    port = (data[4] << 8) | data[5];
    size_t offset = 6;
    nameTarget = parseCountName(data, offset);
}
std::vector<uint8_t> SRVRecord::encode() const {
    std::vector<uint8_t> buf;
    auto w16 = [&](uint16_t v) { buf.push_back((v >> 8) & 0xFF); buf.push_back(v & 0xFF); };
    w16(priority); w16(weight); w16(port);
    encodeCountName(buf, nameTarget);
    return buf;
}

void NAPTRRecord::parse(const std::vector<uint8_t> &data) {
    if (data.size() < 4) return;
    order = (data[0] << 8) | data[1];
    preference = (data[2] << 8) | data[3];
    size_t offset = 4;
    flags = parseRpcName(data, offset);
    service = parseRpcName(data, offset);
    substitution = parseRpcName(data, offset);
    replacement = parseCountName(data, offset);
}
std::vector<uint8_t> NAPTRRecord::encode() const {
    std::vector<uint8_t> buf;
    buf.push_back((order >> 8) & 0xFF); buf.push_back(order & 0xFF);
    buf.push_back((preference >> 8) & 0xFF); buf.push_back(preference & 0xFF);
    encodeRpcName(buf, flags);
    encodeRpcName(buf, service);
    encodeRpcName(buf, substitution);
    encodeCountName(buf, replacement);
    return buf;
}

void ATMARecord::parse(const std::vector<uint8_t> &data) {
    if (data.empty()) return;
    format = data[0];
    address.assign(data.begin() + 1, data.end());
}
std::vector<uint8_t> ATMARecord::encode() const {
    std::vector<uint8_t> buf = {format};
    buf.insert(buf.end(), address.begin(), address.end());
    return buf;
}

void WINSRecord::parse(const std::vector<uint8_t> &data) {
    if (data.size() < 16) return;
    memcpy(&mappingFlag, &data[0], 4);
    memcpy(&lookupTimeout, &data[4], 4);
    memcpy(&cacheTimeout, &data[8], 4);
    memcpy(&winsSrvCount, &data[12], 4);
    for (uint32_t i = 0; i < winsSrvCount && 16 + i * 4 + 4 <= data.size(); i++) {
        winsServers.push_back(parseIP(std::vector<uint8_t>(data.begin() + 16 + i * 4, data.begin() + 20 + i * 4)));
    }
}
std::vector<uint8_t> WINSRecord::encode() const {
    std::vector<uint8_t> buf;
    auto w32 = [&](uint32_t v) { auto p = reinterpret_cast<uint8_t*>(&v); buf.insert(buf.end(), p, p+4); };
    w32(mappingFlag); w32(lookupTimeout); w32(cacheTimeout); w32(winsSrvCount);
    for (const auto &s : winsServers) {
        unsigned int a,b,c,d;
        if (sscanf(s.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
            buf.push_back(a); buf.push_back(b); buf.push_back(c); buf.push_back(d);
        }
    }
    return buf;
}

void WINSRRecord::parse(const std::vector<uint8_t> &data) {
    if (data.size() < 12) return;
    memcpy(&mappingFlag, &data[0], 4);
    memcpy(&lookupTimeout, &data[4], 4);
    memcpy(&cacheTimeout, &data[8], 4);
    size_t offset = 12;
    nameResultDomain = parseCountName(data, offset);
}
std::vector<uint8_t> WINSRRecord::encode() const {
    std::vector<uint8_t> buf;
    auto w32 = [&](uint32_t v) { auto p = reinterpret_cast<uint8_t*>(&v); buf.insert(buf.end(), p, p+4); };
    w32(mappingFlag); w32(lookupTimeout); w32(cacheTimeout);
    encodeCountName(buf, nameResultDomain);
    return buf;
}

void SIGRecord::parse(const std::vector<uint8_t> &data) {
    if (data.size() < 18) return;
    auto r16 = [&](size_t off) { return (data[off] << 8) | data[off+1]; };
    auto r32 = [&](size_t off) { return (data[off]<<24)|(data[off+1]<<16)|(data[off+2]<<8)|data[off+3]; };
    typeCovered = r16(0); algorithm = data[2]; labels = data[3];
    originalTTL = r32(4); sigExpiration = r32(8); sigInception = r32(12);
    keyTag = r16(16);
    size_t offset = 18;
    nameSigner = parseCountName(data, offset);
    signatureInfo.assign(data.begin() + offset, data.end());
}
std::vector<uint8_t> SIGRecord::encode() const {
    std::vector<uint8_t> buf;
    auto w16 = [&](uint16_t v) { buf.push_back((v>>8)&0xFF); buf.push_back(v&0xFF); };
    auto w32 = [&](uint32_t v) { buf.push_back((v>>24)&0xFF); buf.push_back((v>>16)&0xFF); buf.push_back((v>>8)&0xFF); buf.push_back(v&0xFF); };
    w16(typeCovered); buf.push_back(algorithm); buf.push_back(labels);
    w32(originalTTL); w32(sigExpiration); w32(sigInception); w16(keyTag);
    encodeCountName(buf, nameSigner);
    buf.insert(buf.end(), signatureInfo.begin(), signatureInfo.end());
    return buf;
}

void KEYRecord::parse(const std::vector<uint8_t> &data) {
    if (data.size() < 4) return;
    flags = (data[0] << 8) | data[1];
    protocol = data[2]; algorithm = data[3];
    key.assign(data.begin() + 4, data.end());
}
std::vector<uint8_t> KEYRecord::encode() const {
    std::vector<uint8_t> buf;
    buf.push_back((flags >> 8) & 0xFF); buf.push_back(flags & 0xFF);
    buf.push_back(protocol); buf.push_back(algorithm);
    buf.insert(buf.end(), key.begin(), key.end());
    return buf;
}

void DSRecord::parse(const std::vector<uint8_t> &data) {
    if (data.size() < 4) return;
    keyTag = (data[0] << 8) | data[1];
    algorithm = data[2]; digestType = data[3];
    digest.assign(data.begin() + 4, data.end());
}
std::vector<uint8_t> DSRecord::encode() const {
    std::vector<uint8_t> buf;
    buf.push_back((keyTag>>8)&0xFF); buf.push_back(keyTag&0xFF);
    buf.push_back(algorithm); buf.push_back(digestType);
    buf.insert(buf.end(), digest.begin(), digest.end());
    return buf;
}

void NSECRecord::parse(const std::vector<uint8_t> &data) {
    size_t offset = 0;
    nameSigner = parseCountName(data, offset);
    nsecBitmap.assign(data.begin() + offset, data.end());
}
std::vector<uint8_t> NSECRecord::encode() const {
    std::vector<uint8_t> buf;
    encodeCountName(buf, nameSigner);
    buf.insert(buf.end(), nsecBitmap.begin(), nsecBitmap.end());
    return buf;
}

void DHCIDRecord::parse(const std::vector<uint8_t> &data) { digest = data; }
std::vector<uint8_t> DHCIDRecord::encode() const { return digest; }

void NSEC3Record::parse(const std::vector<uint8_t> &data) {
    if (data.size() < 6) return;
    algorithm = data[0]; flags = data[1];
    iterations = (data[2] << 8) | data[3];
    saltLength = data[4]; hashLength = data[5];
    size_t off = 6;
    if (off + saltLength + hashLength > data.size()) return;
    salt.assign(data.begin() + off, data.begin() + off + saltLength);
    off += saltLength;
    nextHashedOwnerName.assign(data.begin() + off, data.begin() + off + hashLength);
    off += hashLength;
    bitmaps.assign(data.begin() + off, data.end());
}
std::vector<uint8_t> NSEC3Record::encode() const {
    std::vector<uint8_t> buf;
    buf.push_back(algorithm); buf.push_back(flags);
    buf.push_back((iterations>>8)&0xFF); buf.push_back(iterations&0xFF);
    buf.push_back(saltLength); buf.push_back(hashLength);
    buf.insert(buf.end(), salt.begin(), salt.end());
    buf.insert(buf.end(), nextHashedOwnerName.begin(), nextHashedOwnerName.end());
    buf.insert(buf.end(), bitmaps.begin(), bitmaps.end());
    return buf;
}

void NSEC3PARAMRecord::parse(const std::vector<uint8_t> &data) {
    if (data.size() < 5) return;
    algorithm = data[0]; flags = data[1];
    iterations = (data[2] << 8) | data[3];
    saltLength = data[4];
    if (5 + saltLength > data.size()) return;
    salt.assign(data.begin() + 5, data.begin() + 5 + saltLength);
}
std::vector<uint8_t> NSEC3PARAMRecord::encode() const {
    std::vector<uint8_t> buf;
    buf.push_back(algorithm); buf.push_back(flags);
    buf.push_back((iterations>>8)&0xFF); buf.push_back(iterations&0xFF);
    buf.push_back(saltLength);
    buf.insert(buf.end(), salt.begin(), salt.end());
    return buf;
}

void TLSARecord::parse(const std::vector<uint8_t> &data) {
    if (data.size() < 3) return;
    certificateUsage = data[0]; selector = data[1]; matchingType = data[2];
    certificateAssociationData.assign(data.begin() + 3, data.end());
}
std::vector<uint8_t> TLSARecord::encode() const {
    std::vector<uint8_t> buf = {certificateUsage, selector, matchingType};
    buf.insert(buf.end(), certificateAssociationData.begin(), certificateAssociationData.end());
    return buf;
}

} // namespace diratlas::adidns
