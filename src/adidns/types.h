// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Manuel FLURY
//
// This file is part of DirAtlas — an LDAP Directory Explorer.
//
// Licensed under the GNU Affero General Public License v3.0
// (https://www.gnu.org/licenses/agpl-3.0.txt).
//
// Originally based on godap (github.com/Macmod/godap) — MIT license.

#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <memory>

namespace diratlas::adidns {

extern const std::map<uint16_t, std::string> DnsRecordTypes;
uint16_t findRecordType(const std::string &typeStr);

struct DcPromoFlag {
    uint32_t value;
    std::string description;
};
extern const std::vector<DcPromoFlag> dcPromoFlags;
std::string findDcPromoDescription(uint32_t value);

struct DNSPropertyId {
    uint32_t id;
    std::string name;
};
extern const std::vector<DNSPropertyId> dnsPropertyIds;
std::string findPropName(uint32_t id);

// DNSRecord stored in LDAP dnsRecord attribute
struct DNSRecord {
    uint16_t dataLength{0};
    uint16_t type{0};
    uint8_t version{0};
    uint8_t rank{0};
    uint16_t flags{0};
    uint32_t serial{0};
    uint32_t ttlSeconds{0};
    uint32_t reserved{0};
    uint32_t timestamp{0};
    std::vector<uint8_t> data;

    std::vector<uint8_t> encode() const;
    bool decode(const std::vector<uint8_t> &bytes);
    std::string printType() const;
    int64_t unixTimestamp() const;
};

struct DNSRecord;
struct DNSProperty;

// Forward declare RecordData interface
struct RecordData {
    virtual ~RecordData() = default;
    virtual void parse(const std::vector<uint8_t> &data) = 0;
    virtual std::vector<uint8_t> encode() const = 0;
};

struct DNSProperty {
    uint32_t dataLength{0};
    uint32_t nameLength{0};
    uint32_t flag{0};
    uint32_t version{0};
    uint32_t id{0};
    std::vector<uint8_t> data;
    uint8_t name{0};

    std::vector<uint8_t> encode() const;
    bool decode(const std::vector<uint8_t> &bytes);
    std::string printFormat(const std::string &timeFormat) const;
};

struct DNSZone {
    std::string dn;
    std::string name;
    std::vector<DNSProperty> props;
};

struct DNSNode {
    std::string dn;
    std::string name;
    std::vector<DNSRecord> records;
};

DNSRecord makeDNSRecord(const RecordData &rec, uint16_t recType, uint32_t ttl);

// Name encoding helpers
std::string parseRpcName(const std::vector<uint8_t> &data, size_t &offset);
bool encodeRpcName(std::vector<uint8_t> &buf, const std::string &name);
std::string parseCountName(const std::vector<uint8_t> &data, size_t &offset);
bool encodeCountName(std::vector<uint8_t> &buf, const std::string &name);

// Record types
struct ZERORecord : RecordData {
    void parse(const std::vector<uint8_t> &data) override {}
    std::vector<uint8_t> encode() const override { return {}; }
};

struct ARecord : RecordData {
    std::string address;
    void parse(const std::vector<uint8_t> &data) override;
    std::vector<uint8_t> encode() const override;
};

struct AAAARecord : RecordData {
    std::string address;
    void parse(const std::vector<uint8_t> &data) override;
    std::vector<uint8_t> encode() const override;
};

struct RecordNodeName : RecordData {
    std::string nameNode;
    void parse(const std::vector<uint8_t> &data) override;
    std::vector<uint8_t> encode() const override;
};

using NSRecord = RecordNodeName;
using MDRecord = RecordNodeName;
using MFRecord = RecordNodeName;
using CNAMERecord = RecordNodeName;
using MBRecord = RecordNodeName;
using MGRecord = RecordNodeName;
using MRRecord = RecordNodeName;
using PTRRecord = RecordNodeName;
using DNAMERecord = RecordNodeName;

struct RecordString : RecordData {
    std::vector<std::string> strData;
    void parse(const std::vector<uint8_t> &data) override;
    std::vector<uint8_t> encode() const override;
};

using HINFORecord = RecordString;
using ISDNRecord = RecordString;
using TXTRecord = RecordString;
using X25Record = RecordString;
using LOCRecord = RecordString;

struct RecordMailError : RecordData {
    std::string mailBX;
    std::string errorMailBX;
    void parse(const std::vector<uint8_t> &data) override;
    std::vector<uint8_t> encode() const override;
};

using MINFORecord = RecordMailError;
using RPRecord = RecordMailError;

struct RecordNamePreference : RecordData {
    uint16_t preference{0};
    std::string exchange;
    void parse(const std::vector<uint8_t> &data) override;
    std::vector<uint8_t> encode() const override;
};

using MXRecord = RecordNamePreference;
using AFSDBRecord = RecordNamePreference;
using RTRecord = RecordNamePreference;

struct SOARecord : RecordData {
    uint32_t serial{0}, refresh{0}, retry{0}, expire{0}, minimumTTL{0};
    std::string namePrimaryServer;
    std::string zoneAdminEmail;
    void parse(const std::vector<uint8_t> &data) override;
    std::vector<uint8_t> encode() const override;
};

struct NULLRecord : RecordData {
    std::vector<uint8_t> rawData;
    void parse(const std::vector<uint8_t> &data) override;
    std::vector<uint8_t> encode() const override;
};

struct WKSRecord : RecordData {
    std::string address;
    uint8_t protocol{0};
    std::vector<uint8_t> bitMask;
    void parse(const std::vector<uint8_t> &data) override;
    std::vector<uint8_t> encode() const override;
};

struct SRVRecord : RecordData {
    uint16_t priority{0}, weight{0}, port{0};
    std::string nameTarget;
    void parse(const std::vector<uint8_t> &data) override;
    std::vector<uint8_t> encode() const override;
};

struct NAPTRRecord : RecordData {
    uint16_t order{0}, preference{0};
    std::string flags, service, substitution, replacement;
    void parse(const std::vector<uint8_t> &data) override;
    std::vector<uint8_t> encode() const override;
};

struct ATMARecord : RecordData {
    uint8_t format{0};
    std::string address;
    void parse(const std::vector<uint8_t> &data) override;
    std::vector<uint8_t> encode() const override;
};

struct WINSRecord : RecordData {
    uint32_t mappingFlag{0}, lookupTimeout{0}, cacheTimeout{0}, winsSrvCount{0};
    std::vector<std::string> winsServers;
    void parse(const std::vector<uint8_t> &data) override;
    std::vector<uint8_t> encode() const override;
};

struct WINSRRecord : RecordData {
    uint32_t mappingFlag{0}, lookupTimeout{0}, cacheTimeout{0};
    std::string nameResultDomain;
    void parse(const std::vector<uint8_t> &data) override;
    std::vector<uint8_t> encode() const override;
};

struct SIGRecord : RecordData {
    uint16_t typeCovered{0};
    uint8_t algorithm{0}, labels{0};
    uint32_t originalTTL{0}, sigExpiration{0}, sigInception{0};
    uint16_t keyTag{0};
    std::string nameSigner;
    std::vector<uint8_t> signatureInfo;
    void parse(const std::vector<uint8_t> &data) override;
    std::vector<uint8_t> encode() const override;
};

using RRSIGRecord = SIGRecord;

// Additional types
struct KEYRecord : RecordData {
    uint16_t flags{0};
    uint8_t protocol{0}, algorithm{0};
    std::vector<uint8_t> key;
    void parse(const std::vector<uint8_t> &data) override;
    std::vector<uint8_t> encode() const override;
};

using DNSKEYRecord = KEYRecord;

struct DSRecord : RecordData {
    uint16_t keyTag{0};
    uint8_t algorithm{0}, digestType{0};
    std::vector<uint8_t> digest;
    void parse(const std::vector<uint8_t> &data) override;
    std::vector<uint8_t> encode() const override;
};

struct NSECRecord : RecordData {
    std::string nameSigner;
    std::vector<uint8_t> nsecBitmap;
    void parse(const std::vector<uint8_t> &data) override;
    std::vector<uint8_t> encode() const override;
};

struct DHCIDRecord : RecordData {
    std::vector<uint8_t> digest;
    void parse(const std::vector<uint8_t> &data) override;
    std::vector<uint8_t> encode() const override;
};

struct NSEC3Record : RecordData {
    uint8_t algorithm{0}, flags{0};
    uint16_t iterations{0};
    uint8_t saltLength{0}, hashLength{0};
    std::vector<uint8_t> salt;
    std::vector<uint8_t> nextHashedOwnerName;
    std::vector<uint8_t> bitmaps;
    void parse(const std::vector<uint8_t> &data) override;
    std::vector<uint8_t> encode() const override;
};

struct NSEC3PARAMRecord : RecordData {
    uint8_t algorithm{0}, flags{0};
    uint16_t iterations{0};
    uint8_t saltLength{0};
    std::vector<uint8_t> salt;
    void parse(const std::vector<uint8_t> &data) override;
    std::vector<uint8_t> encode() const override;
};

struct TLSARecord : RecordData {
    uint8_t certificateUsage{0}, selector{0}, matchingType{0};
    std::vector<uint8_t> certificateAssociationData;
    void parse(const std::vector<uint8_t> &data) override;
    std::vector<uint8_t> encode() const override;
};

} // namespace diratlas::adidns
