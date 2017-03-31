// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UDPNET_H
#define BITCOIN_UDPNET_H

#include <atomic>
#include <stdint.h>
#include <vector>
#include <mutex>

#include <boost/static_assert.hpp>

#include "udpapi.h"

#include "blockencodings.h"
#include "fec.h"
#include "netaddress.h"

// This is largely the API between udpnet and udprelay, see udpapi for the
// external-facing API

// 1 Gbps - DO NOT CHANGE, this determines encoding, see do_send_messages to actually change upload speed
#define NETWORK_TARGET_BYTES_PER_SECOND (1024 * 1024 * 1024 / 8)

static const uint32_t UDP_PROTOCOL_VERSION = (2 << 16) | 2; // Min version 2, current version 2

enum UDPMessageType {
    MSG_TYPE_SYN = 0,
    MSG_TYPE_KEEPALIVE = 1, // aka SYN_ACK
    MSG_TYPE_DISCONNECT = 2,
    MSG_TYPE_BLOCK_HEADER = 3,
    MSG_TYPE_BLOCK_CONTENTS = 4,
    MSG_TYPE_PING = 5,
    MSG_TYPE_PONG = 6,
};

struct __attribute__((packed)) UDPMessageHeader {
    uint64_t chk1;
    uint64_t chk2;
    uint8_t msg_type; // A UDPMessageType
};
BOOST_STATIC_ASSERT_MSG(sizeof(UDPMessageHeader) == 17, "__attribute__((packed)) must work");

// Message body cannot exceed 1173 bytes (1191 bytes in total UDP message contents, with a padding byte in message)
#define MAX_UDP_MESSAGE_LENGTH 1173

enum UDPBlockMessageFlags {
    HAVE_BLOCK = 1,
};

struct __attribute__((packed)) UDPBlockMessage {
    uint64_t hash_prefix; // First 8 bytes of blockhash, interpreted in LE (note that this will not include 0s, those are at the end)
    int32_t  prng_seed;
    uint32_t obj_length; // Size of full FEC-coded data
    uint16_t chunks_sent; // Total chunks including source and repair chunks
    uint16_t chunk_id;
    uint8_t block_flags; // Flags as defined by UDPBlockMessageFlags
    unsigned char data[FEC_CHUNK_SIZE];
};
#define UDP_BLOCK_METADATA_LENGTH (sizeof(UDPBlockMessage) - sizeof(UDPBlockMessage::data))
BOOST_STATIC_ASSERT_MSG(sizeof(UDPBlockMessage) <= MAX_UDP_MESSAGE_LENGTH, "Messages must be <= MAX_UDP_MESSAGE_LENGTH");

struct __attribute__((packed)) UDPMessage {
    UDPMessageHeader header;
    union __attribute__((packed)) {
        unsigned char message[MAX_UDP_MESSAGE_LENGTH + 1];
        uint64_t longint;
        struct UDPBlockMessage block;
    } msg;
};
BOOST_STATIC_ASSERT_MSG(sizeof(UDPMessage) == 1191, "__attribute__((packed)) must work");
#define PACKET_SIZE (sizeof(UDPMessage) + 40 + 8)
BOOST_STATIC_ASSERT_MSG(PACKET_SIZE <= 1280, "All packets must fit in min-MTU for IPv6");
BOOST_STATIC_ASSERT_MSG(sizeof(UDPMessage) == sizeof(UDPMessageHeader) + MAX_UDP_MESSAGE_LENGTH + 1, "UDPMessage should have 1 padding byte");

enum UDPState {
    STATE_INIT = 0, // Indicating the node was just added
    STATE_GOT_SYN = 1, // We received their SYN
    STATE_GOT_SYN_ACK = 1 << 1, // We've received a KEEPALIVE (which they only send after receiving our SYN)
    STATE_INIT_COMPLETE = STATE_GOT_SYN | STATE_GOT_SYN_ACK, // We can now send data to this peer
};

struct PartialBlockData {
    const int64_t timeHeaderRecvd;
    const CService nodeHeaderRecvd;

    std::atomic_bool in_header; // Indicates we are currently downloading header (or block txn)
    std::atomic_bool initialized; // Indicates Init has been called in current in_header state
    std::atomic_bool is_decodeable; // Indicates decoder.DecodeReady() && !in_header

    std::mutex state_mutex;
    // Background thread is preparing to, and is submitting to core
    // This is set with state_mutex held, and afterwards block_data and
    // nodesWithChunksAvailableSet should be treated read-only.
    std::atomic_bool currentlyProcessing;

    uint32_t obj_length; // FEC-coded length of currently-being-download object
    uint32_t chunks_sent;
    std::vector<unsigned char> data_recvd;
    FECDecoder decoder;
    PartiallyDownloadedChunkBlock block_data;

    // nodes with chunks_avail set -> packets that were useful, packets provided
    std::map<CService, std::pair<uint32_t, uint32_t> > nodesWithChunksAvailableSet;

    bool Init(const UDPMessage& msg);
    ReadStatus ProvideHeaderData(const CBlockHeaderAndLengthShortTxIDs& header);
    PartialBlockData(const CService& node, const UDPMessage& header_msg); // Must be a MSG_TYPE_BLOCK_HEADER
    void ReconstructBlockFromDecoder();
};

class ChunksAvailableSet {
private:
    int32_t header_chunk_count;
    bool allSent;
    uint8_t bitset[496]; // We can only track a total of ~4MB of header+block data+fec chunks...should be plenty
public:
    ChunksAvailableSet(bool hasAllChunks) : header_chunk_count(-1), allSent(hasAllChunks) { if (!allSent) memset(bitset, 0, sizeof(bitset)); }
    bool IsHeaderChunkAvailable(uint16_t chunk_id) const {
        if (allSent) return true;
        if (chunk_id / 8 > sizeof(bitset)) return false;
        return ((bitset[chunk_id / 8] >> (chunk_id & 7)) & 1);
    }
    void SetHeaderChunkAvailable(uint16_t chunk_id) {
        if (allSent) return;
        if (chunk_id / 8 > sizeof(bitset)) return;
        bitset[chunk_id / 8]  |= 1 << (chunk_id & 7);
    }
    void SetHeaderDataAndFECChunkCount(uint16_t chunks_sent) { header_chunk_count = chunks_sent; }
    bool IsBlockChunkAvailable(uint16_t chunk_id) const {
        if (allSent) return true;
        if (header_chunk_count == -1) return false;
        uint32_t bitset_id = header_chunk_count + chunk_id;
        if (bitset_id / 8 > sizeof(bitset)) return false;
        return ((bitset[bitset_id / 8] >> (bitset_id & 7)) & 1);
    }
    void SetBlockChunkAvailable(uint16_t chunk_id) {
        if (allSent) return;
        if (header_chunk_count == -1) return;
        uint32_t bitset_id = header_chunk_count + chunk_id;
        if (bitset_id / 8 > sizeof(bitset)) return;
        bitset[bitset_id / 8]  |= 1 << (bitset_id & 7);
    }

    void SetAllAvailable() { allSent = true; }
    bool AreAllAvailable() const { return allSent; }
};

struct UDPConnectionInfo {
    uint64_t local_magic;  // Already LE
    uint64_t remote_magic; // Already LE
    size_t group;
    bool fTrusted;
};

struct UDPConnectionState {
    UDPConnectionInfo connection;
    int state; // Flags from UDPState
    uint32_t protocolVersion;
    int64_t lastSendTime;
    int64_t lastRecvTime;
    int64_t lastPingTime;
    std::map<uint64_t, int64_t> ping_times;
    double last_pings[10];
    unsigned int last_ping_location;
    std::map<uint64_t, ChunksAvailableSet> chunks_avail;

    UDPConnectionState() : state(0), protocolVersion(0), lastSendTime(0), lastRecvTime(0), lastPingTime(0), last_ping_location(0)
        { for (size_t i = 0; i < sizeof(last_pings) / sizeof(double); i++) last_pings[i] = -1; }
};
#define PROTOCOL_VERSION_MIN(ver) (((ver) >> 16) & 0xffff)
#define PROTOCOL_VERSION_CUR(ver) (((ver) >>  0) & 0xffff)
#define PROTOCOL_VERSION_FLAGS(ver) (((ver) >> 32) & 0xffffffff)

extern std::recursive_mutex cs_mapUDPNodes;
extern std::map<CService, UDPConnectionState> mapUDPNodes;

void SendMessage(const UDPMessage& msg, const unsigned int length, const CService& service, const uint64_t magic, size_t group);
void SendMessage(const UDPMessage& msg, const unsigned int length, const std::map<CService, UDPConnectionState>::const_iterator& node);
void DisconnectNode(const std::map<CService, UDPConnectionState>::iterator& it);

#endif
