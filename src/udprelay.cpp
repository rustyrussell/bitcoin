// Copyright (c) 2016 Matt Corallo
// Unlike the rest of Bitcoin Core, this file is
// distributed under the Affero General Public License (AGPL v3)

#include "udprelay.h"

#include "chainparams.h"
#include "util.h"
#include "streams.h"
#include "validation.h"
#include "version.h"

#include <condition_variable>
#include <thread>

#include <boost/thread.hpp>

#define to_millis_double(t) (std::chrono::duration_cast<std::chrono::duration<double, std::chrono::milliseconds::period> >(t).count())

static CService TRUSTED_PEER_DUMMY;
static std::map<std::pair<uint64_t, CService>, std::shared_ptr<PartialBlockData> > mapPartialBlocks;
static std::set<uint64_t> setBlocksRelayed;
// In cases where we receive a block without its previous block, or a block
// which is already (to us) an orphan, we will not get a UDPRelayBlock
// callback. However, we do not want to re-process the still-happening stream
// of packets into more ProcessNewBlock calls, so we have to keep a separate
// set here.
static std::set<uint64_t> setBlocksReceived;

static std::map<std::pair<uint64_t, CService>, std::shared_ptr<PartialBlockData> >::iterator RemovePartialBlock(std::map<std::pair<uint64_t, CService>, std::shared_ptr<PartialBlockData> >::iterator it) {
    uint64_t hash_prefix = it->first.first;
    std::lock_guard<std::mutex> lock(it->second->state_mutex);
    // Note that we do not modify nodesWithChunksAvailableSet, as it might be "read-only" due to currentlyProcessing
    for (const std::pair<CService, std::pair<uint32_t, uint32_t> >& node : it->second->nodesWithChunksAvailableSet) {
        std::map<CService, UDPConnectionState>::iterator nodeIt = mapUDPNodes.find(node.first);
        if (nodeIt == mapUDPNodes.end())
            continue;
        std::map<uint64_t, ChunksAvailableSet>::iterator chunks_avail_it = nodeIt->second.chunks_avail.find(hash_prefix);
        if (chunks_avail_it == nodeIt->second.chunks_avail.end())
            continue; // Peer reconnected at some point
        nodeIt->second.chunks_avail.erase(chunks_avail_it);
    }
    return mapPartialBlocks.erase(it);
}

static void RemovePartialBlock(const std::pair<uint64_t, CService>& key) {
    auto it = mapPartialBlocks.find(key);
    if (it != mapPartialBlocks.end())
        RemovePartialBlock(it);
}

static void RemovePartialBlocks(uint64_t hash_prefix) {
    std::map<std::pair<uint64_t, CService>, std::shared_ptr<PartialBlockData> >::iterator it = mapPartialBlocks.lower_bound(std::make_pair(hash_prefix, TRUSTED_PEER_DUMMY));
    while (it != mapPartialBlocks.end() && it->first.first == hash_prefix)
        it = RemovePartialBlock(it);
}

static void SendMessageToNode(const UDPMessage& msg, unsigned int length, uint64_t hash_prefix, std::map<CService, UDPConnectionState>::iterator it) {
    if ((it->second.state & STATE_INIT_COMPLETE) != STATE_INIT_COMPLETE)
        return;
    const auto chunks_avail_it = it->second.chunks_avail.find(hash_prefix);

    bool use_chunks_avail = chunks_avail_it != it->second.chunks_avail.end();
    if (use_chunks_avail) {
        if (chunks_avail_it->second.AreAllAvailable())
            return;

        if (msg.header.msg_type == MSG_TYPE_BLOCK_HEADER) {
            chunks_avail_it->second.SetHeaderDataAndFECChunkCount(le32toh(msg.msg.block.chunks_sent));
            if (chunks_avail_it->second.IsHeaderChunkAvailable(le32toh(msg.msg.block.chunk_id)))
                return;
        } else if (chunks_avail_it->second.IsBlockChunkAvailable(le32toh(msg.msg.block.chunk_id)))
            return;
    }

    SendMessage(msg, length, it);

    if (use_chunks_avail) {
        if (msg.header.msg_type == MSG_TYPE_BLOCK_HEADER)
            chunks_avail_it->second.SetHeaderChunkAvailable(le32toh(msg.msg.block.chunk_id));
        else if (msg.header.msg_type == MSG_TYPE_BLOCK_CONTENTS)
            chunks_avail_it->second.SetBlockChunkAvailable(le32toh(msg.msg.block.chunk_id));
    }
}

static void SendMessageToAllNodes(const UDPMessage& msg, unsigned int length, uint64_t hash_prefix) {
    for (std::map<CService, UDPConnectionState>::iterator it = mapUDPNodes.begin(); it != mapUDPNodes.end(); it++)
        SendMessageToNode(msg, length, hash_prefix, it);
}

#define DIV_CEIL(a, b) (((a) + (b) - 1) / (b))
static void SendMessageData(UDPMessage& msg, const std::vector<unsigned char>& data, uint64_t hash_prefix, uint16_t chunk_limit=std::numeric_limits<uint16_t>::max()) {
    const size_t msg_chunks = DIV_CEIL(data.size(), FEC_CHUNK_SIZE);

    for (auto it = mapUDPNodes.begin(); it != mapUDPNodes.end(); it++) {
        auto send_it = it;
        for (uint16_t i = 0; i < msg_chunks && i < chunk_limit; i++) {
            msg.msg.block.chunk_id = htole16(i);

            size_t msg_size = i == msg_chunks - 1 ? (data.size() % FEC_CHUNK_SIZE) : sizeof(msg.msg.block.data);
            if (msg_size == 0)
                msg_size = FEC_CHUNK_SIZE;
            memcpy(msg.msg.block.data, &data[i * FEC_CHUNK_SIZE], msg_size);
            if (msg_size != sizeof(msg.msg.block.data))
                memset(&msg.msg.block.data[msg_size], 0, sizeof(msg.msg.block.data) - msg_size);

            SendMessageToNode(msg, sizeof(UDPMessageHeader) + sizeof(UDPBlockMessage), hash_prefix, send_it);
            send_it++;
            if (send_it == mapUDPNodes.end())
                send_it = mapUDPNodes.begin();
        }
    }
}

struct DataFECer {
    size_t fec_chunks;
    std::vector<unsigned char> fec_data;
    FECEncoder enc;
    DataFECer(const std::vector<unsigned char>& data, int32_t of_prng_seed, size_t fec_chunks_in) :
        fec_chunks(fec_chunks_in),
        fec_data(fec_chunks * FEC_CHUNK_SIZE),
        enc(&data, of_prng_seed, &fec_data) {}
};

static void SendFECData(UDPMessage& msg, DataFECer& fec, size_t msg_chunks, uint64_t hash_prefix) {
    assert(fec.fec_chunks > 9);

    for (auto it = mapUDPNodes.begin(); it != mapUDPNodes.end(); it++) {
        auto send_it = it;
        for (uint16_t i = 0; i < fec.fec_chunks; i++) {
            assert(fec.enc.BuildChunk(i)); // TODO: Handle errors?

            msg.msg.block.chunk_id = htole16(i + msg_chunks);
            memcpy(msg.msg.block.data, &fec.fec_data[i * FEC_CHUNK_SIZE], FEC_CHUNK_SIZE);

            SendMessageToNode(msg, sizeof(UDPMessageHeader) + sizeof(UDPBlockMessage), hash_prefix, send_it);
            send_it++;
            if (send_it == mapUDPNodes.end())
                send_it = mapUDPNodes.begin();
        }
    }
}

static void FillBlockMessageHeader(UDPMessage& msg, const uint64_t hash_prefix, UDPMessageType type, const std::vector<unsigned char>& data, size_t fec_chunks, int32_t of_prng_seed) {
    const size_t msg_chunks = DIV_CEIL(data.size(), FEC_CHUNK_SIZE);
    assert(msg_chunks + fec_chunks < std::numeric_limits<uint16_t>::max());

    // First fill in common message elements
    msg.header.msg_type        = type;
    msg.msg.block.hash_prefix  = htole64(hash_prefix);
    msg.msg.block.prng_seed    = htole32(of_prng_seed);
    msg.msg.block.obj_length   = htole32(data.size());
    msg.msg.block.chunks_sent  = htole16(msg_chunks + fec_chunks);
    msg.msg.block.block_flags  = HAVE_BLOCK;
}

static void SendFECedData(const uint256& blockhash, UDPMessageType type, const std::vector<unsigned char>& data, DataFECer& fec, int32_t of_prng_seed) {
    UDPMessage msg;
    uint64_t hash_prefix = blockhash.GetUint64(0);
    const size_t msg_chunks = DIV_CEIL(data.size(), FEC_CHUNK_SIZE);
    FillBlockMessageHeader(msg, hash_prefix, type, data, fec.fec_chunks, of_prng_seed);

    // For header messages, the actual data is more useful.
    // For block contents, the probably generated most chunks from the header + mempool.
    // We send in usefulness-first order
    if (type == MSG_TYPE_BLOCK_HEADER) {
        SendMessageData(msg, data, hash_prefix);
        SendFECData(msg, fec, msg_chunks, hash_prefix);
    } else {
        SendFECData(msg, fec, msg_chunks, hash_prefix);
        SendMessageData(msg, data, hash_prefix);
    }
}

static void SendLimitedDataChunks(const uint256& blockhash, UDPMessageType type, const std::vector<unsigned char>& data, size_t fec_chunks, int32_t of_prng_seed) {
    UDPMessage msg;
    uint64_t hash_prefix = blockhash.GetUint64(0);
    FillBlockMessageHeader(msg, hash_prefix, type, data, fec_chunks, of_prng_seed);

    SendMessageData(msg, data, hash_prefix, 3); // Send 3 packets to each peer, in RR
}

static boost::thread *process_block_thread = NULL;
void UDPRelayBlock(const CBlock& block) {
    std::chrono::steady_clock::time_point start;
    const bool fBench = LogAcceptCategory("bench");
    if (fBench)
        start = std::chrono::steady_clock::now();

    uint256 hashBlock = block.GetHash();
    uint64_t hash_prefix = hashBlock.GetUint64(0);
    std::unique_lock<std::recursive_mutex> lock(cs_mapUDPNodes, std::defer_lock);

    {
        int32_t of_prng_seed = (int32_t)(hashBlock.GetUint64(1) & 0x7fffffff);

        const std::vector<unsigned char> *block_chunks = NULL;
        bool skipEncode = false;
        std::unique_lock<std::mutex> partial_block_lock;
        bool inUDPProcess = process_block_thread && boost::this_thread::get_id() == process_block_thread->get_id();
        if (inUDPProcess) {
            lock.lock();

            auto it = mapPartialBlocks.find(std::make_pair(hash_prefix, TRUSTED_PEER_DUMMY));
            if (it != mapPartialBlocks.end() && it->second->currentlyProcessing) {
                partial_block_lock = std::unique_lock<std::mutex>(it->second->state_mutex); // Locked after cs_mapUDPNodes
                if (it->second->block_data.AreChunksAvailable()) {
                    if (fBench)
                        LogPrintf("UDP: Building FEC chunks from decoded block\n");
                    skipEncode = true;
                    block_chunks = &it->second->block_data.GetCodedBlock();
                } else {
                    partial_block_lock.unlock();
                    lock.unlock();
                }
            }
        }

        std::chrono::steady_clock::time_point initd;
        if (fBench)
            initd = std::chrono::steady_clock::now();

        ChunkCodedBlock *codedBlock = (ChunkCodedBlock*) alloca(sizeof(ChunkCodedBlock));
        std::vector<unsigned char> data;
        VectorOutputStream stream(&data, SER_NETWORK, PROTOCOL_VERSION);
        CBlockHeaderAndLengthShortTxIDs headerAndIDs(block, true);
        stream << headerAndIDs;

        std::chrono::steady_clock::time_point coded;
        if (fBench)
            coded = std::chrono::steady_clock::now();

        DataFECer header_fecer(data, of_prng_seed,
                (NETWORK_TARGET_BYTES_PER_SECOND / 1000 / PACKET_SIZE / 4) + 10); // 1ms/4 nodes + 10 chunks of header FEC

        DataFECer *block_fecer = (DataFECer*) alloca(sizeof(DataFECer));
        size_t data_fec_chunks = 0;
        if (inUDPProcess) {
            // If we're actively receiving UDP packets, go ahead and spend the time to precalculate FEC now,
            // otherwise we want to start getting the header/first block chunks out ASAP
            header_fecer.enc.PrefillChunks();

            if (!skipEncode) {
                new (codedBlock) ChunkCodedBlock(block, headerAndIDs);
                block_chunks = &codedBlock->GetCodedBlock();
            }
            if (!block_chunks->empty()) {
                data_fec_chunks = DIV_CEIL(block_chunks->size(), FEC_CHUNK_SIZE) + 10; //TODO: Pick something different?
                new (block_fecer) DataFECer(*block_chunks, of_prng_seed, data_fec_chunks);
                block_fecer->enc.PrefillChunks();
            }
        }

        std::chrono::steady_clock::time_point feced;
        if (fBench)
            feced = std::chrono::steady_clock::now();

        // We do all the expensive calculations before locking cs_mapUDPNodes
        // so that the forward-packets-without-block logic in HandleBlockMessage
        // continues without interruption as long as possible
        if (!lock)
            lock.lock();

        if (mapUDPNodes.empty())
            return;

        if (setBlocksRelayed.count(hash_prefix))
            return;

        SendFECedData(hashBlock, MSG_TYPE_BLOCK_HEADER, data, header_fecer, of_prng_seed);

        std::chrono::steady_clock::time_point header_sent;
        if (fBench)
            header_sent = std::chrono::steady_clock::now();

        if (!inUDPProcess) { // We sent header before calculating any block stuff
            if (!skipEncode) {
                new (codedBlock) ChunkCodedBlock(block, headerAndIDs);
                block_chunks = &codedBlock->GetCodedBlock();
            }

            // Because we need the coded block's size to init block decoding, it
            // is important we get the first block packet out to peers ASAP. Thus,
            // we go ahead and send the first few non-FEC block packets here.
            if (!block_chunks->empty()) {
                data_fec_chunks = DIV_CEIL(block_chunks->size(), FEC_CHUNK_SIZE) + 10; //TODO: Pick something different?
                SendLimitedDataChunks(hashBlock, MSG_TYPE_BLOCK_CONTENTS, *block_chunks, data_fec_chunks, of_prng_seed);
            }
        }

        std::chrono::steady_clock::time_point block_coded;
        if (fBench)
            block_coded = std::chrono::steady_clock::now();

        if (!inUDPProcess) { // We sent header before calculating any block stuff
            if (!block_chunks->empty()) {
                new (block_fecer) DataFECer(*block_chunks, of_prng_seed, data_fec_chunks);
            }
        }

        std::chrono::steady_clock::time_point block_fec_initd;
        if (fBench)
            block_fec_initd = std::chrono::steady_clock::now();

        // Now (maybe) send the transaction chunks
        if (!block_chunks->empty())
            SendFECedData(hashBlock, MSG_TYPE_BLOCK_CONTENTS, *block_chunks, *block_fecer, of_prng_seed);

        if (fBench) {
            std::chrono::steady_clock::time_point all_sent(std::chrono::steady_clock::now());
            LogPrintf("UDP: Built all FEC chunks for block %s in %lf %lf %lf %lf %lf %lf %lf ms\n", hashBlock.ToString(), to_millis_double(initd - start), to_millis_double(coded - initd), to_millis_double(feced - coded), to_millis_double(header_sent - feced), to_millis_double(block_coded - header_sent), to_millis_double(block_fec_initd - block_coded), to_millis_double(all_sent - block_fec_initd));
            if (!inUDPProcess)
                LogPrintf("UDP: Block %s had serialized size %lu\n", hashBlock.ToString(), GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION));
        } else
            LogPrintf("UDP: Built all FEC chunks for block %s\n", hashBlock.ToString());

        if (!skipEncode)
            codedBlock->~ChunkCodedBlock();

        if (!block_chunks->empty())
            block_fecer->~DataFECer();

        // Destroy partial_block_lock before we RemovePartialBlocks()
    }

    setBlocksRelayed.insert(hash_prefix);
    RemovePartialBlocks(hash_prefix);
}

static std::mutex block_process_mutex;
static std::condition_variable block_process_cv;
static std::atomic_bool block_process_shutdown(false);
static std::vector<std::pair<std::pair<uint64_t, CService>, std::shared_ptr<PartialBlockData> > > block_process_queue;

static void DoBackgroundBlockProcessing(const std::pair<std::pair<uint64_t, CService>, std::shared_ptr<PartialBlockData> >& block_data) {
    // If we just blindly call ProcessNewBlock here, we have a cs_main/cs_mapUDPNodes inversion
    // (actually because fucking P2P code calls everything with cs_main already locked).
    // Instead we pass the processing back to ProcessNewBlockThread without cs_mapUDPNodes
    std::unique_lock<std::mutex> lock(block_process_mutex);
    block_process_queue.emplace_back(block_data);
    lock.unlock();
    block_process_cv.notify_all();
}

static void ProcessBlockThread() {
    const bool fBench = LogAcceptCategory("bench");

    while (true) {
        std::unique_lock<std::mutex> process_lock(block_process_mutex);
        while (block_process_queue.empty() && !block_process_shutdown)
            block_process_cv.wait(process_lock);
        if (block_process_shutdown)
            return;
        // To avoid vector re-allocation we pop_back, so its secretly a stack, shhhhh, dont tell anyone
        std::pair<std::pair<uint64_t, CService>, std::shared_ptr<PartialBlockData> > process_block = block_process_queue.back();
        block_process_queue.pop_back();
        process_lock.unlock();

        std::unique_lock<std::mutex> lock(process_block.second->state_mutex);
        if (process_block.second->is_decodeable || process_block.second->block_data.IsBlockAvailable()) {
            process_block.second->currentlyProcessing = true;
            std::chrono::steady_clock::time_point reconstruct_start;
            if (fBench)
                reconstruct_start = std::chrono::steady_clock::now();

            if (!process_block.second->block_data.IsBlockAvailable()) {
                process_block.second->ReconstructBlockFromDecoder();
                assert(process_block.second->block_data.IsBlockAvailable());
            }

            std::chrono::steady_clock::time_point fec_reconstruct_finished;
            if (fBench)
                fec_reconstruct_finished = std::chrono::steady_clock::now();

            ReadStatus status = process_block.second->block_data.FinalizeBlock();;

            std::chrono::steady_clock::time_point block_finalized;
            if (fBench)
                block_finalized = std::chrono::steady_clock::now();

            if (status != READ_STATUS_OK) {
                lock.unlock();
                std::lock_guard<std::recursive_mutex> udpNodesLock(cs_mapUDPNodes);

                if (status == READ_STATUS_INVALID) {
                    if (process_block.first.second == TRUSTED_PEER_DUMMY)
                        LogPrintf("UDP: Unable to decode block from trusted peer(s), check your trusted peers are behaving well.\n");
                    else {
                        const auto it = mapUDPNodes.find(process_block.first.second);
                        if (it != mapUDPNodes.end())
                            DisconnectNode(it);
                    }
                }
                RemovePartialBlock(process_block.first);
                continue;
            } else {
                std::shared_ptr<const CBlock> pdecoded_block = process_block.second->block_data.GetBlock();
                const CBlock& decoded_block = *pdecoded_block;
                std::string debug_string;
                if (fBench) {
                    uint32_t total_chunks_recvd = 0, total_chunks_used = 0;
                    std::map<CService, std::pair<uint32_t, uint32_t> >& chunksProvidedByNode = process_block.second->nodesWithChunksAvailableSet;
                    for (const std::pair<CService, std::pair<uint32_t, uint32_t> >& provider : chunksProvidedByNode) {
                        total_chunks_recvd += provider.second.second;
                        total_chunks_used += provider.second.first;
                    }
                    debug_string += strprintf("UDP: Block %s reconstructed from %s with %u chunks in %lf ms (%u recvd from %u peers)\n", decoded_block.GetHash().ToString(), process_block.second->nodeHeaderRecvd.ToString(), total_chunks_used, (GetTimeMicros() - process_block.second->timeHeaderRecvd) / 1000.0, total_chunks_recvd, chunksProvidedByNode.size());
                    for (const std::pair<CService, std::pair<uint32_t, uint32_t> >& provider : chunksProvidedByNode)
                        debug_string += strprintf("UDP:    %u/%u used from %s\n", provider.second.first, provider.second.second, provider.first.ToString());
                }

                lock.unlock();

                std::chrono::steady_clock::time_point process_start;
                if (fBench)
                    process_start = std::chrono::steady_clock::now();

                if (!ProcessNewBlock(Params(), pdecoded_block, false, NULL)) {
                    LogPrintf("UDP: Failed to decode block %s\n", decoded_block.GetHash().ToString());
                    std::lock_guard<std::recursive_mutex> udpNodesLock(cs_mapUDPNodes);
                    RemovePartialBlock(process_block.first);
                    continue; // Probably a tx collision generating merkle-tree errors
                }
                if (fBench) {
                    LogPrintf(debug_string);
                    LogPrintf("UDP: Final block processing for %s took %lf %lf %lf %lf ms\n", decoded_block.GetHash().ToString(), to_millis_double(fec_reconstruct_finished - reconstruct_start), to_millis_double(block_finalized - fec_reconstruct_finished), to_millis_double(process_start - block_finalized), to_millis_double(std::chrono::steady_clock::now() - process_start));
                    LogPrintf("UDP: Block %s had serialized size %lu\n", decoded_block.GetHash().ToString(), GetSerializeSize(decoded_block, SER_NETWORK, PROTOCOL_VERSION));
                }

                std::lock_guard<std::recursive_mutex> udpNodesLock(cs_mapUDPNodes);
                RemovePartialBlocks(process_block.first.first); // Ensure we remove even if we didnt UDPRelayBlock()
            }
        } else if (!process_block.second->in_header && process_block.second->initialized) {
            uint32_t mempool_provided_chunks = 0;
            uint32_t total_chunk_count = 0;
            uint256 blockHash;
            bool fDone = process_block.second->block_data.IsIterativeFillDone();
            for (size_t i = 0; !fDone; i++) {
                size_t firstChunkProcessed;
                if (!lock)
                    lock.lock();
                if (!total_chunk_count) {
                    total_chunk_count = process_block.second->block_data.GetChunkCount();
                    blockHash = process_block.second->block_data.GetBlockHash();
                }
                ReadStatus res = process_block.second->block_data.DoIterativeFill(firstChunkProcessed);
                if (res != READ_STATUS_OK) {
                    lock.unlock();
                    std::lock_guard<std::recursive_mutex> udpNodesLock(cs_mapUDPNodes);
                    if (res == READ_STATUS_INVALID) {
                        if (process_block.first.second == TRUSTED_PEER_DUMMY)
                            LogPrintf("UDP: Unable to process mempool for block %s from trusted peer(s), check your trusted peers are behaving well.\n", blockHash.ToString());
                        else {
                            LogPrintf("UDP: Unable to process mempool for block %s from %s, disconnecting\n", blockHash.ToString(), process_block.first.second.ToString());
                            const auto it = mapUDPNodes.find(process_block.first.second);
                            if (it != mapUDPNodes.end())
                                DisconnectNode(it);
                        }
                    } else
                        LogPrintf("UDP: Unable to process mempool for block %s, dropping block\n", blockHash.ToString());
                    RemovePartialBlock(process_block.first);
                    break;
                } else {
                    while (firstChunkProcessed < total_chunk_count && process_block.second->block_data.IsChunkAvailable(firstChunkProcessed)) {
                        if (!process_block.second->decoder.HasChunk(firstChunkProcessed)) {
                            process_block.second->decoder.ProvideChunk(process_block.second->block_data.GetChunk(firstChunkProcessed), firstChunkProcessed);
                            mempool_provided_chunks++;
                        }
                        firstChunkProcessed++;
                    }

                    if (process_block.second->decoder.DecodeReady() || process_block.second->block_data.IsBlockAvailable()) {
                        process_block.second->is_decodeable = true;
                        DoBackgroundBlockProcessing(process_block);
                        break;
                    }
                }
                fDone = process_block.second->block_data.IsIterativeFillDone();
                if (i % 20 == 19) {
                    lock.unlock();
                    std::this_thread::sleep_for(std::chrono::microseconds(1));
                }
            }
            if (lock)
                lock.unlock();
            LogPrintf("UDP: Initialized block %s with %ld/%ld mempool-provided chunks (or more)\n", blockHash.ToString(), mempool_provided_chunks, total_chunk_count);
        }
    }
}

void BlockRecvInit() {
    process_block_thread = new boost::thread(boost::bind(&TraceThread<void (*)()>, "udpprocess", &ProcessBlockThread));
}

void BlockRecvShutdown() {
    if (process_block_thread) {
        block_process_shutdown = true;
        block_process_cv.notify_all();
        process_block_thread->join();
        delete process_block_thread;
        process_block_thread = NULL;
    }
}

// TODO: Use the one from net_processing (with appropriate lock-free-ness)
static std::vector<std::pair<uint256, CTransactionRef>> udpnet_dummy_extra_txn;
ReadStatus PartialBlockData::ProvideHeaderData(const CBlockHeaderAndLengthShortTxIDs& header) {
    assert(in_header);
    in_header = false;
    initialized = false;
    is_decodeable = false;
    return block_data.InitData(header, udpnet_dummy_extra_txn);
}

bool PartialBlockData::Init(const UDPMessage& msg) {
    assert(msg.header.msg_type == MSG_TYPE_BLOCK_HEADER || msg.header.msg_type == MSG_TYPE_BLOCK_CONTENTS);
    obj_length  = msg.msg.block.obj_length;
    chunks_sent = msg.msg.block.chunks_sent;
    if (msg.header.msg_type == MSG_TYPE_BLOCK_HEADER)
        data_recvd.resize(DIV_CEIL(obj_length, sizeof(UDPBlockMessage::data)) * sizeof(UDPBlockMessage::data));
    decoder = FECDecoder(obj_length, chunks_sent, msg.msg.block.prng_seed);
    initialized = true;
    return true;
}

PartialBlockData::PartialBlockData(const CService& node, const UDPMessage& msg) :
        timeHeaderRecvd(GetTimeMicros()), nodeHeaderRecvd(node),
        in_header(true), initialized(false), is_decodeable(false),
        currentlyProcessing(false), block_data(&mempool)
    { assert(Init(msg)); }

void PartialBlockData::ReconstructBlockFromDecoder() {
    assert(decoder.DecodeReady());

    for (uint32_t i = 0; i < DIV_CEIL(obj_length, sizeof(UDPBlockMessage::data)); i++) {
        const void* data_ptr = decoder.GetDataPtr(i);
        assert(data_ptr);

        if (!block_data.IsChunkAvailable(i)) {
            memcpy(block_data.GetChunk(i), data_ptr, sizeof(UDPBlockMessage::data));
            block_data.MarkChunkAvailable(i);
        }
    }

    assert(block_data.IsBlockAvailable());
};

static void BlockMsgHToLE(UDPMessage& msg) {
    msg.msg.block.hash_prefix = htole64(msg.msg.block.hash_prefix);
    msg.msg.block.prng_seed   = htole32(msg.msg.block.prng_seed);
    msg.msg.block.obj_length  = htole32(msg.msg.block.obj_length);
    msg.msg.block.chunks_sent = htole16(msg.msg.block.chunks_sent);
    msg.msg.block.chunk_id    = htole16(msg.msg.block.chunk_id);
}

bool HandleBlockMessage(UDPMessage& msg, size_t length, const CService& node, UDPConnectionState& state) {
    //TODO: There are way too many damn tree lookups here...either cut them down or increase parallelism

    assert(msg.header.msg_type == MSG_TYPE_BLOCK_HEADER || msg.header.msg_type == MSG_TYPE_BLOCK_CONTENTS);

    if (length != sizeof(UDPMessageHeader) + sizeof(UDPBlockMessage)) {
        LogPrintf("UDP: Got invalidly-sized block message from %s\n", node.ToString());
        return false;
    }

    msg.msg.block.hash_prefix = le64toh(msg.msg.block.hash_prefix);
    msg.msg.block.prng_seed   = le32toh(msg.msg.block.prng_seed);
    msg.msg.block.obj_length  = le32toh(msg.msg.block.obj_length);
    msg.msg.block.chunks_sent = le16toh(msg.msg.block.chunks_sent);
    msg.msg.block.chunk_id    = le16toh(msg.msg.block.chunk_id);

    const uint64_t hash_prefix = msg.msg.block.hash_prefix; // Need a reference in a few places, but its packed, so we can't have one directly

    if (msg.msg.block.obj_length > 2000000) {
        LogPrintf("UDP: Got massive obj_length of %u\n", msg.msg.block.obj_length);
        return false;
    }

    if (DIV_CEIL(msg.msg.block.obj_length, FEC_CHUNK_SIZE) > msg.msg.block.chunks_sent) {
        LogPrintf("UDP: Peer %s sent fewer chunks than object length\n", node.ToString());
        return false;
    }

    if (setBlocksRelayed.count(msg.msg.block.hash_prefix) || setBlocksReceived.count(msg.msg.block.hash_prefix))
        return true;

    std::map<uint64_t, ChunksAvailableSet>::iterator chunks_avail_it = state.chunks_avail.find(msg.msg.block.hash_prefix);

    if (chunks_avail_it == state.chunks_avail.end()) {
        if (msg.header.msg_type == MSG_TYPE_BLOCK_HEADER) {
            if (state.chunks_avail.size() > 1 && !state.connection.fTrusted) {
                // Non-trusted nodes can only be forwarding up to 2 blocks at a time
                assert(state.chunks_avail.size() == 2);
                auto first_partial_block_it  = mapPartialBlocks.find(std::make_pair(state.chunks_avail. begin()->first, node));
                assert(first_partial_block_it != mapPartialBlocks.end());
                auto second_partial_block_it = mapPartialBlocks.find(std::make_pair(state.chunks_avail.rbegin()->first, node));
                assert(second_partial_block_it != mapPartialBlocks.end());
                if (first_partial_block_it->second->timeHeaderRecvd < second_partial_block_it->second->timeHeaderRecvd) {
                    state.chunks_avail.erase(first_partial_block_it->first.first);
                    mapPartialBlocks.erase(first_partial_block_it);
                } else {
                    state.chunks_avail.erase(second_partial_block_it->first.first);
                    mapPartialBlocks.erase(second_partial_block_it);
                }
            }
            // Once we add to chunks_avail, we MUST add to mapPartialBlocks->second->nodesWithChunksAvailableSet, or we will leak memory
            chunks_avail_it = state.chunks_avail.insert(std::make_pair(hash_prefix, ChunksAvailableSet(msg.msg.block.block_flags & HAVE_BLOCK))).first;
        } else // Probably stale (ie we just finished reconstructing
            return true;
    }

    if (msg.msg.block.block_flags & HAVE_BLOCK)
        chunks_avail_it->second.SetAllAvailable();
    else {
        // By calling Set*ChunkAvailable before SendMessageToNode's
        // SetHeaderDataAndFECChunkCount call, we will miss the first block packet we
        // receive and re-send that in UDPRelayBlock...this is OK because we'll save
        // more by doing this before the during-process relay below
        if (msg.header.msg_type == MSG_TYPE_BLOCK_HEADER)
            chunks_avail_it->second.SetHeaderChunkAvailable(msg.msg.block.chunk_id);
        else
            chunks_avail_it->second.SetBlockChunkAvailable(msg.msg.block.chunk_id);
    }


    std::map<std::pair<uint64_t, CService>, std::shared_ptr<PartialBlockData> >::iterator it = mapPartialBlocks.find(std::make_pair(hash_prefix, state.connection.fTrusted ? TRUSTED_PEER_DUMMY : node));
    if (it == mapPartialBlocks.end()) {
        if (msg.header.msg_type == MSG_TYPE_BLOCK_HEADER)
            it = mapPartialBlocks.insert(std::make_pair(std::make_pair(hash_prefix, state.connection.fTrusted ? TRUSTED_PEER_DUMMY : node), std::make_shared<PartialBlockData>(node, msg))).first;
        else // Probably stale (ie we just finished reconstructing)
            return true;
    }
    PartialBlockData& block = *it->second;

    std::unique_lock<std::mutex> block_lock(block.state_mutex, std::try_to_lock);

    if (state.connection.fTrusted && (block.is_decodeable || block.currentlyProcessing)) {
        // It takes quite some time to decode the block and check its merkle tree
        // (10+ms) due to lots of SHA256 activity...
        // Thus, while the block is processing in ProcessNewBlockThread, we
        // continue forwarding chunks we received from trusted peers
        BlockMsgHToLE(msg);
        msg.msg.block.block_flags = HAVE_BLOCK;
        SendMessageToAllNodes(msg, length, hash_prefix);
        return true;
    }

    if (!block_lock)
        block_lock.lock();

    // currentlyProcessing must come before any chunk-accessors in block.block_data
    // Additionally, IsBlockAvailable protects us from processing anything in the
    // time between when we submit the block and when the background thread picks it up.
    // Note that there is a crash there as well if we do not, for mempool-only blocks
    if ((block.is_decodeable || block.currentlyProcessing) || (!block.in_header && block.block_data.IsBlockAvailable()))
        return true;

    std::map<CService, std::pair<uint32_t, uint32_t> >::iterator usefulChunksFromNodeIt =
            block.nodesWithChunksAvailableSet.insert(std::make_pair(node, std::make_pair(0, 0))).first;
    usefulChunksFromNodeIt->second.second++;

    if (msg.header.msg_type == MSG_TYPE_BLOCK_HEADER && !block.in_header) {
        if (state.connection.fTrusted) {
            // Keep forwarding on header packets to our peers to make sure they
            // get the whole header.
            BlockMsgHToLE(msg);
            msg.msg.block.block_flags = 0;
            SendMessageToAllNodes(msg, length, hash_prefix);
        }
        return true;
    }
    if (msg.header.msg_type == MSG_TYPE_BLOCK_CONTENTS && block.in_header) {
        // Either we're getting packets out of order and wasting this packet,
        // or we didnt get enough header and will fail download anyway
        return true;
    }

    if (msg.header.msg_type == MSG_TYPE_BLOCK_CONTENTS && !block.initialized) {
        if (!block.Init(msg)) {
            LogPrintf("UDP: Got block contents that couldn't match header for block id %lu\n", msg.msg.block.hash_prefix);
            return true;
        }
        DoBackgroundBlockProcessing(*it); // Kick off mempool scan (waits on us to unlock block_lock)
    }

    if (msg.msg.block.obj_length  != block.obj_length ||
        msg.msg.block.chunks_sent != block.chunks_sent) {
        // Duplicate hash_prefix or bad trusted peer
        LogPrintf("UDP: Got wrong obj_length/chunsk_sent for block id %lu from peer %s! Check your trusted peers are behaving well\n", msg.msg.block.hash_prefix, node.ToString());
        return true;
    }

    if (msg.msg.block.chunk_id > block.chunks_sent) {
        LogPrintf("UDP: Got chunk out of range from %s\n", node.ToString());
        return false;
    }

    if (block.decoder.HasChunk(msg.msg.block.chunk_id))
        return true;

    if (msg.header.msg_type == MSG_TYPE_BLOCK_CONTENTS &&
            msg.msg.block.chunk_id < block.block_data.GetChunkCount()) {
        assert(!block.block_data.IsChunkAvailable(msg.msg.block.chunk_id)); // HasChunk should have returned false, then
        memcpy(block.block_data.GetChunk(msg.msg.block.chunk_id), msg.msg.block.data, sizeof(UDPBlockMessage::data));
        block.block_data.MarkChunkAvailable(msg.msg.block.chunk_id);
    }
    //TODO: Also pre-copy header data into data_recvd here, if its a non-FEC chunk

    if (!block.decoder.ProvideChunk(msg.msg.block.data, msg.msg.block.chunk_id)) {
        // Not actually sure what can cause this, so we don't disconnect here
        LogPrintf("UDP: FEC chunk decode failed for chunk %d from block %lu from %s\n", msg.msg.block.chunk_id, msg.msg.block.hash_prefix, node.ToString());
        return true;
    }

    usefulChunksFromNodeIt->second.first++;

    if (state.connection.fTrusted) {
        BlockMsgHToLE(msg);
        msg.msg.block.block_flags = 0;
        SendMessageToAllNodes(msg, length, hash_prefix);
    }

    if (block.decoder.DecodeReady()) {
        if (block.in_header) {
            const bool fBench = LogAcceptCategory("bench");
            std::chrono::steady_clock::time_point decode_start;
            if (fBench)
                decode_start = std::chrono::steady_clock::now();

            for (uint32_t i = 0; i < DIV_CEIL(block.obj_length, sizeof(UDPBlockMessage::data)); i++) {
                const void* data_ptr = block.decoder.GetDataPtr(i);
                assert(data_ptr);

                memcpy(&block.data_recvd[i * sizeof(UDPBlockMessage::data)], data_ptr, sizeof(UDPBlockMessage::data));
            }

            std::chrono::steady_clock::time_point data_copied;
            if (fBench)
                data_copied = std::chrono::steady_clock::now();

            CBlockHeaderAndLengthShortTxIDs header;
            try {
                CDataStream stream(block.data_recvd, SER_NETWORK, PROTOCOL_VERSION);
                stream >> header;
            } catch (std::ios_base::failure& e) {
                LogPrintf("UDP: Failed to decode received header and short txids from %s\n", node.ToString());
                return false;
            }
            std::chrono::steady_clock::time_point header_deserialized;
            if (fBench)
                header_deserialized = std::chrono::steady_clock::now();

            ReadStatus decode_status = block.ProvideHeaderData(header);
            if (decode_status == READ_STATUS_INVALID) {
                LogPrintf("UDP: Got invalid header and short txids from %s\n", node.ToString());
                return false;
            } else if (decode_status == READ_STATUS_FAILED) {
                LogPrintf("UDP: Failed to read header and short txids from %s\n", node.ToString());
                return true;
            }
            if (fBench) {
                std::chrono::steady_clock::time_point header_provided(std::chrono::steady_clock::now());
                LogPrintf("UDP: Got full header and shorttxids from %s in %lf %lf %lf ms\n", node.ToString(), to_millis_double(data_copied - decode_start), to_millis_double(header_deserialized - data_copied), to_millis_double(header_provided - header_deserialized));
            } else
                LogPrintf("UDP: Got full header and shorttxids from %s\n", node.ToString());

            if (block.block_data.IsBlockAvailable())
                block.is_decodeable = true;
        } else
            block.is_decodeable = true;

        if (block.is_decodeable) {
            // We do not RemovePartialBlock as we want ChunkAvailableSets to be there when UDPRelayBlock gets called
            // from inside ProcessBlockThread, so after we notify the ProcessNewBlockThread we cannot access block.
            block_lock.unlock();
            DoBackgroundBlockProcessing(*it); // Decode block and call ProcessNewBlock
            // Make sure we throw out any future packets for this block
            setBlocksReceived.insert(msg.msg.block.hash_prefix);
        }
    }

    return true;
}

void ProcessDownloadTimerEvents() {
    std::unique_lock<std::recursive_mutex> lock(cs_mapUDPNodes);
    for (auto it = mapPartialBlocks.begin(); it != mapPartialBlocks.end();) {
        if (it->second->timeHeaderRecvd < GetTimeMicros() - 1000 * 1000 * 1000)
            it = RemovePartialBlock(it);
        else
            it++;
    }
    //TODO: Prune setBlocksRelayed and setBlocksReceived to keep lookups fast?
}
