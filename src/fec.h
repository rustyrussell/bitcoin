// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_FEC_H
#define BITCOIN_FEC_H

#include <assert.h>
#include <memory>
#include <stdint.h>
#include <vector>

#include "wh256/src/wh256.h"

class FECDecoder {
private:
    size_t chunk_count, chunks_recvd, chunks_sent;
    mutable bool decodeComplete;
    std::vector<bool> chunk_recvd_flags;
    std::aligned_storage<FEC_CHUNK_SIZE, 16>::type tmp_chunk;

    wh256_state state = NULL;
public:
    FECDecoder(size_t data_size, size_t chunks_provided, int32_t prng_seed);
    FECDecoder() {}
    ~FECDecoder();

    FECDecoder(const FECDecoder&) =delete;
    FECDecoder(FECDecoder&& decoder) =delete;
    FECDecoder& operator=(FECDecoder&& decoder);

    bool ProvideChunk(const unsigned char* chunk, size_t chunk_id);
    bool HasChunk(size_t chunk_id);
    bool DecodeReady() const;
    const void* GetDataPtr(size_t chunk_id); // Only valid until called again
};

class FECEncoder {
private:
    wh256_state state = NULL;
    const std::vector<unsigned char>* data;
    std::vector<unsigned char>* fec_chunks;

public:
    // dataIn/fec_chunksIn must not change during lifetime of this object
    FECEncoder(const std::vector<unsigned char>* dataIn, const int32_t prng_seed, std::vector<unsigned char>* fec_chunksIn);
    ~FECEncoder();

    FECEncoder(const FECDecoder&) =delete;
    FECEncoder(FECDecoder&&) =delete;

    bool BuildChunk(size_t fec_chunk_id);
    bool PrefillChunks();
};

bool BuildFECChunks(const std::vector<unsigned char>& data, const int32_t prng_seed, std::vector<unsigned char>& fec_chunks);

#endif
