// Copyright (c) 2016 Matt Corallo
// Unlike the rest of Bitcoin Core, this file is
// distributed under the Affero General Public License (AGPL v3)

#ifndef BITCOIN_PREFILLED_BLOCK_H
#define BITCOIN_PREFILLED_BLOCK_H

#include "primitives/block.h"

#include <memory>

class CTxMemPool;

class CBlockHeaderAndCheapHashTxIDs {
protected:
    std::vector<uint64_t> shorttxids;
    std::vector<CTransactionRef> prefilledtxn;

public:
    CBlockHeader header;

    // Dummy for deserialization
    CBlockHeaderAndCheapHashTxIDs() {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(header);
        READWRITE(shorttxids);
        READWRITE(prefilledtxn);
    }

    std::shared_ptr<const CBlock> MaybeGetBlock(const CTxMemPool* pool, const std::vector<std::pair<uint256, CTransactionRef>>& extra_txn);
};

#endif
