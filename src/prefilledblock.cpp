// Copyright (c) 2016 Matt Corallo
// Unlike the rest of Bitcoin Core, this file is
// distributed under the Affero General Public License (AGPL v3)

#include "prefilledblock.h"
#include "consensus/consensus.h"
#include "consensus/validation.h"
#include "chainparams.h"
#include "hash.h"
#include "random.h"
#include "streams.h"
#include "txmempool.h"
#include "validation.h"
#include "util.h"

#include <unordered_map>

#define MIN_TRANSACTION_BASE_SIZE (::GetSerializeSize(CTransaction(), SER_NETWORK, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS))

#include <chrono>
#define to_millis_double(t) (std::chrono::duration_cast<std::chrono::duration<double, std::chrono::milliseconds::period> >(t).count())

std::shared_ptr<const CBlock> CBlockHeaderAndCheapHashTxIDs::MaybeGetBlock(const CTxMemPool* pool, const std::vector<std::pair<uint256, CTransactionRef>>& extra_txn) {
    const bool fBench = LogAcceptCategory("bench");
    std::chrono::steady_clock::time_point start;
    if (fBench)
        start = std::chrono::steady_clock::now();

    if (header.IsNull() || shorttxids.empty() ||
            shorttxids.size() > MAX_BLOCK_BASE_SIZE / MIN_TRANSACTION_BASE_SIZE ||
            shorttxids.size() > 65535) {
        LogPrint("cmpctblock", "Got insane cheap hash block\n");
        return std::shared_ptr<const CBlock>();
    }

    std::map<uint64_t, uint16_t> mapCheaphash;
    for (size_t i = 0; i < shorttxids.size(); i++)
        mapCheaphash[shorttxids[i]] = i;

    if (mapCheaphash.size() != shorttxids.size()) {
        LogPrint("cmpctblock", "Got cheap hash block with conflicting cheap hashes\n");
        return std::shared_ptr<const CBlock>();
    }

    std::chrono::steady_clock::time_point shortids_mapped;
    if (fBench)
        shortids_mapped = std::chrono::steady_clock::now();

    std::vector<CTransactionRef> txn_available(shorttxids.size());
    std::vector<bool> txn_from_prefill(shorttxids.size());
    uint64_t have_txn_count = 0;

    for (const CTransactionRef& ptx : prefilledtxn) {
        auto it = mapCheaphash.find(ptx->GetHash().GetCheapHash());
        if (it == mapCheaphash.end()) {
            LogPrint("cmpctblock", "Got cheap hash block bogus prefilled txn\n");
            return std::shared_ptr<const CBlock>();
        }
        txn_available[it->second] = ptx;
        txn_from_prefill[it->second] = true;
        have_txn_count++;
    }

    std::chrono::steady_clock::time_point prefilled_added;
    if (fBench)
        prefilled_added = std::chrono::steady_clock::now();

    {
    LOCK(pool->cs);
    const std::vector<std::pair<uint256, CTxMemPool::txiter> >& vTxHashes = pool->vTxHashes;
    for (size_t i = 0; i < vTxHashes.size(); i++) {
        uint64_t shortid = vTxHashes[i].first.GetCheapHash();
        //TODO: Put an ifdef guard around the prefetch here
        if (i + 1 < vTxHashes.size())
            __builtin_prefetch(vTxHashes[i + 1].first.begin());
        auto idit = mapCheaphash.find(shortid);
        if (idit != mapCheaphash.end()) {
            if (txn_from_prefill[idit->second])
                continue;
            if (!txn_available[idit->second]) {
                txn_available[idit->second] = vTxHashes[i].second->GetSharedTx();
                have_txn_count++;
            } else {
                LogPrint("cmpctblock", "Got conflicting mempool cheap hashes\n");
                return std::shared_ptr<const CBlock>();
            }
        }
        // Though ideally we'd continue scanning for the two-txn-match-shortid case,
        // the performance win of an early exit here is too good to pass up and worth
        // the extra risk.
        if (have_txn_count == shorttxids.size())
            break;
    }
    }

    for (size_t i = 0; i < extra_txn.size(); i++) {
        uint64_t shortid = extra_txn[i].first.GetCheapHash();
        auto idit = mapCheaphash.find(shortid);
        if (idit != mapCheaphash.end()) {
            if (!txn_available[idit->second]) {
                txn_available[idit->second] = extra_txn[i].second;
                have_txn_count++;
            } else {
                // If we find two mempool/extra txn that match the short id, just
                // request it.
                // This should be rare enough that the extra bandwidth doesn't matter,
                // but eating a round-trip due to FillBlock failure would be annoying
                // Note that we dont want duplication between extra_txn and mempool to
                // trigger this case, so we compare witness hashes first
                if (txn_available[idit->second]->GetHash() != extra_txn[i].second->GetHash()) {
                    LogPrint("cmpctblock", "Got conflicting mempool/extra pool cheap hashes\n");
                    return std::shared_ptr<const CBlock>();
                }
            }
        }
        // Though ideally we'd continue scanning for the two-txn-match-shortid case,
        // the performance win of an early exit here is too good to pass up and worth
        // the extra risk.
        if (have_txn_count == shorttxids.size())
            break;
    }

    if (have_txn_count != shorttxids.size()) {
        LogPrint("cmpctblock", "Got cheap hash block, but only filled %lu/%lu txn\n", have_txn_count, shorttxids.size());
        return std::shared_ptr<const CBlock>();
    }

    std::chrono::steady_clock::time_point txn_searched;
    if (fBench)
        txn_searched = std::chrono::steady_clock::now();

    std::shared_ptr<CBlock> res = std::make_shared<CBlock>(header);

    res->vtx.resize(txn_available.size());

    for (size_t i = 0; i < txn_available.size(); i++) {
        assert(txn_available[i]);
        res->vtx[i] = txn_available[i];
    }

    CValidationState state;
    if (!CheckBlock(*res, state, Params().GetConsensus())) {
        LogPrint("cmpctblock", "Got cheap hash block which failed merkle tree check\n");
        return std::shared_ptr<const CBlock>();
    }

    if (fBench) {
        std::chrono::steady_clock::time_point finished(std::chrono::steady_clock::now());
        LogPrintf("CBlockHeaderAndCheapHashTxIDs::MaybeGetBlock got block after %lf %lf %lf %lf ms\n", to_millis_double(shortids_mapped - start), to_millis_double(prefilled_added - shortids_mapped), to_millis_double(txn_searched - prefilled_added), to_millis_double(finished - txn_searched));
    }

    LogPrint("cmpctblock", "Got block via CheapHashTxIDs for block %s\n", header.GetHash().ToString());

    return res;
}
