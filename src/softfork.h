// Copyright (c) 2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SOFTFORK_H
#define BITCOIN_SOFTFORK_H
#include "chain.h"

struct VersionBitsBIPActivation;
extern const VersionBitsBIPActivation NormalChainBIPS[];

/**
 * BIPState encapsulates the BIP activation parameters for a given chain. 
 */
struct BIPState
{
    BIPState(unsigned int threshold, unsigned int period,
             const VersionBitsBIPActivation *activations)
    : nThreshold(threshold), nPeriod(period), pActivations(activations) {
        CheckBIPTable(activations);
    }

    unsigned int nThreshold; //!< Versionbits set for lockin
    unsigned int nPeriod;    //!< How often to examine versionbits
    const VersionBitsBIPActivation *pActivations; //!< BIPs possible on chain
        
    mutable std::map<const CBlockIndex*, struct BIPStatus*> cache; //!< Speed up.

    // Startup time sanity check.
    static void CheckBIPTable(const VersionBitsBIPActivation *activations);
};

/**
 * BIP gives you a handle for a BIP.  Its only purpose is to allow you
 * to query whether it applies to a given block.
 */
struct BIP
{
    // Unique id for indexing into arrays. 
    unsigned int id;
    BIP(unsigned int myid) : id(myid) { }

    // Is this BIP active for this block?
    virtual bool IsActive(const CBlockIndex* pblockIndex,
                          const BIPState& state) const = 0;
};

/**
 * A BIP which uses BIP9 (versionbits) to activate.  To add a new one,
 * be sure to detail its VersionBitsBIPActivation in softfork.cpp.
 */
struct VersionBitsBIP : public BIP
{
    VersionBitsBIP(unsigned int myid) : BIP(myid) { }

    // Is this BIP active for this block?
    virtual bool IsActive(const CBlockIndex* pblockIndex,
                          const BIPState& state) const;
};

/**
 * VersionForNextBlock:  As a miner, what should nVersion be for next block?
 * @param[in] pblockIndex: the block you're building on top of.
 * @param[in] state: the BIPState for this chain
 */
int VersionForNextBlock(const CBlockIndex* pblockIndex,
                        const BIPState& state);

/**
 * VersionBitsWarning: Should we warn for this block?
 * @param[in] pblockIndex: the block you're building on top of.
 * @param[in] state: the BIPState for this chain
 * @param[out] blockHeight: the block height at which activation is expected.
 */
bool VersionBitsWarning(const CBlockIndex* pblockIndex,
                        const BIPState& state,
                        unsigned int *blockHeight);

#endif // BITCOIN_SOFTFORK_H
