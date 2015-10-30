// Copyright (c) 2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SOFTFORK_H
#define BITCOIN_SOFTFORK_H
#include "chain.h"

/**
 * BIPState encapsulates the BIP activation parameters for a given chain. 
 */
struct BIPState
{
    BIPState(unsigned int threshold, unsigned int period)
        : nThreshold(threshold), nPeriod(period) {}

    unsigned int nThreshold; //!< Versionbits set for lockin
    unsigned int nPeriod;    //!< How often to examine versionbits
};

/**
 * BIP gives you a handle for a BIP.  Its only purpose is to allow you
 * to query whether it applies to a given block.
 */
struct BIP
{
    // Is this BIP active for this block?
    virtual bool IsActive(const CBlockIndex* pblockIndex,
                          const BIPState& state) const = 0;
};

/**
 * A BIP which uses BIP9 (versionbits) to activate.  To add a new one,
 * be sure to append it to the table in softfork.cpp.
 */
struct VersionBitsBIP : public BIP
{
    static const size_t NUM_VERSION_BITS = 29;

    // Optional table arg is a hack for testing.
    VersionBitsBIP(int year,
                   const VersionBitsBIP*** override_table = NULL);

    // Is this BIP active for this block?
    virtual bool IsActive(const CBlockIndex* pblockIndex,
                          const BIPState& state) const;

    int64_t nTimeout;            //!< Timeout in seconds since epoch
    unsigned int nBit;           //!< Which version bit, derived from table
    const VersionBitsBIP* pNext; //!< Next version bit user, if any.
};

/**
 * Status of all BIPs for a given block.
 */
struct BIPStatus
{
    BIPStatus(const CBlockIndex* pblockIndex, const BIPState& state);

    // Two exclusive sets (active could include non-versionbits)
    std::set<const BIP*> active;
    std::set<const VersionBitsBIP*> locked_in;

    // Where we're up to in version_bits_table (each of these is inactive,
    // or locked_in).
    // FIXME: C++11 std::array!
    std::vector<const VersionBitsBIP*> pending;

    // Activate a locked-in bip (happens 1 period after activation).
    void ActivateBIP(const VersionBitsBIP* bip);

    // Time out any active bips which are past their date.
    void TimeoutBIP(const VersionBitsBIP* bip);

    // Lock in a BIP which has reached consensus.
    void LockInBIP(const VersionBitsBIP* bip);

private:
    // Update to next pending bip.
    void BIPConcluded(const VersionBitsBIP* bip);
};

/**
 * VersionForNextBlock:  As a miner, what should nVersion be for next block?
 * @param[in] pblockIndex: the block you're building on top of.
 */
int VersionForNextBlock(const CBlockIndex* pblockIndex,
                        const BIPState& state);

#endif // BITCOIN_SOFTFORK_H
