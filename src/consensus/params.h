// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_PARAMS_H
#define BITCOIN_CONSENSUS_PARAMS_H

#include "uint256.h"

namespace Consensus {
/**
 * Parameters that influence chain consensus.
 */
struct Params {
    uint256 hashGenesisBlock;
    int nSubsidyHalvingInterval;
    /** Used to check majorities for block version upgrade */
    int nMajorityEnforceBlockUpgrade;
    int nMajorityRejectBlockOutdated;
    int nMajorityWindow;
    /** Block height and hash at which BIP34 becomes active */
    int BIP34Height;
    uint256 BIP34Hash;
    /** Block height at which BIP-back becomes active */
    int BIPBackHeight;
    /** Proof of work parameters */
    uint256 powLimit;
    bool fPowAllowMinDifficultyBlocks;
    bool fPowNoRetargeting;
    int64_t nPowTargetSpacing;
    int64_t nPowTargetTimespan;
    int64_t DifficultyAdjustmentInterval() const { return nPowTargetTimespan / nPowTargetSpacing; }
    unsigned int MaxBlockSize(int height) const {
	unsigned int base = 1000000;

	// Not activated, or never activating.
	if (BIPBackHeight < 0 || height < BIPBackHeight)
	    return base;

	// Note: 37 blocks in a "year" for regtest
	const unsigned int year_of_blocks = nSubsidyHalvingInterval / 4;

	// Linear ramp to 2MB in first year 
	unsigned int t = height - BIPBackHeight;
	unsigned int extra_target = 1000000;
	if (t < year_of_blocks)
	    return base + extra_target * t / year_of_blocks;

	// A linear ramp to 4MB in next 2 years
	base += extra_target;
	t -= year_of_blocks;
	extra_target = 2000000;
	if (t < year_of_blocks * 2)
	    return base + extra_target * t / (year_of_blocks * 2);

	// Then a linear ramp to 8MB in next 2 years.
	base += 2000000;
	t -= year_of_blocks * 2;
	if (t < year_of_blocks * 2)
	    return base + 4000000 * t / (year_of_blocks * 2);

	// Max out at 8MB
	base += 4000000;
	return base;
    }
    unsigned int MaxBlockSigOps(int height) const { return MaxBlockSize(height) / 50; }
};
} // namespace Consensus

#endif // BITCOIN_CONSENSUS_PARAMS_H
