// Copyright (c) 2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include <vector>
#include <stdexcept>
#include "alert.h"
#include "softfork.h"
#include "utiltime.h"
#include "util.h"

// From BIP 009:
//   The highest 3 bits are set to 001, so the range of actually
//   possible nVersion values is [0x20000000...0x3FFFFFFF], inclusive.
#define NUM_VERSION_BITS 29

// This constant is large enough to cover tests, too. 
#define MAX_BIPS 16

// From BIP 009, 2018 onwards
static const unsigned int TIMEOUT_YEAR_BASE = 2018;
static const unsigned int year_timemap[] = {
    1514764800, 1546300800, 1577836800, 1609459200, 1640995200, 1672531200,
    1704067200, 1735689600, 1767225600, 1798761600, 1830297600, 1861920000,
    1893456000, 1924992000, 1956528000, 1988150400 /* 2033 */
};

static int64_t YearToSeconds(unsigned int year)
{
    if (year < TIMEOUT_YEAR_BASE)
        throw std::domain_error("Year below base");
    if (year > TIMEOUT_YEAR_BASE + sizeof(year_timemap)/sizeof(year_timemap[0]))
        throw std::domain_error("Year beyond table end");
    return year_timemap[year - TIMEOUT_YEAR_BASE];
}

// The activation rules for a particular VersionBitsBIP
struct VersionBitsBIPActivation
{
    const struct VersionBitsBIP *pBIP;
    unsigned int nBit;
    int64_t nTimeout;

    VersionBitsBIPActivation(const struct VersionBitsBIP &bip,
                             unsigned int bit,
                             unsigned int expiry_year)
        : pBIP(&bip), nBit(bit), nTimeout(YearToSeconds(expiry_year)) {
        assert(bit < NUM_VERSION_BITS);
    }

    // If a BIP never applies to this chain.
    enum never { NEVER };
    VersionBitsBIPActivation(const struct VersionBitsBIP &bip, enum never n)
        : pBIP(&bip), nBit(NUM_VERSION_BITS), nTimeout(0) { }
    
    // Default creates end marker. 
    VersionBitsBIPActivation()
        : pBIP(NULL) { }

    bool IsEnd() const { return pBIP == NULL; }
};

enum bip_index {
    BIP_TEST1,
    BIP_TEST2
};

VersionBitsBIP BIP_Test1(BIP_TEST1);
VersionBitsBIP BIP_Test2(BIP_TEST2);

// Currently same BIPs are used for test and main chains, but could be
// different in theory (or for testing).
const VersionBitsBIPActivation NormalChainBIPS[] = {
    // Insert new bips here in id order!
    VersionBitsBIPActivation(BIP_Test1, 0, 2018),
    VersionBitsBIPActivation(BIP_Test2, 1, 2019),

    // Explicit terminator
    VersionBitsBIPActivation()
};

// Just check table is correct.
void BIPState::CheckBIPTable(const VersionBitsBIPActivation *activations)
{
    for (size_t i = 0; i < MAX_BIPS; i++) {
        if (activations[i].IsEnd())
            return;
        if (activations[i].pBIP->id != i)
            throw std::logic_error("BIP activation table out of order");
        if (activations[i].nBit == NUM_VERSION_BITS) {
            if (activations[i].nTimeout != 0) {
                throw std::logic_error("BIP activation table invalid never bip");
            }
        } else if (activations[i].nBit > NUM_VERSION_BITS) {
            throw std::logic_error("BIP activation table invalid bip bit");
        }
    }
    throw std::logic_error("BIP activation table missing terminator");
}

static unsigned int NextActivationIndex(unsigned int bit,
                                        unsigned int i,
                                        const VersionBitsBIPActivation *arr)
{
    while (!arr[i].IsEnd()) {
        if (arr[i].nBit == bit)
            break;
        i++;
    }
    return i;
}

// Is this block at end of a period?
static bool AtEndOfPeriod(unsigned int height, unsigned int period)
{
    return height % period == period - 1;
}

// FIXME:C++11, std::array please!
// Return version bits counts for period (of which, pblockIndex is last)
static std::vector<unsigned int>
TallyVersionBits(const CBlockIndex* pblockIndex, unsigned int period)
{
    assert(AtEndOfPeriod(pblockIndex->nHeight, period));

    std::vector<unsigned int> counts(NUM_VERSION_BITS);
    for (unsigned int i = 0; i < period; i++) {
        // Is it a valid versionbits header?  Top three bits 001.
        if ((pblockIndex->nVersion >> 29) != 0x1)
            continue;

        // Add up all the bits.
        for (unsigned int b = 0; b < NUM_VERSION_BITS; b++)
            if ((pblockIndex->nVersion >> b) & 1)
                counts[b]++;

        // Go back.
        pblockIndex = pblockIndex->pprev;
    }

    return counts;
}

/**
 * Status of all BIPs for a given block.
 *
 * The indices correspond to the position in state->pActivations.
 */
struct BIPStatus
{
    BIPStatus(const CBlockIndex* pblockIndex, const BIPState& astate);

    enum OneState {
        // Not yet considered.
        UNKNOWN,
        PENDING,
        LOCKED_IN,
        ACTIVE,
        TIMEDOUT
    };
    // State of every BIP, by unique index.
    enum OneState bips[MAX_BIPS];

    // Indices into bips[] for each versionbits bit.
    unsigned int pending[NUM_VERSION_BITS];

    // If non-zero, the min height at which we activate an unknown fork.
    unsigned int unknown_activation;

    // Activate a locked-in bip (happens 1 period after activation).
    void ActivateBIP(unsigned int index, const BIPState& state);

    // Time out any active bips which are past their date.
    void TimeoutBIP(unsigned int index, const BIPState& state);

    // Lock in a BIP which has reached consensus.
    void LockInBIP(unsigned int index);

private:
    // Update to next pending bip.
    void BIPConcluded(unsigned int index, const BIPState& state);
};

void BIPStatus::BIPConcluded(unsigned int index, const BIPState& state)
{
    // This bip must be ACTIVE or TIMEDOUT.
    assert(index < MAX_BIPS);
    assert(bips[index] == ACTIVE || bips[index] == TIMEDOUT);

    unsigned bit = state.pActivations[index].nBit;
    // Pending index for this bit must be correct.
    assert(pending[bit] == index);

    // Find next user for this bit, if any.
    pending[bit] = NextActivationIndex(bit, index+1, state.pActivations);
}

void BIPStatus::ActivateBIP(unsigned int index, const BIPState& state)
{
    // Must be locked in.
    assert(bips[index] == LOCKED_IN);
    bips[index] = ACTIVE;

    // BIP 009:
    //   At the that activation block and after, miners should stop
    //   setting bit B, which may be reused for a different soft fork.
    BIPConcluded(index, state);
}

// Time out any active bips which are past their date.
void BIPStatus::TimeoutBIP(unsigned int index, const BIPState& state)
{
    // Must be pending in.
    assert(bips[index] == PENDING);
    bips[index] = TIMEDOUT;

    BIPConcluded(index, state);
}

// Lock in a BIP which has reached consensus.
void BIPStatus::LockInBIP(unsigned int index)
{
    // Must be pending.
    assert(bips[index] == PENDING);
    bips[index] = LOCKED_IN;
}

BIPStatus::BIPStatus(const CBlockIndex* pblockIndex, const BIPState& state)
    : unknown_activation(0)
{
    // Before end of first period, set up pending to first bit users.
    if (!pblockIndex || pblockIndex->nHeight < (int)state.nPeriod - 1) {
        for (unsigned int b = 0; b < NUM_VERSION_BITS; ++b) {
            pending[b] = NextActivationIndex(b, 0, state.pActivations);
            if (state.pActivations[pending[b]].IsEnd())
                bips[pending[b]] = UNKNOWN;
            else
                bips[pending[b]] = PENDING;
        }
        return;
    }

    // We only change state on period boundaries, so get end of last period.
    if (!AtEndOfPeriod(pblockIndex->nHeight, state.nPeriod)) {
        int past_adjust = pblockIndex->nHeight % state.nPeriod;
        pblockIndex = pblockIndex->GetAncestor(pblockIndex->nHeight - past_adjust - 1);
    }

    assert(AtEndOfPeriod(pblockIndex->nHeight, state.nPeriod));

    // Pointers are constant for us, so this works.
    std::map<const CBlockIndex*, BIPStatus*>::iterator it;
    it = state.cache.find(pblockIndex);
    if (it != state.cache.end()) {
        *this = *it->second;
        return;
    }

    // Use block from one period ago as a base.
    *this = BIPStatus(pblockIndex->GetAncestor(pblockIndex->nHeight - state.nPeriod), state);

    // Look for lockins (consensus reached).
    std::vector<unsigned int> counts = TallyVersionBits(pblockIndex, state.nPeriod);

    // Time for this block.
    int64_t now = pblockIndex->GetMedianTimePast();

    for (unsigned int b = 0; b < NUM_VERSION_BITS; ++b) {
        bool success = (counts[b] >= state.nThreshold);

        switch (bips[pending[b]]) {
        case UNKNOWN: {
            // Only warn if something's happening.
            if (!success)
                break;

            // BIP 009:
            //  Whenever lock-in for the unknown upgrade is detected,
            //  the software should warn loudly about the upcoming
            //  soft fork.
            static bool fWarned = false;
            unsigned int activate_height = pblockIndex->nHeight + state.nPeriod;
            if (!fWarned) {
                std::string time = DateTimeStrFormat("%Y-%m-%d %H:%M:%S",
                                                     pblockIndex->nTime);

                CAlert::Notify(strprintf(_("WARNING: at %s block %d locked in an unknown upgrade %d: update your software before block %u activates it!"),
                                         time.c_str(),
                                         pblockIndex->nHeight,
                                         b,
                                         activate_height),
                               true);
                fWarned = true;
            }

            if (unknown_activation == 0 || activate_height < unknown_activation)
                unknown_activation = activate_height;
        }
            break;

        case LOCKED_IN:
            // BIP 009:
            //  The consensus rules related to ''locked-in'' soft fork will
            //  be enforced in the second retarget period
            ActivateBIP(pending[b], state);
            break;

        case PENDING:
            // If we got the numbers, we lock it in now.
            if (success) {
                LockInBIP(pending[b]);
                break;
            }

            // Otherwise, check for timeout.
            if (now >= state.pActivations[pending[b]].nTimeout) {
                TimeoutBIP(pending[b], state);
                break;
            }

            // BIP is still waiting to be activated.
            break;

        case TIMEDOUT:
            throw std::logic_error("BIP is timed out already?");
        case ACTIVE:
            throw std::logic_error("BIP is active already?");
        }
    }

    // BIP 009:
    //   It should warn even more loudly after the next retarget period.
    static bool fWarned = false;
    if (unknown_activation &&
        (unsigned)pblockIndex->nHeight >= unknown_activation && !fWarned) {
        // Same message as if transaction versions increase.
        std::string warning = _("Warning: This version is obsolete; upgrade required!");
        CAlert::Notify(warning, true);
        fWarned = true;
    }

    // We never trim the cache, since it grows by one entry every 2 weeks.
    // But we could, trivially.
    state.cache.insert(std::pair<const CBlockIndex*, BIPStatus*>(pblockIndex,
                                                                 new BIPStatus(*this)));
}

bool VersionBitsBIP::IsActive(const CBlockIndex* pblockIndex,
                              const BIPState& state) const
{
    // Get status for all the BIPs for this block.
    BIPStatus status(pblockIndex, state);
    return status.bips[id] == BIPStatus::ACTIVE;
}

int VersionForNextBlock(const CBlockIndex* pblockIndex, const BIPState& state)
{
    // BIP 009:
    //   The highest 3 bits are set to 001
    uint32_t bits = (1U << 29);

    BIPStatus status(pblockIndex, state);

    // BIP009:
    //  Software which supports the change should begin by setting B
    //  in all blocks mined until it is resolved.
    for (unsigned int b = 0; b < NUM_VERSION_BITS; b++) {
        if (status.pending[b] == BIPStatus::ACTIVE ||
            status.pending[b] == BIPStatus::LOCKED_IN) {
            bits |= (1U << b);
        }
    }

    return bits;
}

