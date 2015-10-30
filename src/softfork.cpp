// Copyright (c) 2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include <vector>
#include <stdexcept>
#include "alert.h"
#include "softfork.h"
#include "utiltime.h"
#include "util.h"

// Append new BIPs to the appropriate array, before the NULL terminator.
static const VersionBitsBIP
    *bit00[] = { NULL },
    *bit01[] = { NULL },
    *bit02[] = { NULL },
    *bit03[] = { NULL },
    *bit04[] = { NULL },
    *bit05[] = { NULL },
    *bit06[] = { NULL },
    *bit07[] = { NULL },
    *bit08[] = { NULL },
    *bit09[] = { NULL },
    *bit10[] = { NULL },
    *bit11[] = { NULL },
    *bit12[] = { NULL },
    *bit13[] = { NULL },
    *bit14[] = { NULL },
    *bit15[] = { NULL },
    *bit16[] = { NULL },
    *bit17[] = { NULL },
    *bit18[] = { NULL },
    *bit19[] = { NULL },
    *bit20[] = { NULL },
    *bit21[] = { NULL },
    *bit22[] = { NULL },
    *bit23[] = { NULL },
    *bit24[] = { NULL },
    *bit25[] = { NULL },
    *bit26[] = { NULL },
    *bit27[] = { NULL },
    *bit28[] = { NULL };

// We keep them in separate variables so they can be different lengths.
static const VersionBitsBIP **version_bits_table[VersionBitsBIP::NUM_VERSION_BITS] = {
    bit00, bit01, bit02, bit03, bit04, bit05, bit06, bit07, bit08, bit09,
    bit10, bit11, bit12, bit13, bit14, bit15, bit16, bit17, bit18, bit19,
    bit20, bit21, bit22, bit23, bit24, bit25, bit26, bit27, bit28
};

// A pointer, for testing to override.
static const VersionBitsBIP*** bip_table = version_bits_table;

// From BIP 009, 2018 onwards
static const unsigned int TIMEOUT_YEAR_BASE = 2018;
static const unsigned int year_timemap[] = {
    1514764800, 1546300800, 1577836800, 1609459200, 1640995200, 1672531200,
    1704067200, 1735689600, 1767225600, 1798761600, 1830297600, 1861920000,
    1893456000, 1924992000, 1956528000, 1988150400 /* 2033 */
};

static int64_t TimeoutToSeconds(unsigned int year)
{
    if (year < TIMEOUT_YEAR_BASE)
        throw std::domain_error("Year below base");
    if (year > TIMEOUT_YEAR_BASE + sizeof(year_timemap)/sizeof(year_timemap[0]))
        throw std::domain_error("Year beyond table end");
    return year_timemap[year - TIMEOUT_YEAR_BASE];
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

    std::vector<unsigned int> counts(VersionBitsBIP::NUM_VERSION_BITS);
    for (unsigned int i = 0; i < period; i++) {
        // Is it a valid versionbits header?  Top three bits 001.
        if ((pblockIndex->nVersion >> 29) != 0x1)
            continue;

        // Add up all the bits.
        for (unsigned int b = 0; b < VersionBitsBIP::NUM_VERSION_BITS; b++)
            if ((pblockIndex->nVersion >> b) & 1)
                counts[b]++;

        // Go back.
        pblockIndex = pblockIndex->pprev;
    }

    return counts;
}

void BIPStatus::BIPConcluded(const VersionBitsBIP* bip)
{
    assert(pending[bip->nBit] == bip);
    pending[bip->nBit] = bip->pNext;
}

void BIPStatus::ActivateBIP(const VersionBitsBIP* bip)
{
    // Can't activate twice.
    assert(active.find(bip) == active.end());

    // Must be locked in.
    if (locked_in.erase(bip) != 1)
        throw std::logic_error("BIP not locked in?");

    active.insert(bip);

    // BIP 009:
    //   At the that activation block and after, miners should stop
    //   setting bit B, which may be reused for a different soft fork.
    BIPConcluded(bip);
}

// Time out any active bips which are past their date.
void BIPStatus::TimeoutBIP(const VersionBitsBIP* bip)
{
    // Can't be activated.
    assert(active.find(bip) == active.end());
    // Can't be locked in.
    assert(locked_in.find(bip) == locked_in.end());

    BIPConcluded(bip);
}

// Lock in a BIP which has reached consensus.
void BIPStatus::LockInBIP(const VersionBitsBIP* bip)
{
    // Can't be activated.
    assert(active.find(bip) == active.end());
    // Can't be locked in.
    if (!locked_in.insert(bip).second)
        throw std::logic_error("BIP locked in twice?");
}

BIPStatus::BIPStatus(const CBlockIndex* pblockIndex, const BIPState& state)
    : pending(std::vector<const VersionBitsBIP*>(VersionBitsBIP::NUM_VERSION_BITS)),
      unknown_activation(0)
{
    // Before end of first period, set up pending to first bit users.
    if (!pblockIndex || pblockIndex->nHeight < (int)state.nPeriod - 1) {
        for (unsigned int b = 0; b < VersionBitsBIP::NUM_VERSION_BITS; ++b)
            pending[b] = bip_table[b][0];
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

    for (unsigned int b = 0; b < VersionBitsBIP::NUM_VERSION_BITS; ++b) {
        // Locked in.  Figure out current BIP for that bit.
        const VersionBitsBIP* bip = pending[b];

        bool success = (counts[b] >= state.nThreshold);

        // Unknown BIP?
        if (!bip) {
            // Only warn if something's happening.
            if (!success)
                continue;

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

            continue;
        }

        // BIP 009:
        //  The consensus rules related to ''locked-in'' soft fork will
        //  be enforced in the second retarget period
        if (find(locked_in.begin(), locked_in.end(), bip) != locked_in.end()) {
            ActivateBIP(bip);
            continue;
        }

        // If we got the numbers, we lock it in now.
        if (success) {
            LockInBIP(bip);
            continue;
        }

        // Otherwise, check for timeout.
        if (now >= bip->nTimeout) {
            TimeoutBIP(bip);
            continue;
        }

        // BIP is still waiting to be activated.
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

// The table is canonical, and nicely visual.  We derive our position on
// first usage.
VersionBitsBIP::VersionBitsBIP(int year,
                               const VersionBitsBIP*** table)
    : nTimeout(TimeoutToSeconds(year))
{
    if (table)
        bip_table = table;

    // Find ourselves in the table.
    for (size_t b = 0; b < NUM_VERSION_BITS; b++) {
        for (size_t gen = 0; bip_table[b][gen]; gen++) {
            if (bip_table[b][gen] == this) {
                nBit = b;
                pNext = bip_table[b][gen + 1];
                return;
            }
        }
    }

    // We're not in the table.
    throw std::logic_error("BIP is not in the version_bits_table");
}

bool VersionBitsBIP::IsActive(const CBlockIndex* pblockIndex,
                              const BIPState& state) const
{
    // Get status for all the BIPs for this block.
    BIPStatus status(pblockIndex, state);

    // Are we in the active set?
    return status.active.find(this) != status.active.end();
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
    for (unsigned int b = 0; b < VersionBitsBIP::NUM_VERSION_BITS; b++)
        if (status.pending[b])
            bits |= (1U << b);

    return bits;
}
