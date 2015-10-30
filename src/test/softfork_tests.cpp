// Copyright (c) 2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "alert.h"
#include "chain.h"
#include "chainparams.h"
#include "main.h"
#include "miner.h"
#include "primitives/block.h"
#include "softfork.h"
#include "test/test_bitcoin.h"
#include "consensus/validation.h"

#include <boost/test/unit_test.hpp>

extern VersionBitsBIP BIP_Test0;
extern VersionBitsBIP BIP_Test1;
extern VersionBitsBIP BIP_Test0_next;
extern VersionBitsBIP BIP_Test28;

static const VersionBitsBIP
    *bit00[] = { &BIP_Test0, &BIP_Test0_next, NULL },
    *bit01[] = { &BIP_Test1, NULL },
    *bit02[] = { NULL },
    *bit03[] = { NULL }, // Add any real BIPs here, out of way of tests.
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
    *bit28[] = { &BIP_Test28, NULL };

// We keep them in separate variables so they can be different lengths.
const VersionBitsBIP **test_table[VersionBitsBIP::NUM_VERSION_BITS] = {
    bit00, bit01, bit02, bit03, bit04, bit05, bit06, bit07, bit08, bit09,
    bit10, bit11, bit12, bit13, bit14, bit15, bit16, bit17, bit18, bit19,
    bit20, bit21, bit22, bit23, bit24, bit25, bit26, bit27, bit28
};

// Constructors override VersionBitsBIP internal table.
VersionBitsBIP BIP_Test0(2018, test_table);
VersionBitsBIP BIP_Test0_next(2020, test_table);
VersionBitsBIP BIP_Test1(2018, test_table);
VersionBitsBIP BIP_Test28(2019, test_table);

struct SoftforkSetup : public TestingSetup {
    SoftforkSetup()
        : TestingSetup(CBaseChainParams::REGTEST),
          // Reduced to save lots of generation time!
          state(24, 32)
          { }
    void GenBlock(unsigned int seconds, unsigned int version);

    void CheckEmpty();
    struct BIPState state;
};

void SoftforkSetup::GenBlock(unsigned int seconds, unsigned int version)
{
    CKey coinbaseKey;

    coinbaseKey.MakeNewKey(true);
    CScript scriptPubKey = CScript() <<  ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;

    CBlockTemplate *pblocktemplate = CreateNewBlock(scriptPubKey);
    CBlock& block = pblocktemplate->block;

    block.nVersion = version;
    block.nTime = seconds;

    // Make the time valid.
    SetMockTime(seconds);

    // IncrementExtraNonce creates a valid coinbase and merkleRoot
    unsigned int extraNonce = 0;
    IncrementExtraNonce(&block, chainActive.Tip(), extraNonce);

    while (!CheckProofOfWork(block.GetHash(), block.nBits, Params(CBaseChainParams::REGTEST).GetConsensus())) ++block.nNonce;

    CValidationState state;
    ProcessNewBlock(state, NULL, &block, true, NULL);
    delete pblocktemplate;
}

void SoftforkSetup::CheckEmpty()
{
    BIPStatus status(chainActive.Tip(), state);

    // Nothing active or locked in so far.
    BOOST_CHECK(status.active.empty());
    BOOST_CHECK(status.locked_in.empty());

    // Three should be pending.
    for (unsigned int b = 0; b < VersionBitsBIP::NUM_VERSION_BITS; ++b) {
        if (b == 0)
            BOOST_CHECK(status.pending[b] == &BIP_Test0);
        else if (b == 1)
            BOOST_CHECK(status.pending[b] == &BIP_Test1);
        else if (b == 28)
            BOOST_CHECK(status.pending[b] == &BIP_Test28);
        else
            BOOST_CHECK(status.pending[b] == NULL);
    }

    // We should be accepting all 3 for next block.
    BOOST_CHECK(VersionForNextBlock(chainActive.Tip(), state) ==
                (0x20000000 | (1<<0) | (1<<1) | (1<<28)));
}

BOOST_FIXTURE_TEST_SUITE(softfork_tests, SoftforkSetup)

BOOST_AUTO_TEST_CASE(softfork_table_check)
{
    // Each BIP should be found in table.
    BOOST_CHECK(BIP_Test0.nBit == 0);
    BOOST_CHECK(BIP_Test0.pNext == &BIP_Test0_next);
    BOOST_CHECK(BIP_Test1.nBit == 1);
    BOOST_CHECK(BIP_Test1.pNext == NULL);
    BOOST_CHECK(BIP_Test28.nBit == 28);
    BOOST_CHECK(BIP_Test28.pNext == NULL);
    BOOST_CHECK(BIP_Test0_next.nBit == 0);
    BOOST_CHECK(BIP_Test0_next.pNext == NULL);
}

BOOST_AUTO_TEST_CASE(softfork_genesis_bip_status)
{
    CheckEmpty();
}

BOOST_AUTO_TEST_CASE(softfork_no_votes)
{
    // Year 2015.  Nothing changes.
    for (unsigned int i = 1; i < state.nPeriod; i++)
        GenBlock(1446063300+i, 4);

    CheckEmpty();
}

// BIP 009:
//   If bit B is set in 1916 (1512 on testnet) or
//   more of the 2016 blocks within a retarget period, it is considered
//   locked-in.
BOOST_AUTO_TEST_CASE(softfork_insufficient_votes)
{
    // Almost...
    unsigned int i = 1;
    for (; i < state.nThreshold; i++)
        GenBlock(1446063300+i, 0x20000000 | (1<<0) | (1<<1) | (1<<28));

    // "The highest 3 bits are set to 001..."
    // => These won't count.
    GenBlock(1446063300+i, (1<<0) | (1<<1) | (1<<28));
    i++;
    GenBlock(1446063300+i, 0x40000000 | (1<<0) | (1<<1) | (1<<28));
    i++;
    GenBlock(1446063300+i, 0x80000000 | (1<<0) | (1<<1) | (1<<28));
    i++;
    GenBlock(1446063300+i, 0xC0000000 | (1<<0) | (1<<1) | (1<<28));
    i++;

    // These vote for nothing.
    for (; i < state.nPeriod; i++)
        GenBlock(1446063300+i, 0x20000000);
    
    CheckEmpty();
}

// BIP 009:
//   If bit B is set in 1916 (1512 on testnet) or
//   more of the 2016 blocks within a retarget period, it is considered
//   locked-in.
BOOST_AUTO_TEST_CASE(softfork_one_progress)
{
    // Almost...
    unsigned int i = 1;
    for (; i < state.nThreshold; i++)
        GenBlock(1446063300+i, 0x20000000 | (1<<0) | (1<<1) | (1<<28));

    // A single vote to activate Test0
    GenBlock(1446063300+i, 0x20000000 | (1<<0));
    i++;

    // These vote for nothing.
    for (; i < state.nPeriod; i++)
        GenBlock(1446063300+i, 0x20000000);

    BIPStatus status(chainActive.Tip(), state);

    // Nothing active.
    BOOST_CHECK(status.active.empty());

    // But Test0 is locked in!
    BOOST_CHECK(status.locked_in.size() == 1);
    BOOST_CHECK(status.locked_in.count(&BIP_Test0) == 1);

    // Three should be pending.
    for (unsigned int b = 0; b < VersionBitsBIP::NUM_VERSION_BITS; ++b) {
        if (b == 0)
            BOOST_CHECK(status.pending[b] == &BIP_Test0);
        else if (b == 1)
            BOOST_CHECK(status.pending[b] == &BIP_Test1);
        else if (b == 28)
            BOOST_CHECK(status.pending[b] == &BIP_Test28);
        else
            BOOST_CHECK(status.pending[b] == NULL);
    }

    // BIP 009:
    //   Miners should continue setting bit B, so uptake is
    //   visible.
    BOOST_CHECK(VersionForNextBlock(chainActive.Tip(), state) ==
                (0x20000000 | (1<<0) | (1<<1) | (1<<28)));

    // Another period, and it activates whatever the vote.
    for (i = 0; i < state.nPeriod; i++)
        GenBlock(1446063300+2016+i, 0x20000000);

    status = BIPStatus(chainActive.Tip(), state);

    // It's active.
    BOOST_CHECK(status.active.size() == 1);
    BOOST_CHECK(status.active.count(&BIP_Test0) == 1);

    BOOST_CHECK(status.locked_in.empty());

    // Three should be pending.
    for (unsigned int b = 0; b < VersionBitsBIP::NUM_VERSION_BITS; ++b) {
        // This should progress to BIP_Test0_next.
        if (b == 0)
            BOOST_CHECK(status.pending[b] == &BIP_Test0_next);
        else if (b == 1)
            BOOST_CHECK(status.pending[b] == &BIP_Test1);
        else if (b == 28)
            BOOST_CHECK(status.pending[b] == &BIP_Test28);
        else
            BOOST_CHECK(status.pending[b] == NULL);
    }

    BOOST_CHECK(VersionForNextBlock(chainActive.Tip(), state) ==
                (0x20000000 | (1<<0) | (1<<1) | (1<<28)));
}

// BIP 009:
//   If the soft fork still not ''locked-in'' and the
//   GetMedianTimePast() of a block following a retarget period is at or
//   past this timeout, miners should cease setting this bit.
BOOST_AUTO_TEST_CASE(softfork_timeout)
{
    // We aim for a median of *exactly* year 2018.
    for (unsigned int i = 1; i < state.nPeriod - 6; i++)
        GenBlock(1446063300+i, 0x20000000);

    for (int i = 0; i < 6; i++)
        GenBlock(1514764800+i, 0x20000000);
    
    BIPStatus status(chainActive.Tip(), state);

    // None active, none locked in.
    BOOST_CHECK(status.active.empty());
    BOOST_CHECK(status.locked_in.empty());

    // Two should be pending (0 and 1 timed out)
    for (unsigned int b = 0; b < VersionBitsBIP::NUM_VERSION_BITS; ++b) {
        // This should progress to BIP_Test0_next.
        if (b == 0)
            BOOST_CHECK(status.pending[b] == &BIP_Test0_next);
        else if (b == 28)
            BOOST_CHECK(status.pending[b] == &BIP_Test28);
        else
            BOOST_CHECK(status.pending[b] == NULL);
    }

    BOOST_CHECK(VersionForNextBlock(chainActive.Tip(), state) ==
                (0x20000000 | (1<<0) | (1<<28)));
}

// Lockin beats timeout, if both happen at once.
BOOST_AUTO_TEST_CASE(softfork_lockin_before_timeout)
{
    // We aim for a median of *exactly* year 2018.
    for (unsigned int i = 1; i < state.nPeriod - 6; i++)
        GenBlock(1446063300+i, 0x20000000 | (1<<0));

    for (int i = 0; i < 6; i++)
        GenBlock(1514764800+i, 0x20000000);
    
    BIPStatus status(chainActive.Tip(), state);

    BOOST_CHECK(status.active.empty());
    // Test0 is locked in!
    BOOST_CHECK(status.locked_in.size() == 1);
    BOOST_CHECK(status.locked_in.count(&BIP_Test0) == 1);

    // Two should be pending (1 timed out)
    for (unsigned int b = 0; b < VersionBitsBIP::NUM_VERSION_BITS; ++b) {
        if (b == 0)
            BOOST_CHECK(status.pending[b] == &BIP_Test0);
        else if (b == 28)
            BOOST_CHECK(status.pending[b] == &BIP_Test28);
        else
            BOOST_CHECK(status.pending[b] == NULL);
    }

    BOOST_CHECK(VersionForNextBlock(chainActive.Tip(), state) ==
                (0x20000000 | (1<<0) | (1<<28)));
}

// Alert when an unknown BIP gets locked-in.
BOOST_AUTO_TEST_CASE(softfork_unknown_locked_in)
{
    // Make UpdateTip etc use the same modified threshold and period
    bipState = &state;

    // Bit 2.
    for (unsigned int i = 1; i < state.nPeriod-1; i++)
        GenBlock(1446063300+i, 0x20000000 | (1<<2));

    bool caught = false;
    notifyThrowAlerts = true;

    // This should *not* throw.
    BIPStatus status(chainActive.Tip(), state);

    try {
        GenBlock(1446063300+state.nPeriod, 0x20000000 | (1<<2));
    } catch (std::runtime_error &e) {
        caught = true;

        std::string time = DateTimeStrFormat("%Y-%m-%d %H:%M:%S",
                                             1446063300+state.nPeriod);
        std::string warn = strprintf(_("WARNING: at %s block %d locked in an unknown upgrade %d: update your software before block %u activates it!"),
                                     time.c_str(), state.nPeriod-1, 2, state.nPeriod-1+state.nPeriod);
        BOOST_CHECK_EQUAL(e.what(), warn);
    }
    BOOST_CHECK(caught);
    notifyThrowAlerts = false;
}

// Alert when an unknown BIP gets activated.
BOOST_AUTO_TEST_CASE(softfork_unknown_activated)
{
    // Make UpdateTip etc use the same modified threshold and period
    bipState = &state;

    // Bit 2, locked in and almost activated.
    for (unsigned int i = 1; i < state.nPeriod * 2 - 1; i++)
        GenBlock(1446063300+i, 0x20000000 | (1<<2));

    bool caught = false;
    notifyThrowAlerts = true;
    try {
        GenBlock(1446063300+state.nPeriod*2-1, 0x20000000 | (1<<2));
    } catch (std::runtime_error &e) {
        caught = true;

        BOOST_CHECK_EQUAL(e.what(), _("Warning: This version is obsolete; upgrade required!"));
    }
    BOOST_CHECK(caught);
    notifyThrowAlerts = false;
}

// Alert when an unknown BIP gets activated.
BOOST_AUTO_TEST_CASE(softfork_cache)
{
    int64_t time = 1446063300;

    // Cut period even further, since GenBlock is so slow.
    state.nPeriod = 5;
    state.nThreshold = 4;
    
    // Test0 is locked in..
    for (unsigned int i = 1; i < state.nPeriod; i++)
        GenBlock(time++, 0x20000000 | (1<<0));

    // Activate, add many periods.
    for (unsigned int period = 0; period < 100; period++)
        for (unsigned int i = 0; i < state.nPeriod; i++)
            GenBlock(time++, 0x20000000);

    BOOST_CHECK(BIP_Test0.IsActive(chainActive.Tip(), state));
    BOOST_CHECK(!BIP_Test1.IsActive(chainActive.Tip(), state));
    BOOST_CHECK(!BIP_Test0_next.IsActive(chainActive.Tip(), state));
    BOOST_CHECK(!BIP_Test28.IsActive(chainActive.Tip(), state));

    BOOST_CHECK(state.cache.find(chainActive.Tip()) != state.cache.end());
    
#if 0 // Timing test.
    size_t counts = 0;
    for (unsigned int i = 0; i < 100000; i++)
        counts += BIP_Test0.IsActive(chainActive.Tip(), state);
    BOOST_CHECK(counts == 100000);
#endif
}

// FIXME: Test two activations at once
// FIXME: Test one timeout one activation

BOOST_AUTO_TEST_SUITE_END()
