// Copyright (c) 2016-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <bench/bench.h>
#include <key.h>
#if defined(HAVE_CONSENSUS_LIB)
#include <script/bitcoinconsensus.h>
#endif
#include <script/script.h>
#include <script/interpreter.h>
#include <secp256k1.h>
#include <streams.h>
#include <test/util/transaction_utils.h>

#include <array>

// Microbenchmark for verification of a basic P2WPKH script. Can be easily
// modified to measure performance of other types of scripts.
static void VerifyScriptBench(benchmark::Bench& bench)
{
    ECC_Start();

    const uint32_t flags{SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH};
    const int witnessversion = 0;

    // Key pair.
    CKey key;
    static const std::array<unsigned char, 32> vchKey = {
        {
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
        }
    };
    key.Set(vchKey.begin(), vchKey.end(), false);
    CPubKey pubkey = key.GetPubKey();
    uint160 pubkeyHash;
    CHash160().Write(pubkey).Finalize(pubkeyHash);

    // Script.
    CScript scriptPubKey = CScript() << witnessversion << ToByteVector(pubkeyHash);
    CScript scriptSig;
    CScript witScriptPubkey = CScript() << OP_DUP << OP_HASH160 << ToByteVector(pubkeyHash) << OP_EQUALVERIFY << OP_CHECKSIG;
    const CMutableTransaction& txCredit = BuildCreditingTransaction(scriptPubKey, 1);
    CMutableTransaction txSpend = BuildSpendingTransaction(scriptSig, CScriptWitness(), CTransaction(txCredit));
    CScriptWitness& witness = txSpend.vin[0].scriptWitness;
    witness.stack.emplace_back();
    key.Sign(SignatureHash(witScriptPubkey, txSpend, 0, SIGHASH_ALL, txCredit.vout[0].nValue, SigVersion::WITNESS_V0), witness.stack.back());
    witness.stack.back().push_back(static_cast<unsigned char>(SIGHASH_ALL));
    witness.stack.push_back(ToByteVector(pubkey));

    // Benchmark.
    bench.run([&] {
        ScriptError err;
        bool success = VerifyScript(
            txSpend.vin[0].scriptSig,
            txCredit.vout[0].scriptPubKey,
            &txSpend.vin[0].scriptWitness,
            flags,
            MutableTransactionSignatureChecker(&txSpend, 0, txCredit.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL),
            &err);
        assert(err == SCRIPT_ERR_OK);
        assert(success);

#if defined(HAVE_CONSENSUS_LIB)
        DataStream stream;
        stream << TX_WITH_WITNESS(txSpend);
        int csuccess = bitcoinconsensus_verify_script_with_amount(
            txCredit.vout[0].scriptPubKey.data(),
            txCredit.vout[0].scriptPubKey.size(),
            txCredit.vout[0].nValue,
            (const unsigned char*)stream.data(), stream.size(), 0, flags, nullptr);
        assert(csuccess == 1);
#endif
    });
    ECC_Stop();
}

static void VerifyNestedIfScript(benchmark::Bench& bench)
{
    std::vector<std::vector<unsigned char>> stack;
    CScript script;
    for (int i = 0; i < 100; ++i) {
        script << OP_1 << OP_IF;
    }
    for (int i = 0; i < 1000; ++i) {
        script << OP_1;
    }
    for (int i = 0; i < 100; ++i) {
        script << OP_ENDIF;
    }
    bench.run([&] {
        auto stack_copy = stack;
        ScriptError error;
        bool ret = EvalScript(stack_copy, script, 0, BaseSignatureChecker(), SigVersion::BASE, &error);
        assert(ret);
    });
}


static void VerifySchnorr(benchmark::Bench& bench)
{
    ECC_Start();

    // Key pair.
    CKey key;
    static const std::array<unsigned char, 32> vchKey = {
        {
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
        }
    };
    key.Set(vchKey.begin(), vchKey.end(), false);
    CPubKey pubkey = key.GetPubKey();

    std::vector<unsigned char> vchSig(64);
    const uint256 hash = uint256::ONE;
    key.SignSchnorr(hash, vchSig, NULL, hash);

    XOnlyPubKey xpub(pubkey);
    Span<const unsigned char> sigbytes(vchSig.data(), vchSig.size());
    assert(sigbytes.size() == 64);

    // Benchmark.
    bench.run([&] {
        bool res = xpub.VerifySchnorr(hash, sigbytes);
        assert(res);
    });
    ECC_Stop();
}

static void VerifyTweakAdd(benchmark::Bench& bench)
{
    ECC_Start();

    // To be a fair test, the tweak and pubkey have to start serialized
    const unsigned char tweak[] = {
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32
    };

    std::array<unsigned char, 33> key = {
        {
            0x02, 0xba, 0xd0, 0x00, 0x00, 0x00, 0x00, 0xb8, 0x59, 0x92, 0xd9, 0x5d, 0x9a, 0x0d, 0x20, 0x64, 0x76, 0xe5, 0xcd, 0x22, 0x8d, 0xb1, 0xe6, 0x9e, 0x87, 0x1e, 0x18, 0x13, 0x12, 0xe5, 0x8e, 0x17, 0x9e, 
        }
    };

    bool res;
    secp256k1_pubkey pubkey;

    res = secp256k1_ec_pubkey_parse(secp256k1_context_static, &pubkey,
                                    key.data(), key.size());
    assert(res);

    // Benchmark.
    bench.run([&] {
        res = secp256k1_ec_pubkey_tweak_add(secp256k1_context_static, &pubkey, tweak);
        assert(res);
    });
    ECC_Stop();
}

BENCHMARK(VerifyScriptBench, benchmark::PriorityLevel::HIGH);
BENCHMARK(VerifyNestedIfScript, benchmark::PriorityLevel::HIGH);
BENCHMARK(VerifySchnorr, benchmark::PriorityLevel::LOW);
BENCHMARK(VerifyTweakAdd, benchmark::PriorityLevel::LOW);
