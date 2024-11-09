// Copyright (c) 2015-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/nanobench.h>

#include <consensus/consensus.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/val64.h>
#include <util/translation.h>

#include <common/args.h>
#include <crypto/sha256.h>
#include <util/fs.h>
#include <util/strencodings.h>
#include <key.h>

#include <chrono>
#include <cstdint>
#include <iostream>
#include <fstream>
#include <map>
#include <regex>
#include <sstream>
#include <vector>

static const char* DEFAULT_BENCH_FILTER = ".*";
static constexpr int64_t DEFAULT_MIN_TIME_MS{10};

const std::function<std::string(const char*)> G_TRANSLATION_FUN = nullptr;

static void SetupBenchArgs(ArgsManager& argsman)
{
    SetupHelpOptions(argsman);

    argsman.AddArg("-filter=<regex>", strprintf("Regular expression filter to select benchmark by name (default: %s)", DEFAULT_BENCH_FILTER), ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-list", "List benchmarks without executing them", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-min-time=<milliseconds>", strprintf("Minimum runtime per benchmark, in milliseconds (default: %d)", DEFAULT_MIN_TIME_MS), ArgsManager::ALLOW_ANY | ArgsManager::DISALLOW_NEGATION, OptionsCategory::OPTIONS);
    argsman.AddArg("-sanity-check", "Run benchmarks for only one iteration with no output", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-verbose", "Show individual benchmark results", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-output-csv=<output.csv>", "Generate CSV file with the most important benchmark results", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-micro", "Run micro-benchmarks: single runs to compare against baseline", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
}

// Helpers
static const std::vector<unsigned char> num_vec(size_t val)
{
    Val64 v(val);
    return v.move_to_valtype();
}

static const std::vector<unsigned char> shift_vec(size_t bytes)
{
    return num_vec(bytes * 8);
}

// Different styles of restore
enum restore_style {
    // No need to restore
    RESTORE_NONE,
    // We have a 4MB object on stack underneath top.
    RESTORE_DROP_AND_DUP_4M,
    // Just duplicate the top 4MB object
    RESTORE_DUP_4M,
    // Just duplicate the top 2MB object twice
    RESTORE_DUP_2Mx2,
    // We don't have a 4MB object anymore, make two.
    RESTORE_RECREATE_4Mx2,
    // We don't have a 2MB object anymore, make two.
    RESTORE_RECREATE_2Mx2,
    // We want a 1M object pushed onto the stack
    RESTORE_RECREATE_1M,
    // Drop the top, and dup 1M twice.
    RESTORE_DROP_AND_DUP_1Mx2,
    // Drop the top, and dup 1M three times.
    RESTORE_DROP_AND_DUP_1Mx3,
    // Drop the top, and dup 2M twice.
    RESTORE_DROP_AND_DUP_2Mx2,
    // Drop the top, and create two 10k objects.
    RESTORE_DROP_AND_RECREATE_10Kx2,
    // Drop the top, and create two 4MB objects.
    RESTORE_DROP_AND_RECREATE_4Mx2,
    // Drop the top, and create two 4MB objects, identical
    RESTORE_DROP_AND_RECREATE_4Mx2_IDENTICAL,
    // Drop the top, and create two 4MB objects, zero until last byte
    RESTORE_DROP_AND_RECREATE_4Mx2_MOSTLY_ZERO,
    // Drop the top, and create 2x4MB object with a value of 2000000.
    RESTORE_DROP_AND_RECREATE_4MBx2_2MBVAL,
    // Drop the top, and create 2x4MB object with a value of 16000000.
    RESTORE_DROP_AND_RECREATE_4MBx2_16MBVAL,
    // Drop the top, and create a 3999999-byte value and a 4MB object with a value of 1.
    RESTORE_DROP_AND_CREATE_3999999_AND_4MB_1VAL,
    // Drop the top, DUP the 4MB and add an empty object
    RESTORE_DROP_AND_DUP4M_AND_EMPTY,

};

struct varops_bench {
    // Class of benchmark
    std::string classname;
    // What is this benchmark called
    std::string name;
    // What should this benchmark be compared to
    std::string comparison_benchname;
    // varops cost of benchmark.
    size_t varops_cost;
    // Initial stack.
    std::vector<std::vector<unsigned char>> (*init_stack)();
    // Opcodes to initialize CScript
    std::vector<opcodetype> opcodes;
    // How to restore stack to original state
    enum restore_style restore_style;
};

// Standard sizes for benchmarks, for easier reading
#define FOUR_MB     uint64_t(4000000U)
#define TWO_MB      uint64_t(2000000U)
#define ONE_MB      uint64_t(1000000U)
#define TEN_KB        uint64_t(10000U)

// Normal case: two 4MB opcodes
static std::vector<std::vector<unsigned char>> init_stack_two_4MB_operands()
{
    std::vector<std::vector<unsigned char>> stack;
    stack.push_back(std::vector<unsigned char>(FOUR_MB, 2));
    stack.push_back(std::vector<unsigned char>(FOUR_MB, 1));
    return stack;
}

static std::vector<std::vector<unsigned char>> init_stack_4MB_and_1MB_operands()
{
    std::vector<std::vector<unsigned char>> stack;
    stack.push_back(std::vector<unsigned char>(FOUR_MB, 2));
    stack.push_back(std::vector<unsigned char>(ONE_MB, 1));
    stack.push_back(std::vector<unsigned char>(ONE_MB, 1));
    stack.push_back(std::vector<unsigned char>(ONE_MB, 1));
    stack.push_back(std::vector<unsigned char>(ONE_MB, 1));
    return stack;
}

// Where we make multiple copies: four 2MB opcodes
static std::vector<std::vector<unsigned char>> init_stack_four_2MB_operands()
{
    std::vector<std::vector<unsigned char>> stack;
    stack.push_back(std::vector<unsigned char>(TWO_MB, 1));
    stack.push_back(std::vector<unsigned char>(TWO_MB, 2));
    stack.push_back(std::vector<unsigned char>(TWO_MB, 3));
    stack.push_back(std::vector<unsigned char>(TWO_MB, 1));
    return stack;
}

static std::vector<std::vector<unsigned char>> init_stack_four_2MB_operands_FF()
{
    std::vector<std::vector<unsigned char>> stack;
    stack.push_back(std::vector<unsigned char>(TWO_MB, 0xFF));
    stack.push_back(std::vector<unsigned char>(TWO_MB, 0xFF));
    stack.push_back(std::vector<unsigned char>(TWO_MB, 0xFF));
    stack.push_back(std::vector<unsigned char>(TWO_MB, 0xFF));
    return stack;
}

static std::vector<std::vector<unsigned char>> init_stack_eight_1MB_operands()
{
    std::vector<std::vector<unsigned char>> stack;
    stack.push_back(std::vector<unsigned char>(ONE_MB, 8));
    stack.push_back(std::vector<unsigned char>(ONE_MB, 7));
    stack.push_back(std::vector<unsigned char>(ONE_MB, 6));
    stack.push_back(std::vector<unsigned char>(ONE_MB, 5));
    stack.push_back(std::vector<unsigned char>(ONE_MB, 4));
    stack.push_back(std::vector<unsigned char>(ONE_MB, 3));
    stack.push_back(std::vector<unsigned char>(ONE_MB, 2));
    stack.push_back(std::vector<unsigned char>(ONE_MB, 1));
    return stack;
}

static std::vector<std::vector<unsigned char>> init_stack_eight_1MB_zero_operands()
{
    std::vector<std::vector<unsigned char>> stack;
    stack.push_back(std::vector<unsigned char>(ONE_MB, 0));
    stack.push_back(std::vector<unsigned char>(ONE_MB, 0));
    stack.push_back(std::vector<unsigned char>(ONE_MB, 0));
    stack.push_back(std::vector<unsigned char>(ONE_MB, 0));
    stack.push_back(std::vector<unsigned char>(ONE_MB, 0));
    stack.push_back(std::vector<unsigned char>(ONE_MB, 0));
    stack.push_back(std::vector<unsigned char>(ONE_MB, 0));
    stack.push_back(std::vector<unsigned char>(ONE_MB, 0));
    return stack;
}

// Two identical operands
static std::vector<std::vector<unsigned char>> init_stack_two_identical_4MB_operands()
{
    std::vector<std::vector<unsigned char>> stack;
    stack.push_back(std::vector<unsigned char>(FOUR_MB, 1));
    stack.push_back(std::vector<unsigned char>(FOUR_MB, 1));
    return stack;
}

// Two identical zero operands
static std::vector<std::vector<unsigned char>> init_stack_two_zero_4MB_operands()
{
    std::vector<std::vector<unsigned char>> stack;
    stack.push_back(std::vector<unsigned char>(FOUR_MB, 0));
    stack.push_back(std::vector<unsigned char>(FOUR_MB, 0));
    return stack;
}

// This forces worst case when comparing with zero.
static std::vector<std::vector<unsigned char>> init_stack_two_4MB_operands_mostly_zeros()
{
    std::vector<std::vector<unsigned char>> stack;
    std::vector<unsigned char> mostly_zero(FOUR_MB - 1, 0);
    mostly_zero.push_back(1);
    stack.push_back(mostly_zero);
    stack.push_back(mostly_zero);
    return stack;
}

static std::vector<std::vector<unsigned char>> init_stack_4MB_1val_and_4MB_minus_1_operands()
{
    std::vector<std::vector<unsigned char>> stack;
    std::vector<unsigned char> oneval(1, 0), fourmb_minus_one(FOUR_MB-1, 2);

    oneval.resize(FOUR_MB);
    stack.push_back(fourmb_minus_one);
    stack.push_back(oneval);
    return stack;
}

static std::vector<std::vector<unsigned char>> init_stack_two_10K_operands()
{
    std::vector<std::vector<unsigned char>> stack;
    stack.push_back(std::vector<unsigned char>(TEN_KB, 1));
    stack.push_back(std::vector<unsigned char>(TEN_KB, 1));
    return stack;
}

// Two vectors, both 4MB val 32MB, plus an empty vector.
static std::vector<std::vector<unsigned char>> init_stack_4MBx2_32MBval_0_operands()
{
    std::vector<std::vector<unsigned char>> stack;
    std::vector<unsigned char> sixteenmb = num_vec(FOUR_MB * 8);
    sixteenmb.resize(FOUR_MB);

    stack.push_back(sixteenmb);
    stack.push_back(sixteenmb);
    stack.push_back(std::vector<unsigned char>());
    return stack;
}

static std::vector<std::vector<unsigned char>> init_stack_4MBx2_2MBval_operands()
{
    std::vector<std::vector<unsigned char>> stack;
    // This is a 4MB long operand, mostly zeroes.  Value is 2MB.
    Val64 two_mb_num(TWO_MB);
    std::vector<unsigned char> num_vec = two_mb_num.move_to_valtype();
    num_vec.resize(FOUR_MB, 0);

    stack.push_back(num_vec);
    stack.push_back(num_vec);
    return stack;
}

static std::vector<std::vector<unsigned char>> init_stack_4MBx2_16MBval_operands()
{
    std::vector<std::vector<unsigned char>> stack;
    // This is a 4MB long operand, mostly zeroes.  Value is 16MB (i.e. 2M bytes, in bits)
    Val64 sixteen_mb_num(16000000);
    std::vector<unsigned char> num_vec = sixteen_mb_num.move_to_valtype();
    num_vec.resize(FOUR_MB, 0);

    stack.push_back(num_vec);
    stack.push_back(num_vec);
    return stack;
}

static std::vector<std::vector<unsigned char>> init_stack_1MB_and_3val_operands()
{
    std::vector<std::vector<unsigned char>> stack;
    // This is a 1MB long operand, mostly zeroes.  Value is 3
    Val64 three_num(3);
    std::vector<unsigned char> num_vec = three_num.move_to_valtype();
    num_vec.resize(ONE_MB, 0);

    stack.push_back(num_vec);
    stack.push_back(std::vector<unsigned char>(ONE_MB, 1));
    stack.push_back(num_vec);
    stack.push_back(std::vector<unsigned char>(ONE_MB, 1));
    stack.push_back(num_vec);
    stack.push_back(std::vector<unsigned char>(ONE_MB, 1));
    stack.push_back(num_vec);
    stack.push_back(std::vector<unsigned char>(ONE_MB, 1));
    return stack;
}

static std::vector<std::vector<unsigned char>> init_stack_within_operands()
{
    std::vector<std::vector<unsigned char>> stack;
    std::vector<unsigned char> num_vec(ONE_MB, 1);
    std::vector<unsigned char> num_vec_plus_one;

    num_vec_plus_one = num_vec;
    num_vec_plus_one[ONE_MB-1] = 2;

    // Ignored: we want 8 stack values to compare against base.
    stack.push_back(std::vector<unsigned char>(ONE_MB, 4));
    stack.push_back(std::vector<unsigned char>(ONE_MB, 4));

    // These are used to restore stack.
    stack.push_back(num_vec);
    stack.push_back(num_vec);
    stack.push_back(num_vec_plus_one);

    // Values to make sure comparison can't abort early.
    // Is this number...
    stack.push_back(num_vec);
    // >= this number
    stack.push_back(num_vec);
    // < this number.
    stack.push_back(num_vec_plus_one);
    return stack;
}

static const struct varops_bench varops_benches[] = {
    // Base noop ones for comparison
    {
        "base", "4MBx2 noop", "",
        0, init_stack_two_4MB_operands, {OP_NOP}, RESTORE_NONE
    },
    {
        "base", "4MB+1MB noop", "",
        0, init_stack_4MB_and_1MB_operands, {OP_NOP}, RESTORE_NONE
    },
    {
        "base", "2MBx4 noop", "",
        0, init_stack_four_2MB_operands, {OP_NOP}, RESTORE_NONE
    },
    {
        "base", "1MBx8 noop", "",
        0, init_stack_eight_1MB_operands, {OP_NOP}, RESTORE_NONE
    },
    {
        "base", "10kx2 noop", "",
        0, init_stack_two_10K_operands, {OP_NOP}, RESTORE_NONE,
    },

    //
    // Fast operations
    //

    // BIP#ops:
    // |OP_VERIFY
    // |Operand length (COMPARINGZERO)
    {
        "fast", "OP_VERIFY", "4MBx2 noop",
        FOUR_MB,
        init_stack_two_4MB_operands,
        {OP_VERIFY},
        RESTORE_DUP_4M,
    },

    // BIP#ops:
    // |OP_NOT
    // |Operand length (COMPARINGZERO)
    {
        "fast", "OP_NOT", "4MBx2 noop",
        FOUR_MB,
        init_stack_two_zero_4MB_operands,
        {OP_NOT},
        RESTORE_DROP_AND_DUP_4M,
    },

    // BIP#ops:
    // |OP_0NOTEQUAL
    // |Operand length (COMPARINGZERO)
    {
        "fast", "OP_0NOTEQUAL", "4MBx2 noop",
        FOUR_MB,
        init_stack_two_zero_4MB_operands,
        {OP_0NOTEQUAL},
        RESTORE_DROP_AND_DUP_4M,
    },

    // BIP#ops:
    // |OP_EQUAL
    // |If length unequal: 0, otherwise length (COMPARING)
    {
        "fast", "OP_EQUAL", "4MBx2 noop",
        FOUR_MB,
        init_stack_two_identical_4MB_operands,
        {OP_EQUAL},
        RESTORE_DROP_AND_RECREATE_4Mx2,
    },

    // BIP#ops:
    // |OP_EQUALVERIFY
    // |If length unequal: 0, otherwise length (COMPARING)
    {
        "fast", "OP_EQUALVERIFY", "4MBx2 noop",
        FOUR_MB,
        init_stack_two_identical_4MB_operands,
        {OP_EQUALVERIFY},
        RESTORE_RECREATE_4Mx2,
    },

    // BIP#ops:
    // |OP_EQUALVERIFY
    // |If length unequal: 0, otherwise length (COMPARING)
    {
        "fast", "OP_EQUALVERIFY 2MB & UPSHIFT", "2MBx4 noop",
        TWO_MB,
        init_stack_four_2MB_operands_FF,
        {OP_EQUALVERIFY},
        RESTORE_RECREATE_2Mx2,
    },

    // BIP#ops:
    // |OP_EQUALVERIFY
    // |If length unequal: 0, otherwise length (COMPARING)
    {
        "fast", "OP_EQUALVERIFY 2MB & DUP", "2MBx4 noop",
        TWO_MB,
        init_stack_four_2MB_operands_FF,
        {OP_EQUALVERIFY},
        RESTORE_DUP_2Mx2,
    },

	// BIP#ops:
    // |OP_2DUP
    // |Sum of two operand lengths (COPYING)
    // |Sum of lengths of new stack entries
    {
        "fast", "OP_2DUP", "2MBx4 noop",
        TWO_MB * 2,
        init_stack_four_2MB_operands,
        {OP_DROP, OP_DROP, OP_2DUP},
        RESTORE_NONE,
    },

    // BIP#ops:
    // |OP_3DUP
    // |Sum of three operand lengths (COPYING)
    // |Sum of lengths of new stack entries
    {
        "fast", "OP_3DUP", "1MBx8 noop",
        ONE_MB * 3,
        init_stack_eight_1MB_operands,
        {OP_DROP, OP_DROP, OP_DROP, OP_3DUP},
        RESTORE_NONE,
    },

    // BIP#ops:
    // |OP_2OVER
    // |Sum of lengths of third and fourth-top stack entries (before) (COPYING)
    // |Sum of lengths of new stack entries
    {
        "fast", "OP_2OVER", "1MBx8 noop",
        ONE_MB * 2,
        init_stack_eight_1MB_operands,
        {OP_DROP, OP_DROP, OP_2OVER},
        RESTORE_NONE,
    },

    // BIP#ops:
    // |OP_IFDUP
    // |(Length of top stack entry (before)) * 2 (COMPARINGZERO + COPYING)
    {
        "fast", "OP_IFDUP", "4MBx2 noop",
        FOUR_MB * 2,
        init_stack_two_4MB_operands_mostly_zeros,
        {OP_DROP, OP_IFDUP},
        RESTORE_NONE,
    },

    // BIP#ops:
    // |OP_DUP
    // |Length of top stack entry (before) (COPYING)
    // |Length of new stack entry
    {
        "fast", "OP_DUP", "4MBx2 noop",
        FOUR_MB,
        init_stack_two_4MB_operands,
        {OP_DROP, OP_DUP},
        RESTORE_NONE,
    },

    // BIP#ops:
    // |OP_OVER
    // |Length of second-top stack entry (before) (COPYING)
    // |Length of new stack entry
    {
        "fast", "OP_OVER", "2MBx4 noop",
        TWO_MB,
        init_stack_four_2MB_operands,
        {OP_DROP, OP_OVER},
        RESTORE_NONE,
    },

    // BIP#ops:
    // |OP_PICK
    // |Length of top stack entry + Length of N-th-from-top stack entry (before) (LENGTHCONV + COPYING)
    {
        "fast", "OP_PICK", "4MBx2 noop",
        FOUR_MB * 2,
        init_stack_two_zero_4MB_operands,
        {OP_PICK},
        RESTORE_NONE,
    },

    // BIP#ops:
    // |OP_TUCK
    // |Length of second-from-top stack entry (before) (COPYING)
    // |Length of new stack entry
    {
        "fast", "OP_TUCK", "2MBx4 noop",
        TWO_MB,
        init_stack_four_2MB_operands,
        {OP_DROP, OP_TUCK},
        RESTORE_NONE,
    },

    // BIP#ops:
    // |OP_ROLL
    // |Length of top stack entry (LENGTHCONV)
    {
        "fast", "OP_ROLL", "4MBx2 noop",
        FOUR_MB,
        init_stack_two_zero_4MB_operands,
        {OP_ROLL},
        RESTORE_DUP_4M,
    },
    
    // BIP#ops:
    // |OP_UPSHIFT
    // |Length of BITS + (Value of BITS) / 8 + Length of A (LENGTHCONV + ZEROING + COPYING).  If BITS % 8 != 0, add (Length of A) * 2.
    {
        "fast", "OP_UPSHIFT round number", "4MBx2 noop",
        // BITS is 4000000 * 8 (4 bytes long), A is 0 bytes long.
        FOUR_MB + FOUR_MB * 2,
        init_stack_4MBx2_32MBval_0_operands,
        {OP_LSHIFT},
        RESTORE_DROP_AND_DUP4M_AND_EMPTY,
    },

    // BIP#ops:
    // |OP_LEFT
    // |Length of OFFSET operand (LENGTHCONV)
    {
        "fast", "OP_LEFT", "4MBx2 noop",
        FOUR_MB,
        init_stack_two_zero_4MB_operands,
        {OP_LEFT},
        RESTORE_DROP_AND_RECREATE_4Mx2,
    },

    //
    // Normal "slow" operations
    //

    // BIP#ops:
    // |OP_CAT
    // |Sum of two operand lengths (COPYING)
    {
        "slow", "OP_CAT", "2MBx4 noop",
        TWO_MB + TWO_MB,
        init_stack_four_2MB_operands,
        {OP_CAT},
        RESTORE_DROP_AND_DUP_2Mx2,
    },
    
    // BIP#ops:
    // |OP_SUBSTR
    // |(Sum of lengths of LEN and BEGIN operands) + MIN(Value of first operand (LEN), Length of operand A - Value of BEGIN, 0) (LENGTHCONV + COPYING)
    {
        "slow", "OP_SUBSTR", "1MBx8 noop",
        ONE_MB + ONE_MB,
        init_stack_eight_1MB_zero_operands,
        {OP_SUBSTR},
        RESTORE_DROP_AND_DUP_1Mx3,
    },
    
    // BIP#ops:
    // |OP_RIGHT
    // |Length of OFFSET operand + MAX(Length of A - Value of OFFSET, 0) (LENGTHCONV + COPYING)
    {
        "slow", "OP_RIGHT (2MB)", "4MBx2 noop",
        FOUR_MB + TWO_MB,
        init_stack_4MBx2_2MBval_operands,
        {OP_RIGHT},
        RESTORE_DROP_AND_RECREATE_4MBx2_2MBVAL,
    },

    // BIP#ops:
    // |OP_INVERT
    // |(Length of operand) * 2
    {
        "slow", "OP_INVERT", "4MBx2 noop",
        FOUR_MB * 2,
        init_stack_two_4MB_operands,
        {OP_INVERT},
        RESTORE_NONE,
    },

    // BIP#ops:
    // |OP_AND
    // |Sum of two operand lengths
    {
        "slow", "OP_AND", "4MBx2 noop",
        FOUR_MB + FOUR_MB,
        init_stack_two_4MB_operands,
        {OP_AND},
        RESTORE_DUP_4M,
    },
    {
        "slow", "OP_AND (4MB & 1MB)", "4MB+1MB noop",
        FOUR_MB + ONE_MB,
        init_stack_4MB_and_1MB_operands,
        {OP_AND},
        RESTORE_RECREATE_1M,
    },
   
    // BIP#ops:
    // |OP_OR
    // |(Lesser of the two operand lengths) * 2
    {
        "slow", "OP_OR", "4MBx2 noop",
        FOUR_MB * 2,
        init_stack_two_4MB_operands,
        {OP_OR},
        RESTORE_DUP_4M,
    },
    {
        "slow", "OP_OR (4MB & 1MB)", "4MB+1MB noop",
        ONE_MB * 2,
        init_stack_4MB_and_1MB_operands,
        {OP_OR},
        RESTORE_RECREATE_1M,
    },

    // BIP#ops:
    // |OP_XOR
    // |(Lesser of the two operand lengths) * 2
    {
        "slow", "OP_XOR", "4MBx2 noop",
        FOUR_MB * 2,
        init_stack_two_4MB_operands,
        {OP_XOR},
        RESTORE_DUP_4M,
    },
    {
        "slow", "OP_XOR (4MB & 1MB)", "4MB+1MB noop",
        ONE_MB * 2,
        init_stack_4MB_and_1MB_operands,
        {OP_XOR},
        RESTORE_RECREATE_1M,
    },

    // BIP#ops:
    // |OP_UPSHIFT
    // |Length of BITS + (Value of BITS) / 8 + Length of A (LENGTHCONV + ZEROING + COPYING).  If BITS % 8 != 0, add (Length of A) * 2.
    {
        "slow", "OP_UPSHIFT", "4MBx2 noop",
        FOUR_MB + 1/8 + (FOUR_MB - 1) * 2 + (FOUR_MB - 1) * 2,
        init_stack_4MB_1val_and_4MB_minus_1_operands,
        {OP_LSHIFT},
        RESTORE_DROP_AND_CREATE_3999999_AND_4MB_1VAL,
    },

    // BIP#ops:
    // |OP_DOWNSHIFT
    // |Length of BITS + MAX((Length of A - (Value of BITS) / 8), 0) * 2
    {
        "slow", "OP_DOWNSHIFT (2MB)", "4MBx2 noop",
        FOUR_MB + TWO_MB,
        init_stack_4MBx2_16MBval_operands,
        {OP_RSHIFT},
        RESTORE_DROP_AND_RECREATE_4MBx2_16MBVAL,
    },
    
    //
    // Arithmetic operations
    //

    // BIP#ops:
    // |OP_ADD
    // |Greater of two operand lengths * 3
    {
        "arithmetic", "OP_ADD", "4MBx2 noop",
        FOUR_MB * 3,
        init_stack_two_4MB_operands,
        {OP_ADD},
        RESTORE_DROP_AND_RECREATE_4Mx2,
    },
    {
        "arithmetic", "OP_ADD (overflow)", "2MBx4 noop",
        TWO_MB * 3,
        init_stack_four_2MB_operands_FF,
        {OP_ADD},
        RESTORE_DROP_AND_DUP_2Mx2,
    },
    
    // BIP#ops:
    // |OP_1ADD
    // |MAX(1, operand length) * 3
    {
        "arithmetic", "OP_1ADD", "4MBx2 noop",
        FOUR_MB * 3,
        init_stack_two_4MB_operands,
        {OP_1ADD},
        RESTORE_NONE,
    },
    {
        "arithmetic", "OP_1ADD (overflow)", "2MBx4 noop",
        TWO_MB * 3,
        init_stack_four_2MB_operands_FF,
        // Drop first, otherwise we overflow.
        {OP_DROP, OP_1ADD},
        RESTORE_DROP_AND_DUP_2Mx2,
    },

    // BIP#ops:
    // |OP_SUB
    // |Greater of two operand lengths * 2
    {
        "arithmetic", "OP_SUB", "4MBx2 noop",
        FOUR_MB * 2,
        init_stack_two_4MB_operands,
        {OP_SUB},
        RESTORE_DROP_AND_RECREATE_4Mx2,
    },
    {
        "arithmetic", "OP_SUB (to zero)", "4MBx2 noop",
        FOUR_MB * 2,
        init_stack_two_identical_4MB_operands,
        {OP_SUB},
        RESTORE_DROP_AND_RECREATE_4Mx2_IDENTICAL,
    },

    // BIP#ops:
    // |OP_1SUB
    // |MAX(1, operand length) * 2
    {
        "arithmetic", "OP_1SUB", "4MBx2 noop",
        FOUR_MB * 2,
        init_stack_two_4MB_operands,
        {OP_1SUB},
        RESTORE_NONE,
    },

    // BIP#ops:
    // |OP_2MUL
    // |Operand length * 3
    {
        "arithmetic", "OP_2MUL", "4MBx2 noop",
        FOUR_MB * 3,
        init_stack_two_4MB_operands,
        {OP_2MUL},
        RESTORE_DROP_AND_DUP_4M,
    },

    // BIP#ops:
    // |OP_2DIV
    // |Operand length * 2
    {
        "arithmetic", "OP_2DIV", "4MBx2 noop",
        FOUR_MB * 2,
        init_stack_two_4MB_operands,
        {OP_2DIV},
        RESTORE_DROP_AND_DUP_4M,
    },

    // BIP#ops:
    // |OP_MUL
    // |Length of A + length of B + (length of A + 7) / 8 * (length of B) * 4  (BEWARE OVERFLOW)
    {
        "arithmetic", "OP_MUL", "10kx2 noop",
        TEN_KB + TEN_KB + (TEN_KB + 7) / 8 * TEN_KB * 4,
        init_stack_two_10K_operands,
        {OP_MUL},
        RESTORE_DROP_AND_RECREATE_10Kx2,
    },

    // BIP#ops:
    // |OP_DIV
    // |Length of A * 9 + length of B * 2 + (length of A)^2 / 4
    {
        "arithmetic", "OP_DIV", "1MBx8 noop",
        ONE_MB * 9 + ONE_MB * 2 + (ONE_MB)*(ONE_MB) / 4,
        init_stack_eight_1MB_operands,
        {OP_DIV},
        RESTORE_DROP_AND_DUP_1Mx2,
    },
    {
        "arithmetic", "OP_DIV by 3", "1MBx8 noop",
        ONE_MB * 9 + ONE_MB * 2 + (ONE_MB)*(ONE_MB) / 4,
        init_stack_1MB_and_3val_operands,
        {OP_DIV},
        RESTORE_DROP_AND_DUP_1Mx2,
    },
    // FIXME: Calculate worst-case to hit underflow in DIV.

    // BIP#ops:
    // |OP_MOD
    // |Length of A * 9 + length of B * 2 + (length of A)^2 / 4
    {
        "arithmetic", "OP_MOD", "1MBx8 noop",
        ONE_MB * 9 + ONE_MB * 2 + (ONE_MB)*(ONE_MB) / 4,
        init_stack_eight_1MB_operands,
        {OP_MOD},
        RESTORE_DROP_AND_DUP_1Mx2,
    },
    {
        "arithmetic", "OP_MOD by 3", "1MBx8 noop",
        ONE_MB * 9 + ONE_MB * 2 + (ONE_MB)*(ONE_MB) / 4,
        init_stack_1MB_and_3val_operands,
        {OP_MOD},
        RESTORE_DROP_AND_DUP_1Mx2,
    },
    // FIXME: Calculate worst-case to hit underflow in DIV.

    //
    // Numeric comparison
    //

    // BIP#ops:
    // |OP_BOOLAND
    // |Sum of two operand lengths
    {
        "numeric comparison", "OP_BOOLAND", "4MBx2 noop",
        FOUR_MB + FOUR_MB,
        init_stack_two_4MB_operands_mostly_zeros,
        {OP_BOOLAND},
        RESTORE_DROP_AND_RECREATE_4Mx2_MOSTLY_ZERO,
    },

    // BIP#ops:
    // |OP_BOOLOR
    // |Sum of two operand lengths
    {
        "numeric comparison", "OP_BOOLOR", "4MBx2 noop",
        FOUR_MB + FOUR_MB,
        init_stack_two_4MB_operands_mostly_zeros,
        {OP_BOOLOR},
        RESTORE_DROP_AND_RECREATE_4Mx2_MOSTLY_ZERO,
    },

    // BIP#ops:
    // |OP_NUMEQUAL
    // |Sum of two operand lengths
    {
        "numeric comparison", "OP_NUMEQUAL", "4MBx2 noop",
        FOUR_MB + FOUR_MB,
        init_stack_two_identical_4MB_operands,
        {OP_NUMEQUAL},
        RESTORE_DROP_AND_RECREATE_4Mx2_IDENTICAL,
    },

    // BIP#ops:
    // |OP_NUMEQUALVERIFY
    // |Sum of two operand lengths
    {
        "numeric comparison", "OP_NUMEQUALVERIFY", "4MBx2 noop",
        FOUR_MB + FOUR_MB,
        init_stack_two_identical_4MB_operands,
        {OP_NUMEQUALVERIFY},
        RESTORE_DROP_AND_RECREATE_4Mx2_IDENTICAL,
    },

    // BIP#ops:
    // |OP_NUMNOTEQUAL
    // |Sum of two operand lengths
    {
        "numeric comparison", "OP_NUMNOTEQUAL", "4MBx2 noop",
        FOUR_MB + FOUR_MB,
        init_stack_two_identical_4MB_operands,
        {OP_NUMNOTEQUAL},
        RESTORE_DROP_AND_RECREATE_4Mx2_IDENTICAL,
    },

    // BIP#ops:
    // |OP_LESSTHAN
    // |Sum of two operand lengths
    {
        "numeric comparison", "OP_LESSTHAN", "4MBx2 noop",
        FOUR_MB + FOUR_MB,
        init_stack_two_identical_4MB_operands,
        {OP_LESSTHAN},
        RESTORE_DROP_AND_RECREATE_4Mx2_IDENTICAL,
    },

    // BIP#ops:
    // |OP_GREATERTHAN
    // |Sum of two operand lengths
    {
        "numeric comparison", "OP_GREATERTHAN", "4MBx2 noop",
        FOUR_MB + FOUR_MB,
        init_stack_two_identical_4MB_operands,
        {OP_GREATERTHAN},
        RESTORE_DROP_AND_RECREATE_4Mx2_IDENTICAL,
    },

    // BIP#ops:
    // |OP_LESSTHANOREQUAL
    // |Sum of two operand lengths
    {
        "numeric comparison", "OP_LESSTHANOREQUAL", "4MBx2 noop",
        FOUR_MB + FOUR_MB,
        init_stack_two_identical_4MB_operands,
        {OP_LESSTHANOREQUAL},
        RESTORE_DROP_AND_RECREATE_4Mx2_IDENTICAL,
    },

    // BIP#ops:
    // |OP_GREATERTHANOREQUAL
    // |Sum of two operand lengths
    {
        "numeric comparison", "OP_GREATERTHANOREQUAL", "4MBx2 noop",
        FOUR_MB + FOUR_MB,
        init_stack_two_identical_4MB_operands,
        {OP_GREATERTHANOREQUAL},
        RESTORE_DROP_AND_RECREATE_4Mx2_IDENTICAL,
    },

    // BIP#ops:
    // |OP_MIN
    // |Sum of two operand lengths
    {
        "numeric comparison", "OP_MIN", "4MBx2 noop",
        FOUR_MB + FOUR_MB,
        init_stack_two_identical_4MB_operands,
        {OP_MIN},
        RESTORE_DROP_AND_RECREATE_4Mx2_IDENTICAL,
    },

    // BIP#ops:
    // |OP_MAX
    // |Sum of two operand lengths
    {
        "numeric comparison", "OP_MAX", "4MBx2 noop",
        FOUR_MB + FOUR_MB,
        init_stack_two_identical_4MB_operands,
        {OP_MAX},
        RESTORE_DROP_AND_RECREATE_4Mx2_IDENTICAL,
    },

    // BIP#ops:
    // |OP_WITHIN
    // |3rd from stack top operand length * 2 + sum of other two operand lengths
    {
        "numeric comparison", "OP_WITHIN", "1MBx8 noop",
        ONE_MB * 2 + ONE_MB + ONE_MB,
        init_stack_within_operands,
        {OP_WITHIN},
        RESTORE_DROP_AND_DUP_1Mx3,
    },
    

    //
    // Hashing operations.
    //

    // BIP#ops:
    // |OP_SHA256
    // |(Length of the operand) * 10
    {
        "hashing", "SHA256", "4MBx2 noop",
        MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE * 10,
        init_stack_two_4MB_operands,
        {OP_SHA256},
        RESTORE_DROP_AND_DUP_4M,
    },        


    // BIP#ops:
    // |OP_HASH160
    // |(Length of the operand) * 10
    {
        "hashing", "HASH160", "4MBx2 noop",
        MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE * 10,
        init_stack_two_4MB_operands,
        {OP_HASH160},
        RESTORE_DROP_AND_DUP_4M,
    },        


    // BIP#ops:
    // |OP_HASH256
    // |(Length of the operand) * 10
    {
        "hashing", "HASH256", "4MBx2 noop",
        MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE * 10,
        init_stack_two_4MB_operands,
        {OP_HASH256},
        RESTORE_DROP_AND_DUP_4M,
    },        

    // Schnorr, special for comparison (not a script evaluation!)
    {
        "Schnorr", "Schnorr sigcheck", "",
        0, NULL, {},
        RESTORE_NONE,
    },
};

static const struct varops_bench &find_bench(const std::string &name)
{
    for (auto &b: varops_benches) {
        if (b.name == name)
            return b;
    }
    std::cerr << "Unknown benchmark " << name << std::endl;
    assert(0);
}

static void run_schnorr(ankerl::nanobench::Bench &benches,
                        const struct varops_bench &bench)
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
    std::smatch baseMatch;
    benches.run(bench.name, [&] {
        bool res = xpub.VerifySchnorr(hash, sigbytes);
        assert(res);
    });

    ECC_Stop();
}

static const ankerl::nanobench::Result *find_result(const ankerl::nanobench::Bench &benches,
                                                    const std::string name)
{
    for (auto &r: benches.results()) {
        if (r.config().mBenchmarkName == name)
            return &r;
    }
    return NULL;
}

struct ByteSize {
    size_t size;
};

struct VaropsCost {
    CScript &m_script;
    size_t m_total_cost;
    size_t m_bytes;

    explicit VaropsCost(CScript &script, size_t bytes = 0) : m_script(script), m_total_cost(0), m_bytes(bytes) {}
    uint64_t get_bytes() const { assert(m_bytes); return m_bytes; }

    VaropsCost& operator<<(struct ByteSize size)
    {
        m_bytes = size.size;
        return *this;
    }
    
    VaropsCost& operator<<(opcodetype opcode)
    {
        switch (opcode) {
        case OP_0:
        case OP_1:
        case OP_DROP:
        case OP_SWAP:
        case OP_NOP:
            break;
        case OP_DUP:
            // BIP#ops:
            // |OP_DUP
            // |Length of top stack entry (before) (COPYING)
            // |Length of new stack entry
            m_total_cost += get_bytes();
            break;
        case OP_LSHIFT:
            // |OP_UPSHIFT
            // |Length of BITS + (Value of BITS) / 8 + Length of A (LENGTHCONV + ZEROING + COPYING).  If BITS % 8 != 0, add (Length of A) * 2.
            m_total_cost += get_bytes() + get_bytes() * 2;
            break;
        case OP_RSHIFT:
            // |OP_DOWNSHIFT
            // |Length of BITS + MAX((Length of A - (Value of BITS) / 8), 0) * 2
            assert(get_bytes() == FOUR_MB);
            // This is how we use it.
            m_total_cost += FOUR_MB + TWO_MB;
            break;
        case OP_CAT:
            // BIP#ops:
            // |OP_CAT
            // |Sum of two operand lengths (COPYING)
            m_total_cost += get_bytes() * 2;
            break;

        case OP_0NOTEQUAL:
        case OP_NOT:
        case OP_VERIFY:
        case OP_EQUAL:
        case OP_EQUALVERIFY:
        case OP_OVER:
        case OP_TUCK:
        case OP_ROLL:
            m_total_cost += get_bytes();
            break;

        case OP_IFDUP:
        case OP_2DUP:
        case OP_2OVER:
        case OP_PICK:
            m_total_cost += get_bytes() * 2;
            break;

        case OP_INVERT:
            m_total_cost += get_bytes() * 2;
            break;

        // We assume top-of-stack number is padded to size
        case OP_LEFT:
            m_total_cost += get_bytes();
            break;

        case OP_AND:
        case OP_OR:
        case OP_XOR:
        case OP_SUB:
        case OP_1SUB:
        case OP_2DIV:
        case OP_BOOLAND:
        case OP_BOOLOR:
        case OP_NUMEQUAL:
        case OP_NUMNOTEQUAL:
        case OP_NUMEQUALVERIFY:
        case OP_LESSTHAN:
        case OP_LESSTHANOREQUAL:
        case OP_GREATERTHAN:
        case OP_GREATERTHANOREQUAL:
        case OP_MIN:
        case OP_MAX:
            m_total_cost += get_bytes() * 2;
            break;

        // BIP#ops:
        // |OP_WITHIN
        // |3rd from stack top operand length * 2 + sum of other two operand lengths
        case OP_WITHIN:
            m_total_cost += get_bytes() * 4;
            break;

        case OP_2MUL:
            m_total_cost += get_bytes() * 3;
            break;

        case OP_MUL:
            // BIP#ops:
            // |OP_MUL
            // |Length of A + length of B + (length of A + 7) / 8 * (length of B) * 4  (BEWARE OVERFLOW)
            m_total_cost += get_bytes() * 2 + (get_bytes() + 7) / 8 * get_bytes() * 4;
            break;

        case OP_DIV:
        case OP_MOD:
            // BIP#ops:
            // |OP_DIV
            // |Length of A * 9 + length of B * 2 + (length of A)^2 / 4
            m_total_cost += get_bytes() * 11 + (get_bytes() * get_bytes()) / 4;
            break;
            
        case OP_1ADD:
        case OP_ADD:
            m_total_cost += get_bytes() * 3;
            break;

        case OP_SUBSTR:
            m_total_cost += get_bytes() * 2;
            break;

        // These need boutique handling
        case OP_RIGHT:
            // FIXME: This is how we actually use it.
            assert(get_bytes() == FOUR_MB);
            m_total_cost += FOUR_MB + TWO_MB;
            break;
            
        case OP_3DUP:
            m_total_cost += get_bytes() * 3;
            break;

        case OP_SHA256:
        case OP_HASH160:
        case OP_HASH256:
            m_total_cost += get_bytes() * 10;
            break;

        default:
            assert(0);
        }
        m_script << opcode;
        return *this;
    }

    VaropsCost& operator<<(const std::vector<unsigned char>& b) {
        m_script << b;
        return *this;
    }
};

// Returns varops needed for restoration
static void append_restore(VaropsCost &vcost, enum restore_style restore_style)
{
    switch (restore_style) {
    // No need to restore
    case RESTORE_NONE:
        return;

    // We have a 4MB object on stack underneath top.
    case RESTORE_DROP_AND_DUP_4M:
        vcost << ByteSize(FOUR_MB) << OP_DROP << OP_DUP;
        return;

    // Just duplicate the top 4MB object
    case RESTORE_DUP_4M:
        vcost << ByteSize(FOUR_MB) << OP_DUP;
        return;
        
    // We don't have a 4MB object anymore, make two.
    case RESTORE_RECREATE_4Mx2:
        vcost << ByteSize(FOUR_MB) << OP_0 << shift_vec(FOUR_MB) << OP_LSHIFT << OP_DUP;
        return;

    // We don't have a 2MB object anymore, make two.
    case RESTORE_RECREATE_2Mx2:
        vcost << ByteSize(TWO_MB) << OP_0 << shift_vec(TWO_MB) << OP_LSHIFT << OP_DUP;
        return;

    // We want a 1M object pushed onto the stack
    case RESTORE_RECREATE_1M:
        vcost << ByteSize(ONE_MB) << OP_0 << shift_vec(ONE_MB) << OP_LSHIFT;
        return;

    // Drop the top, and dup 1M twice.
    case RESTORE_DROP_AND_DUP_1Mx2:
        vcost << ByteSize(ONE_MB) << OP_DROP << OP_DUP << OP_DUP;
        return;
        
    // Drop the top, and dup 1M three times.
    case RESTORE_DROP_AND_DUP_1Mx3:
        vcost << ByteSize(ONE_MB) << OP_DROP << OP_DUP << OP_DUP << OP_DUP;
        return;
        
    // Drop the top, and dup 2M twice.
    case RESTORE_DROP_AND_DUP_2Mx2:
        vcost << ByteSize(TWO_MB) << OP_DROP << OP_DUP << OP_DUP;
        return;

    // Dup 2M twice
    case RESTORE_DUP_2Mx2:
        vcost << ByteSize(TWO_MB) << OP_DUP << OP_DUP;
        return;

    // Drop the top, and create two 10k objects.
    case RESTORE_DROP_AND_RECREATE_10Kx2:
        vcost << ByteSize(TEN_KB) << OP_DROP << OP_0 << shift_vec(TEN_KB) << OP_LSHIFT << OP_DUP;
        return;

    // Drop the top, and create two 4MB objects.
    case RESTORE_DROP_AND_RECREATE_4Mx2:
    case RESTORE_DROP_AND_RECREATE_4Mx2_IDENTICAL:
        vcost << ByteSize(FOUR_MB) << OP_DROP << OP_0 << shift_vec(FOUR_MB) << OP_LSHIFT << OP_DUP;
        return;
        
    // Drop the top, and create two 4MB objects, zero until last byte
    case RESTORE_DROP_AND_RECREATE_4Mx2_MOSTLY_ZERO:
        vcost << ByteSize(FOUR_MB) << OP_DROP << OP_1 << shift_vec(FOUR_MB-1) << OP_LSHIFT << OP_DUP;
        return;

    // Drop the top, and create 2x4MB object with a value of 2000000.
    case RESTORE_DROP_AND_RECREATE_4MBx2_2MBVAL:
        vcost << OP_DROP
              << num_vec(TWO_MB)
              << OP_0 << num_vec(FOUR_MB - num_vec(TWO_MB).size())
              << ByteSize(FOUR_MB - num_vec(TWO_MB).size())
              << OP_LSHIFT
              << ByteSize(TWO_MB) << OP_CAT
              << ByteSize(FOUR_MB) << OP_DUP;
        return;

    // Drop the top, and create 2x4MB object with a value of 16000000.
    case RESTORE_DROP_AND_RECREATE_4MBx2_16MBVAL:
        vcost << OP_DROP
              << num_vec(16000000)
              << OP_0 << num_vec(FOUR_MB - num_vec(16000000).size())
              << ByteSize(FOUR_MB - num_vec(16000000).size()) << OP_LSHIFT
              << ByteSize(TWO_MB) << OP_CAT
              << ByteSize(FOUR_MB) << OP_DUP;
        return;

    // Drop the top, and create 4MB object with a value of 1, and a 3999999-byte value.
    case RESTORE_DROP_AND_CREATE_3999999_AND_4MB_1VAL:
        // We make two 3999999 byte zero vals, and prepend one with a 1.
        vcost << OP_DROP
              << OP_0 << shift_vec(FOUR_MB - 1) << ByteSize(FOUR_MB - 1) << OP_LSHIFT
              << OP_DUP
              << ByteSize(FOUR_MB) << OP_1 << OP_SWAP << OP_CAT;
        return;

    // Drop the top, DUP the 4MB and add an empty object
    case RESTORE_DROP_AND_DUP4M_AND_EMPTY:
        vcost << ByteSize(FOUR_MB) << OP_DROP << OP_DUP << OP_0;
        return;
    }
}
    
static void run_bench(ankerl::nanobench::Bench &benches,
                      std::map<std::string, size_t> &varop_costs_map,
                      const struct varops_bench &bench,
                      bool list_only,
                      const std::regex &reFilter,
                      bool micro)
{
    std::smatch baseMatch;
    if (!std::regex_match(bench.name, baseMatch, reFilter))
        return;

    // Calculate comparison if we need to (even if not in regex!)
    if (bench.comparison_benchname != ""
        && !find_result(benches, bench.comparison_benchname)) {
        const struct varops_bench &dep = find_bench(bench.comparison_benchname);
        run_bench(benches, varop_costs_map, dep,
                  list_only, std::regex(DEFAULT_BENCH_FILTER), micro);
    }

    // Schnorr is special!
    if (bench.name == "Schnorr sigcheck") {
        run_schnorr(benches, bench);
        return;
    }

    const std::vector<std::vector<unsigned char>> master_stack = bench.init_stack();
    
    CScript script;

    // Most tests use uniform sizes: fix those that don't
    size_t bytesize = master_stack.front().size();
    if (bench.name == "OP_AND (4MB & 1MB)")
        bytesize = (FOUR_MB + ONE_MB) / 2;
    else if (bench.name == "OP_OR (4MB & 1MB)")
        bytesize = ONE_MB;
    else if (bench.name == "OP_XOR (4MB & 1MB)")
        bytesize = ONE_MB;

    VaropsCost vcost(script, bytesize);
    for (auto opcode: bench.opcodes)
        vcost << opcode;

    // This uses weird sizes.
    if (bench.name != "OP_UPSHIFT")
        assert(vcost.m_total_cost == bench.varops_cost);

    // Big enough script that a bit of variance in exact length doesn't matter.
    if (!micro) {
        while (script.size() < 10000) {
            append_restore(vcost, bench.restore_style);
            for (auto opcode: bench.opcodes)
                vcost << opcode;
        }
        append_restore(vcost, bench.restore_style);
    }
    varop_costs_map[bench.name] = vcost.m_total_cost;

    if (list_only) {
        std::cout << bench.name << std::endl;
        return;
    }

    BaseSignatureChecker checker;
    ScriptExecutionData sdata;
    ScriptError serror;
    benches.run(bench.name, [&] {
        std::vector<std::vector<unsigned char> > stack = master_stack;
        if (!EvalScript(stack, script, 0, checker,
                        SigVersion::TAPSCRIPT_V2, sdata, &serror)) {
            std::cerr << "EvalScript error " << ScriptErrorString(serror) << std::endl;
            assert(0);
        }

        // Empty stack manually for better comparison!
        while (!stack.empty()) {
            stack.pop_back();
        }
    });
}

static bool per_varop_time(const struct varops_bench &b,
                           const ankerl::nanobench::Bench benches,
                           std::map<std::string, size_t> &varop_costs_map,
                           double &time)
{
    const ankerl::nanobench::Result *r = find_result(benches, b.name);

    if (!r)
        return false;

    const ankerl::nanobench::Result *base = find_result(benches, b.comparison_benchname);
    if (!base)
        return false;

    time = (r->median(ankerl::nanobench::Result::Measure::elapsed)
            - base->median(ankerl::nanobench::Result::Measure::elapsed)) / varop_costs_map[b.name];
    return true;
}

int main(int argc, char** argv)
{
    ArgsManager argsman;
    SetupBenchArgs(argsman);
    SHA256AutoDetect();
    std::string error;
    if (!argsman.ParseParameters(argc, argv, error)) {
        tfm::format(std::cerr, "Error parsing command line arguments: %s\n", error);
        return EXIT_FAILURE;
    }

    if (HelpRequested(argsman)) {
        std::cout << "Usage:  bench_varops [options]\n"
                     "\n"
                  << argsman.GetHelpMessage()
                  << "Description:\n"
                     "\n"
                     "  bench_varops executes microbenchmarks. The quality of the benchmark results\n"
                     "  highly depend on the stability of the machine. It can sometimes be difficult\n"
                     "  to get stable, repeatable results, so here are a few tips:\n"
                     "\n"
                     "  * Use pyperf [1] to disable frequency scaling, turbo boost etc. For best\n"
                     "    results, use CPU pinning and CPU isolation (see [2]).\n"
                     "\n"
                     "  * Each call of run() should do exactly the same work. E.g. inserting into\n"
                     "    a std::vector doesn't do that as it will reallocate on certain calls. Make\n"
                     "    sure each run has exactly the same preconditions.\n"
                     "\n"
                     "  * If results are still not reliable, increase runtime with e.g.\n"
                     "    -min-time=5000 to let a benchmark run for at least 5 seconds.\n"
                     "\n"
                     "  * bench_bitcoin uses nanobench [3] for which there is extensive\n"
                     "    documentation available online.\n"
                     "\n"
                     "Environment Variables:\n"
                     "\n"
                     "  To attach a profiler you can run a benchmark in endless mode. This can be\n"
                     "  done with the environment variable NANOBENCH_ENDLESS. E.g. like so:\n"
                     "\n"
                     "    NANOBENCH_ENDLESS=MuHash ./bench_bitcoin -filter=MuHash\n"
                     "\n"
                     "  In rare cases it can be useful to suppress stability warnings. This can be\n"
                     "  done with the environment variable NANOBENCH_SUPPRESS_WARNINGS, e.g:\n"
                     "\n"
                     "    NANOBENCH_SUPPRESS_WARNINGS=1 ./bench_bitcoin\n"
                     "\n"
                     "Notes:\n"
                     "\n"
                     "  1. pyperf\n"
                     "     https://github.com/psf/pyperf\n"
                     "\n"
                     "  2. CPU pinning & isolation\n"
                     "     https://pyperf.readthedocs.io/en/latest/system.html\n"
                     "\n"
                     "  3. nanobench\n"
                     "     https://github.com/martinus/nanobench\n"
                     "\n";

        return EXIT_SUCCESS;
    }

    bool list_only = argsman.GetBoolArg("-list", false);
    uint64_t min_time = argsman.GetIntArg("-min-time", DEFAULT_MIN_TIME_MS);
    std::regex reFilter(argsman.GetArg("-filter", DEFAULT_BENCH_FILTER));
    bool micro = argsman.GetBoolArg("-micro", false);

    ankerl::nanobench::Bench benches;

    benches.performanceCounters(100);
    if (!argsman.GetBoolArg("-verbose", false))
        benches.output(nullptr);

    if (min_time > 0) {
        std::chrono::nanoseconds min_time_ns = std::chrono::milliseconds(min_time);
        benches.minEpochTime(min_time_ns / benches.epochs());
    }

    if (argsman.GetBoolArg("-sanity-check", false)) {
        benches.epochs(1).epochIterations(1);
    } else {
        // Microbenchmarks are fast, so do more warmup.
        if (micro)
            benches.warmup(100);
        else
            benches.warmup(1);
    }

    std::map<std::string, size_t> varop_costs_map;
    for (auto &b: varops_benches)
        run_bench(benches, varop_costs_map, b, list_only, reFilter, micro);

    fs::path csv = argsman.GetPathArg("-output-csv");
    if (!csv.empty()) {
        std::ofstream fout{csv};
        if (!fout.is_open()) {
            std::cerr << "Could not write to file " << csv << std::endl;
            exit(1);
        }
        
        fout << "# Class, name, basis, time, reltime, varops, reltime_per_varop, "
             << "(version " GIT_VERSION ")"
             << std::endl;

        for (auto &b: varops_benches) {
            const ankerl::nanobench::Result *r = find_result(benches, b.name);
            if (!r)
                continue;
            const ankerl::nanobench::Result *base = find_result(benches, b.comparison_benchname);
            double time, reltime, per_vop_time;

            time = r->median(ankerl::nanobench::Result::Measure::elapsed);
            reltime = time - (base ? base->median(ankerl::nanobench::Result::Measure::elapsed) : 0.0);

            fout << b.classname << ","
                 << b.name << ","
                 << b.comparison_benchname << ","
                 << time << ",";
            if (base)
                fout << reltime << ",";
            else 
                fout << ",";

            fout << varop_costs_map[b.name] << ",";
            if (per_varop_time(b, benches, varop_costs_map, per_vop_time))
                fout << per_vop_time;
            fout << std::endl;
        }
    }

    const struct varops_bench *worst = NULL;
    double worst_time = -1000000000.0;

    // Get the worst.
    for (auto &b: varops_benches) {
        double time;
        if (!per_varop_time(b, benches, varop_costs_map, time))
            continue;
        if (time > worst_time) {
            worst = &b;
            worst_time = time;
        }
    }
    if (worst) {
        std::cout << "Slowest per-varop is "
                  << worst->name
                  << " with a per-varop time of "
                  << worst_time * 1000000000.0
                  << "nsec"
                  << std::endl;
        std::cout << "Worst time for an entire block: "
                  << worst_time * 5200 * 4000000
                  << " seconds"
                  << std::endl;
    }
    const ankerl::nanobench::Result *schnorr = find_result(benches, "Schnorr sigcheck");
    if (schnorr) {
        std::cout << "Time for 80,000 Schnorr signature validations: "
                  << schnorr->median(ankerl::nanobench::Result::Measure::elapsed) * 80000
                  << " seconds"
                  << std::endl;
    }
    return 0;
}
