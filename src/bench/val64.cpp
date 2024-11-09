// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <bench/bench.h>

#include <random.h>
#include <streams.h>

#include <cstddef>
#include <vector>
#include <crypto/sha256.h>
#include <script/val64.h>

// A de-privatizing child.
class Val64Test: public Val64 {
public:
    static void set_force_unaligned(bool val) { Val64::force_unaligned = val; }
    uint64_t &last_word(size_t off = 0) { return Val64::m_u64span[m_u64span.size() - 1 - off]; }
    const uint64_t &last_word(size_t off = 0) const { return Val64::m_u64span[m_u64span.size() - 1 - off]; }
    const Span<le64_t> span() const { return Val64::m_u64span; }
    Span<le64_t> span() { return Val64::m_u64span; }
    static void mul_span(Span<le64_t> res,
                         const Span<le64_t> src,
                         uint64_t mul) { return Val64::mul_span(res, src, mul); }
};

#define DEFAULT_BENCH_SIZE 4000000

static size_t bench_size(const char *varname = "VAL64_BENCH_BYTES")
{
	const char *env = getenv(varname);
	if (!env)
		return DEFAULT_BENCH_SIZE;
	return atol(env);
}

static void Val64UpShiftSmall(benchmark::Bench& bench)
{
    size_t size = bench_size();
    std::vector<unsigned char> v1vec(size, 255);
    Val64 v1(v1vec);
    Val64 v2(1);
    size_t n = 1;
    size_t varcost;

    bench.run([&] {
        bool ok = Val64::op_upshift(v1, v2, size + n, varcost);
        assert(ok);
        ok = Val64::op_upshift(v1, v2, size + n, varcost);
        assert(ok);
        n++;
    });
}
BENCHMARK(Val64UpShiftSmall, benchmark::PriorityLevel::LOW);

static void Val64DownShiftSmall(benchmark::Bench& bench)
{
    size_t size = bench_size();
    std::vector<unsigned char> v1vec(size, 255);
    Val64 v1(v1vec);
    Val64 v2(1);
    size_t varcost;

    bench.run([&] {
        Val64::op_downshift(v1, v2, varcost);
        Val64::op_downshift(v1, v2, varcost);
    });
}
BENCHMARK(Val64DownShiftSmall, benchmark::PriorityLevel::LOW);
   
static void Val64BothShiftSmall(benchmark::Bench& bench)
{
    size_t size = bench_size();
    std::vector<unsigned char> v1vec(size, 255);
    Val64 v1(v1vec);
    Val64 v2(1);
    size_t n;
    size_t varcost;

    bench.run([&] {
        Val64::op_downshift(v1, v2, varcost);
        bool ok = Val64::op_upshift(v1, v2, size + n, varcost);
        assert(ok);
        n++;
    });
}
BENCHMARK(Val64BothShiftSmall, benchmark::PriorityLevel::LOW);

static void Val64BothShiftLarge(benchmark::Bench& bench)
{
    size_t size = bench_size();
    std::vector<unsigned char> v1vec(size, 255);
    Val64 v1(v1vec);
    Val64 v2(size / 2 + 1);
    size_t n;
    size_t varcost;

    bench.run([&] {
        Val64::op_downshift(v1, v2, varcost);
        bool ok = Val64::op_upshift(v1, v2, size + n, varcost);
        assert(ok);
        n++;
    });
}
BENCHMARK(Val64BothShiftLarge, benchmark::PriorityLevel::LOW);

static void Val64AddCarry(benchmark::Bench& bench)
{
    size_t size = bench_size();
    std::vector<unsigned char> v1(size, 0);
    std::vector<unsigned char> v2(size, 1);

    Val64Test v641(v1), v642(v2);
    size_t varcost;

    assert(v642.last_word() == UINT64_C(0x0101010101010101));
    bench.run([&] {
        v641.last_word() = UINT64_MAX;
        Val64::op_add(v641, v642, varcost);
        v641.last_word() = UINT64_MAX;
        Val64::op_add(v641, v642, varcost);
        // Should not change v2!
        assert(v642.last_word() == UINT64_C(0x0101010101010101));
    });
}
BENCHMARK(Val64AddCarry, benchmark::PriorityLevel::LOW);

static void Val64AddNoCarry(benchmark::Bench& bench)
{
    size_t size = bench_size();
    std::vector<unsigned char> v1(size, 1);
    std::vector<unsigned char> v2(size, 1);

    Val64Test v641(v1), v642(v2);
    size_t varcost;

    bench.run([&] {
        v641.last_word() = 1;
        Val64::op_add(v641, v642, varcost);
        v641.last_word() = 1;
        Val64::op_add(v641, v642, varcost);
    });
}
BENCHMARK(Val64AddNoCarry, benchmark::PriorityLevel::LOW);

// This is called with various permutations, for a differential benchmark.
// We want to see if different patterns of overflow have different performance
// (especially can we make the branch predictions wrong?).
//
// There are three cases:
// 0. Maximal overflow, as carry makes result == u1.
// 1. Overflows normally.
// 2. Does not overflow.
//
// #0 can only happen in the word after #0 or #1.
// We use VAL64_ADD_CARRYPATTERN, and convert it into a pattern.  Not all are valid,
// but we run them anyway (I tested 2187 through 6560 inclusive).
//
// The results, on my Intel Laptop, and an RPi5 were noise.
// The RPi3 shows some differences, here are the slowest 5 and fastest 5:
//  2443,31261722.72
//  3405,30675625.79
//  2676,30714874.50
//  4404,30541586.76
//  2286,30498973.89
//  3243,30272764.12
// Fastest:
//  6396,28596129.60
//  6477,29002149.55
//  6068,28578248.90
//  6560,28476473.18
//  6478,28602590.90
//
// Still within 10% though.
static void Val64AddPattern(benchmark::Bench& bench)
{
    size_t size = bench_size();
    const char *env = getenv("VAL64_ADD_CARRYPATTERN");

    std::vector<unsigned char> template1, template2;

    size_t pval = env ? atol(env) : 0;

    for (size_t i = 0; i < 8; i++) {
        switch (pval % 3) {
        case 0:
            template1.insert(template1.end(), 8, 1);
            template2.insert(template2.end(), 8, 0xFF);
            break;
        case 1:
            template1.insert(template1.end(), 8, 0xFF);
            template2.insert(template2.end(), 8, 1);
            break;
        case 2:
            template1.insert(template1.end(), 8, 1);
            template2.insert(template2.end(), 8, 1);
            break;
        }
        pval /= 3;
    }

    // Make sure size covers templates exactly
    const size_t num_chunks = size / template1.size();
    size = num_chunks * template1.size();
    std::vector<unsigned char> v1(size);
    std::vector<unsigned char> v2(size);

    size_t varcost;

    bench.run([&] {
        v1.resize(size);
        v2.resize(size);

        for (size_t i = 0; i < num_chunks; i++) {
            std::copy(template1.begin(), template1.end(), v1.begin() + i * template1.size());
            std::copy(template2.begin(), template2.end(), v2.begin() + i * template1.size());
        }
        // Don't do final overflow!
        v1[v1.size()-1] = 0;
        v2[v2.size()-1] = 0;
        Val64Test v641(v1), v642(v2);
        // No $VAL64_ADD_CARRYPATTERN: skip actual add, to benchmark the rest of it.
        if (env)
            Val64::op_add(v641, v642, varcost);
    });
}
BENCHMARK(Val64AddPattern, benchmark::PriorityLevel::LOW);

static void Val64SubUnderflow(benchmark::Bench& bench)
{
    size_t size = bench_size();
    std::vector<unsigned char> v1(size, 0);
    std::vector<unsigned char> v2(size, 0xFF);

    Val64Test v641(v1);
    const Val64Test v642(v2);
    size_t varcost, n = 0;

    bench.run([&] {
        bool ok;
        v641.last_word() = 0;
        ok = Val64::op_sub(v641, v642, varcost);
        if (ok) {
            std::cerr << "No underflow on round " << n << " part 1" << std::endl;
            assert(0);
        }
        v641.last_word() = 0;
        ok = Val64::op_sub(v641, v642, varcost);
        if (ok) {
            std::cerr << "No underflow on round " << n << " part 2" << std::endl;
            assert(0);
        }
        n++;
    });
}
BENCHMARK(Val64SubUnderflow, benchmark::PriorityLevel::LOW);

static void Val64SubNoUnderflow(benchmark::Bench& bench)
{
    size_t size = bench_size();
    std::vector<unsigned char> v1(size, 1);
    std::vector<unsigned char> v2(size, 0);

    Val64Test v641(v1);
    const Val64Test v642(v2);
    size_t varcost;

    bench.run([&] {
        Val64::op_sub(v641, v642, varcost);
        Val64::op_sub(v641, v642, varcost);
        // Should not change either one
        assert(v641.last_word() == UINT64_C(0x0101010101010101));
        assert(v642.last_word() == 0);
    });
}
BENCHMARK(Val64SubNoUnderflow, benchmark::PriorityLevel::LOW);

static void Val64MulSpan(benchmark::Bench& bench)
{
    size_t size = bench_size();
    std::vector<unsigned char> v1(size, 1);
    std::vector<unsigned char> v2(size + 1);

    const Val64Test v641(v1);
    Val64Test v642(v2);

    bench.run([&] {
        Val64Test::mul_span(v642.span(), v641.span(), 1);
        Val64Test::mul_span(v642.span(), v641.span(), 1);
        // Should not change either one
        assert(v641.last_word() == UINT64_C(0x0101010101010101));
        assert(v642.last_word(1) == UINT64_C(0x0101010101010101));
    });
}
BENCHMARK(Val64MulSpan, benchmark::PriorityLevel::LOW);
