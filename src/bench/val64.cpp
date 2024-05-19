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
};

#define DEFAULT_BENCH_SIZE 520000
#define MAX_ITERS 1000

static size_t bench_size(const char *varname = "VAL64_BENCH_BYTES")
{
	const char *env = getenv(varname);
	if (!env)
		return DEFAULT_BENCH_SIZE;
	return atol(env);
}

static void or_bench(benchmark::Bench& bench)
{
    std::vector<unsigned char> v1(bench_size(), 1), v2(bench_size(), 1);

    bench.run([&] {
        Val64 v641(v1), v642(v2);
        Val64::op_or(v641, v642);
        v1 = v641.move_to_valtype();
        v2 = v642.move_to_valtype();
    });
    assert(v1.size() == bench_size());
    assert(v2.size() == bench_size());
    assert(v1[0] == (unsigned char)1);
}

static void Val64OrMisalign(benchmark::Bench& bench)
{
    Val64Test::set_force_unaligned(true);

    or_bench(bench);
}

static void Val64OrAlign(benchmark::Bench& bench)
{
    Val64Test::set_force_unaligned(false);

    or_bench(bench);
}

static void naive_or(std::vector<unsigned char> &v1,
                      std::vector<unsigned char> &v2)
{
    // We make sure v1 is the bigger.
    if (v1.size() < v2.size())
        v1.swap(v2);

    for (size_t i = 0; i < v2.size(); i++) {
        v1[i] |= v2[i];
    }
}

static void Val64OrNaive(benchmark::Bench& bench)
{
    std::vector<unsigned char> v1(bench_size(), 1), v2(bench_size(), 1);

    bench.run([&] {
        naive_or(v1, v2);
    });
}
BENCHMARK(Val64OrMisalign, benchmark::PriorityLevel::LOW);
BENCHMARK(Val64OrAlign, benchmark::PriorityLevel::LOW);
BENCHMARK(Val64OrNaive, benchmark::PriorityLevel::LOW);

static void invert_bench(benchmark::Bench& bench)
{
    std::vector<unsigned char> v1(bench_size(), 1);

    bench.run([&] {
        Val64 v641(v1);
        Val64::op_invert(v641);
        v1 = v641.move_to_valtype();
    });
    assert(v1.size() == bench_size());
    assert(v1[0] == (unsigned char)1 || v1[0] == (unsigned char)~1);
}

static void Val64InvertMisalign(benchmark::Bench& bench)
{
    Val64Test::set_force_unaligned(true);

    invert_bench(bench);
}

static void Val64InvertAlign(benchmark::Bench& bench)
{
    Val64Test::set_force_unaligned(false);

    invert_bench(bench);
}

static void naive_invert(std::vector<unsigned char> &v1)
{
    for (size_t i = 0; i < v1.size(); i++) {
        v1[i] ^= 0xFF;
    }
}

static void Val64InvertNaive(benchmark::Bench& bench)
{
    std::vector<unsigned char> v1(bench_size(), 1);

    bench.run([&] {
        naive_invert(v1);
    });
}
BENCHMARK(Val64InvertMisalign, benchmark::PriorityLevel::LOW);
BENCHMARK(Val64InvertAlign, benchmark::PriorityLevel::LOW);
BENCHMARK(Val64InvertNaive, benchmark::PriorityLevel::LOW);

// For a simple speed comparison
static void Val64SHA256(benchmark::Bench& bench)
{
    std::vector<unsigned char> v1(bench_size(), 1);

    bench.run([&] {
        CSHA256().Write(v1.data(), v1.size()).Finalize(v1.data());
    });
}
BENCHMARK(Val64SHA256, benchmark::PriorityLevel::LOW);
