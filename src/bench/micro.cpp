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
    uint64_t *access_u64() const { return m_u64span.data(); }
    size_t num_u64() const { return m_u64span.size(); }
    void set(size_t index, uint64_t v) { Val64::set(index, v); }
    uint64_t get(size_t index) const { return Val64::get(index); }
};

#define DEFAULT_BENCH_SIZE 4000000

static size_t bench_size(const char *varname = "MICRO_BENCH_BYTES")
{
	const char *env = getenv(varname);
	if (!env)
		return DEFAULT_BENCH_SIZE;
	return atol(env);
}

// For a simple speed comparison
static void MicroSHA256(benchmark::Bench& bench)
{
    std::vector<unsigned char> v1(bench_size(), 1);

    bench.run([&] {
        CSHA256().Write(v1.data(), v1.size()).Finalize(v1.data());
    });
}
BENCHMARK(MicroSHA256, benchmark::PriorityLevel::LOW);

/* Read-only benchmarks */
static void MicroReadMemcmpSelf(benchmark::Bench& bench)
{
    size_t size = bench_size();
    std::vector<unsigned char> v1(size + 64, 1);
    std::vector<unsigned char> v2(size + 64, 1);

    bench.run([&] {
        if (memcmp(v1.data(), v1.data() + 64, size) != 0)
            abort();
        if (memcmp(v2.data(), v2.data() + 64, size) != 0)
            abort();
    });
}
BENCHMARK(MicroReadMemcmpSelf, benchmark::PriorityLevel::LOW);

static void MicroReadMemchr(benchmark::Bench& bench)
{
    size_t size = bench_size();
    std::vector<unsigned char> v1(size, 1);
    std::vector<unsigned char> v2(size, 1);

    bench.run([&] {
        if (memchr(v1.data(), 0, size) != nullptr)
            abort();
        if (memchr(v2.data(), 0, size) != nullptr)
            abort();
    });
}
BENCHMARK(MicroReadMemchr, benchmark::PriorityLevel::LOW);

static void MicroReadManual(benchmark::Bench& bench)
{
    size_t size = bench_size();
    std::vector<unsigned char> v1(size, 1);
    std::vector<unsigned char> v2(size, 1);

    Val64Test v641(v1), v642(v2);

    bench.run([&] {
        size_t size = v641.num_u64();
        for (size_t i = 0; i < size; i++) {
            if (v641.get(i) != v642.get(i))
                abort();
        }
    });
}
BENCHMARK(MicroReadManual, benchmark::PriorityLevel::LOW);

/* Write benchmarks. */
static void MicroWriteMemset(benchmark::Bench& bench)
{
    size_t size = bench_size();
    std::vector<unsigned char> v1(size, 1);
    std::vector<unsigned char> v2(size, 1);
    char n = 2;

    bench.run([&] {
        memset(v1.data(), n, size);
        memset(v2.data(), n, size);
        n++;
    });

    /* Use it so it can't be optimized out */
    assert(memchr(v1.data(), n, v1.size()) == nullptr);
    assert(memchr(v2.data(), n, v2.size()) == nullptr);
}
BENCHMARK(MicroWriteMemset, benchmark::PriorityLevel::LOW);

static void MicroWriteManual(benchmark::Bench& bench)
{
    size_t size = bench_size();
    std::vector<unsigned char> v1(size, 1);
    std::vector<unsigned char> v2(size, 1);

    Val64Test v641(v1), v642(v2);
    uint64_t n = 1;

    bench.run([&] {
        size_t size = v641.num_u64();
        for (size_t i = 0; i < size; i++)
            v641.set(i, n);
        for (size_t i = 0; i < size; i++)
            v642.set(i, n);
    });
}
BENCHMARK(MicroWriteManual, benchmark::PriorityLevel::LOW);

static void MicroRWInvert(benchmark::Bench& bench)
{
    size_t size = bench_size();
    std::vector<unsigned char> v1(size, 1);
    std::vector<unsigned char> v2(size, 1);

    Val64Test v641(v1), v642(v2);
    uint64_t *p1, *p2;

    p1 = v641.access_u64();
    p2 = v642.access_u64();

    bench.run([&] {
        for (size_t i = 0; i < v641.num_u64(); i++)
            p1[i] = ~p1[i];
        for (size_t i = 0; i < v642.num_u64(); i++)
            p2[i] = ~p2[i];
    });

    /* Use it so it can't be optimized out */
    assert(memchr(v1.data(), 2, v1.size()) == nullptr);
    assert(memchr(v2.data(), 2, v2.size()) == nullptr);
}
BENCHMARK(MicroRWInvert, benchmark::PriorityLevel::LOW);

static void MicroRWAnd(benchmark::Bench& bench)
{
    size_t size = bench_size();
    std::vector<unsigned char> v1(size, 1);
    std::vector<unsigned char> v2(size, 1);

    Val64Test v641(v1), v642(v2);
    uint64_t *p1, *p2;

    p1 = v641.access_u64();
    p2 = v642.access_u64();

    bench.run([&] {
        for (size_t i = 0; i < v641.num_u64(); i++)
            p1[i] &= p2[i];
        for (size_t i = 0; i < v642.num_u64(); i++)
            p2[i] &= p1[i];
    });
}
BENCHMARK(MicroRWAnd, benchmark::PriorityLevel::LOW);

static void MicroRWOpAnd(benchmark::Bench& bench)
{
    size_t size = bench_size();
    std::vector<unsigned char> v1(size, 1);
    std::vector<unsigned char> v2(size, 1);
    size_t varcost;

    Val64Test v641(v1), v642(v2);

    bench.run([&] {
        Val64::op_and(v641, v642, varcost);
        Val64::op_and(v642, v641, varcost);
    });

    /* Use it so it can't be optimized out */
    assert(memchr(v1.data(), 2, v1.size()) == nullptr);
    assert(memchr(v2.data(), 2, v2.size()) == nullptr);
}
BENCHMARK(MicroRWOpAnd, benchmark::PriorityLevel::LOW);

static void MicroRWAdd(benchmark::Bench& bench)
{
    size_t size = bench_size();
    std::vector<unsigned char> v1(size, 1);
    std::vector<unsigned char> v2(size, 1);

    Val64Test v641(v1), v642(v2);
    size_t varcost;

    bench.run([&] {
        Val64::op_add(v641, v642, varcost);
        Val64::op_add(v642, v641, varcost);
    });

    /* Use it so it can't be optimized out */
    assert(memchr(v1.data(), 1, v1.size()) == nullptr
           || memchr(v1.data(), 1, v1.size()) != memchr(v2.data(), 1, v2.size()));
}
BENCHMARK(MicroRWAdd, benchmark::PriorityLevel::LOW);

static void MicroRWCopy(benchmark::Bench& bench)
{
    size_t size = bench_size();
    std::vector<unsigned char> v1(size, 2);
    std::vector<unsigned char> v2(size, 1);

    bench.run([&] {
        memcpy(v1.data(), v2.data(), size);
        memcpy(v2.data(), v1.data(), size);
    });

    /* Use it so it can't be optimized out */
    assert(memchr(v1.data(), 2, v1.size()) == nullptr);
    assert(memchr(v2.data(), 2, v2.size()) == nullptr);
}
BENCHMARK(MicroRWCopy, benchmark::PriorityLevel::LOW);

static void MicroRWCopyManual(benchmark::Bench& bench)
{
    size_t size = bench_size();
    std::vector<unsigned char> v1(size, 2);
    std::vector<unsigned char> v2(size, 1);

    Val64Test v641(v1), v642(v2);
    uint64_t *p1, *p2;

    p1 = v641.access_u64();
    p2 = v642.access_u64();

    bench.run([&] {
        for (size_t i = 0; i < v641.num_u64(); i++)
            p1[i] = p2[i];
        for (size_t i = 0; i < v641.num_u64(); i++)
            p2[i] = p1[i];
    });

    /* Use it so it can't be optimized out */
    assert(memchr(v1.data(), 2, v1.size()) == nullptr);
    assert(memchr(v2.data(), 2, v2.size()) == nullptr);
}
BENCHMARK(MicroRWCopyManual, benchmark::PriorityLevel::LOW);
