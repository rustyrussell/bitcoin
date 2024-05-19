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

static void lshift_bench(benchmark::Bench& bench, size_t bits)
{
    Val64 *v641[MAX_ITERS];
    size_t vecsize = bench_size(), maxsize = vecsize + bits / 8 + 1;

    // Turn bits into a vector array.
    Val64 v2(bits);

    for (size_t i = 0; i < MAX_ITERS; i++) {
        std::vector<unsigned char> v1(vecsize, 128);
        v641[i] = new Val64(v1);
    }

    size_t n = 0;
    bench.run([&] {
        bool ok = Val64::op_upshift(*v641[n++], v2, maxsize);
        assert(ok);
        assert(n < MAX_ITERS);
    });
}

static void Val64LShiftOneMisalign(benchmark::Bench& bench)
{
    Val64Test::set_force_unaligned(true);

    lshift_bench(bench, 1);
}

static void Val64LShiftOneAlign(benchmark::Bench& bench)
{
    Val64Test::set_force_unaligned(false);

    lshift_bench(bench, 1);
}

static void naive_lshift(std::vector<unsigned char> &v1)
{
    v1.resize(v1.size() + 1);
    for (size_t i = 1; i < v1.size(); i++) {
        v1[i] = ((v1[i-1] >> (8 - 1)) | (v1[i] << 1));
    }
    v1[0] <<= 1;
}

static void Val64LShiftOneNaive(benchmark::Bench& bench)
{
    std::vector<unsigned char> v1(bench_size(), 1);

    bench.run([&] {
        naive_lshift(v1);
    });
}

static void Val64LShift(benchmark::Bench& bench)
{
    size_t bits = 65;
	const char *env = getenv("VAL64_SHIFT_BITS");
	if (env)
        bits = atol(env);

    lshift_bench(bench, bits);
}

BENCHMARK(Val64LShiftOneMisalign, benchmark::PriorityLevel::LOW);
BENCHMARK(Val64LShiftOneAlign, benchmark::PriorityLevel::LOW);
BENCHMARK(Val64LShiftOneNaive, benchmark::PriorityLevel::LOW);
BENCHMARK(Val64LShift, benchmark::PriorityLevel::LOW);

static void rshift_bench(benchmark::Bench& bench, size_t bits)
{
    Val64 *v641[MAX_ITERS];

    // Turn bits into a vector array.
    Val64 v2(bits);
    
    for (size_t i = 0; i < MAX_ITERS; i++) {
        std::vector<unsigned char> v1(bench_size(), 128);
        v641[i] = new Val64(v1);
    }

    size_t n = 0;
    bench.run([&] {
        Val64::op_downshift(*v641[n++], v2);
        assert(n < MAX_ITERS);
    });
}

static void Val64RShiftMisalign(benchmark::Bench& bench)
{
    Val64Test::set_force_unaligned(true);

    rshift_bench(bench, 1);
}

static void Val64RShiftAlign(benchmark::Bench& bench)
{
    Val64Test::set_force_unaligned(false);

    rshift_bench(bench, 1);
}

static void naive_rshift(std::vector<unsigned char> &v1)
{
    unsigned char carry = 0;
    for (auto it = v1.rbegin(); it != v1.rend(); ++it) {
        unsigned char next_carry = *it & 1;
        *it = (*it >> 1) | (carry << 7);
        carry = next_carry;
    }
}

static void Val64RShiftNaive(benchmark::Bench& bench)
{
    std::vector<unsigned char> v1(bench_size(), 1);

    bench.run([&] {
        naive_rshift(v1);
    });
}

static void Val64RShift(benchmark::Bench& bench)
{
    size_t bits = 65;
	const char *env = getenv("VAL64_SHIFT_BITS");
	if (env)
        bits = atol(env);

    rshift_bench(bench, bits);
}

BENCHMARK(Val64RShiftMisalign, benchmark::PriorityLevel::LOW);
BENCHMARK(Val64RShiftAlign, benchmark::PriorityLevel::LOW);
BENCHMARK(Val64RShiftNaive, benchmark::PriorityLevel::LOW);
BENCHMARK(Val64RShift, benchmark::PriorityLevel::LOW);

// This grows a little over time, but that's noise.
static void add_bench(benchmark::Bench& bench)
{
    std::vector<unsigned char> v1(bench_size(), 1), v2(bench_size(), 1);
    size_t n = 0;

    bench.run([&] {
        Val64 v641(v1), v642(v2);
        Val64::op_add(v641, v642);
        v1 = v641.move_to_valtype();
        v2 = v642.move_to_valtype();
        n++;
    });
    assert(v1.size() == bench_size() + n/256);
    assert(v1[0] == (unsigned char)(n + 1));
    assert(v2.size() == bench_size());
}

static void Val64AddMisalign(benchmark::Bench& bench)
{
    Val64Test::set_force_unaligned(true);

    add_bench(bench);
}

static void Val64AddAlign(benchmark::Bench& bench)
{
    Val64Test::set_force_unaligned(false);

    add_bench(bench);
}

static void naive_add(std::vector<unsigned char> &v1,
                      std::vector<unsigned char> &v2)
{
    // We make sure v1 is the bigger.
    if (v1.size() < v2.size())
        v1.swap(v2);

    // Little endian, overflow forward.
    bool carry = false;
    for (size_t i = 0; i < v1.size(); i++) {
        carry = __builtin_add_overflow(v1[i], carry, &v1[i]);
        if (i < v2.size()) {
            carry |= __builtin_add_overflow(v1[i], v2[i], &v1[i]);
        } else {
            // v2 finished, if there's no carry, we can stop.
            if (!carry)
                break;
        }
    }

    if (carry)
        v1.push_back(carry);
}

static void Val64AddNaive(benchmark::Bench& bench)
{
    std::vector<unsigned char> v1(bench_size(), 1), v2(bench_size(), 1);

    bench.run([&] {
        naive_add(v1, v2);
    });
}

BENCHMARK(Val64AddMisalign, benchmark::PriorityLevel::LOW);
BENCHMARK(Val64AddAlign, benchmark::PriorityLevel::LOW);
BENCHMARK(Val64AddNaive, benchmark::PriorityLevel::LOW);

static void sub_bench(benchmark::Bench& bench)
{
    std::vector<unsigned char> v1(bench_size(), 0xFF), v2(bench_size(), 1);
    size_t n = 0;

    bench.run([&] {
        Val64 v641(v1), v642(v2);
        Val64::op_sub(v641, v642);
        v1 = v641.move_to_valtype();
        v2 = v642.move_to_valtype();
        n++;
    });
    // We assume this doesn't run *too* many times!
    assert(n < 256);
    assert(v1.size() == bench_size());
    assert(v1[0] == (0xFF - n));
    assert(v2.size() == bench_size());
}

static void Val64SubMisalign(benchmark::Bench& bench)
{
    Val64Test::set_force_unaligned(true);

    sub_bench(bench);
}

static void Val64SubAlign(benchmark::Bench& bench)
{
    Val64Test::set_force_unaligned(false);

    sub_bench(bench);
}

static bool naive_sub(std::vector<unsigned char> &v1,
                      std::vector<unsigned char> &v2)
{
    // Little endian, underflow forward.
    bool underflow = false;
    for (size_t i = 0; i < std::max(v1.size(), v2.size()); i++) {
        unsigned char u1, u2;
        if (i < v1.size())
            u1 = v1[i];
        else
            u1 = 0;
        if (i < v2.size())
            u2 = v2[i];
        else
            u2 = 0;
        
        underflow = __builtin_sub_overflow(u1, underflow, &u1);
        underflow |= __builtin_sub_overflow(u1, u2, &u1);
        if (i < v1.size()) {
            v1[i] = u1;
        }
    }

    return !underflow;
}

static void Val64SubNaive(benchmark::Bench& bench)
{
    std::vector<unsigned char> v1(bench_size(), 1), v2(bench_size(), 1);

    bench.run([&] {
        naive_sub(v1, v2);
    });
}
BENCHMARK(Val64SubMisalign, benchmark::PriorityLevel::LOW);
BENCHMARK(Val64SubAlign, benchmark::PriorityLevel::LOW);
BENCHMARK(Val64SubNaive, benchmark::PriorityLevel::LOW);

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

static void mul_bench(benchmark::Bench& bench)
{
    size_t size1 = bench_size("VAL64_BENCH_MUL1_BYTES");
    size_t size2 = bench_size("VAL64_BENCH_MUL2_BYTES");
    std::vector<unsigned char> v1(size1, 0xFF), v2(size2, 0xFF), resvec;

    bench.run([&] {
        Val64 v641(v1), v642(v2);
        Val64 res = Val64::op_mul(v641, v642);
        resvec = res.move_to_valtype();
        assert(resvec.size() == size1 + size2);
        assert(resvec[0] == 1);
        assert(resvec[resvec.size()-1] == 0xFF);
        v1 = v641.move_to_valtype();
        v2 = v642.move_to_valtype();
    });
}

static void Val64MulAlign(benchmark::Bench& bench)
{
    Val64Test::set_force_unaligned(false);

    mul_bench(bench);
}

static void Val64MulMisalign(benchmark::Bench& bench)
{
    Val64Test::set_force_unaligned(true);

    mul_bench(bench);
}

BENCHMARK(Val64MulAlign, benchmark::PriorityLevel::LOW);
BENCHMARK(Val64MulMisalign, benchmark::PriorityLevel::LOW);

// For a simple speed comparison
static void Val64SHA256(benchmark::Bench& bench)
{
    std::vector<unsigned char> v1(bench_size(), 1);

    bench.run([&] {
        CSHA256().Write(v1.data(), v1.size()).Finalize(v1.data());
    });
}
BENCHMARK(Val64SHA256, benchmark::PriorityLevel::LOW);
