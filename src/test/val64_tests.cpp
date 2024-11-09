// Copyright (c) 2011-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/data/val64_conversion.json.h>
#include <script/val64.h>
#include <test/util/json.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <util/vector.h>

#include <univalue.h>

#include <boost/test/unit_test.hpp>
#include <string>

BOOST_FIXTURE_TEST_SUITE(val64_tests, BasicTestingSetup)

// Resize/create vector so this bit will fit
static std::vector<unsigned char> vec_sized_for_bit(size_t bit,
                                                    const std::vector<unsigned char> in = std::vector<unsigned char>())
{
    std::vector<unsigned char> v = in;
    if (v.size() < (bit + 8) / 8)
        v.resize((bit + 8) / 8);
    return v;
}

// Set bit or create vector with this bit set.
static std::vector<unsigned char> vec_setbit(size_t bit,
                                             const std::vector<unsigned char> in = std::vector<unsigned char>())
{
    std::vector<unsigned char> v = vec_sized_for_bit(bit, in);
    v[bit / 8] |= (1 << (bit % 8));
    return v;
}

// Helper function to convert a vector to a string for printing (ChatGPT)
template <typename T>
std::string vector_to_string(const std::vector<T>& vec) {
    std::ostringstream oss;
    for (const auto& item : vec) {
        oss << static_cast<int>(item) << " ";
    }
    return oss.str();
}

// A de-privatizing child.  Not efficient, as constructor copies, but convenient for testing.
class Val64Test: public Val64 {
public:
    // Unlike Val64, this makes a copy.
    Val64Test(std::vector<unsigned char> v): Val64(v) { };
    Val64Test(const Val64Test &v): Val64(v) { };
    Val64Test(uint64_t v): Val64(v) { };
    Val64Test() { };

    Span<le64_t> span() const { return Val64::m_u64span; }
    size_t u64_size() const { return Val64::m_u64span.size(); }
    size_t realsize() const { return Val64::m_realsize; }
    uint64_t get(size_t i) const { return Val64::get(i); }
    static void set_force_unaligned(bool val) { Val64::force_unaligned = val; }

    void set(size_t index, uint64_t v) { Val64::set(index, v); }
    const uint64_t *access_u64() const { return m_u64span.data(); }
    static void mul_span(Span<le64_t> res, const Span<le64_t> src, uint64_t mul) { return Val64::mul_span(res, src, mul); }
    static bool add_span(Span<uint64_t> v1, const Span<uint64_t> v2, size_t &nonzero_len) { return Val64::add_span(v1, v2, nonzero_len); }
    static bool sub_span(Span<uint64_t> v1, const Span<uint64_t> v2, size_t &nonzero_len) { return Val64::sub_span(v1, v2, nonzero_len); }
    static int cmp_span(const Span<le64_t> v1, const Span<le64_t> v2) { return Val64::cmp_span(v1, v2); }
    std::vector<uint64_t> copy_vector() {
        std::vector<uint64_t> v;
        for (size_t i = 0; i < u64_size(); i++) {
            v.push_back(get(i));
        }
        return v;
    }
};    

static Val64Test val64_singleton(uint64_t val)
{
    std::vector<unsigned char> bitvec(8);
    Val64Test v(bitvec);
    v.set(0, val);

    return v;
}

#if USE_GMP
#include <gmp.h>

static void vector_to_mpz(const std::vector<unsigned char>& vec, mpz_t &num)
{
    mpz_init(num);
    mpz_import(num, vec.size(), -1, sizeof(vec[0]), 0, 0, vec.data());
}

// Because mpz will trim zeroes, we might want to pad to len
static std::vector<unsigned char> mpz_to_vector(const mpz_t &num, size_t len = -1)
{
    size_t count;
    void *raw_data = mpz_export(nullptr, &count, -1, sizeof(uint8_t), 0, 0, num);
    std::vector<unsigned char> vec(count);
    memcpy(vec.data(), raw_data, count);
    free(raw_data);

    if (len != (size_t)-1) {
        assert(vec.size() <= len);
        vec.resize(len);
    }
    return vec;
}
#endif // USE_GMP

// Boost unit test is terrible.
#define I_KNOW_HOW_TO_USE_A_DEBUGGER

#ifdef I_KNOW_HOW_TO_USE_A_DEBUGGER
#define CHECK(x) assert(x)
#else
#define CHECK(x) BOOST_CHECK(x)
#endif

// FIXME: Make this a template
static std::vector<unsigned char> ParseVec8(const UniValue &arr)
{
    std::vector<unsigned char> ret;

    for (size_t i = 0; i < arr.size(); i++) {
        ret.push_back(arr[i].getInt<unsigned char>());
    }
    return ret;
}

static std::vector<uint64_t> ParseVec64(const UniValue &arr)
{
    std::vector<uint64_t> ret;

    for (size_t i = 0; i < arr.size(); i++) {
        ret.push_back(arr[i].getInt<uint64_t>());
    }
    return ret;
}

BOOST_AUTO_TEST_CASE(val64_valtype_conversion)
{
    UniValue tests = read_json(json_tests::val64_conversion);

    for (unsigned int idx = 0; idx < tests.size(); idx++) {
        const UniValue& test = tests[idx];

        for (bool unaligned: {false, true}) {
            Val64Test::set_force_unaligned(unaligned);

            // JSON: COMMENT, u8-arr, u64-arr
            const std::vector<unsigned char> v_in = ParseVec8(test[1].get_array());
            std::vector<uint64_t> v_out = ParseVec64(test[2].get_array());

            // Check that we get expected u64 vector (make a copy, we mangle it!)
            Val64Test test_v64(v_in);
            std::vector<uint64_t> v64 = test_v64.copy_vector();
            CHECK(v64 == v_out);

            // We should get vector back!
            std::vector<unsigned char> v_ret = test_v64.move_to_valtype();
            CHECK(v_ret == v_in);
        }
    }
    Val64Test::set_force_unaligned(false);
}

BOOST_AUTO_TEST_CASE(val64_unaligned)
{
    Val64Test::set_force_unaligned(true);

    std::vector<unsigned char> v_in_empty;        
    std::vector<unsigned char> v_in_small = {1,2,3};
    std::vector<unsigned char> v_in_word = {1,2,3,4,5,6,7,8};
    std::vector<unsigned char> v_in_large = {1,2,3,4,5,6,7,8,9};
        
    // We don't mess with empty vectors (they're always "aligned")
    Val64Test v1(v_in_empty);
    CHECK(v1.u64_size() == 0);

    Val64Test v2(v_in_small);
    CHECK(v2.u64_size() == 1);

    CHECK(v2.get(0) == 0x0000000000030201);

    Val64Test v3(v_in_word);
    CHECK(v3.u64_size() == 1);

    CHECK(v3.get(0) == 0x0807060504030201);

    Val64Test v4(v_in_large);
    CHECK(v4.u64_size() == 2);

    CHECK(v4.get(0) == 0x0807060504030201);
    CHECK(v4.get(1) == 0x0000000000000009);

    Val64Test::set_force_unaligned(false);
}

BOOST_AUTO_TEST_CASE(val64_and_or_xor)
{
    // FIXME: Test varcosts!
    size_t varcost = 0;
    for (bool unaligned: {false, true}) {
        Val64Test::set_force_unaligned(unaligned);

        for (size_t i = 0; i < 128; i++) {
            for (size_t j = 0; j < 128; j++) {
                std::vector<unsigned char> expected_and, expected_or, expected_xor;

                expected_or = vec_setbit(j, vec_setbit(i, expected_or));
                if (i != j) {
                    expected_and = vec_sized_for_bit(i, vec_sized_for_bit(j));
                    expected_xor = expected_or;
                } else {
                    expected_and = vec_setbit(i);
                    expected_xor = vec_sized_for_bit(i);
                }

                // AND test
                {
                    Val64Test v64a(vec_setbit(i));
                    Val64Test v64b(vec_setbit(j));
                    Val64::op_and(v64a, v64b, varcost);
                    CHECK(v64a.move_to_valtype() == expected_and);
                }

                // OR test
                {
                    Val64Test v64a(vec_setbit(i));
                    Val64Test v64b(vec_setbit(j));
                    Val64::op_or(v64a, v64b, varcost);
                    CHECK(v64a.move_to_valtype() == expected_or);
                }

                // XOR test
                {
                    Val64Test v64a(vec_setbit(i));
                    Val64Test v64b(vec_setbit(j));
                    Val64::op_xor(v64a, v64b, varcost);
                    CHECK(v64a.move_to_valtype() == expected_xor);
                }
            }
        }


#ifdef USE_GMP
        for (size_t i = 0; i < 1000; i++) {
            size_t len1 = InsecureRandRange(50);
            size_t len2 = InsecureRandRange(50);

            std::vector<unsigned char> v1 =    g_insecure_rand_ctx.randbytes(len1);
            std::vector<unsigned char> v2 =    g_insecure_rand_ctx.randbytes(len2);

            // GMP version
            mpz_t mpz1, mpz2, mpz_result_and, mpz_result_or, mpz_result_xor;
            vector_to_mpz(v1, mpz1);
            vector_to_mpz(v2, mpz2);
            mpz_init(mpz_result_and);
            mpz_and(mpz_result_and, mpz1, mpz2);
            mpz_init(mpz_result_or);
            mpz_ior(mpz_result_or, mpz1, mpz2);
            mpz_init(mpz_result_xor);
            mpz_xor(mpz_result_xor, mpz1, mpz2);

            // We preserve length.
            size_t expected_len = std::max(len1, len2);
            std::vector<uint8_t> expect_and = mpz_to_vector(mpz_result_and, expected_len);
            std::vector<uint8_t> expect_or = mpz_to_vector(mpz_result_or, expected_len);
            std::vector<uint8_t> expect_xor = mpz_to_vector(mpz_result_xor, expected_len);
            mpz_clears(mpz1, mpz2, mpz_result_and, mpz_result_or, mpz_result_xor, NULL);

            // AND
            {
                Val64Test v64a(v1);
                Val64Test v64b(v2);
                Val64::op_and(v64a, v64b, varcost);
                CHECK(v64a.move_to_valtype() == expect_and);
            }

            // OR
            {
                Val64Test v64a(v1);
                Val64Test v64b(v2);
                Val64::op_or(v64a, v64b, varcost);
                CHECK(v64a.move_to_valtype() == expect_or);
            }

            // XOR
            {
                Val64Test v64a(v1);
                Val64Test v64b(v2);
                Val64::op_xor(v64a, v64b, varcost);
                CHECK(v64a.move_to_valtype() == expect_xor);
            }
        }
#endif
    }
}

BOOST_AUTO_TEST_CASE(val64_add)
{
    // FIXME: Test varcosts!
    size_t varcost = 0;
    for (bool unaligned: {false, true}) {
        Val64Test::set_force_unaligned(unaligned);

        // Add two bits, check result.
        for (size_t i = 0; i < 128; i++) {
            for (size_t j = 0; j < 128; j++) {
                Val64Test v64a(vec_setbit(i));
                Val64Test v64b(vec_setbit(j));
                Val64::op_add(v64a, v64b, varcost);

                // Check against expected vector.
                std::vector<unsigned char> expected;
                if (i != j) {
                    expected = vec_setbit(i);
                    expected = vec_setbit(j, expected);
                } else {
                    expected = vec_setbit(i + 1);
                }
                CHECK(v64a.move_to_valtype() == expected);
            }
        }

        // Overflow tests.
        for (size_t i = 1; i < 24; i++) {
            std::vector<unsigned char> almost(i, 0xff);
            std::vector<unsigned char> one{1};

            Val64 v64a(almost);
            Val64 v64b(one);
            Val64::op_add(v64a, v64b, varcost);
            std::vector<unsigned char> res = v64a.move_to_valtype();

            std::vector<unsigned char> expect(i, 0);
            expect.push_back(1);

            CHECK(res == expect);
        }

#ifdef USE_GMP
        for (size_t i = 0; i < 1000; i++) {
            size_t len1 = InsecureRandRange(50);
            size_t len2 = InsecureRandRange(50);

            std::vector<unsigned char> v1 =    g_insecure_rand_ctx.randbytes(len1);
            std::vector<unsigned char> v2 =    g_insecure_rand_ctx.randbytes(len2);

            BOOST_TEST_MESSAGE("Adding " << vector_to_string(v1) << " + " << vector_to_string(v2));

            // GMP version
            mpz_t mpz1, mpz2, mpz_result;
            vector_to_mpz(v1, mpz1);
            vector_to_mpz(v2, mpz2);
            mpz_init(mpz_result);
            mpz_add(mpz_result, mpz1, mpz2);
            std::vector<uint8_t> expect = mpz_to_vector(mpz_result);
            mpz_clears(mpz1, mpz2, mpz_result, NULL);

            // Val64 version
            Val64 v64_1(v1), v64_2(v2);

            Val64::op_add(v64_1, v64_2, varcost);
            std::vector<unsigned char> res = v64_1.move_to_valtype();

            CHECK(res == expect);
        }
#endif
    }
}

BOOST_AUTO_TEST_CASE(val64_sub)
{
    // FIXME: Test varcosts!
    size_t varcost = 0;
    for (bool unaligned: {false, true}) {
        Val64Test::set_force_unaligned(unaligned);

        // Sub zero (unchanged).
        for (size_t i = 0; i < 128; i++) {
            const std::vector<unsigned char> zero;

            // Subtract 0, should not change.
            Val64Test v64a(vec_setbit(i));
            Val64Test v64zero(zero);

            bool res = Val64::op_sub(v64a, v64zero, varcost);
            CHECK(res);
        
            CHECK(v64a.move_to_valtype() == vec_setbit(i));
        }

        // Sub one.
        for (size_t i = 63; i < 128; i++) {
            const std::vector<unsigned char> one{1};

            Val64Test v64a(vec_setbit(i));
            Val64Test v64one(one);

            bool res = Val64::op_sub(v64a, v64one, varcost);
            CHECK(res);

            std::vector<unsigned char> expected;
            for (size_t j = 0; j < i; j++)
                expected = vec_setbit(j, expected);

            std::vector<unsigned char> va = v64a.move_to_valtype();
            BOOST_TEST_MESSAGE("i is " << i << " expected " << vector_to_string(expected) << " got " << vector_to_string(va));
            CHECK(va == expected);
        }

#ifdef USE_GMP
        for (size_t i = 0; i < 1000; i++) {
            size_t len1 = InsecureRandRange(50);
            size_t len2 = InsecureRandRange(50);

            std::vector<unsigned char> v1 =    g_insecure_rand_ctx.randbytes(len1);
            std::vector<unsigned char> v2 =    g_insecure_rand_ctx.randbytes(len2);

            BOOST_TEST_MESSAGE("Subtracting " << vector_to_string(v1) << " - " << vector_to_string(v2));

            // GMP version
            mpz_t mpz1, mpz2, mpz_result;
            vector_to_mpz(v1, mpz1);
            vector_to_mpz(v2, mpz2);
            mpz_init(mpz_result);
            mpz_sub(mpz_result, mpz1, mpz2);
            std::vector<uint8_t> expect = mpz_to_vector(mpz_result);
            bool expect_neg = (mpz_sgn(mpz_result) == -1);
            mpz_clears(mpz1, mpz2, mpz_result, NULL);

            // Val64 version
            Val64 v64_1(v1), v64_2(v2);

            bool neg = !Val64::op_sub(v64_1, v64_2, varcost);
            std::vector<unsigned char> res = v64_1.move_to_valtype();

            if (expect_neg) {
                CHECK(neg == true);
            } else {
                CHECK(neg == false);
                CHECK(res == expect);
            }
        }
#endif
    }
}

BOOST_AUTO_TEST_CASE(val64_cmp)
{
    // FIXME: Test varcosts!
    size_t varcost = 0;
    for (bool unaligned: {false, true}) {
        Val64Test::set_force_unaligned(unaligned);

        for (size_t i = 0; i < 128; i++) {
            for (size_t j = 0; j < 128; j++) {
                std::vector<unsigned char> va = vec_setbit(i);
                std::vector<unsigned char> vb = vec_setbit(j);
                BOOST_TEST_MESSAGE("Cmp " << vector_to_string(va) << " vs " << vector_to_string(vb));

                Val64 v64a(va);
                Val64 v64b(vb);
                int res = v64a.cmp(v64b, varcost);

                int expected;
                if (i == j)
                    expected = 0;
                else if (i > j)
                    expected = 1;
                else
                    expected = -1;

                BOOST_TEST_MESSAGE("Got " << res << " expected " << expected);

                CHECK(res == expected);
            }
        }


#ifdef USE_GMP
        for (size_t i = 0; i < 1000; i++) {
            size_t len1 = InsecureRandRange(50);
            size_t len2 = InsecureRandRange(50);

            std::vector<unsigned char> v1 =    g_insecure_rand_ctx.randbytes(len1);
            std::vector<unsigned char> v2 =    g_insecure_rand_ctx.randbytes(len2);

            BOOST_TEST_MESSAGE("Cmp " << vector_to_string(v1) << " vs " << vector_to_string(v2));

            // GMP version
            mpz_t mpz1, mpz2;
            vector_to_mpz(v1, mpz1);
            vector_to_mpz(v2, mpz2);

            int expected = mpz_cmp(mpz1, mpz2);
            // Documentation says negative, zero or positive.  Normalize!
            if (expected > 0)
                expected = 1;
            else if (expected < 0)
                expected = -1;
            mpz_clears(mpz1, mpz2, NULL);

            // Val64 version
            Val64Test v64_1(v1), v64_2(v2);

            int res = v64_1.cmp(v64_2, varcost);

            CHECK(res == expected);
        }
#endif
    }
}

BOOST_AUTO_TEST_CASE(val64_upshift)
{
    // FIXME: Test varcosts!
    size_t varcost = 0;
    for (bool unaligned: {false, true}) {
        Val64Test::set_force_unaligned(unaligned);

        for (size_t i = 0; i < 128; i++) {
            for (size_t j = 0; j < 128; j++) {
                std::vector<unsigned char> va = vec_setbit(i);
                BOOST_TEST_MESSAGE("Upshift " << vector_to_string(va) << " by " << j);

                Val64 v64a(va);
                bool ok = Val64::op_upshift(v64a, val64_singleton(j), 1000, varcost);
                assert(ok);
                va = v64a.move_to_valtype();

                std::vector<unsigned char> expected = vec_setbit(i + j);
                // Definitionally, upshift inserts an extra (j + 7) / 8 bytes.
                expected.resize(1 + i / 8 + (j + 7) / 8);

                BOOST_TEST_MESSAGE("Got " << vector_to_string(va) << " expected " << vector_to_string(expected));

                CHECK(va == expected);
            }
        }


#ifdef USE_GMP
        for (size_t i = 0; i < 1000; i++) {
            size_t len1 = InsecureRandRange(500);
            size_t sbits = InsecureRandRange(500 * 8);

            std::vector<unsigned char> v1 =    g_insecure_rand_ctx.randbytes(len1);

            BOOST_TEST_MESSAGE("Left shifting " << vector_to_string(v1) << " by " << sbits);

            // GMP version
            mpz_t mpz1, mpz_result;
            vector_to_mpz(v1, mpz1);
            mpz_init(mpz_result);
            mpz_mul_2exp(mpz_result, mpz1, sbits);

            // Always leaves trailing zeroes
            std::vector<uint8_t> expect = mpz_to_vector(mpz_result, len1 + sbits / 8 + (sbits % 8 ? 1 : 0));
            mpz_clears(mpz1, mpz_result, NULL);

            // Val64 version
            Val64 v64(v1);
            bool ok = Val64::op_upshift(v64, val64_singleton(sbits), 5000, varcost);
            assert(ok);
            v1 = v64.move_to_valtype();

            CHECK(v1 == expect);
        }
#endif
    }
}

BOOST_AUTO_TEST_CASE(val64_downshift)
{
    // FIXME: Test varcosts!
    size_t varcost = 0;
    for (bool unaligned: {false, true}) {
        Val64Test::set_force_unaligned(unaligned);

        for (size_t i = 0; i < 128; i++) {
            for (size_t j = 0; j < 128; j++) {
                std::vector<unsigned char> va = vec_setbit(i);
                BOOST_TEST_MESSAGE("Downshift " << vector_to_string(va) << " by " << j);

                assert(va.size() == (i + 8) / 8);
                Val64 v64a(va);
                Val64::op_downshift(v64a, val64_singleton(j), varcost);
                va = v64a.move_to_valtype();

                std::vector<unsigned char> expected;
                if (j <= i)
                    expected = vec_setbit(i - j);

                // Definitionally, downshift only removes one byte for every 8 bits shifted.
                if (j / 8 <= (i + 8) / 8) 
                    expected.resize((i + 8) / 8 - j / 8);

                BOOST_TEST_MESSAGE("Got " << vector_to_string(va) << " expected " << vector_to_string(expected));

                CHECK(va == expected);
            }
        }


#ifdef USE_GMP
        for (size_t i = 0; i < 1000; i++) {
            size_t len1 = InsecureRandRange(500);
            size_t sbits = InsecureRandRange(500 * 8);

            std::vector<unsigned char> v1 =    g_insecure_rand_ctx.randbytes(len1);

            BOOST_TEST_MESSAGE("Right shifting " << vector_to_string(v1) << " by " << sbits);

            // GMP version
            mpz_t mpz1, mpz_result;
            vector_to_mpz(v1, mpz1);
            mpz_init(mpz_result);
            mpz_fdiv_q_2exp(mpz_result, mpz1, sbits);

            // We subtract only whole bytes from length.
            std::vector<uint8_t> expect = mpz_to_vector(mpz_result, v1.size() > sbits / 8 ? v1.size() - sbits / 8 : 0);
            mpz_clears(mpz1, mpz_result, NULL);

            // Val64 version
            Val64 v64(v1);
            Val64::op_downshift(v64, val64_singleton(sbits), varcost);
            v1 = v64.move_to_valtype();

            CHECK(v1 == expect);
        }
#endif
    }
}

BOOST_AUTO_TEST_CASE(val64_add_span)
{
    Val64Test res(std::vector<unsigned char>(sizeof(uint64_t) * 2));

    // 0xFFFFFFFFFFFFFFFF
    const Val64Test u64_max(std::vector<unsigned char>(sizeof(uint64_t), 0xff));
    const Val64Test u64_zero(std::vector<unsigned char>(sizeof(uint64_t), 0));
    bool carry;
    size_t nonzero_len;

    // Add empty at offset 0.
    carry = Val64Test::add_span(res.span(), u64_zero.span(), nonzero_len);
    assert(res.get(0) == 0);
    assert(res.get(1) == 0);
    assert(nonzero_len == 0);
    assert(!carry);
    
    // Add at offset 0.
    carry = Val64Test::add_span(res.span(), u64_max.span(), nonzero_len);
    assert(res.get(0) == 0xFFFFFFFFFFFFFFFFULL);
    assert(res.get(1) == 0);
    assert(nonzero_len == 1);
    assert(!carry);

    // Add at offset 1.
    carry = Val64Test::add_span(res.span().subspan(1), u64_max.span(), nonzero_len);
    assert(res.get(0) == 0xFFFFFFFFFFFFFFFFULL);
    assert(res.get(1) == 0xFFFFFFFFFFFFFFFFULL);
    // Relative to subspan!
    assert(nonzero_len == 1);
    assert(!carry);

    // Add one more, should carry.
    carry = Val64Test::add_span(res.span().subspan(1), Val64Test(1).span(), nonzero_len);
    assert(res.get(0) == 0xFFFFFFFFFFFFFFFFULL);
    assert(res.get(1) == 0);
    assert(carry);
}
    
BOOST_AUTO_TEST_CASE(val64_sub_span)
{
    Val64Test res(std::vector<unsigned char>(sizeof(uint64_t) * 2, 0xFF));

    // 0xFFFFFFFFFFFFFFFF
    const Val64Test u64_max(std::vector<unsigned char>(sizeof(uint64_t), 0xff));
    const Val64Test u64_zero(std::vector<unsigned char>(sizeof(uint64_t), 0));
    bool underflow;
    size_t nonzero_len;

    // Sub empty at offset 0.
    underflow = Val64Test::sub_span(res.span(), u64_zero.span(),
                                    nonzero_len);
    assert(res.get(0) == 0xFFFFFFFFFFFFFFFFULL);
    assert(res.get(1) == 0xFFFFFFFFFFFFFFFFULL);
    assert(nonzero_len == 2);
    assert(!underflow);

    // Sub at offset 1.
    underflow = Val64Test::sub_span(res.span().subspan(1), u64_max.span(),
                                    nonzero_len);
    assert(res.get(0) == 0xFFFFFFFFFFFFFFFFULL);
    assert(res.get(1) == 0);
    assert(nonzero_len == 0);
    assert(!underflow);

    // Sub at offset 0.
    underflow = Val64Test::sub_span(res.span(), u64_max.span(), nonzero_len);
    assert(res.get(0) == 0);
    assert(res.get(1) == 0);
    assert(nonzero_len == 0);
    assert(!underflow);

    // Sub one more, should underflow.
    underflow = Val64Test::sub_span(res.span().subspan(1), Val64Test(1).span(),
                                    nonzero_len);
    assert(res.get(0) == 0);
    assert(res.get(1) == 0xFFFFFFFFFFFFFFFFULL);
    assert(underflow);
}
    
BOOST_AUTO_TEST_CASE(val64_mul_span)
{
    Val64Test::set_force_unaligned(false);

    // Mulitply this by mul, place into res.
    for (size_t i = 0; i < 128; i++) {
        for (size_t j = 0; j < 65; j++) {
            Val64Test v64a(vec_setbit(i));

            // Initial contents shouldn't matter, but size needs to match.
            size_t vecsize = (v64a.u64_size() + 1) * sizeof(uint64_t);
            std::vector<unsigned char> dummy(vecsize, 1|j);
            Val64Test res64(dummy);

            if (j == 64) {
                // Test multiply by 0
                Val64Test::mul_span(res64.span(), v64a.span(), 0);
            } else {
                Val64Test::mul_span(res64.span(), v64a.span(), (uint64_t)1 << j);
            }

            // mul_vector does not trim zeros.
            std::vector<unsigned char> expected(vecsize);
            if (j != 64)
                expected = vec_setbit(i + j, expected);
            CHECK(res64.move_to_valtype() == expected);
        }
    }
}

BOOST_AUTO_TEST_CASE(val64_mul)
{
    // FIXME: Test varcosts!
    size_t varcost = 0;
    for (bool unaligned: {false, true}) {
        Val64Test::set_force_unaligned(unaligned);

        for (size_t i = 0; i < 128; i++) {
            for (size_t j = 0; j < 129; j++) {
                std::vector<unsigned char> va = vec_setbit(i), vb;

                if (j != 129) // Test multiply by 0!
                    vb = vec_setbit(j);
                BOOST_TEST_MESSAGE("Multiply " << vector_to_string(va) << " by " << vector_to_string(vb));

                Val64 v64a(va);
                Val64 v64b(vb);
                Val64 ret = Val64::op_mul(v64a, v64b);
                auto retvec = ret.move_to_valtype();

                std::vector<unsigned char> expected;
                if (j != 129)
                    expected = vec_setbit(i + j);

                BOOST_TEST_MESSAGE("Got " << vector_to_string(retvec) << " expected " << vector_to_string(expected));

                CHECK(retvec == expected);
            }
        }

        // Also easy to test N-1.
        for (size_t i = 1; i < 128; i++) {
            for (size_t j = 0; j < 128; j++) {
                std::vector<unsigned char> va, vb;

                for (size_t n = 0; n < i; n++)
                    va = vec_setbit(n, va);
                vb = vec_setbit(j);
                BOOST_TEST_MESSAGE("Multiply " << vector_to_string(va) << " by " << vector_to_string(vb));

                Val64 v64a(va);
                Val64 v64b(vb);
                Val64 ret = Val64::op_mul(v64a, v64b);
                auto retvec = ret.move_to_valtype();

                // Subtract 1 j.
                Val64Test expected64(vec_setbit(i + j));
                Val64Test single(vec_setbit(j));
                bool ok = Val64::op_sub(expected64, single, varcost);
                assert(ok);
                std::vector<unsigned char> expected = expected64.move_to_valtype();

                BOOST_TEST_MESSAGE("Got " << vector_to_string(retvec) << " expected " << vector_to_string(expected));

                CHECK(retvec == expected);
            }
        }        

#ifdef USE_GMP
        for (size_t i = 0; i < 1000; i++) {
            size_t len1 = InsecureRandRange(50);
            size_t len2 = InsecureRandRange(50);

            std::vector<unsigned char> v1 =    g_insecure_rand_ctx.randbytes(len1);
            std::vector<unsigned char> v2 =    g_insecure_rand_ctx.randbytes(len2);

            BOOST_TEST_MESSAGE("Multiplying " << vector_to_string(v1) << " by " << vector_to_string(v2));

            // GMP version
            mpz_t mpz1, mpz2, mpz_result;
            vector_to_mpz(v1, mpz1);
            vector_to_mpz(v2, mpz2);
            mpz_init(mpz_result);
            mpz_mul(mpz_result, mpz1, mpz2);

            std::vector<uint8_t> expect = mpz_to_vector(mpz_result);
            mpz_clears(mpz1, mpz2, mpz_result, NULL);

            // Val64 version
            Val64 v64a(v1);
            Val64 v64b(v2);
            Val64 ret64 = Val64::op_mul(v64a, v64b);
            std::vector<uint8_t> ret = ret64.move_to_valtype();

            CHECK(ret == expect);
        }
#endif
    }
}

BOOST_AUTO_TEST_CASE(val64_2mul)
{
    // FIXME: Test varcosts!
    size_t varcost = 0;
    for (bool unaligned: {false, true}) {
        Val64Test::set_force_unaligned(unaligned);

        for (size_t i = 0; i < 129; i++) {
            for (size_t j = 0; j < 16; j++) {
                std::vector<unsigned char> va;

                // Test zero case
                if (i != 128)
                    va = vec_setbit(i);

                // Append empty bytes (shouldn't make a difference)
                va.insert(va.end(), j, 0);
                BOOST_TEST_MESSAGE("2mul " << vector_to_string(va));

                Val64 v64a(va);
                Val64::op_2mul(v64a, varcost);
                va = v64a.move_to_valtype();

                std::vector<unsigned char> expected;

                if (i != 128)
                    expected = vec_setbit(i + 1);

                BOOST_TEST_MESSAGE("Got " << vector_to_string(va) << " expected " << vector_to_string(expected));

                CHECK(va == expected);
            }
        }


#ifdef USE_GMP
        for (size_t i = 0; i < 1000; i++) {
            size_t len1 = InsecureRandRange(500);
            std::vector<unsigned char> v1 =    g_insecure_rand_ctx.randbytes(len1);

            BOOST_TEST_MESSAGE("2mul " << vector_to_string(v1));

            // GMP version
            mpz_t mpz1, mpz_result;
            vector_to_mpz(v1, mpz1);
            mpz_init(mpz_result);
            mpz_mul_2exp(mpz_result, mpz1, 1);

            std::vector<uint8_t> expect = mpz_to_vector(mpz_result);
            mpz_clears(mpz1, mpz_result, NULL);

            // Val64 version
            Val64 v64(v1);
            Val64::op_2mul(v64, varcost);
            v1 = v64.move_to_valtype();

            CHECK(v1 == expect);
        }
#endif
    }
}

BOOST_AUTO_TEST_CASE(val64_2div)
{
    // FIXME: Test varcosts!
    size_t varcost = 0;
    for (bool unaligned: {false, true}) {
        Val64Test::set_force_unaligned(unaligned);

        for (size_t i = 0; i < 129; i++) {
            for (size_t j = 0; j < 16; j++) {
                std::vector<unsigned char> va;

                // Test zero case
                if (i != 128)
                    va = vec_setbit(i);

                // Append empty bytes (shouldn't make a difference)
                va.insert(va.end(), j, 0);

                BOOST_TEST_MESSAGE("2div " << vector_to_string(va));
                Val64 v64a(va);
                Val64::op_2div(v64a, varcost);
                va = v64a.move_to_valtype();

                std::vector<unsigned char> expected;
                if (i > 0 && i != 128)
                    expected = vec_setbit(i - 1);

                BOOST_TEST_MESSAGE("Got " << vector_to_string(va) << " expected " << vector_to_string(expected));

                CHECK(va == expected);
            }
        }


#ifdef USE_GMP
        for (size_t i = 0; i < 1000; i++) {
            size_t len1 = InsecureRandRange(500);
            std::vector<unsigned char> v1 =    g_insecure_rand_ctx.randbytes(len1);

            BOOST_TEST_MESSAGE("2mul " << vector_to_string(v1));

            // GMP version
            mpz_t mpz1, mpz_result;
            vector_to_mpz(v1, mpz1);
            mpz_init(mpz_result);
            mpz_fdiv_q_2exp(mpz_result, mpz1, 1);

            std::vector<uint8_t> expect = mpz_to_vector(mpz_result);
            mpz_clears(mpz1, mpz_result, NULL);

            // Val64 version
            Val64 v64(v1);
            Val64::op_2div(v64, varcost);
            v1 = v64.move_to_valtype();

            CHECK(v1 == expect);
        }
#endif
    }
}

BOOST_AUTO_TEST_CASE(val64_div_mod)
{
    for (bool unaligned: {false, true}) {
        Val64Test::set_force_unaligned(unaligned);

        for (size_t i = 0; i < 128; i++) {
            for (size_t j = 0; j < 129; j++) {
                std::vector<unsigned char> va = vec_setbit(i), vb;

                if (j != 129) // Test divide by 0!
                    vb = vec_setbit(j);
                BOOST_TEST_MESSAGE("Divide " << vector_to_string(va) << " by " << vector_to_string(vb));

                Val64Test v64a_div(va), v64a_mod(va);
                Val64Test v64b_div(vb), v64b_mod(vb);
                bool div_ret = Val64Test::op_div(v64a_div, v64b_div);
                bool mod_ret = Val64Test::op_mod(v64a_mod, v64b_mod);
                auto div_vec = v64a_div.move_to_valtype();
                auto mod_vec = v64a_mod.move_to_valtype();

                std::vector<unsigned char> expected_div, expected_remainder;
                if (j == 129) {
                    CHECK(div_ret == false);
                    CHECK(mod_ret == false);
                } else {
                    CHECK(div_ret == true);
                    CHECK(mod_ret == true);
                    if (i >= j)
                        expected_div = vec_setbit(i - j);
                    else
                        expected_remainder = vec_setbit(i);

                    BOOST_TEST_MESSAGE("Got " << vector_to_string(div_vec) << "/" << vector_to_string(mod_vec) << " expected " << vector_to_string(expected_div) << "/" << vector_to_string(expected_remainder));

                    CHECK(div_vec == expected_div);
                    CHECK(mod_vec == expected_remainder);
                }
            }
        }

#ifdef USE_GMP
        for (size_t i = 0; i < 1000; i++) {
            size_t len1 = InsecureRandRange(50);
            size_t len2 = InsecureRandRange(50);

            std::vector<unsigned char> v1 =    g_insecure_rand_ctx.randbytes(len1);
            std::vector<unsigned char> v2 =    g_insecure_rand_ctx.randbytes(len2);

            BOOST_TEST_MESSAGE("Dividing " << vector_to_string(v1) << " by " << vector_to_string(v2));

            // GMP version
            mpz_t mpz1, mpz2, mpz_result, mpz_remainder;
            bool expect_success;
            vector_to_mpz(v1, mpz1);
            vector_to_mpz(v2, mpz2);
            mpz_init(mpz_result);
            mpz_init(mpz_remainder);
            if (mpz_sgn(mpz2) == 0) {
                expect_success = false;
            } else {
                mpz_fdiv_qr(mpz_result, mpz_remainder, mpz1, mpz2);
                expect_success = true;
            }
            std::vector<uint8_t> expect_res = mpz_to_vector(mpz_result);
            std::vector<uint8_t> expect_rem = mpz_to_vector(mpz_remainder);
            mpz_clears(mpz1, mpz2, mpz_result, mpz_remainder, NULL);

            // Val64 version
            Val64Test v64a_div(v1), v64a_mod(v1);
            Val64Test v64b_div(v2), v64b_mod(v2);
            bool div_ret = Val64Test::op_div(v64a_div, v64b_div);
            bool mod_ret = Val64Test::op_mod(v64a_mod, v64b_mod);
            auto div_vec = v64a_div.move_to_valtype();
            auto mod_vec = v64a_mod.move_to_valtype();

            CHECK(div_ret == expect_success);
            CHECK(mod_ret == expect_success);
            if (expect_success) {
                CHECK(div_vec == expect_res);
                CHECK(mod_vec == expect_rem);
            }
        }
#endif
    }
}
BOOST_AUTO_TEST_SUITE_END()
