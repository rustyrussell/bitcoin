// Copyright (c) 2011-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/data/val64_conversion.json.h>
#include <script/val64.h>
#include <test/util/json.h>
#include <test/util/setup_common.h>
#include <util/vector.h>

#include <univalue.h>

#include <boost/test/unit_test.hpp>
#include <string>

BOOST_FIXTURE_TEST_SUITE(val64_tests, BasicTestingSetup)

// A de-privatizing child.
class Val64Test: public Val64 {
public:
    // Unlike Val64, this makes a copy.
    Val64Test(std::vector<unsigned char> v): Val64(v) { };
    Val64Test(const Val64Test &v): Val64(v) { };

    size_t u64_size() const { return Val64::u64_size(); }
    uint64_t get(size_t i) const { return Val64::non_access_get(i); }
    static void set_force_unaligned(bool val) { Val64::force_unaligned = val; }

    const uint64_t *access_u64(size_t *num) const { return Val64::access_u64(num); }

    std::vector<uint64_t> copy_vector() {
        std::vector<uint64_t> v;
        for (size_t i = 0; i < u64_size(); i++) {
            v.push_back(get(i));
        }
        return v;
    }
};    

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

    size_t dummy;
    Val64Test v2(v_in_small);
    CHECK(v2.u64_size() == 1);
    CHECK(v2.access_u64(&dummy) == NULL);

    CHECK(v2.get(0) == 0x0000000000030201);

    Val64Test v3(v_in_word);
    CHECK(v3.u64_size() == 1);
    CHECK(v3.access_u64(&dummy) == NULL);

    CHECK(v3.get(0) == 0x0807060504030201);

    Val64Test v4(v_in_large);
    CHECK(v4.u64_size() == 2);
    CHECK(v4.access_u64(&dummy) == NULL);

    CHECK(v4.get(0) == 0x0807060504030201);
    CHECK(v4.get(1) == 0x0000000000000009);

    Val64Test::set_force_unaligned(false);
}

BOOST_AUTO_TEST_SUITE_END()
