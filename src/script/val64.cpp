// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/val64.h>
#include <cassert>
#include <cstring>
#include <memory>
#include <endian.h>
#include <iostream>

// For testing.
bool Val64::force_unaligned = false;

// For clarity.
typedef uint64_t le64;

static void warn_alignment_once(const void *p, size_t len)
{
    static bool warned = false;

    if (warned)
        return;

    std::cerr
        << "WARNING: Vector pointer " << p
        << " size " << len
        << " is misaligned: performance may suffer"
        << std::endl;
    warned = true;
}

Val64::Val64(std::vector<unsigned char> &v)
{
    move_from_valtype(v);
}

void Val64::move_from_valtype(std::vector<unsigned char> &vch)
{
    m_charv = std::move(vch);
}

Val64::Val64()
{
}

Val64::Val64(const Val64 &v)
{
    m_charv = v.m_charv;
}

Val64::Val64(uint64_t v) : m_charv(8)
{
    bool ok = non_access_set(0, v);
    assert(ok);
    trim_u64(1);
}

// Move constructor
Val64::Val64(Val64&& other) noexcept:
    m_charv(std::move(other.m_charv))
{
}

// Move assignment operator
Val64& Val64::operator=(Val64&& other) noexcept {
    if (this != &other) {
        m_charv = std::move(other.m_charv);
    }
    return *this;
}

void Val64::swap(Val64 &other)
{
    std::swap(m_charv, other.m_charv);
}

std::vector<unsigned char> Val64::move_to_valtype()
{
    return std::move(m_charv);
}

uint64_t Val64::to_u64_ceil(size_t max) const
{
    const le64 *vu64;
    size_t vu64len;
    uint64_t v;

    vu64 = access_u64(&vu64len);

    // Little endian: get first word (zero-fills)
    v = get(vu64, vu64len, 0);
    if (v > max)
        return max;

    // Now make sure rest, if any, is zero.
    for (size_t i = 1; i < u64_size(); i++) {
        if (get(vu64, vu64len, i) != 0)
            return max;
    }

    return v;
}

bool Val64::is_zero() const
{
    return to_u64_ceil(1) == 0;
}

int Val64::cmp_with_offset(const Val64 &v2, size_t shift_words) const
{
    const le64 *v1u64, *v2u64;
    size_t v1u64len, v2u64len;

    v1u64 = access_u64(&v1u64len);
    v2u64 = v2.access_u64(&v2u64len);

    size_t maxlen = std::max(u64_size(), v2.u64_size() + shift_words);
    for (ssize_t i = maxlen-1; i >= 0; --i) {
        uint64_t iv1 = get(v1u64, v1u64len, i);
        uint64_t iv2 = size_t(i) < shift_words ? 0 : v2.get(v2u64, v2u64len, i - shift_words);
        if (iv1 < iv2)
            return -1;
        if (iv1 > iv2)
            return 1;
    }
    return 0;
}

int Val64::cmp(const Val64 &v2) const
{
    return cmp_with_offset(v2, 0);
}

// if p not aligned: sets num_u64s to 0, returns NULL.
// Otherwise, returns sets num_u64s to number of whole u64s, returns p.
static const void *u64_aligned_len(void *vp, size_t len, bool force_unaligned,
                                   size_t *num_u64s)
{
    void *orig = vp;
    if (std::align(alignof(uint64_t), sizeof(uint64_t), vp, len) == orig
        && !force_unaligned) {
        *num_u64s = len / sizeof(uint64_t);
        return vp;
    }
    if (len >= 8)
        warn_alignment_once(orig, len);

    *num_u64s = 0;
    return NULL;
}
    
const uint64_t *Val64::access_u64(size_t *num) const
{
    void *vp = (void *)m_charv.data();

    return (const uint64_t *)u64_aligned_len(vp, m_charv.size(), force_unaligned, num);
}

uint64_t *Val64::access_u64(size_t *num)
{
    void *vp = (void *)m_charv.data();

    return (uint64_t *)u64_aligned_len(vp, m_charv.size(), force_unaligned, num);
}

// Access the non-u64-compatible part
uint64_t Val64::non_access_get(size_t index) const
{
    le64 ret = 0;
    size_t off = index * sizeof(uint64_t);

    // Everything past end is 0.
    if (off >= m_charv.size())
        return 0;

    size_t len = m_charv.size() - off;
    if (len > sizeof(uint64_t))
        len = sizeof(uint64_t);
    memcpy(&ret, m_charv.data() + off, len);
    return le64toh(ret);
}

// Access the non-u64-compatible part.  Returns false if trimmed.
bool Val64::non_access_set(size_t index, uint64_t v)
{
    le64 val = htole64(v);
    size_t off = index * sizeof(uint64_t);

    // You can write zeroes past end without trimming.
    if (off >= m_charv.size())
        return v == 0;

    size_t len = m_charv.size() - off;
    if (len > sizeof(uint64_t))
        len = sizeof(uint64_t);
    memcpy(m_charv.data() + off, &val, len);
    return len == sizeof(uint64_t) || (val >> (len*8)) == 0;
}

uint64_t Val64::get(const uint64_t *access, size_t access_num, size_t idx) const
{
    if (idx < access_num)
        return le64toh(access[idx]);
    return non_access_get(idx);
}

bool Val64::set(uint64_t *access, size_t access_num, size_t idx, uint64_t val)
{
    if (idx < access_num) {
        access[idx] = htole64(val);
        return true;
    }
    return non_access_set(idx, val);
}    

size_t Val64::trim_tail()
{
    size_t trimmed = 0;
    while (m_charv.size() > 0 && m_charv.back() == 0) {
        m_charv.pop_back();
        trimmed++;
    }
    return trimmed;
}

void Val64::trim_u64(size_t u64_index)
{
    if (u64_index * sizeof(uint64_t) < m_charv.size()) {
#ifdef DEBUG
        // You promised these were all zeros!
        for (size_t i = u64_index * sizeof(uint64_t); i < m_charv.size(); i++)
            assert(m_charv[i] == 0);
#endif
        m_charv.resize(u64_index * sizeof(uint64_t));
    }

    // Technical violation of BIP, as this touches one more
    // cacheline.  But it's simple.
    size_t trimmed = trim_tail();

    // You were supposed to track last non-zero so we don't
    // walk all the way back here.
    assert(trimmed < sizeof(uint64_t));
}

// Add v1 into this at word offset shift_words.
// Returns offset of last zero byte in result.
size_t Val64::add_with_offset(const Val64 &v1, size_t shift_words, bool &carry)
{
    le64 *vu64;
    const le64 *v1u64;
    size_t vu64len, v1u64len;

    vu64 = access_u64(&vu64len);
    v1u64 = v1.access_u64(&v1u64len);

    // Little endian, overflow forward.
    carry = false;
    bool trimmed = false;

    // We track the last non-zero val, so we don't have
    // to traverse again to trim.
    size_t trailing_zero = shift_words;

    for (size_t i = 0; i < u64_size(); ++i) {
        uint64_t u1, u2;

        u1 = get(vu64, vu64len, shift_words + i);
        u2 = v1.get(v1u64, v1u64len, i);

        carry = __builtin_add_overflow(u1, carry, &u1);
        carry |= __builtin_add_overflow(u1, u2, &u1);
        trimmed |= !set(vu64, vu64len, shift_words + i, u1);
        if (u1 != 0)
            trailing_zero = shift_words + i + 1;
    }

    // Overflow at end causes trimmed flag to be set.
    carry |= trimmed;
    return trailing_zero;
}
    
void Val64::op_add(Val64 &v1, Val64 &v2)
{
    binop_v1_longest(v1, v2);

    bool carry;
    size_t trailing_zero = v1.add_with_offset(v2, 0, carry);

    if (carry)
        v1.m_charv.push_back(1);
    else
        v1.trim_u64(trailing_zero);
}

void Val64::op_1add(Val64 &v1)
{
    Val64 v2(1);

    op_add(v1, v2);
}

// *this -= v1 << shift_words*64
size_t Val64::sub_with_offset(const Val64 &v1, size_t shift_words, bool &underflow)
{
    le64 *u64;
    const le64 *v1u64;
    size_t u64len, v1u64len;

    // This is max(u64_size() - shift_words, v1.u64_size()):
    auto maxlen = v1.u64_size();
    if (u64_size() > shift_words && u64_size() - shift_words > maxlen)
        maxlen = u64_size() - shift_words;
    
    u64 = access_u64(&u64len);
    v1u64 = v1.access_u64(&v1u64len);

    // Little endian, underflow forward.
    underflow = false;

    // We track the last non-zero val, so we don't have
    // to traverse again to trim.
    size_t trailing_zero = shift_words;
    bool trimmed = false;

    for (size_t i = 0; i < maxlen; ++i) {
        uint64_t u1, u2;

        u1 = get(u64, u64len, shift_words + i);
        u2 = v1.get(v1u64, v1u64len, i);

        underflow = __builtin_sub_overflow(u1, underflow, &u1);
        underflow |= __builtin_sub_overflow(u1, u2, &u1);
        trimmed = !set(u64, u64len, shift_words + i, u1);
        if (u1 != 0)
            trailing_zero = shift_words + i + 1;
    }

    // Underflow at end causes trimmed flag to be set.
    underflow |= trimmed;
    return trailing_zero;
}

bool Val64::op_sub(Val64 &v1, const Val64 &v2)
{
    bool underflow;
    size_t trailing_zero = v1.sub_with_offset(v2, 0, underflow);

    if (underflow)
        return false;

    v1.trim_u64(trailing_zero);
    return true;
}

bool Val64::op_1sub(Val64 &v1)
{
    const Val64 v2(1);

    return op_sub(v1, v2);
}

// 0 -> 0
// [1..8] -> 1
// [9..16] -> 2
size_t Val64::u64_size() const
{
    return (m_charv.size() + sizeof(uint64_t) - 1) / sizeof(uint64_t);
}

size_t Val64::bitshift_down(size_t words, size_t bits)
{
    le64 *vu64;
    size_t vu64len;

    // Not empty
    assert(u64_size() != 0);
    assert(bits > 0);
    assert(bits < 64);

    vu64 = access_u64(&vu64len);

    // We track the last non-zero val, so we don't have
    // to traverse again to trim.
    size_t trailing_zero = 0;

    // [B, A] rshift 1 => [B>>1 | A>>63, A << 1]
    uint64_t prev = get(vu64, vu64len, words);
    for (size_t i = words; i < u64_size() - 1; ++i) {
        uint64_t next = get(vu64, vu64len, i + 1);
        uint64_t v = (prev >> bits) | (next << (64 - bits));
        set(vu64, vu64len, i - words, v);
        if (v != 0)
            trailing_zero = i - words + 1;
        prev = next;
    }
    // Shift the last word
    set(vu64, vu64len, u64_size() - 1 - words, prev >> bits);
    if ((prev >> bits) != 0)
        trailing_zero = u64_size() - words;

    return trailing_zero;
}
    
void Val64::op_downshift(Val64 &v1, const Val64 &v2)
{
    uint64_t bits = v2.to_u64_ceil(v1.m_charv.size() * 8);
    size_t bytes = bits / 8;

    // Shift past end?  Empty.  Also covers empty array.
    if (bytes >= v1.m_charv.size()) {
        v1.m_charv.resize(0);
        return;
    }

    // Bitwise shifts can't do 0 anyway, as << 64 undefined.
    // And we might as well do erase here if we can.
    if (bits % 8 == 0) {
        // Remove least-significant words.
        v1.m_charv.erase(v1.m_charv.begin(),
                         v1.m_charv.begin() + bytes);
        return;
    }

    // Size after this is at least 1!
    assert(v1.u64_size() > 0);

    // We shift and move at the same time.
    v1.bitshift_down(bits / 64, bits % 64);

    // Truncate.
    v1.m_charv.resize(v1.m_charv.size() - bytes);
}

// This means "shift bits higher": number go up!
bool Val64::op_upshift(Val64 &v1, const Val64 &v2, size_t max_size)
{
    // BIP#ops: If the sum of BITS plus 8 times the length of A is greater than
    // 520,000 x 8, fail.    
    uint64_t bits = v2.to_u64_ceil(max_size * 8 + 1);

    // Cannot overflow: size() is (far) less than 32 bits, so is max_size.
    if (bits + v1.m_charv.size() * 8 > max_size * 8)
        return false;

    // How many whole bytes should we prepend?
    size_t prebytes = bits / 8;

    if (bits % 8 == 0) {
        // Simply insert bytes at the beginning.
        v1.m_charv.insert(v1.m_charv.begin(), prebytes, 0);
    } else {
        // There's no nice C++ "add this many bytes at the beginning,
        // and one at the end" so we are actually best off prepending too
        // many bytes (fast!) and shifting backwards.
        v1.m_charv.insert(v1.m_charv.begin(), prebytes + 1, 0);
        v1.bitshift_down(0, 8 - (bits % 8));
    }

    return true;
}

size_t Val64::bitshift_up_small(size_t bits, bool &carry)
{
    le64 *vu64;
    size_t vu64len;

    assert(bits > 0);
    assert(bits < 64);

    vu64 = access_u64(&vu64len);

    uint64_t prevbits = 0;
    size_t trailing_zero = 0;
    carry = false;

    // [B, A] lshift 1 => [B<<1, A<<1 | B >> 63]
    for (size_t i = 0; i < u64_size(); ++i) { 
        uint64_t old_v = get(vu64, vu64len, i);
        uint64_t new_v = (old_v << bits) | prevbits;

        carry = !set(vu64, vu64len, i, new_v);
        if (new_v != 0)
            trailing_zero = i + 1;
        prevbits = old_v >> (64 - bits);
    }
    // Either the set indicated we lost non-zero bits, or prevbits
    // says we should carry.
    if (prevbits != 0)
        carry = true;

    return trailing_zero;
}

void Val64::op_2mul(Val64 &v1)
{
    bool carry;
    size_t trailing_zero;

    trailing_zero = v1.bitshift_up_small(1, carry);

    if (carry)
        v1.m_charv.push_back(1);
    else
        v1.trim_u64(trailing_zero);
}

void Val64::op_2div(Val64 &v1)
{
    size_t trailing_zero;

    // bitshift_down assumes non-zero size.
    if (v1.u64_size() == 0)
        return;

    trailing_zero = v1.bitshift_down(0, 1);
    v1.trim_u64(trailing_zero);
}

void Val64::op_invert(Val64 &v1)
{
    le64 *vu64;
    size_t vu64len;

    vu64 = v1.access_u64(&vu64len);
    for (size_t i = 0; i < v1.u64_size(); ++i) {
        v1.set(vu64, vu64len, i, v1.get(vu64, vu64len, i) ^ UINT64_MAX);
    }
}

// Makes sure v1 is at least as long as v2.
void Val64::binop_v1_longest(Val64 &v1, Val64 &v2)
{
    // Make sure v1 is the longer one.
    if (v1.m_charv.size() < v2.m_charv.size())
        v1.swap(v2);
}
    
void Val64::op_and(Val64 &v1, Val64 &v2)
{
    le64 *v1u64;
    const le64 *v2u64;
    size_t v1u64len, v2u64len;

    binop_v1_longest(v1, v2);

    v1u64 = v1.access_u64(&v1u64len);
    v2u64 = v2.access_u64(&v2u64len);

    for (size_t i = 0; i < v1.u64_size(); ++i) {
        v1.set(v1u64, v1u64len, i,
               v1.get(v1u64, v1u64len, i) & v2.get(v2u64, v2u64len, i));
    }
}

void Val64::op_or(Val64 &v1, Val64 &v2)
{
    le64 *v1u64;
    const le64 *v2u64;
    size_t v1u64len, v2u64len;

    binop_v1_longest(v1, v2);

    v1u64 = v1.access_u64(&v1u64len);
    v2u64 = v2.access_u64(&v2u64len);

    for (size_t i = 0; i < v1.u64_size(); ++i) {
        v1.set(v1u64, v1u64len, i,
               v1.get(v1u64, v1u64len, i) | v2.get(v2u64, v2u64len, i));
    }
}

void Val64::op_xor(Val64 &v1, Val64 &v2)
{
    le64 *v1u64;
    const le64 *v2u64;
    size_t v1u64len, v2u64len;

    binop_v1_longest(v1, v2);

    v1u64 = v1.access_u64(&v1u64len);
    v2u64 = v2.access_u64(&v2u64len);

    for (size_t i = 0; i < v1.u64_size(); ++i) {
        v1.set(v1u64, v1u64len, i,
               v1.get(v1u64, v1u64len, i) ^ v2.get(v2u64, v2u64len, i));
    }
}

void Val64::mul_vector(Val64 &res, uint64_t mul) const
{
    const le64 *vu64;
    le64 *resu64;
    size_t vu64len, resu64len;

    vu64 = access_u64(&vu64len);
    resu64 = res.access_u64(&resu64len);

    // Result must be (at least) 1 word larger, for carry.
    assert(res.u64_size() >= u64_size() + 1);

    // Calculate this * mul, into res.
    res.set(resu64, resu64len, 0, 0);
    for (size_t i = 0; i < u64_size(); i++) {
        uint64_t hi, lo, oldhi;

        // Take advantage of 64 bit multiplier if platform
        // has it (otherwise falls back to software)
        unsigned __int128 product;

        product = get(vu64, vu64len, i);
        product *= mul;
        hi = product >> 64;
        lo = product;

        oldhi = res.get(resu64, resu64len, i);
        /* Note: hi cannot overflow since UINT64MAX * UINT64MAX
         * gives an upper u64 which is < UINT64MAX. */
        if (__builtin_add_overflow(lo, oldhi, &lo))
            hi++;
        res.set(resu64, resu64len, i, lo);
        res.set(resu64, resu64len, i+1, hi);
    }
}

Val64 Val64::op_mul(Val64 &v1, Val64 &v2)
{
    const le64 *v1u64;
    size_t v1u64len;

    // Slightly more optimal if v1 is the larger operand.
    binop_v1_longest(v1, v2);

    // Access into v1.
    v1u64 = v1.access_u64(&v1u64len);

    // Result.
    std::vector<unsigned char> retvec(v1.m_charv.size() + v2.m_charv.size());
    Val64 ret(retvec);

    // Result of each v1[] * v2 (make it whole u64s).
    std::vector<unsigned char> scratchvec((v2.u64_size() + 1) * sizeof(uint64_t));
    Val64 scratch(scratchvec);

    // Track where last 0 was in v1, so trimming doesn't traverse again.
    size_t trailing_zero = 0;
    
    for (size_t i = 0; i < v1.u64_size(); i++) {
        size_t this_trailing_zero;

        // Multiply v2 by v1[i].
        v2.mul_vector(scratch, v1.get(v1u64, v1u64len, i));

        // Now add into result at offset i.
        // Cannot overflow.  Worst case ret effectively adds 1 to v1[i],
        // which *still* doesn't quite overflow.
        bool carry;
        this_trailing_zero = ret.add_with_offset(scratch, i, carry);
        assert(!carry);

        // If we wrote all zeros, don't update previous best.
        if (this_trailing_zero != i)
            trailing_zero = this_trailing_zero;
    }

    ret.trim_u64(trailing_zero);
    return ret;
}
