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

void Val64::op_add(Val64 &v1, Val64 &v2)
{
    le64 *v1u64;
    const le64 *v2u64;
    size_t v1u64len, v2u64len;

    binop_v1_longest(v1, v2);

    v1u64 = v1.access_u64(&v1u64len);
    v2u64 = v2.access_u64(&v2u64len);

    // Little endian, overflow forward.
    bool carry = false;
    bool trimmed = false;

    // We track the last non-zero val, so we don't have
    // to traverse again to trim.
    size_t trailing_zero = 0;

    for (size_t i = 0; i < v1.u64_size(); ++i) {
        uint64_t u1, u2;

        u1 = v1.get(v1u64, v1u64len, i);
        u2 = v2.get(v2u64, v2u64len, i);

        carry = __builtin_add_overflow(u1, carry, &u1);
        carry |= __builtin_add_overflow(u1, u2, &u1);
        trimmed = !v1.set(v1u64, v1u64len, i, u1);
        if (u1 != 0)
            trailing_zero = i + 1;
    }

    // Final carry, or final set() trimmed
    if (carry || trimmed)
        v1.m_charv.push_back(1);
    else
        v1.trim_u64(trailing_zero);
}

bool Val64::op_sub(Val64 &v1, const Val64 &v2)
{
    le64 *v1u64;
    const le64 *v2u64;
    size_t v1u64len, v2u64len;
    auto len = std::max(v1.u64_size(), v2.u64_size());

    v1u64 = v1.access_u64(&v1u64len);
    v2u64 = v2.access_u64(&v2u64len);

    // Little endian, underflow forward.
    bool underflow = false;

    // We track the last non-zero val, so we don't have
    // to traverse again to trim.
    size_t trailing_zero = 0;

    for (size_t i = 0; i < len; ++i) {
        uint64_t u1, u2;

        u1 = v1.get(v1u64, v1u64len, i);
        u2 = v2.get(v2u64, v2u64len, i);

        underflow = __builtin_sub_overflow(u1, underflow, &u1);
        underflow |= __builtin_sub_overflow(u1, u2, &u1);
        // If we write (non-zero) past end, we underflowed.
        if (!v1.set(v1u64, v1u64len, i, u1))
            return false;
        if (u1 != 0)
            trailing_zero = i + 1;
    }

    v1.trim_u64(trailing_zero);

    // True if v1 >= v2
    return !underflow;
}

// 0 -> 0
// [1..8] -> 1
// [9..16] -> 2
size_t Val64::u64_size() const
{
    return (m_charv.size() + sizeof(uint64_t) - 1) / sizeof(uint64_t);
}

void Val64::bitshift_down(size_t words, size_t bits)
{
    le64 *vu64;
    size_t vu64len;

    assert(bits > 0);
    assert(bits < 64);

    vu64 = access_u64(&vu64len);

    // [B, A] rshift 1 => [B>>1 | A>>63, A << 1]
    uint64_t prev = get(vu64, vu64len, words);
    for (size_t i = words; i < u64_size() - 1; ++i) {
        uint64_t next = get(vu64, vu64len, i + 1);
        set(vu64, vu64len, i - words, (prev >> bits) | (next << (64 - bits)));
        prev = next;
    }
    // Shift the last word
    set(vu64, vu64len, u64_size() - 1 - words, prev >> bits);
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
