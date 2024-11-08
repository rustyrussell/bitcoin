// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/val64.h>
#include <bit>
#include <cassert>
#include <cstring>
#include <memory>
#include <endian.h>
#include <iostream>

// For testing.
bool Val64::force_unaligned = false;

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

size_t Val64::u64ptr_off() const
{
    const unsigned char *p = reinterpret_cast<const unsigned char *>(m_u64span.data());

    /* Sanity check it's in bounds */
    assert(p >= m_charvec.data());
    assert(p + m_realsize <= m_charvec.data() + m_charvec.size());

    return p - m_charvec.data();
}

// Only m_charvec is set: initialize other fields.
void Val64::set_span()
{
    m_realsize = m_charvec.size();

    // Round up to get number of u64s
    size_t u64size = (m_realsize + sizeof(uint64_t) - 1) / sizeof(uint64_t);

    // Enlarge if necessary (trailing zeroes are harmless in little-endian)
    if (m_charvec.size() < u64size * sizeof(uint64_t))
        m_charvec.insert(m_charvec.end(), u64size * sizeof(uint64_t) - m_charvec.size(), 0);

    // We are always 64-bit aligned, but we handle it if we're not.
    size_t space = m_charvec.size();
    void *ptr = m_charvec.data();
    if (std::align(alignof(uint64_t), u64size * sizeof(uint64_t), ptr, space) == m_charvec.data()
        && ptr == m_charvec.data()
        && !force_unaligned) {
        m_u64span = Span<le64_t>(reinterpret_cast<uint64_t *>(m_charvec.data()), u64size);
        return;
    }

    warn_alignment_once(m_charvec.data(), m_charvec.size());

    // Append zeroes so we can move values.  This might change alignment.
    m_charvec.insert(m_charvec.end(), sizeof(uint64_t), 0);
    space = m_charvec.size();
    ptr = m_charvec.data();
    std::align(alignof(uint64_t), u64size * sizeof(uint64_t), ptr, space);

    // For testing, it will actually be aligned, so move a whole u64.
    if (force_unaligned && ptr == m_charvec.data())
        ptr = m_charvec.data() + sizeof(uint64_t);

    m_u64span = Span<le64_t>(reinterpret_cast<uint64_t *>(ptr), u64size);

    // Figure out how much the offset now is, so we can move data.
    size_t off = u64ptr_off();
    memmove(m_charvec.data() + off, m_charvec.data(), u64size * sizeof(uint64_t));
}

// Remove offset because we're changing m_charvec.
void Val64::charvec_change_start()
{
    size_t off = u64ptr_off();
    if (off)
        m_charvec.erase(m_charvec.begin(), m_charvec.begin() + off);

    // Trim any added bytes.
    assert(m_realsize <= m_charvec.size());
    m_charvec.resize(m_realsize);
}

void Val64::charvec_change_end()
{
    set_span();
}

void Val64::remove_front(size_t bytes)
{
    assert(bytes <= m_realsize);

    charvec_change_start();
    m_charvec.erase(m_charvec.begin(), m_charvec.begin() + bytes);
    charvec_change_end();
}

void Val64::prepend_zeros(size_t prebytes)
{
    charvec_change_start();
    m_charvec.insert(m_charvec.begin(), prebytes, 0);
    charvec_change_end();
}

void Val64::truncate(size_t new_realsize)
{
    assert(new_realsize <= m_charvec.size());

    charvec_change_start();
    m_charvec.resize(new_realsize);
    charvec_change_end();
}

void Val64::move_from_valtype(std::vector<unsigned char> &vch)
{
    m_charvec = std::move(vch);
    set_span();
}

std::vector<unsigned char> Val64::move_to_valtype()
{
    std::vector<unsigned char> ret;

    charvec_change_start();
    ret = std::move(m_charvec);
    charvec_change_end();

    return ret;
}

Val64::Val64()
{
    set_span();
}

Val64::Val64(const Val64 &v)
{
    m_charvec = v.m_charvec;
    set_span();
}

// Faster "trim zeroes from end" function
void Val64::trim_tail(size_t nonzero_len)
{
#if DEBUG
    // Check that the words after nonzero len are indeed all zero.
    for (size_t i = nonzero_len; i < m_u64span.size(); i++) {
        assert(m_u64span[i] == 0);
    }
#endif

    if (nonzero_len < m_u64span.size())
        m_u64span = m_u64span.first(nonzero_len);

    trim_tail();
}

void Val64::trim_tail()
{
    // We don't care how long it started, just what it could be now.
    m_realsize = m_u64span.size_bytes();

    charvec_change_start();
    while (m_charvec.size() > 0 && m_charvec.back() == 0)
        m_charvec.pop_back();
    charvec_change_end();
}

Val64::Val64(uint64_t v) : m_charvec(sizeof(uint64_t))
{
    set_span();
    set(0, v);
    trim_tail();
}

// Move constructor
Val64::Val64(Val64&& other) noexcept:
    m_charvec(std::move(other.m_charvec))
{
    set_span();
}

// Move assignment operator
Val64& Val64::operator=(Val64&& other) noexcept {
    if (this != &other) {
        other.charvec_change_start();
        m_charvec = std::move(other.m_charvec);
        other.charvec_change_end();
        set_span();
    }
    return *this;
}

void Val64::swap(Val64 &other)
{
    std::swap(m_charvec, other.m_charvec);
    std::swap(m_realsize, other.m_realsize);
    std::swap(m_u64span, other.m_u64span);
}

void Val64::set(size_t index, uint64_t v)
{
    m_u64span[index] = htole64(v);
}

uint64_t Val64::get(size_t index) const
{
    return le64toh(m_u64span[index]);
}

uint64_t Val64::get_or_zero(size_t index) const
{
    if (index >= m_u64span.size())
        return 0;
    return get(index);
}

// Append a 1 byte to the u64ptr array.
void Val64::append_one()
{
    charvec_change_start();

    // Make sure we have room to append.
    m_charvec.resize(m_u64span.size() * sizeof(uint64_t) + 1);
    m_charvec[m_u64span.size() * sizeof(uint64_t)] = 1;

    // Re-evaluate with new m_charvec.
    charvec_change_end();
}

uint64_t Val64::to_u64_ceil(size_t max, size_t &varcost) const
{
    uint64_t v;

    // Worst case, we have to examine all bytes.
    varcost += m_realsize;

    // Little endian: get first word (zero-fills)
    v = get_or_zero(0);
    if (v > max)
        return max;

    // If any other bytes are non-zero, it's > UINT64_MAX.
    if (m_u64span.size() > 1 && !span_is_allzero(m_u64span.last(m_u64span.size()-1))) {
        return max;
    }

    return v;
}

bool Val64::is_zero(size_t &varcost) const
{
    varcost += m_realsize;
    return span_is_allzero(m_u64span);
}

bool Val64::span_is_allzero(const Span<le64_t> span)
{
    if (span.size() == 0)
        return true;
    if (span[0] != 0)
        return false;
    // memcmp-with-self trick: see https://rusty.ozlabs.org/2015/10/20/ccanmems-memeqzero-iteration.html
    return memcmp(span.data(), span.data() + 1, (span.size() - 1) * sizeof(le64_t)) == 0;
}

// If v1 > v2: 1.  If v1 < v2: -1.  Else 0
int Val64::cmp_span(const Span<le64_t> v1, const Span<le64_t> v2)
{
    size_t maxlen = std::max(v1.size(), v2.size());

    for (ssize_t i = maxlen-1; i >= 0; --i) {
        uint64_t iv1, iv2;

        iv1 = size_t(i) < v1.size() ? le64toh(v1[i]) : 0;
        iv2 = size_t(i) < v2.size() ? le64toh(v2[i]) : 0;
        if (iv1 < iv2)
            return -1;
        if (iv1 > iv2)
            return 1;
    }
    return 0;
}

int Val64::cmp(const Val64 &v2, size_t &varcost) const
{
    // Worst case examination is both lengths
    varcost += m_realsize + v2.m_realsize;

    return cmp_span(m_u64span, v2.m_u64span);
}

// v1 += v2 (size v2 <= v1).  Return true if carry overflowed.
bool Val64::add_span(Span<le64_t> v1, const Span<le64_t> v2,
                     size_t &nonzero_len)
{
    assert(v1.size() >= v2.size());

    // Little endian, overflow forward.
    bool carry = false;

    size_t i;
    nonzero_len = 0;
    for (i = 0; i < v2.size(); ++i) {
        uint64_t u1, u2, res;

        u1 = le64toh(v1[i]);
        u2 = le64toh(v2[i]);

        res = u1 + u2 + carry;
        if (res)
            nonzero_len = i + 1;
        v1[i] = htole64(res);
        if (res > u1)
            carry = false;
        else {
            carry = (res < u1) || (res == u1 && u2 != 0);
        }
    }

    /* Carry forwards if required (continue even if not overflowing,
     * to set nonzero_len) */
    while (i < v1.size()) {
        uint64_t u1 = le64toh(v1[i] + carry);
        v1[i] = htole64(u1);
        if (u1)
            nonzero_len = i + 1;
        carry = carry && (u1 == 0);
        i++;
    }

    return carry;
}

void Val64::op_add(Val64 &v1, Val64 &v2, size_t &varcost)
{
    binop_v1_longest(v1, v2);

    // BIP#ops:
    // |OP_ADD
    // |Greater of two operand lengths * 3
    varcost += v1.m_realsize * 3;

    size_t nonzero_len;
    bool carry = add_span(v1.m_u64span, v2.m_u64span, nonzero_len);

    if (carry) {
        v1.append_one();
        return;
    }

    v1.trim_tail(nonzero_len);
}

void Val64::op_1add(Val64 &v1, size_t &varcost)
{
    Val64 v2(1);

    // BIP#ops:
    // |OP_1ADD
    // |MAX(1, operand length) * 3

    // BIP#ops:
    // OP_1ADD and OP_1SUB are the same cost as ADD/SUB with a minimal 1 operand.
    op_add(v1, v2, varcost);
}

// v1 -= v2
bool Val64::sub_span(Span<le64_t> v1, const Span<le64_t> v2, size_t &nonzero_len)
{
    auto common_len = std::min(v1.size(), v2.size());

    // Little endian, underflow forward.
    bool underflow = false;

    size_t i;
    nonzero_len = 0;
    for (i = 0; i < common_len; ++i) {
        uint64_t u1, u2, res;

        u1 = le64toh(v1[i]);
        u2 = le64toh(v2[i]);

        res = u1 - u2 - underflow;
        v1[i] = htole64(res);
        if (res)
            nonzero_len = i + 1;
        if (res < u1)
            underflow = false;
        else {
            underflow = (res > u1) || (res == u1 && u2 != 0);
        }
    }

    /* We have exhausted v1? */
    if (i < v2.size()) {
        if (underflow)
            return underflow;
        while (i < v2.size()) {
            if (v2[i] != 0)
                return true;
            i++;
        }
        return false;
    }

    /* We have exhausted v2.  Underflow forwards if required: we keep
     * going even if we don't need to, to update nonzero_len. */
    while (i < v1.size()) {
        uint64_t u1 = le64toh(v1[i]);
        v1[i] = htole64(u1 - underflow);
        if (v1[i] != 0)
            nonzero_len = i + 1;
        underflow = (underflow && u1 == 0);
        i++;
    }

    return underflow;
}


bool Val64::op_sub(Val64 &v1, const Val64 &v2, size_t &varcost)
{
    // BIP#ops:
    // |OP_SUB
    // |Greater of two operand lengths * 2
    varcost += std::max(v1.m_realsize, v2.m_realsize) * 2;
    size_t nonzero_len;

    bool underflow = sub_span(v1.m_u64span, v2.m_u64span, nonzero_len);
    if (underflow)
        return false;

    v1.trim_tail(nonzero_len);
    return true;
}

bool Val64::op_1sub(Val64 &v1, size_t &varcost)
{
    const Val64 v2(1);

    return op_sub(v1, v2, varcost);
}

void Val64::bitshift_down(size_t words, size_t bits)
{
    // Not empty
    assert(m_u64span.size() != 0);
    assert(bits > 0);
    assert(bits < 64);

    // [B, A] rshift 1 => [B>>1 | A>>63, A << 1]
    uint64_t prevbits = get(words) >> bits;
    for (size_t i = words; i < m_u64span.size() - 1; ++i) {
        uint64_t next = get(i + 1);
        uint64_t v = prevbits | (next << (64 - bits));
        set(i - words, v);
        prevbits = next >> bits;
    }
    // Shift the last word
    set(m_u64span.size() - 1 - words, prevbits);
}

void Val64::op_downshift(Val64 &v1, const Val64 &v2, size_t &varcost)
{
    uint64_t bits = v2.to_u64_ceil(v1.m_realsize * 8, varcost);
    size_t bytes = bits / 8;

    // BIP#ops:
    // |OP_DOWNSHIFT
    // |Length of BITS + MAX((Length of A - (Value of BITS) / 8), 0) * 2

    // We already added length of BITS in to_u64_ceil above.
    
    // Shift past end?  Empty.  Also covers empty array.
    if (bytes >= v1.m_realsize) {
        v1 = Val64(0);
        return;
    }

    // (Length of A - (Value of BITS) / 8) > 0.
    varcost += (v1.m_realsize - bytes) * 2;

    // Bitwise shifts can't do 0 anyway, as << 64 undefined.
    if (bits % 8 == 0) {
        // Remove least-significant words.
        v1.remove_front(bytes);
        return;
    }

    // Size after this is at least 1!
    assert(v1.m_u64span.size() > 0);

    // We shift and move at the same time.
    v1.bitshift_down(bits / 64, bits % 64);

    // Truncate.
    v1.truncate(v1.m_realsize - bytes);
}

// This means "shift bits higher": number go up!
bool Val64::op_upshift(Val64 &v1, const Val64 &v2, size_t max_size, size_t &varcost)
{
    uint64_t bits = v2.to_u64_ceil(max_size * 8 + 1, varcost);

    // BIP#ops:
    // |OP_UPSHIFT
    // ...

    // Cannot overflow: m_realsize is (far) less than 32 bits, so is max_size.
    if (bits + v1.m_realsize * 8 > max_size * 8)
        return false;

    // How many whole bytes should we prepend?
    size_t prebytes = bits / 8;

    // BIP#ops:
    // |OP_UPSHIFT
    // |Length of BITS + (Value of BITS) / 8 + Length of A (LENGTHCONV + ZEROING + COPYING).
    // If BITS % 8 != 0, add (Length of A) * 2.
    varcost += prebytes + v1.m_realsize;
    
    if (bits % 8 == 0) {
        // Simply insert bytes at the beginning.
        v1.prepend_zeros(prebytes);
    } else {
        varcost += v1.m_realsize * 2;
        // There's no nice C++ "add this many bytes at the beginning,
        // and one at the end" so we are actually best off prepending too
        // many bytes (fast!) and shifting backwards.
        v1.prepend_zeros(prebytes + 1);
        v1.bitshift_down(0, 8 - (bits % 8));
    }

    return true;
}

bool Val64::bitshift_up_small(size_t bits)
{
    assert(bits > 0);
    assert(bits < 64);

    uint64_t prevbits = 0;

    // [B, A] lshift 1 => [B<<1, A<<1 | B >> 63]
    for (size_t i = 0; i < m_u64span.size(); ++i) { 
        uint64_t old_v = get(i);
        uint64_t new_v = (old_v << bits) | prevbits;

        set(i, new_v);
        prevbits = old_v >> (64 - bits);
    }
    return (prevbits != 0);
}

void Val64::op_2mul(Val64 &v1, size_t &varcost)
{
    bool carry;

    // BIP#ops:
    // |OP_2MUL
    // |Operand length * 3
    varcost += v1.m_realsize * 3;

    // Trim first: any bytes we trim here, we avoid shifting.
    v1.trim_tail();

    carry = v1.bitshift_up_small(1);

    if (carry)
        v1.append_one();
    else
        v1.trim_tail();
}

void Val64::op_2div(Val64 &v1, size_t &varcost)
{
    // BIP#ops:
    // |OP_2DIV
    // |Operand length
    varcost += v1.m_realsize;

    // Trim first: any bytes we trim here, we avoid shifting.
    v1.trim_tail();

    // bitshift_down assumes non-zero size.
    if (v1.m_realsize == 0)
        return;

    v1.bitshift_down(0, 1);
    v1.trim_tail();
}

void Val64::op_invert(Val64 &v1, size_t &varcost)
{
    // BIP#ops:
    // |OP_INVERT
    // |(Length of operand) * 2
    varcost += v1.m_realsize * 2;

    // Endian doesn't matter, so access raw.
    for (auto &v: v1.m_u64span) {
        v ^= UINT64_MAX;
    }
}

// Makes sure v1 is at least as long as v2.
void Val64::binop_v1_longest(Val64 &v1, Val64 &v2)
{
    // Make sure v1 is the longer one.
    if (v1.m_realsize < v2.m_realsize)
        v1.swap(v2);
}
    
void Val64::op_and(Val64 &v1, Val64 &v2, size_t &varcost)
{
    binop_v1_longest(v1, v2);

    // BIP#ops:
    // |OP_AND
    // |Sum of two operand lengths
    varcost += v1.m_realsize + v2.m_realsize;

    // Endian doesn't matter, so access raw.
    for (size_t i = 0; i < v2.m_u64span.size(); ++i) {
        v1.m_u64span[i] &= v2.m_u64span[i];
    }

    // Rest is 0.
    std::fill(v1.m_u64span.begin() + v2.m_u64span.size(), v1.m_u64span.end(), 0);
}

void Val64::op_or(Val64 &v1, Val64 &v2, size_t &varcost)
{
    binop_v1_longest(v1, v2);

    // BIP#ops:
    // |OP_OR
    // |(Lesser of the two operand lengths) * 2
    varcost += v2.m_realsize * 2;

    // Endian doesn't matter, so access raw.
    for (size_t i = 0; i < v2.m_u64span.size(); ++i)
        v1.m_u64span[i] |= v2.m_u64span[i];
}

void Val64::op_xor(Val64 &v1, Val64 &v2, size_t &varcost)
{
    binop_v1_longest(v1, v2);

    // BIP#ops:
    // |OP_XOR
    // |(Lesser of the two operand lengths) * 2
    varcost += v2.m_realsize * 2;

    // Endian doesn't matter, so access raw.
    for (size_t i = 0; i < v2.m_u64span.size(); ++i)
        v1.m_u64span[i] ^= v2.m_u64span[i];
}

void Val64::mul_span(Span<le64_t> res,
                     const Span<le64_t> src,
                     uint64_t mul)
{
    // Result must be (at least) 1 word larger, for carry.
    assert(res.size() >= src.size() + 1);

    // Calculate this * mul, into res.
    res[0] = htole64(0);
    for (size_t i = 0; i < src.size(); ++i) {
        uint64_t hi, lo, oldhi;

        // Take advantage of 64 bit multiplier if platform
        // has it (otherwise falls back to software)
        unsigned __int128 product;

        product = (__int128)(le64toh(src[i])) * mul;
        hi = product >> 64;
        lo = product;

        oldhi = le64toh(res[i]);
        /* Note: hi cannot overflow since UINT64MAX * UINT64MAX
         * gives an upper u64 which is < UINT64MAX. */
        if (__builtin_add_overflow(lo, oldhi, &lo))
            hi++;
        res[i] = htole64(lo);
        res[i+1] = htole64(hi);
    }
}

Val64 Val64::op_mul(Val64 &v1, Val64 &v2)
{
    // Slightly more optimal if v1 is the larger operand.
    binop_v1_longest(v1, v2);

    // Result (worst case is sum of operand lengths)
    std::vector<unsigned char> retvec((v1.m_u64span.size() + v2.m_u64span.size()) * sizeof(uint64_t));
    Val64 ret(retvec);

    // Result of each v1[] * v2.
    std::vector<le64_t> scratch(v2.m_u64span.size() + 1);

    size_t ret_nonzero_len = 0;
    
    for (size_t i = 0; i < v1.m_u64span.size(); i++) {
        size_t nonzero_len;
        // Multiply v2 by v1[i] into scratch.
        mul_span(scratch, v2.m_u64span, v1.get(i));

        // Now add into result at offset i.
        // Cannot overflow.  Worst case ret effectively adds 1 to v1[i],
        // which *still* doesn't quite overflow.
        bool carry = add_span(ret.m_u64span.subspan(i, v2.m_u64span.size() + 1),
                              scratch, nonzero_len);
        assert(!carry);
        if (nonzero_len)
            ret_nonzero_len = i + nonzero_len;
    }

    ret.trim_tail(ret_nonzero_len);
    return ret;
}

// False iff v2 is 0.
bool Val64::div_mod(Val64 &v1, Val64 &v2, divmod_op op)
{
    // This is BasecaseDivRem from "Modern Computer Arithmetic" by Richard
    // Brent and Paul Zimmerman.  I discovered later that this is the same as
    // Knuth's TAOCP v2 (of course!) page 272, Algorithm D "Division of
    // non-negative integers".

    // For efficiency, the divisor (v2) needs to be *normalized*, i.e.
    // the top bit is set.  We trim and shift both to ensure this is true.

    // Note: this doesn't cost cost anything!  This is because any
    // bytes trimmed here (cost == number of bytes trimmed + 1) saves
    // costs below.
    v1.trim_tail();
    v2.trim_tail();

    // BIP#ops:
    // |OP_DIV
    //...
    // If B is empty or all zeroes, fail.
    //...
    // |OP_MOD
    //...
    // If B is empty or all zeroes, fail.

    // Now there's only one canonical zero.
    if (v2.m_realsize == 0)
        return false;

    // How many bits do we have to shift to get top bit set?
    size_t k = std::countl_zero(v2.get(v2.m_u64span.size()-1));

    if (v1.m_realsize < v2.m_realsize) {
        // v2 > v1: v1 is remainder, quotient is 0.
        if (op == divmod_op::VAL64_DIV)
            v1 = Val64(0);
        return true;
    }

    // These might have to reallocate, but by no more than 8 bytes.
    // In theory, we could save this cost by doing shifting as we go.
    // But this shift isn't really the main overhead, so keep it simple.
    if (k != 0) {
        size_t varcost;
        // FIXME: create upshift which takes size_t to avoid Val64(k) here!
        op_upshift(v1, Val64(k), v1.m_realsize + sizeof(uint64_t), varcost);
        bool overflow = v2.bitshift_up_small(k);
        assert(!overflow);
    }

    // Shift can add a few zero bytes, re-normalize.
    v1.trim_tail();
    v2.trim_tail();

    // v1 has n+m words, v2 has n words.  β is the base (2^64 here).
    assert(v1.m_u64span.size() >= v2.m_u64span.size());
    size_t n = v2.m_u64span.size();
    size_t m = v1.m_u64span.size() - n;

    // If we need quotient, create empty q vec, worst-case len.
    Val64 q;
    if (op == divmod_op::VAL64_DIV) {
        std::vector<unsigned char> qvec((m + 1) * sizeof(uint64_t));
        q.move_from_valtype(qvec);
    }

    // 1: if v1 >= β^m x v2, then q_m = 1, v1 = v1 - β^m x v2 else q_m = 0
    if (cmp_span(v1.m_u64span.subspan(m), v2.m_u64span) > -1) {
        size_t last_nonzero;
        if (op == divmod_op::VAL64_DIV)
            q.set(m, 1);
        bool carry = sub_span(v1.m_u64span.subspan(m), v2.m_u64span, last_nonzero);
        assert(!carry);
    } else {
        if (op == divmod_op::VAL64_DIV)
            q.set(m, 0);
    }

    // We need a temporary, but we overwrite it all, so create outside loop.
    std::vector<le64_t> scratch((v2.m_u64span.size() + 1) * sizeof(uint64_t));

    // 2: for j from m-1 downto 0 do:
    for (ssize_t j = m - 1; j >= 0; j--) {
        // 3: q* = floor((v1_n+j_ x β + v1_n+j-1_) / v2_n-1_)
        unsigned __int128 v;
        unsigned __int128 qstar;
        unsigned __int128 rstar;

        v = ((unsigned __int128)v1.get(n+j)) << 64 | v1.get(n+j-1);
        qstar = v / v2.get(n-1);

        // Knuth suggests: (notation reworked to match us, the rest is a
        // direct quote):
        
        // ... let r* be the remainer.
        // Now test if q* == β, or q* x v2_n-2_ > βr* + v1_n+j-2_:
        // if so, decrease q* by 1, increase r* by v2_n-1_, and
        // repeat this test if r* < β. (The test on v2_n-2_ determines at
        // high speed most of the cases in which the trial value q* is
        // one too large, and it eliminates /all/ cases where q* is
        // two too large
        rstar = v % v2.get(n-1);

        if ((qstar >> 64) != 0
            || (n > 1 && qstar * v2.get(n-2)
                > (rstar << 64) + v1.get(n+j-2))) {
            qstar--;
            rstar += v2.get(n-1);
            if ((rstar >> 64) == 0
                && (n > 1 && qstar * v2.get(n-2)
                    > (rstar << 64) + v1.get(n+j-2))) {
                qstar--;
            }
        }

        // This is our (64-bit) guess.
        uint64_t qj = qstar;

        // D4: v1 = v1 - q_j_ x β^j x v2

        // Assign scratch = q_j_ x v2
        // Note: v2 doesn't change in this loop, so scratch gets fully
        // overwritten each time, meaning we don't need to zero it.
        mul_span(scratch, v2.m_u64span, qj);

        bool underflow;
        size_t last_nonzero;
        underflow = sub_span(v1.m_u64span.subspan(j), scratch, last_nonzero);
        // D5: Set q_j_ = q*.  If the result of D4 was negative, go to D6.
        if (underflow) {
            // D6: Decrease q_j_ by 1, and add β^j x v2 to v1

            // FIXME: As Knuth points out, this is a hard to hit case:
            // solve Exercise 21 so we can test the damn thing!

            // Intuitively: we've got an estimate on v1/v2, using division on
            // the high words, plus a compensation from the next-highest.  It
            // could be an overestimate by one, however!
            qj--;
            bool carry;
            size_t nonzero_len;
            carry = add_span(v1.m_u64span.subspan(j), v2.m_u64span, nonzero_len);
            assert(carry);
        }

        // Keep shrinking v1.  Note: we could use the sub/add_with_offset
        // return to trim a bit faster if we wanted.
        if (v1.m_u64span.size() > 0) {
            assert(v1.get(v1.m_u64span.size()-1) == 0);
            v1.truncate((v1.m_u64span.size()-1) * sizeof(uint64_t));
        }

        if (op == divmod_op::VAL64_DIV)
            q.set(j, qj);
    }

    switch (op) {
    case divmod_op::VAL64_MOD:
        // Remainder needs shifting back (quotient is unaffected, since
        // (A * N) / (B * N) == A / B).
        if (k != 0 && v1.m_realsize != 0)
            v1.bitshift_down(0, k);
        v1.trim_tail();
        return true;
    case divmod_op::VAL64_DIV:
        v1 = std::move(q);
        v1.trim_tail();
        return true;
    }
    assert(!"Invalid op");
}

bool Val64::op_div(Val64 &v1, Val64 &v2)
{
    return div_mod(v1, v2, divmod_op::VAL64_DIV);
}

bool Val64::op_mod(Val64 &v1, Val64 &v2)
{
    return div_mod(v1, v2, divmod_op::VAL64_MOD);
}

size_t Val64::op_mul_varcost(const Val64 &v1, const Val64 &v2)
{
    // BIP#ops:
    // |OP_MUL
    // |Length of A + length of B + (length of A + 7) / 8 * (length of B) * 4
    //  (BEWARE OVERFLOW)
    return v1.m_realsize + v2.m_realsize + (v1.m_realsize + 7) / 8 * uint64_t(v2.m_realsize) * 4;
}

size_t Val64::op_div_varcost(const Val64 &v1, const Val64 &v2)
{
    // BIP#ops:
    // |OP_DIV
    // |Length of A * 9 + length of B * 2 + (length of A)^2 / 4  (BEWARE OVERFLOW)
    return v1.m_realsize * 9 + v2.m_realsize * 2
        + uint64_t(v1.m_realsize) * uint64_t(v1.m_realsize) / 4;
}

size_t Val64::op_mod_varcost(const Val64 &v1, const Val64 &v2)
{
    // BIP#ops:
    // |OP_MOD
    // |Length of A * 9 + length of B * 2 + (length of A)^2 / 4  (BEWARE OVERFLOW)
    return v1.m_realsize * 9 + v2.m_realsize * 2
        + uint64_t(v1.m_realsize) * uint64_t(v1.m_realsize) / 4;
}
