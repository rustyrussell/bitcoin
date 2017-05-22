#ifndef OPEN_HASH_MAP_H
#define OPEN_HASH_MAP_H

#include <utility>

#include <stdio.h>

/** Implements an open hash set.
 */
template<class Key, class IsKeyNull, class Hash = std::hash<Key>, class KeyEqual = std::equal_to<Key>>
class open_hash_set {
public:
    typedef Key key_type;
    typedef Key value_type;
    typedef size_t size_type;
    typedef Hash hasher;
    typedef KeyEqual key_equal;

    class iterator {
        value_type* ptr;
    public:
        iterator(value_type* ptr_) : ptr(ptr_) {}
        value_type& operator*() const { return *ptr; }
        value_type* operator->() const { return ptr; }
        bool operator==(iterator x) const { return ptr == x.ptr; }
        bool operator!=(iterator x) const { return ptr != x.ptr; }
        bool operator>=(iterator x) const { return ptr >= x.ptr; }
        bool operator<=(iterator x) const { return ptr <= x.ptr; }
        bool operator>(iterator x) const { return ptr > x.ptr; }
        bool operator<(iterator x) const { return ptr < x.ptr; }
    };

private:
    hasher hash_instance;
    key_equal equal_instance;
    IsKeyNull null_instance;
    const size_type bits;
    // With 1/4 chance of a bucket being full, this means 1 in 2^40 of this
    // many in a row.
    static const int scan_max = 20;
    std::vector<value_type> table;
    size_type count = 0;

    /* Hash should be uniform already. */
    inline size_t hash_base(uint64_t hash) {
        return hash & ((size_type(1) << bits)-1);
    }

    // Power of 2 which keeps us under 25 full.
    static inline size_type optimal_hashbits(size_type entry_count) {
        size_type bits = 8;
        while ((1ULL << bits) < (entry_count * 4))
            bits++;
        return bits;
    }

public:
    open_hash_set(size_type entry_count) :
        bits(optimal_hashbits(entry_count)),
        table(1ULL << bits)
    {}

    std::pair<iterator, bool> insert(const value_type& value) {
        size_t pos = hash_base(hash_instance(value));
        size_t i = 0;
        while (i < scan_max) {
            if (null_instance(table[pos]))
               break;
            if (equal_instance(table[pos], value))
               break;
            pos = (pos + 1)  & ((size_type(1) << bits)-1);
            i++;
        }

        if (i == scan_max)
            return std::make_pair(end(), false);

        if (equal_instance(table[pos], value)) {
            return std::make_pair(iterator(&table[pos]), false);
        }

        table[pos] = value;
        count++;
        return std::make_pair(iterator(&table[pos]), true);
    }

    iterator find(const value_type& value) {
        size_t pos = hash_base(hash_instance(value));
        size_t i = 0;
        while (i < scan_max) {
            if (null_instance(table[pos]))
               break;
            if (equal_instance(table[pos], value))
               break;
            pos = (pos + 1)  & ((size_type(1) << bits)-1);
            i++;
        }

        if (i == scan_max || null_instance(table[pos]) || !equal_instance(table[pos], value))
            return end();
        return iterator(&table[pos]);
    }

    iterator end() {
        value_type* ptr = &table[table.size() - 1];
        return iterator(ptr + 1);
    }

    size_type size() const { return count; }
};

#endif // OPEN_HASH_MAP_H
