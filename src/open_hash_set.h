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
    std::vector<value_type> table;
    size_type count = 0, scan_max;

    inline size_t hash_pos(uint64_t hash, size_t i) {
        uint64_t input = hash * (i + 1);
        uint32_t value = (input & 0xffffffffffLLU) ^ ((input & 0xffff00000000LLU) >> 16) ^ ((input & 0xffff000000000000LLU) >> 32);
        return (value * uint64_t(table.size())) >> 32;
    }

public:
    open_hash_set(size_type entry_count=1000) :
        table(std::max(128*1024/sizeof(value_type), entry_count*3)), // max(1/2 of L2, 3*entries)
        scan_max(table.size() / 2)
    {}

    std::pair<iterator, bool> insert(const value_type& value) {
        size_t pos;
        size_t i = 0;
        while (i < scan_max) {
            pos = hash_pos(hash_instance(value), i);
            if (null_instance(table[pos]))
               break;
            if (equal_instance(table[pos], value))
               break;
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
        size_t pos;
        size_t i = 0;
        while (i < scan_max) {
            pos = hash_pos(hash_instance(value), i);
            if (null_instance(table[pos]))
               break;
            if (equal_instance(table[pos], value))
               break;
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
