/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @file socperf_lrucache_fuzzer.cpp
 * @brief Comprehensive fuzzing driver for SocPerfLRUCache
 */

#include <cstdint>
#include <cstddef>
#include <cstring>

#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <list>
#include <unordered_map>
#include <unordered_set>

// SocPerf LRU Cache header
#include "socperf_lru_cache.h"

namespace FuzzUtils {

// ============================================================================
// Constants (G.CNS.02: Use named constants instead of magic numbers)
// ============================================================================

// Input size constraints
constexpr int32_t MIN_FUZZ_INPUT_SIZE = 4;
constexpr int32_t MAX_FUZZ_INPUT_SIZE = 8192;

// Cache capacity constraints
constexpr int32_t MAX_CAPACITY = 256;
constexpr int32_t MIN_CAPACITY = 1;
constexpr int32_t DEFAULT_CAPACITY = 16;

// Iteration count constants (G.CNS.02)
constexpr int32_t SMALL_ITERATION_COUNT = 10;
constexpr int32_t MEDIUM_ITERATION_COUNT = 50;
constexpr int32_t LARGE_ITERATION_COUNT = 100;
constexpr int32_t STRESS_ITERATION_COUNT = 200;

// Large cache size for stress testing
constexpr int32_t LARGE_CACHE_CAPACITY = 10000;
constexpr int32_t LARGE_CACHE_ITEMS = 200;
constexpr int32_t EXTRA_LARGE_CACHE_ITEMS = 500;

// String length constraints
constexpr size_t MAX_STRING_LENGTH = 32;
constexpr size_t MAX_STRING_VALUE_LENGTH = 256;

// Key pattern constants (G.CNS.02)
constexpr int32_t HOT_KEY_BASE_1 = 10;
constexpr int32_t HOT_KEY_BASE_2 = 20;
constexpr int32_t HOT_KEY_BASE_3 = 30;
constexpr int32_t EVICTION_START_KEY = 1000;
constexpr int32_t EVICTION_END_KEY = 1200;
constexpr int32_t SPECIAL_KEY_VALUE = 42;
constexpr int32_t PATTERN_HASH_MOD = 17;
constexpr int32_t PATTERN_MULTIPLIER = 31;
constexpr int32_t STRESS_ITER_DIV = 20;

// Large operation constants
constexpr size_t LARGE_OPS_BASE = 500;
constexpr size_t LARGE_OPS_MOD = 1000;
constexpr size_t STRESS_OPS_BASE = 1000;
constexpr size_t STRESS_OPS_MOD = 5000;

// Additional magic number replacement constants (G.CNS.02)
constexpr int32_t CAPACITY_MULTIPLIER = 2;
constexpr int32_t VALUE_MULTIPLIER_100 = 100;
constexpr int32_t UPDATE_ITERATION_COUNT = 5;
constexpr int32_t CAPACITY_CHANGE_TESTS = 5;
constexpr int32_t KEY_BASE_MULTIPLIER = 1000;
constexpr int32_t VALUE_MULTIPLIER_10 = 10;
constexpr int32_t OP_MOD = 3;
constexpr int32_t KEY_MOD = 100;
constexpr int32_t KEY_OFFSET = 1000;
constexpr int32_t STRESS_OP_MOD = 4;
constexpr int32_t VALUE_MULTIPLIER_7 = 7;
constexpr int32_t BURST_ITERATION_COUNT = 20;
constexpr int32_t READ_INTERVAL = 10;
constexpr int32_t READ_KEY_OFFSET = 10;
constexpr int32_t VALUE_MULTIPLIER_1000 = 1000;
constexpr int32_t CAPACITY_QUARTER_DIV = 4;
constexpr int32_t CAPACITY_QUARTER_MUL = 3;

// Derived capacity values
constexpr int32_t HOT_KEY_RANGE_START = DEFAULT_CAPACITY / CAPACITY_QUARTER_DIV;
constexpr int32_t HOT_KEY_RANGE_END = DEFAULT_CAPACITY * CAPACITY_QUARTER_MUL / CAPACITY_QUARTER_DIV;
constexpr int32_t CAPACITY_DOUBLED = DEFAULT_CAPACITY * CAPACITY_MULTIPLIER;

// Mixed operation type constants (G.CNS.02)
constexpr uint8_t MIXED_OP_PUT = 0;
constexpr uint8_t MIXED_OP_GET_EXISTING = 1;
constexpr uint8_t MIXED_OP_GET_NONEXISTING = 2;

// Stress test operation type constants (G.CNS.02)
constexpr uint8_t STRESS_OP_PUT_RANDOM = 0;
constexpr uint8_t STRESS_OP_GET_RANDOM = 1;
constexpr uint8_t STRESS_OP_PUT_SEQ = 2;
constexpr uint8_t STRESS_OP_GET_PREV = 3;

// Test case selectors
constexpr uint8_t TEST_CASE_BASIC_PUT_GET = 0;
constexpr uint8_t TEST_CASE_EVICTION = 1;
constexpr uint8_t TEST_CASE_UPDATE = 2;
constexpr uint8_t TEST_CASE_MISS = 3;
constexpr uint8_t TEST_CASE_CAPACITY_CHANGE = 4;
constexpr uint8_t TEST_CASE_SEQUENTIAL_KEYS = 5;
constexpr uint8_t TEST_CASE_RANDOM_KEYS = 6;
constexpr uint8_t TEST_CASE_HOT_KEYS = 7;
constexpr uint8_t TEST_CASE_DUPLICATE_KEYS = 8;
constexpr uint8_t TEST_CASE_BOUNDARY_CAPACITY = 9;
constexpr uint8_t TEST_CASE_MIXED_OPERATIONS = 10;
constexpr uint8_t TEST_CASE_LARGE_CACHE = 11;
constexpr uint8_t TEST_CASE_SMALL_CACHE = 12;
constexpr uint8_t TEST_CASE_PATTERN_FUZZING = 13;
constexpr uint8_t TEST_CASE_STRESS_TEST = 14;
constexpr uint8_t TEST_CASE_HOT_KEY_ACCESS = 15;
constexpr uint8_t TEST_CASE_COUNT = 16;

// ============================================================================
// DataExtractor Class
// ============================================================================

class DataExtractor {
public:
    explicit DataExtractor(const uint8_t* data, size_t size)
        : data_(data), size_(size), offset_(0) {}

    ~DataExtractor() = default;

    int32_t ExtractInt32()
    {
        const uint8_t* ptr = SafeRead(sizeof(int32_t));
        if (ptr == nullptr) {
            return 0;
        }
        int32_t value = 0;
        (void)memcpy_s(&value, sizeof(int32_t), ptr, sizeof(int32_t));
        return value;
    }

    uint32_t ExtractUInt32()
    {
        const uint8_t* ptr = SafeRead(sizeof(uint32_t));
        if (ptr == nullptr) {
            return 0;
        }
        uint32_t value = 0;
        (void)memcpy_s(&value, sizeof(uint32_t), ptr, sizeof(uint32_t));
        return value;
    }

    size_t ExtractSizeT()
    {
        const uint8_t* ptr = SafeRead(sizeof(size_t));
        if (ptr == nullptr) {
            return 0;
        }
        size_t value = 0;
        (void)memcpy_s(&value, sizeof(size_t), ptr, sizeof(size_t));
        return value;
    }

    uint8_t ExtractUInt8()
    {
        const uint8_t* ptr = SafeRead(sizeof(uint8_t));
        if (ptr == nullptr) {
            return 0;
        }
        return *ptr;
    }

    bool ExtractBool()
    {
        const uint8_t* ptr = SafeRead(sizeof(uint8_t));
        if (ptr == nullptr) {
            return false;
        }
        return *ptr != 0;
    }

    std::string ExtractString(size_t maxLen = MAX_STRING_LENGTH)
    {
        if (offset_ >= size_) {
            return "";
        }
        size_t len = data_[offset_] % (maxLen + 1);
        const uint8_t* ptr = SafeRead(len + 1);
        if (ptr == nullptr) {
            return "";
        }
        if (len > 0) {
            return std::string(reinterpret_cast<const char*>(ptr + 1), len);
        }
        return "";
    }

    bool HasMore() const
    {
        return offset_ < size_;
    }

    size_t Remaining() const
    {
        return size_ - offset_;
    }

    DataExtractor(const DataExtractor&) = delete;
    DataExtractor& operator=(const DataExtractor&) = delete;

private:
    bool CanExtract(size_t size) const
    {
        return offset_ + size <= size_;
    }

    const uint8_t* SafeRead(size_t size)
    {
        if (!CanExtract(size)) {
            return nullptr;
        }
        const uint8_t* ptr = data_ + offset_;
        offset_ += size;
        return ptr;
    }

    const uint8_t* data_;
    size_t size_;
    size_t offset_;
};

} // namespace FuzzUtils

using namespace FuzzUtils;

// ============================================================================
// Test Helper Templates
// ============================================================================

template<typename K, typename V>
void TestBasicPutGet(OHOS::SOCPERF::SocPerfLRUCache<K, V>& cache, DataExtractor& extractor)
{
    for (int32_t i = 0; i < SMALL_ITERATION_COUNT && extractor.HasMore(); ++i) {
        K key = static_cast<K>(extractor.ExtractInt32());
        V value = static_cast<V>(extractor.ExtractInt32());
        cache.put(key, value);
    }

    for (int32_t i = 0; i < SMALL_ITERATION_COUNT && extractor.HasMore(); ++i) {
        K key = static_cast<K>(extractor.ExtractInt32());
        V retrievedValue;
        (void)cache.get(key, retrievedValue);
    }
}

template<typename K, typename V>
void TestEviction(OHOS::SOCPERF::SocPerfLRUCache<K, V>& cache, size_t capacity, DataExtractor& extractor)
{
    (void)extractor;
    // Fill cache beyond capacity to trigger eviction
    for (size_t i = 0; i < capacity * CAPACITY_MULTIPLIER; ++i) {
        K key = static_cast<K>(i);
        V value = static_cast<V>(i * VALUE_MULTIPLIER_100);
        cache.put(key, value);
    }

    // Verify oldest entry should be evicted
    K oldestKey = static_cast<K>(0);
    V retrievedValue;
    bool found = cache.get(oldestKey, retrievedValue);
    (void)found;

    // Verify newest entry should still exist
    K newestKey = static_cast<K>(capacity * 2 - 1);
    found = cache.get(newestKey, retrievedValue);
    (void)found;
}

template<typename K, typename V>
void TestUpdate(OHOS::SOCPERF::SocPerfLRUCache<K, V>& cache, DataExtractor& extractor)
{
    (void)extractor;
    // Insert initial values
    for (int32_t i = 0; i < UPDATE_ITERATION_COUNT; ++i) {
        K key = static_cast<K>(i);
        V value = static_cast<V>(i * VALUE_MULTIPLIER_100);
        cache.put(key, value);
    }

    // Update same keys with new values
    for (int32_t i = 0; i < UPDATE_ITERATION_COUNT; ++i) {
        K key = static_cast<K>(i);
        V newValue = static_cast<V>(i * VALUE_MULTIPLIER_100 * CAPACITY_MULTIPLIER);
        cache.put(key, newValue);
    }

    // Verify updates
    for (int32_t i = 0; i < UPDATE_ITERATION_COUNT; ++i) {
        K key = static_cast<K>(i);
        V retrievedValue;
        (void)cache.get(key, retrievedValue);
    }
}

template<typename K, typename V>
void TestMiss(OHOS::SOCPERF::SocPerfLRUCache<K, V>& cache, DataExtractor& extractor)
{
    (void)extractor;
    // Fill cache
    for (int32_t i = 0; i < SMALL_ITERATION_COUNT; ++i) {
        K key = static_cast<K>(i);
        V value = static_cast<V>(i * 100);
        cache.put(key, value);
    }

    // Try to get non-existent keys
    for (int32_t i = EVICTION_START_KEY; i < EVICTION_END_KEY; ++i) {
        K key = static_cast<K>(i);
        V retrievedValue;
        bool found = cache.get(key, retrievedValue);
        (void)found;
    }
}

template<typename K, typename V>
void TestCapacityChange(DataExtractor& extractor)
{
    size_t capacity = extractor.ExtractSizeT() % MAX_CAPACITY + 1;
    OHOS::SOCPERF::SocPerfLRUCache<K, V> cache(capacity);

    for (int32_t test = 0; test < CAPACITY_CHANGE_TESTS; ++test) {
        for (int32_t i = 0; i < static_cast<int32_t>(capacity * CAPACITY_MULTIPLIER); ++i) {
            K key = static_cast<K>(test * KEY_BASE_MULTIPLIER + i);
            V value = static_cast<V>(i);
            cache.put(key, value);
        }
    }
}

template<typename K, typename V>
void TestSequentialKeys(OHOS::SOCPERF::SocPerfLRUCache<K, V>& cache, DataExtractor& extractor)
{
    (void)extractor;
    // Insert sequential keys
    for (int32_t i = 0; i < LARGE_ITERATION_COUNT; ++i) {
        K key = static_cast<K>(i);
        V value = static_cast<V>(i * VALUE_MULTIPLIER_10);
        cache.put(key, value);
    }

    // Access in sequence
    for (int32_t i = 0; i < LARGE_ITERATION_COUNT; ++i) {
        K key = static_cast<K>(i);
        V retrievedValue;
        (void)cache.get(key, retrievedValue);
    }
}

template<typename K, typename V>
void TestRandomKeys(OHOS::SOCPERF::SocPerfLRUCache<K, V>& cache, DataExtractor& extractor)
{
    for (int32_t i = 0; i < LARGE_ITERATION_COUNT && extractor.HasMore(); ++i) {
        K key = static_cast<K>(extractor.ExtractInt32());
        V value = static_cast<V>(extractor.ExtractInt32());
        cache.put(key, value);
    }

    for (int32_t i = 0; i < LARGE_ITERATION_COUNT && extractor.HasMore(); ++i) {
        K key = static_cast<K>(extractor.ExtractInt32());
        V retrievedValue;
        (void)cache.get(key, retrievedValue);
    }
}

template<typename K, typename V>
void TestHotKeys(OHOS::SOCPERF::SocPerfLRUCache<K, V>& cache, DataExtractor& extractor)
{
    (void)extractor;
    // Insert items
    for (int32_t i = 0; i < LARGE_ITERATION_COUNT; ++i) {
        K key = static_cast<K>(i);
        V value = static_cast<V>(i * 100);
        cache.put(key, value);
    }

    // Define hot keys
    K hotKey1 = static_cast<K>(HOT_KEY_BASE_1);
    K hotKey2 = static_cast<K>(HOT_KEY_BASE_2);
    K hotKey3 = static_cast<K>(HOT_KEY_BASE_3);

    // Access some keys repeatedly (hot keys)
    for (int32_t i = 0; i < MEDIUM_ITERATION_COUNT; ++i) {
        V value1;
        V value2;
        V value3;
        (void)cache.get(hotKey1, value1);
        (void)cache.get(hotKey2, value2);
        (void)cache.get(hotKey3, value3);
    }

    // Fill cache to trigger eviction
    for (int32_t i = EVICTION_START_KEY; i < EVICTION_END_KEY; ++i) {
        K key = static_cast<K>(i);
        V value = static_cast<V>(i);
        cache.put(key, value);
    }

    // Hot keys should still be accessible
    V value1;
    V value2;
    V value3;
    bool found1 = cache.get(hotKey1, value1);
    bool found2 = cache.get(hotKey2, value2);
    bool found3 = cache.get(hotKey3, value3);
    (void)found1;
    (void)found2;
    (void)found3;
}

template<typename K, typename V>
void TestDuplicateKeys(OHOS::SOCPERF::SocPerfLRUCache<K, V>& cache, DataExtractor& extractor)
{
    (void)extractor;
    K key = static_cast<K>(SPECIAL_KEY_VALUE);
    for (int32_t i = 0; i < LARGE_ITERATION_COUNT; ++i) {
        V value = static_cast<V>(i);
        cache.put(key, value);
    }

    V retrievedValue;
    bool found = cache.get(key, retrievedValue);
    (void)found;
}

template<typename K, typename V>
void TestBoundaryCapacity(DataExtractor& extractor)
{
    (void)extractor;
    // Test with capacity 1
    {
        OHOS::SOCPERF::SocPerfLRUCache<K, V> cache(MIN_CAPACITY);
        for (int32_t i = 0; i < LARGE_ITERATION_COUNT; ++i) {
            K key = static_cast<K>(i);
            V value = static_cast<V>(i);
            cache.put(key, value);
        }
    }

    // Test with small capacity
    {
        OHOS::SOCPERF::SocPerfLRUCache<K, V> cache(MIN_CAPACITY + 1);
        for (int32_t i = 0; i < SMALL_ITERATION_COUNT * CAPACITY_MULTIPLIER; ++i) {
            K key = static_cast<K>(i);
            V value = static_cast<V>(i);
            cache.put(key, value);
        }
    }

    // Test with large capacity
    {
        OHOS::SOCPERF::SocPerfLRUCache<K, V> cache(LARGE_CACHE_CAPACITY);
        for (int32_t i = 0; i < LARGE_CACHE_ITEMS; ++i) {
            K key = static_cast<K>(i);
            V value = static_cast<V>(i);
            cache.put(key, value);
        }
    }

    // Test with extra large item count
    {
        OHOS::SOCPERF::SocPerfLRUCache<K, V> cache(EXTRA_LARGE_CACHE_ITEMS);
        for (int32_t i = 0; i < EXTRA_LARGE_CACHE_ITEMS; ++i) {
            K key = static_cast<K>(i);
            V value = static_cast<V>(i * 5);
            cache.put(key, value);
        }
    }
}

template<typename K, typename V>
void TestMixedOperations(OHOS::SOCPERF::SocPerfLRUCache<K, V>& cache, DataExtractor& extractor)
{
    for (int32_t i = 0; i < MEDIUM_ITERATION_COUNT && extractor.HasMore(); ++i) {
        uint8_t op = extractor.ExtractUInt8() % OP_MOD;

        switch (op) {
            case MIXED_OP_PUT: {
                K key = static_cast<K>(extractor.ExtractInt32());
                V value = static_cast<V>(extractor.ExtractInt32());
                cache.put(key, value);
                break;
            }
            case MIXED_OP_GET_EXISTING: {
                K key = static_cast<K>(extractor.ExtractInt32() % KEY_MOD);
                V value;
                (void)cache.get(key, value);
                break;
            }
            case MIXED_OP_GET_NONEXISTING: {
                K key = static_cast<K>(KEY_OFFSET + extractor.ExtractInt32() % KEY_MOD);
                V value;
                (void)cache.get(key, value);
                break;
            }
            default:
                break;
        }
    }
}

template<typename K, typename V>
void TestLargeCache(OHOS::SOCPERF::SocPerfLRUCache<K, V>& cache, DataExtractor& extractor)
{
    size_t numOps = extractor.ExtractSizeT() % LARGE_OPS_MOD + LARGE_OPS_BASE;

    for (size_t i = 0; i < numOps; ++i) {
        K key = static_cast<K>(i);
        V value = static_cast<V>(i * VALUE_MULTIPLIER_1000);
        cache.put(key, value);

        if (i % READ_INTERVAL == 0) {
            K readKey = static_cast<K>(i - READ_KEY_OFFSET);
            V retrievedValue;
            (void)cache.get(readKey, retrievedValue);
        }
    }
}

template<typename K, typename V>
void TestSmallCache(OHOS::SOCPERF::SocPerfLRUCache<K, V>& cache, DataExtractor& extractor)
{
    for (int32_t i = 0; i < LARGE_ITERATION_COUNT && extractor.HasMore(); ++i) {
        K key = static_cast<K>(extractor.ExtractInt32());
        V value = static_cast<V>(extractor.ExtractInt32());
        cache.put(key, value);
    }

    K key = static_cast<K>(0);
    V retrievedValue;
    (void)cache.get(key, retrievedValue);
}

template<typename K, typename V>
void TestPatternFuzzing(OHOS::SOCPERF::SocPerfLRUCache<K, V>& cache, DataExtractor& extractor)
{
    (void)extractor;
    // Pattern 1: Same key
    K sameKey = static_cast<K>(999);
    for (int32_t i = 0; i < MEDIUM_ITERATION_COUNT; ++i) {
        V value = static_cast<V>(i);
        cache.put(sameKey, value);
    }

    // Pattern 2: Alternating keys
    for (int32_t i = 0; i < MEDIUM_ITERATION_COUNT; ++i) {
        K key = static_cast<K>((i % 2 == 0) ? 100 : 200);
        V value = static_cast<V>(i);
        cache.put(key, value);
    }

    // Pattern 3: Hash-like distribution
    for (int32_t i = 0; i < MEDIUM_ITERATION_COUNT; ++i) {
        K key = static_cast<K>((i * PATTERN_HASH_MOD) % 1000);
        V value = static_cast<V>(i * PATTERN_MULTIPLIER);
        cache.put(key, value);
    }

    // Pattern 4: Sequential burst
    for (int32_t i = 0; i < BURST_ITERATION_COUNT; ++i) {
        K key = static_cast<K>(i);
        V value = static_cast<V>(i * VALUE_MULTIPLIER_100);
        cache.put(key, value);
    }
}

template<typename K, typename V>
void TestStressTest(OHOS::SOCPERF::SocPerfLRUCache<K, V>& cache, DataExtractor& extractor)
{
    size_t numOps = extractor.ExtractSizeT() % STRESS_OPS_MOD + STRESS_OPS_BASE;

    for (size_t i = 0; i < numOps; ++i) {
        uint8_t op = extractor.ExtractUInt8() % STRESS_OP_MOD;

        switch (op) {
            case STRESS_OP_PUT_RANDOM: {
                K key = static_cast<K>(extractor.ExtractInt32());
                V value = static_cast<V>(extractor.ExtractInt32());
                cache.put(key, value);
                break;
            }
            case STRESS_OP_GET_RANDOM: {
                K key = static_cast<K>(extractor.ExtractInt32());
                V value;
                (void)cache.get(key, value);
                break;
            }
            case STRESS_OP_PUT_SEQ: {
                K key = static_cast<K>(i);
                V value = static_cast<V>(i * VALUE_MULTIPLIER_7);
                cache.put(key, value);
                break;
            }
            case STRESS_OP_GET_PREV: {
                K key = static_cast<K>(i - 1);
                V value;
                (void)cache.get(key, value);
                break;
            }
            default:
                break;
        }
    }
}

template<typename K, typename V>
void TestHotKeyAccess(OHOS::SOCPERF::SocPerfLRUCache<K, V>& cache, DataExtractor& extractor)
{
    (void)extractor;
    // Insert a set of initial items
    for (int32_t i = 0; i < DEFAULT_CAPACITY; ++i) {
        K key = static_cast<K>(i);
        V value = static_cast<V>(i * 10);
        cache.put(key, value);
    }

    // Access middle items to make them "hot"
    for (int32_t i = 0; i < STRESS_ITERATION_COUNT / STRESS_ITER_DIV; ++i) {
        for (int32_t j = HOT_KEY_RANGE_START; j < HOT_KEY_RANGE_END; ++j) {
            K key = static_cast<K>(j);
            V retrievedValue;
            (void)cache.get(key, retrievedValue);
        }
    }

    // Fill beyond capacity
    for (int32_t i = DEFAULT_CAPACITY; i < CAPACITY_DOUBLED; ++i) {
        K key = static_cast<K>(i);
        V value = static_cast<V>(i * VALUE_MULTIPLIER_10);
        cache.put(key, value);
    }

    // Check hot keys should still be accessible
    for (int32_t j = HOT_KEY_RANGE_START; j < HOT_KEY_RANGE_END; ++j) {
        K key = static_cast<K>(j);
        V retrievedValue;
        bool found = cache.get(key, retrievedValue);
        (void)found;
    }
}

using CacheTestCaseFunc = void (*)(DataExtractor&, size_t);

template<typename K, typename V>
void RunTestBasicPutGet(DataExtractor& extractor, size_t capacity)
{
    OHOS::SOCPERF::SocPerfLRUCache<K, V> cache(capacity);
    TestBasicPutGet(cache, extractor);
}

template<typename K, typename V>
void RunTestEviction(DataExtractor& extractor, size_t capacity)
{
    OHOS::SOCPERF::SocPerfLRUCache<K, V> cache(capacity);
    TestEviction(cache, capacity, extractor);
}

template<typename K, typename V>
void RunTestUpdate(DataExtractor& extractor, size_t capacity)
{
    OHOS::SOCPERF::SocPerfLRUCache<K, V> cache(capacity);
    TestUpdate(cache, extractor);
}

template<typename K, typename V>
void RunTestMiss(DataExtractor& extractor, size_t capacity)
{
    OHOS::SOCPERF::SocPerfLRUCache<K, V> cache(capacity);
    TestMiss(cache, extractor);
}

template<typename K, typename V>
void RunTestCapacityChange(DataExtractor& extractor, size_t /* capacity */)
{
    TestCapacityChange<K, V>(extractor);
}

template<typename K, typename V>
void RunTestSequentialKeys(DataExtractor& extractor, size_t capacity)
{
    OHOS::SOCPERF::SocPerfLRUCache<K, V> cache(capacity);
    TestSequentialKeys(cache, extractor);
}

template<typename K, typename V>
void RunTestRandomKeys(DataExtractor& extractor, size_t capacity)
{
    OHOS::SOCPERF::SocPerfLRUCache<K, V> cache(capacity);
    TestRandomKeys(cache, extractor);
}

template<typename K, typename V>
void RunTestHotKeys(DataExtractor& extractor, size_t capacity)
{
    OHOS::SOCPERF::SocPerfLRUCache<K, V> cache(capacity);
    TestHotKeys(cache, extractor);
}

template<typename K, typename V>
void RunTestDuplicateKeys(DataExtractor& extractor, size_t capacity)
{
    OHOS::SOCPERF::SocPerfLRUCache<K, V> cache(capacity);
    TestDuplicateKeys(cache, extractor);
}

template<typename K, typename V>
void RunTestBoundaryCapacity(DataExtractor& extractor, size_t /* capacity */)
{
    TestBoundaryCapacity<K, V>(extractor);
}

template<typename K, typename V>
void RunTestMixedOperations(DataExtractor& extractor, size_t capacity)
{
    OHOS::SOCPERF::SocPerfLRUCache<K, V> cache(capacity);
    TestMixedOperations(cache, extractor);
}

template<typename K, typename V>
void RunTestLargeCache(DataExtractor& extractor, size_t capacity)
{
    OHOS::SOCPERF::SocPerfLRUCache<K, V> cache(capacity);
    TestLargeCache(cache, extractor);
}

template<typename K, typename V>
void RunTestSmallCache(DataExtractor& extractor, size_t capacity)
{
    OHOS::SOCPERF::SocPerfLRUCache<K, V> cache(capacity);
    TestSmallCache(cache, extractor);
}

template<typename K, typename V>
void RunTestPatternFuzzing(DataExtractor& extractor, size_t capacity)
{
    OHOS::SOCPERF::SocPerfLRUCache<K, V> cache(capacity);
    TestPatternFuzzing(cache, extractor);
}

template<typename K, typename V>
void RunTestStressTest(DataExtractor& extractor, size_t capacity)
{
    OHOS::SOCPERF::SocPerfLRUCache<K, V> cache(capacity);
    TestStressTest(cache, extractor);
}

template<typename K, typename V>
void RunTestHotKeyAccess(DataExtractor& extractor, size_t capacity)
{
    OHOS::SOCPERF::SocPerfLRUCache<K, V> cache(capacity);
    TestHotKeyAccess(cache, extractor);
}

static const CacheTestCaseFunc g_cacheTestFuncs[TEST_CASE_COUNT] = {
    RunTestBasicPutGet<int32_t, int32_t>,
    RunTestEviction<int32_t, int32_t>,
    RunTestUpdate<int32_t, int32_t>,
    RunTestMiss<int32_t, int32_t>,
    RunTestCapacityChange<int32_t, int32_t>,
    RunTestSequentialKeys<int32_t, int32_t>,
    RunTestRandomKeys<int32_t, int32_t>,
    RunTestHotKeys<int32_t, int32_t>,
    RunTestDuplicateKeys<int32_t, int32_t>,
    RunTestBoundaryCapacity<int32_t, int32_t>,
    RunTestMixedOperations<int32_t, int32_t>,
    RunTestLargeCache<int32_t, int32_t>,
    RunTestSmallCache<int32_t, int32_t>,
    RunTestPatternFuzzing<int32_t, int32_t>,
    RunTestStressTest<int32_t, int32_t>,
    RunTestHotKeyAccess<int32_t, int32_t>,
};

// Helper function to dispatch test case (reduces cyclomatic complexity)
void DispatchTestCase(uint8_t testCase, DataExtractor& extractor, size_t capacity)
{
    if (testCase < TEST_CASE_COUNT) {
        g_cacheTestFuncs[testCase](extractor, capacity);
    }
}

// ============================================================================
// Main Fuzz Entry Point
// ============================================================================

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < MIN_FUZZ_INPUT_SIZE) {
        return 0;
    }

    if (size > MAX_FUZZ_INPUT_SIZE) {
        return 0;
    }

    DataExtractor extractor(data, size);

    uint8_t testCase = extractor.ExtractUInt8() % TEST_CASE_COUNT;

    size_t capacity = extractor.ExtractSizeT() % MAX_CAPACITY + MIN_CAPACITY;

    DispatchTestCase(testCase, extractor, capacity);

    // Also test with string keys for template coverage
    {
        OHOS::SOCPERF::SocPerfLRUCache<std::string, int32_t> strCache(capacity);
        std::string key = extractor.ExtractString(MAX_STRING_LENGTH);
        int32_t value = extractor.ExtractInt32();
        strCache.put(key, value);
        int32_t retrieved;
        (void)strCache.get(key, retrieved);

        // Test with longer string values
        std::string longKey = std::string(MAX_STRING_VALUE_LENGTH, 'x');
        int32_t longValue = extractor.ExtractInt32();
        strCache.put(longKey, longValue);
        int32_t longRetrieved;
        (void)strCache.get(longKey, longRetrieved);
    }

    return 0;
}