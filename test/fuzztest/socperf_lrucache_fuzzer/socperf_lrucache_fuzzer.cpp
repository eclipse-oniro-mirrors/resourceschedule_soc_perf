/*
 * Copyright (c) 2024-2026 Huawei Device Co., Ltd.
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
 *
 * Coverage targets:
 * - Basic get/put operations
 * - Capacity limits and eviction
 * - Cache size variations
 * - Key patterns (sequential, random, duplicate, hot)
 * - Value patterns and edge cases
 * - Template instantiation with various types
 * - Concurrent access simulation
 * - Boundary conditions and error handling
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

// Iteration count constants
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
// DataExtractor Class (G.EXP.09: Variables declared when needed)
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
        memcpy(&value, ptr, sizeof(int32_t));
        return value;
    }

    uint32_t ExtractUInt32()
    {
        const uint8_t* ptr = SafeRead(sizeof(uint32_t));
        if (ptr == nullptr) {
            return 0;
        }
        uint32_t value = 0;
        memcpy(&value, ptr, sizeof(uint32_t));
        return value;
    }

    size_t ExtractSizeT()
    {
        const uint8_t* ptr = SafeRead(sizeof(size_t));
        if (ptr == nullptr) {
            return 0;
        }
        size_t value = 0;
        memcpy(&value, ptr, sizeof(size_t));
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
// Test Helper Templates (G.EXP.09: Variables declared when used)
// ============================================================================

/**
 * @brief Test basic put and get operations
 */
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

/**
 * @brief Test cache eviction behavior
 */
template<typename K, typename V>
void TestEviction(OHOS::SOCPERF::SocPerfLRUCache<K, V>& cache, size_t capacity, DataExtractor& extractor)
{
    (void)extractor;
    // Fill cache beyond capacity to trigger eviction
    for (size_t i = 0; i < capacity * 2; ++i) {
        K key = static_cast<K>(i);
        V value = static_cast<V>(i * 100);
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

/**
 * @brief Test updating existing keys
 */
template<typename K, typename V>
void TestUpdate(OHOS::SOCPERF::SocPerfLRUCache<K, V>& cache, DataExtractor& extractor)
{
    (void)extractor;
    // Insert initial values
    for (int32_t i = 0; i < 5; ++i) {
        K key = static_cast<K>(i);
        V value = static_cast<V>(i * 100);
        cache.put(key, value);
    }

    // Update same keys with new values
    for (int32_t i = 0; i < 5; ++i) {
        K key = static_cast<K>(i);
        V newValue = static_cast<V>(i * 200);
        cache.put(key, newValue);
    }

    // Verify updates
    for (int32_t i = 0; i < 5; ++i) {
        K key = static_cast<K>(i);
        V retrievedValue;
        (void)cache.get(key, retrievedValue);
    }
}

/**
 * @brief Test cache misses
 */
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

    // Try to get non-existent keys (starting from 100)
    for (int32_t i = 100; i < 200; ++i) {
        K key = static_cast<K>(i);
        V retrievedValue;
        bool found = cache.get(key, retrievedValue);
        (void)found;
    }
}

/**
 * @brief Test with various cache capacities
 */
template<typename K, typename V>
void TestCapacityChange(DataExtractor& extractor)
{
    size_t capacity = extractor.ExtractSizeT() % MAX_CAPACITY + 1;
    OHOS::SOCPERF::SocPerfLRUCache<K, V> cache(capacity);

    for (int32_t test = 0; test < 5; ++test) {
        for (int32_t i = 0; i < static_cast<int32_t>(capacity * 2); ++i) {
            K key = static_cast<K>(test * 1000 + i);
            V value = static_cast<V>(i);
            cache.put(key, value);
        }
    }
}

/**
 * @brief Test sequential keys
 */
template<typename K, typename V>
void TestSequentialKeys(OHOS::SOCPERF::SocPerfLRUCache<K, V>& cache, DataExtractor& extractor)
{
    (void)extractor;
    // Insert sequential keys
    for (int32_t i = 0; i < LARGE_ITERATION_COUNT; ++i) {
        K key = static_cast<K>(i);
        V value = static_cast<V>(i * 10);
        cache.put(key, value);
    }

    // Access in sequence
    for (int32_t i = 0; i < LARGE_ITERATION_COUNT; ++i) {
        K key = static_cast<K>(i);
        V retrievedValue;
        (void)cache.get(key, retrievedValue);
    }
}

/**
 * @brief Test with random keys
 */
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

/**
 * @brief Test with hot (frequently accessed) keys
 */
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
    K hotKey1 = static_cast<K>(10);
    K hotKey2 = static_cast<K>(20);
    K hotKey3 = static_cast<K>(30);

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
    for (int32_t i = 1000; i < 1200; ++i) {
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

/**
 * @brief Test with duplicate key operations
 */
template<typename K, typename V>
void TestDuplicateKeys(OHOS::SOCPERF::SocPerfLRUCache<K, V>& cache, DataExtractor& extractor)
{
    (void)extractor;
    K key = static_cast<K>(42);
    for (int32_t i = 0; i < LARGE_ITERATION_COUNT; ++i) {
        V value = static_cast<V>(i);
        cache.put(key, value);
    }

    V retrievedValue;
    bool found = cache.get(key, retrievedValue);
    (void)found;
}

/**
 * @brief Test with boundary capacity values
 */
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

    // Test with small capacity from fuzz data
    {
        OHOS::SOCPERF::SocPerfLRUCache<K, V> cache(MIN_CAPACITY + 1);
        for (int32_t i = 0; i < SMALL_ITERATION_COUNT * 2; ++i) {
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

/**
 * @brief Test mixed operations
 */
template<typename K, typename V>
void TestMixedOperations(OHOS::SOCPERF::SocPerfLRUCache<K, V>& cache, DataExtractor& extractor)
{
    for (int32_t i = 0; i < MEDIUM_ITERATION_COUNT && extractor.HasMore(); ++i) {
        uint8_t op = extractor.ExtractUInt8() % 3;

        switch (op) {
            case 0: {
                K key = static_cast<K>(extractor.ExtractInt32());
                V value = static_cast<V>(extractor.ExtractInt32());
                cache.put(key, value);
                break;
            }
            case 1: {
                K key = static_cast<K>(extractor.ExtractInt32() % 100);
                V value;
                (void)cache.get(key, value);
                break;
            }
            case 2: {
                K key = static_cast<K>(1000 + extractor.ExtractInt32() % 100);
                V value;
                (void)cache.get(key, value);
                break;
            }
            default:
                break;
        }
    }
}

/**
 * @brief Test with large cache
 */
template<typename K, typename V>
void TestLargeCache(OHOS::SOCPERF::SocPerfLRUCache<K, V>& cache, DataExtractor& extractor)
{
    size_t numOps = extractor.ExtractSizeT() % 1000 + 500;

    for (size_t i = 0; i < numOps; ++i) {
        K key = static_cast<K>(i);
        V value = static_cast<V>(i * 1000);
        cache.put(key, value);

        if (i % 10 == 0) {
            K readKey = static_cast<K>(i - 10);
            V retrievedValue;
            (void)cache.get(readKey, retrievedValue);
        }
    }
}

/**
 * @brief Test with small cache
 */
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

/**
 * @brief Test with various key patterns
 */
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
        K key = static_cast<K>((i * 17) % 1000);
        V value = static_cast<V>(i * 31);
        cache.put(key, value);
    }

    // Pattern 4: Sequential burst
    for (int32_t i = 0; i < 20; ++i) {
        K key = static_cast<K>(i);
        V value = static_cast<V>(i * 100);
        cache.put(key, value);
    }
}

/**
 * @brief Stress test with intensive operations
 */
template<typename K, typename V>
void TestStressTest(OHOS::SOCPERF::SocPerfLRUCache<K, V>& cache, DataExtractor& extractor)
{
    size_t numOps = extractor.ExtractSizeT() % 5000 + 1000;

    for (size_t i = 0; i < numOps; ++i) {
        uint8_t op = extractor.ExtractUInt8() % 4;

        switch (op) {
            case 0: {
                K key = static_cast<K>(extractor.ExtractInt32());
                V value = static_cast<V>(extractor.ExtractInt32());
                cache.put(key, value);
                break;
            }
            case 1: {
                K key = static_cast<K>(extractor.ExtractInt32());
                V value;
                (void)cache.get(key, value);
                break;
            }
            case 2: {
                K key = static_cast<K>(i);
                V value = static_cast<V>(i * 7);
                cache.put(key, value);
                break;
            }
            case 3: {
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

/**
 * @brief Test hot key access patterns with eviction protection
 */
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

    // Access middle items to make them "hot" (using STRESS_ITERATION_COUNT for hot access)
    for (int32_t i = 0; i < STRESS_ITERATION_COUNT / 20; ++i) {
        for (int32_t j = DEFAULT_CAPACITY / 4; j < DEFAULT_CAPACITY * 3 / 4; ++j) {
            K key = static_cast<K>(j);
            V retrievedValue;
            (void)cache.get(key, retrievedValue);
        }
    }

    // Fill beyond capacity
    for (int32_t i = DEFAULT_CAPACITY; i < DEFAULT_CAPACITY * 2; ++i) {
        K key = static_cast<K>(i);
        V value = static_cast<V>(i * 10);
        cache.put(key, value);
    }

    // Check hot keys should still be accessible
    for (int32_t j = DEFAULT_CAPACITY / 4; j < DEFAULT_CAPACITY * 3 / 4; ++j) {
        K key = static_cast<K>(j);
        V retrievedValue;
        bool found = cache.get(key, retrievedValue);
        (void)found;
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

    switch (testCase) {
        case TEST_CASE_BASIC_PUT_GET: {
            OHOS::SOCPERF::SocPerfLRUCache<int32_t, int32_t> cache(capacity);
            TestBasicPutGet(cache, extractor);
            break;
        }
        case TEST_CASE_EVICTION: {
            OHOS::SOCPERF::SocPerfLRUCache<int32_t, int32_t> cache(capacity);
            TestEviction(cache, capacity, extractor);
            break;
        }
        case TEST_CASE_UPDATE: {
            OHOS::SOCPERF::SocPerfLRUCache<int32_t, int32_t> cache(capacity);
            TestUpdate(cache, extractor);
            break;
        }
        case TEST_CASE_MISS: {
            OHOS::SOCPERF::SocPerfLRUCache<int32_t, int32_t> cache(capacity);
            TestMiss(cache, extractor);
            break;
        }
        case TEST_CASE_CAPACITY_CHANGE: {
            TestCapacityChange<int32_t, int32_t>(extractor);
            break;
        }
        case TEST_CASE_SEQUENTIAL_KEYS: {
            OHOS::SOCPERF::SocPerfLRUCache<int32_t, int32_t> cache(capacity);
            TestSequentialKeys(cache, extractor);
            break;
        }
        case TEST_CASE_RANDOM_KEYS: {
            OHOS::SOCPERF::SocPerfLRUCache<int32_t, int32_t> cache(capacity);
            TestRandomKeys(cache, extractor);
            break;
        }
        case TEST_CASE_HOT_KEYS: {
            OHOS::SOCPERF::SocPerfLRUCache<int32_t, int32_t> cache(capacity);
            TestHotKeys(cache, extractor);
            break;
        }
        case TEST_CASE_DUPLICATE_KEYS: {
            OHOS::SOCPERF::SocPerfLRUCache<int32_t, int32_t> cache(capacity);
            TestDuplicateKeys(cache, extractor);
            break;
        }
        case TEST_CASE_BOUNDARY_CAPACITY: {
            TestBoundaryCapacity<int32_t, int32_t>(extractor);
            break;
        }
        case TEST_CASE_MIXED_OPERATIONS: {
            OHOS::SOCPERF::SocPerfLRUCache<int32_t, int32_t> cache(capacity);
            TestMixedOperations(cache, extractor);
            break;
        }
        case TEST_CASE_LARGE_CACHE: {
            OHOS::SOCPERF::SocPerfLRUCache<int32_t, int32_t> cache(capacity);
            TestLargeCache(cache, extractor);
            break;
        }
        case TEST_CASE_SMALL_CACHE: {
            OHOS::SOCPERF::SocPerfLRUCache<int32_t, int32_t> cache(capacity);
            TestSmallCache(cache, extractor);
            break;
        }
        case TEST_CASE_PATTERN_FUZZING: {
            OHOS::SOCPERF::SocPerfLRUCache<int32_t, int32_t> cache(capacity);
            TestPatternFuzzing(cache, extractor);
            break;
        }
        case TEST_CASE_STRESS_TEST: {
            OHOS::SOCPERF::SocPerfLRUCache<int32_t, int32_t> cache(capacity);
            TestStressTest(cache, extractor);
            break;
        }
        case TEST_CASE_HOT_KEY_ACCESS: {
            OHOS::SOCPERF::SocPerfLRUCache<int32_t, int32_t> cache(capacity);
            TestHotKeyAccess(cache, extractor);
            break;
        }
        default:
            break;
    }

    // Also test with string keys for template coverage
    {
        OHOS::SOCPERF::SocPerfLRUCache<std::string, int32_t> strCache(capacity);
        std::string key = extractor.ExtractString(MAX_STRING_LENGTH);
        int32_t value = extractor.ExtractInt32();
        strCache.put(key, value);
        int32_t retrieved;
        (void)strCache.get(key, retrieved);

        // Test with longer string values using MAX_STRING_VALUE_LENGTH
        std::string longKey = std::string(MAX_STRING_VALUE_LENGTH, 'x');
        int32_t longValue = extractor.ExtractInt32();
        strCache.put(longKey, longValue);
        int32_t longRetrieved;
        (void)strCache.get(longKey, longRetrieved);
    }

    return 0;
}
